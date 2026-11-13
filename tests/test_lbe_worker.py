"""Dormant LBE Worker: source-only T0 fake launch, pipe and cancellation.

Never use Popen, native OS pipes/signals or a real Workspace. In particular
these tests do NOT approve F1 exception, real Exec apply or integration PASS.
"""
from __future__ import annotations

from collections import deque
from dataclasses import replace
import os
import selectors
import subprocess
import threading
import time

import pytest

from gateway.lbe_direct_owner import DirectChildOwner, LbeOwnerError
from gateway.lbe_pipe_drain import BoundedPipeDrain
from gateway.lbe_worker import LbeWorkPlan, LbeWorker, LbeWorkerError, LbeNoChildStarted


class FakePipe:
    def __init__(self, fd):
        self._fd = fd
        self.closed = False

    def fileno(self):
        return self._fd

    def close(self):
        self.closed = True


class FakeKey:
    def __init__(self, fd, data):
        self.fd = fd
        self.data = data


class FakeSelector:
    def __init__(self):
        self.mu = threading.Lock()
        self.registered = {}
        self.queues = {}
        self.closed = False

    def register(self, fd, events, data):
        assert events == selectors.EVENT_READ
        with self.mu:
            self.registered[fd] = FakeKey(fd, data)
            # Fake stdout can become ready before attach/register.
            self.queues.setdefault(fd, deque())

    def unregister(self, fd):
        with self.mu:
            return self.registered.pop(fd)

    def enqueue(self, fd, item):
        with self.mu:
            self.queues.setdefault(fd, deque()).append(item)

    def select(self, timeout):
        with self.mu:
            ready = [
                (item, selectors.EVENT_READ)
                for fd, item in self.registered.items()
                if self.queues[fd]
            ]
        if not ready:
            time.sleep(min(0.003, timeout))
        return ready

    def read(self, fd, size):
        assert size == 8192
        with self.mu:
            try:
                entry = self.queues[fd].popleft()
            except IndexError:
                raise BlockingIOError() from None
        if isinstance(entry, BaseException):
            raise entry
        return entry

    def close(self):
        self.closed = True
        self.registered.clear()


class FakeChild:
    def __init__(self, *, exit_code=0, stdout_fd=91, stderr_fd=92):
        self.stdout = FakePipe(stdout_fd)
        self.stderr = FakePipe(stderr_fd)
        self.started_wait = threading.Event()
        self.exit = threading.Event()
        self.exit_code = exit_code
        self.wait_calls = 0

    def wait(self):
        self.wait_calls += 1
        self.started_wait.set()
        if not self.exit.wait(timeout=7):
            raise AssertionError("fake child was not released")
        return self.exit_code


def plan(*, timeout=2, runner="direct"):
    requested = ("go", "build", "./...")
    effective = requested if runner == "direct" else ("pipenv", "run", *requested)
    return LbeWorkPlan(
        workspace="a", cwd="go-project",
        requested_argv=requested,
        effective_argv=effective,
        runner=runner, runner_project="go-project",
        timeout_seconds=timeout,
    )


def driver(*, owner=None, selector=None, launch=None, grace=0.05):
    owner = owner or DirectChildOwner()
    selector = selector or FakeSelector()
    def make_drain(capture):
        return BoundedPipeDrain(
            capture, selector_factory=lambda: selector,
            read_fn=selector.read,
            set_nonblocking=lambda fd, enabled: None,
            eof_grace=grace,
        )
    return LbeWorker(
        owner, launcher=launch or (lambda _plan: FakeChild()),
        drain_factory=make_drain), owner, selector


def wait_until(fn, timeout=2):
    limit = time.monotonic() + timeout
    while not fn() and time.monotonic() < limit:
        time.sleep(0.004)
    assert fn()


@pytest.mark.parametrize("exit_code", [0, 3, -15])
def test_successful_observed_exit_reports_child_only_not_descendant_cleanup(exit_code):
    fake = FakeChild(exit_code=exit_code)
    selector = FakeSelector()
    selector_payloads = []
    def launch(the_plan):
        assert the_plan.workspace == "a"
        selector.enqueue(91, b"out-hello")
        selector.enqueue(91, b"")
        selector.enqueue(92, b"err-note")
        selector.enqueue(92, b"")
        fake.exit.set()
        selector_payloads.append(True)
        return fake

    worker, owner, selector = driver(selector=selector, launch=launch)
    result = worker.run(plan())
    assert selector_payloads == [True]
    assert result["status"] == "exited"
    assert result["executed"] is True
    assert result["exit_code"] == exit_code
    assert result["timed_out"] is False
    assert result["mode"] == "local_best_effort"
    assert result["runner"] == "direct"
    assert result["requested_argv"] == ["go", "build", "./..."]
    assert result["effective_argv"] == ["go", "build", "./..."]
    assert result["cleanup_proven"] is False
    assert result["full_descendant_tree_clean"] == "not_proven"
    assert result["process_may_be_running"] is True
    assert result["output_complete"] is True
    assert "out-hello" in result["stdout"]
    assert "err-note" in result["stderr"]
    assert fake.wait_calls == 1
    assert fake.stdout.closed and fake.stderr.closed
    assert owner.snapshot()["running_direct_children"] == 0
    owner.close()


def test_exit_with_descendant_held_pipe_grace_reports_incomplete_output():
    fake = FakeChild()
    def launch(_plan):
        sel.enqueue(91, b"partial from original")
        fake.exit.set()
        return fake
    worker, owner, sel = driver(launch=launch, grace=0.025)
    result = worker.run(plan())
    assert result["status"] == "exited"
    assert result["exit_code"] == 0
    assert result["output_complete"] is False
    assert result["cleanup_proven"] is False
    assert "partial" in result["stdout"]
    assert fake.stdout.closed and fake.stderr.closed
    owner.close()


def test_timeout_does_not_release_live_direct_child_or_stop_its_drainer():
    fake = FakeChild()
    counter = []
    def launch(_plan):
        counter.append("launched")
        return fake
    worker, owner, sel = driver(launch=launch)
    result = worker.run(plan(timeout=1))
    assert result["status"] == "timed_out"
    assert result["executed"] is True
    assert result["exit_code"] is None
    assert result["timed_out"] is True
    assert result["process_may_be_running"] is True
    assert result["output_complete"] is False
    assert owner.snapshot()["reserved_slots"] == 1
    with pytest.raises(LbeWorkerError, match="busy"):
        worker.run(plan())
    assert counter == ["launched"]
    sel.enqueue(91, b"late data")
    sel.enqueue(91, b"")
    sel.enqueue(92, b"")
    fake.exit.set()
    wait_until(lambda: owner.snapshot()["reserved_slots"] == 0)
    assert fake.wait_calls == 1
    owner.close()


def test_early_cancellation_never_spawns_or_admits():
    fake = FakeChild()
    event = threading.Event()
    event.set()
    worker, owner, _selector = driver(launch=lambda _plan: fake)
    with pytest.raises(LbeWorkerError, match="waiter_disconnected"):
        worker.run(plan(), cancelled=event)
    assert owner.snapshot()["reserved_slots"] == 0
    assert fake.wait_calls == 0
    owner.close()


def test_cancellation_during_prelaunch_preallocation_never_calls_launcher(
    monkeypatch,
):
    """Cancel after initial check but before spawn; release no-child lease."""
    owner = DirectChildOwner()
    cancel = threading.Event()
    selector = FakeSelector()
    launched = []

    def allocate_then_cancel(capture):
        reader = BoundedPipeDrain(
            capture, selector_factory=lambda: selector,
            read_fn=selector.read,
            set_nonblocking=lambda fd, enabled: None,
        )
        # The first is_set() ran before this allocation callback.
        cancel.set()
        return reader

    def no_native(*args, **kwargs):
        raise AssertionError("No native child or process signal is allowed")

    worker = LbeWorker(
        owner, launcher=lambda work: launched.append(work),
        drain_factory=allocate_then_cancel,
    )
    try:
        with monkeypatch.context() as m:
            m.setattr(subprocess, "Popen", no_native)
            m.setattr(os, "kill", no_native)
            m.setattr(os, "killpg", no_native, raising=False)
            with pytest.raises(LbeWorkerError) as error:
                worker.run(plan(), cancelled=cancel)
        assert error.value.code == "waiter_disconnected"
        assert error.value.process_may_be_running is False
        assert launched == []
        assert selector.closed is True
        assert owner.snapshot()["reserved_slots"] == 0
        assert owner.snapshot()["running_direct_children"] == 0
        assert owner.snapshot()["unavailable"] is False
    finally:
        owner.close()


def test_disconnected_caller_keeps_owner_and_cleans_only_after_child_exit():
    fake = FakeChild()
    calls = []
    def launch(_plan):
        calls.append("launch")
        return fake
    worker, owner, sel = driver(launch=launch)
    cancel = threading.Event()
    result = []
    def invoke():
        try:
            worker.run(plan(), cancelled=cancel)
        except LbeWorkerError as err:
            result.append((err.code, err.process_may_be_running))
    thread = threading.Thread(target=invoke, daemon=True)
    thread.start()
    assert fake.started_wait.wait(2)
    cancel.set()
    thread.join(2)
    assert not thread.is_alive()
    assert result == [("waiter_disconnected", True)]
    assert owner.snapshot()["reserved_slots"] == 1
    assert calls == ["launch"]
    with pytest.raises(LbeWorkerError, match="busy"):
        worker.run(plan())
    sel.enqueue(91, b"")
    sel.enqueue(92, b"")
    fake.exit.set()
    wait_until(lambda: owner.snapshot()["reserved_slots"] == 0)
    assert fake.wait_calls == 1
    owner.close()


def test_explicit_no_child_witness_releases_reservation():
    calls = []
    def rejected_before_spawn(_plan):
        calls.append(True)
        raise LbeNoChildStarted("trusted witness: no original child created")
    worker, owner, sel = driver(launch=rejected_before_spawn)
    result = worker.run(plan())
    assert result["status"] == "launch_failed"
    assert result["executed"] is False
    assert result["exit_code"] is None
    assert result["process_may_be_running"] is False
    assert result["output_complete"] is False
    assert owner.snapshot()["reserved_slots"] == 0
    assert sel.closed
    assert calls == [True]
    owner.close()


def test_unqualified_launcher_error_is_uncertain_and_fail_closed():
    def broken(_plan):
        raise RuntimeError("could have spawned already")
    worker, owner, _sel = driver(launch=broken)
    with pytest.raises(LbeWorkerError) as error:
        worker.run(plan())
    assert error.value.code == "exec_state_unavailable"
    assert error.value.process_may_be_running is True
    assert owner.snapshot()["reserved_slots"] == 1
    assert owner.snapshot()["unavailable"] is True
    owner.close()


def test_duplicate_pipe_fds_latch_owner_but_still_reap_original_child():
    fake = FakeChild(stdout_fd=91, stderr_fd=91)
    worker, owner, _selector = driver(launch=lambda _plan: fake)
    with pytest.raises(LbeWorkerError) as error:
        worker.run(plan())
    assert error.value.code == "exec_state_unavailable"
    assert error.value.process_may_be_running is True
    assert owner.snapshot()["unavailable"] is True
    assert fake.started_wait.wait(2)
    assert owner.snapshot()["reserved_slots"] == 1
    fake.exit.set()
    wait_until(lambda: owner.snapshot()["reserved_slots"] == 0)
    assert fake.wait_calls == 1
    owner.close()


def test_fake_pipe_read_error_latches_owner_even_if_child_exits():
    fake = FakeChild()
    def launch(_plan):
        sel.enqueue(91, OSError("fake read failure"))
        sel.enqueue(92, b"")
        fake.exit.set()
        return fake
    worker, owner, sel = driver(launch=launch)
    result = worker.run(plan())
    assert result["status"] == "exited"
    assert result["output_complete"] is False
    assert owner.snapshot()["unavailable"] is True
    owner.close()


@pytest.mark.parametrize("bad", [
    lambda: plan(timeout=0),
    lambda: plan(timeout=301),
    lambda: plan(timeout=True),
    lambda: plan(runner="unknown"),
    lambda: LbeWorkPlan("a", ".", ("python", "a.py"), ("python", "other.py"),
                        "direct", ".", 2),
    lambda: LbeWorkPlan("a", ".", ("python", "-c", "print(1)"),
                        ("python", "-c", "print(1)"), "direct", ".", 2),
])
def test_malformed_prepared_plan_never_spawns(bad):
    calls = []
    worker, owner, _sel = driver(launch=lambda p: calls.append(p))
    with pytest.raises(LbeWorkerError, match="invalid_plan"):
        worker.run(bad())
    assert calls == []
    assert owner.snapshot()["reserved_slots"] == 0
    owner.close()


def test_worker_has_no_default_launcher_and_never_uses_real_popen(monkeypatch):
    calls = []
    def forbidden(*args, **kwargs):
        calls.append(1)
        raise AssertionError("real process or OS signal not authorized")
    with monkeypatch.context() as m:
        m.setattr(subprocess, "Popen", forbidden)
        m.setattr(os, "kill", forbidden)
        m.setattr(os, "killpg", forbidden, raising=False)
        owner = DirectChildOwner()
        with pytest.raises(TypeError):
            LbeWorker(owner)
        worker, _, sel = driver(owner=owner, launch=lambda _p: FakeChild())
        fake = FakeChild()
        worker, _, sel = driver(owner=owner, launch=lambda _p: fake)
        sel.enqueue(91, b"")
        sel.enqueue(92, b"")
        fake.exit.set()
        assert worker.run(plan())["status"] == "exited"
        owner.close()
    assert calls == []



@pytest.mark.parametrize("error", [
    FileNotFoundError("could be after a child was launched"),
    OSError("cannot prove absence of original child"),
    InterruptedError("interrupted after possible native spawn"),
])
def test_ordinary_launcher_oserror_never_proves_no_child(error):
    def uncertain(_plan):
        raise error
    worker, owner, _selector = driver(launch=uncertain)
    with pytest.raises(LbeWorkerError) as err:
        worker.run(plan())
    assert err.value.code == "exec_state_unavailable"
    assert err.value.process_may_be_running is True
    assert owner.snapshot()["unavailable"] is True
    assert owner.snapshot()["reserved_slots"] == 1
    with pytest.raises(LbeWorkerError, match="exec_state_unavailable"):
        worker.run(plan())
    owner.close()


def test_prelaunch_owner_reject_closes_unadopted_selector(monkeypatch):
    owner = DirectChildOwner()
    selector = FakeSelector()
    def make_drain(capture):
        return BoundedPipeDrain(
            capture, selector_factory=lambda: selector,
            read_fn=selector.read, set_nonblocking=lambda fd, enabled: None)
    def fail_prepare(*args, **kwargs):
        raise RuntimeError("unavailable owner before spawn")
    with monkeypatch.context() as m:
        m.setattr(owner, "prepare_pipe_drain", fail_prepare)
        launcher_called = []
        worker = LbeWorker(
            owner, launcher=lambda p: launcher_called.append(p),
            drain_factory=make_drain)
        with pytest.raises(LbeWorkerError, match="exec_state_unavailable"):
            worker.run(plan())
    assert launcher_called == []
    assert selector.closed is True
    assert owner.snapshot()["reserved_slots"] == 0
    owner.close()

# Five-day D1: Worker plan fields are not public permissions. Test the shape
# before custom hash/equality callbacks; no real child, socket or OS signal.
@pytest.mark.parametrize("kind", [
    "equal", "throws_on_hash", "throws_on_eq", "str_subclass", "unhashable",
])
def test_worker_runner_field_denies_custom_comparator_without_invoking_it(kind):
    from dataclasses import replace

    hooks = []

    class FakeRunner:
        def __hash__(self):
            hooks.append("hash")
            if kind == "throws_on_hash":
                raise RuntimeError("custom hash reached")
            return hash("direct")

        def __eq__(self, other):
            hooks.append("eq")
            if kind == "throws_on_eq":
                raise RuntimeError("custom equality reached")
            return True

    class CustomStr(str):
        def __new__(cls):
            return str.__new__(cls, "direct")

        def __hash__(self):
            hooks.append("str hash")
            return hash("direct")

        def __eq__(self, other):
            hooks.append("str eq")
            return True

    class Unhashable:
        def __eq__(self, other):
            hooks.append("unhashable eq")
            return True

    runner = CustomStr() if kind == "str_subclass" else (
        Unhashable() if kind == "unhashable" else FakeRunner())
    forged = replace(plan(), runner=runner)
    seen = []
    owner = DirectChildOwner()
    worker = LbeWorker(owner, launcher=lambda _plan: seen.append("launch"))
    try:
        with pytest.raises(LbeWorkerError, match="invalid_plan"):
            worker.run(forged)
        assert hooks == [], "no user comparison/hash callback on rejected plan"
        assert seen == [], "no launcher reached"
        assert owner.snapshot()["reserved_slots"] == 0
    finally:
        owner.close()


def test_worker_plain_go_python_pipenv_plan_shapes_do_not_grant_exec():
    from dataclasses import replace

    good_go = plan()
    LbeWorker._check_plan(good_go)
    good_py = replace(
        good_go, runner="direct", cwd="python-project",
        runner_project="python-project",
        requested_argv=("python", "-m", "pytest"),
        effective_argv=("python", "-m", "pytest"),
    )
    LbeWorker._check_plan(good_py)
    pipenv = replace(good_py, runner="pipenv",
                     effective_argv=("pipenv", "run", "python", "-m", "pytest"),
                     planned_pipfile_sha256="a" * 64)
    LbeWorker._check_plan(pipenv)
    assert good_go.runner == "direct" and pipenv.runner == "pipenv"



# r006: a planned Go output is display metadata, not execution authority.
def test_r006_planned_go_output_is_strictly_typed_and_not_a_grant():
    from dataclasses import replace

    base = plan()
    argv = ("go", "build", "-o=bin/app", "./cmd/app")
    proposed = replace(
        base, requested_argv=argv, effective_argv=argv,
        planned_go_output="go-project/bin/app")
    LbeWorker._check_plan(proposed)
    hooks = []

    class Malicious:
        def __eq__(self, other):
            hooks.append("eq")
            return True

    for invalid in (Malicious(), True, 10, "", "../outside", "bin//bad"):
        forged = replace(proposed, planned_go_output=invalid)
        with pytest.raises(LbeWorkerError, match="invalid_plan"):
            LbeWorker._check_plan(forged)
    no_flag = replace(
        base, planned_go_output="go-project/bin/app")
    with pytest.raises(LbeWorkerError, match="invalid_plan"):
        LbeWorker._check_plan(no_flag)
    py = replace(
        proposed, requested_argv=("python", "-m", "pytest"),
        effective_argv=("python", "-m", "pytest"))
    with pytest.raises(LbeWorkerError, match="invalid_plan"):
        LbeWorker._check_plan(py)
    assert hooks == []


@pytest.mark.parametrize("argv,shown", [
    (("go","build","-o","bin/app","./cmd/app"), None),
    (("go","build","-o=bin/app","./cmd/app"), "go-project/bin/other"),
    (("go","build","./cmd/app"), "go-project/bin/app"),
    (("go","test","./..."), "go-project/bin/app"),
])
def test_r006_go_planned_output_must_match_command(argv, shown):
    from dataclasses import replace
    candidate = replace(plan(), requested_argv=argv, effective_argv=argv,
                        planned_go_output=shown)
    with pytest.raises(LbeWorkerError, match="invalid_plan"):
        LbeWorker._check_plan(candidate)


@pytest.mark.parametrize("argv", [
    ("go","build","-o","bin/app","./cmd/app"),
    ("go","build","-o=bin/app","./cmd/app"),
])
def test_r006_go_planned_output_accepts_both_legal_flag_forms(argv):
    from dataclasses import replace
    candidate = replace(plan(), requested_argv=argv, effective_argv=argv,
                        planned_go_output="go-project/bin/app")
    LbeWorker._check_plan(candidate)


def test_r006_python_script_source_hash_must_be_exact_and_bound():
    from dataclasses import replace

    base = plan()
    script_args = ("python", "hello.py")
    valid = replace(base, requested_argv=script_args,
                    effective_argv=script_args,
                    planned_script_sha256="a" * 64)
    LbeWorker._check_plan(valid)
    for poisoned in (None, "", True, 123, "A" * 64, "x" * 64, "a" * 63):
        with pytest.raises(LbeWorkerError, match="invalid_plan"):
            LbeWorker._check_plan(
                replace(valid, planned_script_sha256=poisoned))
    with pytest.raises(LbeWorkerError, match="invalid_plan"):
        LbeWorker._check_plan(replace(base, planned_script_sha256="a" * 64))
    with pytest.raises(LbeWorkerError, match="invalid_plan"):
        LbeWorker._check_plan(replace(valid, planned_pipfile_sha256="b" * 64))
    called = []
    class MaliciousDigest:
        def __eq__(self, _other):
            called.append("eq")
            return True
        def __hash__(self):
            called.append("hash")
            return 1
    with pytest.raises(LbeWorkerError, match="invalid_plan"):
        LbeWorker._check_plan(replace(valid,
            planned_script_sha256=MaliciousDigest()))
    assert called == []


def test_r006_pipenv_runner_requires_pinned_pipfile_hash():
    from dataclasses import replace
    base = plan()
    py = ("python", "-m", "pytest")
    valid = replace(base, requested_argv=py,
                    effective_argv=("pipenv", "run", *py),
                    runner="pipenv", planned_pipfile_sha256="a" * 64)
    LbeWorker._check_plan(valid)
    for invalid in (None, "invalid", "f" * 63, True):
        with pytest.raises(LbeWorkerError, match="invalid_plan"):
            LbeWorker._check_plan(
                replace(valid, planned_pipfile_sha256=invalid))


def _r010_fake_worker_envelope():
    """NON_RUNTIME Job row with the existing Worker fake-child path."""
    from tools.r010_authority_chain_t0 import (
        JobEnvelope, R010_STATE_DOMAIN, SharedJobRegistry, StateProvenance,
    )
    state = StateProvenance(
        state_domain=R010_STATE_DOMAIN, provider_check_run_id=12345,
        github_hosted_ephemeral=True, workflow_restores_state=False,
        earlier_positive_gateway_step=False,
        canonical_root_absent_before_create=True,
        historic_conflicting_state=False,
        offline_owner_lock_created=True,
        existing_only_open_succeeded=True,
    )
    return JobEnvelope.create(
        key="fake-owned-original-t0",
        requested_config_root="/fake-canonical-r010",
        canonical_config_root="/fake-canonical-r010",
        provider_check_run_id=12345, registry=SharedJobRegistry(),
        state_provenance=state,
    )


def _r012_record_private_owner_observe(patch, owner):
    """T0 spy on the actual DirectChildOwner.observe(reservation) call."""
    original_observe = owner.observe
    record = {"owner": owner}

    def observe(item, *, wait_seconds):
        result = original_observe(item, wait_seconds=wait_seconds)
        record["reservation"] = item
        record["direct_observation"] = result
        return result

    patch.setattr(owner, "observe", observe)
    return record


def _r010_finish_from_owned_fake_worker(
    env, result, *, owner_record, fs_ok, worker_override=None,
    observation_override=None,
):
    """One same-reservation T0 observation, never a REST/MCP caller claim."""
    from tools.r010_authority_chain_t0 import OwnedRowObservationT0

    assert type(result) is dict
    direct = owner_record["direct_observation"]
    reservation = owner_record["reservation"]
    # Real code observations of this exact private reservation and Owner:
    # the public Worker dictionary cannot independently override health.
    assert reservation.owner is owner_record["owner"]
    assert reservation.pipe_drain is not None
    reader_private = reservation.pipe_drain.snapshot()
    owner_private = owner_record["owner"].snapshot()
    observed_worker = dict(result)
    if worker_override is not None:
        observed_worker.update(worker_override)
    nonce = "fake-row-1"
    env.begin_row(0, nonce, nonce)
    obs = OwnedRowObservationT0(
        attempt_nonce=nonce,
        owner_attempt_nonce=nonce,
        worker_attempt_nonce=nonce,
        owner_reservation=reservation,
        worker_reservation=reservation,
        owner_status=direct.status,
        owner_exit_code=direct.exit_code,
        original_child_reaped=(
            direct.status == "exited" and type(direct.exit_code) is int
        ),
        original_child_unambiguous=(
            direct.status == "exited" and type(direct.exit_code) is int
        ),
        worker_status=observed_worker["status"],
        worker_executed=observed_worker["executed"],
        worker_timed_out=observed_worker["timed_out"],
        worker_exit_code=observed_worker["exit_code"],
        worker_cancelled=False,
        ack_lost=False,
        worker_pipe_reader_failed=observed_worker["pipe_reader_failed"],
        owner_pipe_reader_failed=reader_private["pipe_reader_failed"],
        pipe_reader_finished=reader_private["pipe_reader_finished"],
        owner_unavailable=owner_private["unavailable"],
        owner_closing=owner_private["closing"],
        stdout_eof=observed_worker["output_complete"],
        stderr_eof=observed_worker["output_complete"],
        stdout_truncated=observed_worker["stdout_truncated"],
        stderr_truncated=observed_worker["stderr_truncated"],
        output_within_bound=True,
        finite_observed_fs_ok=fs_ok,
        process_may_be_running=observed_worker["process_may_be_running"],
        cleanup_proven=observed_worker["cleanup_proven"],
        full_descendant_tree_clean=observed_worker["full_descendant_tree_clean"],
    )
    if observation_override is not None:
        obs = replace(obs, **observation_override)
    return env.finish_row(0, observation=obs)


@pytest.mark.parametrize(
    "exit_code,streams_eof,fs_ok,expected",
    [
        (0, True, True, "ROW_POSITIVE_SUCCESS"),
        (7, True, True, "ROW_OBSERVED_NONZERO"),
        (0, False, True, "ROW_OBSERVED_ZERO_INVALID_OUTPUT_OR_FS"),
        (0, True, False, "ROW_OBSERVED_ZERO_INVALID_OUTPUT_OR_FS"),
    ],
)
def test_r010_worker_fake_child_reap_is_not_descendant_cleanup(
    monkeypatch, exit_code, streams_eof, fs_ok, expected,
):
    """Actual Worker/DirectChildOwner code; synthetic FakeChild only."""
    fake = FakeChild(exit_code=exit_code)
    selector = FakeSelector()

    def launch(_plan):
        selector.enqueue(91, b"fake original child output")
        if streams_eof:
            selector.enqueue(91, b"")
            selector.enqueue(92, b"")
        fake.exit.set()
        return fake

    worker, owner, _selector = driver(selector=selector, launch=launch, grace=0.025)

    def deny_real_process(*_args, **_kwargs):
        raise AssertionError("R012 SAFE T0 forbids native launch and signals")

    try:
        with monkeypatch.context() as patch:
            patch.setattr(subprocess, "Popen", deny_real_process)
            patch.setattr(os, "kill", deny_real_process)
            patch.setattr(os, "killpg", deny_real_process, raising=False)
            record = _r012_record_private_owner_observe(patch, owner)
            result = worker.run(plan())

        assert result["status"] == "exited"
        assert result["executed"] is True and result["timed_out"] is False
        assert result["exit_code"] == exit_code
        assert record["direct_observation"].status == "exited"
        assert record["direct_observation"].exit_code == exit_code
        assert fake.wait_calls == 1
        assert owner.snapshot()["running_direct_children"] == 0
        assert result["process_may_be_running"] is True
        assert result["cleanup_proven"] is False
        assert result["full_descendant_tree_clean"] == "not_proven"

        env = _r010_fake_worker_envelope()
        verdict = _r010_finish_from_owned_fake_worker(
            env, result, owner_record=record, fs_ok=fs_ok,
        )
        assert verdict.value == expected
        if expected != "ROW_POSITIVE_SUCCESS":
            from tools.r010_authority_chain_t0 import JobState, RowState
            assert env.state == JobState.FAILED
            assert all(x == RowState.VOID for x in env.row_states[1:])
            with pytest.raises(Exception, match="not ready"):
                env.begin_row(1, "fake-next", "fake-next")
    finally:
        owner.close()


def test_r010_unreaped_fake_timeout_fails_closed_without_signal(monkeypatch):
    """Request timeout has no completed trusted reap; late exit not replayed."""
    from tools.r010_authority_chain_t0 import JobState, RowState
    fake = FakeChild()
    worker, owner, selector = driver(launch=lambda _plan: fake, grace=0.025)

    def deny_real_process(*_args, **_kwargs):
        raise AssertionError("R012 SAFE T0 forbids native launch and signals")

    try:
        with monkeypatch.context() as patch:
            patch.setattr(subprocess, "Popen", deny_real_process)
            patch.setattr(os, "kill", deny_real_process)
            patch.setattr(os, "killpg", deny_real_process, raising=False)
            record = _r012_record_private_owner_observe(patch, owner)
            result = worker.run(plan(timeout=1))

        assert result["status"] == "timed_out"
        assert result["exit_code"] is None
        assert result["process_may_be_running"] is True
        assert record["direct_observation"].status == "timed_out"
        assert record["direct_observation"].exit_code is None
        assert fake.wait_calls == 1
        assert owner.snapshot()["reserved_slots"] == 1

        env = _r010_fake_worker_envelope()
        assert _r010_finish_from_owned_fake_worker(
            env, result, owner_record=record, fs_ok=True,
        ) == RowState.AMBIGUOUS
        assert env.state == JobState.FAILED
        assert all(x == RowState.VOID for x in env.row_states[1:])
        with pytest.raises(Exception, match="not ready"):
            env.begin_row(1, "fake-next", "fake-next")
    finally:
        selector.enqueue(91, b"")
        selector.enqueue(92, b"")
        fake.exit.set()
        wait_until(lambda: owner.snapshot()["reserved_slots"] == 0)
        owner.close()


@pytest.mark.parametrize("worker_change,observation_change", [
    ({"status": "timed_out"}, None),
    ({"status": "launch_failed"}, None),
    ({"executed": False}, None),
    ({"timed_out": True}, None),
    ({"exit_code": 9}, None),
    ({"cleanup_proven": True}, None),
    (None, {"worker_attempt_nonce": "another-execution-attempt"}),
    (None, {"owner_attempt_nonce": "another-execution-attempt"}),
    (None, {"owner_reservation": object()}),
    (None, {"worker_reservation": object()}),
    (None, {"worker_cancelled": True}),
    (None, {"ack_lost": True}),
])
def test_r012_worker_owner_conflicting_same_fake_attempt_voids_remaining(
    monkeypatch, worker_change, observation_change,
):
    """Independent B R011 counterexamples on actual Worker/Owner fake path."""
    from tools.r010_authority_chain_t0 import JobState, RowState
    fake = FakeChild(exit_code=0)
    selector = FakeSelector()

    def launch(_plan):
        selector.enqueue(91, b"valid observed output")
        selector.enqueue(91, b"")
        selector.enqueue(92, b"")
        fake.exit.set()
        return fake

    worker, owner, _sel = driver(selector=selector, launch=launch)
    def deny_real_process(*_args, **_kwargs):
        raise AssertionError("R012 SAFE T0 forbids Popen/signal")
    try:
        with monkeypatch.context() as patch:
            patch.setattr(subprocess, "Popen", deny_real_process)
            patch.setattr(os, "kill", deny_real_process)
            patch.setattr(os, "killpg", deny_real_process, raising=False)
            record = _r012_record_private_owner_observe(patch, owner)
            result = worker.run(plan())
        assert result["status"] == "exited"
        assert result["exit_code"] == 0
        assert record["direct_observation"].status == "exited"
        assert record["direct_observation"].exit_code == 0
        assert fake.wait_calls == 1
        env = _r010_fake_worker_envelope()
        assert _r010_finish_from_owned_fake_worker(
            env, result, owner_record=record, fs_ok=True,
            worker_override=worker_change,
            observation_override=observation_change,
        ) == RowState.AMBIGUOUS
        assert env.state == JobState.FAILED
        assert all(x == RowState.VOID for x in env.row_states[1:])
        with pytest.raises(Exception, match="not ready"):
            env.begin_row(1, "fake-next", "fake-next")
        assert result["process_may_be_running"] is True
        assert result["cleanup_proven"] is False
        assert result["full_descendant_tree_clean"] == "not_proven"
    finally:
        owner.close()


def test_r013_red_both_eof_then_selector_close_fault_cannot_advance_row(monkeypatch):
    """Real library Worker/Owner/Drain with FakeChild; NO native launch."""
    from tools.r010_authority_chain_t0 import JobState, RowState

    class FaultAfterBothEofSelector(FakeSelector):
        def close(self):
            assert not self.registered, "test fault must occur AFTER both EOFs"
            super().close()
            raise OSError("fake selector cleanup fault after EOF")

    fake = FakeChild(exit_code=0)
    selector = FaultAfterBothEofSelector()

    def launch(_plan):
        selector.enqueue(91, b"original stdout")
        selector.enqueue(91, b"")
        selector.enqueue(92, b"original stderr")
        selector.enqueue(92, b"")
        fake.exit.set()
        return fake

    worker, owner, _ = driver(selector=selector, launch=launch, grace=0.025)
    def deny_native(*_args, **_kwargs):
        raise AssertionError("R013 SAFE T0 forbids subprocess and OS signals")

    try:
        with monkeypatch.context() as m:
            m.setattr(subprocess, "Popen", deny_native)
            m.setattr(os, "kill", deny_native)
            m.setattr(os, "killpg", deny_native, raising=False)
            record = _r012_record_private_owner_observe(m, owner)
            result = worker.run(plan())

        assert result["status"] == "exited"
        assert result["executed"] is True
        assert result["timed_out"] is False
        assert result["exit_code"] == 0
        assert result["output_complete"] is True
        assert result["pipe_reader_failed"] is True
        assert record["direct_observation"].status == "exited"
        assert record["direct_observation"].exit_code == 0
        assert record["reservation"].pipe_drain.snapshot()["pipe_reader_finished"] is True
        assert owner.snapshot()["unavailable"] is True
        assert fake.wait_calls == 1

        env = _r010_fake_worker_envelope()
        assert _r010_finish_from_owned_fake_worker(
            env, result, owner_record=record, fs_ok=True,
        ) == RowState.AMBIGUOUS
        assert env.state == JobState.FAILED
        assert all(x == RowState.VOID for x in env.row_states[1:])
        with pytest.raises(Exception, match="not ready"):
            env.begin_row(1, "next", "next")
        assert result["process_may_be_running"] is True
        assert result["cleanup_proven"] is False
        assert result["full_descendant_tree_clean"] == "not_proven"
    finally:
        owner.close()


@pytest.mark.parametrize("worker_override,private_override", [
    ({"pipe_reader_failed": True}, None),
    (None, {"worker_pipe_reader_failed": True}),
    (None, {"owner_pipe_reader_failed": True}),
    (None, {"pipe_reader_finished": False}),
    (None, {"owner_unavailable": True}),
    (None, {"owner_closing": True}),
])
def test_r013_source_fake_worker_reader_or_owner_fault_forbids_later_row(
    monkeypatch, worker_override, private_override,
):
    """Healthy REAL Worker FakeChild plus injected health contradiction."""
    from tools.r010_authority_chain_t0 import RowState, JobState
    fake = FakeChild(exit_code=0)
    selector = FakeSelector()

    def launch(_plan):
        selector.enqueue(91, b"original-good")
        selector.enqueue(91, b"")
        selector.enqueue(92, b"")
        fake.exit.set()
        return fake

    worker, owner, _ = driver(selector=selector, launch=launch)
    def no_popen(*_a, **_kw):
        raise AssertionError("R013 SAFE T0 forbids native child/signals")
    try:
        with monkeypatch.context() as m:
            m.setattr(subprocess, "Popen", no_popen)
            m.setattr(os, "kill", no_popen)
            m.setattr(os, "killpg", no_popen, raising=False)
            record = _r012_record_private_owner_observe(m, owner)
            result = worker.run(plan())
        assert result["status"] == "exited"
        assert result["output_complete"] is True
        assert result["pipe_reader_failed"] is False
        assert record["reservation"].pipe_drain.snapshot()["pipe_reader_finished"] is True
        assert owner.snapshot()["unavailable"] is False
        env = _r010_fake_worker_envelope()
        assert _r010_finish_from_owned_fake_worker(
            env, result, owner_record=record, fs_ok=True,
            worker_override=worker_override,
            observation_override=private_override,
        ) == RowState.AMBIGUOUS
        assert env.state == JobState.FAILED
        assert all(row == RowState.VOID for row in env.row_states[1:])
        with pytest.raises(Exception, match="not ready"):
            env.begin_row(1, "second", "second")
    finally:
        owner.close()


def test_cancel_at_postcheck_launch_boundary_is_possibly_started():
    """Deterministically close the Worker-check/Popen-observation race (T0).

    The last Worker cancellation check has already returned false when the
    launcher callback is entered.  A cancellation signaled inside that
    callback is POST-COMMIT from the Worker perspective: we must never claim
    no child or release its owner lease while the direct child is still alive.
    No native Popen, OS pipe, PID signal, or real child is involved.
    """
    event = threading.Event()
    fake = FakeChild()
    selector = FakeSelector()
    calls = []

    def launch(_plan):
        calls.append("launcher_entered_after_last_check")
        event.set()
        return fake

    worker, owner, selector = driver(selector=selector, launch=launch)
    try:
        with pytest.raises(LbeWorkerError) as exc:
            worker.run(plan(), cancelled=event)
        assert exc.value.code == "waiter_disconnected"
        assert exc.value.process_may_be_running is True
        assert calls == ["launcher_entered_after_last_check"]
        assert owner.snapshot()["reserved_slots"] == 1
        assert owner.snapshot()["running_direct_children"] == 1
        # No replay while the original direct child is unobserved.
        with pytest.raises(LbeWorkerError, match="busy"):
            worker.run(plan())
        selector.enqueue(91, b"")
        selector.enqueue(92, b"")
        fake.exit.set()
        wait_until(lambda: owner.snapshot()["reserved_slots"] == 0)
        assert fake.wait_calls == 1
    finally:
        fake.exit.set()
        owner.close()
