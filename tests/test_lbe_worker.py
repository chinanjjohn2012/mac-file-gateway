"""Dormant LBE Worker: source-only T0 fake launch, pipe and cancellation.

Never use Popen, native OS pipes/signals or a real Workspace. In particular
these tests do NOT approve F1 exception, real Exec apply or integration PASS.
"""
from __future__ import annotations

from collections import deque
import os
import selectors
import subprocess
import threading
import time

import pytest

from gateway.lbe_direct_owner import DirectChildOwner, LbeOwnerError
from gateway.lbe_pipe_drain import BoundedPipeDrain
from gateway.lbe_worker import LbeWorkPlan, LbeWorker, LbeWorkerError


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
            self.queues[fd] = deque()

    def unregister(self, fd):
        with self.mu:
            return self.registered.pop(fd)

    def enqueue(self, fd, item):
        with self.mu:
            self.queues[fd].append(item)

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


def test_known_file_not_found_means_no_child_and_releases_reservation():
    calls = []
    def missing(_plan):
        calls.append(True)
        raise FileNotFoundError("fake tool missing")
    worker, owner, sel = driver(launch=missing)
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

