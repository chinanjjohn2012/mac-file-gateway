"""R010 actual Worker/Owner/Reader with injected FakeChild; SAFE T0 only."""
from collections import deque
from dataclasses import replace
import os
import selectors
import socket
import subprocess
import threading
import time

import pytest

from gateway.lbe_direct_owner import DirectChildOwner
from gateway.lbe_pipe_drain import BoundedPipeDrain
from gateway.lbe_worker import LbeWorkPlan, LbeWorker
from gateway.lbe_r010_owned_row import (
    R010OwnedRowDenied, observe_r010_private_owner_row,
)


class FakePipe:
    def __init__(self, fd):
        self.fd = fd

    def fileno(self):
        return self.fd

    def close(self):
        pass


class FakeKey:
    def __init__(self, fd, data):
        self.fd, self.data = fd, data


class FakeSelector:
    def __init__(self, *, close_fails=False):
        self.lock = threading.Lock()
        self.registered = {}
        self.queue = {}
        self.close_fails = close_fails

    def register(self, fd, events, data):
        assert events == selectors.EVENT_READ
        with self.lock:
            self.registered[fd] = FakeKey(fd, data)
            self.queue.setdefault(fd, deque())

    def unregister(self, fd):
        with self.lock:
            return self.registered.pop(fd)

    def feed(self, fd, value):
        with self.lock:
            self.queue.setdefault(fd, deque()).append(value)

    def select(self, timeout):
        with self.lock:
            ready = [
                (key, selectors.EVENT_READ)
                for fd, key in self.registered.items() if self.queue[fd]
            ]
        if not ready:
            time.sleep(min(0.002, timeout))
        return ready

    def read(self, fd, size):
        assert size == 8192
        with self.lock:
            if not self.queue.get(fd):
                raise BlockingIOError()
            return self.queue[fd].popleft()

    def close(self):
        if self.close_fails:
            raise OSError("injected post-EOF selector close fault")


class FakeChild:
    def __init__(self, exit_code):
        self.stdout = FakePipe(91)
        self.stderr = FakePipe(92)
        self.exit_code = exit_code
        self.reaped = 0

    def wait(self):
        self.reaped += 1
        return self.exit_code


def plan():
    return LbeWorkPlan(
        workspace="a", cwd="go-project",
        requested_argv=("go", "test", "./..."),
        effective_argv=("go", "test", "./..."),
        runner="direct", runner_project="go-project", timeout_seconds=2,
    )


@pytest.fixture(autouse=True)
def no_foreign_effects(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("SAFE T0 cannot spawn/connect/signal")
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(os, "kill", forbidden)
    monkeypatch.setattr(os, "killpg", forbidden, raising=False)
    monkeypatch.setattr(socket.socket, "connect", forbidden)


def run_fake(*, exit_code=0, both_eof=True, close_fails=False,
             proposed_plan=None):
    owner = DirectChildOwner()
    sel = FakeSelector(close_fails=close_fails)
    child = FakeChild(exit_code)
    reservations = []
    old_reserve = owner.reserve

    def reserve(workspace):
        item = old_reserve(workspace)
        reservations.append(item)
        return item

    owner.reserve = reserve

    def launch(_plan):
        sel.feed(91, b"out")
        sel.feed(91, b"")
        sel.feed(92, b"err")
        if both_eof:
            sel.feed(92, b"")
        return child

    def make_reader(capture):
        return BoundedPipeDrain(
            capture, selector_factory=lambda: sel,
            read_fn=sel.read, set_nonblocking=lambda *_: None,
            eof_grace=0.05,
        )

    worker = LbeWorker(owner, launcher=launch, drain_factory=make_reader)
    proposed = plan() if proposed_plan is None else proposed_plan
    result = worker.run(proposed)
    assert len(reservations) == 1
    assert child.reaped == 1
    observed = observe_r010_private_owner_row(
        owner=owner, reservation=reservations[0], plan=proposed,
        worker_result=result, row=1, nonce_sha256="a" * 64,
    )
    return observed, owner, reservations[0], proposed, result


def test_actual_owned_zero_reader_success_is_not_t1_or_six_command_pass():
    item, owner, _, _, _ = run_fake()
    assert item.outcome == "ORIGINAL_ZERO_READER_HEALTHY_FINITE_FS_NOT_CHECKED"
    assert item.observed_original_exit_code == 0
    assert item.original_child_reaped is True
    assert item.owner_reader_healthy is True
    assert item.output_complete is True
    assert item.native_launch_allowed is False
    assert item.row_positive_success is False
    assert item.six_command_product_t1_pass is False
    assert item.descendant_cleanup_proven is False
    owner.close()


@pytest.mark.parametrize("code", [1, 3, -15])
def test_actual_original_nonzero_is_not_success(code):
    item, owner, _, _, _ = run_fake(exit_code=code)
    assert item.outcome == "ROW_OBSERVED_NONZERO"
    assert item.observed_original_exit_code == code
    assert item.row_positive_success is False
    owner.close()


def test_healthy_original_exit_zero_but_missing_eof_is_invalid_output():
    item, owner, _, _, _ = run_fake(both_eof=False)
    assert item.outcome == "ROW_OBSERVED_ZERO_INVALID_OUTPUT_OR_FS"
    assert item.output_complete is False
    owner.close()


def test_post_eof_reader_close_fault_is_ambiguous():
    item, owner, _, _, _ = run_fake(close_fails=True)
    assert item.outcome == "ROW_AMBIGUOUS"
    assert item.owner_reader_healthy is False
    assert owner.snapshot()["unavailable"] is True
    owner.close()


def test_forged_worker_exit_is_not_reaper_observation():
    _, owner, reservation, proposed, result = run_fake()
    tampered = dict(result, exit_code=14)
    item = observe_r010_private_owner_row(
        owner=owner, reservation=reservation, plan=proposed,
        worker_result=tampered, row=1, nonce_sha256="a" * 64)
    assert item.outcome == "ROW_AMBIGUOUS"
    owner.close()


def test_lost_worker_ack_does_not_become_later_success():
    _, owner, reservation, proposed, result = run_fake()
    item = observe_r010_private_owner_row(
        owner=owner, reservation=reservation, plan=proposed,
        worker_result={**result, "status": "timed_out", "timed_out": True},
        row=1, nonce_sha256="a" * 64)
    assert item.outcome == "ROW_AMBIGUOUS"
    owner.close()


def test_unavailable_or_closed_owner_cannot_be_healthy():
    _, owner, reservation, proposed, result = run_fake()
    owner.close()
    item = observe_r010_private_owner_row(
        owner=owner, reservation=reservation, plan=proposed,
        worker_result=result, row=1, nonce_sha256="a" * 64)
    assert item.outcome == "ROW_AMBIGUOUS"


def test_forged_worker_output_complete_does_not_override_reader():
    _, owner, reservation, proposed, result = run_fake(both_eof=False)
    tampered = dict(result, output_complete=True)
    item = observe_r010_private_owner_row(
        owner=owner, reservation=reservation, plan=proposed,
        worker_result=tampered, row=1, nonce_sha256="a" * 64)
    assert item.outcome == "ROW_AMBIGUOUS"
    owner.close()


@pytest.mark.parametrize("row,nonce", [
    (0, "a" * 64), (7, "a" * 64), (1, "z" * 64),
    (1, "a" * 63), (True, "a" * 64),
])
def test_bad_row_identity_is_deny(row, nonce):
    _, owner, reservation, proposed, result = run_fake()
    with pytest.raises(R010OwnedRowDenied):
        observe_r010_private_owner_row(
            owner=owner, reservation=reservation, plan=proposed,
            worker_result=result, row=row, nonce_sha256=nonce)
    owner.close()


def test_wrong_reservation_or_workspace_identity_is_deny():
    _, owner, reservation, proposed, result = run_fake()
    with pytest.raises(R010OwnedRowDenied):
        observe_r010_private_owner_row(
            owner=DirectChildOwner(), reservation=reservation, plan=proposed,
            worker_result=result, row=1, nonce_sha256="a" * 64)
    with pytest.raises(R010OwnedRowDenied):
        observe_r010_private_owner_row(
            owner=owner, reservation=reservation,
            plan=replace(proposed, workspace="other"),
            worker_result=result, row=1, nonce_sha256="a" * 64)
    owner.close()


def _r010_pytest_plan():
    return LbeWorkPlan(
        workspace="py-direct", cwd="py-direct", runner="direct",
        runner_project="py-direct", timeout_seconds=2,
        requested_argv=("python", "-m", "pytest", "-q"),
        effective_argv=("python", "-m", "pytest", "-q"),
    )


@pytest.fixture
def r010_journal(tmp_path):
    import hashlib
    from gateway.lbe_r010_job_envelope import (
        R010JobKey, _create_once_in_pinned_anchor)
    from gateway.lbe_r010_serial_journal import R010SerialNonceJournal

    anchor = tmp_path / "job-anchor"
    anchor.mkdir(mode=0o700)
    fd = os.open(anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    key = R010JobKey(
        repo="chinanjjohn2012/mac-file-gateway", pr=114,
        workflow_id=145, workflow_path=".github/workflows/r010.yml",
        workflow_ref=("chinanjjohn2012/mac-file-gateway/"
                      ".github/workflows/r010.yml@refs/heads/main"),
        run_id=42640408843, run_attempt=1, check_run_id=129239691259,
        job_name="r010_preexec_hold", head_sha="a" * 40,
        design_id="MWE-LBE-R010-AUTHORITY-CHAIN-DESIGN-013-CANDIDATE",
        design_blob="f57e39543a6fe3d64fe99b8669fc7da854b93a64",
        owner_choice_comment_id=6740275850, host_option="A1",
        review_sequence_option="B1",
        state_domain="R010_EPHEMERAL_JOB_STATE_V1",
    )
    raw = tuple(f"{i:064x}" for i in range(1, 7))
    digests = tuple(
        hashlib.sha256(bytes.fromhex(n)).hexdigest() for n in raw)
    try:
        with _create_once_in_pinned_anchor(fd, key) as envelope:
            journal = R010SerialNonceJournal(
                envelope, six_nonce_sha256=digests)
            journal.burn_first_nonce(raw[0])
            yield anchor, envelope, journal, raw
    finally:
        os.close(fd)


@pytest.fixture
def r010_first_row_private_files(tmp_path):
    from gateway.lbe_r010_finite_integrity import observe_selected_source_files
    from gateway.lbe_r010_row_fs import observe_r010_private_tree

    selected = tmp_path / "selected"
    private = tmp_path / "private"
    selected.mkdir(mode=0o700)
    private.mkdir(mode=0o700)
    (selected / "main.py").write_text("x=1\n")
    sfd = os.open(selected, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    pfd = os.open(private, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        yield {
            "selected_root_fd": sfd,
            "selected_before": observe_selected_source_files(
                root_fd=sfd, relative_paths=("main.py",)),
            "private_root_fd": pfd,
            "private_before": observe_r010_private_tree(root_fd=pfd),
            "selected_path": selected, "private_path": private,
        }
    finally:
        os.close(sfd)
        os.close(pfd)


def _finalize_first_row(journal, files, *, exit_code=0, both_eof=True,
                        close_fails=False, tamper_result=None,
                        proposed_plan=None):
    proposed = _r010_pytest_plan() if proposed_plan is None else proposed_plan
    _, owner, reservation, plan_obj, result = run_fake(
        exit_code=exit_code, both_eof=both_eof,
        close_fails=close_fails, proposed_plan=proposed)
    if tamper_result:
        result = {**result, **tamper_result}
    try:
        return journal.finalize_first_row_from_actual_owner_source_only(
            owner=owner, reservation=reservation, plan=plan_obj,
            worker_result=result,
            selected_root_fd=files["selected_root_fd"],
            selected_before=files["selected_before"],
            private_root_fd=files["private_root_fd"],
            private_before=files["private_before"])
    finally:
        owner.close()


def _durable_failure(anchor, envelope):
    import json
    root = anchor / envelope.snapshot()["envelope_root_name"]
    return json.loads(
        (root / "command-journal" / "r010-row-failure.json").read_text())


def test_first_row_owner_plus_finite_source_persists_no_t1(
        r010_journal, r010_first_row_private_files):
    import json
    from gateway.lbe_r010_serial_journal import R010SerialAdmissionDenied

    anchor, env, journal, raw = r010_journal
    outcome = _finalize_first_row(journal, r010_first_row_private_files)
    assert outcome["status"] == "ROW_FINITE_ZERO_SOURCE_ONLY_NOT_PRODUCT_T1"
    assert outcome["next_row_allowed"] is False
    assert outcome["native_launch_allowed"] is False
    root = anchor / env.snapshot()["envelope_root_name"]
    record = json.loads(
        (root / "command-journal" / "row-01-source-only.json").read_text())
    assert record["row_positive_success"] is False
    assert record["original_exit_code"] == 0
    with pytest.raises(R010SerialAdmissionDenied, match="not implemented"):
        journal.begin_later_row(2, raw[1])
    with pytest.raises(R010SerialAdmissionDenied, match="consumed"):
        journal.finalize_first_row_from_actual_owner_source_only(
            owner=None, reservation=None, plan=_r010_pytest_plan(),
            worker_result={},
            selected_root_fd=r010_first_row_private_files["selected_root_fd"],
            selected_before=r010_first_row_private_files["selected_before"],
            private_root_fd=r010_first_row_private_files["private_root_fd"],
            private_before=r010_first_row_private_files["private_before"])


@pytest.mark.parametrize("exit_code,both_eof,close_fails,expected", [
    (3, True, False, "ROW_OBSERVED_NONZERO"),
    (0, False, False, "ROW_OBSERVED_ZERO_INVALID_OUTPUT_OR_FS"),
    (0, True, True, "ROW_AMBIGUOUS"),
])
def test_actual_worker_negative_latches_six_rows(
        r010_journal, r010_first_row_private_files,
        exit_code, both_eof, close_fails, expected):
    import json
    from gateway.lbe_r010_serial_journal import R010SerialAdmissionDenied

    anchor, env, journal, raw = r010_journal
    result = _finalize_first_row(
        journal, r010_first_row_private_files,
        exit_code=exit_code, both_eof=both_eof,
        close_fails=close_fails)
    assert result["status"] == expected
    assert result["durably_latched"] is True
    assert result["next_row_allowed"] is False
    record = _durable_failure(anchor, env)
    assert record["rows"] == [expected] + ["ROW_VOID"] * 5
    with pytest.raises(R010SerialAdmissionDenied):
        journal.begin_later_row(2, raw[1])


def test_private_source_drift_after_fake_child_latches_invalid(
        r010_journal, r010_first_row_private_files):
    anchor, env, journal, _ = r010_journal
    path = r010_first_row_private_files["selected_path"] / "main.py"
    path.write_text("x=2\n")
    result = _finalize_first_row(journal, r010_first_row_private_files)
    assert result["status"] == "ROW_OBSERVED_ZERO_INVALID_OUTPUT_OR_FS"
    assert _durable_failure(anchor, env)["reason"] == "invalid_output_or_fs"


@pytest.mark.parametrize("poison", [
    {"status": "timed_out", "timed_out": True},
    {"exit_code": 14}, {"pipe_reader_failed": True},
])
def test_forged_worker_result_is_ambiguous_not_a_positive_record(
        r010_journal, r010_first_row_private_files, poison):
    anchor, env, journal, _ = r010_journal
    result = _finalize_first_row(
        journal, r010_first_row_private_files, tamper_result=poison)
    assert result["status"] == "ROW_AMBIGUOUS"
    assert _durable_failure(anchor, env)["rows"][0] == "ROW_AMBIGUOUS"


def test_wrong_plan_fails_closed_before_owner_acceptance(
        r010_journal, r010_first_row_private_files):
    from gateway.lbe_r010_serial_journal import R010SerialAdmissionDenied

    anchor, env, journal, _ = r010_journal
    with pytest.raises(R010SerialAdmissionDenied, match="uncertain"):
        _finalize_first_row(
            journal, r010_first_row_private_files, proposed_plan=plan())
    assert _durable_failure(anchor, env)["rows"][0] == "ROW_AMBIGUOUS"
