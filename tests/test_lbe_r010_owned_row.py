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


def run_fake(*, exit_code=0, both_eof=True, close_fails=False):
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
    proposed = plan()
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
