"""Pure T0 tests for the unactivated bounded original-child pipe drainer.

Every descriptor and select/read operation is a fake in-memory object.
No Popen, real child, OS pipe, native signal or user Workspace is touched.
"""
from __future__ import annotations

from collections import deque
import os
import selectors
import subprocess
import threading
import time

import pytest

from gateway.lbe_output_capture import BoundedCapture
from gateway.lbe_direct_owner import DirectChildOwner, LbeOwnerError
from gateway.lbe_pipe_drain import BoundedPipeDrain, LbePipeError


class FakePipe:
    def __init__(self, fd):
        self.fd = fd
        self.closed = False
        self.close_count = 0

    def fileno(self):
        return self.fd

    def close(self):
        self.closed = True
        self.close_count += 1


class FakeKey:
    def __init__(self, fd, data):
        self.fd = fd
        self.data = data


class FakeSelector:
    def __init__(self):
        self.registered = {}
        self.pending = {}
        self.closed = False
        self._lock = threading.Lock()

    def register(self, fd, events, data):
        assert events == selectors.EVENT_READ
        with self._lock:
            if fd in self.registered:
                raise AssertionError("duplicate descriptor registration")
            self.registered[fd] = FakeKey(fd, data)
            self.pending[fd] = deque()

    def unregister(self, fd):
        with self._lock:
            return self.registered.pop(fd)

    def put(self, fd, chunk):
        with self._lock:
            self.pending[fd].append(chunk)

    def select(self, timeout):
        with self._lock:
            hits = [(key, selectors.EVENT_READ)
                    for fd, key in self.registered.items()
                    if self.pending[fd]]
        if not hits:
            time.sleep(min(timeout, 0.002))
        return hits

    def read(self, fd, n):
        assert n == 8192
        with self._lock:
            try:
                item = self.pending[fd].popleft()
            except IndexError:
                raise BlockingIOError() from None
        if isinstance(item, Exception):
            raise item
        assert type(item) is bytes
        return item

    def close(self):
        self.closed = True
        self.registered.clear()


def create(*, grace=0.06, fake=None, nonblocking=None, on_fault=None):
    sel = fake or FakeSelector()
    capture = BoundedCapture()
    call_log = []
    def set_flag(fd, is_blocking):
        call_log.append((fd, is_blocking))
        if nonblocking is not None:
            nonblocking(fd, is_blocking)
    drain = BoundedPipeDrain(
        capture, selector_factory=lambda: sel, read_fn=sel.read,
        set_nonblocking=set_flag, eof_grace=grace, on_fault=on_fault)
    return drain, sel, capture, call_log


def fake_pipes():
    return FakePipe(71), FakePipe(72)


def test_exact_eof_is_required_for_output_complete():
    drain, sel, capture, calls = create()
    stdout, stderr = fake_pipes()
    drain.attach(stdout, stderr)
    sel.put(71, b"STDOUT")
    sel.put(71, b"")
    sel.put(72, b"STDERR")
    sel.put(72, b"")
    assert drain.wait_finished(2)
    snapshot = drain.snapshot()
    assert "STDOUT" in snapshot["stdout"]
    assert "STDERR" in snapshot["stderr"]
    assert snapshot["output_complete"] is True
    assert snapshot["pipe_reader_failed"] is False
    assert snapshot["pipe_reader_finished"] is True
    assert calls == [(71, False), (72, False)]
    assert stdout.closed and stderr.closed and sel.closed
    assert capture.stored_bytes() == len(b"STDOUT") + len(b"STDERR")


def test_parent_exit_with_descendant_held_fds_finishes_on_grace_not_eof():
    drain, sel, _capture, _calls = create(grace=0.04)
    out, err = fake_pipes()
    drain.attach(out, err)
    sel.put(71, b"known prefix")
    deadline = time.monotonic() + 2
    while "known prefix" not in drain.snapshot()["stdout"] and time.monotonic() < deadline:
        time.sleep(0.002)
    assert "known prefix" in drain.snapshot()["stdout"]
    assert drain.snapshot()["output_complete"] is False
    drain.note_original_exit()  # fake witnessed parent exit only
    assert drain.wait_finished(2)
    assert drain.snapshot()["output_complete"] is False
    assert drain.snapshot()["pipe_reader_failed"] is False
    assert out.closed and err.closed and sel.closed
    assert not sel.registered


def test_timeout_waiter_does_not_stop_active_reader():
    drain, sel, capture, _calls = create()
    out, err = fake_pipes()
    drain.attach(out, err)
    assert not drain.wait_finished(0.015)
    assert drain.snapshot()["output_complete"] is False
    sel.put(71, b"output after waiter timeout")
    sel.put(71, b"")
    sel.put(72, b"")
    assert drain.wait_finished(2)
    assert "output after waiter timeout" in drain.snapshot()["stdout"]
    assert drain.snapshot()["output_complete"] is True
    assert capture.stored_bytes() == len(b"output after waiter timeout")


def test_very_large_output_is_drained_without_unbounded_retention():
    drain, sel, capture, _calls = create()
    out, err = fake_pipes()
    drain.attach(out, err)
    for _ in range(120):
        sel.put(71, b"x" * 8192)
        sel.put(72, b"y" * 8192)
    sel.put(71, b"")
    sel.put(72, b"")
    assert drain.wait_finished(5)
    snap = drain.snapshot()
    assert capture.stored_bytes() == 96000
    assert snap["stdout_truncated"] and snap["stderr_truncated"]
    assert snap["output_complete"] is True
    assert snap["pipe_reader_failed"] is False


def test_broken_read_latches_fault_and_does_not_claim_eof():
    drain, sel, _capture, _calls = create()
    out, err = fake_pipes()
    drain.attach(out, err)
    sel.put(71, OSError("simulated nonblocking read failure"))
    assert drain.wait_finished(2)
    assert drain.snapshot()["pipe_reader_failed"] is True
    assert drain.snapshot()["output_complete"] is False
    assert out.closed and err.closed


def test_both_fds_must_be_distinct_and_nonnegative():
    for fds in [(-1, 72), (71, -1), (71, 71)]:
        drain, _sel, _capture, _calls = create()
        out, err = FakePipe(fds[0]), FakePipe(fds[1])
        with pytest.raises(LbePipeError, match="pipe_setup_unavailable"):
            drain.attach(out, err)
        assert drain.snapshot()["pipe_reader_failed"] is True
        assert drain.wait_finished(0)
        assert out.closed and err.closed


def test_registration_or_set_nonblocking_failure_closes_owned_pipes():
    def deny(_fd, _enabled):
        raise OSError("fake not-blocking setup failure")
    drain, selector, _capture, _calls = create(nonblocking=deny)
    out, err = fake_pipes()
    with pytest.raises(LbePipeError, match="pipe_setup_unavailable"):
        drain.attach(out, err)
    assert drain.snapshot()["pipe_reader_failed"] is True
    assert drain.wait_finished(0)
    assert out.closed and err.closed and selector.closed


def test_reuse_and_double_attach_fail_closed():
    drain, sel, _capture, _calls = create()
    out, err = fake_pipes()
    drain.attach(out, err)
    with pytest.raises(LbePipeError, match="invalid_pipe_state"):
        drain.attach(FakePipe(81), FakePipe(82))
    sel.put(71, b"")
    sel.put(72, b"")
    assert drain.wait_finished(2)
    with pytest.raises(LbePipeError, match="invalid_pipe_state"):
        drain.attach(out, err)


def test_spawn_failed_preallocated_drain_has_no_reader_or_fd():
    drain, selector, _capture, _calls = create()
    drain.abandon_without_child()
    assert drain.wait_finished(0)
    assert selector.closed
    assert drain.snapshot()["pipe_reader_finished"] is True
    assert drain.snapshot()["output_complete"] is False
    with pytest.raises(LbePipeError, match="invalid_pipe_state"):
        drain.attach(*fake_pipes())


@pytest.mark.parametrize("value", [-1, 11, "1", None, True, float("nan")])
def test_wait_timeout_refuses_bad_types_and_nonfinite_values(value):
    drain, _sel, _capture, _calls = create()
    with pytest.raises(LbePipeError, match="invalid_argument"):
        drain.wait_finished(value)
    drain.abandon_without_child()


@pytest.mark.parametrize("value", [-1, 1.1, None, True, float("nan")])
def test_eof_grace_refuses_invalid_values(value):
    with pytest.raises(LbePipeError, match="invalid_eof_grace"):
        create(grace=value)


def test_pure_fake_pipe_drain_does_not_start_or_signal_native_process(monkeypatch):
    invoked = []
    def forbidden(*_args, **_kwargs):
        invoked.append(True)
        raise AssertionError("physical process or OS signal forbidden")
    with monkeypatch.context() as m:
        m.setattr(subprocess, "Popen", forbidden)
        m.setattr(os, "killpg", forbidden, raising=False)
        m.setattr(os, "kill", forbidden)
        drain, sel, _capture, _calls = create()
        out, err = fake_pipes()
        drain.attach(out, err)
        sel.put(71, b"plain fake output")
        sel.put(71, b"")
        sel.put(72, b"")
        assert drain.wait_finished(2)
        assert drain.snapshot()["output_complete"] is True
    assert invoked == []


class WaitableFakeOriginal:
    def __init__(self, code=0):
        self.ready = threading.Event()
        self.exit = threading.Event()
        self.code = code

    def wait(self):
        self.ready.set()
        if not self.exit.wait(timeout=5):
            raise RuntimeError("T0 original fake not released")
        return self.code


def owner_drain_pair(owner, name="a", *, grace=0.1):
    token = owner.reserve(name)
    drain, sel, _cap, _setflags = create(
        grace=grace,
        on_fault=lambda: owner.latch_unavailable(token))
    owner.prepare_pipe_drain(token, drain)
    drain.attach(*fake_pipes())
    child = WaitableFakeOriginal()
    owner.bind(token, child)
    assert child.ready.wait(2)
    return token, drain, sel, child


def test_direct_child_reaper_notifies_exact_original_exit_then_eof_grace():
    owner = DirectChildOwner()
    token, drain, sel, child = owner_drain_pair(owner, grace=0.04)
    sel.put(71, b"original output")
    deadline = time.monotonic() + 2
    while "original output" not in drain.snapshot()["stdout"] and time.monotonic() < deadline:
        time.sleep(0.002)
    assert "original output" in drain.snapshot()["stdout"]
    assert drain.snapshot()["output_complete"] is False
    child.exit.set()
    result = owner.observe(token, wait_seconds=2)
    assert result.status == "exited"
    assert result.exit_code == 0
    assert result.full_descendant_tree_clean == "not_proven"
    assert owner.snapshot()["reserved_slots"] == 0
    assert drain.wait_finished(2)
    state = drain.snapshot()
    assert state["pipe_reader_failed"] is False
    assert state["pipe_reader_finished"] is True
    assert state["output_complete"] is False
    assert owner.snapshot()["unavailable"] is False
    owner.close()


def test_async_read_fault_latches_service_without_signalling_orig_child():
    owner = DirectChildOwner()
    token, drain, sel, child = owner_drain_pair(owner)
    sel.put(71, OSError("T0 stream error"))
    assert drain.wait_finished(2)
    assert drain.snapshot()["pipe_reader_failed"] is True
    assert drain.snapshot()["output_complete"] is False
    assert owner.snapshot()["unavailable"] is True
    assert owner.snapshot()["running_direct_children"] == 1
    with pytest.raises(LbeOwnerError) as exc:
        owner.reserve("b")
    assert exc.value.code == "exec_state_unavailable"
    child.exit.set()
    assert owner.observe(token, wait_seconds=2).status == "exited"
    assert owner.snapshot()["unavailable"] is True
    owner.close()


def test_postspawn_pipe_attachment_failure_does_not_release_original_slot():
    owner = DirectChildOwner()
    token = owner.reserve("a")
    drain, _sel, _cap, _flag = create(
        on_fault=lambda: owner.latch_unavailable(token))
    owner.prepare_pipe_drain(token, drain)
    # Bind the original child and preallocated reaper immediately after spawn;
    # a subsequent pipe attachment failure MUST NOT stop wait()/reaping.
    child = WaitableFakeOriginal()
    owner.bind(token, child)
    assert child.ready.wait(2)
    with pytest.raises(LbePipeError, match="pipe_setup_unavailable"):
        drain.attach(FakePipe(71), FakePipe(71))
    assert owner.snapshot()["unavailable"] is True
    assert owner.snapshot()["reserved_slots"] == 1
    with pytest.raises(LbeOwnerError, match="exec_state_unavailable"):
        owner.reserve("b")
    child.exit.set()
    assert owner.observe(token, wait_seconds=2).status == "exited"
    assert owner.snapshot()["reserved_slots"] == 0
    assert owner.snapshot()["unavailable"] is True
    owner.close()


def test_no_spawn_releases_preallocated_reader_and_original_slot():
    owner = DirectChildOwner()
    token = owner.reserve("a")
    drain, sel, _cap, _calls = create()
    owner.prepare_pipe_drain(token, drain)
    owner.spawn_failed(token)
    assert drain.wait_finished(0)
    assert sel.closed
    assert owner.snapshot()["reserved_slots"] == 0
    owner.close()


def test_retired_eof_grace_readers_are_separately_bounded():
    owner = DirectChildOwner()
    readers = []
    for name in ("a", "b", "c", "d"):
        token, drain, sel, child = owner_drain_pair(owner, name, grace=0.5)
        child.exit.set()
        assert owner.observe(token, wait_seconds=2).status == "exited"
        readers.append(drain)
    assert owner.snapshot()["reserved_slots"] == 0
    with pytest.raises(LbeOwnerError, match="busy"):
        owner.reserve("e")
    assert all(drain.wait_finished(2) for drain in readers)
    token = owner.reserve("e")
    owner.spawn_failed(token)
    assert owner.snapshot()["unavailable"] is False
    owner.close()


def test_read_completion_before_parent_exit_does_not_reserve_retired_reader():
    owner = DirectChildOwner()
    token, drain, sel, child = owner_drain_pair(owner, grace=0.2)
    sel.put(71, b"")
    sel.put(72, b"")
    assert drain.wait_finished(2)
    assert drain.snapshot()["output_complete"] is True
    child.exit.set()
    assert owner.observe(token, wait_seconds=2).status == "exited"
    token2 = owner.reserve("a")
    owner.spawn_failed(token2)
    owner.close()



@pytest.mark.parametrize("caller_callback", ["none", "raises"])
def test_owner_fault_latch_is_mandatory_even_without_caller_callback(caller_callback):
    owner = DirectChildOwner()
    token = owner.reserve("a")

    def caller_failure():
        raise RuntimeError("optional observer failure")

    callback = caller_failure if caller_callback == "raises" else None
    drain, _sel, _capture, _calls = create(on_fault=callback)
    owner.prepare_pipe_drain(token, drain)
    # Simulated post-spawn pipe setup fault must not free the reservation,
    # and cannot be suppressed by a missing or throwing optional callback.
    with pytest.raises(LbePipeError, match="pipe_setup_unavailable"):
        drain.attach(FakePipe(71), FakePipe(71))
    assert owner.snapshot()["unavailable"] is True
    assert owner.snapshot()["reserved_slots"] == 1
    with pytest.raises(LbeOwnerError, match="exec_state_unavailable"):
        owner.reserve("b")
    owner.close()


def test_selector_is_closed_if_preallocated_reader_thread_construction_fails(monkeypatch):
    from gateway import lbe_pipe_drain as pipe_module

    selector = FakeSelector()
    def fail_thread(*args, **kwargs):
        raise RuntimeError("preallocated thread failure")

    with monkeypatch.context() as m:
        m.setattr(pipe_module.threading, "Thread", fail_thread)
        with pytest.raises(LbePipeError, match="pipe_setup_unavailable"):
            BoundedPipeDrain(BoundedCapture(), selector_factory=lambda: selector)
    assert selector.closed is True


def test_fault_latch_cannot_be_registered_after_reader_started():
    drain, sel, _capture, _calls = create()
    drain.attach(*fake_pipes())
    with pytest.raises(LbePipeError, match="invalid_pipe_state"):
        drain.add_fault_callback(lambda: None)
    sel.put(71, b"")
    sel.put(72, b"")
    assert drain.wait_finished(2)
    assert drain.snapshot()["output_complete"] is True

