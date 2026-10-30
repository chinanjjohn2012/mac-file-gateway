"""T0 fake-original-child lifecycle contracts for dormant LBE owner.

No native Popen, subprocess, OS signal, child process or durable state writes.
These prove only the in-memory lease/reaper behavior under deterministic fakes.
"""
from __future__ import annotations

import os
import subprocess
import threading

import pytest

from gateway.lbe_direct_owner import DirectChildOwner, LbeOwnerError


class FakeChild:
    def __init__(self, code=0):
        self.entered = threading.Event()
        self.exit = threading.Event()
        self.code = code
        self.calls = 0

    def wait(self):
        self.calls += 1
        self.entered.set()
        if not self.exit.wait(timeout=10):
            raise RuntimeError("test fake not released in time")
        return self.code


class BadWaitChild:
    def wait(self):
        raise RuntimeError("original child wait failed")


def finish(owner, token, child):
    child.exit.set()
    observed = owner.observe(token, wait_seconds=5)
    assert observed.status == "exited"
    return observed


def code(exc):
    return exc.value.code


def test_reservation_before_spawn_and_failed_spawn_releases_slot():
    owner = DirectChildOwner()
    slot = owner.reserve("a")
    assert owner.snapshot() == {
        "running_direct_children": 0, "reserved_slots": 1,
        "capacity_exhausted": False, "unavailable": False, "closing": False,
    }
    with pytest.raises(LbeOwnerError, match="busy"):
        owner.reserve("a")
    owner.spawn_failed(slot)
    assert owner.snapshot()["reserved_slots"] == 0
    assert owner.reserve("a") is not slot
    owner.close()


@pytest.mark.parametrize("exit_code", [0, 1, -9, 255])
def test_direct_exit_is_not_descendant_cleanup(exit_code):
    owner = DirectChildOwner()
    child = FakeChild(exit_code)
    slot = owner.reserve("workspace")
    owner.bind(slot, child)
    assert child.entered.wait(2)
    timed = owner.observe(slot, wait_seconds=0)
    assert timed.status == "timed_out"
    assert timed.timed_out is True
    assert timed.exit_code is None
    assert timed.process_may_be_running is True
    assert timed.cleanup_proven is False
    assert timed.full_descendant_tree_clean == "not_proven"
    with pytest.raises(LbeOwnerError) as error:
        owner.reserve("workspace")
    assert code(error) == "busy"
    exited = finish(owner, slot, child)
    assert exited.exit_code == exit_code
    assert exited.status == "exited"
    assert exited.timed_out is False
    assert exited.process_may_be_running is True
    assert exited.cleanup_proven is False
    assert exited.full_descendant_tree_clean == "not_proven"
    assert child.calls == 1
    assert owner.snapshot()["running_direct_children"] == 0
    assert owner.snapshot()["reserved_slots"] == 0
    owner.close()


def test_capacity_is_one_per_workspace_and_four_per_service():
    owner = DirectChildOwner()
    children = []
    for name in ("a", "b", "c", "d"):
        child = FakeChild()
        slot = owner.reserve(name)
        owner.bind(slot, child)
        children.append((slot, child))
    assert all(child.entered.wait(2) for _slot, child in children)
    status = owner.snapshot()
    assert status["running_direct_children"] == 4
    assert status["reserved_slots"] == 4
    assert status["capacity_exhausted"] is True
    for name in ("a", "e"):
        with pytest.raises(LbeOwnerError) as error:
            owner.reserve(name)
        assert code(error) == "busy"

    first_slot, first_child = children[0]
    finish(owner, first_slot, first_child)
    assert owner.snapshot()["running_direct_children"] == 3
    replacement = owner.reserve("e")
    owner.spawn_failed(replacement)
    for slot, child in children[1:]:
        finish(owner, slot, child)
    assert owner.snapshot()["reserved_slots"] == 0
    owner.close()


def test_disconnect_does_not_release_slot_or_claim_ack():
    owner = DirectChildOwner()
    slot = owner.reserve("a")
    child = FakeChild()
    owner.bind(slot, child)
    assert child.entered.wait(2)
    assert owner.detach_waiter(slot) is None
    with pytest.raises(LbeOwnerError) as error:
        owner.observe(slot, wait_seconds=0)
    assert code(error) == "waiter_disconnected"
    with pytest.raises(LbeOwnerError) as error:
        owner.reserve("a")
    assert code(error) == "busy"
    child.exit.set()
    # The original child exit alone releases its slot, independent of waiter.
    slot.waiter.join(timeout=2)
    assert not slot.waiter.is_alive()
    assert owner.snapshot()["reserved_slots"] == 0
    assert owner.snapshot()["unavailable"] is False
    owner.close()


def test_close_denies_new_reservations_without_waiting_or_killing_direct_child():
    owner = DirectChildOwner()
    slot = owner.reserve("a")
    child = FakeChild()
    owner.bind(slot, child)
    assert child.entered.wait(2)
    assert owner.close() is None
    assert owner.snapshot()["closing"] is True
    assert owner.snapshot()["running_direct_children"] == 1
    with pytest.raises(LbeOwnerError) as error:
        owner.reserve("b")
    assert code(error) == "service_closing"
    assert finish(owner, slot, child).status == "exited"
    assert owner.snapshot()["running_direct_children"] == 0


def test_unavailable_reaper_refuses_future_admission_without_releasing_slot():
    owner = DirectChildOwner()
    slot = owner.reserve("a")
    owner.bind(slot, BadWaitChild())
    slot.waiter.join(timeout=2)
    assert not slot.waiter.is_alive()
    assert owner.snapshot()["unavailable"] is True
    assert owner.snapshot()["reserved_slots"] == 1
    assert owner.snapshot()["running_direct_children"] == 1
    with pytest.raises(LbeOwnerError) as error:
        owner.observe(slot, wait_seconds=0)
    assert code(error) == "exec_state_unavailable"
    with pytest.raises(LbeOwnerError) as error:
        owner.reserve("b")
    assert code(error) == "exec_state_unavailable"
    owner.close()


@pytest.mark.parametrize("bad_code", [None, True, "0", 1.2])
def test_invalid_wait_result_is_not_treated_as_exit(bad_code):
    owner = DirectChildOwner()
    child = FakeChild(code=bad_code)
    slot = owner.reserve("a")
    owner.bind(slot, child)
    child.exit.set()
    slot.waiter.join(timeout=2)
    assert not slot.waiter.is_alive()
    assert owner.snapshot()["unavailable"] is True
    assert owner.snapshot()["reserved_slots"] == 1
    owner.close()


def test_failed_reaper_allocation_denies_without_slot_or_child(monkeypatch):
    from gateway import lbe_direct_owner as module

    owner = DirectChildOwner()

    def cannot_allocate(*args, **kwargs):
        raise RuntimeError("thread resource exhaustion")

    monkeypatch.setattr(module.threading, "Thread", cannot_allocate)
    with pytest.raises(LbeOwnerError) as error:
        owner.reserve("a")
    assert code(error) == "exec_state_unavailable"
    assert owner.snapshot()["reserved_slots"] == 0
    assert owner.snapshot()["unavailable"] is True
    owner.close()


def test_reaper_start_failure_after_child_preserves_uncertain_slot(monkeypatch):
    owner = DirectChildOwner()
    slot = owner.reserve("a")
    child = FakeChild()
    monkeypatch.setattr(slot.waiter, "start",
                        lambda: (_ for _ in ()).throw(RuntimeError("no thread")))
    with pytest.raises(LbeOwnerError) as error:
        owner.bind(slot, child)
    assert code(error) == "exec_state_unavailable"
    assert owner.snapshot()["reserved_slots"] == 1
    assert owner.snapshot()["unavailable"] is True
    assert child.calls == 0
    assert slot.phase == "UNREAPABLE"
    owner.close()


def test_malformed_postspawn_child_latches_unavailable_without_signals():
    owner = DirectChildOwner()
    slot = owner.reserve("a")
    with pytest.raises(LbeOwnerError) as error:
        owner.bind(slot, object())
    assert code(error) == "exec_state_unavailable"
    assert owner.snapshot()["unavailable"] is True
    assert owner.snapshot()["reserved_slots"] == 1
    owner.close()


def test_rejected_foreign_token_and_illegal_state_transitions():
    owner = DirectChildOwner()
    second = DirectChildOwner()
    token = owner.reserve("a")
    with pytest.raises(LbeOwnerError, match="invalid_reservation"):
        second.bind(token, FakeChild())
    with pytest.raises(LbeOwnerError, match="invalid_reservation"):
        owner.observe(token, wait_seconds=0)
    with pytest.raises(LbeOwnerError, match="invalid_reservation"):
        owner.detach_waiter(token)
    owner.spawn_failed(token)
    with pytest.raises(LbeOwnerError, match="invalid_reservation"):
        owner.spawn_failed(token)
    owner.close()
    second.close()


@pytest.mark.parametrize("value", [-1, 301, None, True, "1", float("nan"),
                                   float("inf")])
def test_wait_timeout_rejects_invalid_number(value):
    owner = DirectChildOwner()
    token = owner.reserve("a")
    child = FakeChild()
    owner.bind(token, child)
    with pytest.raises(LbeOwnerError) as error:
        owner.observe(token, wait_seconds=value)
    assert code(error) == "invalid_argument"
    finish(owner, token, child)
    owner.close()


def test_forked_process_latches_without_claiming_inherited_child(monkeypatch):
    from gateway import lbe_direct_owner as module

    owner = DirectChildOwner()
    assert owner.snapshot()["unavailable"] is False
    old_pid = os.getpid()
    with monkeypatch.context() as m:
        m.setattr(module.os, "getpid", lambda: old_pid + 10000)
        assert owner.snapshot()["unavailable"] is True
        with pytest.raises(LbeOwnerError) as error:
            owner.reserve("a")
        assert code(error) == "exec_state_unavailable"
    # Never auto-unquarantine after a possibly unsafe fork observation.
    assert owner.snapshot()["unavailable"] is True
    owner.close()


def test_no_subprocess_or_unsafe_signal_in_fake_lifecycle(monkeypatch):
    calls = []

    def forbidden(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("owner must not spawn or signal process")

    owner = DirectChildOwner()
    token = owner.reserve("a")
    child = FakeChild()
    with monkeypatch.context() as m:
        m.setattr(subprocess, "Popen", forbidden)
        m.setattr(os, "kill", forbidden)
        m.setattr(os, "killpg", forbidden, raising=False)
        owner.bind(token, child)
        assert child.entered.wait(2)
        assert owner.observe(token, wait_seconds=0).timed_out
        assert finish(owner, token, child).status == "exited"
    assert calls == []
    owner.close()

