"""Real concurrent admission/state logic; no simulated process can escape tests."""
import asyncio
import copy
import gc
import subprocess
import sys
import threading
import weakref
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest
from gateway.core import GatewayError
from gateway.exec_contracts import ExecutionIntent, ExecutionOutcome, parse_execution_request


def intent(workspace="a", **extra):
    request = parse_execution_request({"workspace": workspace, "cwd": "service", "argv": ["pytest"], "dry_run": False, **extra})
    return ExecutionIntent(request, "service", "auto", None)


def registry(**kwargs):
    from gateway.exec_registry import ExecRegistry
    return ExecRegistry(**kwargs)


ABANDONED = ExecutionOutcome(None, False, "abandoned")
DONE = ExecutionOutcome(0, False, None)


def test_one_per_workspace_and_four_global():
    r = registry()
    leases = [r.reserve(intent(w)) for w in "abcd"]
    for w in ("a", "e"):
        with pytest.raises(GatewayError) as error:
            r.reserve(intent(w))
        assert error.value.code == "exec_busy"
    assert r.snapshot().active_total == 4
    assert dict(r.snapshot().workspace_counts) == dict.fromkeys("abcd", 1)
    r.finish(leases[0], ABANDONED)
    other = r.reserve(intent("e"))
    assert r.snapshot().active_total == 4
    for lease in [*leases[1:], other]:
        r.finish(lease, ABANDONED)
    assert r.snapshot().active_total == 0


def test_dry_run_never_reserves():
    r = registry()
    with pytest.raises(GatewayError):
        r.reserve(intent(dry_run=True))
    assert r.snapshot().active_total == 0


def test_concurrent_reserve_is_atomic():
    r = registry()
    barrier = threading.Barrier(3)
    accepted, rejected = [], []
    def worker():
        barrier.wait(timeout=3)
        try:
            accepted.append(r.reserve(intent()))
        except GatewayError as error:
            rejected.append(error.code)
    threads = [threading.Thread(target=worker) for _ in range(2)]
    for thread in threads:
        thread.start()
    barrier.wait(timeout=3)
    for thread in threads:
        thread.join(timeout=3)
        assert not thread.is_alive()
    assert len(accepted) == 1 and rejected == ["exec_busy"]
    r.finish(accepted[0], ABANDONED)


def test_duplicate_finish_does_not_release_successor():
    r = registry()
    old = r.reserve(intent())
    r.finish(old, ABANDONED)
    new = r.reserve(intent())
    r.finish(old, ABANDONED)
    assert new.ticket_id != old.ticket_id
    assert r.snapshot().active_total == 1
    with pytest.raises(GatewayError):
        r.record_attempt(old)
    r.finish(new, ABANDONED)


def test_foreign_lease_cannot_release():
    a, b = registry(), registry()
    x, y = a.reserve(intent()), b.reserve(intent())
    for bogus in (y, copy.copy(x), x.ticket_id, None):
        with pytest.raises(GatewayError) as error:
            a.finish(bogus, ABANDONED)
        assert error.value.code == "invalid_argument"
    assert a.snapshot().active_total == b.snapshot().active_total == 1
    a.finish(x, ABANDONED)
    b.finish(y, ABANDONED)


def test_attempt_recorded_at_most_once():
    r = registry()
    lease = r.reserve(intent())
    r.record_attempt(lease)
    with pytest.raises(GatewayError) as error:
        r.record_attempt(lease)
    assert error.value.code == "exec_state"
    r.record_started(lease)
    r.finish(lease, DONE)


def test_waiter_cancel_does_not_finish_owner():
    r = registry()
    owner_ready, finish_owner = threading.Event(), threading.Event()
    lease = r.reserve(intent())
    def owner():
        r.record_attempt(lease)
        r.record_started(lease)
        owner_ready.set()
        assert finish_owner.wait(timeout=3)
        r.finish(lease, DONE)
    thread = threading.Thread(target=owner)
    thread.start()
    try:
        assert owner_ready.wait(timeout=3)
        async def cancel_waiter():
            entered, completed = asyncio.Event(), asyncio.Event()
            async def waiter():
                entered.set()
                await completed.wait()
            task = asyncio.create_task(waiter())
            await entered.wait()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        asyncio.run(cancel_waiter())
        # Only the independent owner may release after this real cancellation.
        assert r.snapshot().active_total == 1
        with pytest.raises(GatewayError):
            r.reserve(intent())
    finally:
        finish_owner.set()
        thread.join(timeout=3)
    assert not thread.is_alive() and r.snapshot().active_total == 0


def test_timeout_requests_stop_without_pretending_reaped():
    now = [10.0]
    r = registry(clock=lambda: now[0])
    lease = r.reserve(intent(timeout_seconds=1))
    r.record_attempt(lease)
    now[0] = 100.0
    assert r.mark_expired() == ()  # STARTING has no execution clock yet.
    r.record_started(lease)
    now[0] = 100.999
    assert r.mark_expired() == ()
    now[0] = 101.0
    assert r.mark_expired() == (lease.ticket_id,)
    assert r.mark_expired() == ()
    assert r.snapshot().active_total == 1
    r.finish(lease, ExecutionOutcome(None, True, None))
    assert r.snapshot().active_total == 0


def test_close_vs_reserve_has_single_order():
    r = registry()
    barrier = threading.Barrier(3)
    results = []
    def reserve():
        barrier.wait(timeout=3)
        try:
            results.append(r.reserve(intent()))
        except GatewayError as e:
            results.append(e.code)
    def close():
        barrier.wait(timeout=3)
        r.begin_close()
    threads = [threading.Thread(target=reserve), threading.Thread(target=close)]
    for t in threads:
        t.start()
    barrier.wait(timeout=3)
    for t in threads:
        t.join(timeout=3)
        assert not t.is_alive()
    assert r.snapshot().closing
    if results[0] != "service_closing":
        r.finish(results[0], ABANDONED)
    with pytest.raises(GatewayError) as e:
        r.reserve(intent())
    assert e.value.code == "service_closing"
    r.wait_idle()


def test_finished_records_do_not_grow():
    r = registry()
    refs = []
    for _ in range(200):
        lease = r.reserve(intent())
        refs.append(weakref.ref(lease))
        r.finish(lease, ABANDONED)
    del lease
    gc.collect()
    assert all(ref() is None for ref in refs)
    assert r.snapshot().active_total == 0


def test_original_quota_is_preserved_after_all_failure_paths():
    r = registry()
    lease = r.reserve(intent())
    with pytest.raises(GatewayError):
        r.record_started(lease)
    with pytest.raises(GatewayError):
        r.finish(lease, object())
    assert r.snapshot().active_total == 1
    r.record_attempt(lease)
    r.finish(lease, ExecutionOutcome(None, False, "spawn_failed"))
    assert r.snapshot().active_total == 0


def test_snapshot_and_lease_are_read_only():
    r = registry()
    lease = r.reserve(intent())
    with pytest.raises(FrozenInstanceError):
        lease.workspace = "b"
    with pytest.raises(FrozenInstanceError):
        r.snapshot().active_total = 0
    r.finish(lease, ABANDONED)


def test_request_stop_is_owner_bound_and_idempotent():
    r = registry()
    lease = r.reserve(intent())
    r.record_attempt(lease)
    r.record_started(lease)
    r.request_stop(lease, "shutdown")
    r.request_stop(lease, "shutdown")
    assert r.snapshot().active_total == 1
    with pytest.raises(GatewayError):
        r.request_stop(lease, "client_cancel")
    r.finish(lease, ExecutionOutcome(None, False, "shutdown"))


def test_registry_imports_no_sdk_or_process_backend():
    # This test subprocess is an import probe, not an execution task.
    code = '''import builtins
real_import = builtins.__import__
def guarded(name, *args, **kwargs):
    if name.split(".")[0] in {"mcp", "subprocess", "ctypes"}:
        raise AssertionError("registry imports forbidden backend: " + name)
    return real_import(name, *args, **kwargs)
builtins.__import__ = guarded
from gateway.exec_registry import ExecRegistry
assert ExecRegistry().snapshot().active_total == 0
'''
    result = subprocess.run([sys.executable, "-c", code], cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
