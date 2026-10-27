"""R2-S r002: reviewer-derived isolated T0/T1 negatives, no process launch.

All paths are caller-owned pytest disposable roots. No Native OS signal, crash,
production config, persistent home-state migration or positive Exec routing.
"""
import json
import os
from pathlib import Path

import pytest

from gateway.r2s_state_s2 import S2PrivateState, S2Blocked, S2Unavailable


@pytest.fixture
def sandbox(tmp_path):
    private = tmp_path / "private"
    workspace = tmp_path / "workspace"
    private.mkdir(mode=0o700)
    workspace.mkdir(mode=0o700)
    root = private / "exec-state-s2-candidate"
    return root, workspace


def owner(sandbox):
    root, workspace = sandbox
    return S2PrivateState(root, workspace_root=workspace)


def state_bytes(sandbox):
    return (sandbox[0] / "state-v2.json").read_bytes()


def test_r002_missing_lock_with_valid_state_never_recreated(sandbox):
    with owner(sandbox) as first:
        first.approve_fake()
    root, _ = sandbox
    baseline = state_bytes(sandbox)
    (root / "owner.lock").unlink()
    with pytest.raises((S2Blocked, S2Unavailable)):
        owner(sandbox)
    assert not (root / "owner.lock").exists()
    assert state_bytes(sandbox) == baseline


def test_r002_same_name_replaced_lock_never_borrows_old_flock(sandbox):
    root, _ = sandbox
    with owner(sandbox) as first:
        first.approve_fake()
        lock = root / "owner.lock"
        old_ino = os.fstat(first._lock_fd).st_ino
        lock.rename(root.parent / "preserved-owner-lock")
        with lock.open("wb"):
            pass
        os.chmod(lock, 0o600)
        assert lock.stat().st_ino != old_ino
        with pytest.raises((S2Blocked, S2Unavailable)):
            owner(sandbox)
        with pytest.raises((S2Blocked, S2Unavailable)):
            first.prepare_offline()
    assert json.loads(state_bytes(sandbox))["owner_active"] is True


def test_r002_unqualified_limited_shape_denied_without_rewrite(sandbox):
    with owner(sandbox) as first:
        first.approve_fake()
        ticket = first.prepare_offline()
    path = sandbox[0] / "state-v2.json"
    obj = json.loads(path.read_bytes())
    record = obj["attempts"][ticket.attempt_id]
    record["phase"] = "RETIRED_LIMITED"
    record["cleanup_scope"] = "original_group_only"
    path.write_text(json.dumps(obj, sort_keys=True) + "\n")
    before = path.read_bytes()
    with pytest.raises((S2Blocked, S2Unavailable)):
        owner(sandbox)
    assert path.read_bytes() == before


def test_r002_pending_create_enospc_does_not_resurrect_consent(sandbox, monkeypatch):
    import gateway.r2s_state_s2 as mod
    with owner(sandbox) as first:
        first.approve_fake()
        before = state_bytes(sandbox)
        old_open = os.open
        def denied(name, *args, **kwargs):
            if isinstance(name, str) and name.startswith("pending-"):
                raise OSError(28, "isolated ENOSPC before journal marker")
            return old_open(name, *args, **kwargs)
        with monkeypatch.context() as m:
            m.setattr(mod.os, "open", denied)
            with pytest.raises(S2Unavailable):
                first.revoke_fake()
        assert first.status == "unavailable"
        assert state_bytes(sandbox) == before
        assert not any(p.name.startswith("pending-") for p in sandbox[0].iterdir())
    with owner(sandbox) as fresh:
        assert fresh.status == "quarantined"
        assert fresh.snapshot()["quarantined"]
        assert not fresh.snapshot()["consent_active"]
        with pytest.raises(S2Blocked):
            fresh.prepare_offline()


def test_r002_healthy_clean_owner_close_keeps_approved_epoch(sandbox):
    with owner(sandbox) as first:
        first.approve_fake()
        old = first.snapshot()
        assert old["owner_active"] is True
    assert json.loads(state_bytes(sandbox))["owner_active"] is False
    with owner(sandbox) as fresh:
        current = fresh.snapshot()
        assert fresh.status == "healthy"
        assert current["consent_active"]
        assert current["consent_epoch"] == old["consent_epoch"]
        assert current["owner_generation"] != old["owner_generation"]
        assert current["owner_active"] is True


def test_r002_late_attributed_after_quarantined_restart_persisted(sandbox):
    with owner(sandbox) as first:
        first.approve_fake()
        ticket = first.prepare_offline()
    with owner(sandbox) as second:
        assert second.status == "quarantined"
        assert second.snapshot()["attempts"][ticket.attempt_id]["phase"] == "UNKNOWN"
        second.late_positive_fake(ticket)
        assert second.snapshot()["attempts"][ticket.attempt_id]["late_positive"]
        with pytest.raises(S2Blocked):
            second.prepare_offline()
    with owner(sandbox) as third:
        assert third.status == "quarantined"
        assert third.snapshot()["attempts"][ticket.attempt_id]["late_positive"]


def test_r002_late_orphan_after_quarantine_never_unquarantines(sandbox):
    with owner(sandbox) as first:
        first.approve_fake()
        first.prepare_offline()
    with owner(sandbox) as second:
        assert second.status == "quarantined"
        second.late_positive_fake(None)
        assert second.snapshot()["orphan_positive"] is True
        assert second.status == "quarantined"
    with owner(sandbox) as third:
        assert third.status == "quarantined"
        assert third.snapshot()["orphan_positive"] is True


def test_r002_failed_late_append_does_not_erase_quarantine(sandbox):
    with owner(sandbox) as first:
        first.approve_fake()
        ticket = first.prepare_offline()
    with owner(sandbox) as later:
        assert later.status == "quarantined"
        later._fault_at = "after_pending"  # T1 controlled file-write fault, no crash
        with pytest.raises(S2Unavailable):
            later.late_positive_fake(ticket)
        assert later.status == "unavailable"
    with pytest.raises((S2Blocked, S2Unavailable)):
        owner(sandbox)


def test_r002_failed_seal_before_pending_keeps_reboot_fenced(sandbox, monkeypatch):
    import gateway.r2s_state_s2 as mod
    first = owner(sandbox)
    first.approve_fake()
    old_open = os.open
    def denied(name, *args, **kwargs):
        if isinstance(name, str) and name.startswith("pending-"):
            raise OSError(28, "isolated ENOSPC before clean seal")
        return old_open(name, *args, **kwargs)
    with monkeypatch.context() as m:
        m.setattr(mod.os, "open", denied)
        first.close()
    assert first.status == "unavailable"
    assert json.loads(state_bytes(sandbox))["owner_active"] is True
    with owner(sandbox) as second:
        assert second.status == "quarantined"
        with pytest.raises(S2Blocked):
            second.prepare_offline()


def test_r002_legacy_s2_schema_never_migrates_silently(sandbox):
    with owner(sandbox):
        pass
    path = sandbox[0] / "state-v2.json"
    obj = json.loads(path.read_bytes())
    del obj["owner_active"]
    path.write_text(json.dumps(obj) + "\n")
    before = path.read_bytes()
    with pytest.raises((S2Blocked, S2Unavailable)):
        owner(sandbox)
    assert path.read_bytes() == before
