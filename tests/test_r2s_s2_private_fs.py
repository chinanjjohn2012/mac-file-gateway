"""R2-S S2 T0/T1: real disposable private FS, NO spawned Exec or signals.

The tests own every path under pytest's temporary root.  This candidate is
not wired to a real Gateway, local consent, worker, Native backend or user Mac.
"""
from __future__ import annotations

from copy import deepcopy
import json
import os
from pathlib import Path
import stat
import threading

import pytest

from gateway.r2s_state_s2 import (
    OfflineTicket, S2Blocked, S2NonspawningCoordinator,
    S2PrivateState, S2Unavailable,
)


@pytest.fixture
def isolated(tmp_path):
    base = tmp_path.resolve()
    work = base / "workspace"
    private = base / "private"
    work.mkdir(mode=0o700)
    private.mkdir(mode=0o700)
    return private / "exec-state-s2-candidate", work


def open_s2(isolated, **kw):
    root, workspace = isolated
    return S2PrivateState(root, workspace_root=workspace, **kw)


def stored(isolated):
    root, _ = isolated
    return (root / "state-v2.json").read_bytes()


def test_s2_real_fs_initializes_private_v2_owner_and_no_positive_backend(isolated):
    root, _ = isolated
    with open_s2(isolated) as s:
        assert s.status == "healthy"
        v = s.snapshot()
        assert v["schema_version"] == 2
        assert v["consent_epoch"] == 0
        assert not v["consent_active"]
        assert not v["attempts"] and not v["quarantined"]
        assert set(p.name for p in root.iterdir()) == {"owner.lock", "state-v2.json"}
        for name in ("owner.lock", "state-v2.json"):
            assert stat.S_IMODE((root / name).stat().st_mode) == 0o600
        assert stat.S_IMODE(root.stat().st_mode) == 0o700
        with pytest.raises(S2Blocked, match="exec_cleanup_proof_required"):
            S2NonspawningCoordinator().deny_apply(s, profile="native_limited")
        assert s.snapshot() == v


def test_s2_real_owner_lock_rejects_two_instances_then_releases(isolated):
    first = open_s2(isolated)
    with pytest.raises(S2Unavailable):
        open_s2(isolated)
    assert first.status == "healthy"
    first.close()
    with open_s2(isolated) as later:
        assert later.status == "healthy"


def test_s2_clean_restart_rotates_owner_but_keeps_fake_consent(isolated):
    with open_s2(isolated) as s:
        s.approve_fake()
        before = s.snapshot()
        assert before["consent_active"] and before["consent_epoch"] == 1
    with open_s2(isolated) as again:
        after = again.snapshot()
        assert again.status == "healthy"
        assert after["owner_generation"] != before["owner_generation"]
        assert after["consent_epoch"] == before["consent_epoch"]
        assert after["binding"] == before["binding"]
        ticket = again.prepare_offline()
        assert ticket.owner_generation == after["owner_generation"]
        assert again.snapshot()["attempts"][ticket.attempt_id]["phase"] == "PREPARED"
    with open_s2(isolated) as restarted:
        assert restarted.status == "quarantined"
        with pytest.raises(S2Blocked):
            restarted.prepare_offline()
        assert restarted.snapshot()["attempts"][ticket.attempt_id]["phase"] == "UNKNOWN"  # old owner cannot preserve live PREPARED


def test_s2_reapproval_with_outstanding_prepared_fences_prior_ticket(isolated):
    # Re-consent is a different epoch and may not grandfather an old PREPARED
    # record. Persist UNKNOWN/quarantine even though nothing can spawn here.
    with open_s2(isolated) as s:
        s.approve_fake()
        old = s.prepare_offline()
        with pytest.raises(S2Blocked, match="unresolved|prepared|fenced"):
            s.approve_fake()
        v = s.snapshot()
        assert v["consent_epoch"] == 2
        assert not v["consent_active"]
        assert v["quarantined"]
        assert v["attempts"][old.attempt_id]["phase"] == "UNKNOWN"
        assert v["attempts"][old.attempt_id]["token"] == old.token
        with pytest.raises(S2Blocked):
            s.prepare_offline()
    with open_s2(isolated) as s:
        assert s.status == "quarantined"
        assert s.snapshot()["attempts"][old.attempt_id]["phase"] == "UNKNOWN"


def test_s2_reconsent_without_unresolved_ticket_stays_valid(isolated):
    with open_s2(isolated) as s:
        s.approve_fake()
        s.approve_fake()
        assert s.status == "healthy"
        assert s.snapshot()["consent_epoch"] == 2
        assert s.prepare_offline().consent_epoch == 2


def test_s2_mismatched_workspace_on_boot_cannot_inherit_old_consent(isolated):
    root, _ = isolated
    with open_s2(isolated) as s:
        s.approve_fake()
        old = s.snapshot()["binding"]
    foreign = root.parent.parent / "replacement-workspace"
    foreign.mkdir(mode=0o700)
    with S2PrivateState(root, workspace_root=foreign) as imported:
        v = imported.snapshot()
        assert imported.status == "quarantined"
        assert v["binding"] == old  # forensic identity retained
        assert not v["consent_active"]
        assert v["quarantined"]
        with pytest.raises(S2Blocked):
            imported.prepare_offline()
    with open_s2(isolated) as again:
        assert again.status == "quarantined"  # no automatic reapproval


def test_s2_revoke_after_prepared_durably_fences_without_any_dispatch(isolated):
    with open_s2(isolated) as s:
        s.approve_fake()
        ticket = s.prepare_offline()
        s.revoke_fake()
        assert s.status == "quarantined"
        v = s.snapshot()
        assert not v["consent_active"]
        assert v["consent_epoch"] == 2
        assert v["attempts"][ticket.attempt_id]["phase"] == "UNKNOWN"
        with pytest.raises(S2Blocked):
            s.prepare_offline()
    with open_s2(isolated) as again:
        assert again.status == "quarantined"
        assert again.snapshot()["attempts"][ticket.attempt_id]["phase"] == "UNKNOWN"


def test_s2_fake_approval_scope_and_backend_must_be_supported(isolated):
    with open_s2(isolated) as s:
        for bad in ("", "fake/backend", " offline-scope", "a" * 129, "bad\nscope"):
            with pytest.raises(S2Blocked):
                s.approve_fake(exec_scope=bad)
        for bad in ("native-v1", "unsupported", None, 1):
            with pytest.raises(S2Blocked):
                s.approve_fake(backend=bad)
        assert not s.snapshot()["consent_active"]
        s.approve_fake()
        assert s.prepare_offline().consent_epoch == 1


def test_s2_actual_workspace_replacement_cannot_borrow_consent(isolated):
    _, work = isolated
    with open_s2(isolated) as s:
        s.approve_fake()
        work.rename(work.with_name("old-workspace"))
        work.mkdir(mode=0o700)
        with pytest.raises(S2Blocked):
            s.prepare_offline()


def test_s2_rejects_foreign_v1_migration_without_touching_bytes(isolated):
    root, _ = isolated
    root.mkdir(mode=0o700)
    legacy = root / ("r-" + "a" * 32 + ".json")
    legacy.write_bytes(b'{"schema_version":1,"phase":"RETIRED"}\n')
    baseline = legacy.read_bytes()
    with pytest.raises(S2Blocked, match="foreign or interrupted"):
        open_s2(isolated)
    assert legacy.read_bytes() == baseline
    assert not (root / "state-v2.json").exists()


def test_s2_malformed_v1_snapshot_never_auto_upgrades(isolated):
    with open_s2(isolated):
        pass
    root, _ = isolated
    state = root / "state-v2.json"
    legacy = b'{"schema_version":1,"phase":"RETIRED"}\n'
    state.write_bytes(legacy)
    with pytest.raises(S2Unavailable, match="private v2 state/lock unavailable"):
        open_s2(isolated)
    assert state.read_bytes() == legacy


def test_s2_rejects_copy_consent_epoch_zero_and_duplicate_keys(isolated):
    with open_s2(isolated):
        pass
    root, _ = isolated
    state = root / "state-v2.json"
    obj = json.loads(state.read_text())
    obj["consent_active"] = True
    state.write_text(json.dumps(obj) + "\n")
    with pytest.raises(S2Unavailable, match="private v2 state/lock unavailable"):
        open_s2(isolated)
    assert json.loads(state.read_text())["consent_active"]
    state.write_text(state.read_text().replace('"schema_version": 2', '"schema_version": 2, "schema_version": 2'))
    with pytest.raises((S2Unavailable, S2Blocked, ValueError)):
        open_s2(isolated)


@pytest.mark.parametrize("fault", ["after_pending", "before_replace", "after_replace", "after_dirsync"])
def test_s2_faulted_real_fs_transition_preserves_forensic_marker(isolated, fault):
    # Failing boot on a fresh isolated root tests a real file/dir write and
    # owner-lock release; NOT a process crash or power-loss experiment.
    with pytest.raises(S2Unavailable):
        open_s2(isolated, fault_at=fault)
    root, _ = isolated
    assert any(n.name.startswith("pending-") for n in root.iterdir())
    with pytest.raises(S2Blocked, match="foreign or interrupted"):
        open_s2(isolated)
    assert any(n.name.startswith("pending-") for n in root.iterdir())


def test_s2_fault_during_existing_approval_preserves_failed_mutation(isolated):
    with open_s2(isolated) as s:
        before = s.snapshot()
        s._fault_at = "after_replace"  # deterministic private test seam
        with pytest.raises(S2Unavailable):
            s.approve_fake()
        assert s.status == "unavailable"
        with pytest.raises(S2Blocked):
            s.prepare_offline()
        assert s.snapshot() == before
    with pytest.raises(S2Blocked):
        open_s2(isolated)


def test_s2_symlink_private_root_parent_and_hardlink_lock_rejected(isolated, tmp_path):
    root, work = isolated
    target = tmp_path / "outside"
    target.mkdir(mode=0o700)
    root.symlink_to(target, target_is_directory=True)
    with pytest.raises(S2Unavailable):
        open_s2(isolated)
    root.unlink()
    with open_s2(isolated):
        pass
    lock = root / "owner.lock"
    alias = root / "alias-lock"
    os.link(lock, alias)
    with pytest.raises(S2Blocked, match="unsafe v2 file"):
        open_s2(isolated)
    assert alias.exists()


def test_s2_symlink_state_file_and_foreign_temp_denied_without_deletion(isolated, tmp_path):
    with open_s2(isolated):
        pass
    root, _ = isolated
    state = root / "state-v2.json"
    preserved = state.read_bytes()
    state.unlink()
    outside = tmp_path / "outside.json"
    outside.write_bytes(preserved)
    state.symlink_to(outside)
    with pytest.raises((S2Blocked, S2Unavailable)):
        open_s2(isolated)
    assert outside.read_bytes() == preserved
    state.unlink()
    state.write_bytes(preserved)
    pending = root / "temp-orphaned.tmp"
    pending.write_bytes(b"incomplete")
    with pytest.raises(S2Blocked, match="foreign or interrupted"):
        open_s2(isolated)
    assert pending.read_bytes() == b"incomplete"


def test_s2_positive_fake_survivor_has_no_os_signal_and_latches_across_restart(isolated):
    with open_s2(isolated) as s:
        s.approve_fake()
        t = s.prepare_offline()
        s.late_positive_fake(t)
        v = s.snapshot()
        assert v["attempts"][t.attempt_id]["phase"] == "UNKNOWN"
        assert v["attempts"][t.attempt_id]["late_positive"]
        assert s.status == "quarantined"
    with open_s2(isolated) as s:
        assert s.status == "quarantined"
        assert s.snapshot()["attempts"][t.attempt_id]["phase"] == "UNKNOWN"


def test_s2_unattributable_positive_becomes_global_orphan_quarantine(isolated):
    with open_s2(isolated) as s:
        s.late_positive_fake(OfflineTicket("a" * 32, 1, "b" * 32, "c" * 32))
        assert s.snapshot()["orphan_positive"]
        assert s.status == "quarantined"
    with open_s2(isolated) as again:
        assert again.status == "quarantined"
        assert again.snapshot()["orphan_positive"]


def test_s2_real_state_quota_fail_closed_and_no_silent_eviction(isolated):
    with open_s2(isolated, max_records=1) as s:
        s.approve_fake()
        t = s.prepare_offline()
        with pytest.raises(S2Unavailable, match="quota"):
            s.prepare_offline()
        assert s.status == "unavailable"
        assert t.attempt_id in s.snapshot()["attempts"]
    with open_s2(isolated) as again:
        assert again.status == "quarantined"  # unresolved PREPARED preserved
        assert t.attempt_id in again.snapshot()["attempts"]


def test_s2_total_byte_quota_persists_fail_closed_marker_before_restart(isolated):
    # A valid approved snapshot is smaller than 512 bytes, but adding even
    # one PREPARED record exceeds this bounded journal. Overflow must not
    # surface as a plain ValueError with a still-healthy owner.
    with open_s2(isolated, max_total_bytes=512) as s:
        s.approve_fake()
        before = stored(isolated)
        with pytest.raises(S2Unavailable, match="quota|capacity"):
            s.prepare_offline()
        assert s.status == "unavailable"
        assert stored(isolated) == before  # failed intent never committed
        root, _ = isolated
        assert any(p.name.startswith("pending-") for p in root.iterdir())
        with pytest.raises(S2Blocked):
            s.prepare_offline()
    # A previously valid active-consent snapshot cannot be revived by reboot.
    with pytest.raises(S2Blocked, match="foreign or interrupted"):
        open_s2(isolated, max_total_bytes=512)


def test_s2_mutable_workspace_contents_do_not_revoke_offline_consent(isolated):
    _, work = isolated
    with open_s2(isolated) as s:
        s.approve_fake()
        epoch = s.snapshot()["consent_epoch"]
        (work / "script.py").write_text("x=1\n")
        assert s.snapshot()["consent_epoch"] == epoch
        t = s.prepare_offline()
        assert t.consent_epoch == epoch


def test_s2_concurrent_revoke_and_prepare_are_serialized(isolated):
    with open_s2(isolated) as s:
        s.approve_fake()
        barrier = threading.Barrier(3)
        results = []
        def prepare():
            barrier.wait()
            try:
                results.append(s.prepare_offline())
            except S2Blocked:
                results.append("blocked")
        def revoke():
            barrier.wait()
            try:
                s.revoke_fake()
            except S2Blocked:
                results.append("revoke-blocked")
        a = threading.Thread(target=prepare)
        b = threading.Thread(target=revoke)
        a.start(); b.start(); barrier.wait()
        a.join(timeout=5); b.join(timeout=5)
        assert not a.is_alive() and not b.is_alive()
        assert not s.snapshot()["consent_active"]
        assert all(r == "blocked" or r == "revoke-blocked" or isinstance(r, OfflineTicket) for r in results)
        if any(isinstance(r, OfflineTicket) for r in results):
            assert s.status == "quarantined"
            assert all(x["phase"] == "UNKNOWN" for x in s.snapshot()["attempts"].values())
        else:
            assert s.status == "healthy"  # revoke won before PREPARED


def test_s2_mutating_snapshot_cannot_change_persistent_state(isolated):
    with open_s2(isolated) as s:
        v = s.snapshot()
        v["consent_active"] = True
        v["attempts"]["f" * 32] = {}
        assert not s.snapshot()["consent_active"]
        assert not s.snapshot()["attempts"]


def test_s2_no_runtime_wiring_and_no_process_or_signal_functions():
    import inspect
    import gateway.r2s_state_s2 as module
    text = inspect.getsource(module)
    assert "subprocess" not in text.replace("No positive Native capability, live migration, process start or signal operation.", "")
    assert "os.kill(" not in text and "os.killpg(" not in text
    assert "Popen(" not in text
    assert not hasattr(S2PrivateState, "start_once")
    assert not hasattr(S2PrivateState, "dispatch")
    assert not hasattr(S2NonspawningCoordinator, "allow")
