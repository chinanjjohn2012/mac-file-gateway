"""PR #90 r003 isolated T1 regressions for the FINAL directory-fsync recovery gap.

Only pytest-owned disposable private roots; no real process spawn, signals,
production Gateway, user Mac, or power-loss/crash experiment.  Original RED
on r002 must fail the new cases before the state writer is changed.
"""
from __future__ import annotations

import errno
import json
import os

import pytest

import gateway.r2s_state_s2 as mod
from gateway.r2s_state_s2 import S2Blocked, S2PrivateState, S2Unavailable


@pytest.fixture
def isolated(tmp_path):
    private = tmp_path / "private"
    workspace = tmp_path / "workspace"
    private.mkdir(mode=0o700)
    workspace.mkdir(mode=0o700)
    return private / "exec-state-s2-candidate", workspace


def owner(paths):
    root, workspace = paths
    return S2PrivateState(root, workspace_root=workspace)


def _inject_final_directory_fsync_error(state, monkeypatch):
    """Fail just AFTER pending was unlinked, without kernel crash/signal."""
    actual = os.fsync
    observed = []

    def injected(fd):
        if fd == state._fd:
            names = set(os.listdir(fd))
            if "state-v2.json" in names and not any(
                name.startswith("pending-") for name in names
            ):
                observed.append(names)
                raise OSError(errno.EIO, "injected final dir fsync AFTER pending unlink")
        return actual(fd)

    monkeypatch.setattr(mod.os, "fsync", injected)
    return observed


def test_r003_failed_close_fsync_after_pending_unlink_blocks_reboot(isolated, monkeypatch):
    first = owner(isolated)
    first.approve_fake()
    root, _ = isolated
    approved = first.snapshot()
    assert approved["consent_active"] and approved["owner_active"]
    with monkeypatch.context() as m:
        observed = _inject_final_directory_fsync_error(first, m)
        first.close()
    assert len(observed) == 1, "must exercise the actual final fsync after unlink"
    assert not any(p.name.startswith("pending-") for p in root.iterdir())
    # The persisted close snapshot may already say owner_active=False, but
    # an INDEPENDENT durable forensic fence must remain until fsync succeeds.
    stored = json.loads((root / "state-v2.json").read_bytes())
    assert stored["owner_active"] is False and stored["consent_active"] is True
    fence = [p for p in root.iterdir() if p.name.startswith("final-fence-")]
    assert len(fence) == 1, "failed final fsync removed the only durable uncertainty evidence"
    assert fence[0].read_bytes()
    original_bytes = (root / "state-v2.json").read_bytes()
    original_fence = fence[0].read_bytes()
    with pytest.raises((S2Blocked, S2Unavailable)):
        owner(isolated)
    assert (root / "state-v2.json").read_bytes() == original_bytes
    assert fence[0].read_bytes() == original_fence


def test_r003_failed_revoke_fsync_after_unlink_never_rearms_fake_consent(isolated, monkeypatch):
    first = owner(isolated)
    first.approve_fake()
    root, _ = isolated
    with monkeypatch.context() as m:
        observed = _inject_final_directory_fsync_error(first, m)
        with pytest.raises(S2Unavailable, match="durability"):
            first.revoke_fake()
    assert len(observed) == 1
    assert first.status == "unavailable"
    assert any(p.name.startswith("final-fence-") for p in root.iterdir())
    first.close()  # an unavailable session may not hide failed revoke via seal
    with pytest.raises((S2Blocked, S2Unavailable)):
        owner(isolated)


def test_r003_final_fence_cleanup_eio_retains_uncertainty(isolated, monkeypatch):
    first = owner(isolated)
    first.approve_fake()
    root, _ = isolated
    real_unlink = os.unlink
    observed = []

    def injected(name, *args, **kwargs):
        if isinstance(name, str) and name.startswith("final-fence-"):
            observed.append(name)
            raise OSError(errno.EIO, "isolated fence cleanup failed")
        return real_unlink(name, *args, **kwargs)

    with monkeypatch.context() as m:
        m.setattr(mod.os, "unlink", injected)
        first.close()
    assert len(observed) == 1, "must exercise explicit final-fence cleanup"
    assert (root / observed[0]).is_file()
    with pytest.raises((S2Blocked, S2Unavailable)):
        owner(isolated)
    assert (root / observed[0]).is_file()


def test_r003_legal_clean_close_and_reboot_keep_fake_consent(isolated):
    root, _ = isolated
    with owner(isolated) as first:
        first.approve_fake()
        old = first.snapshot()
        assert old["owner_active"]
        assert old["consent_active"]
    assert set(p.name for p in root.iterdir()) == {"owner.lock", "state-v2.json"}
    disk = json.loads((root / "state-v2.json").read_bytes())
    assert disk["owner_active"] is False and disk["consent_active"] is True
    with owner(isolated) as next_owner:
        assert next_owner.status == "healthy"
        now = next_owner.snapshot()
        assert now["consent_epoch"] == old["consent_epoch"]
        assert now["owner_generation"] != old["owner_generation"]
        ticket = next_owner.prepare_offline()
        assert ticket.consent_epoch == old["consent_epoch"]
    with owner(isolated) as rebooted:
        assert rebooted.status == "quarantined"
        assert rebooted.snapshot()["attempts"][ticket.attempt_id]["phase"] == "UNKNOWN"
        with pytest.raises(S2Blocked):
            rebooted.prepare_offline()
