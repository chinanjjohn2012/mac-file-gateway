"""SAFE T0 disposable-FS tests for explicit first-install state setup.

These tests create only temporary files; no service or native child is run.
"""
from __future__ import annotations

import os
import stat

import pytest

from gateway.lbe_mvp_first_setup import initialize_fresh_v2_exec_state
from gateway.private_fs import PrivateFileError
from gateway.exec_state import ExecStateStore


@pytest.fixture
def private(tmp_path):
    control = tmp_path / "private"
    control.mkdir(mode=0o700)
    control.chmod(0o700)
    workspace = tmp_path / "workspaces" / "example"
    workspace.mkdir(parents=True)
    return control, workspace


def _first(control, *, first=True, stopped=True):
    return initialize_fresh_v2_exec_state(
        control,
        operator_confirmed_first_install=first,
        operator_confirmed_gateway_stopped=stopped,
    )


@pytest.mark.parametrize("first,stopped", [
    (False, False), (False, True), (True, False),
])
def test_never_provision_without_both_explicit_confirmations(
        private, first, stopped):
    control, _ = private
    with pytest.raises(PrivateFileError, match="confirmed"):
        _first(control, first=first, stopped=stopped)
    assert not (control / "exec-state").exists()


def test_first_install_is_openable_by_existing_only_store_and_never_runs_native(
        private, monkeypatch):
    import subprocess
    control, workspace = private
    monkeypatch.setattr(subprocess, "Popen",
                        lambda *a, **k: pytest.fail("setup spawned a child"))
    status = _first(control)
    assert status["status"] == "first_install_provisioned"
    assert status["exec_enabled"] is False
    assert status["native_command_executed"] is False
    root = control / "exec-state"
    lock = root / "owner.lock"
    assert sorted(p.name for p in root.iterdir()) == ["owner.lock"]
    assert stat.S_IMODE(root.stat().st_mode) == 0o700
    assert stat.S_IMODE(lock.stat().st_mode) == 0o600
    assert lock.stat().st_size == 0
    store = ExecStateStore(
        root, workspace_roots=(str(workspace),), existing_only=True)
    try:
        assert store.durability_state == "healthy"
    finally:
        store.close()


def test_repeat_provision_never_resets_existing_history(private):
    control, _ = private
    _first(control)
    root = control / "exec-state"
    evidence = root / "preexisting-evidence"
    evidence.write_text("do not erase or replay")
    lock = (root / "owner.lock")
    identity = (lock.stat().st_dev, lock.stat().st_ino)
    with pytest.raises(PrivateFileError, match="already exists"):
        _first(control)
    assert evidence.read_text() == "do not erase or replay"
    assert (lock.stat().st_dev, lock.stat().st_ino) == identity


def test_refuse_existing_symlink_state(private):
    control, _ = private
    foreign = control / "foreign"
    foreign.mkdir()
    (control / "exec-state").symlink_to(foreign, target_is_directory=True)
    with pytest.raises(PrivateFileError, match="already exists"):
        _first(control)
    assert (control / "exec-state").is_symlink()
    assert (foreign / "owner.lock").exists() is False


def test_refuse_nonprivate_config_root(private):
    control, _ = private
    control.chmod(0o755)
    with pytest.raises(PrivateFileError, match="0700"):
        _first(control)
    assert not (control / "exec-state").exists()


def test_cli_requires_confirmations_without_touching_state(private, capsys):
    from tools.mvp_exec_first_install import main
    control, _ = private
    assert main(["--config-dir", str(control)]) == 2
    assert not (control / "exec-state").exists()
    assert main([
        "--config-dir", str(control),
        "--confirm-first-install",
        "--confirm-gateway-stopped",
    ]) == 0
    assert (control / "exec-state" / "owner.lock").exists()
    result = capsys.readouterr().out
    assert "first_install_provisioned" in result
    assert "native_command_executed" in result
