"""R2-T02-B0: state-store boot, lock lifetime, and conservative recovery.

This is a stand-alone incremental bridge: **NOT** a normal-Exec proof gate
and NOT a full Worker lifecycle. All state directories are temporary.
Existing PR #56 real process acceptance remains unchanged in this batch.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import signal
import stat
import subprocess

import pytest

from gateway.core import GatewayError
from gateway.exec_state import ExecStateStore
from gateway.workspaces import ActiveRuntimeInventory, WorkspaceService
from gateway.workspaces_config import parse_workspace_config


class _Scene:
    def __init__(self, tmp_path: Path, *, enabled: bool = True,
                 git: bool = False):
        root = tmp_path / "projects"
        root.mkdir()
        self.a = root / "a"
        self.b = root / "b"
        self.a.mkdir()
        self.b.mkdir()
        (self.a / "src").mkdir()
        (self.a / "src" / "hello.py").write_text("print('disposable')\n")
        (self.b / "safe.txt").write_text("independent-read\n")
        self.config = tmp_path / "config"
        self.config.mkdir(mode=0o700)
        self.config.chmod(0o700)
        self.runtime = tmp_path / "runtime"
        self.runtime.mkdir()
        self.state = self.config / "exec-state"
        cfg = {"schema_version": 1, "server": {
            "exec": {"enabled": enabled},
            "git": {"enabled": git},
        }, "workspaces": {
            "a": {"root": str(self.a)},
            "b": {"root": str(self.b)},
        }}
        if enabled:
            cfg["workspaces"]["a"]["exec"] = {
                "enabled": True, "paths": ["src"], "runners": ["src=direct"]}
        if git:
            cfg["workspaces"]["b"]["git"] = {
                "allowed_commands": ["status"]}
        self.settings = parse_workspace_config(cfg)
        self.services: list[WorkspaceService] = []

    def service(self) -> WorkspaceService:
        svc = WorkspaceService(
            self.settings, config_dir=self.config,
            inventory=ActiveRuntimeInventory(paths=(self.runtime,)))
        self.services.append(svc)
        return svc

    def seed(self, phase: str = "UNKNOWN") -> tuple[Path, bytes]:
        store = ExecStateStore(
            self.state, workspace_roots=(str(self.a), str(self.b)))
        try:
            assert store.durability_state == "healthy"
            root = self.a.stat()
            attempt = store.prepare("a", (root.st_dev, root.st_ino))
            if phase == "UNKNOWN":
                store.mark_unknown(attempt)
        finally:
            store.close()
        record = self.state / ("r-" + attempt + ".json")
        result = record.read_bytes()
        assert json.loads(result)["phase"] == phase
        return record, result

    def close(self) -> None:
        for svc in reversed(self.services):
            svc.close()


@pytest.fixture
def scene(tmp_path):
    item = _Scene(tmp_path)
    try:
        yield item
    finally:
        item.close()


def _policy(svc):
    return svc.info()["exec_policy"]


def test_b0_exec_enabled_boot_owns_pinned_private_state_and_lifetime_lock(scene):
    svc = scene.service()
    assert scene.state.is_dir()
    assert stat.S_IMODE(scene.state.stat().st_mode) == 0o700
    lock = scene.state / "owner.lock"
    assert lock.is_file() and lock.stat().st_nlink == 1
    assert stat.S_IMODE(lock.stat().st_mode) == 0o600
    policy = _policy(svc)
    assert policy["durability_state"] == "healthy"
    assert policy["quarantined"] is False
    assert policy["quarantine_reason_code"] is None

    contender = ExecStateStore(scene.state)
    try:
        assert contender.durability_state == "unavailable"
        assert contender.quarantine_reason_code == "owner_lock_unavailable"
    finally:
        contender.close()

    svc.close()
    reopened = ExecStateStore(scene.state)
    try:
        assert reopened.durability_state == "healthy"
        reopened.require_healthy()
    finally:
        reopened.close()


def test_b0_globally_disabled_exec_does_not_create_active_state(tmp_path):
    scene = _Scene(tmp_path, enabled=False)
    try:
        svc = scene.service()
        p = _policy(svc)
        assert p["enabled"] is False
        assert p["durability_state"] == "disabled"
        assert p["quarantined"] is False
        assert p["quarantine_reason_code"] is None
        assert not scene.state.exists()
        with pytest.raises(GatewayError) as error:
            svc.invoke_exec("a", "src", ["python", "hello.py"])
        assert error.value.code == "exec_disabled"
    finally:
        scene.close()


def test_b0_recovered_unknown_rejects_exec_but_file_stays_independent(
        scene, monkeypatch):
    record, original = scene.seed("UNKNOWN")
    svc = scene.service()
    p = _policy(svc)
    assert p["durability_state"] == "quarantined"
    assert p["quarantined"] is True
    assert p["quarantine_reason_code"] == "cleanup_unknown"
    assert p["available"] is False
    calls = []
    monkeypatch.setattr(svc.get("a").gateway, "run_command",
                        lambda *args, **kwargs: calls.append(args))
    for dry_run in (True, False):
        with pytest.raises(GatewayError) as error:
            svc.invoke_exec("a", "src", ["python", "hello.py"],
                            dry_run=dry_run)
        assert error.value.code == "exec_quarantined"
    assert calls == []
    assert record.read_bytes() == original
    assert svc.invoke("b", "read_file", "safe.txt", 1, 10)["workspace"] == "b"
    # A genuine service-reported quarantine is established BEFORE file read.
    assert _policy(svc)["quarantined"] is True


def test_b0_corrupt_state_record_is_preserved_and_closes_admission(scene):
    record, _ = scene.seed("PREPARED")
    corrupt = b'{"broken":true}'
    record.write_bytes(corrupt)
    svc = scene.service()
    p = _policy(svc)
    assert p["durability_state"] == "quarantined"
    assert p["quarantined"] is True
    assert p["quarantine_reason_code"] == "corrupt_record"
    assert p["available"] is False
    with pytest.raises(GatewayError) as error:
        svc.invoke_exec("a", "src", ["python", "hello.py"])
    assert error.value.code == "exec_quarantined"
    assert record.read_bytes() == corrupt


def test_b0_second_owner_stays_latched_unavailable_even_after_lock_free(scene):
    holder = ExecStateStore(
        scene.state, workspace_roots=(str(scene.a), str(scene.b)))
    try:
        assert holder.durability_state == "healthy"
        svc = scene.service()
        policy = _policy(svc)
        assert policy["durability_state"] == "unavailable"
        assert policy["quarantined"] is False
        assert policy["quarantine_reason_code"] == "owner_lock_unavailable"
        assert policy["available"] is False
        with pytest.raises(GatewayError) as error:
            svc.invoke_exec("a", "src", ["python", "hello.py"],
                            dry_run=True)
        assert error.value.code == "exec_state_unavailable"
    finally:
        holder.close()
    assert _policy(svc)["durability_state"] == "unavailable"
    with pytest.raises(GatewayError) as error:
        svc.invoke_exec("a", "src", ["python", "hello.py"], dry_run=False)
    assert error.value.code == "exec_state_unavailable"
    assert svc.invoke("b", "read_file", "safe.txt", 1, 10)["workspace"] == "b"


def test_b0_symlink_state_root_fails_closed_without_following_it(scene, tmp_path):
    victim = tmp_path / "dont-touch"
    victim.mkdir()
    content = victim / "sentinel.txt"
    content.write_bytes(b"unchanged")
    scene.state.symlink_to(victim, target_is_directory=True)
    svc = scene.service()
    p = _policy(svc)
    assert p["durability_state"] == "unavailable"
    assert p["available"] is False
    assert p["quarantine_reason_code"] == "state_io_unavailable"
    with pytest.raises(GatewayError) as error:
        svc.invoke_exec("a", "src", ["python", "hello.py"],
                        dry_run=False)
    assert error.value.code == "exec_state_unavailable"
    assert content.read_bytes() == b"unchanged"
    assert sorted(p.name for p in victim.iterdir()) == ["sentinel.txt"]


@pytest.mark.parametrize("phase", ["PREPARED", "UNKNOWN"])
def test_b0_boot_scan_does_not_spawn_or_signal_stale_processes(
        scene, monkeypatch, phase):
    record, original = scene.seed(phase)
    forbidden_calls = []
    def forbidden(*args, **kwargs):
        forbidden_calls.append((args, kwargs))
        raise AssertionError("UNAUTHORIZED_HOST_PROCESS_OR_SIGNAL")
    with monkeypatch.context() as m:
        base_popen = subprocess.Popen
        class _BlockedPopen(base_popen):
            def __new__(cls, *args, **kwargs):
                return forbidden(*args, **kwargs)
        m.setattr(subprocess, "Popen", _BlockedPopen)
        for name in ("kill", "killpg", "posix_spawn", "posix_spawnp"):
            if hasattr(os, name):
                m.setattr(os, name, forbidden)
        if hasattr(signal, "pthread_kill"):
            m.setattr(signal, "pthread_kill", forbidden)
        svc = scene.service()
        p = _policy(svc)
    assert p["quarantined"] is True
    assert p["quarantine_reason_code"] == "cleanup_unknown"
    assert forbidden_calls == []
    assert record.read_bytes() == original
