"""R2-T02-B1-B1-A: independently staged ordinary no-proof Default DENY RED.

This non-default-collected contract runs only via the strict B1-B1 RED
verifier. A successful verifier means **missing product functionality**.
No actual subprocess, signals, native C, user Workspace or Tunnel are run.
A separate later B1-B1 Worker migration MUST preserve all original real
Exec acceptance tests, never rewrite/skip them to make a green report.
"""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import signal
import subprocess

import pytest
from starlette.testclient import TestClient

from gateway.core import GatewayError
from gateway.exec_state import ExecStateStore
from gateway.http_multi import create_multi_app
from gateway.workspaces import WorkspaceService, ActiveRuntimeInventory
from gateway.workspaces_config import parse_workspace_config

RPC_HEADERS = {"Accept": "application/json, text/event-stream",
               "Content-Type": "application/json"}
APPLY = {"workspace": "a", "cwd": "src",
         "argv": ["python", "probe.py"], "dry_run": False}


class _HostGuard:
    """Protect the ENTIRE test lifetime, including startup and teardown.

    Test-owned Python-level witness, not a kernel process sandbox. We do not
    run commands or signal OS PIDs; all future accidental attempts fail.
    """
    def __init__(self):
        self.attempts = []

    def _ban(self, name):
        def stop(*args, **kwargs):
            self.attempts.append(name)
            raise AssertionError("B1B1_FORBIDDEN_HOST_ACTION:" + name)
        return stop

    def install(self, patch):
        base = subprocess.Popen
        guard = self
        class _ForbiddenPopen(base):
            # MCP SDK uses Popen[bytes] at import time, preserve type.
            def __new__(cls, *args, **kwargs):
                return guard._ban("Popen")(*args, **kwargs)
        patch.setattr(subprocess, "Popen", _ForbiddenPopen)
        for name in (
            "kill", "killpg", "fork", "forkpty", "posix_spawn",
            "posix_spawnp", "system", "spawnl", "spawnle", "spawnlp",
            "spawnlpe", "spawnv", "spawnve", "spawnvp", "spawnvpe",
            "execl", "execle", "execlp", "execlpe", "execv", "execve",
            "execvp", "execvpe",
        ):
            if hasattr(os, name):
                patch.setattr(os, name, self._ban("os." + name))
        for name in ("pthread_kill", "raise_signal"):
            if hasattr(signal, name):
                patch.setattr(signal, name, self._ban("signal." + name))
        for name in ("create_subprocess_exec", "create_subprocess_shell"):
            if hasattr(asyncio, name):
                patch.setattr(asyncio, name, self._ban("asyncio." + name))


@pytest.fixture(autouse=True)
def _host_isolation(monkeypatch):
    guard = _HostGuard()
    guard.install(monkeypatch)
    try:
        yield
    finally:
        if guard.attempts:
            pytest.fail("B1B1_UNEXPECTED_HOST_PROCESS_OR_SIGNAL:" +
                        repr(guard.attempts), pytrace=False)


class _Scene:
    def __init__(self, tmp: Path, *, global_exec=True, workspace_exec=True):
        projects = tmp / "projects"
        projects.mkdir()
        self.a, self.b = projects / "a", projects / "b"
        self.a.mkdir()
        self.b.mkdir()
        (self.a / "src").mkdir()
        (self.a / "src" / "probe.py").write_text("print('NEVER RUN')\n")
        (self.b / "public.txt").write_text("file-access-survives\n")
        self.config = tmp / "config"
        self.config.mkdir(mode=0o700)
        self.runtime = tmp / "trusted-runtime"
        self.runtime.mkdir()
        self.state = self.config / "exec-state"
        self.settings = parse_workspace_config({
            "schema_version": 1,
            "server": {"exec": {"enabled": global_exec}},
            "workspaces": {
                "a": {"root": str(self.a), "exec": {
                    "enabled": workspace_exec,
                    "paths": ["src"] if workspace_exec else [],
                    "runners": ["src=direct"] if workspace_exec else [],
                }},
                "b": {"root": str(self.b)},
            },
        })
        self.services = []

    def service(self):
        svc = WorkspaceService(
            self.settings, config_dir=self.config,
            inventory=ActiveRuntimeInventory(paths=(self.runtime,)))
        self.services.append(svc)
        return svc

    def close(self):
        for svc in reversed(self.services):
            svc.close()


@pytest.fixture
def scene(tmp_path):
    x = _Scene(tmp_path)
    try:
        yield x
    finally:
        x.close()


def _require(predicate, marker, data):
    if not predicate:
        pytest.fail("B1B1_RED_" + marker + ": " + repr(data)[:450],
                    pytrace=False)


def _run(svc, *, dry_run=False):
    try:
        value = svc.invoke_exec("a", "src", ["python", "probe.py"],
                                dry_run=dry_run)
        return "returned", value
    except GatewayError as exc:
        return exc.code, None


def _runner_spy(svc, monkeypatch):
    calls = []
    def fake(*args, **kwargs):
        calls.append((args, kwargs))
        return {"executed": True, "exit_code": 0, "timed_out": False,
                "stdout": "UNAUTHORIZED", "stderr": "", "dry_run": False}
    monkeypatch.setattr(svc.get("a").gateway, "run_command", fake)
    return calls


def _records(scene):
    if not scene.state.is_dir():
        return {}
    return {p.name: p.read_bytes()
            for p in scene.state.iterdir() if p.is_file() and not p.is_symlink()}


class _IntentWitness:
    """Watch both store APIs and intermediate physical state mutations.

    A broken Worker cannot hide 'write PREPARED then unlink' just by making
    before/after disk snapshots look identical. Install *after boot*, when
    ExecStateStore has legitimately initialized owner.lock.
    """
    def __init__(self, root: Path):
        self.root = os.path.abspath(os.fspath(root))
        self.events = []

    @staticmethod
    def _attempt(path):
        if not isinstance(path, (str, bytes, os.PathLike)):
            return False
        name = os.path.basename(os.fsdecode(os.fspath(path)))
        return (name.startswith("r-") and name.endswith(".json")
                or name.startswith("temp-") and name.endswith(".tmp"))

    def _matches(self, path, dir_fd=None):
        if not self._attempt(path):
            return False
        try:
            value = os.fsdecode(os.fspath(path))
            if os.path.isabs(value):
                return os.path.dirname(os.path.abspath(value)) == self.root
            if dir_fd is None:
                return os.path.dirname(os.path.abspath(value)) == self.root
            st = os.stat(self.root, follow_symlinks=False)
            pinned = os.fstat(dir_fd)
            return (st.st_dev, st.st_ino) == (pinned.st_dev, pinned.st_ino)
        except (OSError, ValueError, TypeError):
            return False

    def install(self, patch):
        real_prepare = ExecStateStore.prepare
        real_atomic = ExecStateStore._atomic_write
        real_open = os.open
        real_replace = os.replace
        real_rename = os.rename
        real_unlink = os.unlink
        witness = self

        def prepare(store, *args, **kwargs):
            witness.events.append("prepare")
            return real_prepare(store, *args, **kwargs)
        def atomic(store, path, payload):
            if witness._matches(path, store._fd):
                witness.events.append("atomic_write")
            return real_atomic(store, path, payload)
        def open_write(path, flags, *args, **kwargs):
            if (flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC)
                    and witness._matches(path, kwargs.get("dir_fd"))):
                witness.events.append("open_write")
            return real_open(path, flags, *args, **kwargs)
        def replace(src, dst, *args, **kwargs):
            if witness._matches(dst, kwargs.get("dst_dir_fd")):
                witness.events.append("replace")
            return real_replace(src, dst, *args, **kwargs)
        def rename(src, dst, *args, **kwargs):
            if witness._matches(dst, kwargs.get("dst_dir_fd")):
                witness.events.append("rename")
            return real_rename(src, dst, *args, **kwargs)
        def unlink(path, *args, **kwargs):
            if witness._matches(path, kwargs.get("dir_fd")):
                witness.events.append("unlink")
            return real_unlink(path, *args, **kwargs)

        patch.setattr(ExecStateStore, "prepare", prepare)
        patch.setattr(ExecStateStore, "_atomic_write", atomic)
        patch.setattr(os, "open", open_write)
        patch.setattr(os, "replace", replace)
        patch.setattr(os, "rename", rename)
        patch.setattr(os, "unlink", unlink)


def _never_started(scene, witness, before, calls):
    return not calls and not witness.events and _records(scene) == before


def test_b1b1_normal_direct_apply_denies_before_any_intent(scene, monkeypatch):
    svc = scene.service()
    calls = _runner_spy(svc, monkeypatch)
    witness = _IntentWitness(scene.state)
    with monkeypatch.context() as p:
        witness.install(p)
        before = _records(scene)
        code, value = _run(svc)
        clean = _never_started(scene, witness, before, calls)
    _require(code == "exec_cleanup_proof_required" and value is None and clean,
             "DEFAULT_DIRECT",
             {"code": code, "runner_calls": len(calls),
              "intent_events": witness.events, "unchanged": _records(scene) == before})


def test_b1b1_normal_rest_apply_503_denied_before_any_intent(scene, monkeypatch):
    svc = scene.service()
    calls = _runner_spy(svc, monkeypatch)
    witness = _IntentWitness(scene.state)
    with monkeypatch.context() as p:
        witness.install(p)
        before = _records(scene)
        with TestClient(create_multi_app(svc, enable_mcp=False),
                        base_url="http://127.0.0.1:8765") as client:
            response = client.post("/run", json=APPLY)
        clean = _never_started(scene, witness, before, calls)
    _require(response.status_code == 503 and
             response.json() == {"error": "exec_cleanup_proof_required"} and
             clean, "DEFAULT_REST",
             {"status": response.status_code, "body": response.text[:135],
              "calls": len(calls), "intent_events": witness.events,
              "unchanged": _records(scene) == before})


def test_b1b1_normal_mcp_apply_structured_proof_error(scene, monkeypatch):
    pytest.importorskip("mcp")
    svc = scene.service()
    calls = _runner_spy(svc, monkeypatch)
    witness = _IntentWitness(scene.state)
    with monkeypatch.context() as p:
        witness.install(p)
        before = _records(scene)
        with TestClient(create_multi_app(svc),
                        base_url="http://127.0.0.1:8765") as client:
            initial = client.post("/mcp", headers=RPC_HEADERS, json={
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2025-11-25",
                           "capabilities": {},
                           "clientInfo": {"name": "b1b1-red", "version": "1"}}})
            assert initial.status_code == 200 and "result" in initial.json()
            client.post("/mcp", headers=RPC_HEADERS, json={
                "jsonrpc": "2.0", "method": "notifications/initialized"})
            response = client.post("/mcp", headers=RPC_HEADERS, json={
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "run_command", "arguments": APPLY}})
        clean = _never_started(scene, witness, before, calls)
    result = response.json().get("result", {}) if response.status_code == 200 else {}
    structured = result.get("structuredContent") or {}
    _require(response.status_code == 200 and
             result.get("isError") is True and
             structured.get("error") == "exec_cleanup_proof_required" and clean,
             "DEFAULT_MCP", {"http": response.status_code,
                             "result": repr(result)[:180], "calls": len(calls),
                             "intent_events": witness.events})


def test_b1b1_info_health_report_same_unavailable_proof_policy(scene):
    svc = scene.service()
    with TestClient(create_multi_app(svc, enable_mcp=False),
                    base_url="http://127.0.0.1:8765") as client:
        info = client.get("/info")
        health = client.get("/health")
    policy = info.json().get("exec_policy", {})
    health_policy = health.json().get("exec_policy")
    _require(info.status_code == 200 and health.status_code == 200 and
             policy == health_policy and type(policy) is dict and
             policy.get("enabled") is True and
             policy.get("adapter_exposed") is True and
             policy.get("available") is False and
             policy.get("quarantined") is False and
             policy.get("durability_state") == "healthy" and
             policy.get("quarantine_reason_code") is None and
             policy.get("completion_capability") == "none" and
             "owner.lock" not in json.dumps(policy) and
             "exec-state" not in json.dumps(policy),
             "POLICY_PARITY",
             {"info": repr(policy)[:200], "health": repr(health_policy)[:180]})


def test_b1b1_missing_proof_precedes_worker_busy_slot(scene, monkeypatch):
    svc = scene.service()
    calls = _runner_spy(svc, monkeypatch)
    svc._exec_active.add("a")  # held slot, test-owned and released below
    try:
        code, value = _run(svc)
    finally:
        svc._exec_active.discard("a")
    _require(code == "exec_cleanup_proof_required" and
             value is None and not calls, "PROOF_BEFORE_BUSY",
             {"code": code, "calls": len(calls)})


@pytest.mark.parametrize("flag", ["GATEWAY_EXEC_TEST_GRANT", "GATEWAY_R1_TEST_ONLY"])
def test_b1b1_env_cannot_mint_cleanup_proof(scene, monkeypatch, flag):
    monkeypatch.setenv(flag, "true")
    svc = scene.service()
    calls = _runner_spy(svc, monkeypatch)
    witness = _IntentWitness(scene.state)
    with monkeypatch.context() as p:
        witness.install(p)
        before = _records(scene)
        code, value = _run(svc)
        clean = _never_started(scene, witness, before, calls)
    _require(code == "exec_cleanup_proof_required" and
             value is None and clean, "ENV_BYPASS",
             {"flag": flag, "code": code, "calls": len(calls),
              "intent_events": witness.events})


def test_b1b1_guard_ordinary_preview_remains_allowed(scene):
    svc = scene.service()
    code, result = _run(svc, dry_run=True)
    assert code == "returned"
    assert result["dry_run"] is True and result["executed"] is False
    assert result["workspace"] == "a"
    assert result["runner"] == "direct"


def test_b1b1_guard_global_off_precedes_proof(tmp_path):
    local = _Scene(tmp_path, global_exec=False, workspace_exec=False)
    try:
        svc = local.service()
        code, val = _run(svc)
        assert code == "exec_disabled" and val is None
    finally:
        local.close()


def test_b1b1_guard_file_read_independent_of_missing_exec_proof(scene):
    svc = scene.service()
    data = svc.invoke("b", "read_file", "public.txt", 1, 10)
    assert data["workspace"] == "b"
    assert data["path"] == "public.txt"


@pytest.mark.parametrize("bad_field", ["test_grant", "listener_host",
                                     "full_descendant_tree_clean"])
def test_b1b1_guard_client_fields_cannot_select_private_proof(
        scene, monkeypatch, bad_field):
    svc = scene.service()
    calls = _runner_spy(svc, monkeypatch)
    with TestClient(create_multi_app(svc, enable_mcp=False),
                    base_url="http://127.0.0.1:8765") as client:
        response = client.post("/run", json={**APPLY, bad_field: True})
    assert response.status_code == 400
    assert calls == []


def test_b1b1_guard_transient_intent_witness_rejects_write_then_delete(
        scene, monkeypatch):
    """Infrastructure counterexample, not a product success.

    A *real* PREPARED record is written/fsynced and unlinked/fsynced.
    Final on-disk bytes are identical: a snapshot-only test would lie.
    """
    store = ExecStateStore(scene.state,
                           workspace_roots=(str(scene.a), str(scene.b)))
    try:
        assert store.durability_state == "healthy"
        witness = _IntentWitness(scene.state)
        with monkeypatch.context() as p:
            witness.install(p)
            before = _records(scene)
            st = scene.a.stat()
            attempt = store.prepare("a", (st.st_dev, st.st_ino))
            os.unlink("r-" + attempt + ".json", dir_fd=store._fd)
            os.fsync(store._fd)
            after = _records(scene)
        assert before == after
        assert "prepare" in witness.events
        assert any(x in witness.events for x in ("atomic_write", "open_write"))
        assert "unlink" in witness.events
        assert not _never_started(scene, witness, before, [])
    finally:
        store.close()


def test_b1b1_guard_host_interceptor_is_type_preserving(monkeypatch):
    witness = _HostGuard()
    with monkeypatch.context() as p:
        witness.install(p)
        assert isinstance(subprocess.Popen, type)
        assert subprocess.Popen[bytes]
        with pytest.raises(AssertionError, match="B1B1_FORBIDDEN_HOST_ACTION"):
            subprocess.Popen(["python", "must-not-run.py"])
        with pytest.raises(AssertionError, match="B1B1_FORBIDDEN_HOST_ACTION"):
            os.killpg(os.getpgrp(), signal.SIGTERM)
    assert witness.attempts == ["Popen", "os.killpg"]
