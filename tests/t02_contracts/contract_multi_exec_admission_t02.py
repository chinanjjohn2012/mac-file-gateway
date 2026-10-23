"""R2-T02-A: deterministic RED for *normal* Multi-Workspace Exec admission.

This non-default test module is run ONLY by the isolated T02-A verifier.
A successful verifier means existing runtime behavior is NOT YET integrated.
No trusted test-grant constructor, real Popen, host signal, Native C,
arbitrary command execution, or production/Tunnel request is used here.
"""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import signal
import stat
import subprocess

import pytest
from starlette.testclient import TestClient

from gateway.core import GatewayError
from gateway.exec_state import ExecStateStore
from gateway.http_multi import create_multi_app
from gateway.private_fs import PrivateFileError
from gateway.workspaces import ActiveRuntimeInventory, WorkspaceService
from gateway.workspaces_config import parse_workspace_config

_HEADERS = {"Accept": "application/json, text/event-stream",
            "Content-Type": "application/json"}
_ARGUMENTS = {"workspace": "a", "cwd": "src",
              "argv": ["python", "preview.py"], "dry_run": False}


class _HostProcessGuard:
    """Test-owned, entire-fixture protection. Not a native-process sandbox."""

    def __init__(self):
        self.violations = []

    def _block(self, name):
        def prohibited(*args, **kwargs):
            self.violations.append(name)
            raise AssertionError("T02_UNSAFE_HOST_PROCESS_OR_SIGNAL: " + name)
        return prohibited

    def install(self, patch):
        original = subprocess.Popen
        guard = self

        class _ForbiddenPopen(original):
            # Retain class typing and Popen[bytes] (real MCP SDK uses it).
            def __new__(cls, *args, **kwargs):
                return guard._block("subprocess.Popen")(*args, **kwargs)

        patch.setattr(subprocess, "Popen", _ForbiddenPopen)
        for name in (
            "kill", "killpg", "fork", "forkpty", "posix_spawn",
            "posix_spawnp", "system", "spawnl", "spawnle", "spawnlp",
            "spawnlpe", "spawnv", "spawnve", "spawnvp", "spawnvpe",
            "execl", "execle", "execlp", "execlpe", "execv", "execve",
            "execvp", "execvpe",
        ):
            if hasattr(os, name):
                patch.setattr(os, name, self._block("os." + name))
        for name in ("pthread_kill", "raise_signal"):
            if hasattr(signal, name):
                patch.setattr(signal, name, self._block("signal." + name))
        for name in ("create_subprocess_exec", "create_subprocess_shell"):
            if hasattr(asyncio, name):
                patch.setattr(asyncio, name, self._block("asyncio." + name))

    def assert_untouched(self):
        if self.violations:
            pytest.fail("T02_TEST_INFRA_FORBIDDEN_HOST_ACTIVITY: " +
                        repr(self.violations), pytrace=False)


@pytest.fixture(autouse=True)
def _no_host_process_or_signal(monkeypatch):
    # Autouse fixture starts BEFORE user scene and exits AFTER scene teardown:
    # child starts/signals inside ctor, REST/MCP dispatch, close or cleanup
    # are all blocked even when a defective future implementation swallows
    # the immediate exception.
    guard = _HostProcessGuard()
    guard.install(monkeypatch)
    try:
        yield
    finally:
        guard.assert_untouched()



class _Scene:
    """External, temporary on-disk authority; no product-owned test grant."""

    def __init__(self, tmp_path, *, server_exec=True, workspace_exec=True):
        projects = tmp_path / "projects"
        projects.mkdir()
        self.a, self.b = projects / "a", projects / "b"
        self.a.mkdir()
        self.b.mkdir()
        (self.a / "src").mkdir()
        (self.a / "src" / "preview.py").write_text("print('never spawn in T02')\n")
        (self.b / "readme.txt").write_text("independent-file-read\n")
        self.control = tmp_path / "config"
        self.control.mkdir(mode=0o700)
        self.runtime = tmp_path / "runtime"
        self.runtime.mkdir()
        self.state = self.control / "exec-state"
        self.settings = parse_workspace_config({
            "schema_version": 1,
            "server": {"exec": {"enabled": server_exec}},
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
            self.settings, config_dir=self.control,
            inventory=ActiveRuntimeInventory(paths=(self.runtime,)))
        self.services.append(svc)
        return svc

    def seed(self, phase="PREPARED"):
        """Use the actual reviewed T01 persistence codec, never synthetic API."""
        store = ExecStateStore(
            self.state, workspace_roots=(str(self.a), str(self.b)))
        try:
            assert store.durability_state == "healthy"
            st = self.a.stat()
            attempt = store.prepare("a", (st.st_dev, st.st_ino))
        finally:
            store.close()
        file = self.state / ("r-" + attempt + ".json")
        if phase != "PREPARED":
            obj = json.loads(file.read_bytes())
            obj["phase"] = phase
            raw = (json.dumps(obj, sort_keys=True, separators=(",", ":"))
                   + "\n").encode("utf-8")
            if phase == "UNKNOWN":
                assert obj["cleanup_scope"] == "none"
            assert len(raw) <= 4096
            fd = os.open(file, os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW)
            try:
                assert os.write(fd, raw) == len(raw)
                os.fsync(fd)
            finally:
                os.close(fd)
            fd = os.open(self.state, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        assert stat.S_IMODE(file.stat().st_mode) == 0o600
        assert file.stat().st_nlink == 1
        return file

    def close(self):
        for svc in reversed(self.services):
            svc.close()


@pytest.fixture
def scene(tmp_path):
    case = _Scene(tmp_path)
    try:
        yield case
    finally:
        case.close()


def _fail(marker, evidence):
    pytest.fail("T02_RED_" + marker + ": " + str(evidence)[:400],
                pytrace=False)


def _require(predicate, marker, evidence):
    if not predicate:
        _fail(marker, evidence)


def _status(svc):
    policy = svc.info()["exec_policy"]
    assert type(policy) is dict
    return policy


def _fake_runner(scene, svc, monkeypatch):
    """No actual runner/Popen: record an unauthorized invocation externally."""
    calls = []
    def forbidden(*args, **kwargs):
        calls.append((args, kwargs))
        return {"executed": True, "exit_code": 0, "stdout": "FAKE",
                "stderr": "", "timed_out": False, "dry_run": False}
    monkeypatch.setattr(svc.get("a").gateway, "run_command", forbidden)
    return calls


def _direct_result(svc, *, dry_run=False):
    try:
        return "returned", svc.invoke_exec(
            "a", "src", ["python", "preview.py"], dry_run=dry_run)
    except GatewayError as exc:
        return exc.code, None


def _disk_snapshot(scene):
    if not scene.state.exists():
        return {}
    return {p.name: p.read_bytes() for p in scene.state.iterdir()
            if p.is_file() and not p.is_symlink()}


def test_t02_boot_pins_state_and_owns_exclusive_lock(scene):
    svc = scene.service()
    _require(scene.state.is_dir() and (scene.state / "owner.lock").is_file(),
             "BOOT_STATE_NOT_OPENED", "no physical Exec store after service construction")
    another = ExecStateStore(scene.state)
    try:
        _require(another.durability_state == "unavailable" and
                 another.quarantine_reason_code == "owner_lock_unavailable",
                 "BOOT_STATE_NOT_OPENED", "another owner acquired the same lock")
    finally:
        another.close()


def test_t02_normal_apply_requires_proof_before_worker_or_intent(
        scene, monkeypatch):
    svc = scene.service()
    calls = _fake_runner(scene, svc, monkeypatch)
    before = _disk_snapshot(scene)
    code, _ = _direct_result(svc)
    after = _disk_snapshot(scene)
    _require(code == "exec_cleanup_proof_required"
             and not calls and before == after,
             "NORMAL_PROOF_GATE",
             {"code": code, "runner_calls": len(calls),
              "physical_state_changed": before != after})


def test_t02_rest_apply_is_structured_503_and_zero_runner_calls(
        scene, monkeypatch):
    svc = scene.service()
    calls = _fake_runner(scene, svc, monkeypatch)
    with TestClient(create_multi_app(svc, enable_mcp=False),
                    base_url="http://127.0.0.1:8765") as client:
        response = client.post("/run", json=_ARGUMENTS)
    _require(response.status_code == 503 and
             response.json() == {"error": "exec_cleanup_proof_required"} and
             not calls, "REST_PROOF_GATE",
             {"http": response.status_code, "body": response.text[:150],
              "runner_calls": len(calls)})


def test_t02_mcp_tools_call_structured_proof_error_before_runner(
        scene, monkeypatch):
    pytest.importorskip("mcp")
    svc = scene.service()
    calls = _fake_runner(scene, svc, monkeypatch)
    with TestClient(create_multi_app(svc),
                    base_url="http://127.0.0.1:8765") as client:
        init = client.post("/mcp", headers=_HEADERS, json={
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-11-25",
                       "capabilities": {},
                       "clientInfo": {"name": "t02-admission", "version": "1"}}})
        assert init.status_code == 200 and "result" in init.json()
        client.post("/mcp", headers=_HEADERS, json={
            "jsonrpc": "2.0", "method": "notifications/initialized"})
        response = client.post("/mcp", headers=_HEADERS, json={
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "run_command", "arguments": _ARGUMENTS}})
    body = response.json() if response.status_code == 200 else {}
    result = body.get("result", {})
    structured = result.get("structuredContent") or {}
    _require(response.status_code == 200 and
             result.get("isError") is True and
             structured.get("error") == "exec_cleanup_proof_required" and
             not calls, "MCP_PROOF_GATE",
             {"http": response.status_code,
              "result": repr(result)[:160], "runner_calls": len(calls)})


def test_t02_normal_policy_reports_no_available_cleanup_qualification(scene):
    svc = scene.service()
    with TestClient(create_multi_app(svc, enable_mcp=False),
                    base_url="http://127.0.0.1:8765"):
        policy = _status(svc)
    _require(
        policy.get("enabled") is True and
        policy.get("adapter_exposed") is True and
        policy.get("available") is False and
        policy.get("quarantined") is False and
        policy.get("durability_state") == "healthy" and
        policy.get("quarantine_reason_code") is None and
        policy.get("completion_capability") == "none",
        "NORMAL_STATUS_AVAILABILITY",
        policy)


def test_t02_health_and_info_return_identical_sanitized_policy(scene):
    svc = scene.service()
    with TestClient(create_multi_app(svc, enable_mcp=False),
                    base_url="http://127.0.0.1:8765") as client:
        info = client.get("/info")
        health = client.get("/health")
    a = info.json().get("exec_policy")
    b = health.json().get("exec_policy")
    _require(info.status_code == 200 and health.status_code == 200 and
             type(a) is dict and a == b and
             a.get("completion_capability") == "none",
             "HEALTH_INFO_POLICY_PARITY", {"info": a, "health": b})


@pytest.mark.parametrize("phase", ["PREPARED", "RUNNING", "UNKNOWN"])
def test_t02_boot_replays_no_unresolved_attempt_and_quarantines(
        scene, monkeypatch, phase):
    record = scene.seed(phase)
    before = record.read_bytes()
    attempted = []
    # No signals or process creation are permitted while loading history.
    def forbidden(*a, **kw):
        attempted.append((a, kw))
        raise AssertionError("UNSAFE_RESTART_OS_PROCESS_OR_SIGNAL")
    with monkeypatch.context() as m:
        for name in ("kill", "killpg", "posix_spawn", "posix_spawnp"):
            if hasattr(os, name):
                m.setattr(os, name, forbidden)
        # Keep subprocess.Popen a *type* for SDK type annotations.
        base_popen = subprocess.Popen
        class _ForbiddenPopen(base_popen):
            def __new__(cls, *a, **kw):
                return forbidden(*a, **kw)
        m.setattr(subprocess, "Popen", _ForbiddenPopen)
        svc = scene.service()
        policy = _status(svc)
    _require(
        policy.get("quarantined") is True and
        policy.get("durability_state") == "quarantined" and
        policy.get("quarantine_reason_code") == "cleanup_unknown" and
        policy.get("available") is False and
        record.read_bytes() == before and not attempted,
        "BOOT_UNRESOLVED_NOT_QUARANTINED",
        {"phase": phase, "policy": policy, "signal_or_spawn": len(attempted)})


def test_t02_corrupt_disk_record_is_quarantined_without_mutation(scene):
    record = scene.seed()
    bad = b'{"invalid":"fixed physical bytes"}'
    record.write_bytes(bad)
    svc = scene.service()
    policy = _status(svc)
    _require(policy.get("quarantined") is True and
             policy.get("quarantine_reason_code") == "corrupt_record" and
             policy.get("available") is False and
             record.read_bytes() == bad,
             "BOOT_CORRUPT_RECORD_IGNORED", policy)


def test_t02_competing_owner_latches_unavailable_and_refuses_preview(
        scene, monkeypatch):
    holder = ExecStateStore(scene.state)
    try:
        assert holder.durability_state == "healthy"
        svc = scene.service()
        calls = _fake_runner(scene, svc, monkeypatch)
        code, _ = _direct_result(svc, dry_run=True)
        policy = _status(svc)
        _require(code == "exec_state_unavailable" and
                 policy.get("durability_state") == "unavailable" and
                 policy.get("quarantine_reason_code") == "owner_lock_unavailable"
                 and policy.get("available") is False and not calls,
                 "OWNER_LOCK_FAIL_CLOSED",
                 {"code": code, "policy": policy, "runner_calls": len(calls)})
    finally:
        holder.close()


def test_t02_quarantined_preview_and_apply_both_deny_before_runner(
        scene, monkeypatch):
    record = scene.seed("UNKNOWN")
    before = record.read_bytes()
    svc = scene.service()
    calls = _fake_runner(scene, svc, monkeypatch)
    preview_code, _ = _direct_result(svc, dry_run=True)
    apply_code, _ = _direct_result(svc, dry_run=False)
    _require(preview_code == "exec_quarantined" and
             apply_code == "exec_quarantined" and not calls and
             record.read_bytes() == before,
             "QUARANTINE_PREVIEW_OR_APPLY",
             {"preview": preview_code, "apply": apply_code,
              "runner_calls": len(calls)})


def test_t02_exec_disabled_status_is_distinct_from_unavailable(tmp_path):
    scene = _Scene(tmp_path, server_exec=False, workspace_exec=False)
    try:
        svc = scene.service()
        p = _status(svc)
        _require(p.get("durability_state") == "disabled" and
                 p.get("enabled") is False and
                 p.get("available") is False and
                 p.get("completion_capability") == "none",
                 "DISABLED_STATUS_DISTINCTION", p)
    finally:
        scene.close()


def test_t02_external_environment_cannot_grant_cleanup_proof(
        scene, monkeypatch):
    monkeypatch.setenv("GATEWAY_EXEC_TEST_GRANT", "1")
    monkeypatch.setenv("GATEWAY_R1_TEST_ONLY", "true")
    svc = scene.service()
    calls = _fake_runner(scene, svc, monkeypatch)
    code, _ = _direct_result(svc)
    _require(code == "exec_cleanup_proof_required" and not calls,
             "ENV_PROOF_BYPASS", {"code": code, "runner_calls": len(calls)})


def test_t02_guard_preview_keeps_ordinary_validation(scene):
    svc = scene.service()
    result = svc.invoke_exec("a", "src", ["python", "preview.py"],
                             dry_run=True)
    assert result["dry_run"] is True and result["executed"] is False
    assert result["workspace"] == "a"


def test_t02_guard_file_read_independent_of_exec_quarantine(scene):
    scene.seed("UNKNOWN")
    svc = scene.service()
    result = svc.invoke("b", "read_file", "readme.txt", 1, 10)
    assert result["workspace"] == "b"



def test_t02_guard_host_interceptor_rejects_process_and_group_signal(
        tmp_path, monkeypatch):
    """A GREEN infrastructure witness, not an R2 product-cleanup GREEN."""
    local = _HostProcessGuard()
    with monkeypatch.context() as patch:
        local.install(patch)
        assert isinstance(subprocess.Popen, type)
        assert subprocess.Popen[bytes]
        with pytest.raises(AssertionError, match="T02_UNSAFE_HOST_PROCESS_OR_SIGNAL"):
            subprocess.Popen(["python", "never-run.py"])
        with pytest.raises(AssertionError, match="T02_UNSAFE_HOST_PROCESS_OR_SIGNAL"):
            os.killpg(os.getpgrp(), signal.SIGTERM)
    assert local.violations == ["subprocess.Popen", "os.killpg"]



def test_t02_guard_external_configuration_cannot_inject_private_grant(scene):
    config = {"schema_version": 1,
              "server": {"exec": {"enabled": True, "test_grant": True}},
              "workspaces": {
                  "a": {"root": str(scene.a), "exec": {
                      "enabled": True, "paths": ["src"],
                      "runners": ["src=direct"]}}}}
    with pytest.raises(PrivateFileError):
        parse_workspace_config(config)
