"""PR101 C101-SOURCE-01/02 fail-closed public v2 admission T0.

Only synthetic temporary private roots and test doubles. Zero native Exec,
network, signals, Go/Pipenv toolchains or user Mac/Tunnel.
"""
from __future__ import annotations

import os
from pathlib import Path
import subprocess

import pytest
from starlette.testclient import TestClient

from gateway.core import GatewayError
from gateway.exec_state import ExecStateStore
from gateway.http_multi import create_multi_app
from gateway.workspaces import ActiveRuntimeInventory, WorkspaceService
from gateway.workspaces_config import parse_workspace_config


def _service(tmp_path: Path, *, fixture=False) -> WorkspaceService:
    a, b = tmp_path / "a", tmp_path / "b"
    (a / "python-project").mkdir(parents=True)
    (a / "python-project" / "ok.py").write_text("print('NEVER_EXECUTED')\n")
    b.mkdir()
    (b / "safe.txt").write_text("before")
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    old = ExecStateStore(
        private / "exec-state", workspace_roots=(str(a), str(b)))
    assert old.durability_state == "healthy"
    old.close()
    config = {
        "schema_version": 2,
        "server": {"port": 8765, "transport": "http",
                   "git": {"enabled": True}},
        "workspaces": {
            "a": {"root": str(a),
                  "exec": {"paths": ["python-project"], "runners": []}},
            "b": {"root": str(b),
                  "write": {"enabled": True, "paths": ["safe.txt"]},
                  "git": {"allowed_commands": ["status"]}},
        },
    }
    return WorkspaceService(
        parse_workspace_config(config), config_dir=private,
        inventory=ActiveRuntimeInventory(paths=(runtime,)),
        _approved_python_t1_fixture=fixture,
    )


def _no_child(*args, **kwargs):
    raise AssertionError("Unapproved public schema-v2 Exec reached Popen")


def _assert_denied(svc: WorkspaceService) -> None:
    with pytest.raises(GatewayError) as err:
        svc.invoke_exec("a", "python-project", ["python", "ok.py"],
                        timeout_seconds=5, dry_run=False)
    assert err.value.code == "exec_cleanup_proof_required"


def test_ordinary_v2_paths_not_operative_even_with_healthy_old_owner(
    tmp_path, monkeypatch,
):
    svc = _service(tmp_path)
    try:
        state = svc.info()["exec_policy"]
        assert state["mode"] == "local_best_effort"
        assert state["enabled"] is True
        assert state["durability_state"] == "healthy"
        assert state["available"] is False
        assert state["completion_capability"] == "none"
        preview = svc.invoke_exec("a", "python-project",
                                  ["python", "ok.py"], timeout_seconds=5)
        assert preview["status"] == "preview"
        assert preview["executed"] is False
        with monkeypatch.context() as m:
            m.setattr(subprocess.Popen, "__init__", _no_child)
            m.setattr(os, "kill", _no_child)
            m.setattr(os, "killpg", _no_child, raising=False)
            _assert_denied(svc)
            assert svc._lbe_owner.snapshot()["reserved_slots"] == 0
            assert svc._exec_active == set()
        assert not (tmp_path / "a/python-project/NEVER_EXECUTED").exists()
        assert svc._exec_state.durability_state == "healthy"
    finally:
        svc.close()


def test_rest_and_official_mcp_reject_unapproved_v2_apply(tmp_path, monkeypatch):
    svc = _service(tmp_path)
    body = {"workspace": "a", "cwd": "python-project",
            "argv": ["python", "ok.py"], "timeout_seconds": 5,
            "dry_run": False}
    headers = {"Accept": "application/json, text/event-stream",
               "Content-Type": "application/json"}
    try:
        with monkeypatch.context() as m:
            m.setattr(subprocess.Popen, "__init__", _no_child)
            m.setattr(os, "kill", _no_child)
            m.setattr(os, "killpg", _no_child, raising=False)
            with TestClient(create_multi_app(svc),
                            base_url="http://127.0.0.1:8765") as client:
                before = client.get("/health").json()["exec_policy"]
                assert before == client.get("/info").json()["exec_policy"]
                assert before["available"] is False
                denied = client.post("/run", json=body)
                assert denied.status_code == 403
                assert denied.json()["error"] == "exec_cleanup_proof_required"

                init = client.post("/mcp", headers=headers, json={
                    "jsonrpc": "2.0", "id": 1, "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-11-25",
                        "capabilities": {},
                        "clientInfo": {"name": "v2-denial-t0", "version": "1"},
                    },
                })
                assert init.status_code == 200
                client.post("/mcp", headers=headers, json={
                    "jsonrpc": "2.0", "method": "notifications/initialized"})
                tool = client.post("/mcp", headers=headers, json={
                    "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                    "params": {"name": "run_command", "arguments": body},
                })
                assert tool.status_code == 200, tool.text
                result = tool.json()["result"]
                assert result.get("isError") is True
                assert result["structuredContent"]["error"] == (
                    "exec_cleanup_proof_required")
                assert client.get("/health").json()["exec_policy"] == before
            assert svc._lbe_owner.snapshot()["reserved_slots"] == 0
    finally:
        svc.close()


def test_unapproved_exec_does_not_disable_separately_authorized_file_git(
    tmp_path, monkeypatch,
):
    svc = _service(tmp_path)
    try:
        with monkeypatch.context() as m:
            m.setattr(subprocess.Popen, "__init__", _no_child)
            _assert_denied(svc)
        before = svc.invoke("b", "read_file", "safe.txt")
        assert before["content"] == "before"
        svc.invoke("b", "write_file", "safe.txt", "after",
                   before["file_sha256"], dry_run=False)
        assert svc.invoke("b", "read_file", "safe.txt")["content"] == "after"
        assert svc.require_git("b", "status").name == "b"
        assert svc.info()["git_policy"]["enabled"] is True
        with pytest.raises(GatewayError) as denied:
            svc.invoke_exec("b", ".", ["python", "ok.py"], dry_run=False)
        assert denied.value.code == "exec_disabled"
    finally:
        svc.close()


def test_fake_hosted_environment_without_private_scratch_cannot_unlock(
    tmp_path, monkeypatch,
):
    # No real hosted workflow is run by this T0; spoof all process-scoped
    # marker strings, but keep the roots outside the deliberately wrong temp.
    fake_temp = tmp_path / "not-workspace-owner"
    fake_temp.mkdir()
    fake = {
        "LBE_NATIVE_T1_AUTHORIZED":
            "PR101_R002_MACOS15_ARM64_DISPOSABLE_PYTHON_ONLY",
        "GITHUB_ACTIONS": "true",
        "GITHUB_EVENT_NAME": "pull_request",
        "GITHUB_REPOSITORY": "chinanjjohn2012/mac-file-gateway",
        "GITHUB_HEAD_REF": "feat/multi-exec-lbe-v2-config-preflight-r001-20261030",
        "GITHUB_BASE_REF": "rc/multi-exec-f1-g05-integrated-ms1-20261025",
        "GITHUB_WORKFLOW": "PR101 authorized macOS ARM64 original child T1",
        "RUNNER_OS": "macOS",
        "RUNNER_ARCH": "ARM64",
        "RUNNER_TEMP": str(fake_temp),
    }
    with monkeypatch.context() as m:
        for k, v in fake.items():
            m.setenv(k, v)
        svc = _service(tmp_path, fixture=True)
        try:
            assert svc._lbe_positive_authorized is False
            assert svc.info()["exec_policy"]["available"] is False
            with m.context() as guard:
                guard.setattr(subprocess.Popen, "__init__", _no_child)
                _assert_denied(svc)
        finally:
            svc.close()
