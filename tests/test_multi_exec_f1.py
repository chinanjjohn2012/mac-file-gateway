"""F1 production-first safety: real ingress + private-state witness + Git apply.

These checks never launch an Exec subprocess, signal a host PID/PGID, reset
quarantine, or mount an internal test-grant on public network adapters.
Authorized Git subprocesses run only in pytest disposable repositories.
"""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest
from starlette.testclient import TestClient

from gateway.core import GatewayError
from gateway.http_multi import create_multi_app
from gateway.workspaces import ActiveRuntimeInventory, WorkspaceService
from gateway.workspaces_config import parse_workspace_config


_APPLY = {"workspace": "a", "cwd": "src",
          "argv": ["python", "hello.py"], "dry_run": False}
_HEADERS = {"Accept": "application/json, text/event-stream",
            "Content-Type": "application/json"}


def _previously_reviewed_physical_witness():
    """Reuse frozen B1-B1-A physical intent hooks; don't duplicate a weak oracle."""
    path = (Path(__file__).parent / "b1b1_contracts" /
            "contract_multi_exec_default_deny_b1b1.py")
    spec = importlib.util.spec_from_file_location("_f1_b1b1_frozen_witness", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module._IntentWitness, module._records, module._public_policy_is_sanitized


@pytest.fixture
def mixed(tmp_path):
    project = tmp_path / "projects"
    project.mkdir()
    a, b = project / "a", project / "b"
    a.mkdir()
    b.mkdir()
    (a / "src").mkdir()
    (b / "src").mkdir()
    (a / "src" / "hello.py").write_text("print('must-not-execute')\n")
    (b / "src" / "read.txt").write_text("file-read-only\n")
    subprocess.run(["git", "init", "-q"], cwd=project, check=True,
                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                   stderr=subprocess.PIPE)
    config = tmp_path / "config"
    config.mkdir(mode=0o700)
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    cfg = {"schema_version": 1,
           "server": {"exec": {"enabled": True}, "git": {"enabled": True}},
           "workspaces": {
               "a": {"root": str(a),
                     "exec": {"enabled": True, "paths": ["src"],
                              "runners": ["src=direct"]},
                     "write": {"enabled": True, "paths": ["src"]},
                     "git": {"allowed_commands": ["status"]}},
               "b": {"root": str(b)},
           }}
    svc = WorkspaceService(
        parse_workspace_config(cfg), config_dir=config,
        inventory=ActiveRuntimeInventory(paths=(runtime,)))
    try:
        yield svc, a, b, config
    finally:
        svc.close()


def _error_code(svc, workspace="a", dry_run=False):
    with pytest.raises(GatewayError) as exc:
        svc.invoke_exec(workspace, "src", ["python", "hello.py"],
                        dry_run=dry_run)
    return exc.value.code


def _mcp(client, method, params=None, identifier=2):
    response = client.post("/mcp", headers=_HEADERS,
                           json={"jsonrpc": "2.0", "id": identifier,
                                 "method": method, "params": params or {}})
    assert response.status_code == 200, response.text
    return response.json()


def test_f1_physical_no_prep_or_runner_and_proof_before_busy(mixed, monkeypatch):
    svc, a, _b, config = mixed
    assert svc._exec_state is not None
    assert svc._exec_state.durability_state == "healthy"
    assert svc.info()["exec_policy"]["completion_capability"] == "none"
    assert svc.info()["exec_policy"]["available"] is False
    assert svc.invoke_exec("a", "src", ["python", "hello.py"])["executed"] is False
    Witness, records, _ = _previously_reviewed_physical_witness()
    scene = SimpleNamespace(state=config / "exec-state")
    witness = Witness(scene.state)
    calls = []
    svc._exec_active.add("a")
    try:
        with monkeypatch.context() as patch:
            patch.setattr(svc.get("a").gateway, "run_command",
                          lambda *args, **kwargs: calls.append((args, kwargs)))
            witness.install(patch)
            before = records(scene)
            assert _error_code(svc) == "exec_cleanup_proof_required"
            assert calls == [] and witness.events == []
            assert records(scene) == before and witness._root_is_pinned()
    finally:
        svc._exec_active.discard("a")
    assert _error_code(svc, "b") == "exec_disabled"
    assert svc.invoke_exec("a", "src", ["python", "hello.py"])["dry_run"] is True


def test_f1_real_rest_sdk_mcp_and_status_policy(mixed, monkeypatch):
    pytest.importorskip("mcp")
    svc, a, _b, config = mixed
    app = create_multi_app(svc)
    Witness, records, public_policy = _previously_reviewed_physical_witness()
    scene = SimpleNamespace(state=config / "exec-state")
    with TestClient(app, base_url="http://127.0.0.1:8765") as client:
        info = client.get("/info").json()
        health = client.get("/health").json()
        assert info["exec_policy"] == health["exec_policy"]
        assert public_policy(info["exec_policy"])
        assert info["exec_policy"]["available"] is False
        assert info["exec_policy"]["completion_capability"] == "none"
        dry = client.post("/run", json={**_APPLY, "dry_run": True})
        assert dry.status_code == 200 and dry.json()["executed"] is False
        initialized = _mcp(client, "initialize", {
            "protocolVersion": "2025-11-25", "capabilities": {},
            "clientInfo": {"name": "f1-deny-only", "version": "1"}}, 1)
        assert "result" in initialized
        client.post("/mcp", headers=_HEADERS,
                    json={"jsonrpc": "2.0", "method": "notifications/initialized"})
        witness = Witness(scene.state)
        calls = []
        with monkeypatch.context() as patch:
            patch.setattr(svc.get("a").gateway, "run_command",
                          lambda *args, **kwargs: calls.append((args, kwargs)))
            witness.install(patch)
            before = records(scene)
            rest = client.post("/run", json=_APPLY)
            assert rest.status_code == 503, rest.text
            assert rest.json()["error"] == "exec_cleanup_proof_required"
            mcp = _mcp(client, "tools/call", {
                "name": "run_command", "arguments": _APPLY}, 3)
            tool_result = mcp["result"]
            assert tool_result.get("isError") is True, tool_result
            assert tool_result["structuredContent"]["error"] == "exec_cleanup_proof_required"
            for field in ("test_grant", "test_mode", "group_only_test_grant"):
                denied = client.post("/run", json={**_APPLY, field: True})
                assert denied.status_code == 400
                assert denied.json()["error"] == "invalid_argument"
            header = client.post("/run", json=_APPLY,
                                 headers={"X-Gateway-Test-Mode": "1"})
            assert header.status_code == 503
            assert calls == [] and witness.events == []
            assert records(scene) == before and witness._root_is_pinned()
    assert svc.info()["exec_policy"]["adapter_exposed"] is True


def test_f1_same_service_real_git_and_file_write_survive_exec_quarantine(mixed):
    svc, a, b, config = mixed
    assert svc.any_exec and svc.any_git and svc.any_write
    assert _error_code(svc) == "exec_cleanup_proof_required"
    # The same live service that will run Git must also reject the
    # production REST apply route, not just a separate test fixture.
    with TestClient(create_multi_app(svc, enable_mcp=False),
                    base_url="http://127.0.0.1:8765") as client:
        rest = client.post("/run", json=_APPLY)
        assert rest.status_code == 503
        assert rest.json()["error"] == "exec_cleanup_proof_required"
    first = svc.invoke_git("a", "status", dry_run=False)
    assert first["exit_code"] == 0 and first["execute_started"] is True
    write = svc.invoke("a", "create_file", "src/f1-legal.txt",
                       "legal\n", False)
    assert write["workspace"] == "a"
    assert (a / "src" / "f1-legal.txt").read_text() == "legal\n"
    with pytest.raises(GatewayError) as exc:
        svc.invoke_git("b", "status", dry_run=False)
    assert exc.value.code == "git_command_not_allowed"
    with pytest.raises(GatewayError) as exc:
        svc.invoke_git("a", "pull", dry_run=False)
    assert exc.value.code == "git_command_not_allowed"
    with pytest.raises(GatewayError) as exc:
        svc.invoke("b", "create_file", "src/illegal.txt", "bad", False)
    assert exc.value.code == "write_disabled"
    assert not (b / "src" / "illegal.txt").exists()

    store = svc._exec_state
    assert store is not None and store.durability_state == "healthy"
    st = a.stat()
    attempt = store.prepare("a", (st.st_dev, st.st_ino))
    store.mark_unknown(attempt)
    record = config / "exec-state" / ("r-" + attempt + ".json")
    original = record.read_bytes()
    assert _error_code(svc) == "exec_quarantined"
    assert svc.info()["exec_policy"]["durability_state"] == "quarantined"
    assert svc.info()["exec_policy"]["quarantined"] is True
    with TestClient(create_multi_app(svc, enable_mcp=False),
                    base_url="http://127.0.0.1:8765") as client:
        quarantined_rest = client.post("/run", json=_APPLY)
        assert quarantined_rest.status_code == 503
        assert quarantined_rest.json()["error"] == "exec_quarantined"
    second = svc.invoke_git("a", "status", dry_run=False)
    assert second["exit_code"] == 0 and second["execute_started"] is True
    assert svc.invoke("a", "create_file", "src/f1-quarantined.txt",
                      "still-legal\n", False)["workspace"] == "a"
    assert (a / "src" / "f1-quarantined.txt").read_text() == "still-legal\n"
    with pytest.raises(GatewayError) as exc:
        svc.invoke("b", "create_file", "src/illegal-after.txt", "bad", False)
    assert exc.value.code == "write_disabled"
    assert record.read_bytes() == original
    assert svc.info()["exec_policy"]["quarantined"] is True
