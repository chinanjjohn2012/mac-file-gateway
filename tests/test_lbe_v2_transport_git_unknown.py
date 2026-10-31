"""R005 F1: one real v2 service, REST + SDK MCP, physical intent witness,
real independently authorized Git subprocess + File Write, healthy and UNKNOWN.

Actual positive children here are *only* Git status in disposable pytest tmp_path.
No positive Gateway Exec, Go/Pipenv, signals, unmanaged user Mac/Tunnel, or T2/T3.
This is not a general OS process sandbox or a full F1/product PASS.
"""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest
from starlette.testclient import TestClient

from gateway.core import GatewayError
from gateway.exec_state import ExecStateStore
from gateway.http_multi import create_multi_app
from gateway.workspaces import ActiveRuntimeInventory, WorkspaceService
from gateway.workspaces_config import parse_workspace_config


_MCP_HEADERS = {
    "Accept": "application/json, text/event-stream",
    "Content-Type": "application/json",
}
_EXEC = {
    "workspace": "a", "cwd": "src", "argv": ["python", "ok.py"],
    "timeout_seconds": 5, "dry_run": False,
}
_GIT = {
    "workspace": "a", "command": "status", "dry_run": False,
    "timeout_seconds": 30,
}


def _frozen_intent_witness():
    """Load existing independently reviewed F1/B1 physical trap, never edit it."""
    path = (
        Path(__file__).parent / "b1b1_contracts" /
        "contract_multi_exec_default_deny_b1b1.py"
    )
    spec = importlib.util.spec_from_file_location("_r005_f1_intent_oracle", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module._IntentWitness, module._records


def _mcp(client: TestClient, method: str, params=None, *, id: int):
    response = client.post("/mcp", headers=_MCP_HEADERS, json={
        "jsonrpc": "2.0", "id": id, "method": method,
        "params": {} if params is None else params,
    })
    assert response.status_code == 200, response.text
    return response.json()


def _unapproved_exec(*args, **kwargs):
    raise AssertionError("R005_V2_EXEC_ATTEMPTED_CHILD_OR_OS_SIGNAL")


def _verify_no_exec_intent(
    client: TestClient, service: WorkspaceService, monkeypatch,
    state_root: Path, expected: str, *, first_id: int,
):
    """Both ingress paths AND direct API on exact same instance, with syscall trap.

    Each denial must leave the original owner-locked state bytes untouched;
    the frozen witness detects transient PREPARED write-then-unlink too.
    """
    Witness, records = _frozen_intent_witness()
    scene = SimpleNamespace(state=state_root)
    witness = Witness(state_root)
    expected_http_code = 503
    before = records(scene)
    with monkeypatch.context() as patch:
        witness.install(patch)
        patch.setattr(subprocess.Popen, "__init__", _unapproved_exec)
        patch.setattr(os, "kill", _unapproved_exec)
        patch.setattr(os, "killpg", _unapproved_exec, raising=False)
        patch.setattr(service.get("a").gateway, "run_command",
                      _unapproved_exec)

        # Direct synchronous service method
        with pytest.raises(GatewayError) as denied:
            service.invoke_exec(
                "a", "src", ["python", "ok.py"], timeout_seconds=5,
                dry_run=False)
        assert denied.value.code == expected

        # REST inside the same already-initialized ASGI TestClient
        rest = client.post("/run", json=_EXEC)
        assert rest.status_code == expected_http_code, rest.text
        assert rest.json()["error"] == expected

        # The real SDK MCP adapter with JSON-RPC tools/call
        reply = _mcp(client, "tools/call", {
            "name": "run_command", "arguments": _EXEC,
        }, id=first_id)
        assert reply["result"]["isError"] is True, reply
        assert reply["result"]["structuredContent"]["error"] == expected

        # An untrusted header does not mint a positive Exec permission.
        forged = client.post(
            "/run", json=_EXEC, headers={"X-Gateway-Test-Mode": "1"})
        assert forged.status_code == expected_http_code
        assert forged.json()["error"] == expected
        assert witness.events == [], witness.events
        assert witness._root_is_pinned()
        assert records(scene) == before
        assert service._lbe_owner.snapshot()["reserved_slots"] == 0
    # Crucial: Popen and syscall traps MUST NOT cover authorized Git itself.
    assert records(scene) == before


def _real_rest_git(client: TestClient):
    response = client.post("/git/run", json=_GIT)
    assert response.status_code == 200, response.text
    git = response.json()
    assert git["exit_code"] == 0, git
    assert git["execute_started"] is True
    assert git["repository_checked"] is True
    assert git["cleanup_status"] == "complete"
    return git


def _real_mcp_git(client: TestClient):
    reply = _mcp(client, "tools/call", {
        "name": "run_git", "arguments": _GIT,
    }, id=8)
    assert reply["result"].get("isError") is not True, reply
    git = reply["result"]["structuredContent"]
    assert git["exit_code"] == 0, git
    assert git["execute_started"] is True
    assert git["repository_checked"] is True
    assert git["cleanup_status"] == "complete"
    return git


def _real_rest_write(client: TestClient, service: WorkspaceService,
                     root: Path, old: str, new: str):
    original = service.invoke("a", "read_file", "src/safe.txt")
    assert old in original["content"]
    written = client.post("/write", json={
        "workspace": "a", "path": "src/safe.txt",
        "content": new, "expected_sha256": original["file_sha256"],
        "dry_run": False,
    })
    assert written.status_code == 200, written.text
    assert (root / "src" / "safe.txt").read_text() == new
    assert new.strip() in service.invoke(
        "a", "read_file", "src/safe.txt")["content"]


def test_r005_v2_rest_mcp_denial_and_real_git_file_both_old_state_modes(
    tmp_path: Path, monkeypatch,
):
    """One service, two persisted Exec states, real REST and SDK MCP + Git.

    Hosted Linux CI exercises actual service, real private ExecStateStore,
    real GitCLIExecutor/Popen and disk File Write; witness checks transient
    Exec intent during both REST and SDK MCP requests. This test never makes
    a positive Exec attempt succeed.
    """
    pytest.importorskip("mcp")
    projects = tmp_path / "projects"
    a, b = projects / "a", projects / "b"
    (a / "src").mkdir(parents=True)
    b.mkdir()
    (a / "src" / "ok.py").write_text("print('NOT_EXECUTED')\n")
    (a / "src" / "safe.txt").write_text("FIRST\n")

    subprocess.run(
        ["git", "init", "-q"], cwd=a, check=True,
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=15,
    )
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    seed = ExecStateStore(
        private / "exec-state", workspace_roots=(str(a), str(b)))
    assert seed.durability_state == "healthy"
    seed.close()

    settings = parse_workspace_config({
        "schema_version": 2,
        "server": {"port": 8765, "transport": "http",
                   "git": {"enabled": True}},
        "workspaces": {
            "a": {"root": str(a),
                  "exec": {"paths": ["src"], "runners": []},
                  "write": {"enabled": True, "paths": ["src"]},
                  "git": {"allowed_commands": ["status"]}},
            "b": {"root": str(b)},
        },
    })
    svc = WorkspaceService(
        settings, config_dir=private,
        inventory=ActiveRuntimeInventory(paths=(runtime,)))
    state_root = private / "exec-state"
    try:
        assert svc.any_exec and svc.any_git and svc.any_write
        with TestClient(create_multi_app(svc),
                        base_url="http://127.0.0.1:8765") as client:
            initialized = _mcp(client, "initialize", {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "r005-v2-combined", "version": "1"},
            }, id=1)
            assert "result" in initialized
            notify = client.post("/mcp", headers=_MCP_HEADERS, json={
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
            })
            assert notify.status_code in (200, 202)
            healthy = client.get("/info").json()["exec_policy"]
            assert healthy == client.get("/health").json()["exec_policy"]
            assert healthy["enabled"] is True
            assert healthy["available"] is False
            assert healthy["completion_capability"] == "none"
            assert healthy["durability_state"] == "healthy"
            preview = client.post("/run", json={**_EXEC, "dry_run": True})
            assert preview.status_code == 200
            assert preview.json()["status"] == "preview"
            assert preview.json()["executed"] is False
            _verify_no_exec_intent(
                client, svc, monkeypatch, state_root,
                "exec_cleanup_proof_required", first_id=2)

            # Real Git and physical File writes, SAME live instance/Workspace.
            _real_rest_git(client)
            _real_rest_write(client, svc, a, "FIRST", "SECOND\n")

            # Seed UNKNOWN only from the original legitimate Exec store APIs.
            # No positive Exec Popen, no signal, no replay or reset.
            store = svc._exec_state
            assert store is not None
            st = a.stat()
            attempt = store.prepare("a", (st.st_dev, st.st_ino))
            store.mark_unknown(attempt)
            marker = state_root / ("r-" + attempt + ".json")
            marker_bytes = marker.read_bytes()
            assert store.durability_state == "quarantined"
            quarantined = client.get("/health").json()["exec_policy"]
            assert quarantined["quarantined"] is True
            assert quarantined["available"] is False

            _verify_no_exec_intent(
                client, svc, monkeypatch, state_root,
                "exec_quarantined", first_id=3)
            _real_rest_git(client)
            _real_mcp_git(client)
            _real_rest_write(client, svc, a, "SECOND", "THIRD\n")

            # Wrong-Workspace callers must not borrow A's Git or File grant.
            wrong_git = client.post(
                "/git/run", json={**_GIT, "workspace": "b"})
            assert wrong_git.status_code == 403
            assert wrong_git.json()["error"] == "git_command_not_allowed"
            wrong_write = client.post("/create", json={
                "workspace": "b", "path": "illegal.txt",
                "content": "NO", "dry_run": False,
            })
            assert wrong_write.status_code == 403
            assert wrong_write.json()["error"] == "write_disabled"
            wrong_exec = client.post(
                "/run", json={**_EXEC, "workspace": "b"})
            assert wrong_exec.status_code == 403
            assert wrong_exec.json()["error"] == "exec_disabled"
            assert not (b / "illegal.txt").exists()
            assert marker.read_bytes() == marker_bytes
            assert svc.info()["exec_policy"]["quarantined"] is True
            assert store.durability_state == "quarantined"
            assert svc._lbe_owner.snapshot()["reserved_slots"] == 0
    finally:
        svc.close()
