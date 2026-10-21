"""D boundary: Git grants publish only independently authorized Git adapters."""
from __future__ import annotations

import json
import subprocess

import pytest

pytest.importorskip("mcp", reason="MCP SDK needed for registry regression")
from starlette.testclient import TestClient

from gateway.core import Gateway
from gateway.http import create_app
from gateway.http_multi import create_multi_app
from gateway.workspaces import ActiveRuntimeInventory, WorkspaceService
from gateway.workspaces_config import parse_workspace_config


HEADERS = {"Accept": "application/json, text/event-stream",
           "Content-Type": "application/json"}


def rpc(client, method, params=None):
    return client.post("/mcp", headers=HEADERS, json={
        "jsonrpc": "2.0", "id": 21, "method": method, "params": params or {},
    })


def assert_git_adapters_enabled(client, *, multi):
    init = rpc(client, "initialize", {
        "protocolVersion": "2025-11-25", "capabilities": {},
        "clientInfo": {"name": "git-phase-c", "version": "1"},
    })
    assert init.status_code == 200, init.text
    client.post("/mcp", headers=HEADERS,
                json={"jsonrpc": "2.0", "method": "notifications/initialized"})
    reply = rpc(client, "tools/list")
    assert reply.status_code == 200, reply.text
    names = {tool["name"] for tool in reply.json()["result"]["tools"]}
    assert "gateway_info" in names
    assert "run_git" in names
    assert "run_command" not in names
    assert client.get("/git/run").status_code == 405
    payload = {"command": "status"}
    if multi:
        assert client.post("/git/run", json=payload).status_code == 400
        payload["workspace"] = "a"
    response = client.post("/git/run", json=payload)
    assert response.status_code == 200, response.text
    assert response.json()["dry_run"] is True
    assert response.json()["execute_started"] is False
    assert response.json()["repository_checked"] is False


def test_legacy_git_grant_registers_reviewed_mcp_and_rest(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    private = tmp_path / "control"
    private.mkdir(mode=0o700)
    gateway = Gateway(root, allow_git=True, git_allowed_commands=("status",),
                      git_state_dir=private / "git-state")
    try:
        assert gateway.info()["git_policy"]["enabled"] is True
        assert gateway.info()["git_policy"]["adapter_exposed"] is False
        with TestClient(create_app(gateway, port=8765), base_url="http://127.0.0.1:8765") as client:
            assert_git_adapters_enabled(client, multi=False)
            reply = client.get("/info")
            assert reply.status_code == 200
            assert reply.json()["git_policy"]["enabled"] is True
            assert reply.json()["git_policy"]["adapter_exposed"] is True
    finally:
        gateway.close()


def test_multi_git_grant_requires_explicit_workspace_on_mcp_and_rest(tmp_path):
    a = tmp_path / "project"
    a.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=a, check=True)
    config = tmp_path / "control"
    config.mkdir(mode=0o700)
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    settings = parse_workspace_config({
        "schema_version": 1,
        "server": {"git": {"enabled": True}},
        "workspaces": {"a": {"root": str(a),
                             "git": {"allowed_commands": ["status"]}}},
    })
    svc = WorkspaceService(settings, config_dir=config,
                           inventory=ActiveRuntimeInventory(paths=(runtime,)))
    try:
        assert svc.any_git
        assert svc.info()["git_policy"]["adapter_exposed"] is False
        with TestClient(create_multi_app(svc, port=8765), base_url="http://127.0.0.1:8765") as client:
            assert_git_adapters_enabled(client, multi=True)
            assert client.get("/info").json()["git_policy"]["enabled"] is True
            assert client.get("/info").json()["git_policy"]["adapter_exposed"] is True
    finally:
        svc.close()
