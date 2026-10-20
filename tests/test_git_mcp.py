"""D/T10: real official MCP SDK Git tool registry, parameters and apply.

Only disposable Git repositories are touched, never network remotes.
"""
from __future__ import annotations

import subprocess

import pytest
pytest.importorskip("mcp", reason="Official MCP SDK required")

from starlette.testclient import TestClient
from mcp.types import (
    CLIENT_CAPABILITIES_META_KEY, CLIENT_INFO_META_KEY,
    PROTOCOL_VERSION_META_KEY,
)

from gateway.core import Gateway
from gateway.http import create_app
from gateway.http_multi import create_multi_app
from gateway.workspaces import WorkspaceService, ActiveRuntimeInventory
from gateway.workspaces_config import parse_workspace_config
from gateway.mcp_multi import build_multi_mcp
from gateway.mcp_adapter import build_mcp


HEADERS = {"Accept": "application/json, text/event-stream",
           "Content-Type": "application/json"}
PROTOCOLS = ("2025-11-25", "2026-07-28")


def rpc(client, method, params=None):
    params = {} if params is None else params
    headers = dict(HEADERS)
    if getattr(client, "_git_test_protocol", "2025-11-25") == "2026-07-28":
        headers.update({
            "MCP-Protocol-Version": "2026-07-28",
            "Mcp-Method": method,
        })
        if method == "tools/call" and "name" in params:
            headers["Mcp-Name"] = params["name"]
        params = {
            "_meta": {
                PROTOCOL_VERSION_META_KEY: "2026-07-28",
                CLIENT_INFO_META_KEY: {"name": "git-d-modern", "version": "1"},
                CLIENT_CAPABILITIES_META_KEY: {},
            },
            **params,
        }
    resp = client.post(
        "/mcp", headers=headers,
        json={"jsonrpc": "2.0", "id": 11, "method": method, "params": params},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["result"]


def initialized(client, protocol):
    client._git_test_protocol = protocol
    if protocol == "2026-07-28":
        discovery = rpc(client, "server/discover")
        assert "2026-07-28" in discovery["supportedVersions"]
        return
    first = rpc(client, "initialize", {
        "protocolVersion": protocol, "capabilities": {},
        "clientInfo": {"name": "git-d-tests", "version": "1.0"},
    })
    assert "serverInfo" in first
    acknowledged = client.post(
        "/mcp", headers=HEADERS,
        json={"jsonrpc": "2.0", "method": "notifications/initialized"},
    )
    assert acknowledged.status_code in (200, 202)


def make_repo(path):
    path.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=path, check=True)


def legacy_gateway(tmp_path, *, git_enabled=True):
    root = tmp_path / "project"
    make_repo(root)
    private = tmp_path / "control"
    private.mkdir(mode=0o700)
    grants = ("status", "diff") if git_enabled else ()
    return Gateway(root, allow_git=git_enabled,
                   git_allowed_commands=grants,
                   git_state_dir=private / "git-state")


def multi_service(tmp_path, *, git_enabled=True):
    repo = tmp_path / "project"
    make_repo(repo)
    a, b = repo / "a", repo / "b"
    a.mkdir()
    b.mkdir()
    config = tmp_path / "control"
    config.mkdir(mode=0o700)
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    workspaces = {
        "a": {"root": str(a),
              "git": {"allowed_commands": ["status"] if git_enabled else []}},
        "b": {"root": str(b),
              "git": {"allowed_commands": ["diff"] if git_enabled else []}},
    }
    settings = parse_workspace_config({
        "schema_version": 1,
        "server": {"git": {"enabled": git_enabled}},
        "workspaces": workspaces,
    })
    return WorkspaceService(
        settings, config_dir=config,
        inventory=ActiveRuntimeInventory(paths=(runtime,)),
    )


def check_git_schema(tool, *, multi):
    annotations = tool["annotations"]
    assert annotations["readOnlyHint"] is False
    assert annotations["destructiveHint"] is True
    assert annotations["idempotentHint"] is False
    assert annotations["openWorldHint"] is True
    schema = tool["inputSchema"]
    assert schema["type"] == "object"
    assert "command" in schema["required"]
    assert ("workspace" in schema["required"]) is multi
    assert schema["properties"]["dry_run"]["default"] is True
    assert schema["properties"]["timeout_seconds"]["default"] == 120


@pytest.mark.parametrize("protocol", PROTOCOLS)
def test_legacy_mcp_git_tool_registers_only_with_independent_grant(tmp_path, protocol):
    gateway = legacy_gateway(tmp_path)
    try:
        assert "subscriptions/listen" not in build_mcp(gateway)._lowlevel_server._request_handlers
        with TestClient(create_app(gateway), base_url="http://127.0.0.1:8765") as client:
            initialized(client, protocol)
            tools = {x["name"]: x for x in rpc(client, "tools/list")["tools"]}
            assert "run_git" in tools and "run_command" not in tools
            check_git_schema(tools["run_git"], multi=False)

            # Bounded dry-run is pure: even a physically nonexistent Git root
            # would be accepted by preview. It has no lock/state/Popen.
            preview = rpc(client, "tools/call", {
                "name": "run_git", "arguments": {"command": "status"},
            })
            assert preview.get("isError") is not True, preview
            value = preview["structuredContent"]
            assert value["dry_run"] is True
            assert value["execute_started"] is False
            assert value["repository_checked"] is False
            assert value["branch_checked"] is False
            assert value["remote_checked"] is False
            assert value["effective_argv"][0] == "status"

            actual = rpc(client, "tools/call", {
                "name": "run_git", "arguments": {"command": "status", "dry_run": False},
            })
            assert actual.get("isError") is not True, actual
            status = actual["structuredContent"]
            assert status["exit_code"] == 0
            assert status["execute_started"] is True
            assert status["repository_checked"] is True
            assert status["cleanup_status"] == "complete"
            assert rpc(client, "tools/call", {"name": "gateway_info", "arguments": {}})["structuredContent"]["git_policy"]["adapter_exposed"] is True

            for arguments in (
                {"command": "push"},
                {"command": "status", "workspace": "unexpected"},
                {"command": "status", "dry_run": 0},
                {"command": "status", "timeout_seconds": True},
                {"command": "status", "options": {"hidden_git_option": 1}},
                {"command": "status", "paths": ["../outside"]},
                {"command": "checkout"},
            ):
                rejected = rpc(client, "tools/call", {
                    "name": "run_git", "arguments": arguments,
                })
                assert rejected.get("isError") is True, arguments

    finally:
        gateway.close()


@pytest.mark.parametrize("protocol", PROTOCOLS)
def test_multi_mcp_git_is_workspace_scoped_and_no_other_exec(tmp_path, protocol):
    service = multi_service(tmp_path)
    try:
        assert "subscriptions/listen" not in build_multi_mcp(service)._lowlevel_server._request_handlers
        with TestClient(create_multi_app(service), base_url="http://127.0.0.1:8765") as client:
            initialized(client, protocol)
            tools = {x["name"]: x for x in rpc(client, "tools/list")["tools"]}
            assert "run_git" in tools and "run_command" not in tools
            assert "run_skill_script" not in tools
            check_git_schema(tools["run_git"], multi=True)

            for arguments in (
                {"command": "status"},
                {"workspace": "missing", "command": "status"},
                {"workspace": "a", "command": "push"},
                {"workspace": "b", "command": "status"},
                {"workspace": "a", "command": "status", "timeout_seconds": False},
                {"workspace": "a", "command": "status", "dry_run": "false"},
                {"workspace": "a", "command": "status", "options": {"bogus": True}},
                {"workspace": "a", "command": "status", "cwd": "../outside"},
                {"workspace": "a", "command": "status", "paths": ["../outside"]},
            ):
                denied = rpc(client, "tools/call", {
                    "name": "run_git", "arguments": arguments,
                })
                assert denied.get("isError") is True, arguments

            preview = rpc(client, "tools/call", {
                "name": "run_git",
                "arguments": {"workspace": "a", "command": "status"},
            })["structuredContent"]
            assert preview["workspace"] == "a"
            assert preview["dry_run"] is True
            assert preview["execute_started"] is False
            assert preview["repository_checked"] is False

            actual = rpc(client, "tools/call", {
                "name": "run_git",
                "arguments": {"workspace": "a", "command": "status", "dry_run": False},
            })
            assert actual.get("isError") is not True, actual
            assert actual["structuredContent"]["exit_code"] == 0
            assert actual["structuredContent"]["cleanup_status"] == "complete"
            assert rpc(client, "tools/call", {"name": "gateway_info", "arguments": {}})["structuredContent"]["git_policy"]["adapter_exposed"] is True

            # L0 rejects duplicate JSON object keys BEFORE reaching SDK.
            raw = (b'{"jsonrpc":"2.0","id":43,"method":"tools/call",'
                   b'"params":{"name":"run_git","arguments":{'
                   b'"workspace":"a","workspace":"b","command":"status"}}}')
            response = client.post("/mcp", headers=HEADERS, content=raw)
            assert response.status_code == 400
    finally:
        service.close()


@pytest.mark.parametrize("mode", ["legacy", "multi"])
def test_mcp_git_tool_absent_without_effective_grants(tmp_path, mode):
    instance = legacy_gateway(tmp_path, git_enabled=False) if mode == "legacy" else multi_service(
        tmp_path, git_enabled=False,
    )
    try:
        app = create_app(instance) if mode == "legacy" else create_multi_app(instance)
        with TestClient(app, base_url="http://127.0.0.1:8765") as client:
            initialized(client, PROTOCOLS[0])
            names = {x["name"] for x in rpc(client, "tools/list")["tools"]}
            assert "run_git" not in names
            res = rpc(client, "tools/call", {
                "name": "run_git",
                "arguments": {"command": "status", **({"workspace": "a"} if mode == "multi" else {})},
            })
            assert res.get("isError") is True
    finally:
        instance.close()
