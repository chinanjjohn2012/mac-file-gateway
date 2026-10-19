"""Real official MCP SDK v2.3 HTTP contract across both protocol eras.

2025-era initialize coverage also lives in test_mcp.py and test_phase1_multi_mcp.py.
These tests explicitly address 2026-07-28, with the required modern metadata.
"""
import json

import pytest

pytest.importorskip("mcp", reason="Official MCP SDK v2 is required")
from mcp.types import (
    CLIENT_CAPABILITIES_META_KEY,
    CLIENT_INFO_META_KEY,
    PROTOCOL_VERSION_META_KEY,
)
from starlette.testclient import TestClient

from gateway.core import Gateway
from gateway.http import create_app
from gateway.http_multi import create_multi_app
from gateway.workspaces import ActiveRuntimeInventory, WorkspaceService
from gateway.workspaces_config import parse_workspace_config

MODERN_HEADERS = {
    "Accept": "application/json, text/event-stream",
    "Content-Type": "application/json",
    "MCP-Protocol-Version": "2026-07-28",
}
MODERN_META = {
    PROTOCOL_VERSION_META_KEY: "2026-07-28",
    CLIENT_INFO_META_KEY: {"name": "gateway-v2-tests", "version": "1"},
    CLIENT_CAPABILITIES_META_KEY: {},
}


def modern_body(method, params=None):
    return {
        "jsonrpc": "2.0",
        "id": 4,
        "method": method,
        "params": {"_meta": MODERN_META, **(params or {})},
    }


def modern_call(client, method, params=None):
    response = client.post("/mcp", headers=MODERN_HEADERS, json=modern_body(method, params))
    assert response.status_code == 200, response.text
    payload = response.json()
    assert "result" in payload, payload
    return payload["result"]


def test_modern_read_only_tools_and_discovery(tmp_path):
    (tmp_path / "demo.py").write_text("x = 1\n")
    gateway = Gateway(tmp_path)
    try:
        with TestClient(create_app(gateway), base_url="http://127.0.0.1:8765") as client:
            discovered = modern_call(client, "server/discover")
            assert "supportedVersions" in discovered
            tools = modern_call(client, "tools/list")["tools"]
            assert {tool["name"] for tool in tools} == {
                "gateway_info", "list_files", "read_file", "search_files",
            }
            read = modern_call(client, "tools/call", {
                "name": "read_file", "arguments": {"path": "demo.py"},
            })
            assert read["structuredContent"]["content"] == "1: x = 1"
            invalid = modern_call(client, "tools/call", {
                "name": "read_file", "arguments": {"path": "demo.py", "unexpected": "x"},
            })
            assert invalid["isError"] is True
    finally:
        gateway.close()


def test_modern_writes_keep_strict_validation_and_preview(tmp_path):
    gateway = Gateway(tmp_path, allow_write=True)
    try:
        with TestClient(create_app(gateway), base_url="http://127.0.0.1:8765") as client:
            args = {"path": "demo.py", "content": "x = 1\n"}
            preview = modern_call(client, "tools/call", {
                "name": "create_file", "arguments": args,
            })
            assert preview["structuredContent"]["applied"] is False
            assert not (tmp_path / "demo.py").exists()
            for extra in ({"dry_run": "false"}, {"dry_run": 0}, {"unknown": 1}):
                rejected = modern_call(client, "tools/call", {
                    "name": "create_file",
                    "arguments": {**args, **extra},
                })
                assert rejected["isError"] is True
                assert not (tmp_path / "demo.py").exists()
            created = modern_call(client, "tools/call", {
                "name": "create_file",
                "arguments": {**args, "dry_run": False},
            })
            assert created["structuredContent"]["applied"] is True
            assert (tmp_path / "demo.py").read_text() == "x = 1\n"
    finally:
        gateway.close()


def test_modern_multi_workspace_isolation_and_large_wire_body(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir()
    b.mkdir()
    (a / "demo.py").write_text("origin = 'a'\n")
    (b / "demo.py").write_text("origin = 'b'\n")
    config_dir = tmp_path / "config"
    config_dir.mkdir(mode=0o700)
    config_dir.chmod(0o700)
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    settings = parse_workspace_config({
        "schema_version": 1,
        "workspaces": {
            "a": {"root": str(a), "write": {"enabled": True, "paths": ["."]}},
            "b": {"root": str(b), "write": {"enabled": False}},
        },
    })
    service = WorkspaceService(
        settings,
        config_dir=config_dir,
        inventory=ActiveRuntimeInventory(paths=(runtime,)),
    )
    try:
        with TestClient(create_multi_app(service), base_url="http://127.0.0.1:8765") as client:
            for workspace, value in (("a", "'a'"), ("b", "'b'")):
                read = modern_call(client, "tools/call", {
                    "name": "read_file",
                    "arguments": {"workspace": workspace, "path": "demo.py"},
                })
                assert read["structuredContent"]["content"].endswith(value)
            for args in (
                {"path": "demo.py"},
                {"workspace": "a", "path": "demo.py", "extra_workspace": "b"},
                {"workspace": "b", "path": "demo.py", "dry_run": False},
            ):
                name = "create_file" if "dry_run" in args else "read_file"
                response = modern_call(client, "tools/call", {
                    "name": name, "arguments": args,
                })
                assert response["isError"] is True
            denied = modern_call(client, "tools/call", {
                "name": "create_file",
                "arguments": {"workspace": "b", "path": "private.py", "content": "x", "dry_run": False},
            })
            assert denied["isError"] is True
            assert not (b / "private.py").exists()

            # A >4 MiB wire payload remains admitted under the 8 MiB multi-mode limit.
            # Escaped JSON is intentionally much larger than the decoded content.
            payload = json.dumps(modern_body("tools/call", {
                "name": "create_file",
                "arguments": {"workspace": "a", "path": "large.py", "content": "MARKER"},
            })).encode("utf-8")
            payload = payload.replace(b'"MARKER"', b'"' + b'\\u0061' * 800_000 + b'"')
            assert 4 * 1024 * 1024 < len(payload) < 8 * 1024 * 1024
            response = client.post("/mcp", headers=MODERN_HEADERS, content=payload)
            assert response.status_code == 200, response.text[:500]
            assert response.json()["result"]["structuredContent"]["applied"] is False
            assert not (a / "large.py").exists()

            # Duplicate object members are refused by L0 before SDK parsing.
            raw = (b'{"jsonrpc":"2.0","id":6,"method":"tools/call",'
                   b'"params":{"name":"read_file",'
                   b'"arguments":{"workspace":"a","workspace":"b","path":"demo.py"}}}')
            duplicate = client.post("/mcp", headers=MODERN_HEADERS, content=raw)
            assert duplicate.status_code == 400
    finally:
        service.close()
