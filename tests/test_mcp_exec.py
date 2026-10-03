"""Official MCP SDK coverage for controlled execution."""
import os
from pathlib import Path

import pytest
pytest.importorskip("mcp", reason="Official MCP SDK unavailable in this environment")

from starlette.testclient import TestClient

from gateway.core import Gateway
from gateway.http import create_app

HEADERS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}


def rpc(client, method, params=None):
    r = client.post("/mcp", headers=HEADERS, json={"jsonrpc": "2.0", "id": 2, "method": method, "params": params or {}})
    assert r.status_code == 200, r.text
    return r.json()["result"]


def initialize(client):
    r = client.post("/mcp", headers=HEADERS, json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "exec-tests", "version": "2.3"}
    }})
    assert r.status_code == 200, r.text
    client.post("/mcp", headers=HEADERS, json={"jsonrpc": "2.0", "method": "notifications/initialized"})


def executable(path: Path, body: str) -> None:
    path.write_text("#!/bin/sh\nset -eu\n" + body)
    path.chmod(0o755)


def test_run_command_schema_and_execution(tmp_path, monkeypatch):
    project = tmp_path / "project"
    project.mkdir()
    jobs = project / "service-c"
    jobs.mkdir()
    (jobs / "Pipfile").write_text("[packages]\n")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    executable(bin_dir / "pipenv", 'printf "pipenv:%s\\n" "$*"')
    monkeypatch.setenv("PATH", str(bin_dir) + os.pathsep + os.environ.get("PATH", ""))

    g = Gateway(project, allow_exec=True, exec_paths=("service-c",))
    try:
        with TestClient(create_app(g), base_url="http://127.0.0.1:8765") as client:
            initialize(client)
            tools = {tool["name"]: tool for tool in rpc(client, "tools/list")["tools"]}
            assert "run_command" in tools
            tool = tools["run_command"]
            assert tool["annotations"]["destructiveHint"] is True
            assert tool["annotations"]["idempotentHint"] is False
            assert tool["annotations"]["openWorldHint"] is True
            assert tool["inputSchema"]["properties"]["dry_run"]["default"] is True

            preview = rpc(client, "tools/call", {"name": "run_command", "arguments": {
                "cwd": "service-c", "argv": ["pytest", "-q"]
            }})
            assert not preview.get("isError", False), preview
            assert preview["structuredContent"]["effective_argv"] == ["pipenv", "run", "pytest", "-q"]
            assert preview["structuredContent"]["executed"] is False

            applied = rpc(client, "tools/call", {"name": "run_command", "arguments": {
                "cwd": "service-c", "argv": ["pytest", "-q"], "dry_run": False
            }})
            assert not applied.get("isError", False), applied
            assert applied["structuredContent"]["exit_code"] == 0
    finally:
        g.close()


def test_run_command_absent_when_exec_disabled(tmp_path):
    g = Gateway(tmp_path)
    try:
        with TestClient(create_app(g), base_url="http://127.0.0.1:8765") as client:
            initialize(client)
            names = {tool["name"] for tool in rpc(client, "tools/list")["tools"]}
            assert "run_command" not in names
    finally:
        g.close()
