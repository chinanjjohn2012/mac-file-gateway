import os
import json
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from gateway.core import Gateway
from gateway.http import create_app


def executable(path: Path, body: str) -> None:
    path.write_text("#!/bin/sh\nset -eu\n" + body)
    path.chmod(0o755)


def test_http_run_disabled_without_opt_in(tmp_path):
    g = Gateway(tmp_path)
    try:
        with TestClient(create_app(g, enable_mcp=False), base_url="http://127.0.0.1:8765") as c:
            r = c.post("/run", json={"cwd": ".", "argv": ["pytest"]})
            assert r.status_code == 403
            assert r.json()["error"] == "exec_disabled"
    finally:
        g.close()


def test_http_run_preview_and_apply_with_pipenv(tmp_path, monkeypatch):
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
        with TestClient(create_app(g, enable_mcp=False), base_url="http://127.0.0.1:8765") as c:
            body = {"cwd": "service-c", "argv": ["pytest", "-q"]}
            preview = c.post("/run", json=body)
            assert preview.status_code == 200, preview.text
            assert preview.json()["effective_argv"] == ["pipenv", "run", "pytest", "-q"]
            assert preview.json()["executed"] is False
            applied = c.post("/run", json={**body, "dry_run": False})
            assert applied.status_code == 200, applied.text
            assert applied.json()["exit_code"] == 0
            assert "pipenv:run pytest -q" in applied.json()["stdout"]
    finally:
        g.close()


def test_http_run_rejects_shell(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    jobs = project / "service-c"
    jobs.mkdir()
    g = Gateway(project, allow_exec=True, exec_paths=("service-c",))
    try:
        with TestClient(create_app(g, enable_mcp=False), base_url="http://127.0.0.1:8765") as c:
            r = c.post("/run", json={"cwd": "service-c", "argv": ["sh", "-c", "echo bad"], "dry_run": False})
            assert r.status_code == 403
            assert r.json()["error"] == "command_not_allowed"
    finally:
        g.close()


@pytest.mark.parametrize("transport", ["rest", "mcp"])
def test_http_large_command_output_returns_complete_json(tmp_path, monkeypatch, transport):
    if transport == "mcp":
        pytest.importorskip("mcp")
    project = tmp_path / "project"
    project.mkdir()
    payload = {"entries": [{"path": f"module_{i}.py", "sha256": "a" * 64} for i in range(1000)]}
    text = json.dumps(payload, indent=2)
    (project / "inventory.json").write_text(text)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    executable(bin_dir / "pytest", "cat inventory.json\n")
    monkeypatch.setenv("PATH", str(bin_dir) + os.pathsep + os.environ.get("PATH", ""))
    g = Gateway(project, allow_exec=True, exec_paths=(".",))
    try:
        with TestClient(create_app(g, enable_mcp=transport == "mcp"), base_url="http://127.0.0.1:8765") as client:
            arguments = {"cwd": ".", "argv": ["pytest"], "dry_run": False}
            if transport == "rest":
                response = client.post("/run", json=arguments)
                assert response.status_code == 200, response.text[:1000]
                result = response.json()
            else:
                headers = {"Accept": "application/json, text/event-stream"}
                initialized = client.post("/mcp", headers=headers, json={
                    "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                        "protocolVersion": "2025-11-25", "capabilities": {},
                        "clientInfo": {"name": "large-output-test", "version": "1"},
                    },
                })
                assert initialized.status_code == 200, initialized.text[:1000]
                client.post("/mcp", headers=headers, json={"jsonrpc": "2.0", "method": "notifications/initialized"})
                response = client.post("/mcp", headers=headers, json={
                    "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                    "params": {"name": "run_command", "arguments": arguments},
                })
                assert response.status_code == 200, response.text[:1000]
                tool_result = response.json()["result"]
                assert not tool_result.get("isError"), str(tool_result)[:1000]
                result = tool_result["structuredContent"]
            assert result["exit_code"] == 0
            assert not result["stdout_truncated"]
            assert json.loads(result["stdout"]) == payload
            assert len(result["stdout"]) > 48_000
    finally:
        g.close()
