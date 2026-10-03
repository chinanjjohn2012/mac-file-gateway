import os
from pathlib import Path

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
