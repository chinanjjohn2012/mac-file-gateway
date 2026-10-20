"""Task 2 (D1/D2/R1): shared Legacy/Multi-bound CLI safety checks.

These tests exercise the production CommandRunner, not a substitute validator.
Rejected requests must not reach Popen in preview or apply, regardless of runner.
"""
from __future__ import annotations

import os
from contextlib import contextmanager
from pathlib import Path

import pytest

from gateway.core import Gateway, GatewayError


def _executable(path: Path, command: str) -> None:
    path.write_text("#!/bin/sh\nset -eu\n" + command + "\n")
    path.chmod(0o755)


@pytest.fixture
def project(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "service").mkdir()
    (root / "service" / "tests").mkdir()
    (root / "service" / "tests" / "pytest.ini").write_text("[pytest]\n")
    (root / "service" / "go.alt.mod").write_text("module example.invalid/test\n")
    (root / "service" / "Pipfile").write_text("[packages]\n")
    return root


@pytest.fixture
def fake_tools(tmp_path, monkeypatch):
    directory = tmp_path / "bin"
    directory.mkdir()
    marker = tmp_path / "started-marker"
    for command in ("go", "pytest", "python", "pipenv"):
        _executable(directory / command,
                    f'touch "{marker}"; printf "synthetic:%s:%s\\n" "{command}" "$*"; '
                    'printf "pytest_addopts:%s\\n" "${PYTEST_ADDOPTS-unset}"')
    monkeypatch.setenv("PATH", str(directory) + os.pathsep + os.environ.get("PATH", ""))
    monkeypatch.setenv("PYTEST_ADDOPTS", "--pdb")
    return marker


@contextmanager
def _gateway(project: Path, runner: str):
    # Test both execution dispatch modes via the SAME CommandRunner validator.
    g = Gateway(project, allow_exec=True, exec_paths=("service",),
                exec_runners=(f"service={runner}",))
    try:
        yield g
    finally:
        g.close()


_GO_HOOKS = (
    ["-exec=external"], ["--exec=external"], ["-exec", "external"], ["--exec", "external"],
    ["-toolexec=external"], ["--toolexec=external"], ["-toolexec", "external"], ["--toolexec", "external"],
    ["-vettool=external"], ["--vettool=external"], ["-vettool", "external"], ["--vettool", "external"],
    ["./...", "--exec=external"], ["./...", "--toolexec=external"],
    ["./...", "--vettool=external"], ["--", "--exec=external"],
)


@pytest.mark.parametrize("operation", ["test", "vet"])
@pytest.mark.parametrize("extra", _GO_HOOKS)
@pytest.mark.parametrize("runner", ["direct", "pipenv"])
@pytest.mark.parametrize("dry_run", [True, False])
def test_go_external_tool_hooks_rejected_before_popen(project, fake_tools, monkeypatch,
                                                      operation, extra, runner, dry_run):
    invoked = []
    def forbidden(*args, **kwargs):
        invoked.append(args)
        raise AssertionError("Popen must never run a Go external hook")
    monkeypatch.setattr("gateway.executor.subprocess.Popen", forbidden)
    with _gateway(project, runner) as g:
        with pytest.raises(GatewayError) as error:
            g.run_command("service", ["go", operation, *extra], dry_run=dry_run)
        assert error.value.code == "command_not_allowed"
        assert invoked == []
        assert not fake_tools.exists()


_GO_OUT_OF_SCOPE = (
    ["-modfile=../outside/go.mod"], ["-modfile", "../outside/go.mod"],
    ["--modfile=../outside/go.mod"], ["--modfile", "../outside/go.mod"],
    ["-overlay=../outside/over.json"], ["-overlay", "../outside/over.json"],
    ["-coverprofile=../outside/coverage.out"], ["-coverprofile", "../outside/coverage.out"],
    ["-modfile=/tmp/other.mod"], ["-modfile", "~/other.mod"],
)


@pytest.mark.parametrize("extra", _GO_OUT_OF_SCOPE)
@pytest.mark.parametrize("runner", ["direct", "pipenv"])
@pytest.mark.parametrize("dry_run", [True, False])
def test_go_option_path_value_rejected_before_popen(project, fake_tools, monkeypatch,
                                                    extra, runner, dry_run):
    count = []
    def forbidden(*a, **kw):
        count.append(1)
        raise AssertionError("unsafe path reached Popen")
    monkeypatch.setattr("gateway.executor.subprocess.Popen", forbidden)
    with _gateway(project, runner) as g:
        with pytest.raises(GatewayError) as error:
            g.run_command("service", ["go", "test", *extra], dry_run=dry_run)
        assert error.value.code == "command_not_allowed"
    assert count == []
    assert not fake_tools.exists()


_PYTEST_INVALID_PATHS = (
    ["-c../outside/pytest.ini"], ["-c", "../outside/pytest.ini"],
    ["-c=../outside/pytest.ini"], ["--config-file=../outside/pytest.ini"],
    ["--config-file", "../outside/pytest.ini"],
    ["--config-file=/tmp/pytest.ini"], ["-c", "~/pytest.ini"],
    ["--basetemp=../outside"], ["--basetemp", "../outside"],
    ["--junitxml=../outside/result.xml"],
)

_PYTEST_INDIRECT = (
    ["@args.txt"], ["--", "@args.txt"], ["--", "@../outside/evil.txt"],
    ["-o", "addopts=--pdb"], ["-o", "addopts="], ["-oaddopts=--trace"],
    ["-o=addopts=--pdb"], ["--override-ini=addopts=--pdb"],
    ["--override-ini", "addopts=--trace"], ["-qoaddopts=--pdb"],
    ["-qo=addopts=--trace"], ["-vvoaddopts=--pdb"],
    ["-o", "ADDOPTS=--trace"], ["-o", "addopts"],
    ["--override-ini="], ["-o"],
)


@pytest.mark.parametrize("extra", _PYTEST_INVALID_PATHS + _PYTEST_INDIRECT)
@pytest.mark.parametrize("python_module", [False, True])
@pytest.mark.parametrize("runner", ["direct", "pipenv"])
@pytest.mark.parametrize("dry_run", [True, False])
def test_pytest_remote_path_or_indirection_rejected_before_popen(project, fake_tools, monkeypatch,
                                                                 extra, python_module, runner, dry_run):
    count = []
    def forbidden(*a, **kw):
        count.append(1)
        raise AssertionError("unsafe pytest request reached Popen")
    monkeypatch.setattr("gateway.executor.subprocess.Popen", forbidden)
    argv = (["python", "-m", "pytest"] if python_module else ["pytest"]) + list(extra)
    with _gateway(project, runner) as g:
        with pytest.raises(GatewayError) as error:
            g.run_command("service", argv, dry_run=dry_run)
        assert error.value.code == "command_not_allowed"
    assert count == []
    assert not fake_tools.exists()


@pytest.mark.parametrize("argv", [
    ["pytest", "-q"],
    ["pytest", "-c", "tests/pytest.ini", "-q"],
    ["pytest", "-ctests/pytest.ini"],
    ["pytest", "--config-file=tests/pytest.ini"],
    ["pytest", "-o", "log_cli=true", "-q"],
    ["pytest", "-o=log_cli=true", "-q"],
    ["pytest", "-qo=log_cli=true"],
    ["pytest", "--override-ini=log_cli=true"],
    ["pytest", "-k", "test_addopts"],
    ["pytest", "-m", "not addopts"],
    ["pytest", "tests/test_work.py::test_addopts"],
    ["pytest", "--", "--override-ini=addopts=bogus"],
    ["python", "-m", "pytest", "-q", "-o", "log_cli=true"],
    ["go", "test", "./...", "-modfile=go.alt.mod"],
    ["go", "vet", "-modfile", "go.alt.mod", "./..."],
    ["go", "test", "-coverprofile=coverage.out", "./..."],
])
@pytest.mark.parametrize("runner", ["direct", "pipenv"])
def test_safe_commands_still_execute_with_isolated_tools(project, fake_tools, argv, runner):
    with _gateway(project, runner) as g:
        preview = g.run_command("service", argv)
        assert preview["dry_run"] is True
        assert preview["executed"] is False
        assert not fake_tools.exists()
        result = g.run_command("service", argv, dry_run=False)
        assert result["exit_code"] == 0
        assert result["timed_out"] is False
        assert "synthetic:" in result["stdout"]
        assert fake_tools.exists()
        fake_tools.unlink()


def test_pytest_addopts_from_gateway_environment_is_never_inherited(project, fake_tools):
    with _gateway(project, "direct") as g:
        result = g.run_command("service", ["pytest", "-q"], dry_run=False)
    assert result["exit_code"] == 0
    assert result["effective_argv"] == ["pytest", "-q"]
    # The fake executor's argv never contains PYTEST_ADDOPTS; the runner only
    # inherits the explicit SAFE_ENV_KEYS and has no key for PYTEST_ADDOPTS.
    assert "pytest_addopts:unset" in result["stdout"]
    assert "--pdb" not in result["stdout"]


@pytest.mark.parametrize("argv", [
    ["go", "test", "--exec=external"],
    ["go", "vet", "-modfile=../other/go.mod"],
    ["pytest", "-c../other/pytest.ini"],
    ["python", "-m", "pytest", "-qoaddopts=--pdb"],
    ["pytest", "--", "@args.txt"],
])
@pytest.mark.parametrize("runner", ["direct", "pipenv"])
@pytest.mark.parametrize("dry_run", [True, False])
def test_legacy_rest_rejects_remote_indirection(project, fake_tools, argv, runner, dry_run):
    from starlette.testclient import TestClient
    from gateway.http import create_app

    with _gateway(project, runner) as g:
        with TestClient(create_app(g, enable_mcp=False), base_url="http://127.0.0.1:8765") as client:
            response = client.post("/run", json={"cwd": "service", "argv": argv, "dry_run": dry_run})
            assert response.status_code == 403, response.text
            assert response.json()["error"] == "command_not_allowed"
    assert not fake_tools.exists()


@pytest.mark.parametrize("argv", [
    ["go", "test", "--exec=external"],
    ["pytest", "-o=addopts=--trace"],
    ["pytest", "-c../outside/pytest.ini"],
])
@pytest.mark.parametrize("dry_run", [True, False])
def test_legacy_mcp_rejects_remote_indirection(project, fake_tools, argv, dry_run):
    from starlette.testclient import TestClient
    from gateway.http import create_app

    headers = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
    with _gateway(project, "direct") as g:
        with TestClient(create_app(g), base_url="http://127.0.0.1:8765") as client:
            init = client.post("/mcp", headers=headers, json={
                "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                    "protocolVersion": "2025-11-25", "capabilities": {},
                    "clientInfo": {"name": "task2-test", "version": "1.0"},
                },
            })
            assert init.status_code == 200, init.text
            response = client.post("/mcp", headers=headers, json={
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "run_command", "arguments": {
                    "cwd": "service", "argv": argv, "dry_run": dry_run,
                }},
            })
            assert response.status_code == 200, response.text
            result = response.json()["result"]
            assert result.get("isError") is True, result
            assert "command_not_allowed" in str(result.get("content")), result
    assert not fake_tools.exists()
