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
    ["pytest", "-k", "@args.txt"],
    ["go", "test", "-C=../outside", "-v"],
    ["pytest", "-o", "cache_dir=../outside-cache"],
    ["pytest", "--junit-xml=../outside/report.xml"],
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
    ["pytest", "-k", "@args.txt"],
    ["go", "test", "-C=../outside", "-v"],
    ["pytest", "-o", "cache_dir=../outside-cache"],
    ["pytest", "--junit-xml=../outside/report.xml"],
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


# PR #10 independent macOS review: P1 x2, P2 x2.
# These are intentionally exercised via the real Gateway/CommandRunner in
# both dry-run and apply modes, and each rejection must happen before Popen.
_REVIEW_REMAINING_DENIED = (
    ["pytest", "-k", "@args.txt"],
    ["pytest", "-m", "@args.txt"],
    ["python", "-m", "pytest", "-k", "@args.txt"],
    ["go", "test", "-C=../outside", "-v"],
    ["go", "test", "-C=subdir", "-v"],  # changes the Gateway-authorized cwd
    ["go", "vet", "--C=../outside"],
    ["go", "test", "-test.outputdir=../outside"],
    ["go", "test", "-test.coverprofile=../outside"],
    ["go", "test", "-test.cpuprofile=../outside"],
    ["go", "test", "-test.gocoverdir=../outside"],
    ["go", "test", "-test.fuzzcachedir=../outside"],
    ["go", "test", "-test.testlogfile=../outside"],
    ["pytest", "-o", "cache_dir=../outside-cache"],
    ["pytest", "-o=cache_dir=../outside-cache"],
    ["pytest", "-ocache_dir=../outside-cache"],
    ["pytest", "--override-ini=cache_dir=../outside-cache"],
    ["pytest", "-qo=cache_dir=../outside-cache"],
    ["pytest", "-o", "log_file=../outside.log"],
    ["pytest", "-o", 'testpaths="../outside"'],
    ["pytest", "-o", 'pythonpath="../outside"'],
    ["pytest", "--junit-xml=../outside/report.xml"],
    ["pytest", "--junit-xml", "../outside/report.xml"],
    ["python", "-m", "pytest", "--junit-xml=../outside/report.xml"],
)


@pytest.mark.parametrize("argv", _REVIEW_REMAINING_DENIED)
@pytest.mark.parametrize("runner", ["direct", "pipenv"])
@pytest.mark.parametrize("dry_run", [True, False])
def test_review_remaining_bypasses_rejected_before_popen(
    project, fake_tools, monkeypatch, argv, runner, dry_run
):
    attempts = []

    def forbidden(*args, **kwargs):
        attempts.append(args)
        raise AssertionError("Rejected CLI reached Popen")

    monkeypatch.setattr("gateway.executor.subprocess.Popen", forbidden)
    with _gateway(project, runner) as g:
        with pytest.raises(GatewayError) as error:
            g.run_command("service", argv, dry_run=dry_run)
        assert error.value.code == "command_not_allowed"
    assert attempts == []
    assert not fake_tools.exists()


@pytest.mark.parametrize("argv", (
    ["pytest", "-k", "not slow"],
    ["pytest", "-o", "cache_dir=.pytest_cache"],
    ["pytest", "-o", "log_cli=true"],
    ["pytest", "--junit-xml=reports.xml"],
    ["pytest", "--junit-xml", "reports.xml"],
    ["go", "test", "-test.outputdir=reports"],
    ["go", "test", "./...", "-coverprofile=coverage.out"],
))
@pytest.mark.parametrize("runner", ["direct", "pipenv"])
def test_review_safe_options_preserved(project, fake_tools, argv, runner):
    with _gateway(project, runner) as g:
        preview = g.run_command("service", argv)
        assert preview["executed"] is False
        assert not fake_tools.exists()
        result = g.run_command("service", argv, dry_run=False)
        assert result["exit_code"] == 0, result
        assert result["timed_out"] is False
        assert fake_tools.exists()
        fake_tools.unlink()


# Independent P2 review of a58a83e7: scalar pytest INI path types, cache
# environment expansion and Go's PGO build flag. These run through Gateway.
@pytest.mark.parametrize("ini", (
    "cache_dir=cache files",
    "log_file=reports/test results.log",
))
@pytest.mark.parametrize("style", ("-o", "--override-ini", "-o=", "--override-ini="))
@pytest.mark.parametrize("runner", ("direct", "pipenv"))
def test_review3_scalar_ini_paths_accept_spaces(project, fake_tools, ini, style, runner):
    args = [style, ini] if not style.endswith("=") else [style + ini]
    with _gateway(project, runner) as g:
        preview = g.run_command("service", ["pytest", *args])
        assert preview["executed"] is False
        assert not fake_tools.exists()
        result = g.run_command("service", ["pytest", *args], dry_run=False)
        assert result["exit_code"] == 0, result
        assert fake_tools.exists()
        fake_tools.unlink()


@pytest.mark.parametrize("ini", (
    'testpaths=tests "more tests"',
    'pythonpath=src "generated code"',
    'norecursedirs="build dir" temp',
))
@pytest.mark.parametrize("runner", ("direct", "pipenv"))
def test_review3_quoted_ini_pathlists_still_work(project, fake_tools, ini, runner):
    with _gateway(project, runner) as g:
        preview = g.run_command("service", ["pytest", "-o", ini])
        assert preview["executed"] is False
        result = g.run_command("service", ["pytest", "-o", ini], dry_run=False)
        assert result["exit_code"] == 0, result
        assert fake_tools.exists()
        fake_tools.unlink()


@pytest.mark.parametrize("ini", (
    "cache_dir=${HOME}/.pytest_cache",
    "cache_dir=$HOME/.pytest_cache",
    "log_file=reports/$TEST_LOG.log",
    'testpaths=tests "${HOME}/outside"',
    "pythonpath=$HOME/src",
))
@pytest.mark.parametrize("style", ("short", "long"))
@pytest.mark.parametrize("runner", ("direct", "pipenv"))
@pytest.mark.parametrize("dry_run", (True, False))
def test_review3_ini_environment_refs_block_before_spawn(
    project, fake_tools, tmp_path, monkeypatch, ini, style, runner, dry_run
):
    monkeypatch.setenv("HOME", str(tmp_path / "outside-virtual-home"))
    invoked = []
    def forbidden(*args, **kwargs):
        invoked.append(args)
        raise AssertionError("Popen reached for unsafe INI expansion")
    monkeypatch.setattr("gateway.executor.subprocess.Popen", forbidden)
    args = ["-o", ini] if style == "short" else ["--override-ini=" + ini]
    with _gateway(project, runner) as g:
        with pytest.raises(GatewayError) as error:
            g.run_command("service", ["pytest", *args], dry_run=dry_run)
        assert error.value.code == "command_not_allowed"
    assert invoked == []
    assert not fake_tools.exists()


@pytest.mark.parametrize("flag_args", (
    ["-pgo=../review-fixture/profile.pprof"],
    ["--pgo=../review-fixture/profile.pprof"],
    ["-pgo", "../review-fixture/profile.pprof"],
    ["--pgo", "../review-fixture/profile.pprof"],
))
@pytest.mark.parametrize("operation", ("test", "vet"))
@pytest.mark.parametrize("runner", ("direct", "pipenv"))
@pytest.mark.parametrize("dry_run", (True, False))
def test_review3_pgo_external_profile_blocked_before_spawn(
    project, fake_tools, monkeypatch, flag_args, operation, runner, dry_run
):
    invoked = []
    def forbidden(*args, **kwargs):
        invoked.append(args)
        raise AssertionError("Go -pgo external path reached Popen")
    monkeypatch.setattr("gateway.executor.subprocess.Popen", forbidden)
    with _gateway(project, runner) as g:
        with pytest.raises(GatewayError) as error:
            g.run_command("service", ["go", operation, *flag_args], dry_run=dry_run)
        assert error.value.code == "command_not_allowed"
    assert invoked == []
    assert not fake_tools.exists()


@pytest.mark.parametrize("flag_args", (
    ["-pgo=auto"], ["-pgo=off"], ["-pgo", "auto"], ["-pgo", "off"],
    ["--pgo=auto"], ["--pgo", "off"], ["-pgo=profiles/local.pprof"],
))
@pytest.mark.parametrize("runner", ("direct", "pipenv"))
def test_review3_pgo_special_modes_and_relative_paths_work(
    project, fake_tools, flag_args, runner
):
    with _gateway(project, runner) as g:
        preview = g.run_command("service", ["go", "test", *flag_args])
        assert preview["executed"] is False
        assert not fake_tools.exists()
        result = g.run_command("service", ["go", "test", *flag_args], dry_run=False)
        assert result["exit_code"] == 0, result
        assert fake_tools.exists()
        fake_tools.unlink()


def test_review3_real_pytest_accepts_scalar_space_paths(project):
    # Verify the actual pytest interpretation, not only synthetic argv echoes.
    (project / "service" / "tests" / "test_review3_real.py").write_text(
        "def test_ok():\n    assert True\n"
    )
    (project / "service" / "reports").mkdir()
    argv = ["python3", "-m", "pytest", "-q",
            "-o", "cache_dir=cache files",
            "-o", "log_file=reports/test results.log",
            "tests/test_review3_real.py"]
    with _gateway(project, "direct") as g:
        result = g.run_command("service", argv, dry_run=False)
    assert result["exit_code"] == 0, result
    assert (project / "service" / "tests" / "cache files").is_dir()
    assert (project / "service" / "reports" / "test results.log").is_file()


# Independent fourth review of 5da26377: Go's undocumented diagnostic
# output flags must not permit any post-authorization output destination.
# The Gateway does not expose these diagnostics; reject even relative
# values to avoid a second file-output policy.
@pytest.mark.parametrize("diagnostic", ("debug-actiongraph", "debug-trace"))
@pytest.mark.parametrize("prefix", ("-", "--"))
@pytest.mark.parametrize("form", ("inline", "separate"))
@pytest.mark.parametrize("value", ("../review-fixture/graph.json", "reports/graph.json"))
@pytest.mark.parametrize("operation", ("test", "vet"))
@pytest.mark.parametrize("runner", ("direct", "pipenv"))
@pytest.mark.parametrize("dry_run", (True, False))
def test_review4_go_debug_file_flags_rejected_before_spawn(
    project, fake_tools, monkeypatch, diagnostic, prefix, form, value,
    operation, runner, dry_run
):
    invoked = []

    def forbidden(*args, **kwargs):
        invoked.append(args)
        raise AssertionError("Go diagnostics unexpectedly reached Popen")

    monkeypatch.setattr("gateway.executor.subprocess.Popen", forbidden)
    flag = prefix + diagnostic
    extra = [f"{flag}={value}"] if form == "inline" else [flag, value]
    with _gateway(project, runner) as g:
        with pytest.raises(GatewayError) as error:
            g.run_command("service", ["go", operation, *extra], dry_run=dry_run)
        assert error.value.code == "command_not_allowed"
    assert invoked == []
    assert not fake_tools.exists()


@pytest.mark.parametrize("diagnostic", ("debug-actiongraph", "debug-trace"))
@pytest.mark.parametrize("operation", ("test", "vet"))
@pytest.mark.parametrize("runner", ("direct", "pipenv"))
@pytest.mark.parametrize("dry_run", (True, False))
def test_review4_go_debug_after_package_rejected_before_spawn(
    project, fake_tools, monkeypatch, diagnostic, operation, runner, dry_run
):
    invoked = []

    def forbidden(*args, **kwargs):
        invoked.append(args)
        raise AssertionError("Go diagnostics unexpectedly reached Popen")

    monkeypatch.setattr("gateway.executor.subprocess.Popen", forbidden)
    with _gateway(project, runner) as g:
        with pytest.raises(GatewayError) as error:
            g.run_command("service", [
                "go", operation, "./...", "-"+diagnostic+"=reports/graph.json"
            ], dry_run=dry_run)
        assert error.value.code == "command_not_allowed"
    assert invoked == []
    assert not fake_tools.exists()


@pytest.mark.parametrize("argv", (
    ["go", "test", "-v", "./..."],
    ["go", "vet", "-x", "./..."],
    ["go", "test", "-pgo=auto", "-v"],
    ["go", "test", "-coverprofile=reports/cover.out", "./..."],
))
@pytest.mark.parametrize("runner", ("direct", "pipenv"))
def test_review4_safe_go_flags_still_work(project, fake_tools, argv, runner):
    with _gateway(project, runner) as g:
        preview = g.run_command("service", argv)
        assert preview["executed"] is False
        assert not fake_tools.exists()
        result = g.run_command("service", argv, dry_run=False)
        assert result["exit_code"] == 0, result
        assert fake_tools.exists()
        fake_tools.unlink()
