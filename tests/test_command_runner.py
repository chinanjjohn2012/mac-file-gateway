"""Controlled execution uses real subprocesses but never a shell."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from gateway.core import Gateway, GatewayError


def executable(path: Path, body: str) -> None:
    path.write_text("#!/bin/sh\nset -eu\n" + body)
    path.chmod(0o755)


@pytest.fixture
def root(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "service-c").mkdir()
    (root / "service-a").mkdir()
    (root / "other").mkdir()
    return root


@pytest.fixture
def fake_bin(tmp_path, monkeypatch):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    executable(bin_dir / "pytest", 'printf "pytest:%s\\n" "$*"')
    executable(bin_dir / "pipenv", 'printf "pipenv:%s\\n" "$*"; printf "pipfile:%s\\n" "${PIPENV_PIPFILE-}"')
    executable(bin_dir / "go", 'printf "go:%s\\n" "$*"')
    executable(bin_dir / "python", 'printf "python:%s\\n" "$*"')
    monkeypatch.setenv("PATH", str(bin_dir) + os.pathsep + os.environ.get("PATH", ""))
    return bin_dir


def test_exec_disabled_by_default(root):
    g = Gateway(root)
    try:
        assert g.info()["exec_policy"]["enabled"] is False
        with pytest.raises(GatewayError) as exc:
            g.run_command("service-c", ["pytest", "-q"], dry_run=False)
        assert exc.value.code == "exec_disabled"
    finally:
        g.close()


def test_dry_run_resolves_command_without_starting_process(root, fake_bin):
    marker = root / "ran"
    executable(fake_bin / "pytest", f'touch "{marker}"')
    g = Gateway(root, allow_exec=True, exec_paths=("service-c",))
    try:
        result = g.run_command("service-c", ["pytest", "-q"])
        assert result["dry_run"] is True
        assert result["executed"] is False
        assert result["runner"] == "direct"
        assert result["effective_argv"] == ["pytest", "-q"]
        assert not marker.exists()
    finally:
        g.close()


def test_pipfile_auto_selects_pipenv_runner(root, fake_bin):
    (root / "service-c" / "Pipfile").write_text("[packages]\n")
    g = Gateway(root, allow_exec=True, exec_paths=("service-c",))
    try:
        result = g.run_command("service-c", ["pytest", "-q"], dry_run=False)
        assert result["runner"] == "pipenv"
        assert result["effective_argv"] == ["pipenv", "run", "pytest", "-q"]
        assert result["exit_code"] == 0
        assert "pipenv:run pytest -q" in result["stdout"]
        assert result["stdout"].split("pipfile:", 1)[1].strip().endswith("/service-c/Pipfile")
    finally:
        g.close()


def test_explicit_direct_runner_overrides_pipfile(root, fake_bin):
    (root / "service-c" / "Pipfile").write_text("[packages]\n")
    g = Gateway(root, allow_exec=True, exec_paths=("service-c",), exec_runners=("service-c=direct",))
    try:
        result = g.run_command("service-c", ["pytest", "-q"], dry_run=False)
        assert result["runner"] == "direct"
        assert result["effective_argv"] == ["pytest", "-q"]
        assert "pytest:-q" in result["stdout"]
    finally:
        g.close()


def test_explicit_pipenv_runner_applies_to_descendants(root, fake_bin):
    (root / "service-c" / "Pipfile").write_text("[packages]\n")
    (root / "service-c" / "tests").mkdir()
    g = Gateway(root, allow_exec=True, exec_paths=("service-c",), exec_runners=("service-c=pipenv",))
    try:
        result = g.run_command("service-c/tests", ["python", "-m", "pytest", "-q"], dry_run=False)
        assert result["runner"] == "pipenv"
        assert result["effective_argv"][:4] == ["pipenv", "run", "python", "-m"]
    finally:
        g.close()


def test_exec_scope_blocks_other_directories(root, fake_bin):
    g = Gateway(root, allow_exec=True, exec_paths=("service-c", "service-a"))
    try:
        with pytest.raises(GatewayError) as exc:
            g.run_command("other", ["pytest"], dry_run=False)
        assert exc.value.code == "exec_scope"
    finally:
        g.close()


@pytest.mark.parametrize("argv", [
    ["bash", "-lc", "echo bad"],
    ["sh", "-c", "echo bad"],
    ["git", "status"],
    ["pipenv", "run", "pytest"],
    ["python", "-c", "print('bad')"],
    ["python", "-"],
    ["go", "env"],
])
def test_commands_outside_allowlist_are_rejected(root, argv):
    g = Gateway(root, allow_exec=True, exec_paths=("service-c",))
    try:
        with pytest.raises(GatewayError) as exc:
            g.run_command("service-c", argv, dry_run=False)
        assert exc.value.code == "command_not_allowed"
    finally:
        g.close()


@pytest.mark.parametrize("argv", [
    ["pytest", "-q"],
    ["python", "-m", "pytest", "-q"],
    ["python", "-m", "compileall", "."],
    ["go", "test", "./..."],
    ["go", "vet", "./..."],
])
def test_supported_command_shapes_preview(root, argv):
    g = Gateway(root, allow_exec=True, exec_paths=("service-c",))
    try:
        result = g.run_command("service-c", argv)
        assert result["executed"] is False
        assert result["requested_argv"] == argv
    finally:
        g.close()


def test_python_script_must_be_relative_regular_project_file(root, fake_bin):
    (root / "service-c" / "job.py").write_text("print('ok')\n")
    g = Gateway(root, allow_exec=True, exec_paths=("service-c",))
    try:
        assert g.run_command("service-c", ["python", "job.py"])["executed"] is False
        for script in ("../outside.py", "/tmp/outside.py"):
            with pytest.raises(GatewayError):
                g.run_command("service-c", ["python", script])
    finally:
        g.close()


def test_sensitive_environment_is_not_forwarded(root, fake_bin, monkeypatch):
    executable(fake_bin / "pytest", 'printf "secret:%s\\n" "${OPENAI_API_KEY-unset}"; printf "venv:%s\\n" "${VIRTUAL_ENV-unset}"')
    monkeypatch.setenv("OPENAI_API_KEY", "do-not-forward")
    monkeypatch.setenv("VIRTUAL_ENV", "/tmp/wrong-venv")
    g = Gateway(root, allow_exec=True, exec_paths=("service-c",))
    try:
        result = g.run_command("service-c", ["pytest"], dry_run=False)
        assert "do-not-forward" not in result["stdout"]
        assert "secret:unset" in result["stdout"]
        assert "venv:unset" in result["stdout"]
    finally:
        g.close()


def test_timeout_kills_process_group(root, fake_bin):
    executable(fake_bin / "pytest", "sleep 5")
    g = Gateway(root, allow_exec=True, exec_paths=("service-c",))
    try:
        result = g.run_command("service-c", ["pytest"], timeout_seconds=1, dry_run=False)
        assert result["timed_out"] is True
        assert result["exit_code"] is None
    finally:
        g.close()


def test_output_is_bounded(root, fake_bin):
    executable(fake_bin / "pytest", "i=0; while [ $i -lt 9000 ]; do printf 1234567890; i=$((i+1)); done")
    g = Gateway(root, allow_exec=True, exec_paths=("service-c",))
    try:
        result = g.run_command("service-c", ["pytest"], dry_run=False)
        assert result["stdout_truncated"] is True
        assert len(result["stdout"]) <= result["output_limit_chars"]
    finally:
        g.close()


def test_exec_policy_is_explicit(root):
    (root / "service-c" / "Pipfile").write_text("[packages]\n")
    g = Gateway(root, allow_exec=True, exec_paths=("service-c",), exec_runners=("service-c=pipenv",))
    try:
        policy = g.info()["exec_policy"]
        assert policy["enabled"] is True
        assert policy["shell"] is False
        assert policy["paths"] == ["service-c"]
        assert policy["configured_runners"] == {"service-c": "pipenv"}
        assert "go test" in policy["allowed_commands"]
        assert "python -m pytest" in policy["allowed_commands"]
    finally:
        g.close()


@pytest.mark.parametrize("argv", [
    ["pytest", "/tmp/tests"],
    ["pytest", "../outside"],
    ["python", "-m", "compileall", "/tmp"],
    ["go", "test", "-coverprofile=/tmp/cover.out", "./..."],
])
def test_explicit_external_path_arguments_are_rejected(root, argv):
    g = Gateway(root, allow_exec=True, exec_paths=("service-c",))
    try:
        with pytest.raises(GatewayError) as exc:
            g.run_command("service-c", argv)
        assert exc.value.code == "command_not_allowed"
    finally:
        g.close()


def test_auto_pipenv_search_does_not_escape_exec_scope(root, fake_bin):
    (root / "Pipfile").write_text("[packages]\n")
    g = Gateway(root, allow_exec=True, exec_paths=("service-c",))
    try:
        result = g.run_command("service-c", ["pytest", "-q"])
        assert result["runner"] == "direct"
    finally:
        g.close()
