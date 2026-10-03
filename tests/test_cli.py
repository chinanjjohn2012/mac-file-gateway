import json
from pathlib import Path
import subprocess
import sys


def run(*args):
    return subprocess.run([sys.executable, "-m", "gateway", *args], text=True, capture_output=True, timeout=10)


def test_cli_help():
    result = run("--help")
    assert result.returncode == 0
    assert "--root" in result.stdout


def test_cli_requires_explicit_root():
    result = run()
    assert result.returncode == 2
    assert "--root" in result.stderr


def test_cli_refuses_home():
    result = run("--root", str(Path.home()), "--check")
    assert result.returncode == 2
    assert "specific project" in result.stderr


def test_cli_check_does_not_start_server(tmp_path):
    result = run("--root", str(tmp_path), "--check")
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert data["read_only"] is True
    assert str(tmp_path) not in result.stdout


def test_cli_rejects_privileged_port(tmp_path):
    result = run("--root", str(tmp_path), "--port", "80", "--check")
    assert result.returncode == 2


def test_cli_local_skill_root_is_opt_in_and_fail_closed(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    result = run("--root", str(root), "--local-skill-root", "agent-runtime", "--check")
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert data["local_skill_bridge"]["configured"] is True
    assert data["local_skill_bridge"]["status"] == "disabled"
    assert str(root) not in result.stdout
