"""C/T09: Git opt-in CLI and immutable Multi/Legacy mode separation."""
from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

from gateway.__main__ import main
from gateway.git_cli import GitCLIExecutor


def run(root, home, *options):
    home.mkdir(exist_ok=True)
    env = dict(os.environ, HOME=str(home))
    return subprocess.run(
        [sys.executable, "-m", "gateway", "--root", str(root),
         *options, "--check"],
        capture_output=True, text=True, timeout=15, env=env,
    )


def test_legacy_check_defaults_git_disabled(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    proc = run(root, tmp_path / "home")
    assert proc.returncode == 0, proc.stderr
    meta = json.loads(proc.stdout)
    assert meta["git_policy"]["enabled"] is False
    assert meta["git_policy"]["allowed_commands"] == []
    assert meta["git_policy"]["adapter_exposed"] is False
    assert meta["exec_policy"]["enabled"] is False
    assert str(root) not in proc.stdout
    assert not (tmp_path / "home" / ".config" / "mac-file-gateway").exists()


@pytest.mark.parametrize("options", [
    ["--allow-git"],
    ["--git-command", "status"],
    ["--git-command=status"],
    ["--allow-git", "--git-command", "rm"],
    ["--allow-git", "--git-command", "status", "--git-command", "status"],
])
def test_legacy_git_invalid_grants_are_denied(tmp_path, options):
    root = tmp_path / "project"
    root.mkdir()
    result = run(root, tmp_path / "home", *options)
    assert result.returncode == 2
    assert not result.stdout


def test_legacy_check_git_grants_without_git_discovery(tmp_path, monkeypatch, capsys):
    root = tmp_path / "project"
    home = tmp_path / "home"
    root.mkdir()
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))

    def forbidden_discovery(*args, **kwargs):
        raise AssertionError("--check must not discover a Git repository")

    monkeypatch.setattr(GitCLIExecutor, "_run_discovery", forbidden_discovery)
    assert main([
        "--root", str(root), "--allow-git",
        "--git-command", "status", "--git-command", "diff", "--check",
    ]) == 0
    info = json.loads(capsys.readouterr().out)
    assert info["git_policy"]["enabled"] is True
    assert info["git_policy"]["available"] is True
    assert info["git_policy"]["allowed_commands"] == ["status", "diff"]
    assert info["git_policy"]["adapter_exposed"] is False
    assert info["exec_policy"]["enabled"] is False
    assert info["read_only"] is True
    assert str(home) not in json.dumps(info)
    assert (home / ".config" / "mac-file-gateway" / "git-legacy-state").is_dir()


def test_git_scope_does_not_inherit_write_or_exec_grants(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "src").mkdir()
    home = tmp_path / "home"
    proc = run(root, home, "--allow-git", "--git-command", "status")
    assert proc.returncode == 0, proc.stderr
    info = json.loads(proc.stdout)
    assert info["read_only"] is True
    assert info["exec_policy"]["enabled"] is False
    assert info["git_policy"]["enabled"] is True
    other = run(root, home, "--allow-exec", "--exec-path", "src")
    assert other.returncode == 0, other.stderr
    no_git = json.loads(other.stdout)
    assert no_git["git_policy"]["enabled"] is False
    assert no_git["exec_policy"]["enabled"] is True


def test_multi_check_reports_git_grants_with_no_public_adapter(tmp_path, monkeypatch, capsys):
    project = tmp_path / "projects"
    project.mkdir()
    a = project / "a"
    a.mkdir()
    config_dir = tmp_path / "control"
    config_dir.mkdir(mode=0o700)
    conf = config_dir / "gateway.json"
    conf.write_text(json.dumps({
        "schema_version": 1,
        "server": {"git": {"enabled": True}},
        "workspaces": {
            "a": {"root": str(a), "git": {"allowed_commands": ["status", "pull"]}},
        },
    }))
    conf.chmod(0o600)
    def forbidden_discovery(*args, **kwargs):
        raise AssertionError("Multi --check cannot launch Git discovery")
    monkeypatch.setattr(GitCLIExecutor, "_run_discovery", forbidden_discovery)
    assert main(["--config", str(conf), "--check"]) == 0
    info = json.loads(capsys.readouterr().out)
    assert info["mode"] == "multi"
    assert info["git_policy"]["enabled"] is True
    assert info["git_policy"]["available"] is True
    assert info["git_policy"]["adapter_exposed"] is False
    assert info["workspaces"][0]["git"]["allowed_commands"] == ["status", "pull"]
    assert info["read_only"] is True
    assert str(a) not in json.dumps(info)
    assert str(config_dir) not in json.dumps(info)


def test_multi_state_quarantine_does_not_turn_into_unintended_git_access(
    tmp_path, capsys,
):
    a = tmp_path / "project"
    a.mkdir()
    config_dir = tmp_path / "control"
    config_dir.mkdir(mode=0o700)
    state = config_dir / "git-state"
    state.mkdir()
    (state / "unrecognized.tmp").write_text("unclean")
    conf = config_dir / "gateway.json"
    conf.write_text(json.dumps({
        "schema_version": 1,
        "server": {"git": {"enabled": True}},
        "workspaces": {"a": {"root": str(a),
                             "git": {"allowed_commands": ["status"]}}},
    }))
    assert main(["--config", str(conf), "--check"]) == 0
    info = json.loads(capsys.readouterr().out)
    assert info["git_policy"]["enabled"] is True
    assert info["git_policy"]["available"] is False
    assert info["git_policy"]["adapter_exposed"] is False


@pytest.mark.parametrize("extra", [
    ["--allow-git"],
    ["--git-command", "status"],
    ["--git-command=status"],
])
def test_git_legacy_flags_never_accepted_in_multi_config_mode(tmp_path, extra):
    with pytest.raises(SystemExit) as exc:
        main(["--config", str(tmp_path / "unused.json"), "--check", *extra])
    assert exc.value.code == 2
