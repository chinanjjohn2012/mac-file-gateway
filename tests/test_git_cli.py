"""T06 direct internal Git execution tests. All repositories are temporary."""
from __future__ import annotations

import os
from pathlib import Path
import stat
import subprocess
import sys
import time

import pytest

from gateway.core import GatewayError
from gateway.git_cli import GitCLIExecutor, GitProcessRunner, git_environment
from gateway.git_repository import GitRepositoryCoordinator
from gateway.git_state import GitStateStore


def git(cwd: Path, *args: str) -> str:
    result = subprocess.run(["git", *args], cwd=cwd, capture_output=True,
                            text=True, check=True)
    return result.stdout.strip()


def repo_workspace(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-q")
    git(repo, "config", "user.name", "Fixture")
    git(repo, "config", "user.email", "fixture@example.invalid")
    ws = repo / "project-b"
    sibling = repo / "project-a"
    ws.mkdir()
    sibling.mkdir()
    (sibling / "tracked.txt").write_text("first")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "initial")
    return repo, ws, sibling


def execute(executor, workspace: Path, command: str, *,
            options=None, paths=None, dry_run=False):
    fd = os.open(workspace, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        return executor.run(workspace="b", root_fd=fd, root_path=str(workspace),
                            command=command, options={} if options is None else options,
                            paths=[] if paths is None else paths, dry_run=dry_run)
    finally:
        os.close(fd)


def test_git_runner_is_not_a_transport_and_preserves_workspace_parent_repo(tmp_path):
    repo, workspace, sibling = repo_workspace(tmp_path)
    state = GitStateStore(tmp_path / "git-state", workspace_roots=(str(workspace),))
    runner = GitCLIExecutor(state)
    try:
        status = execute(runner, workspace, "status")
        assert status["exit_code"] == 0
        assert status["execute_started"] and status["repository_checked"]
        assert status["cleanup_status"] == "complete"
        assert not list((tmp_path / "git-state").iterdir())
        (sibling / "tracked.txt").write_text("changed outside Workspace")
        # The user-approved Git semantics allow no-paths -A to stage
        # changes in the parent repository, including sibling directories.
        added = execute(runner, workspace, "add", options={"all": True})
        assert added["exit_code"] == 0
        staged = git(repo, "diff", "--cached", "--name-only")
        assert "project-a/tracked.txt" in staged
        committed = execute(runner, workspace, "commit",
                            options={"message": "from gateway sibling"})
        assert committed["exit_code"] == 0
        assert git(repo, "log", "-1", "--format=%s") == "from gateway sibling"
    finally:
        state.close()


def test_non_repository_failure_clears_discovery_record(tmp_path):
    root = tmp_path / "workspace"
    root.mkdir()
    state = GitStateStore(tmp_path / "state")
    executor = GitCLIExecutor(state)
    try:
        with pytest.raises(GatewayError) as exc:
            execute(executor, root, "status")
        assert exc.value.code == "git_not_repository"
        assert not state.globally_quarantined
        assert not list((tmp_path / "state").iterdir())
    finally:
        state.close()


def test_preview_startup_requires_no_git_process(tmp_path, monkeypatch):
    repo, workspace, _ = repo_workspace(tmp_path)
    state = GitStateStore(tmp_path / "state")
    executor = GitCLIExecutor(state)
    fd = os.open(workspace, os.O_RDONLY | os.O_DIRECTORY)
    try:
        monkeypatch.setattr(subprocess, "Popen", lambda *_a, **_k:
                            (_ for _ in ()).throw(AssertionError("Preview spawned Git")))
        preview = executor.run(workspace="b", root_fd=fd, root_path=str(workspace),
                               command="status", dry_run=True)
        assert not preview["repository_checked"] and not preview["execute_started"]
        assert not list((tmp_path / "state").iterdir())
    finally:
        os.close(fd)
        state.close()


def test_git_environment_removes_git_and_gateway_secrets():
    env = git_environment({
        "HOME": "/tmp/fakehome", "USER": "fixture", "SSH_AUTH_SOCK": "/tmp/agent",
        "GIT_DIR": "/tmp/evil", "GIT_WORK_TREE": "/tmp/evil2",
        "GIT_INDEX_FILE": "/tmp/evil/index", "GIT_COMMON_DIR": "/tmp/bad",
        "GIT_SSH_COMMAND": "bad", "GIT_CONFIG_GLOBAL": "/tmp/other",
        "GATEWAY_TOKEN": "secret", "TUNNEL_API_KEY": "private",
    })
    assert env["HOME"] == "/tmp/fakehome"
    assert env["SSH_AUTH_SOCK"] == "/tmp/agent"
    assert env["GIT_TERMINAL_PROMPT"] == "0"
    assert all(not name.startswith("GIT_") or name == "GIT_TERMINAL_PROMPT"
               for name in env)
    assert "GATEWAY_TOKEN" not in env and "TUNNEL_API_KEY" not in env


def test_run_does_not_inherit_poisoned_git_environment(tmp_path, monkeypatch):
    repo, workspace, _ = repo_workspace(tmp_path)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    git(elsewhere, "init", "-q")
    monkeypatch.setenv("GIT_DIR", str(elsewhere / ".git"))
    monkeypatch.setenv("GIT_WORK_TREE", str(elsewhere))
    monkeypatch.setenv("GIT_INDEX_FILE", str(elsewhere / "badindex"))
    state = GitStateStore(tmp_path / "state")
    try:
        executor = GitCLIExecutor(state)
        result = execute(executor, workspace, "status")
        assert result["exit_code"] == 0
        assert not (elsewhere / "badindex").exists()
    finally:
        state.close()


def test_runtime_branch_check_disallows_remote_guess(tmp_path):
    repo, workspace, _ = repo_workspace(tmp_path)
    state = GitStateStore(tmp_path / "state")
    executor = GitCLIExecutor(state)
    try:
        with pytest.raises(GatewayError) as exc:
            execute(executor, workspace, "switch", options={"name": "unavailable"})
        assert exc.value.code == "git_branch_unknown"
        assert not state.globally_quarantined
        new = execute(executor, workspace, "switch",
                      options={"name": "newlocal", "create": True})
        assert new["exit_code"] == 0
        assert git(repo, "branch", "--show-current") == "newlocal"
        assert not list((tmp_path / "state").iterdir())
    finally:
        state.close()


def _fake_git(tmp_path: Path, text: str) -> Path:
    # Fixed absolute interpreter: CI Python may not be on the narrow Git PATH.
    script = tmp_path / "fake-git"
    script.write_text("#!" + sys.executable + "\n" + text, encoding="utf-8")
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return script


def test_runner_streams_large_output_without_memory_growth(tmp_path):
    fake = _fake_git(tmp_path, "import sys\nsys.stdout.write('X'*350000)\nsys.stdout.flush()\n")
    runner = GitProcessRunner(binary=str(fake))
    result = runner.run(str(tmp_path), ["status"],
                        spawn_admitted=lambda spawn: spawn(),
                        execute_until=time.monotonic()+5, deadline=time.monotonic()+12)
    assert result.exit_code == 0
    assert result.cleanup_complete
    assert result.output_truncated
    assert len(result.stdout) <= 131072


def test_timeout_with_confirmed_cleanup_does_not_quarantine(tmp_path):
    fake = _fake_git(tmp_path, "import time\ntime.sleep(20)\n")
    runner = GitProcessRunner(binary=str(fake))
    result = runner.run(str(tmp_path), ["status"],
                        spawn_admitted=lambda spawn: spawn(),
                        execute_until=time.monotonic()+0.3, deadline=time.monotonic()+12)
    assert result.timed_out
    assert result.cleanup_complete
    assert result.exit_code is not None


def test_closed_pipes_do_not_hide_a_live_git_process_group(tmp_path):
    """A hook's non-detached child may close inherited pipes but remain alive."""
    import signal
    pidfile = tmp_path / "group-child-pid"
    child_script = (
        "from pathlib import Path; import os, time; "
        "Path(" + repr(str(pidfile)) + ").write_text(str(os.getpid())); "
        "time.sleep(45)"
    )
    fake_source = (
        "import subprocess, sys\n"
        "subprocess.Popen([sys.executable, '-c', " + repr(child_script) + "], "
        "stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, "
        "stderr=subprocess.DEVNULL, start_new_session=False)\n"
    )
    fake_git = _fake_git(tmp_path, fake_source)
    runner = GitProcessRunner(binary=str(fake_git))
    try:
        result = runner.run(str(tmp_path), ["status"],
                            spawn_admitted=lambda spawn: spawn(),
                            execute_until=time.monotonic() + 0.8,
                            deadline=time.monotonic() + 9)
        # Main Git process exits and its two pipes reach EOF almost
        # immediately; the group's child must still prevent a clean success.
        assert pidfile.exists()
        assert result.timed_out
        assert result.exit_code is not None
    finally:
        if pidfile.exists():
            pid = int(pidfile.read_text())
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
