"""B-phase real process crash/restart admission tests; no external remotes."""
from __future__ import annotations

import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import time

import pytest

from gateway.core import GatewayError
from gateway.git_cli import GitCLIExecutor
from gateway.git_state import GitStateStore


@pytest.mark.skipif(not hasattr(signal, "SIGKILL"), reason="POSIX process signals required")
def test_kill_gateway_during_first_git_discovery_fails_closed_on_restart(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    workspace = repo / "workspace"
    workspace.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    state_dir = tmp_path / "private-state"
    child_started = tmp_path / "git-child-pid"

    # A trusted test-only Git binary that sleeps during the FIRST rev-parse.
    # This is NOT an executable path provided by an MCP/REST client.
    fake_git = tmp_path / "fake-git"
    fake_git.write_text(
        "#!" + sys.executable + "\n"
        "import os, time\nfrom pathlib import Path\n"
        "Path(" + repr(str(child_started)) + ").write_text(str(os.getpid()))\n"
        "time.sleep(80)\n", encoding="utf-8",
    )
    fake_git.chmod(fake_git.stat().st_mode | stat.S_IXUSR)
    process_script = tmp_path / "gateway-worker.py"
    process_script.write_text(
        "import os, sys\n"
        "from gateway.git_cli import GitCLIExecutor, GitProcessRunner\n"
        "from gateway.git_state import GitStateStore\n"
        "state, root, binary = sys.argv[1:]\n"
        "store = GitStateStore(state)\n"
        "fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)\n"
        "try:\n"
        "    GitCLIExecutor(store, runner=GitProcessRunner(binary=binary)).run(\n"
        "        workspace='a', root_fd=fd, root_path=root,\n"
        "        command='status', timeout_seconds=30, dry_run=False)\n"
        "finally:\n"
        "    os.close(fd)\n"
        "    store.close()\n", encoding="utf-8",
    )

    env = dict(os.environ)
    base = str(Path(__file__).resolve().parents[1])
    env["PYTHONPATH"] = base + os.pathsep + env.get("PYTHONPATH", "")
    process = subprocess.Popen(
        [sys.executable, str(process_script), str(state_dir),
         str(workspace), str(fake_git)],
        cwd=base, env=env, stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    child_pid = None
    try:
        limit = time.monotonic() + 12
        while time.monotonic() < limit and not child_started.exists():
            if process.poll() is not None:
                output = process.stderr.read().decode("utf-8", "replace")
                pytest.fail("Gateway fixture exited before Git child launched: " + output)
            time.sleep(0.05)
        assert child_started.exists(), "Test fake Git did not start."
        child_pid = int(child_started.read_text())
        assert list(state_dir.glob("d-*.json")), "Discovery intent missing before Popen."
        os.kill(process.pid, signal.SIGKILL)
        process.wait(timeout=5)
        restarted = GitStateStore(state_dir)
        try:
            assert restarted.globally_quarantined
            launched = []
            with pytest.raises(GatewayError) as exc:
                restarted.start_discovery(restarted.new_call_id(), "b",
                                          lambda: launched.append("forbidden"))
            assert exc.value.code == "git_global_quarantined"
            assert not launched
        finally:
            restarted.close()
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        if child_pid is not None:
            try:
                os.killpg(child_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

    # Offline recovery is permitted only after the controlled child is no
    # longer executing. An orphaned zombie may await OS init reaping; it is
    # not an executing process and cannot mutate the repository.
    assert child_pid is not None and _wait_not_executing(child_pid)
    assert list(state_dir.glob("d-*.json"))
    for item in state_dir.iterdir():
        item.unlink()
    restored = GitStateStore(state_dir)
    try:
        assert not restored.globally_quarantined
        fd = os.open(workspace, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            result = GitCLIExecutor(restored).run(
                workspace="a", root_fd=fd, root_path=str(workspace),
                command="status", timeout_seconds=30, dry_run=False)
            assert result["exit_code"] == 0
        finally:
            os.close(fd)
    finally:
        restored.close()


def test_transfer_gap_has_no_running_git_child_and_restart_quarantines_only_repo(tmp_path):
    state_dir = tmp_path / "state"
    store = GitStateStore(state_dir)
    call = store.new_call_id()
    store.start_discovery(call, "a", lambda: "finished child")
    store.finish_discovery(call, clean=True)
    assert not list(state_dir.iterdir())  # No child survives this gap.
    key = (31, 41)
    store.begin_repo(key, call)  # Durable marker BEFORE lock-held Git starts.
    store.close()
    restarted = GitStateStore(state_dir)
    try:
        assert restarted.is_repo_quarantined(key)
        assert not restarted.globally_quarantined
        assert not restarted.is_repo_quarantined((55, 66))
    finally:
        restarted.close()



def _wait_not_executing(pid: int, timeout: float = 5.0) -> bool:
    """Cross-platform POSIX check: absent or zombie means no running code."""
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        result = subprocess.run(
            ["ps", "-p", str(pid), "-o", "stat="],
            text=True, capture_output=True,
        )
        status = result.stdout.strip()
        if result.returncode != 0 or not status or status.startswith("Z"):
            return True
        time.sleep(0.05)
    return False


@pytest.mark.skipif(not hasattr(signal, "SIGKILL"), reason="POSIX signals required")
@pytest.mark.parametrize("window", ["after_discovery_clean", "after_repo_intent"])
def test_real_gateway_crash_during_handoff_windows(tmp_path, window):
    """Crash at both transitions using a real fully reaped discovery child."""
    repo = tmp_path / "repo"
    repo.mkdir()
    workspace = repo / "workspace"
    workspace.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    state_dir = tmp_path / "state"
    marker = tmp_path / "handoff-position.json"
    worker = tmp_path / "worker.py"
    worker.write_text(
        """
import json
import os
from pathlib import Path
import sys
import time
from gateway.git_cli import GitCLIExecutor, GitProcessRunner
from gateway.git_state import GitStateStore

state_path, workspace, marker, window = sys.argv[1:]
state = GitStateStore(state_path)

class ObservedRunner(GitProcessRunner):
    def __init__(self):
        super().__init__()
        self.children = []

    def run(self, cwd, argv, *, spawn_admitted, execute_until, deadline):
        def tracked(callback):
            child = spawn_admitted(callback)
            self.children.append(child)
            return child
        result = super().run(
            cwd, argv, spawn_admitted=tracked,
            execute_until=execute_until, deadline=deadline,
        )
        return result

runner = ObservedRunner()
executor = GitCLIExecutor(state, runner=runner)

def handoff(position, key):
    # The first discovery process must already have returned, been waited,
    # and its stdout/stderr drained before either injected crash window.
    assert len(runner.children) == 1
    discovered_child = runner.children[0]
    assert discovered_child.poll() is not None
    info = {
        "position": position,
        "key": list(key),
        "discovery_pid": discovered_child.pid,
        "discovery_reaped": discovered_child.returncode is not None,
    }
    Path(marker).write_text(json.dumps(info))
    time.sleep(60)

if window == "after_discovery_clean":
    original = executor._run_discovery
    def delayed_discovery(*args):
        identity = original(*args)
        handoff("after_discovery_clean", identity.common_key)
        return identity
    executor._run_discovery = delayed_discovery
else:
    original = state.begin_repo
    def delayed_begin_repo(key, call_id):
        original(key, call_id)
        handoff("after_repo_intent", key)
    state.begin_repo = delayed_begin_repo

fd = os.open(workspace, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    executor.run(
        workspace="a", root_fd=fd, root_path=workspace,
        command="status", timeout_seconds=90, dry_run=False,
    )
finally:
    os.close(fd)
    state.close()
""", encoding="utf-8",
    )
    env = dict(os.environ)
    project = str(Path(__file__).resolve().parents[1])
    env["PYTHONPATH"] = project + os.pathsep + env.get("PYTHONPATH", "")
    proc = subprocess.Popen(
        [sys.executable, str(worker), str(state_dir), str(workspace),
         str(marker), window],
        cwd=project, env=env, stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    try:
        until = time.monotonic() + 10
        while time.monotonic() < until and not marker.exists():
            if proc.poll() is not None:
                err = proc.stderr.read().decode("utf-8", "replace")
                pytest.fail("handoff worker failed: " + err)
            time.sleep(0.05)
        assert marker.exists(), "handoff window was never reached"
        info = json.loads(marker.read_text())
        assert info["position"] == window
        assert info["discovery_reaped"] is True
        assert _wait_not_executing(info["discovery_pid"], 2.0)
        if window == "after_discovery_clean":
            assert not list(state_dir.iterdir())
        else:
            assert len(list(state_dir.glob("r-*.json"))) == 1
        os.kill(proc.pid, signal.SIGKILL)
        proc.wait(timeout=5)
        restarted = GitStateStore(state_dir)
        try:
            key = tuple(info["key"])
            if window == "after_discovery_clean":
                assert not restarted.globally_quarantined
                assert not restarted.is_repo_quarantined(key)
                # No Git child can survive the marker-free handoff window.
            else:
                assert restarted.is_repo_quarantined(key)
                assert not restarted.globally_quarantined
        finally:
            restarted.close()
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)


# E/T13: Service boundary fault tests extend B's runner-only crash fixtures.
# No test below attempts any network transport or user-selected repo.


@pytest.mark.parametrize("failure", ["write", "file_fsync", "rename", "dir_fsync"])
def test_executor_first_discovery_intent_fault_never_attempts_popen(
    tmp_path, monkeypatch, failure,
):
    import stat
    import gateway.git_cli as git_module

    repo = tmp_path / "repo"
    repo.mkdir()
    workspace = repo / "ws"
    workspace.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    state = GitStateStore(tmp_path / "state")
    executor = GitCLIExecutor(state)
    root_fd = os.open(workspace, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    original_popen = subprocess.Popen
    launched = []
    faults = []

    try:
        with monkeypatch.context() as m:
            if failure == "write":
                original = os.write

                def broken_write(fd, data):
                    faults.append("write")
                    raise OSError("durable intent write failed")

                m.setattr(os, "write", broken_write)
            elif failure in ("file_fsync", "dir_fsync"):
                original = os.fsync
                directory = failure == "dir_fsync"

                def broken_fsync(fd):
                    if stat.S_ISDIR(os.fstat(fd).st_mode) == directory:
                        faults.append(failure)
                        raise OSError("durable intent fsync failed")
                    return original(fd)

                m.setattr(os, "fsync", broken_fsync)
            else:
                def broken_rename(*args, **kwargs):
                    faults.append("rename")
                    raise OSError("durable intent rename failed")

                m.setattr(os, "rename", broken_rename)

            def forbidden_git(*args, **kwargs):
                launched.append(args)
                raise AssertionError("Popen before a durable DISCOVERING record")

            m.setattr(git_module.subprocess, "Popen", forbidden_git)
            with pytest.raises(GatewayError) as exc:
                executor.run(
                    workspace="ws", root_fd=root_fd, root_path=str(workspace),
                    command="status", timeout_seconds=15, dry_run=False,
                )
        assert exc.value.code == "git_state_unavailable"
        assert faults, failure
        assert not launched
        assert state.globally_quarantined
    finally:
        os.close(root_fd)
        state.close()


@pytest.mark.skipif(not hasattr(signal, "SIGKILL"), reason="POSIX signals required")
def test_real_child_uncertain_cleanup_blocks_siblings_linked_and_restart(
    tmp_path, monkeypatch,
):
    from gateway.workspaces import WorkspaceService, ActiveRuntimeInventory
    from gateway.workspaces_config import parse_workspace_config

    repo = tmp_path / "project"
    repo.mkdir()
    a, b = repo / "a", repo / "b"
    a.mkdir()
    b.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "E Test"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.email", "e@example.invalid"], check=True)
    (a / "tracked.txt").write_text("initial\n")
    subprocess.run(["git", "-C", str(repo), "add", "a/tracked.txt"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-qm", "first"], check=True)
    linked = tmp_path / "linked"
    subprocess.run(["git", "-C", str(repo), "worktree", "add", "-q",
                    "-b", "linked", str(linked)], check=True)
    other = tmp_path / "other"
    other.mkdir()
    subprocess.run(["git", "-C", str(other), "init", "-q"], check=True)
    state_home = tmp_path / "control"
    state_home.mkdir(mode=0o700)
    raw = {"schema_version": 1, "server": {"git": {"enabled": True}},
           "workspaces": {
               name: {"root": str(root), "git": {"allowed_commands": ["status"]}}
               for name, root in (("a", a), ("b", b), ("linked", linked), ("other", other))
           }}
    settings = parse_workspace_config(raw)
    runtime = tmp_path / "runtime"
    runtime.mkdir()

    def make_service():
        return WorkspaceService(
            settings, config_dir=state_home,
            inventory=ActiveRuntimeInventory(paths=(runtime,)),
        )

    service = make_service()
    runner = service._git_executor.runner
    actual = runner.run
    children = []
    triggered = []

    def interrupted(cwd, argv, *, spawn_admitted, execute_until, deadline):
        if argv[0] == "status" and not triggered:
            triggered.append(True)
            child = spawn_admitted(lambda: subprocess.Popen(
                [sys.executable, "-c", "import time; time.sleep(60)"],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, start_new_session=True, close_fds=True,
            ))
            children.append(child)
            assert child.poll() is None
            raise OSError("injected post-Popen transport/reader fault")
        return actual(cwd, argv, spawn_admitted=spawn_admitted,
                      execute_until=execute_until, deadline=deadline)

    monkeypatch.setattr(runner, "run", interrupted)
    try:
        with pytest.raises(GatewayError) as exc:
            service.invoke_git("a", "status", dry_run=False, timeout_seconds=20)
        assert exc.value.code == "git_cleanup_incomplete"
        assert children and children[0].poll() is None
        assert list((state_home / "git-state").glob("r-*.json"))

        monkeypatch.setattr(runner, "run", actual)
        for workspace in ("b", "linked"):
            with pytest.raises(GatewayError) as blocked:
                service.invoke_git(workspace, "status", dry_run=False,
                                   timeout_seconds=20)
            assert blocked.value.code == "git_repository_quarantined"
        assert service.invoke_git("other", "status", dry_run=False,
                                  timeout_seconds=20)["exit_code"] == 0
    finally:
        service.close()
        for child in children:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait(timeout=5)
            for pipe in (child.stdout, child.stderr):
                if pipe is not None:
                    pipe.close()

    assert children and _wait_not_executing(children[0].pid)
    restarted = make_service()
    try:
        with pytest.raises(GatewayError) as exc:
            restarted.invoke_git("linked", "status", dry_run=False)
        assert exc.value.code == "git_repository_quarantined"
    finally:
        restarted.close()

    # Controlled test administrator: only after real child group is no
    # longer executing, offline and with all services stopped.
    state_path = state_home / "git-state"
    assert list(state_path.glob("r-*.json"))
    for marker in state_path.iterdir():
        marker.unlink()
    recovered = make_service()
    try:
        assert recovered.invoke_git("a", "status", dry_run=False)["exit_code"] == 0
        assert not list(state_path.iterdir())
    finally:
        recovered.close()


def test_real_hook_running_blocks_gateway_close_until_worker_reaps(
    tmp_path,
):
    import threading
    from gateway.workspaces import WorkspaceService, ActiveRuntimeInventory
    from gateway.workspaces_config import parse_workspace_config

    repo = tmp_path / "project"
    repo.mkdir()
    b = repo / "b"
    b.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "E Test"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.email", "e@example.invalid"], check=True)
    (b / "file.txt").write_text("initial\n")
    subprocess.run(["git", "-C", str(repo), "add", "b/file.txt"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-qm", "initial"], check=True)
    (b / "file.txt").write_text("changed\n")
    subprocess.run(["git", "-C", str(repo), "add", "b/file.txt"], check=True)
    started, allow_finish = tmp_path / "hook-started", tmp_path / "hook-finish"
    hook = repo / ".git" / "hooks" / "pre-commit"
    hook.write_text(
        "#!/bin/sh\n"
        f"printf 'started' > '{started}'\n"
        "i=0\n"
        f"while [ ! -f '{allow_finish}' ] && [ \"$i\" -lt 80 ]; do\n"
        "  sleep 0.1\n"
        "  i=$((i + 1))\n"
        "done\n"
        f"test -f '{allow_finish}'\n"
    )
    hook.chmod(0o755)
    control = tmp_path / "control"
    control.mkdir(mode=0o700)
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    svc = WorkspaceService(parse_workspace_config({
        "schema_version": 1, "server": {"git": {"enabled": True}},
        "workspaces": {"b": {"root": str(b),
                             "git": {"allowed_commands": ["commit", "status"]}}},
    }), config_dir=control, inventory=ActiveRuntimeInventory(paths=(runtime,)))
    fd = svc.get("b").gateway._root_fd
    done = threading.Event()
    failures = []
    results = []

    def perform():
        try:
            results.append(svc.invoke_git(
                "b", "commit", options={"message": "hook release"},
                timeout_seconds=25, dry_run=False,
            ))
        except BaseException as exc:
            failures.append(exc)

    git_worker = threading.Thread(target=perform, name="actual-git-hook-worker")
    closer = threading.Thread(target=lambda: (svc.close(), done.set()),
                              name="actual-git-hook-close")
    try:
        git_worker.start()
        deadline = time.monotonic() + 8
        while not started.exists() and time.monotonic() < deadline:
            time.sleep(0.03)
        assert started.exists(), "actual Git pre-commit hook not observed"
        assert os.fstat(fd).st_ino == b.stat().st_ino
        closer.start()
        deadline = time.monotonic() + 5
        while not svc._closing and time.monotonic() < deadline:
            time.sleep(0.01)
        assert svc._closing
        assert not done.is_set()
        assert os.fstat(fd).st_ino == b.stat().st_ino
        with pytest.raises(GatewayError) as refused:
            svc.invoke_git("b", "status", dry_run=False)
        assert refused.value.code == "service_closing"
    finally:
        allow_finish.write_text("go\n")
        git_worker.join(timeout=15)
        closer.join(timeout=15)
        svc.close()
    assert not git_worker.is_alive() and not closer.is_alive()
    assert not failures, failures
    assert done.is_set()
    assert results[0]["exit_code"] == 0
    assert results[0]["cleanup_status"] == "complete"
    with pytest.raises(OSError):
        os.fstat(fd)
