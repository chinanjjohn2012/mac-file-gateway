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
