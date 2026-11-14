"""PR114 Owner-approved EXTRA T1: real S1 original child + real Git/File.

Only one GitHub-hosted disposable macOS ARM64 WorkspaceService. S1 Python
pytest overlaps physical Git status/File Write. The installed host Python is
selected read-only, without copying or chmod of the executable. No signals,
force cleanup, restarts, user/shared/production resource or seventh command.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
from unittest.mock import patch

from gateway.core import GatewayError
from gateway.lbe_mvp_first_setup import initialize_fresh_v2_exec_state
from gateway.lbe_six_fixed_commands import SIX_FIXED_COMMANDS
from gateway.workspaces import ActiveRuntimeInventory, WorkspaceService
from gateway.workspaces_config import parse_workspace_config

EXPECTED = {
    "GITHUB_ACTIONS": "true",
    "GITHUB_EVENT_NAME": "pull_request",
    "GITHUB_REPOSITORY": "chinanjjohn2012/mac-file-gateway",
    "GITHUB_HEAD_REF": "feat/lbe-five-day-d2-nonoperative-prelaunch-20261106",
    "GITHUB_WORKFLOW": "six-command-mvp-mixed-native-t1-pr114",
    "RUNNER_OS": "macOS", "RUNNER_ARCH": "ARM64",
    "RUNNER_ENVIRONMENT": "github-hosted",
    "MVP_MIXED_T1_APPROVED_PR": "114",
}
S1 = ("python", "-m", "pytest", "-q")


def require_approved_runner() -> tuple[Path, str, str]:
    mismatch = sorted(k for k, v in EXPECTED.items()
                      if os.environ.get(k) != v)
    if mismatch:
        # Report only NAMES of failed gates, never values/secrets.
        raise RuntimeError(
            "Mixed T1 outside exact approved PR114 runner: "
            + ",".join(mismatch))
    if sys.platform != "darwin" or platform.machine().lower() != "arm64":
        raise RuntimeError("Mixed T1 requires hosted macOS ARM64")
    raw = os.environ.get("RUNNER_TEMP", "")
    if not raw.startswith("/"):
        raise RuntimeError("Temporary root unavailable")
    root = Path(raw).resolve(strict=True)
    if not root.is_dir() or root == Path("/"):
        raise RuntimeError("Unsafe temporary root")
    head = subprocess.check_output(
        ["/usr/bin/git", "rev-parse", "HEAD"], text=True).strip()
    tree = subprocess.check_output(
        ["/usr/bin/git", "rev-parse", "HEAD^{tree}"], text=True).strip()
    if (head != os.environ.get("G05_EXPECTED_HEAD")
            or len(head) != 40 or len(tree) != 40):
        raise RuntimeError("G05 and native T1 source differ")
    # GitHub exposes the actual labeled event in a signed-host-runner payload.
    # GITHUB_EVENT_ACTION is not a reliable environment gate on all runners.
    # Validate the triggering event content instead, BEFORE test fixtures.
    event_file = os.environ.get("GITHUB_EVENT_PATH", "")
    if not event_file.startswith("/"):
        raise RuntimeError("Mixed T1 GitHub label-event file unavailable")
    event = json.loads(Path(event_file).read_text())
    pull = event.get("pull_request") or {}
    pull_head = pull.get("head") or {}
    if (event.get("action") != "labeled"
            or (event.get("label") or {}).get("name")
                != "mvp-mixed-native-t1-approved"
            or pull.get("number") != 114
            or pull_head.get("sha") != head
            or pull_head.get("ref") != EXPECTED["GITHUB_HEAD_REF"]
            or (pull_head.get("repo") or {}).get("full_name")
                != EXPECTED["GITHUB_REPOSITORY"]):
        raise RuntimeError("Mixed T1 GitHub label-event scope mismatch")
    return root, head, tree


def _selected_tools(boundary: Path) -> tuple[dict[str, str], dict]:
    python = Path(sys.executable).resolve(strict=True)
    go_str, pipenv_str = shutil.which("go"), shutil.which("pipenv")
    if not go_str or not pipenv_str or not os.access(python, os.X_OK):
        raise RuntimeError("Installed Python/Go/Pipenv not qualified")
    go = Path(go_str).resolve(strict=True)
    original = Path(pipenv_str).read_bytes()
    if (len(original) > 32768 or not original.startswith(b"#!")
            or b"\n" not in original or b"\x00" in original):
        raise RuntimeError("Installed Pipenv console unavailable")
    _, body = original.split(b"\n", 1)
    if b"pipenv" not in body or b"import" not in body:
        raise RuntimeError("Pipenv console not supported")
    tools = boundary / "operator-tools"
    tools.mkdir(mode=0o700)
    tools.chmod(0o700)
    staged = tools / "pipenv"
    staged.write_bytes(b"#!" + os.fsencode(str(python)) + b"\n" + body)
    staged.chmod(0o700)
    if staged.is_symlink() or staged.stat().st_nlink != 1:
        raise RuntimeError("Disposable Pipenv staging unsafe")
    mode = stat.S_IMODE(python.stat().st_mode)
    return (
        {"python": str(python), "pipenv": str(staged), "go": str(go)},
        {"installed_python_mode": oct(mode),
         "installed_python_is_0775": mode == 0o775,
         "installed_python_used_without_copy_or_chmod": True,
         "installed_python_sha256": hashlib.sha256(python.read_bytes()).hexdigest()},
    )


def _git_file(svc: WorkspaceService, root: Path, before: str,
              after: str, name: str) -> dict:
    git = svc.invoke_git("a", "status", timeout_seconds=30, dry_run=False)
    if (git.get("exit_code") != 0 or git.get("execute_started") is not True
            or git.get("repository_checked") is not True
            or git.get("cleanup_status") != "complete"):
        raise AssertionError("Real Git failed: " + name)
    path = root / "py-direct" / "safe.txt"
    original = svc.invoke("a", "read_file", "py-direct/safe.txt")
    if (path.read_text() != before or original.get("file_sha256")
            != hashlib.sha256(before.encode()).hexdigest()):
        raise AssertionError("File read/hash mismatch: " + name)
    svc.invoke("a", "write_file", "py-direct/safe.txt", after,
               original["file_sha256"], dry_run=False)
    updated = svc.invoke("a", "read_file", "py-direct/safe.txt")
    if (path.read_text() != after or updated.get("file_sha256")
            != hashlib.sha256(after.encode()).hexdigest()):
        raise AssertionError("Physical File Write failed: " + name)
    return {"phase": name, "real_git_status": True, "physical_file_write": True}


def _native_exit(result: dict, owner: dict) -> None:
    if (result.get("executed") is not True
            or result.get("status") != "exited"
            or result.get("exit_code") != 0
            or result.get("output_complete") is not True
            or result.get("pipe_reader_failed") is not False
            or result.get("stdout_truncated") is not False
            or result.get("stderr_truncated") is not False
            or result.get("cleanup_proven") is not False
            or result.get("full_descendant_tree_clean") != "not_proven"
            or owner.get("unavailable") is not False
            or owner.get("closing") is not False
            or owner.get("reserved_slots") != 0):
        raise AssertionError("Native S1 result/Owner not clean")


def _execute(boundary: Path, report: dict) -> None:
    root = boundary / "workspaces" / "a"
    root.mkdir(parents=True)
    project = root / "py-direct"
    project.mkdir()
    (project / "safe.txt").write_text("INITIAL\n")
    (project / "test_native_overlap.py").write_text(
        "import time\n"
        "from pathlib import Path\n"
        "def test_native_overlap():\n"
        "    Path(__file__).with_name('native-started.marker').write_text('STARTED')\n"
        "    time.sleep(8)\n"
        "    assert 6 * 7 == 42\n"
    )
    subprocess.run(["/usr/bin/git", "init", "-q"], cwd=root,
                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                   stderr=subprocess.PIPE, timeout=30, check=True)
    private = boundary / "private"
    private.mkdir(mode=0o700)
    private.chmod(0o700)
    runtime = boundary / "runtime"
    runtime.mkdir()
    binaries, observation = _selected_tools(boundary)
    report["tools"] = observation
    print("MVP_MIXED_T1_TOOL=" + json.dumps(observation, sort_keys=True),
          flush=True)
    selection = private / "mvp-exec-tools.json"
    selection.write_text(json.dumps({"executables": binaries}))
    selection.chmod(0o600)
    initialize_fresh_v2_exec_state(
        private, operator_confirmed_first_install=True,
        operator_confirmed_gateway_stopped=True)
    config = parse_workspace_config({
        "schema_version": 2,
        "server": {"port": 8765, "transport": "http",
                   "exec": {"enabled": True}, "git": {"enabled": True}},
        "workspaces": {"a": {
            "root": str(root),
            "exec": {"enabled": True, "paths": ["py-direct"], "runners": []},
            "write": {"enabled": True, "paths": ["py-direct"]},
            "git": {"allowed_commands": ["status"]},
        }},
    })
    svc = WorkspaceService(
        config, config_dir=private,
        inventory=ActiveRuntimeInventory(paths=(runtime,)))
    try:
        policy = svc.info()["exec_policy"]
        if (policy.get("available") is not True
                or policy.get("apply_configured") is not True
                or policy.get("tool_selection_ready") is not True):
            raise AssertionError("MVP positive admission unavailable")
        phases = [_git_file(svc, root, "INITIAL\n", "BEFORE\n", "before")]
        row = next(x for x in SIX_FIXED_COMMANDS
                   if x.command_id == "py-direct-pytest")
        if row.cwd != "py-direct" or tuple(row.requested_argv) != S1:
            raise AssertionError("S1 vector changed")
        result: dict = {}
        done = threading.Event()

        def native() -> None:
            try:
                result["value"] = svc.invoke_exec(
                    "a", row.cwd, list(S1), timeout_seconds=60, dry_run=False)
            except BaseException as error:
                result["error"] = type(error).__name__
            finally:
                done.set()

        thread = threading.Thread(target=native, daemon=True,
                                  name="PR114-disposable-original-S1")
        thread.start()
        started = project / "native-started.marker"
        deadline = time.monotonic() + 20
        while not started.is_file():
            if done.is_set() or time.monotonic() > deadline:
                raise AssertionError("Original child failed to start fixture")
            time.sleep(0.05)
        original = svc._lbe_owner.snapshot()
        if (original["running_direct_children"] != 1
                or original["reserved_slots"] != 1):
            raise AssertionError("Expected one owned active original child")
        phases.append(_git_file(svc, root, "BEFORE\n", "DURING\n", "during"))
        overlap = svc._lbe_owner.snapshot()
        if (overlap["running_direct_children"] != 1
                or overlap["reserved_slots"] != 1):
            raise AssertionError("Git/File was not concurrent with live S1")
        thread.join(timeout=75)
        if thread.is_alive() or "error" in result or "value" not in result:
            raise AssertionError("Native S1 unresolved; no kill/retry allowed")
        _native_exit(result["value"], svc._lbe_owner.snapshot())
        phases.append(_git_file(svc, root, "DURING\n", "AFTER\n", "after"))
        # Quarantine denial cannot consume an extra native command, even
        # on a bug: patch worker/Popen during denial and restore for real Git.
        store = svc._exec_state
        st = root.stat()
        attempt = store.prepare("a", (st.st_dev, st.st_ino))
        store.mark_unknown(attempt)
        marker = private / "exec-state" / ("r-" + attempt + ".json")
        old_record = marker.read_bytes()
        with patch("subprocess.Popen", side_effect=AssertionError(
                "UNKNOWN cannot spawn")), patch(
                "gateway.lbe_worker.LbeWorker.run", side_effect=AssertionError(
                    "UNKNOWN cannot reach worker")):
            try:
                svc.invoke_exec("a", "py-direct", list(S1),
                                timeout_seconds=60, dry_run=False)
            except GatewayError as error:
                if error.code != "exec_quarantined":
                    raise AssertionError("Wrong old UNKNOWN denial")
            else:
                raise AssertionError("UNKNOWN unexpectedly authorized Exec")
        phases.append(_git_file(svc, root, "AFTER\n", "UNDER_UNKNOWN\n",
                                "under-UNKNOWN"))
        if store.durability_state != "quarantined" or marker.read_bytes() != old_record:
            raise AssertionError("Original UNKNOWN record changed")
        report.update(
            status="PASS", native_original_children=1,
            native_exit_code=0, native_output_complete=True,
            original_child_overlapped_real_git_file=True,
            real_git_file_independent_under_unknown=True,
            phases=phases,
            stock_0775_status=("PASS" if observation["installed_python_is_0775"]
                               else "NOT_OBSERVED"),
            full_descendant_tree_clean="not_proven",
        )
    finally:
        # Close handles only; never send a process signal or retry a child.
        svc.close()


def main() -> None:
    root, head, tree = require_approved_runner()
    report = {
        "target": "PR114 native mixed S1 + real Git/File",
        "head": head, "tree": tree,
        "contract": "d90df6de3bdbd81a314109d5f73959799b5a10a6",
        "status": "IN_PROGRESS",
    }
    try:
        with tempfile.TemporaryDirectory(prefix="pr114-mixed-", dir=root) as tmp:
            _execute(Path(tmp), report)
    except BaseException as error:
        report["status"] = "FAIL"
        report["failure_type"] = type(error).__name__
        raise
    finally:
        (root / "mvp-native-mixed-t1-result.json").write_text(
            json.dumps(report, sort_keys=True, indent=2) + "\n")
        print("MVP_MIXED_T1_RESULT=" + json.dumps(report, sort_keys=True),
              flush=True)


if __name__ == "__main__":
    main()
