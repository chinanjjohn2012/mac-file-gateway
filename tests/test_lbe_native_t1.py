"""Approved T1 only: natural-exit Python child in hosted disposable macOS CI.

This source is skipped by default; no existing F1 public Exec gate changes.
No shell, network fixtures, user Mac/Tunnel, process/group signal or T2.
All real commands are fixed local Python scripts under runner scratch.
"""
from __future__ import annotations

import os
from pathlib import Path
import time

import pytest

from gateway.core import GatewayError
from gateway.exec_state import ExecStateStore
from gateway.lbe_native_launcher import make_trusted_lbe_launcher
from gateway.lbe_plan import prepare_lbe_work_plan
from gateway.lbe_worker import LbeWorker, LbeWorkerError
from gateway.workspaces import ActiveRuntimeInventory, WorkspaceService
from gateway.workspaces_config import parse_workspace_config

_GRANT = "PR101_R002_MACOS15_ARM64_DISPOSABLE_PYTHON_ONLY"


@pytest.fixture
def native_scene(tmp_path: Path):
    if os.environ.get("LBE_NATIVE_T1_AUTHORIZED") != _GRANT:
        pytest.skip("T1 NOT_RUN outside specifically authorized hosted macOS job")
    if (os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("RUNNER_OS") != "macOS"
            or os.environ.get("RUNNER_ARCH") != "ARM64"):
        pytest.fail("T1 runner is not an authorized hosted macOS ARM64")
    runner_temp = Path(os.environ["RUNNER_TEMP"]).resolve()
    assert tmp_path.resolve().is_relative_to(runner_temp)

    root = tmp_path / "project-a"
    work = root / "python-project"
    work.mkdir(parents=True)
    (work / "ok.py").write_text(
        "import sys\nprint('T1_ORIGINAL_STDOUT')\n"
        "print('T1_ORIGINAL_STDERR', file=sys.stderr)\n"
    )
    (work / "fail.py").write_text(
        "import sys\nprint('T1_EXIT_NONZERO')\nsys.exit(7)\n"
    )
    (work / "bounded_sleep.py").write_text(
        "import time\nprint('T1_SAFE_SLEEP')\ntime.sleep(1.5)\n"
    )
    (work / "hold.py").write_text(
        "import time\nprint('T1_HELD_ORIGINAL')\ntime.sleep(2.8)\n"
    )
    (work / "large_output.py").write_text(
        "import sys\nsys.stdout.write('O' * 65000)\n"
        "sys.stderr.write('E' * 65000)\n"
    )
    peer = tmp_path / "project-c"
    peer_python = peer / "python-project"
    peer_python.mkdir(parents=True)
    (peer_python / "ok.py").write_text("print('T1_PEER_ORIGINAL')\n")
    other = tmp_path / "project-b"
    other.mkdir()
    (other / "safe.txt").write_text("T1_SAFE_FILE_BEFORE\n")

    private = tmp_path / "private-control"
    private.mkdir(mode=0o700)
    private.chmod(0o700)
    runtime = tmp_path / "runtime-inventory"
    runtime.mkdir()
    state = ExecStateStore(private / "exec-state",
                           workspace_roots=(str(root), str(other), str(peer)))
    assert state.durability_state == "healthy"
    state.close()
    config = {
        "schema_version": 2,
        "server": {"port": 8765, "transport": "http",
                   "git": {"enabled": True}},
        "workspaces": {
            "a": {"root": str(root),
                  "exec": {"paths": ["python-project"], "runners": []}},
            "b": {"root": str(other),
                  "write": {"enabled": True, "paths": ["safe.txt"]},
                  "git": {"allowed_commands": ["status"]}},
            "c": {"root": str(peer),
                  "exec": {"paths": ["python-project"], "runners": []}},
        },
    }
    svc = WorkspaceService(
        parse_workspace_config(config), config_dir=private,
        inventory=ActiveRuntimeInventory(paths=(runtime,)))
    try:
        assert svc.info()["exec_policy"]["durability_state"] == "healthy"
        yield svc, root
    finally:
        svc.close()


def _internal(svc):
    ctx = svc.require_exec("a")
    worker = LbeWorker(
        svc._lbe_owner, launcher=make_trusted_lbe_launcher(ctx),
    )
    return ctx, worker


def _plan(ctx, script, timeout=5):
    return prepare_lbe_work_plan(
        ctx, cwd="python-project", argv=["python", script],
        timeout_seconds=timeout,
    )


@pytest.mark.parametrize("script,code,expected", [
    ("ok.py", 0, "T1_ORIGINAL_STDOUT"),
    ("fail.py", 7, "T1_EXIT_NONZERO"),
])
def test_original_exit_and_redacted_bounded_pipes(
    native_scene, script, code, expected,
):
    svc, root = native_scene
    ctx, worker = _internal(svc)
    result = worker.run(_plan(ctx, script))
    assert result["status"] == "exited"
    assert result["executed"] is True
    assert result["exit_code"] == code
    assert result["timed_out"] is False
    assert expected in result["stdout"]
    assert result["output_complete"] is True
    assert result["cleanup_proven"] is False
    assert result["full_descendant_tree_clean"] == "not_proven"
    assert result["process_may_be_running"] is True
    assert svc._lbe_owner.snapshot()["reserved_slots"] == 0
    assert not (root / "python-project" / "unexpected-child").exists()


def test_timeout_retains_slot_until_natural_direct_exit(native_scene):
    svc, _ = native_scene
    ctx, worker = _internal(svc)
    start = time.monotonic()
    result = worker.run(_plan(ctx, "bounded_sleep.py", timeout=1))
    assert time.monotonic() - start < 4.5
    assert result["status"] == "timed_out"
    assert result["executed"] is True
    assert result["exit_code"] is None
    assert result["timed_out"] is True
    assert result["process_may_be_running"] is True
    assert result["cleanup_proven"] is False
    if svc._lbe_owner.snapshot()["reserved_slots"] == 1:
        with pytest.raises(LbeWorkerError) as error:
            worker.run(_plan(ctx, "ok.py"))
        assert error.value.code == "busy"
    deadline = time.monotonic() + 4
    while svc._lbe_owner.snapshot()["reserved_slots"] and time.monotonic() < deadline:
        time.sleep(0.01)
    assert svc._lbe_owner.snapshot()["reserved_slots"] == 0
    assert svc._lbe_owner.snapshot()["unavailable"] is False


def test_real_v2_service_direct_apply_uses_single_source_gate(native_scene):
    """Actual service positive under owner-approved v2, never v1 or a bypass."""
    svc, _root = native_scene
    policy = svc.info()["exec_policy"]
    assert policy["mode"] == "local_best_effort"
    assert policy["available"] is True
    assert policy["completion_capability"] == "best_effort"
    result = svc.invoke_exec(
        "a", "python-project", ["python", "ok.py"],
        timeout_seconds=5, dry_run=False,
    )
    assert result["workspace"] == "a"
    assert result["mode"] == "local_best_effort"
    assert result["status"] == "exited"
    assert result["executed"] is True
    assert result["exit_code"] == 0
    assert "T1_ORIGINAL_STDOUT" in result["stdout"]
    assert "T1_ORIGINAL_STDERR" in result["stderr"]
    assert result["cleanup_proven"] is False
    assert result["full_descendant_tree_clean"] == "not_proven"
    assert result["output_complete"] is True
    assert svc._lbe_owner.snapshot()["reserved_slots"] == 0


def test_real_rest_run_and_health_share_same_approved_v2_service(native_scene):
    """REST parsing -> actual single Worker and original child, no mocked ACK."""
    from starlette.testclient import TestClient
    from gateway.http_multi import create_multi_app

    svc, _root = native_scene
    body = {"workspace": "a", "cwd": "python-project",
            "argv": ["python", "ok.py"], "timeout_seconds": 5,
            "dry_run": False}
    with TestClient(create_multi_app(svc, enable_mcp=False),
                    base_url="http://127.0.0.1:8765") as client:
        before = client.get("/health").json()["exec_policy"]
        assert before["mode"] == "local_best_effort"
        assert before["available"] is True
        assert before == client.get("/info").json()["exec_policy"]
        response = client.post("/run", json=body)
        assert response.status_code == 200
        result = response.json()
        assert result["workspace"] == "a"
        assert result["status"] == "exited"
        assert result["executed"] is True
        assert result["exit_code"] == 0
        assert "T1_ORIGINAL_STDOUT" in result["stdout"]
        assert result["cleanup_proven"] is False
        assert result["full_descendant_tree_clean"] == "not_proven"
        assert client.get("/health").json()["exec_policy"]["available"] is True


def test_real_mcp_sdk_jsonrpc_tool_uses_same_v2_worker(native_scene):
    """Official MCP SDK through real ASGI JSON-RPC, not a mocked tool call."""
    from starlette.testclient import TestClient
    from gateway.http_multi import create_multi_app

    svc, _root = native_scene
    headers = {"Accept": "application/json, text/event-stream",
               "Content-Type": "application/json"}
    def rpc(client, method, params=None):
        response = client.post("/mcp", headers=headers, json={
            "jsonrpc": "2.0", "id": 2, "method": method,
            "params": params or {},
        })
        assert response.status_code == 200, response.text
        return response.json()

    with TestClient(create_multi_app(svc), base_url="http://127.0.0.1:8765") as client:
        initialized = rpc(client, "initialize", {
            "protocolVersion": "2025-11-25", "capabilities": {},
            "clientInfo": {"name": "lbe-hosted-t1", "version": "1"},
        })
        assert "result" in initialized
        client.post("/mcp", headers=headers, json={
            "jsonrpc": "2.0", "method": "notifications/initialized"})
        names = {
            tool["name"] for tool in rpc(client, "tools/list")["result"]["tools"]
        }
        assert "run_command" in names
        good = {"workspace": "a", "cwd": "python-project",
                "argv": ["python", "ok.py"],
                "timeout_seconds": 5, "dry_run": False}
        executed = rpc(client, "tools/call", {
            "name": "run_command", "arguments": good,
        })["result"]
        assert executed.get("isError") is not True
        result = executed["structuredContent"]
        assert result["workspace"] == "a"
        assert result["mode"] == "local_best_effort"
        assert result["status"] == "exited"
        assert result["executed"] is True
        assert result["exit_code"] == 0
        assert "T1_ORIGINAL_STDOUT" in result["stdout"]
        assert result["cleanup_proven"] is False
        assert result["full_descendant_tree_clean"] == "not_proven"
        denied = rpc(client, "tools/call", {
            "name": "run_command",
            "arguments": {**good, "argv": ["python", "-c", "print(1)"]},
        })["result"]
        assert denied.get("isError") is True
        assert denied["structuredContent"]["error"] == "command_not_allowed"
    assert svc._lbe_owner.snapshot()["reserved_slots"] == 0


def test_v2_file_read_write_and_git_preview_keep_separate_grants(
    native_scene, monkeypatch,
):
    """One disposable v2 service: real File writes, Git preview, Python child.

    Git dry-run invokes no Git OS process (positive Git runtime remains
    NOT_RUN here). Workspace b can read/write files and preview authorized
    Git status but cannot borrow a's Exec permission. Conversely workspace a
    can execute its fixed Python script but cannot borrow b's Git grant.
    """
    import subprocess

    svc, _root = native_scene
    before = svc.invoke("b", "read_file", "safe.txt")
    assert before["workspace"] == "b"
    assert "T1_SAFE_FILE_BEFORE" in before["content"]
    svc.invoke(
        "b", "write_file", "safe.txt", "T1_SAFE_FILE_AFTER\\n",
        before["file_sha256"], dry_run=False,
    )
    after = svc.invoke("b", "read_file", "safe.txt")
    assert "T1_SAFE_FILE_AFTER" in after["content"]
    assert svc.any_exec is True
    assert svc.any_git is True

    def reject_git_spawn(*args, **kwargs):
        raise AssertionError("Git preview is not a native Git positive T1")

    with monkeypatch.context() as m:
        m.setattr(subprocess, "Popen", reject_git_spawn)
        preview = svc.invoke_git("b", "status", dry_run=True)
    assert preview["dry_run"] is True
    assert preview["execute_started"] is False
    with pytest.raises(GatewayError) as bad_git:
        svc.invoke_git("a", "status", dry_run=False)
    assert bad_git.value.code == "git_command_not_allowed"
    with pytest.raises(GatewayError) as bad_exec:
        svc.invoke_exec(
            "b", ".", ["python", "-m", "pytest"],
            timeout_seconds=5, dry_run=False)
    assert bad_exec.value.code == "exec_disabled"
    assert svc._lbe_owner.snapshot()["reserved_slots"] == 0

    ran = svc.invoke_exec(
        "a", "python-project", ["python", "ok.py"],
        timeout_seconds=5, dry_run=False)
    assert ran["executed"] is True
    assert ran["exit_code"] == 0
    assert "T1_ORIGINAL_STDOUT" in ran["stdout"]
    assert svc.invoke("b", "read_file", "safe.txt")["file_sha256"] == (
        after["file_sha256"])
    assert svc._lbe_owner.snapshot()["reserved_slots"] == 0



def test_real_output_cap_reports_both_streams_truncated_without_claiming_cleanup(
    native_scene,
):
    """Original child emits >48K bytes/stream; reader stores bounded prefixes."""
    svc, _root = native_scene
    result = svc.invoke_exec(
        "a", "python-project", ["python", "large_output.py"],
        timeout_seconds=5, dry_run=False,
    )
    assert result["status"] == "exited"
    assert result["executed"] is True
    assert result["exit_code"] == 0
    assert result["stdout_truncated"] is True
    assert result["stderr_truncated"] is True
    assert result["stdout"].startswith("O" * 256)
    assert result["stderr"].startswith("E" * 256)
    assert len(result["stdout"]) <= 48_000
    assert len(result["stderr"]) <= 48_000
    assert result["output_complete"] is True
    assert result["cleanup_proven"] is False
    assert result["full_descendant_tree_clean"] == "not_proven"
    assert result["process_may_be_running"] is True
    assert svc._lbe_owner.snapshot()["reserved_slots"] == 0


def test_public_timeout_retains_original_slot_but_other_workspace_can_execute(
    native_scene,
):
    """Two actual Python originals: timeout never recycles a's live child.

    A's fixed natural-exit child lives 2.8 seconds, while the user-facing
    command budget is 1 second. No PID signal/kill/retry is issued. A second
    independently granted Workspace c can run one short original child.
    """
    svc, _root = native_scene
    result = svc.invoke_exec(
        "a", "python-project", ["python", "hold.py"],
        timeout_seconds=1, dry_run=False,
    )
    assert result["status"] == "timed_out"
    assert result["executed"] is True
    assert result["timed_out"] is True
    assert result["exit_code"] is None
    assert result["process_may_be_running"] is True
    assert result["cleanup_proven"] is False
    policy = svc.info()["exec_policy"]
    assert policy["running_direct_children"] == 1
    # A's unavailable capacity does not disable a separately allowed c.
    assert policy["available"] is True
    with pytest.raises(GatewayError) as denied:
        svc.invoke_exec(
            "a", "python-project", ["python", "ok.py"],
            timeout_seconds=5, dry_run=False)
    assert denied.value.code == "busy"

    peer = svc.invoke_exec(
        "c", "python-project", ["python", "ok.py"],
        timeout_seconds=5, dry_run=False)
    assert peer["status"] == "exited"
    assert peer["executed"] is True
    assert peer["exit_code"] == 0
    assert "T1_PEER_ORIGINAL" in peer["stdout"]
    assert peer["cleanup_proven"] is False
    assert peer["full_descendant_tree_clean"] == "not_proven"

    deadline = time.monotonic() + 5
    while (svc._lbe_owner.snapshot()["reserved_slots"]
           and time.monotonic() < deadline):
        time.sleep(0.01)
    assert svc._lbe_owner.snapshot()["reserved_slots"] == 0
    assert svc._lbe_owner.snapshot()["unavailable"] is False
    assert svc.info()["exec_policy"]["available"] is True


def test_invalid_relative_script_has_zero_launch(native_scene):
    svc, root = native_scene
    ctx, _worker = _internal(svc)
    with pytest.raises(GatewayError):
        _plan(ctx, "../escape.py")
    assert svc._lbe_owner.snapshot()["reserved_slots"] == 0
    assert svc.info()["exec_policy"]["durability_state"] == "healthy"
    assert not (root / "escape.py").exists()
