"""Nonspawning SAFE T0 for approved six-command v2 admission and launcher.

No native Python, Pipenv, or Go child is launched; all subprocess.Popen calls
are replaced by a spy or forbidden.  T1 and same-instance native acceptance
remain separately authorized milestones.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess

import pytest

from gateway.core import GatewayError
from gateway.exec_state import ExecStateStore
from gateway.lbe_mvp_tools import MvpTrustedTools
from gateway.lbe_plan import prepare_lbe_work_plan
from gateway.lbe_native_launcher import make_trusted_lbe_launcher
from gateway.lbe_six_fixed_commands import SIX_FIXED_COMMANDS
from gateway.lbe_worker import LbeWorker
from gateway.workspaces import ActiveRuntimeInventory, WorkspaceService
from gateway.workspaces_config import parse_workspace_config


@pytest.fixture
def mvp(tmp_path):
    root = tmp_path / "projects" / "a"
    root.mkdir(parents=True)
    (root / "py-direct" / "src").mkdir(parents=True)
    (root / "py-direct" / "src" / "main.py").write_text("value = 1\n")
    pip = root / "py-pipenv"
    (pip / ".venv" / "bin").mkdir(parents=True)
    (pip / "Pipfile").write_text("[packages]\n")
    (pip / ".venv" / "bin" / "python").write_bytes(b"test-only virtualenv bytes")
    (pip / ".venv" / "bin" / "python").chmod(0o700)
    go = root / "go-project"
    (go / "cmd" / "app").mkdir(parents=True)
    (go / "cmd" / "app" / "main.go").write_text(
        "package main\nfunc main() {}\n")
    (go / "go.mod").write_text("module fixture.local/example\ngo 1.23\n")
    (go / "bin").mkdir()
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    private.chmod(0o700)
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    bin_dir = tmp_path / "tools"
    bin_dir.mkdir()
    for name in ("python", "go"):
        f = bin_dir / name
        f.write_bytes(b"\x7fELFfake tool; NEVER EXECUTED")
        f.chmod(0o700)
    script = bin_dir / "pipenv"
    script.write_bytes(
        b"#!" + str(bin_dir / "python").encode("utf-8")
        + b"\n# fake console script NEVER EXECUTED\n")
    script.chmod(0o700)
    config_file = private / "mvp-exec-tools.json"
    config_file.write_text(json.dumps({
        "executables": {name: str(bin_dir / name)
                        for name in ("python", "pipenv", "go")},
    }))
    config_file.chmod(0o600)
    state = ExecStateStore(private / "exec-state",
                           workspace_roots=(str(root),))
    state.close()

    def service(*, server_enabled=True, workspace_enabled=True,
                paths=("py-direct", "py-pipenv", "go-project")):
        config = {
            "schema_version": 2,
            "server": {"port": 8765, "transport": "http",
                       "exec": {"enabled": server_enabled}},
            "workspaces": {"a": {
                "root": str(root),
                "exec": {
                    "enabled": workspace_enabled,
                    "paths": list(paths),
                    "runners": ["py-pipenv=pipenv"],
                },
            }},
        }
        return WorkspaceService(
            parse_workspace_config(config), config_dir=private,
            inventory=ActiveRuntimeInventory(paths=(runtime,)))

    yield service, root, private, config_file, bin_dir


@pytest.mark.parametrize("row", SIX_FIXED_COMMANDS, ids=lambda r: r.command_id)
def test_six_service_apply_reaches_worker_only_with_dual_optin(mvp, monkeypatch, row):
    make, root, private, tool_config, bin_dir = mvp
    service = make()
    calls = []

    def no_native(*args, **kwargs):
        raise AssertionError("T0 must not execute native processes")

    def fake_worker_run(self, plan, *, cancelled=None, **kwargs):
        calls.append(plan)
        return {"status": "exited", "executed": True, "exit_code": 0,
                "stdout": "", "stderr": "", "timed_out": False,
                "process_may_be_running": True, "cleanup_proven": False}

    monkeypatch.setattr(subprocess, "Popen", no_native)
    monkeypatch.setattr(LbeWorker, "run", fake_worker_run)
    try:
        preview = service.invoke_exec(
            "a", row.cwd, list(row.requested_argv), dry_run=True)
        assert preview["status"] == "preview" and not preview["executed"]
        result = service.invoke_exec(
            "a", row.cwd, list(row.requested_argv),
            dry_run=False)
        assert result["status"] == "exited"
        assert len(calls) == 1
        assert calls[0].cwd == row.cwd
        assert calls[0].effective_argv == row.effective_argv
    finally:
        service.close()


@pytest.mark.parametrize("server,workspace", [
    (False, False), (False, True), (True, False),
])
def test_false_or_missing_apply_flag_keeps_legacy_preview_only(mvp, monkeypatch,
                                                               server, workspace):
    make, *_ = mvp
    s = make(server_enabled=server, workspace_enabled=workspace)
    monkeypatch.setattr(subprocess, "Popen",
                        lambda *a, **k: pytest.fail("T0 spawned a process"))
    try:
        assert s.invoke_exec("a", "py-direct",
                             ["python", "-m", "pytest", "-q"],
                             dry_run=True)["status"] == "preview"
        with pytest.raises(GatewayError) as denied:
            s.invoke_exec("a", "py-direct",
                          ["python", "-m", "pytest", "-q"],
                          dry_run=False)
        assert denied.value.code == "exec_disabled"
        assert not s.info()["exec_policy"]["apply_configured"]
    finally:
        s.close()


@pytest.mark.parametrize("server,workspace", [
    (False, False), (False, True), (True, False),
])
def test_v2_missing_private_state_still_denies_disabled_apply_first(
        mvp, monkeypatch, server, workspace):
    """Missing old state cannot expose pre-opt-in Exec state or run a child.

    The preserved directory is merely renamed in this disposable T0 fixture;
    this test never resets a real historical Exec state.
    """
    make, _root, private, *_ = mvp
    (private / "exec-state").rename(private / "preserved-test-state")
    s = make(server_enabled=server, workspace_enabled=workspace)
    monkeypatch.setattr(
        subprocess, "Popen",
        lambda *a, **k: pytest.fail("v2 disabled Exec spawned a native child"),
    )
    try:
        with pytest.raises(GatewayError) as denied:
            s.invoke_exec(
                "a", "py-direct", ["python", "-m", "pytest", "-q"],
                dry_run=False,
            )
        assert denied.value.code == "exec_disabled"
        assert not s.info()["exec_policy"]["available"]
    finally:
        s.close()


@pytest.mark.parametrize("wrong_cwd,argv", [
    ("go-project", ["go", "test", "./another"]),
    ("go-project", ["go", "build", "./other"]),
    ("go-project", ["go", "run", "./cmd/app"]),
    ("go-project", ["go", "test", "-exec=/tmp/helper", "./..."]),
    ("py-direct", ["python", "-c", "print(1)"]),
    ("py-direct", ["python", "-m", "pytest", "-q", "--pdb"]),
    ("py-pipenv", ["pipenv", "run", "python", "-m", "pytest", "-q"]),
    ("py-direct/src", ["python", "-m", "pytest", "-q"]),
])
def test_non_six_positive_requests_have_no_child(mvp, monkeypatch,
                                                 wrong_cwd, argv):
    make, *_ = mvp
    s = make()
    monkeypatch.setattr(subprocess, "Popen",
                        lambda *a, **k: pytest.fail("non-six process spawned"))
    monkeypatch.setattr(LbeWorker, "run",
                        lambda *a, **k: pytest.fail("non-six Worker ran"))
    try:
        with pytest.raises(GatewayError) as denied:
            s.invoke_exec("a", wrong_cwd, argv, dry_run=False)
        assert denied.value.code in {
            "command_not_allowed", "invalid_argument", "blocked_path",
            "runner_unavailable", "exec_scope",
        }
    finally:
        s.close()


@pytest.mark.parametrize("row", SIX_FIXED_COMMANDS, ids=lambda r: r.command_id)
def test_launcher_selects_absolute_tool_and_fresh_environment_without_spawn(
        mvp, monkeypatch, row):
    make, root, private, tool_config, bin_dir = mvp
    s = make()
    calls = []

    def fake_popen(argv, **kw):
        calls.append((argv, kw))
        return object()

    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    monkeypatch.setenv("PYTHONPATH", "/untrusted/python")
    monkeypatch.setenv("GOFLAGS", "-toolexec=/untrusted/helper")
    monkeypatch.setenv("GOCACHEPROG", "/untrusted/cache")
    monkeypatch.setenv("PIPENV_PIPFILE", "/untrusted/Pipfile")
    monkeypatch.setenv("SSH_AUTH_SOCK", "/untrusted/ssh")
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://untrusted")
    try:
        ctx = s.get("a")
        plan = prepare_lbe_work_plan(
            ctx, cwd=row.cwd, argv=list(row.requested_argv))
        launch = make_trusted_lbe_launcher(
            ctx, mvp_tools=s._mvp_tools)
        launch(plan)
        assert len(calls) == 1
        argv, kw = calls[0]
        expected_program = ("pipenv" if row.runner == "pipenv"
                            else row.requested_argv[0])
        assert argv[0] == str(bin_dir / expected_program)
        assert kw["cwd"] == str(root / row.cwd)
        assert kw["stdin"] == subprocess.DEVNULL
        assert kw["stdout"] == subprocess.PIPE
        assert kw["stderr"] == subprocess.PIPE
        assert kw["close_fds"] is True
        assert not kw.get("shell")
        env = kw["env"]
        for forbidden in (
            "PYTHONPATH", "GOFLAGS_SECRET", "GOCACHEPROG",
            "SSH_AUTH_SOCK", "ACTIONS_ID_TOKEN_REQUEST_URL",
        ):
            assert forbidden not in env
        if expected_program == "go":
            assert env["GOFLAGS"] == "" and env["GOENV"] == "off"
        else:
            assert "GOFLAGS" not in env
        if expected_program == "pipenv":
            assert env["PIPENV_PIPFILE"] == str(root / "py-pipenv" / "Pipfile")
            assert env["PIPENV_PYTHON"] == str(
                root / "py-pipenv" / ".venv" / "bin" / "python")
            assert env["PIPENV_VENV_IN_PROJECT"] == "1"
            assert env["PIPENV_IGNORE_VIRTUALENVS"] == "1"
            assert env["PIPENV_DONT_LOAD_ENV"] == "1"
        else:
            assert "PIPENV_PIPFILE" not in env
            assert "PIPENV_PYTHON" not in env
    finally:
        s.close()


def test_missing_tool_selection_denies_positive_but_keeps_preview(mvp):
    make, root, private, tool_config, bin_dir = mvp
    tool_config.unlink()
    s = make()
    try:
        assert s.info()["exec_policy"]["apply_configured"]
        assert not s.info()["exec_policy"]["available"]
        assert s.invoke_exec(
            "a", "py-direct", ["python", "-m", "pytest", "-q"],
            dry_run=True)["status"] == "preview"
        with pytest.raises(GatewayError) as denied:
            s.invoke_exec(
                "a", "py-direct", ["python", "-m", "pytest", "-q"],
                dry_run=False)
        assert denied.value.code == "runner_unavailable"
    finally:
        s.close()


def test_mvp_status_uses_actual_configuration_and_old_state(mvp):
    make, root, private, *_ = mvp
    s = make()
    try:
        status = s.info()
        assert status["exec_policy"]["apply_configured"]
        assert status["exec_policy"]["tool_selection_ready"]
        assert status["exec_policy"]["available"]
        assert status["exec_policy"]["completion_capability"] == "best_effort"
        assert len(status["exec_policy"]["supported_apply_commands"]) == 6
        assert status["read_only"] is False
        assert status["workspaces"][0]["exec_apply_available"]
    finally:
        s.close()


@pytest.mark.parametrize("command_id", ["py-direct-pytest", "go-test"])
def test_rest_and_official_mcp_share_same_mocked_positive_service(
        mvp, monkeypatch, command_id):
    """Real Starlette/MCP SDK adapters; only native Worker is a T0 Fake."""
    pytest.importorskip("mcp")
    from starlette.testclient import TestClient
    from gateway.http_multi import create_multi_app

    make, *_ = mvp
    row = next(r for r in SIX_FIXED_COMMANDS if r.command_id == command_id)
    s = make()
    visited = []

    def fake_run(self, plan, *, cancelled=None, **kwargs):
        visited.append((plan.workspace, plan.cwd, plan.requested_argv))
        return {"status": "exited", "executed": True, "exit_code": 0,
                "stdout": "T0 FakeChild only", "stderr": "",
                "timed_out": False, "process_may_be_running": True,
                "cleanup_proven": False, "output_complete": True}

    monkeypatch.setattr(subprocess, "Popen",
                        lambda *a, **kw: pytest.fail("No native T1 grant"))
    monkeypatch.setattr(LbeWorker, "run", fake_run)
    args = {"workspace": "a", "cwd": row.cwd,
            "argv": list(row.requested_argv), "dry_run": False}
    headers = {"Accept": "application/json, text/event-stream",
               "Content-Type": "application/json"}

    def rpc(client, method, params, request_id):
        response = client.post("/mcp", headers=headers, json={
            "jsonrpc": "2.0", "id": request_id,
            "method": method, "params": params})
        assert response.status_code == 200, response.text
        return response.json()

    try:
        with TestClient(create_multi_app(s),
                        base_url="http://127.0.0.1:8765") as client:
            assert client.get("/health").json()["exec_policy"] == (
                client.get("/info").json()["exec_policy"])
            rest = client.post("/run", json=args)
            assert rest.status_code == 200, rest.text
            assert rest.json()["status"] == "exited"
            assert rest.json()["exit_code"] == 0

            initial = rpc(client, "initialize", {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "six-mvp-t0", "version": "1"},
            }, 10)
            assert "result" in initial
            client.post("/mcp", headers=headers, json={
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
            })
            mcp = rpc(client, "tools/call", {
                "name": "run_command", "arguments": args}, 11)
            result = mcp["result"]
            assert not result.get("isError"), result
            structured = result.get("structuredContent", {})
            assert structured["status"] == "exited"
            assert structured["exit_code"] == 0

            # A generic wider Go preview must never acquire a positive
            # Worker through either adapter, even under both opt-ins.
            illegal = dict(args, cwd="go-project",
                           argv=["go", "test", "./another"])
            err_rest = client.post("/run", json=illegal)
            assert err_rest.json()["error"] == "command_not_allowed"
            err_mcp = rpc(client, "tools/call", {
                "name": "run_command", "arguments": illegal}, 12)
            assert err_mcp["result"]["isError"] is True
            assert (err_mcp["result"]["structuredContent"]["error"]
                    == "command_not_allowed")
        assert len(visited) == 2
        assert visited[0] == visited[1] == (
            "a", row.cwd, row.requested_argv)
    finally:
        s.close()


def test_known_prelaunch_cancel_proves_no_child_and_no_slot(mvp, monkeypatch):
    import threading

    make, *_ = mvp
    s = make()
    cancelled = threading.Event()
    cancelled.set()
    monkeypatch.setattr(subprocess, "Popen",
                        lambda *a, **k: pytest.fail("cancelled launch"))
    try:
        with pytest.raises(GatewayError) as denied:
            s.invoke_exec("a", "py-direct",
                          ["python", "-m", "pytest", "-q"],
                          dry_run=False, cancelled=cancelled)
        assert denied.value.code == "waiter_disconnected"
        assert denied.value.details["process_may_be_running"] is False
        assert s._lbe_owner.snapshot()["reserved_slots"] == 0
    finally:
        s.close()


def test_tool_changed_since_startup_is_proven_prelaunch_failure(mvp, monkeypatch):
    make, root, private, tool_config, bin_dir = mvp
    s = make()
    monkeypatch.setattr(subprocess, "Popen",
                        lambda *a, **k: pytest.fail("tool changed before Popen"))
    try:
        (bin_dir / "go").unlink()
        result = s.invoke_exec("a", "go-project", ["go", "test", "./..."],
                               dry_run=False)
        assert result["status"] == "launch_failed"
        assert result["executed"] is False
        assert result["exit_code"] is None
        assert not result["process_may_be_running"]
        assert s._lbe_owner.snapshot()["reserved_slots"] == 0
    finally:
        s.close()


def test_unqualified_pipenv_console_shebang_rejected_at_startup(mvp):
    make, root, private, tool_config, bin_dir = mvp
    (bin_dir / "pipenv").write_bytes(
        b"#!/usr/bin/env python\n# no native execution\n")
    s = make()
    try:
        policy = s.info()["exec_policy"]
        assert policy["apply_configured"]
        assert not policy["tool_selection_ready"]
        assert not policy["available"]
        with pytest.raises(GatewayError) as denied:
            s.invoke_exec("a", "py-pipenv",
                          ["python", "-m", "pytest", "-q"], dry_run=False)
        assert denied.value.code == "runner_unavailable"
    finally:
        s.close()


def test_ambiguous_native_launch_exception_preserves_uncertain_slot(mvp, monkeypatch):
    """Popen OSError cannot prove no child: owner latches, no silent retry."""
    make, *_ = mvp
    s = make()
    raised = []

    def synthetic_exception(*args, **kwargs):
        raised.append(True)
        raise OSError("synthetic Popen may have started a child")

    monkeypatch.setattr(subprocess, "Popen", synthetic_exception)
    try:
        with pytest.raises(GatewayError) as denied:
            s.invoke_exec("a", "py-direct",
                          ["python", "-m", "pytest", "-q"], dry_run=False)
        assert raised == [True]
        assert denied.value.code == "exec_state_unavailable"
        assert denied.value.details["process_may_be_running"] is True
        assert s._lbe_owner.snapshot()["unavailable"] is True
        with pytest.raises(GatewayError):
            s.invoke_exec("a", "py-direct",
                          ["python", "-m", "pytest", "-q"], dry_run=False)
        assert raised == [True], "uncertain attempt must not be retried"
    finally:
        s.close()


def test_pipenv_project_interpreter_must_be_executable_before_spawn(
        mvp, monkeypatch):
    """An interpreter changed to a non-executable is a witnessed NO child."""
    make, root, *_ = mvp
    s = make()
    binary = root / "py-pipenv" / ".venv" / "bin" / "python"
    # Fixture state was already admitted; malicious/swapped executable bytes
    # are not executed in this test (Popen stays forbidden).
    binary.chmod(0o600)
    monkeypatch.setattr(subprocess, "Popen",
                        lambda *a, **k: pytest.fail("Pipenv launched bad python"))
    try:
        out = s.invoke_exec("a", "py-pipenv",
                            ["python", "-m", "pytest", "-q"],
                            dry_run=False)
        assert out["status"] == "launch_failed"
        assert out["executed"] is False and out["exit_code"] is None
        assert out["process_may_be_running"] is False
        assert s._lbe_owner.snapshot()["reserved_slots"] == 0
    finally:
        s.close()


def test_pipenv_python_env_ignores_ambient_override(mvp, monkeypatch):
    """Pipenv uses selected project-local interpreter, never inherited env."""
    make, root, *_ = mvp
    s = make()
    calls = []
    monkeypatch.setenv("PIPENV_PYTHON", "/untrusted/fake")
    monkeypatch.setattr(subprocess, "Popen",
                        lambda argv, **kwargs: calls.append((argv, kwargs)))
    try:
        ctx = s.get("a")
        plan = prepare_lbe_work_plan(
            ctx, cwd="py-pipenv",
            argv=["python", "-m", "pytest", "-q"])
        make_trusted_lbe_launcher(ctx, mvp_tools=s._mvp_tools)(plan)
        assert len(calls) == 1
        env = calls[0][1]["env"]
        assert env["PIPENV_PYTHON"] == str(
            root / "py-pipenv" / ".venv" / "bin" / "python")
        assert env["PIPENV_PYTHON"] != "/untrusted/fake"
        assert env["PIPENV_PIPFILE"] == str(
            root / "py-pipenv" / "Pipfile")
    finally:
        s.close()


def test_phase1_legal_operator_selected_0775_tools_remain_usable(mvp, monkeypatch):
    """Legal 0775 Homebrew-style tools are selected by private operator input."""
    make, _root, _private, _config, tools = mvp
    (tools / "python").chmod(0o775)
    (tools / "pipenv").chmod(0o775)
    (tools / "go").chmod(0o775)
    monkeypatch.setattr(subprocess, "Popen",
                        lambda *a, **k: pytest.fail("T0 must not spawn"))
    service = make()
    try:
        assert service._mvp_tools is not None
        assert service.info()["exec_policy"]["tool_selection_ready"] is True
    finally:
        service.close()


def test_pipenv_project_venv_directory_symlink_cannot_escape(mvp, monkeypatch):
    """The .venv directory is not allowed to alias an external interpreter."""
    make, root, *_ = mvp
    external = root.parent.parent / "outside-venv"
    (external / "bin").mkdir(parents=True)
    (external / "bin" / "python").write_bytes(b"fake external interpreter")
    (external / "bin" / "python").chmod(0o700)
    venv_dir = root / "py-pipenv" / ".venv"
    (venv_dir / "bin" / "python").unlink()
    (venv_dir / "bin").rmdir()
    venv_dir.rmdir()
    venv_dir.symlink_to(external, target_is_directory=True)
    service = make()
    monkeypatch.setattr(subprocess, "Popen",
                        lambda *a, **k: pytest.fail("escaped venv spawned"))
    try:
        result = service.invoke_exec(
            "a", "py-pipenv", ["python", "-m", "pytest", "-q"], dry_run=False)
        assert result["status"] == "launch_failed"
        assert result["executed"] is False
        assert service._lbe_owner.snapshot()["reserved_slots"] == 0
    finally:
        service.close()


def test_native_t1_receipt_rejects_last_row_reader_fault_and_owner_latch():
    """A native zero exit must not become a clean T1 PASS after reader failure."""
    from tools.mvp_six_native_t1 import _check_result

    healthy = {"unavailable": False, "closing": False}
    clean = {
        "status": "exited", "executed": True, "exit_code": 0,
        "workspace": "a", "timed_out": False,
        "stdout": "ok", "stderr": "",
        "output_complete": True, "pipe_reader_failed": False,
        "pipe_reader_finished": True,
        "stdout_truncated": False, "stderr_truncated": False,
        "cleanup_proven": False, "full_descendant_tree_clean": "not_proven",
        "process_may_be_running": True,
    }
    assert _check_result(clean, command_id="last-row", mode="MCP",
                         owner_health=healthy)["output_complete"] is True
    for defect in (
        {"pipe_reader_failed": True},
        {"pipe_reader_finished": False},
        {"output_complete": False},
        {"stdout_truncated": True},
        {"stderr_truncated": True},
        {"cleanup_proven": True},
    ):
        with pytest.raises(AssertionError):
            _check_result({**clean, **defect}, command_id="last-row",
                          mode="MCP", owner_health=healthy)
    with pytest.raises(AssertionError):
        _check_result(clean, command_id="last-row", mode="MCP",
                      owner_health={"unavailable": True, "closing": False})


@pytest.mark.parametrize("row", SIX_FIXED_COMMANDS[2:],
                         ids=lambda r: r.command_id)
def test_phase1_0777_workspace_and_0775_project_allow_s3_to_s6(mvp, monkeypatch, row):
    """Legal trusted-local source roots must reach exact six FakeWorker, zero Popen."""
    make, root, *_ = mvp
    root.chmod(0o777)
    (root / row.cwd).chmod(0o775)
    (root / "go-project" / "bin").chmod(0o777)
    (root / "py-pipenv" / "Pipfile").chmod(0o666)
    output = root / "go-project" / "bin" / "app"
    output.write_bytes(b"existing go output")
    output.chmod(0o666)
    calls = []
    monkeypatch.setattr(subprocess, "Popen",
                        lambda *a, **kw: pytest.fail("SAFE T0 cannot spawn"))
    def fake_worker(self, plan, *, cancelled=None, **kw):
        calls.append(plan)
        return {"status": "exited", "executed": True, "exit_code": 0}
    monkeypatch.setattr(LbeWorker, "run", fake_worker)
    service = make()
    try:
        preview = service.invoke_exec(
            "a", row.cwd, list(row.requested_argv), dry_run=True)
        assert preview["status"] == "preview" and not preview["executed"]
        observed = service.invoke_exec(
            "a", row.cwd, list(row.requested_argv), dry_run=False)
        assert observed["status"] == "exited"
        assert len(calls) == 1
        assert calls[0].effective_argv == row.effective_argv
        assert output.read_bytes() == b"existing go output"
    finally:
        service.close()


def test_native_receipt_requires_finished_reader_not_only_eof():
    from tools.mvp_six_native_t1 import _check_result
    result = {
        "status": "exited", "executed": True, "exit_code": 0,
        "stdout": "ok", "stderr": "", "workspace": "a",
        "timed_out": False, "output_complete": True,
        "pipe_reader_failed": False, "pipe_reader_finished": True,
        "stdout_truncated": False, "stderr_truncated": False,
        "cleanup_proven": False,
        "full_descendant_tree_clean": "not_proven",
        "process_may_be_running": True,
    }
    owner = {"unavailable": False, "closing": False}
    _check_result(result, command_id="last", mode="MCP",
                  owner_health=owner)
    with pytest.raises(AssertionError):
        _check_result({**result, "pipe_reader_finished": False},
                      command_id="last", mode="MCP", owner_health=owner)
