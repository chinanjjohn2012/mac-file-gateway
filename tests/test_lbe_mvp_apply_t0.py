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
        assert denied.value.code == "exec_cleanup_proof_required"
        assert not s.info()["exec_policy"]["apply_configured"]
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
        else:
            assert "PIPENV_PIPFILE" not in env
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
