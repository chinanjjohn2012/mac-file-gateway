"""Disposable same-service v2 File/Git integration; Exec is preview-only.

This uses the existing Linux CI disposable Git CLI authorization: fixed
'git init' in a temporary repository and read-only Git status. It does not
spawn an LBE command, use a real Go/Pipenv process, send an unsafe signal,
or touch a user Mac, Tunnel or production resource.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from gateway.core import GatewayError
from gateway.exec_state import ExecStateStore
from gateway.workspaces import ActiveRuntimeInventory, WorkspaceService
from gateway.workspaces_config import parse_workspace_config


def test_v2_granted_git_file_and_exec_preview_in_same_disposable_service(
    tmp_path: Path,
):
    projects = tmp_path / "projects"
    projects.mkdir()
    a, b = projects / "a", projects / "b"
    a.mkdir()
    b.mkdir()
    (a / "python-project").mkdir()
    (a / "python-project" / "ok.py").write_text("print('PREVIEW_ONLY')\n")
    (b / "safe.txt").write_text("FILE_BEFORE\n")
    subprocess.run(["git", "init", "-q"], cwd=b, check=True, capture_output=True)

    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    private.chmod(0o700)
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    state = ExecStateStore(
        private / "exec-state", workspace_roots=(str(a), str(b)))
    assert state.durability_state == "healthy"
    state.close()

    settings = parse_workspace_config({
        "schema_version": 2,
        "server": {"port": 8765, "transport": "http",
                   "git": {"enabled": True}},
        "workspaces": {
            "a": {"root": str(a),
                  "exec": {"paths": ["python-project"], "runners": []}},
            "b": {"root": str(b),
                  "write": {"enabled": True, "paths": ["safe.txt"]},
                  "git": {"allowed_commands": ["status"]}},
        },
    })
    svc = WorkspaceService(
        settings, config_dir=private,
        inventory=ActiveRuntimeInventory(paths=(runtime,)))
    try:
        assert svc.any_git is True
        assert svc.any_exec is True

        before = svc.invoke("b", "read_file", "safe.txt")
        assert "FILE_BEFORE" in before["content"]
        svc.invoke(
            "b", "write_file", "safe.txt", "FILE_AFTER\n",
            before["file_sha256"], dry_run=False)
        after = svc.invoke("b", "read_file", "safe.txt")
        assert "FILE_AFTER" in after["content"]

        git = svc.invoke_git("b", "status", dry_run=False, timeout_seconds=30)
        assert git["exit_code"] == 0
        assert git["execute_started"] is True
        assert git["repository_checked"] is True
        assert git["cleanup_status"] == "complete"

        preview = svc.invoke_exec(
            "a", "python-project", ["python", "ok.py"],
            timeout_seconds=5, dry_run=True)
        assert preview["executed"] is False
        assert preview["status"] == "preview"
        assert preview["runner"] == "direct"

        with pytest.raises(GatewayError) as e:
            svc.invoke_exec("b", ".", ["python", "-m", "pytest"],
                            timeout_seconds=5, dry_run=False)
        assert e.value.code == "exec_disabled"
        with pytest.raises(GatewayError) as e:
            svc.invoke_git("a", "status", dry_run=False)
        assert e.value.code == "git_command_not_allowed"
        with pytest.raises(GatewayError) as e:
            svc.invoke("a", "write_file", "python-project/ok.py",
                       "FORBIDDEN", "0" * 64, dry_run=False)
        assert e.value.code == "write_disabled"
        assert svc.invoke("b", "read_file", "safe.txt")["file_sha256"] == (
            after["file_sha256"])
        assert svc._lbe_owner.snapshot()["reserved_slots"] == 0
    finally:
        svc.close()
