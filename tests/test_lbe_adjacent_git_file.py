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


def test_v2_same_instance_real_git_and_file_write_after_proof_denial_and_unknown(
    tmp_path: Path, monkeypatch,
):
    """D0 §0.1: one actual service keeps legitimate Git/File after both denials.

    Both Git status invocations use REAL Git only inside this disposable repo.
    The Exec interception windows cannot launch a child or emit an OS signal.
    The UNKNOWN marker is deliberately created only in the test-private state
    and must remain byte-for-byte unchanged after Git and File success.
    """
    import os

    project = tmp_path / "projects"
    project.mkdir()
    a, b = project / "a", project / "b"
    (a / "src").mkdir(parents=True)
    b.mkdir()
    (a / "src" / "ok.py").write_text("print('NO EXEC')\n")
    (a / "src" / "safe.txt").write_text("FIRST\n")
    subprocess.run(
        ["git", "init", "-q"], cwd=a, check=True,
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    seed = ExecStateStore(private / "exec-state",
                          workspace_roots=(str(a), str(b)))
    assert seed.durability_state == "healthy"
    seed.close()

    cfg = parse_workspace_config({
        "schema_version": 2,
        "server": {"port": 8765, "transport": "http",
                   "git": {"enabled": True}},
        "workspaces": {
            "a": {
                "root": str(a),
                "exec": {"paths": ["src"], "runners": []},
                "write": {"enabled": True, "paths": ["src"]},
                "git": {"allowed_commands": ["status"]},
            },
            "b": {"root": str(b)},
        },
    })
    svc = WorkspaceService(
        cfg, config_dir=private,
        inventory=ActiveRuntimeInventory(paths=(runtime,)),
    )

    def unexpected_exec(*_args, **_kwargs):
        raise AssertionError("schema-v2 Exec denial attempted Popen/OS signal")

    try:
        assert svc.any_exec and svc.any_git and svc.any_write
        assert svc._exec_state is not None
        assert svc._exec_state.durability_state == "healthy"
        assert svc.info()["exec_policy"]["available"] is False
        assert svc.invoke_exec(
            "a", "src", ["python", "ok.py"],
            timeout_seconds=5, dry_run=True)["status"] == "preview"

        original_records = {
            p.name: p.read_bytes()
            for p in (private / "exec-state").glob("r-*.json")
        }
        assert original_records == {}
        with monkeypatch.context() as patch:
            patch.setattr(subprocess.Popen, "__init__", unexpected_exec)
            patch.setattr(os, "kill", unexpected_exec)
            patch.setattr(os, "killpg", unexpected_exec, raising=False)
            with pytest.raises(GatewayError) as denied:
                svc.invoke_exec(
                    "a", "src", ["python", "ok.py"],
                    timeout_seconds=5, dry_run=False)
            assert denied.value.code == "exec_cleanup_proof_required"
            assert svc._lbe_owner.snapshot()["reserved_slots"] == 0
        assert list((private / "exec-state").glob("r-*.json")) == []

        # Real authorized Git subprocess AFTER the attempted Exec denial,
        # in the same Workspace and WorkspaceService instance.
        git_healthy = svc.invoke_git(
            "a", "status", dry_run=False, timeout_seconds=30)
        assert git_healthy["exit_code"] == 0
        assert git_healthy["execute_started"] is True
        assert git_healthy["repository_checked"] is True
        original = svc.invoke("a", "read_file", "src/safe.txt")
        assert "FIRST" in original["content"]
        svc.invoke("a", "write_file", "src/safe.txt", "SECOND\n",
                   original["file_sha256"], dry_run=False)
        assert (a / "src" / "safe.txt").read_text() == "SECOND\n"

        # Deliberately seed a persisted UNKNOWN through the actual original
        # state store. This is NOT a real Exec attempt and MUST NOT be cleared.
        stat_root = a.stat()
        store = svc._exec_state
        attempt = store.prepare("a", (stat_root.st_dev, stat_root.st_ino))
        store.mark_unknown(attempt)
        marker = private / "exec-state" / ("r-" + attempt + ".json")
        original_unknown = marker.read_bytes()
        assert store.durability_state == "quarantined"
        assert svc.info()["exec_policy"]["quarantined"] is True
        with monkeypatch.context() as patch:
            patch.setattr(subprocess.Popen, "__init__", unexpected_exec)
            patch.setattr(os, "kill", unexpected_exec)
            patch.setattr(os, "killpg", unexpected_exec, raising=False)
            with pytest.raises(GatewayError) as denied:
                svc.invoke_exec(
                    "a", "src", ["python", "ok.py"],
                    timeout_seconds=5, dry_run=False)
            assert denied.value.code == "exec_quarantined"

        git_unknown = svc.invoke_git(
            "a", "status", dry_run=False, timeout_seconds=30)
        assert git_unknown["exit_code"] == 0
        assert git_unknown["execute_started"] is True
        assert git_unknown["repository_checked"] is True
        before = svc.invoke("a", "read_file", "src/safe.txt")
        svc.invoke("a", "write_file", "src/safe.txt", "THIRD\n",
                   before["file_sha256"], dry_run=False)
        assert (a / "src" / "safe.txt").read_text() == "THIRD\n"
        assert marker.read_bytes() == original_unknown
        assert store.durability_state == "quarantined"
        assert svc._lbe_owner.snapshot()["reserved_slots"] == 0

        with pytest.raises(GatewayError) as denied_git:
            svc.invoke_git("b", "status", dry_run=False)
        assert denied_git.value.code == "git_command_not_allowed"
        with pytest.raises(GatewayError) as denied_write:
            svc.invoke("b", "create_file", "not-allowed.txt", "NO", False)
        assert denied_write.value.code == "write_disabled"
        with pytest.raises(GatewayError) as denied_exec:
            svc.invoke_exec("b", ".", ["python", "ok.py"], dry_run=False)
        assert denied_exec.value.code == "exec_disabled"
        assert not (b / "not-allowed.txt").exists()
        assert marker.read_bytes() == original_unknown
    finally:
        svc.close()
