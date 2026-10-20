"""C/T07: authorized Git and synchronous WorkspaceService worker lifetime."""
from __future__ import annotations

import json
import os
import subprocess
import threading
import time

import pytest

from gateway.core import GatewayError
from gateway.private_fs import PrivateFileError
from gateway.workspaces import ActiveRuntimeInventory, WorkspaceService
from gateway.workspaces_config import parse_workspace_config


def git(cwd, *argv):
    return subprocess.run(["git", *argv], cwd=cwd, check=True,
                          capture_output=True, text=True).stdout.strip()


def fixture(tmp_path, *, enabled=True):
    repo = tmp_path / "project"
    repo.mkdir()
    a, b = repo / "a", repo / "b"
    a.mkdir()
    b.mkdir()
    config = tmp_path / "config"
    config.mkdir(mode=0o700)
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    git(repo, "init", "-q")
    git(repo, "config", "user.name", "Fixture")
    git(repo, "config", "user.email", "fixture@example.invalid")
    (a / "data.txt").write_text("initial\n")
    git(repo, "add", "a/data.txt")
    git(repo, "commit", "-qm", "initial")
    git(repo, "branch", "-M", "main")
    config_data = {
        "schema_version": 1,
        "server": {"git": {"enabled": enabled}},
        "workspaces": {
            "a": {"root": str(a), "git": {"allowed_commands": ["status"] if enabled else []}},
            "b": {"root": str(b), "git": {"allowed_commands": ["status", "pull"] if enabled else []}},
        },
    }
    settings = parse_workspace_config(config_data)
    return (repo, a, b, config, settings,
            ActiveRuntimeInventory(paths=(runtime,)))


def test_git_pull_can_change_parent_repo_outside_granted_workspace(tmp_path):
    repo, a, b, config, settings, inventory = fixture(tmp_path)
    remote = tmp_path / "remote.git"
    git(tmp_path, "init", "--bare", "-q", str(remote))
    git(repo, "remote", "add", "origin", str(remote))
    git(repo, "push", "-q", "origin", "main")
    git(remote, "symbolic-ref", "HEAD", "refs/heads/main")
    writer = tmp_path / "writer"
    git(tmp_path, "clone", "-q", str(remote), str(writer))
    git(writer, "config", "user.name", "Fixture")
    git(writer, "config", "user.email", "fixture@example.invalid")
    (writer / "a" / "data.txt").write_text("remote update\n")
    git(writer, "commit", "-qam", "update")
    git(writer, "push", "-q", "origin", "main")
    service = WorkspaceService(settings, config_dir=config, inventory=inventory)
    try:
        assert service.any_git
        info = service.info()
        assert info["git_policy"]["enabled"] is True
        assert info["git_policy"]["adapter_exposed"] is False
        assert str(repo) not in json.dumps(info)
        assert str(config) not in json.dumps(info)
        assert info["read_only"] is True
        assert service.list_workspaces()["workspaces"][0]["git"]["allowed_commands"] == ["status"]
        preview = service.invoke_git("b", "pull", options={"remote": "origin", "branch": "main"})
        assert preview["dry_run"] is True and preview["execute_started"] is False
        assert (a / "data.txt").read_text() == "initial\n"
        for denied in ("pull", "push", "branch"):
            with pytest.raises(GatewayError) as exc:
                service.invoke_git("a", denied, dry_run=False)
            assert exc.value.code == "git_command_not_allowed"
        assert service.invoke_git("a", "status", dry_run=False)["exit_code"] == 0
        pulled = service.invoke_git(
            "b", "pull", options={"remote": "origin", "branch": "main"},
            dry_run=False, timeout_seconds=30,
        )
        assert pulled["exit_code"] == 0, pulled.get("stderr")
        assert (a / "data.txt").read_text() == "remote update\n"
        with pytest.raises(GatewayError):
            service.invoke("a", "run_command", ".", ["git", "status"])
    finally:
        service.close()


def test_disabled_git_and_file_policy_stay_independent(tmp_path):
    _, _, _, config, settings, inventory = fixture(tmp_path, enabled=False)
    service = WorkspaceService(settings, config_dir=config, inventory=inventory)
    try:
        assert not service.any_git
        assert service.info()["git_policy"]["enabled"] is False
        assert service.invoke("a", "list_files", ".")["workspace"] == "a"
        with pytest.raises(GatewayError) as exc:
            service.invoke_git("a", "status", dry_run=False)
        assert exc.value.code == "git_disabled"
        with pytest.raises(GatewayError):
            service.invoke("b", "run_git")
        assert not (config / "git-state").exists()
    finally:
        service.close()


def test_git_init_fault_disables_only_git_not_file_access(tmp_path, monkeypatch):
    import gateway.workspaces as mod
    _, _, _, config, settings, inventory = fixture(tmp_path)
    def inaccessible(*args, **kwargs):
        raise PrivateFileError("injected private state problem")
    monkeypatch.setattr(mod, "GitStateStore", inaccessible)
    service = WorkspaceService(settings, config_dir=config, inventory=inventory)
    try:
        assert service.info()["git_policy"]["enabled"] is True
        assert service.info()["git_policy"]["available"] is False
        assert not service.any_git
        assert service.invoke("b", "list_files", ".")["workspace"] == "b"
        with pytest.raises(GatewayError) as exc:
            service.invoke_git("b", "pull")
        assert exc.value.code == "git_unavailable"
    finally:
        service.close()


def test_real_git_worker_lease_prevents_fd_close_and_new_admission(tmp_path, monkeypatch):
    _, a, _, config, settings, inventory = fixture(tmp_path)
    service = WorkspaceService(settings, config_dir=config, inventory=inventory)
    entered, release, close_done = threading.Event(), threading.Event(), threading.Event()
    errors = []
    fd = service.get("a").gateway._root_fd

    def blocking_run(**args):
        assert os.fstat(args["root_fd"]).st_ino == os.stat(a).st_ino
        entered.set()
        assert release.wait(timeout=8)
        assert os.fstat(fd).st_ino == os.stat(a).st_ino
        return {"exit_code": 0}

    monkeypatch.setattr(service._git_executor, "run", blocking_run)

    def worker():
        try:
            assert service.invoke_git("a", "status", dry_run=False)["exit_code"] == 0
        except BaseException as exc:
            errors.append(exc)

    t1 = threading.Thread(target=worker, name="sync-Git-worker")
    t2 = threading.Thread(target=lambda: (service.close(), close_done.set()),
                          name="close-server")
    try:
        t1.start()
        assert entered.wait(timeout=5)
        t2.start()
        until = time.monotonic() + 5
        while not service._closing and time.monotonic() < until:
            time.sleep(0.01)
        assert service._closing
        assert not close_done.is_set()
        assert os.fstat(fd).st_ino == os.stat(a).st_ino
        with pytest.raises(GatewayError) as err:
            service.invoke_git("b", "status")
        assert err.value.code == "service_closing"
    finally:
        release.set()
        t1.join(timeout=8)
        t2.join(timeout=8)
        service.close()
    assert not t1.is_alive() and not t2.is_alive()
    assert not errors and close_done.is_set()
    with pytest.raises(OSError):
        os.fstat(fd)


def test_blocking_git_does_not_hold_file_service_lifecycle_mutex(tmp_path, monkeypatch):
    _, _, _, config, settings, inventory = fixture(tmp_path)
    service = WorkspaceService(settings, config_dir=config, inventory=inventory)
    entered, release = threading.Event(), threading.Event()
    errors = []
    def fake_run(**kwargs):
        entered.set()
        if not release.wait(timeout=8):
            raise RuntimeError("timeout in test worker")
        return {"exit_code": 0}
    monkeypatch.setattr(service._git_executor, "run", fake_run)
    def git_worker():
        try:
            assert service.invoke_git("a", "status", dry_run=False)["exit_code"] == 0
        except BaseException as exc:
            errors.append(exc)
    t = threading.Thread(target=git_worker)
    try:
        t.start()
        assert entered.wait(timeout=5)
        assert service.invoke("b", "list_files", ".")["workspace"] == "b"
    finally:
        release.set()
        t.join(timeout=8)
        service.close()
    assert not t.is_alive()
    assert not errors
