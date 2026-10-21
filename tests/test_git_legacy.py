"""C/T08: Legacy Git is separate from File and controlled Exec authorization."""
from __future__ import annotations

import json
import os
import subprocess
import threading
import time

import pytest

from gateway.core import Gateway, GatewayError


def prepared(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    state_parent = tmp_path / "private"
    state_parent.mkdir(mode=0o700)
    return root, state_parent / "git-state"


def test_legacy_git_defaults_off_and_does_not_inherit_exec_or_write(tmp_path):
    root, state_dir = prepared(tmp_path)
    gateway = Gateway(root)
    try:
        assert gateway.info()["git_policy"]["enabled"] is False
        assert gateway.info()["git_policy"]["allowed_commands"] == []
        assert gateway.info()["exec_policy"]["enabled"] is False
        assert gateway.info()["read_only"] is True
        assert gateway.list_files()["path"] == "."
        with pytest.raises(GatewayError) as exc:
            gateway.invoke_git("status", dry_run=False)
        assert exc.value.code == "git_disabled"
        assert not state_dir.exists()
    finally:
        gateway.close()


@pytest.mark.parametrize("enabled,grants", [
    (True, ()),
    (False, ("status",)),
    (True, ("status", "status")),
    (True, ("rm",)),
    (True, ("status", 123)),
])
def test_invalid_direct_legacy_grants_fail_before_git_start(tmp_path, enabled, grants):
    root, state_dir = prepared(tmp_path)
    with pytest.raises(GatewayError):
        Gateway(root, allow_git=enabled, git_allowed_commands=grants,
                git_state_dir=state_dir)
    assert not state_dir.exists()


def test_legacy_real_status_and_blocked_command_have_independent_grants(tmp_path):
    root, state_dir = prepared(tmp_path)
    gateway = Gateway(
        root, allow_git=True, git_allowed_commands=("status",),
        git_state_dir=state_dir,
    )
    try:
        meta = gateway.info()
        assert meta["git_policy"]["enabled"] is True
        assert meta["git_policy"]["available"] is True
        assert meta["git_policy"]["adapter_exposed"] is False
        assert meta["exec_policy"]["enabled"] is False
        assert meta["read_only"] is True
        assert str(root) not in json.dumps(meta)
        assert str(state_dir) not in json.dumps(meta)
        preview = gateway.invoke_git("status")
        assert preview["execute_started"] is False
        actual = gateway.invoke_git("status", dry_run=False)
        assert actual["exit_code"] == 0
        assert actual["cleanup_status"] == "complete"
        with pytest.raises(GatewayError) as exc:
            gateway.invoke_git("push", dry_run=False)
        assert exc.value.code == "git_command_not_allowed"
        assert not list(state_dir.iterdir())
    finally:
        gateway.close()
        gateway.close()


def test_legacy_close_waits_for_real_sync_worker_before_root_fd_close(
    tmp_path, monkeypatch,
):
    root, state_dir = prepared(tmp_path)
    gateway = Gateway(
        root, allow_git=True, git_allowed_commands=("status",),
        git_state_dir=state_dir,
    )
    entered, release, finished = threading.Event(), threading.Event(), threading.Event()
    errors = []
    fd = gateway._root_fd

    def blocked(**kwargs):
        assert kwargs["root_fd"] == fd
        entered.set()
        assert release.wait(timeout=8)
        assert os.fstat(fd).st_ino == root.stat().st_ino
        return {"exit_code": 0}

    monkeypatch.setattr(gateway._git_executor, "run", blocked)
    def job():
        try:
            assert gateway.invoke_git("status", dry_run=False)["exit_code"] == 0
        except BaseException as exc:
            errors.append(exc)

    worker = threading.Thread(target=job, name="legacy-Git-worker")
    closer = threading.Thread(target=lambda: (gateway.close(), finished.set()),
                              name="legacy-close")
    try:
        worker.start()
        assert entered.wait(timeout=5)
        closer.start()
        until = time.monotonic() + 5
        while not gateway._git_closing and time.monotonic() < until:
            time.sleep(0.01)
        assert gateway._git_closing
        assert not finished.is_set()
        assert os.fstat(fd).st_ino == root.stat().st_ino
        with pytest.raises(GatewayError) as exc:
            gateway.invoke_git("status")
        assert exc.value.code == "service_closing"
    finally:
        release.set()
        worker.join(timeout=8)
        closer.join(timeout=8)
        gateway.close()
    assert not worker.is_alive() and not closer.is_alive()
    assert not errors and finished.is_set()
    with pytest.raises(OSError):
        os.fstat(fd)


def test_legacy_git_stale_activity_record_blocks_apply_after_restart(tmp_path):
    root, state_dir = prepared(tmp_path)
    gateway = Gateway(
        root, allow_git=True, git_allowed_commands=("status",),
        git_state_dir=state_dir,
    )
    gateway._git_state.start_discovery(
        gateway._git_state.new_call_id(), "legacy", lambda: "unreaped simulated child",
    )
    gateway.close()
    reopened = Gateway(
        root, allow_git=True, git_allowed_commands=("status",),
        git_state_dir=state_dir,
    )
    try:
        assert reopened.info()["git_policy"]["available"] is False
        with pytest.raises(GatewayError) as exc:
            reopened.invoke_git("status", dry_run=False)
        assert exc.value.code == "git_global_quarantined"
    finally:
        reopened.close()
