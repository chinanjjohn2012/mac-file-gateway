"""Approved Git V1 storage fault model: no untracked living Git child.

This file deliberately separates known-complete process cleanup from uncertain
cleanup. The one case in which quarantine is not sticky across restart is
fully cleaned execution + unlink succeeded + dir fsync failed + global marker
also cannot be written. All other surviving markers still quarantine.
"""
from __future__ import annotations

import os
from pathlib import Path
import subprocess

import pytest

from gateway.core import GatewayError
from gateway.git_cli import GitCLIExecutor
from gateway.git_state import GitStateStore


def _block_global_record(monkeypatch, state: GitStateStore) -> None:
    old = state._atomic_write

    def persist(name, record):
        if name == "global.json":
            raise OSError("injected global marker cannot be written")
        return old(name, record)

    monkeypatch.setattr(state, "_atomic_write", persist)


def _persisted_discovery_before_spawn(state_path: Path, spawned: list[str]):
    """This callback represents the Popen boundary, not cleanup evidence."""
    entries = list(state_path.glob("d-*.json"))
    assert len(entries) == 1
    assert '"kind":"DISCOVERING"' in entries[0].read_text()
    spawned.append("protected")
    return object()


def test_fully_clean_repo_unlink_dir_sync_failure_and_missing_global_marker(
    tmp_path, monkeypatch,
):
    """No orphan exists; current instance closes, restart needs new durable intent."""
    path = tmp_path / "state"
    state = GitStateStore(path)
    key = (177, 218)
    call = state.new_call_id()
    observed_dir_sync = []
    try:
        state.begin_repo(key, call)
        state.start_repo_process(key, call, lambda: "already fully reaped and drained")
        original_sync = os.fsync

        def fail_directory_sync(fd):
            if fd == state._fd:
                observed_dir_sync.append(fd)
                raise OSError("injected directory fsync after unlink")
            return original_sync(fd)

        with monkeypatch.context() as faults:
            faults.setattr(os, "fsync", fail_directory_sync)
            _block_global_record(faults, state)
            with pytest.raises(GatewayError) as exc:
                state.finish_repo(key, call, clean=True)
            assert exc.value.code == "git_state_unavailable"
        assert observed_dir_sync, "must reach the real directory sync after unlink"
        assert not list(path.iterdir()), "unlink happened; no sticky marker was committed"
        assert state.globally_quarantined
        assert state.is_repo_quarantined(key)
        denied = []
        with pytest.raises(GatewayError) as exc:
            state.start_discovery(state.new_call_id(), "a",
                                  lambda: denied.append("must not launch"))
        assert exc.value.code == "git_global_quarantined"
        assert denied == []
    finally:
        state.close()

    # Fault model: deletion did persist; no previous Git child remains.
    # Restart can allow only a *new*, fully persisted discovery intent.
    reopened = GitStateStore(path)
    try:
        assert not reopened.globally_quarantined
        assert not reopened.is_repo_quarantined(key)
        spawned: list[str] = []
        next_call = reopened.new_call_id()
        reopened.start_discovery(
            next_call, "a",
            lambda: _persisted_discovery_before_spawn(path, spawned),
        )
        assert spawned == ["protected"]
        reopened.finish_discovery(next_call, clean=True)
        assert not list(path.iterdir())

        # A new storage failure cannot be bypassed merely because no stale
        # marker survived the *previous, fully cleaned* operation.
        def fail_new_intent(name, record):
            if name.startswith("d-"):
                raise OSError("cannot persist new intent")
            return old_write(name, record)

        old_write = reopened._atomic_write
        with monkeypatch.context() as fault:
            fault.setattr(reopened, "_atomic_write", fail_new_intent)
            with pytest.raises(GatewayError) as exc:
                reopened.start_discovery(
                    reopened.new_call_id(), "a",
                    lambda: spawned.append("forbidden unrecorded Git"),
                )
        assert exc.value.code == "git_state_unavailable"
        assert spawned == ["protected"]
        assert reopened.globally_quarantined
    finally:
        reopened.close()


def test_fully_clean_discovery_post_unlink_failure_is_only_instance_sticky(
    tmp_path, monkeypatch,
):
    path = tmp_path / "state"
    store = GitStateStore(path)
    call = store.new_call_id()
    seen = []
    try:
        store.start_discovery(call, "a", lambda: seen.append("already fully cleaned"))
        old_sync = os.fsync
        with monkeypatch.context() as fault:
            fault.setattr(
                os, "fsync",
                lambda fd: (_ for _ in ()).throw(OSError("dir fsync fails"))
                if fd == store._fd else old_sync(fd),
            )
            _block_global_record(fault, store)
            with pytest.raises(GatewayError) as exc:
                store.finish_discovery(call, clean=True)
        assert exc.value.code == "git_state_unavailable"
        assert seen == ["already fully cleaned"]
        assert store.globally_quarantined
        assert not list(path.iterdir())
    finally:
        store.close()
    reopened = GitStateStore(path)
    try:
        assert not reopened.globally_quarantined
    finally:
        reopened.close()


def test_deletion_failed_before_unlink_stale_running_blocks_restart(
    tmp_path, monkeypatch,
):
    path = tmp_path / "state"
    store = GitStateStore(path)
    key = (33, 44)
    call = store.new_call_id()
    try:
        store.begin_repo(key, call)
        old_unlink = os.unlink

        def cannot_unlink(name, *, dir_fd=None):
            if name.startswith("r-") and dir_fd == store._fd:
                raise OSError("unlink rejected")
            return old_unlink(name, dir_fd=dir_fd)

        with monkeypatch.context() as fault:
            fault.setattr(os, "unlink", cannot_unlink)
            _block_global_record(fault, store)
            with pytest.raises(GatewayError) as exc:
                store.finish_repo(key, call, clean=True)
        assert exc.value.code == "git_state_unavailable"
        assert store.globally_quarantined
        assert len(list(path.glob("r-*.json"))) == 1
    finally:
        store.close()

    restarted = GitStateStore(path)
    try:
        assert restarted.is_repo_quarantined(key)
        assert not restarted.globally_quarantined
        with pytest.raises(GatewayError) as exc:
            restarted.begin_repo(key, restarted.new_call_id())
        assert exc.value.code == "git_repository_quarantined"
    finally:
        restarted.close()


def test_unknown_repo_cleanup_never_unlinks_original_when_markers_fail(
    tmp_path, monkeypatch,
):
    path = tmp_path / "state"
    store = GitStateStore(path)
    key = (65, 66)
    call = store.new_call_id()
    try:
        store.begin_repo(key, call)
        store.start_repo_process(key, call, lambda: "possibly still running")
        old = store._atomic_write
        with monkeypatch.context() as faults:
            def reject_extra_markers(name, record):
                if name.startswith("r-") or name == "global.json":
                    raise OSError("quarantine cannot be written")
                return old(name, record)
            faults.setattr(store, "_atomic_write", reject_extra_markers)
            with pytest.raises(GatewayError) as exc:
                store.finish_repo(key, call, clean=False)
        assert exc.value.code == "git_cleanup_incomplete"
        rows = list(path.glob("r-*.json"))
        assert len(rows) == 1 and '"kind":"RUNNING"' in rows[0].read_text()
        assert store.globally_quarantined
        assert store.is_repo_quarantined(key)
    finally:
        store.close()

    restarted = GitStateStore(path)
    try:
        assert not restarted.globally_quarantined
        assert restarted.is_repo_quarantined(key)
    finally:
        restarted.close()


def test_unknown_discovery_keeps_original_when_global_marker_write_fails(
    tmp_path, monkeypatch,
):
    path = tmp_path / "state"
    store = GitStateStore(path)
    call = store.new_call_id()
    try:
        store.start_discovery(call, "a", lambda: "possibly still running")
        with monkeypatch.context() as fault:
            _block_global_record(fault, store)
            with pytest.raises(GatewayError) as exc:
                store.finish_discovery(call, clean=False)
        assert exc.value.code == "git_cleanup_incomplete"
        assert len(list(path.glob("d-*.json"))) == 1
        assert store.globally_quarantined
    finally:
        store.close()

    restarted = GitStateStore(path)
    try:
        assert restarted.globally_quarantined
        launches = []
        with pytest.raises(GatewayError):
            restarted.start_discovery(
                restarted.new_call_id(), "b", lambda: launches.append("not admitted"),
            )
        assert not launches
    finally:
        restarted.close()


def test_real_git_cleanup_is_proven_before_post_unlink_storage_failure(
    tmp_path, monkeypatch,
):
    """Uses a real temporary Git repo, not a simulated cleanup=True caller."""
    root = tmp_path / "repo"
    root.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    ws = root / "workspace"
    ws.mkdir()
    state_path = tmp_path / "state"
    store = GitStateStore(state_path, workspace_roots=(str(ws),))
    engine = GitCLIExecutor(store)
    fd = os.open(ws, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    actual_delete = store._delete
    actual_sync = os.fsync
    reached_final_delete = []
    try:
        def fail_only_repository_delete(name):
            if not name.startswith("r-"):
                return actual_delete(name)
            # First discovery has already completed. The actual controlled
            # business Git process has returned cleanup_complete=True.
            reached_final_delete.append(True)
            with monkeypatch.context() as fault:
                fault.setattr(
                    os, "fsync",
                    lambda which: (_ for _ in ()).throw(OSError("repo dir fsync fail"))
                    if which == store._fd else actual_sync(which),
                )
                return actual_delete(name)

        with monkeypatch.context() as faults:
            faults.setattr(store, "_delete", fail_only_repository_delete)
            _block_global_record(faults, store)
            with pytest.raises(GatewayError) as exc:
                engine.run(
                    workspace="workspace", root_fd=fd, root_path=str(ws),
                    command="status", timeout_seconds=30, dry_run=False,
                )
            assert exc.value.code == "git_state_unavailable"
            assert reached_final_delete == [True]
            assert not list(state_path.iterdir())
            assert store.globally_quarantined
            with pytest.raises(GatewayError) as second:
                engine.run(
                    workspace="workspace", root_fd=fd, root_path=str(ws),
                    command="status", timeout_seconds=30, dry_run=False,
                )
            assert second.value.code == "git_global_quarantined"
    finally:
        os.close(fd)
        store.close()

    fresh = GitStateStore(state_path, workspace_roots=(str(ws),))
    new_fd = os.open(ws, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        # Without an old orphan and with healthy persistence restored,
        # the new run gets its own DISCOVERING and RUNNING records.
        outcome = GitCLIExecutor(fresh).run(
            workspace="workspace", root_fd=new_fd, root_path=str(ws),
            command="status", timeout_seconds=30, dry_run=False,
        )
        assert outcome["exit_code"] == 0
        assert outcome["cleanup_status"] == "complete"
        assert not list(state_path.iterdir())
    finally:
        os.close(new_fd)
        fresh.close()
