"""T05 persistent intent, global/repository quarantine and offline recovery."""
from __future__ import annotations

import os
import stat
import threading
import time

import pytest

from gateway.core import GatewayError
from gateway.git_repository import GitRepositoryCoordinator
from gateway.git_state import GitStateStore
from gateway.private_fs import PrivateFileError


def test_discovery_intent_precedes_spawn_and_is_removed_after_cleanup(tmp_path):
    state = GitStateStore(tmp_path / "private-git-state")
    call = state.new_call_id()
    try:
        events = []
        def spawn():
            records = list((tmp_path / "private-git-state").glob("d-*.json"))
            assert len(records) == 1 and call in records[0].name
            events.append("started")
            return "process"
        assert state.start_discovery(call, "a", spawn) == "process"
        assert events == ["started"]
        assert not state.globally_quarantined
        state.finish_discovery(call, clean=True)
        assert not list((tmp_path / "private-git-state").iterdir())
    finally:
        state.close()


@pytest.mark.parametrize("failure", [
    "write", "file_fsync", "rename", "directory_fsync",
])
def test_discovery_durable_intent_failure_never_launches(tmp_path, monkeypatch, failure):
    """Each genuine durability syscall fails independently BEFORE any Popen."""
    state = GitStateStore(tmp_path / "state")
    launched = []
    faults = []
    try:
        with monkeypatch.context() as m:
            if failure == "write":
                orig = os.write

                def fail_write(fd, payload):
                    if stat.S_ISREG(os.fstat(fd).st_mode):
                        faults.append("write")
                        raise OSError("injected actual file write failure")
                    return orig(fd, payload)

                m.setattr(os, "write", fail_write)
            elif failure in ("file_fsync", "directory_fsync"):
                orig = os.fsync
                expected_dir = failure == "directory_fsync"

                def fail_fsync(fd):
                    is_dir = stat.S_ISDIR(os.fstat(fd).st_mode)
                    if is_dir == expected_dir:
                        faults.append(failure)
                        raise OSError("injected targeted fsync failure")
                    return orig(fd)

                m.setattr(os, "fsync", fail_fsync)
            else:
                orig = os.rename

                def fail_rename(*args, **kwargs):
                    faults.append("rename")
                    raise OSError("injected atomic rename failure")

                m.setattr(os, "rename", fail_rename)

            with pytest.raises(GatewayError) as exc:
                state.start_discovery(
                    state.new_call_id(), "a",
                    lambda: launched.append("forbidden Popen"),
                )
        assert exc.value.code == "git_state_unavailable"
        assert faults, "the intended syscall must actually be reached"
        assert not launched
        assert state.globally_quarantined
    finally:
        state.close()


def test_stale_discovery_blocks_on_restart_until_offline_recovery(tmp_path):
    path = tmp_path / "state"
    state = GitStateStore(path)
    call = state.new_call_id()
    state.start_discovery(call, "a", lambda: "simulated running process")
    state.close()  # Simulates process disappearance before any finally/cleanup.
    restarted = GitStateStore(path)
    try:
        assert restarted.globally_quarantined
        with pytest.raises(GatewayError) as exc:
            restarted.start_discovery(restarted.new_call_id(), "b", lambda: "should not run")
        assert exc.value.code == "git_global_quarantined"
    finally:
        restarted.close()
    # Only an offline administrator with independent process-exit evidence can
    # remove the stale marker. This fixture simulates that offline action.
    for marker in path.iterdir():
        marker.unlink()
    restored = GitStateStore(path)
    try:
        assert not restored.globally_quarantined
        call = restored.new_call_id()
        restored.start_discovery(call, "a", lambda: "okay")
        restored.finish_discovery(call, clean=True)
    finally:
        restored.close()


def test_repo_running_marker_quarantines_restart_but_not_unrelated_repo(tmp_path):
    path = tmp_path / "state"
    state = GitStateStore(path)
    call = state.new_call_id()
    key = (10, 20)
    state.begin_repo(key, call)
    state.close()
    restarted = GitStateStore(path)
    try:
        assert restarted.is_repo_quarantined(key)
        assert not restarted.globally_quarantined
        assert not restarted.is_repo_quarantined((30, 40))
        with pytest.raises(GatewayError) as exc:
            restarted.begin_repo(key, restarted.new_call_id())
        assert exc.value.code == "git_repository_quarantined"
    finally:
        restarted.close()


def test_normal_success_and_failure_release_repository_state(tmp_path):
    path = tmp_path / "state"
    state = GitStateStore(path)
    key = (42, 55)
    try:
        for _ in range(2):
            call = state.new_call_id()
            state.begin_repo(key, call)
            assert state.start_repo_process(key, call, lambda: "process") == "process"
            state.finish_repo(key, call, clean=True)
            assert not state.is_repo_quarantined(key)
        assert not list(path.iterdir())
    finally:
        state.close()


def test_uncertain_cleanup_quarantines_before_other_workspace_acquires_lock(tmp_path):
    state = GitStateStore(tmp_path / "state")
    coord = GitRepositoryCoordinator()
    key = (13, 24)
    results = []
    try:
        with coord.hold(key, time.monotonic() + 20):
            call = state.new_call_id()
            state.begin_repo(key, call)
            entered = threading.Event()
            def second_workspace():
                entered.set()
                with coord.hold(key, time.monotonic() + 20):
                    try:
                        state.begin_repo(key, state.new_call_id())
                    except GatewayError as exc:
                        results.append(exc.code)
            t = threading.Thread(target=second_workspace)
            t.start()
            assert entered.wait(2)
            with pytest.raises(GatewayError) as exc:
                state.finish_repo(key, call, clean=False)
            assert exc.value.code == "git_cleanup_incomplete"
        t.join(timeout=3)
        assert not t.is_alive()
        assert results == ["git_repository_quarantined"]
        assert state.is_repo_quarantined(key)
        assert not state.is_repo_quarantined((1, 2))
    finally:
        state.close()


def test_state_store_rejects_workspace_overlap_and_symlink_leaf(tmp_path):
    root = tmp_path / "ws"
    root.mkdir()
    with pytest.raises(PrivateFileError):
        GitStateStore(root / "git-state", workspace_roots=(str(root),))
    directory = tmp_path / "real-state"
    directory.mkdir()
    alias = tmp_path / "alias-state"
    alias.symlink_to(directory, target_is_directory=True)
    with pytest.raises(PrivateFileError):
        GitStateStore(alias, workspace_roots=(str(root),))


def test_unsafe_record_and_orphan_temporary_file_fail_closed(tmp_path):
    path = tmp_path / "state"
    state = GitStateStore(path)
    state.close()
    (path / "temp-incomplete.tmp").write_text("partial")
    next_start = GitStateStore(path)
    try:
        assert next_start.globally_quarantined
    finally:
        next_start.close()


def test_concurrent_discovery_records_do_not_override_each_other(tmp_path):
    state = GitStateStore(tmp_path / "state")
    call1, call2 = state.new_call_id(), state.new_call_id()
    try:
        state.start_discovery(call1, "a", lambda: "child a")
        state.start_discovery(call2, "b", lambda: "child b")
        assert len(list((tmp_path / "state").glob("d-*.json"))) == 2
        state.finish_discovery(call1, clean=True)
        assert len(list((tmp_path / "state").glob("d-*.json"))) == 1
        state.finish_discovery(call2, clean=True)
        assert not state.globally_quarantined
    finally:
        state.close()


def test_concurrent_discovery_interleaving_and_global_quarantine_gate(tmp_path):
    """Real threads coexist; global quarantine blocks all later admissions."""
    state_dir = tmp_path / "state"
    state = GitStateStore(state_dir)
    calls = [state.new_call_id(), state.new_call_id()]
    ready = threading.Barrier(3)
    release = threading.Event()
    errors = []
    children = []

    def worker(call, workspace):
        try:
            state.start_discovery(call, workspace, lambda: children.append(workspace))
            ready.wait(timeout=5)
            assert release.wait(timeout=5)
            state.finish_discovery(call, clean=True)
        except BaseException as exc:
            errors.append(exc)

    threads = [
        threading.Thread(target=worker, args=(call, "ws-" + str(i)))
        for i, call in enumerate(calls)
    ]
    try:
        for t in threads:
            t.start()
        ready.wait(timeout=5)
        assert set(children) == {"ws-0", "ws-1"}
        assert len(list(state_dir.glob("d-*.json"))) == 2
        release.set()
        for t in threads:
            t.join(timeout=5)
        assert all(not t.is_alive() for t in threads)
        assert not errors
        assert not list(state_dir.iterdir())

        # An actual second admission following a global failure cannot spawn.
        state.start_discovery(calls[0], "a", lambda: "tracked first")
        with state._gate:  # Test-only fault injection at the global admission gate.
            state._quarantine_global()
        launched = []
        with pytest.raises(GatewayError) as exc:
            state.start_discovery(state.new_call_id(), "b",
                                  lambda: launched.append("not permitted"))
        assert exc.value.code == "git_global_quarantined"
        assert not launched
    finally:
        release.set()
        for t in threads:
            t.join(timeout=5)
        state.close()
