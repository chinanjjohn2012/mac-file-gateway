"""R2-T01 durable Exec state primitives: physical RED -> GREEN contracts.

No Gateway service/Worker integration in T01; no Popen, fork, signal,
Tunnel, native code, or real command execution in this suite.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import stat

import pytest

from gateway.core import GatewayError
from gateway.exec_state import ExecStateStore


def _fresh(tmp_path):
    control = tmp_path / "private-control"
    control.mkdir(mode=0o700)
    workspace = tmp_path / "disposable-project"
    workspace.mkdir()
    path = control / "exec-state"
    return ExecStateStore(path, workspace_roots=(str(workspace),)), path


def _record(path, attempt):
    p = path / ("r-" + attempt + ".json")
    raw = p.read_bytes()
    obj = json.loads(raw)
    return p, raw, obj


def test_r2_t01_empty_private_state_is_healthy_and_pinned(tmp_path):
    store, path = _fresh(tmp_path)
    try:
        assert store.durability_state == "healthy"
        assert store.quarantine_reason_code is None
        assert stat.S_IMODE(path.stat().st_mode) == 0o700
        assert sorted(x.name for x in path.iterdir()) == ["owner.lock"]
        lock = path / "owner.lock"
        assert stat.S_ISREG(lock.stat().st_mode)
        assert lock.stat().st_nlink == 1
        assert stat.S_IMODE(lock.stat().st_mode) == 0o600
        store.require_healthy()
    finally:
        store.close()


def test_r2_t01_owner_lock_is_exclusive_for_full_lifetime(tmp_path):
    first, path = _fresh(tmp_path)
    try:
        second = ExecStateStore(path)
        try:
            assert second.durability_state == "unavailable"
            assert second.quarantine_reason_code == "owner_lock_unavailable"
            with pytest.raises(GatewayError) as exc:
                second.require_healthy()
            assert exc.value.code == "exec_state_unavailable"
        finally:
            second.close()
    finally:
        first.close()
    third = ExecStateStore(path)
    try:
        assert third.durability_state == "healthy"
    finally:
        third.close()


def test_r2_t01_prepared_record_has_bounded_strict_safe_schema(tmp_path):
    store, path = _fresh(tmp_path)
    try:
        attempt = store.prepare("a", (123, 456))
        assert re.fullmatch(r"[a-f0-9]{32}", attempt)
        entry, raw, obj = _record(path, attempt)
        assert entry.stat().st_nlink == 1
        assert stat.S_IMODE(entry.stat().st_mode) == 0o600
        assert 0 < len(raw) <= 4096
        assert obj["schema_version"] == 1
        assert obj["attempt_id"] == attempt
        assert obj["workspace"] == "a"
        assert obj["workspace_dev"] == 123
        assert obj["workspace_ino"] == 456
        assert obj["phase"] == "PREPARED"
        assert obj["full_descendant_tree_clean"] == "not_proven"
        assert obj["cleanup_scope"] == "none"
        assert all(secret not in raw for secret in (
            b"argv", b"stdout", b"stderr", b"token", b"environment"))
    finally:
        store.close()


def test_r2_t01_same_attempt_durable_order_before_any_caller_launch(tmp_path, monkeypatch):
    store, path = _fresh(tmp_path)
    events = []
    original_write, original_fsync, original_replace = (
        os.write, os.fsync, os.replace)
    try:
        with monkeypatch.context() as m:
            def write(fd, data):
                if stat.S_ISREG(os.fstat(fd).st_mode):
                    events.append("write")
                return original_write(fd, data)

            def fsync(fd):
                events.append("dir_fsync" if stat.S_ISDIR(
                    os.fstat(fd).st_mode) else "file_fsync")
                return original_fsync(fd)

            def replace(src, dst, **kwargs):
                events.append("rename")
                return original_replace(src, dst, **kwargs)

            m.setattr(os, "write", write)
            m.setattr(os, "fsync", fsync)
            m.setattr(os, "replace", replace)
            attempt = store.prepare("a", (1, 2))
            events.append("caller_may_attempt_spawn")
        assert events == ["write", "file_fsync", "rename", "dir_fsync",
                          "caller_may_attempt_spawn"], events
        assert _record(path, attempt)[2]["phase"] == "PREPARED"
    finally:
        store.close()


def test_r2_t01_unresolved_prepared_is_quarantined_after_restart(tmp_path):
    store, path = _fresh(tmp_path)
    attempt = store.prepare("a", (1, 2))
    before = _record(path, attempt)[1]
    store.close()
    resumed = ExecStateStore(path)
    try:
        assert resumed.durability_state == "quarantined"
        assert resumed.quarantine_reason_code == "cleanup_unknown"
        with pytest.raises(GatewayError) as exc:
            resumed.require_healthy()
        assert exc.value.code == "exec_quarantined"
        assert _record(path, attempt)[1] == before
    finally:
        resumed.close()


def test_r2_t01_unknown_is_durable_and_restart_never_replays(tmp_path):
    store, path = _fresh(tmp_path)
    attempt = store.prepare("a", (1, 2))
    store.mark_unknown(attempt)
    assert store.durability_state == "quarantined"
    old = _record(path, attempt)[1]
    assert json.loads(old)["phase"] == "UNKNOWN"
    store.close()
    resumed = ExecStateStore(path)
    try:
        assert resumed.durability_state == "quarantined"
        assert _record(path, attempt)[1] == old
        assert [x.name for x in path.glob("r-*.json")] == [
            "r-" + attempt + ".json"]
    finally:
        resumed.close()


@pytest.mark.parametrize("kind", [
    "unknown_file", "unfinished_temp", "corrupt_json", "symlink",
    "hardlink", "illegal_retired",
])
def test_r2_t01_boot_untrusted_records_fail_closed_and_preserve_bytes(
        tmp_path, kind):
    store, path = _fresh(tmp_path)
    attempt = store.prepare("a", (1, 2))
    record, raw, obj = _record(path, attempt)
    store.close()
    if kind == "unknown_file":
        (path / "extra.bin").write_bytes(b"foreign")
    elif kind == "unfinished_temp":
        (path / "temp-123.tmp").write_bytes(b"interrupted")
    elif kind == "corrupt_json":
        record.write_bytes(b"{invalid")
    elif kind == "symlink":
        record.unlink()
        os.symlink(path / "owner.lock", record)
    elif kind == "hardlink":
        os.link(record, path / ("r-" + ("d" * 32) + ".json"))
    elif kind == "illegal_retired":
        obj["phase"] = "RETIRED"
        obj["cleanup_scope"] = "original_group_only"
        record.write_text(json.dumps(obj, sort_keys=True))
    files_before = {x.name: x.read_bytes() for x in path.iterdir()
                    if x.is_file() and not x.is_symlink()}
    resumed = ExecStateStore(path)
    try:
        assert resumed.durability_state == "quarantined"
        with pytest.raises(GatewayError) as exc:
            resumed.require_healthy()
        assert exc.value.code == "exec_quarantined"
        assert files_before == {x.name: x.read_bytes() for x in path.iterdir()
                                if x.is_file() and not x.is_symlink()}
    finally:
        resumed.close()


@pytest.mark.parametrize("fault", [
    "write", "file_fsync", "rename", "dir_fsync",
])
def test_r2_t01_real_durability_syscall_failure_latches_unavailable(
        tmp_path, monkeypatch, fault):
    store, path = _fresh(tmp_path)
    attempts = []
    try:
        with monkeypatch.context() as m:
            if fault == "write":
                original = os.write
                def fail(fd, data):
                    if stat.S_ISREG(os.fstat(fd).st_mode):
                        attempts.append("write")
                        raise OSError("R2 injected write error")
                    return original(fd, data)
                m.setattr(os, "write", fail)
            elif fault in ("file_fsync", "dir_fsync"):
                original = os.fsync
                def fail(fd):
                    is_dir = stat.S_ISDIR(os.fstat(fd).st_mode)
                    if is_dir == (fault == "dir_fsync"):
                        attempts.append(fault)
                        raise OSError("R2 injected fsync error")
                    return original(fd)
                m.setattr(os, "fsync", fail)
            else:
                def fail(*args, **kwargs):
                    attempts.append("rename")
                    raise OSError("R2 injected atomic replace error")
                m.setattr(os, "replace", fail)
            with pytest.raises(GatewayError) as exc:
                store.prepare("a", (1, 2))
        assert exc.value.code == "exec_state_unavailable"
        assert attempts == [fault]
        assert store.durability_state == "unavailable"
        assert store.quarantine_reason_code == "state_io_unavailable"
        with pytest.raises(GatewayError):
            store.prepare("a", (1, 2))
    finally:
        store.close()


def test_r2_t01_unique_attempts_never_replace_unresolved_intent(tmp_path):
    store, path = _fresh(tmp_path)
    try:
        one = store.prepare("a", (1, 2))
        first = _record(path, one)[1]
        two = store.prepare("a", (1, 2))
        assert one != two
        assert _record(path, one)[1] == first
        assert _record(path, two)[2]["phase"] == "PREPARED"
    finally:
        store.close()
