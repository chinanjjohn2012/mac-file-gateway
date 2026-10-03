"""Deterministic syscall faults plus real filesystem/locking regression tests.

Fault injection at os.open models a reported Darwin first-create ENOENT;
these tests do not claim to emulate APFS or confirm the user's exact errno.
"""
from concurrent.futures import ThreadPoolExecutor
import errno
import hashlib
import os
from pathlib import Path
import threading
from types import SimpleNamespace

import pytest

from gateway.core import Gateway, GatewayError
from gateway import write_storage as storage


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


@pytest.fixture
def project(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "app.py").write_bytes(b"before")
    g = Gateway(root, allow_write=True)
    try:
        yield root, g
    finally:
        g.close()


def simulate_platform(monkeypatch, platform):
    # Do not change sys.platform globally (it affects the test runner too).
    monkeypatch.setattr(storage, "sys", SimpleNamespace(platform=platform), raising=False)


@pytest.mark.parametrize("transient_failures", [1, 2])
def test_darwin_lock_open_retries_transient_enoent(project, monkeypatch, transient_failures):
    root, g = project
    simulate_platform(monkeypatch, "darwin")
    original = storage.os.open
    calls = []

    def interrupted_open(path, flags, mode=0o777, *, dir_fd=None):
        if path == ".lock":
            calls.append((path, flags, mode, dir_fd))
            if len(calls) <= transient_failures:
                raise FileNotFoundError(errno.ENOENT, "injected concurrent first-create miss", path)
        return original(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(storage.os, "open", interrupted_open)
    result = g.write_file("app.py", "after", sha(b"before"), dry_run=False)
    assert result["applied"] is True
    assert (root / "app.py").read_bytes() == b"after"
    assert len(calls) == transient_failures + 1
    assert all(call == calls[0] for call in calls)
    _, flags, mode, _ = calls[0]
    required = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    assert flags & required == required
    assert not flags & os.O_TRUNC
    assert mode == 0o600
    assert (root / result["backup_path"]).read_bytes() == b"before"


def test_darwin_persistent_enoent_stops_after_three_calls(project, monkeypatch):
    root, g = project
    simulate_platform(monkeypatch, "darwin")
    original = storage.os.open
    calls = []

    def missing_open(path, flags, mode=0o777, *, dir_fd=None):
        if path == ".lock":
            calls.append(dir_fd)
            raise FileNotFoundError(errno.ENOENT, "sensitive local error", "/private/not-for-clients")
        return original(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(storage.os, "open", missing_open)
    with pytest.raises(GatewayError) as caught:
        g.write_file("app.py", "after", sha(b"before"), dry_run=False)
    assert len(calls) == 3
    assert len(set(calls)) == 1
    assert caught.value.code == "write_failed"
    assert caught.value.details == {"stage": "lock_file_open", "errno": errno.ENOENT, "errno_name": "ENOENT"}
    assert "/private" not in str(caught.value)
    assert "/private" not in repr(caught.value.details)
    assert (root / "app.py").read_bytes() == b"before"
    assert not list(root.rglob("*.bak"))


@pytest.mark.parametrize("number", [errno.EACCES, errno.ELOOP, errno.ENOSPC, errno.EIO, errno.EBADF, errno.ENOTDIR])
def test_nontransient_lock_open_errors_are_not_retried(project, monkeypatch, number):
    root, g = project
    simulate_platform(monkeypatch, "darwin")
    original = storage.os.open
    calls = []

    def failing_open(path, flags, mode=0o777, *, dir_fd=None):
        if path == ".lock":
            calls.append(dir_fd)
            raise OSError(number, "injected nontransient failure", "/private/not-for-clients")
        return original(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(storage.os, "open", failing_open)
    with pytest.raises(GatewayError) as caught:
        g.write_file("app.py", "after", sha(b"before"), dry_run=False)
    assert len(calls) == 1
    assert caught.value.code == "write_failed"
    assert caught.value.details["errno"] == number
    assert caught.value.details["stage"] == "lock_file_open"
    assert "/private" not in str(caught.value)
    assert (root / "app.py").read_bytes() == b"before"


def test_non_darwin_enoent_is_not_retried(project, monkeypatch):
    root, g = project
    simulate_platform(monkeypatch, "linux")
    original = storage.os.open
    calls = []

    def missing_open(path, flags, mode=0o777, *, dir_fd=None):
        if path == ".lock":
            calls.append(dir_fd)
            raise FileNotFoundError(errno.ENOENT, "injected miss")
        return original(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(storage.os, "open", missing_open)
    with pytest.raises(GatewayError) as caught:
        g.write_file("app.py", "after", sha(b"before"), dry_run=False)
    assert len(calls) == 1
    assert caught.value.code == "write_failed"
    assert caught.value.details["stage"] == "lock_file_open"
    assert (root / "app.py").read_bytes() == b"before"


def test_flock_failure_identifies_acquisition_not_file_open(project, monkeypatch):
    root, g = project

    def fail_flock(fd, flags):
        raise OSError(errno.EIO, "not a contention error")

    monkeypatch.setattr(storage.fcntl, "flock", fail_flock)
    with pytest.raises(GatewayError) as caught:
        g.write_file("app.py", "after", sha(b"before"), dry_run=False)
    assert caught.value.code == "write_failed"
    assert caught.value.details == {"stage": "lock_acquire", "errno": errno.EIO, "errno_name": "EIO"}
    assert (root / "app.py").read_bytes() == b"before"


def test_backup_failure_is_not_retried_or_reported_as_lock_contention(project, monkeypatch):
    root, g = project
    calls = []

    def fail_backup(fd, name, data):
        calls.append(name)
        raise OSError(errno.ENOSPC, "sensitive path or contents omitted")

    monkeypatch.setattr(storage, "_save_exact", fail_backup)
    with pytest.raises(GatewayError) as caught:
        g.write_file("app.py", "after", sha(b"before"), dry_run=False)
    assert len(calls) == 1
    assert caught.value.code == "write_failed"
    assert caught.value.details == {"stage": "write_or_backup", "errno": errno.ENOSPC, "errno_name": "ENOSPC"}
    assert (root / "app.py").read_bytes() == b"before"


def test_install_failure_has_safe_stage_and_errno(project, monkeypatch):
    root, g = project

    def fail_replace(*args, **kwargs):
        raise OSError(errno.EIO, "sensitive error", "/private/not-for-clients")

    monkeypatch.setattr(storage.os, "replace", fail_replace)
    with pytest.raises(GatewayError) as caught:
        g.write_file("app.py", "after", sha(b"before"), dry_run=False)
    assert caught.value.code == "write_failed"
    assert caught.value.details["stage"] == "install_file"
    assert caught.value.details["errno"] == errno.EIO
    assert "/private" not in str(caught.value)
    assert (root / "app.py").read_bytes() == b"before"
    assert not list(root.glob(".gateway-tmp-*"))


def test_two_instances_with_one_injected_first_create_miss(project, monkeypatch):
    root, first = project
    simulate_platform(monkeypatch, "darwin")
    second = Gateway(root, allow_write=True)
    original = storage.os.open
    barrier = threading.Barrier(2)
    guard = threading.Lock()
    calls = 0

    def concurrent_open(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal calls
        if path == ".lock":
            with guard:
                calls += 1
                attempt = calls
            if attempt <= 2:
                barrier.wait(timeout=5)
            if attempt == 1:
                raise FileNotFoundError(errno.ENOENT, "injected first-create race")
        return original(path, flags, mode, dir_fd=dir_fd)

    def update(gateway, content):
        try:
            return gateway.write_file("app.py", content, sha(b"before"), dry_run=False)["applied"]
        except GatewayError as exc:
            return exc.code

    monkeypatch.setattr(storage.os, "open", concurrent_open)
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(update, first, "one"), pool.submit(update, second, "two")]
            results = [f.result(timeout=10) for f in futures]
    finally:
        second.close()
    assert results.count(True) == 1 and results.count("conflict") == 1, results
    assert (root / "app.py").read_bytes() in (b"one", b"two")
    assert len(list((root / ".gateway-backups").glob("*.bak"))) == 1


def test_retry_does_not_follow_a_lock_symlink(project, monkeypatch, tmp_path):
    root, g = project
    simulate_platform(monkeypatch, "darwin")
    original = storage.os.open
    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"do not touch")
    calls = []

    def insert_symlink(path, flags, mode=0o777, *, dir_fd=None):
        if path == ".lock":
            calls.append(dir_fd)
            if len(calls) == 1:
                os.symlink(outside, path, dir_fd=dir_fd)
                raise FileNotFoundError(errno.ENOENT, "injected race")
        return original(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(storage.os, "open", insert_symlink)
    with pytest.raises(GatewayError) as caught:
        g.write_file("app.py", "after", sha(b"before"), dry_run=False)
    assert len(calls) == 2
    assert caught.value.code == "write_failed"
    assert caught.value.details["errno"] == errno.ELOOP
    assert outside.read_bytes() == b"do not touch"
    assert (root / "app.py").read_bytes() == b"before"


def test_retry_does_not_accept_a_hardlinked_lock(project, monkeypatch, tmp_path):
    root, g = project
    simulate_platform(monkeypatch, "darwin")
    original = storage.os.open
    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"do not touch")
    outside.chmod(0o600)
    calls = []

    def insert_hardlink(path, flags, mode=0o777, *, dir_fd=None):
        if path == ".lock":
            calls.append(dir_fd)
            if len(calls) == 1:
                os.link(outside, path, dst_dir_fd=dir_fd)
                raise FileNotFoundError(errno.ENOENT, "injected race")
        return original(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(storage.os, "open", insert_hardlink)
    with pytest.raises(GatewayError) as caught:
        g.write_file("app.py", "after", sha(b"before"), dry_run=False)
    assert len(calls) == 2
    assert caught.value.code == "backup_unavailable"
    assert outside.read_bytes() == b"do not touch"
    assert (root / "app.py").read_bytes() == b"before"


@pytest.mark.parametrize("iteration", range(5))
def test_real_concurrent_first_write_keeps_one_winner(project, iteration):
    root, first = project
    second = Gateway(root, allow_write=True)
    start = threading.Barrier(2)

    def update(gateway, content):
        start.wait(timeout=5)
        try:
            return gateway.write_file("app.py", content, sha(b"before"), dry_run=False)["applied"]
        except GatewayError as exc:
            return exc.code, str(exc), exc.details

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(update, first, "one"), pool.submit(update, second, "two")]
            results = [f.result(timeout=10) for f in futures]
    finally:
        second.close()
    codes = [r if r is True else r[0] for r in results]
    assert codes.count(True) == 1 and codes.count("conflict") == 1, results
    assert len(list((root / ".gateway-backups").glob("*.bak"))) == 1
