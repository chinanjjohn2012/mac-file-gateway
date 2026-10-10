"""Descriptor-relative backup and commit primitives; never accepts absolute paths.

Only suitable for a trusted single-user local filesystem. Cooperating gateways
share an advisory lock, but ordinary editors do not participate in that lock.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import ctypes
import errno
import fcntl
import json
import os
import stat
import sys
import time
from typing import Callable, Iterator
from uuid import uuid4

from .core import GatewayError

BACKUP_DIR = ".gateway-backups"
BACKUP_COUNT_LIMIT = 2000
BACKUP_BYTES_LIMIT = 1024 * 1024 * 1024


def _private_file(fd: int) -> None:
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077):
        raise GatewayError("backup_unavailable", "Backup state must be private, owned by this user, and not linked.")


def _open_lock_file(directory: int) -> int:
    """Open the fixed lock leaf, retrying only Darwin's transient ENOENT.

    Concurrent first creation on Darwin can report ENOENT from openat(O_CREAT)
    even though the validated parent descriptor is still open. Keep the same
    descriptor and security flags; do not retry permission, link or I/O errors,
    and never retry a file write or commit. Persistent ENOENT still fails closed.
    """
    attempts = 3 if sys.platform == "darwin" else 1
    flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    for attempt in range(attempts):
        try:
            return os.open(".lock", flags, 0o600, dir_fd=directory)
        except OSError as exc:
            if exc.errno != errno.ENOENT or attempt + 1 == attempts:
                raise
            time.sleep(0.01)
    raise AssertionError("Lock open attempts must be positive")


def _storage_failure(exc: OSError, stage: str, message: str) -> GatewayError:
    """Expose only a fixed stage and errno, never OS paths or file contents."""
    name = errno.errorcode.get(exc.errno, "UNKNOWN")
    details = {"stage": stage, "errno": exc.errno, "errno_name": name}
    return GatewayError("write_failed", f"{message} [stage={stage}, errno={exc.errno} {name}]",
                        details=details)


@contextmanager
def write_lock(root_fd: int) -> Iterator[int]:
    """Create private backup state only for an actual requested write."""
    directory = lock = -1
    stage = "backup_directory_create"
    try:
        try:
            os.mkdir(BACKUP_DIR, mode=0o700, dir_fd=root_fd)
        except FileExistsError:
            pass
        stage = "backup_directory_open"
        directory = os.open(BACKUP_DIR, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root_fd)
        stage = "backup_directory_validate"
        info = os.fstat(directory)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise GatewayError("backup_unavailable", "Backup directory must be private and owned by this user.")
        stage = "lock_file_open"
        lock = _open_lock_file(directory)
        stage = "lock_file_validate"
        _private_file(lock)
        stage = "lock_acquire"
        deadline = time.monotonic() + 5
        while True:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise GatewayError("busy", "Another gateway write holds the project lock; retry later.") from None
                time.sleep(0.025)
        stage = "write_or_backup"
        yield directory
    except OSError as exc:
        raise _storage_failure(exc, stage,
                               "Local write or backup storage is unavailable; inspect the target before retrying.") from None
    finally:
        if lock >= 0:
            os.close(lock)
        if directory >= 0:
            os.close(directory)


def _write_all(fd: int, data: bytes) -> None:
    remaining = memoryview(data)
    while remaining:
        written = os.write(fd, remaining)
        if written <= 0:
            raise OSError("Unable to complete file write")
        remaining = remaining[written:]


def _save_exact(directory: int, name: str, data: bytes) -> None:
    fd = -1
    created = False
    try:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=directory)
        created = True
        _write_all(fd, data)
        os.fsync(fd)
    except BaseException:
        if created:
            try:
                os.unlink(name, dir_fd=directory)
            except OSError:
                pass
        raise
    finally:
        if fd >= 0:
            os.close(fd)


def save_backup(directory: int, path: str, raw: bytes, sha256: str) -> str:
    """Keep original bytes and a separate metadata record; never auto-prune."""
    count = byte_count = entries = 0
    with os.scandir(directory) as iterator:
        for entry in iterator:
            entries += 1
            if entries > BACKUP_COUNT_LIMIT * 3 + 10:
                raise GatewayError("backup_full", "Backup state has too many entries; review it locally before writing.")
            if entry.name.endswith(".bak"):
                info = entry.stat(follow_symlinks=False)
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise GatewayError("backup_unavailable", "Unexpected linked or special file in backup state.")
                count += 1
                byte_count += info.st_size
    if count >= BACKUP_COUNT_LIMIT or byte_count + len(raw) > BACKUP_BYTES_LIMIT:
        raise GatewayError("backup_full", "Backup retention limit reached; review old backups locally before writing.")
    identifier = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + uuid4().hex
    name = identifier + ".bak"
    _save_exact(directory, name, raw)
    metadata = {"path": path, "sha256": sha256, "bytes": len(raw), "backup": name}
    _save_exact(directory, identifier + ".json", json.dumps(metadata, ensure_ascii=True).encode())
    # A failed fsync occurs before the target replacement, so fail closed.
    os.fsync(directory)
    return f"{BACKUP_DIR}/{name}"


def install_file(parent: int, name: str, raw: bytes, mode: int,
                 verify: Callable[[], None], *, create: bool) -> list[str]:
    """Install a fully written sibling. Creation uses a no-clobber hard link."""
    temporary = ".gateway-tmp-" + uuid4().hex
    fd = -1
    made_temp = committed = False
    warnings: list[str] = []
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=parent)
        made_temp = True
        _write_all(fd, raw)
        os.fchmod(fd, mode & 0o777)  # Never introduce setuid/setgid bits.
        os.fsync(fd)
        os.close(fd)
        fd = -1
        verify()
        if create:
            try:
                os.link(temporary, name, src_dir_fd=parent, dst_dir_fd=parent, follow_symlinks=False)
            except FileExistsError:
                raise GatewayError("already_exists", "Creation refused: the destination already exists.") from None
        else:
            os.replace(temporary, name, src_dir_fd=parent, dst_dir_fd=parent)
            made_temp = False
        committed = True
    except OSError as exc:
        raise _storage_failure(exc, "install_file",
                               "Unable to install the new file; no partial replacement was performed.") from None
    finally:
        if fd >= 0:
            os.close(fd)
        if made_temp:
            try:
                os.unlink(temporary, dir_fd=parent)
            except OSError:
                if committed:
                    warnings.append("File committed but temporary-link cleanup failed; inspect the directory locally.")
    try:
        os.fsync(parent)
    except OSError:
        warnings.append("File committed, but directory sync failed; crash durability is not guaranteed.")
    return warnings



def _sync_directory(directory: int, warning: str) -> list[str]:
    try:
        os.fsync(directory)
    except OSError:
        return [warning]
    return []


def remove_file(parent: int, name: str, verify: Callable[[], None]) -> list[str]:
    """Remove one already-validated regular file after a final guarded recheck."""
    verify()
    try:
        os.unlink(name, dir_fd=parent)
    except FileNotFoundError:
        raise GatewayError("conflict", "Source disappeared before deletion; read it again.") from None
    except OSError as exc:
        raise _storage_failure(exc, "unlink_file", "Unable to delete the file; inspect it before retrying.") from None
    return _sync_directory(parent, "File deleted, but directory sync failed; crash durability is not guaranteed.")


def _native_rename_no_replace(source_parent: int, source_name: str,
                              destination_parent: int, destination_name: str) -> None:
    """Use the platform's descriptor-relative, atomic no-clobber rename primitive."""
    libc = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "darwin":
        rename = getattr(libc, "renameatx_np", None)
        flag = 0x00000004  # RENAME_EXCL from Darwin sys/stdio.h.
    elif sys.platform.startswith("linux"):
        rename = getattr(libc, "renameat2", None)
        flag = 1  # RENAME_NOREPLACE from Linux fcntl/uapi headers.
    else:
        rename = None
        flag = 0
    if rename is None:
        raise OSError(errno.ENOSYS, "atomic no-replace rename is unavailable")
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    rc = rename(source_parent, os.fsencode(source_name), destination_parent, os.fsencode(destination_name), flag)
    if rc != 0:
        error = ctypes.get_errno()
        raise OSError(error, errno.errorcode.get(error, "rename failed"))


def move_no_replace(source_parent: int, source_name: str,
                    destination_parent: int, destination_name: str,
                    verify: Callable[[], None]) -> list[str]:
    """Atomically rename one file without replacing a destination."""
    verify()
    try:
        _native_rename_no_replace(source_parent, source_name, destination_parent, destination_name)
    except FileExistsError:
        raise GatewayError("already_exists", "Move refused: the destination already exists.") from None
    except OSError as exc:
        if exc.errno == errno.EEXIST:
            raise GatewayError("already_exists", "Move refused: the destination already exists.") from None
        if exc.errno == errno.EXDEV:
            raise GatewayError("cross_device", "Cross-filesystem moves are not supported; choose a destination on the same filesystem.") from None
        if exc.errno in {errno.ENOSYS, errno.EOPNOTSUPP, errno.ENOTSUP, errno.EINVAL}:
            raise GatewayError("move_unavailable", "This filesystem does not provide the required atomic no-overwrite move primitive.") from None
        if exc.errno == errno.ENOENT:
            raise GatewayError("conflict", "Source or destination parent changed before move; inspect and retry.") from None
        raise _storage_failure(exc, "move_file", "Unable to move the file; inspect both paths before retrying.") from None
    warnings = _sync_directory(source_parent, "File moved, but source directory sync failed; crash durability is not guaranteed.")
    if destination_parent != source_parent:
        warnings += _sync_directory(destination_parent, "File moved, but destination directory sync failed; crash durability is not guaranteed.")
    return warnings
