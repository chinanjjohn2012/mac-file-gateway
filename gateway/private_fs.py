"""FD-pinned, type-checked loading of Gateway control-plane files.

The file API must never be permitted to read or modify these objects. The
loader rejects symlinks and aliases to protected files, and reads from an
already-open FD rather than following a mutable pathname. Local operating-
system accounts are treated as trusted: UID, permission bits and ACLs are
not startup authorization gates in Multi-Workspace Phase 1.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import stat
from typing import Any


class PrivateFileError(ValueError):
    """Sanitized configuration error: no untrusted filename or content."""


_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_FLAGS = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC
_MAX_CONFIG = 256 * 1024


def _check_control_object(st: os.stat_result, *, directory: bool) -> None:
    """Keep type/alias checks; do not police other local user accounts.

    A multiply linked control file could alias an authorized Workspace file.
    Reject that because it breaks the Web/MCP path boundary, regardless of
    whether local users are considered trusted.
    """
    if directory:
        if not stat.S_ISDIR(st.st_mode):
            raise PrivateFileError("Gateway control-plane directory is not a directory.")
    elif not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
        raise PrivateFileError("Gateway control-plane file must be regular and singly linked.")


def _components(path: str | Path) -> tuple[str, ...]:
    raw = os.fspath(path)
    if not isinstance(raw, str) or not raw.startswith("/") or "\x00" in raw:
        raise PrivateFileError("An absolute control-plane path is required.")
    parts = raw.split("/")[1:]
    if not parts or any(not p or p in {".", ".."} for p in parts):
        raise PrivateFileError("Control-plane path must have canonical components.")
    return tuple(parts)


def _identity(st: os.stat_result) -> tuple[int, int]:
    return (st.st_dev, st.st_ino)


@dataclass
class PinnedDirectory:
    """Caller owns fd; ancestor_ids describe actual opened directory objects."""
    fd: int
    ancestor_ids: tuple[tuple[int, int], ...]

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1


def open_pinned_directory(path: str | Path, *, private_leaf: bool = False) -> PinnedDirectory:
    """FD-pin a control directory, Runtime directory or Workspace root.

    The private_leaf flag requests a control-plane directory type check;
    it does not require UID ownership, restrictive POSIX mode or absent ACL.
    """
    parts = _components(path)
    fd = -1
    try:
        fd = os.open("/", _DIR_FLAGS)
        ids = [_identity(os.fstat(fd))]
        for component in parts:
            nxt = os.open(component, _DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = nxt
            st = os.fstat(fd)
            _check_control_object(st, directory=True)
            ids.append(_identity(st))
        if private_leaf:
            _check_control_object(os.fstat(fd), directory=True)
        result = PinnedDirectory(fd, tuple(ids))
        fd = -1
        return result
    except (OSError, PrivateFileError) as exc:
        if isinstance(exc, PrivateFileError):
            raise
        raise PrivateFileError("Control-plane directory is unavailable or unsafe.") from None
    finally:
        if fd >= 0:
            os.close(fd)


def _load_private_bytes(fd: int, size_limit: int) -> bytes:
    before = os.fstat(fd)
    _check_control_object(before, directory=False)
    if not 0 <= before.st_size <= size_limit:
        raise PrivateFileError("Control-plane file size exceeds the limit.")
    chunks: list[bytes] = []
    remaining = size_limit + 1
    while remaining:
        chunk = os.read(fd, min(65_536, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    raw = b"".join(chunks)
    after = os.fstat(fd)
    fields = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
    if len(raw) > size_limit or len(raw) != before.st_size or any(
        getattr(before, name) != getattr(after, name) for name in fields
    ):
        raise PrivateFileError("Control-plane file changed during reading or is too large.")
    return raw


def read_private_file(path: str | Path, *, max_bytes: int = _MAX_CONFIG) -> bytes:
    """Load private bytes from one single-linked, non-symlink regular file."""
    if type(max_bytes) is not int or not 0 < max_bytes <= 2_000_000:
        raise PrivateFileError("Invalid private file size limit.")
    parts = _components(path)
    parent = open_pinned_directory("/" + "/".join(parts[:-1]), private_leaf=True) if len(parts) > 1 else None
    if parent is None:
        raise PrivateFileError("Private file cannot be placed directly under /.")
    try:
        fd = -1
        try:
            fd = os.open(parts[-1], _FILE_FLAGS, dir_fd=parent.fd)
            return _load_private_bytes(fd, max_bytes)
        except OSError:
            raise PrivateFileError("Control-plane file is unavailable or unsafe.") from None
        finally:
            if fd >= 0:
                os.close(fd)
    finally:
        parent.close()


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PrivateFileError("Duplicate JSON configuration key.")
        result[key] = value
    return result


def parse_strict_json(raw: bytes, *, max_depth: int = 32, max_nodes: int = 10_000) -> dict[str, Any]:
    """Reject duplicate keys, non-finite numbers, invalid UTF-8 and deep trees."""
    try:
        obj = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs,
                         parse_constant=lambda _: (_ for _ in ()).throw(PrivateFileError("Invalid JSON constant.")))
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise PrivateFileError("Invalid UTF-8 JSON configuration.") from None
    if type(obj) is not dict:
        raise PrivateFileError("Configuration root must be an object.")
    stack = [(obj, 1)]
    nodes = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > max_nodes or depth > max_depth:
            raise PrivateFileError("Configuration JSON exceeds the complexity budget.")
        if type(item) is dict:
            if len(item) > 256:
                raise PrivateFileError("Too many JSON object members.")
            stack.extend((v, depth + 1) for v in item.values())
        elif type(item) is list:
            stack.extend((v, depth + 1) for v in item)
    return obj


def read_private_json(path: str | Path, *, max_bytes: int = _MAX_CONFIG) -> dict[str, Any]:
    return parse_strict_json(read_private_file(path, max_bytes=max_bytes))
