"""FD-pinned, fail-closed access to private Gateway control-plane files.

The file API must never be permitted to read or modify these objects.  The
loader does not follow user-controlled symlinks and does not parse from a path
that can be switched after ACL validation.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from contextlib import contextmanager
import ctypes
import errno
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any, Iterator


class PrivateFileError(ValueError):
    """Sanitized configuration error: no untrusted filename or content."""


class ACLState(Enum):
    NO_EXTENDED_ACL = "NO_EXTENDED_ACL"
    HAS_EXTENDED_ACL = "HAS_EXTENDED_ACL"
    ACL_CHECK_ERROR = "ACL_CHECK_ERROR"


_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_FLAGS = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC
_MAX_CONFIG = 256 * 1024


def check_extended_acl(fd: int, *, is_directory: bool = False) -> ACLState:
    """Check the *open object*, never a pathname. Unsupported OS fails closed.

    Darwin's valid ENOENT result means an existing FD has no extended ACL.
    Other errno values must NOT be reinterpreted as an empty ACL.
    """
    if sys.platform == "darwin":
        try:
            library = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
            get_acl = library.acl_get_fd_np
            get_acl.argtypes = [ctypes.c_int, ctypes.c_int]
            get_acl.restype = ctypes.c_void_p
            free_acl = library.acl_free
            free_acl.argtypes = [ctypes.c_void_p]
            free_acl.restype = ctypes.c_int
            os.fstat(fd)
            ctypes.set_errno(0)
            acl = get_acl(fd, 0x00000100)  # ACL_TYPE_EXTENDED, Darwin sys/acl.h
            if acl:
                return ACLState.HAS_EXTENDED_ACL if free_acl(acl) == 0 else ACLState.ACL_CHECK_ERROR
            return ACLState.NO_EXTENDED_ACL if ctypes.get_errno() == errno.ENOENT else ACLState.ACL_CHECK_ERROR
        except (OSError, ValueError, AttributeError):
            return ACLState.ACL_CHECK_ERROR
    if sys.platform.startswith("linux"):
        # For supported POSIX ACL filesystems, an absent xattr is ENODATA.
        # EOPNOTSUPP/ENOTSUP, EBADF, EIO, etc. remain hard failures.
        names = ["system.posix_acl_access"]
        if is_directory:
            names.append("system.posix_acl_default")
        for name in names:
            try:
                os.getxattr(fd, name)
                return ACLState.HAS_EXTENDED_ACL
            except OSError as exc:
                if exc.errno != errno.ENODATA:
                    return ACLState.ACL_CHECK_ERROR
        return ACLState.NO_EXTENDED_ACL
    return ACLState.ACL_CHECK_ERROR


def _check_ancestor(st: os.stat_result, *, private_control_plane: bool) -> None:
    """Validate an FD-pinned ancestor according to its trust domain.

    Control-plane ancestors (private config/policy) cannot be group- or
    other-writable. Runtime and explicitly selected Workspace paths may be
    owner/group-writable on a single-user development Mac (e.g. Homebrew's
    user-owned Cellar), but still cannot be writable by *other* users.
    Neither case promises protection from a malicious same-UID process or
    another account authorized as a writable group member.
    """
    mode = stat.S_IMODE(st.st_mode)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid not in {os.geteuid(), 0}:
        raise PrivateFileError("Unsafe pinned directory ancestor.")
    # Keep root-owned sticky system temp dirs as the narrowly justified
    # exception: children are opened by FD with O_NOFOLLOW.
    is_trusted_sticky = st.st_uid == 0 and bool(mode & stat.S_ISVTX)
    denied_write_bits = 0o022 if private_control_plane else 0o002
    if mode & denied_write_bits and not is_trusted_sticky:
        if private_control_plane:
            raise PrivateFileError("Unsafe writable control-plane path ancestor.")
        raise PrivateFileError("Unsafe world-writable runtime or Workspace ancestor.")


def _check_private(st: os.stat_result, *, directory: bool) -> None:
    if (not (stat.S_ISDIR(st.st_mode) if directory else stat.S_ISREG(st.st_mode))
            or st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) & 0o077
            or (not directory and st.st_nlink != 1)):
        raise PrivateFileError("Control-plane object must be private and singly linked.")


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
    """FD-pin a private control directory or a runtime/Workspace directory.

    The private flag governs ancestor permissions as well as the leaf's mode
    and ACL. This must not relax private control-plane file loading.
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
            _check_ancestor(st, private_control_plane=private_leaf)
            ids.append(_identity(st))
        if private_leaf:
            _check_private(os.fstat(fd), directory=True)
            if check_extended_acl(fd, is_directory=True) is not ACLState.NO_EXTENDED_ACL:
                raise PrivateFileError("Control-plane directory ACL is unsafe.")
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
    _check_private(before, directory=False)
    if check_extended_acl(fd) is not ACLState.NO_EXTENDED_ACL:
        raise PrivateFileError("Control-plane file ACL is unsafe.")
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
