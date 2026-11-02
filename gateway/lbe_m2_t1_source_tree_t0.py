"""M2 T1-SOURCE first-party T0: enumerate and check one private source tree.

This is an auditable digest/source-shadow preflight, NOT actual loaded-source
identity. No native Go/Pipenv invocation, network, process or policy attachment.
A caller-provided digest lock does not establish trusted origin or execution
authority. This module never turns a byte match into a grant.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import stat
from types import MappingProxyType
from typing import Mapping

from .lbe_source_preflight import (
    LbeSourcePreflightError, _check_directory, _check_private_root,
    _verified_member,
)

_MEMBER = re.compile(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*\Z")
_SHA256 = re.compile(r"[a-f0-9]{64}\Z")
_MAX_MEMBERS = 20000
_MAX_DIRECTORIES = 30000
_MAX_BYTES = 2 * 1024 * 1024 * 1024
_MAX_SINGLE = 128 * 1024 * 1024


class LbeT1SourceTreeError(ValueError):
    """Exact source closure and trusted-root preflight failed."""


@dataclass(frozen=True)
class T1SourceTreeT0:
    """Actual scanned bytes, but explicitly not proof of what a child loads."""

    member_sha256: Mapping[str, str]
    executable_members: tuple[str, ...]
    manifest_sha256: str
    regular_files: int
    bytes_hashed: int
    status: str = "PRIVATE_SOURCE_TREE_MATCH_T0"
    approved_origin: str = "NOT_ATTESTED"
    actual_native_loaded_source: str = "NOT_ATTESTED"
    snapshot_immutable_after_check: bool = False
    launch_allowed: bool = False
    native_t1: str = "NOT_RUN"


def _validate_lock(
    source_lock: object, executable_members: object,
) -> tuple[dict[str, str], frozenset[str]]:
    if (type(source_lock) is not dict or not source_lock
            or len(source_lock) > _MAX_MEMBERS
            or type(executable_members) is not tuple):
        raise LbeT1SourceTreeError("source lock or executable list invalid")
    copied: dict[str, str] = {}
    for name, digest in dict.items(source_lock):
        if (type(name) is not str or len(name) > 512
                or not _MEMBER.fullmatch(name)
                or any(c in {".", ".."} for c in name.split("/"))
                or type(digest) is not str or not _SHA256.fullmatch(digest)):
            raise LbeT1SourceTreeError("unsafe source member or SHA")
        copied[name] = digest
    if (len(set(x.casefold() for x in copied)) != len(copied)
            or any(type(x) is not str or x not in copied
                   for x in executable_members)
            or len(set(executable_members)) != len(executable_members)):
        raise LbeT1SourceTreeError("executable or case-fold identity drift")
    return copied, frozenset(executable_members)


def inspect_t1_private_source_tree_t0(
    *, private_root: Path, trusted_base: Path,
    source_lock: dict[str, str],
    executable_members: tuple[str, ...],
) -> T1SourceTreeT0:
    """No-follow enumerate *all* files and check each locked byte and mode.

    This rejects unlisted .pth/site seed/source shadows and unlisted executables.
    It does not follow any symlink, open any special file or execute any code.
    CPython/Linux/macOS POSIX fd support is required; on unsupported platforms
    any inspection failure is a hard denial. Inspection can race AFTER return;
    only a later reviewed isolated executor can attest actual loaded sources.
    """
    lock, executables = _validate_lock(source_lock, executable_members)
    # M1 allowed deeper descendants of an approved private base for its T0
    # source candidate. This T1 test fixture is intentionally narrower:
    # the exact stage must be a DIRECT child of the caller-reviewed base.
    # This is a lexical restriction in addition to the no-follow FD walk,
    # not a claim that caller-supplied base provenance is authenticated.
    if (not isinstance(private_root, Path)
            or not isinstance(trusted_base, Path)
            or private_root.parent != trusted_base):
        raise LbeT1SourceTreeError("source stage is not direct child of trusted base")
    root = -1
    visited: set[str] = set()
    seen_dirs = 0
    try:
        root = _check_private_root(private_root, trusted_base=trusted_base)
        def walk(fd: int, prefix: str) -> None:
            nonlocal seen_dirs
            seen_dirs += 1
            if seen_dirs > _MAX_DIRECTORIES:
                raise LbeT1SourceTreeError("too many source directories")
            names = os.listdir(fd)
            if len(names) != len(set(n.casefold() for n in names)):
                raise LbeT1SourceTreeError("casefold-colliding source paths")
            for name in sorted(names):
                path = prefix + name
                if (type(name) is not str or not _MEMBER.fullmatch(name)
                        or len(path) > 512):
                    raise LbeT1SourceTreeError("unexpected source directory entry")
                st = os.stat(name, dir_fd=fd, follow_symlinks=False)
                if stat.S_ISDIR(st.st_mode):
                    child = _check_directory(fd, name)
                    try:
                        walk(child, path + "/")
                    finally:
                        os.close(child)
                elif stat.S_ISREG(st.st_mode):
                    if (path not in lock or path in visited
                            or len(visited) >= _MAX_MEMBERS
                            or st.st_uid != os.getuid() or st.st_nlink != 1
                            or st.st_mode & 0o022
                            or bool(st.st_mode & 0o111) != (path in executables)):
                        raise LbeT1SourceTreeError(
                            "unlisted, ambiguous or unsafe source member")
                    visited.add(path)
                else:
                    # Fail closed for symlinks, FIFOs, sockets and devices.
                    raise LbeT1SourceTreeError("special or linked source denied")
        walk(root, "")
        if visited != set(lock):
            raise LbeT1SourceTreeError("missing expected source member")
        total = 0
        checked: dict[str, str] = {}
        for name in sorted(lock):
            digest, size = _verified_member(
                root, name, lock[name], executable=name in executables,
                max_bytes=min(_MAX_SINGLE, _MAX_BYTES-total),
            )
            checked[name] = digest
            total += size
        # Stable, unambiguous textual artifact identity (not an origin proof).
        manifest = "".join(
            f"{checked[name]}  ./{name}\n" for name in sorted(checked)
        )
        return T1SourceTreeT0(
            member_sha256=MappingProxyType(checked),
            executable_members=tuple(sorted(executables)),
            manifest_sha256=hashlib.sha256(manifest.encode("ascii")).hexdigest(),
            regular_files=len(checked),
            bytes_hashed=total,
        )
    except (LbeSourcePreflightError, OSError, TypeError, ValueError,
            RuntimeError, RecursionError) as exc:
        if isinstance(exc, LbeT1SourceTreeError):
            raise
        raise LbeT1SourceTreeError(
            "source tree cannot be closed or verified") from exc
    finally:
        if root >= 0:
            os.close(root)
