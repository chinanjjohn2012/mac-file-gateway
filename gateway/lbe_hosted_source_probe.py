"""Bounded actual-file evidence for a future trusted-host PRODUCT_T1.

This is a real nofollow, FD-pinned read of independently selected files,
NOT a record of the booted macOS image, an actual dyld/import graph,
an attestation by GitHub, or permission to launch an original child.

Callers must separately supply independently established source digests.
No REST/MCP/client field is wired to this module. A correct selected-file
receipt NEVER unlocks WorkspaceService.invoke_exec or NativeLauncher.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
import re
import stat
import threading


class D4HostedSourceDenied(ValueError):
    """Selected host/runtime source is missing, unqualified, or changed."""


_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
_PART = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.+@-]{0,254}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_FIELDS = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns",
           "st_mode", "st_uid", "st_nlink")
_MAX_FILES = 8
_MAX_DEPTH = 20
_MAX_FILE_BYTES = 32 * 1024 * 1024
_MAX_TOTAL_BYTES = 64 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class D4HostedSelectedSourceObservation:
    """Observed selected bytes/inodes only; never an entire image receipt."""

    root_identity: tuple[int, ...]
    selected: tuple[tuple[str, str, tuple[int, ...]], ...]
    # Include / and EVERY absolute ancestor above source_root. A second
    # one-use observation must match these identities as well as the leaf.
    root_ancestor_identities: tuple[tuple[int, ...], ...]
    source_file_bytes_verified: bool = True
    full_boot_image_identity_attested: bool = False
    actual_loaded_source_graph_attested: bool = False
    host_provider_attested: bool = False
    native_launch_allowed: bool = False
    status: str = "HOSTED_SELECTED_BYTES_ONLY_NOT_IMAGE_OR_LOADER_ATTESTATION"


def _identity(fd: int, *, directory: bool) -> tuple[int, ...]:
    st = os.fstat(fd)
    if ((not stat.S_ISDIR(st.st_mode) if directory else
         not stat.S_ISREG(st.st_mode))
            or st.st_uid not in (0, os.getuid())
            or st.st_mode & 0o022
            or (not directory and st.st_nlink != 1)):
        raise D4HostedSourceDenied("unqualified source inode or permission")
    return tuple(getattr(st, key) for key in _FIELDS)


def _absolute_root(path: object) -> tuple[str, ...]:
    if (type(path) is not str or not 2 <= len(path) <= 2048
            or not path.startswith("/") or "\\" in path
            or any(ord(c) < 33 or ord(c) >= 127 for c in path)):
        raise D4HostedSourceDenied("invalid selected source root")
    parts = path[1:].split("/")
    if any(_PART.fullmatch(p) is None or p in (".", "..") for p in parts):
        raise D4HostedSourceDenied("noncanonical selected source root")
    return tuple(parts)


def _relative(path: object) -> tuple[str, ...]:
    if (type(path) is not str or not path or len(path) > 2048):
        raise D4HostedSourceDenied("invalid selected host source")
    parts = path.split("/")
    if (len(parts) > _MAX_DEPTH
            or any(_PART.fullmatch(p) is None or p in (".", "..")
                   for p in parts)):
        raise D4HostedSourceDenied("unsafe selected host source path")
    return tuple(parts)


def _root_ancestor_identity(fd: int) -> tuple[int, ...]:
    """Stable path-component ownership, type and mode evidence.

    Shared system /tmp is sometimes root-owned and sticky (01777).
    Only that sticky root-owned case is tolerated as an intermediate
    parent; all other group/world-writable ancestors fail. The FINAL
    selected source root still requires the stricter _identity() rule.
    Directory mtime is not included: unrelated new children under a
    shared system parent must not create a false inode/mode drift.
    """
    st = os.fstat(fd)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid not in (0, os.getuid()):
        raise D4HostedSourceDenied("untrusted source-root ancestor")
    if (st.st_mode & 0o022
            and not (st.st_uid == 0 and st.st_mode & stat.S_ISVTX)):
        raise D4HostedSourceDenied("writable source-root ancestor")
    return (st.st_dev, st.st_ino, st.st_mode, st.st_uid)


def _pinned_root(root: tuple[str, ...],
                 ) -> tuple[list[int], tuple[tuple[int, ...], ...]]:
    """Retain ALL /-to-root FDs, including parents outside source_root."""
    chain = [os.open("/", _DIR)]
    try:
        seen = [_root_ancestor_identity(chain[0])]
        for component in root:
            child = os.open(component, _DIR, dir_fd=chain[-1])
            chain.append(child)
            seen.append(_root_ancestor_identity(child))
        # The last component is a private, non-writable selected root.
        _identity(chain[-1], directory=True)
        return chain, tuple(seen)
    except BaseException:
        for fd in reversed(chain):
            os.close(fd)
        raise


def _verify_root_chain(chain: list[int],
                       original: tuple[tuple[int, ...], ...],
                       components: tuple[str, ...]) -> None:
    """Reject parent mode/inode drift AND a changed absolute path binding.

    Re-opening every named component from its pinned parent detects a
    vanished/replaced path even while an old leaf FD still hashes correctly.
    This check is a bounded prelaunch sample, NOT atomic pathname spawn or
    cryptographic proof of a full booted image.
    """
    if len(chain) != len(components) + 1 or len(original) != len(chain):
        raise D4HostedSourceDenied("source-root ancestor chain incomplete")
    if any(_root_ancestor_identity(fd) != before
           for fd, before in zip(chain, original)):
        raise D4HostedSourceDenied("absolute source-root ancestor changed")
    for parent, component, before in zip(chain, components, original[1:]):
        reopened = os.open(component, _DIR, dir_fd=parent)
        try:
            if _root_ancestor_identity(reopened) != before:
                raise D4HostedSourceDenied(
                    "absolute source-root name no longer identifies inode")
        finally:
            os.close(reopened)


def _source_bytes(root_fd: int, parts: tuple[str, ...],
                  expected_sha: str) -> tuple[str, tuple[int, ...], int]:
    # Keep ALL opened parents pinned until the complete read and metadata
    # check have finished. This catches parent chmod/chown/inode drift during
    # the read, not merely leaf content replacement.
    parents = [os.dup(root_fd)]
    initial = [_identity(parents[0], directory=True)]
    try:
        for part in parts[:-1]:
            fd = os.open(part, _DIR, dir_fd=parents[-1])
            parents.append(fd)
            initial.append(_identity(fd, directory=True))
        leaf = os.open(parts[-1], _FILE, dir_fd=parents[-1])
        try:
            before = _identity(leaf, directory=False)
            size = before[2]
            if not 0 < size <= _MAX_FILE_BYTES:
                raise D4HostedSourceDenied("selected source byte budget exceeded")
            remaining = size
            digest = hashlib.sha256()
            while remaining:
                buf = os.read(leaf, min(65536, remaining))
                if not buf:
                    raise D4HostedSourceDenied("selected source unexpectedly truncated")
                digest.update(buf)
                remaining -= len(buf)
            actual = digest.hexdigest()
            if (actual != expected_sha
                    or _identity(leaf, directory=False) != before):
                raise D4HostedSourceDenied("source bytes or inode changed")
            if any(_identity(fd, directory=True) != old
                   for fd, old in zip(parents, initial)):
                raise D4HostedSourceDenied("source ancestor drift during read")
            return actual, before, size
        finally:
            os.close(leaf)
    finally:
        for fd in reversed(parents):
            os.close(fd)


def inspect_d4_hosted_selected_source_files(
    *, source_root: str,
    expected: tuple[tuple[str, str], ...],
) -> D4HostedSelectedSourceObservation:
    """Read and SHA-check up to eight exact pinned files without code execution.

    The expected hashes are an INPUT requiring external review, not proof of
    approval. This function never imports them, fetches network resources,
    discovers paths dynamically, modifies files, or starts any process.
    """
    root_parts = _absolute_root(source_root)
    if (type(expected) is not tuple
            or not 1 <= len(expected) <= _MAX_FILES):
        raise D4HostedSourceDenied("missing bounded independent source manifest")
    checked: list[tuple[tuple[str, ...], str]] = []
    for item in expected:
        if (type(item) is not tuple or len(item) != 2
                or type(item[0]) is not str or type(item[1]) is not str
                or _SHA256.fullmatch(item[1]) is None
                or item[1] == "0" * 64):
            raise D4HostedSourceDenied("unqualified selected source manifest")
        checked.append((_relative(item[0]), item[1]))
    names = tuple("/".join(parts) for parts, _ in checked)
    if names != tuple(sorted(set(names))):
        raise D4HostedSourceDenied("source manifest order or duplicates invalid")
    try:
        root_chain, ancestry = _pinned_root(root_parts)
        try:
            fd = root_chain[-1]
            _verify_root_chain(root_chain, ancestry, root_parts)
            identity = _identity(fd, directory=True)
            observed: list[tuple[str, str, tuple[int, ...]]] = []
            total = 0
            for (parts, digest), name in zip(checked, names):
                found, inode, size = _source_bytes(fd, parts, digest)
                total += size
                if total > _MAX_TOTAL_BYTES:
                    raise D4HostedSourceDenied("selected source aggregate too large")
                observed.append((name, found, inode))
                # The external parent can mutate while os.read consumes the
                # pinned leaf: check it BEFORE producing a valid receipt.
                _verify_root_chain(root_chain, ancestry, root_parts)
            if _identity(fd, directory=True) != identity:
                raise D4HostedSourceDenied("source root changed during scan")
            _verify_root_chain(root_chain, ancestry, root_parts)
            return D4HostedSelectedSourceObservation(
                root_identity=identity, selected=tuple(observed),
                root_ancestor_identities=ancestry)
        finally:
            for fd in reversed(root_chain):
                os.close(fd)
    except OSError:
        raise D4HostedSourceDenied(
            "selected host source path or descriptor unavailable") from None


class D4HostedSelectedSourceRecheck:
    """One observed set, independently re-read before a future launch."""

    __slots__ = ("_root", "_expected", "_previous", "_used", "_lock")

    def __init__(self, *, source_root: str,
                 expected: tuple[tuple[str, str], ...]):
        self._previous = inspect_d4_hosted_selected_source_files(
            source_root=source_root, expected=expected)
        self._root = source_root
        self._expected = expected
        self._used = False
        self._lock = threading.Lock()

    def recheck_once(self) -> None:
        # Burn before IO; error or drift never permits retry.
        with self._lock:
            if self._used:
                raise D4HostedSourceDenied("selected host source receipt replayed")
            self._used = True
        observed = inspect_d4_hosted_selected_source_files(
            source_root=self._root, expected=self._expected)
        if observed != self._previous:
            raise D4HostedSourceDenied("selected host source changed before use")
