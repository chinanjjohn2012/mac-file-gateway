"""Finite R010 source and Go build artifact observations (NO PRODUCT EXEC).

These helpers read only explicitly selected files through pinned directory FDs.
They supply one component of R010 section 10's finite pre/post predicates.
They do NOT prove transient writes, unselected files, source provenance,
original-child completion, descendant cleanup, provider identity or a grant.
Neither these observations nor their SHA256 values permit a native Popen.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
import stat

_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
_MAX_SOURCE_FILES = 2048
_MAX_SOURCE_FILE_BYTES = 8 * 1024 * 1024
_MAX_SOURCE_BYTES = 128 * 1024 * 1024
_MAX_GO_ARTIFACT_BYTES = 67108864


class R010FiniteIntegrityDenied(ValueError):
    """An observed finite source or output invariant was not established."""


@dataclass(frozen=True, slots=True)
class R010SelectedSourceSnapshot:
    root_identity: tuple[int, int, int, int]
    files: tuple[tuple[str, tuple[int, ...], str], ...]
    total_bytes: int
    status: str = "FINITE_SELECTED_SOURCE_ONLY_NOT_ATTESTED"
    native_launch_allowed: bool = False


@dataclass(frozen=True, slots=True)
class R010GoOutputAbsent:
    parent_identity: tuple[int, int, int, int]
    status: str = "PRE_GO_BUILD_OUTPUT_ABSENT_ONLY"
    native_launch_allowed: bool = False


@dataclass(frozen=True, slots=True)
class R010GoArtifactObservation:
    parent_identity: tuple[int, int, int, int]
    file_identity: tuple[int, ...]
    sha256: str
    size_bytes: int
    status: str = "FINITE_GO_ARTIFACT_ONLY_NOT_ATTESTED"
    native_launch_allowed: bool = False


def _file_identity(st: os.stat_result) -> tuple[int, ...]:
    return (st.st_dev, st.st_ino, st.st_uid, st.st_mode, st.st_nlink,
            st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def _directory_identity(fd: int) -> tuple[int, int, int, int]:
    try:
        st = os.fstat(fd)
    except OSError:
        raise R010FiniteIntegrityDenied("source directory FD unavailable") from None
    if (not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid()
            or stat.S_IMODE(st.st_mode) & 0o022):
        raise R010FiniteIntegrityDenied("directory is not owner-controlled")
    return (st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode))


def _path_parts(relative_path: str) -> tuple[str, ...]:
    if (type(relative_path) is not str or not 1 <= len(relative_path) <= 512
            or relative_path.startswith("/") or "\\" in relative_path
            or "\x00" in relative_path):
        raise R010FiniteIntegrityDenied("invalid selected relative path")
    parts = tuple(relative_path.split("/"))
    if (any(component in ("", ".", "..") or len(component) > 255
            or any(ord(char) < 32 for char in component)
            for component in parts)):
        raise R010FiniteIntegrityDenied("invalid selected path component")
    return parts


def _selected_parent_fd(root_fd: int, parts: tuple[str, ...]) -> int:
    fd = os.dup(root_fd)
    try:
        _directory_identity(fd)
        for component in parts[:-1]:
            next_fd = os.open(component, _DIR_FLAGS, dir_fd=fd)
            try:
                current = os.stat(component, dir_fd=fd, follow_symlinks=False)
                if _file_identity(current) != _file_identity(os.fstat(next_fd)):
                    raise R010FiniteIntegrityDenied("selected ancestor changed")
                _directory_identity(next_fd)
            except BaseException:
                os.close(next_fd)
                raise
            os.close(fd)
            fd = next_fd
        return fd
    except BaseException:
        os.close(fd)
        raise


def _read_regular(parent_fd: int, name: str, *, limit: int,
                  go_executable: bool = False) -> tuple[tuple[int, ...], str]:
    fd = os.open(name, _FILE_FLAGS, dir_fd=parent_fd)
    try:
        before = os.fstat(fd)
        mode = stat.S_IMODE(before.st_mode)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                or before.st_nlink != 1 or mode & 0o022
                or not 0 <= before.st_size <= limit):
            raise R010FiniteIntegrityDenied("unsafe source/output file identity")
        if go_executable and (not 1 <= before.st_size
                              or not (mode & stat.S_IXUSR)):
            raise R010FiniteIntegrityDenied("invalid Go executable artifact")
        digest = hashlib.sha256()
        length = 0
        while True:
            block = os.read(fd, 65536)
            if not block:
                break
            length += len(block)
            if length > limit:
                raise R010FiniteIntegrityDenied("file exceeded bounded observation")
            digest.update(block)
        after = os.fstat(fd)
        entry = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        identity = _file_identity(before)
        if (length != before.st_size or identity != _file_identity(after)
                or identity != _file_identity(entry)):
            raise R010FiniteIntegrityDenied("file changed during observation")
        return identity, digest.hexdigest()
    finally:
        os.close(fd)


def observe_selected_source_files(
    *, root_fd: int, relative_paths: tuple[str, ...],
) -> R010SelectedSourceSnapshot:
    """Observe one reviewed selected set. No untrusted path discovery/approval."""
    if (type(relative_paths) is not tuple
            or not 1 <= len(relative_paths) <= _MAX_SOURCE_FILES
            or any(type(path) is not str for path in relative_paths)
            or tuple(sorted(set(relative_paths))) != relative_paths):
        raise R010FiniteIntegrityDenied("source set must be bounded, unique, sorted")
    root_before = _directory_identity(root_fd)
    rows = []
    total = 0
    try:
        for path in relative_paths:
            parts = _path_parts(path)
            parent_fd = _selected_parent_fd(root_fd, parts)
            try:
                identity, digest = _read_regular(
                    parent_fd, parts[-1], limit=_MAX_SOURCE_FILE_BYTES)
            finally:
                os.close(parent_fd)
            total += identity[5]
            if total > _MAX_SOURCE_BYTES:
                raise R010FiniteIntegrityDenied("selected source budget exceeded")
            rows.append((path, identity, digest))
    except OSError:
        raise R010FiniteIntegrityDenied("selected source unavailable") from None
    if _directory_identity(root_fd) != root_before:
        raise R010FiniteIntegrityDenied("source root drift")
    return R010SelectedSourceSnapshot(root_before, tuple(rows), total)


def recheck_selected_source_files(
    *, root_fd: int, expected: R010SelectedSourceSnapshot,
) -> R010SelectedSourceSnapshot:
    """Return same finite evidence only if selected bytes AND metadata persist."""
    if (type(expected) is not R010SelectedSourceSnapshot
            or expected.native_launch_allowed is not False
            or expected.status != "FINITE_SELECTED_SOURCE_ONLY_NOT_ATTESTED"):
        raise R010FiniteIntegrityDenied("unqualified earlier source observation")
    current = observe_selected_source_files(
        root_fd=root_fd, relative_paths=tuple(row[0] for row in expected.files))
    if current != expected:
        raise R010FiniteIntegrityDenied("selected source changed before/after row")
    return current


def observe_go_output_absent(*, parent_fd: int) -> R010GoOutputAbsent:
    """At pre-row time require bin/app absent; caller pins the bin FD separately."""
    parent = _directory_identity(parent_fd)
    try:
        os.stat("app", dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        if _directory_identity(parent_fd) != parent:
            raise R010FiniteIntegrityDenied("Go output directory drift")
        return R010GoOutputAbsent(parent)
    except OSError:
        raise R010FiniteIntegrityDenied("Go output state unavailable") from None
    raise R010FiniteIntegrityDenied("Go build output is not a new artifact")


def inspect_go_build_artifact(
    *, parent_fd: int, output_was_absent: R010GoOutputAbsent,
) -> R010GoArtifactObservation:
    """Check a newly observed bin/app, not a proof of the Go command's origin."""
    if (type(output_was_absent) is not R010GoOutputAbsent
            or output_was_absent.native_launch_allowed is not False
            or output_was_absent.status != "PRE_GO_BUILD_OUTPUT_ABSENT_ONLY"):
        raise R010FiniteIntegrityDenied("unqualified Go pre-row output")
    parent = _directory_identity(parent_fd)
    if parent != output_was_absent.parent_identity:
        raise R010FiniteIntegrityDenied("Go output parent was replaced")
    try:
        identity, sha256 = _read_regular(
            parent_fd, "app", limit=_MAX_GO_ARTIFACT_BYTES, go_executable=True)
    except OSError:
        raise R010FiniteIntegrityDenied("Go output not an existing regular file") from None
    if _directory_identity(parent_fd) != parent:
        raise R010FiniteIntegrityDenied("Go output parent drift")
    return R010GoArtifactObservation(parent, identity, sha256, identity[5])
