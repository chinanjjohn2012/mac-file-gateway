"""Actual owner-controlled D4 runtime source staging, without execution.

A trusted, separately reviewed provisioner must first place the entire exact
source tree under a SEPARATE owner-controlled <provisioner_root>/{go,bin,lib}.
This PRODUCT module copies those source bytes into a NEW
<private_root>/{go,bin,lib}, using
descriptor-relative nofollow opens and exclusive creation. Neither input
SHA claims nor this stage receipt prove the provider/image, runtime loaded
source graph, whole-descendant CPU/RAM isolation, or an owner T1 grant.

No subprocess, import of staged code, signaling, deletion, overwrite,
overwrite-on-error retry, credential transmission or positive Exec occurs.
Failed partial staging is left quarantined: never claimed to be a usable
runtime and never automatically cleaned up.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
import stat

from .lbe_runtime_tree import (
    D4ClosedTreeSnapshot, D4RuntimeTreeDenied,
    _DIR_FLAGS, _FILE_FLAGS, _MAX_SINGLE_FILE, _MAX_TOTAL_BYTES,
    _identity, _manifest, _parts, _rel,
    inspect_d4_closed_staged_tree,
)


class D4RuntimeStageDenied(ValueError):
    """A private runtime could not be staged from trusted selected bytes."""


_KINDS = frozenset(("go", "bin", "lib"))
_MAX_FILES = 24000


@dataclass(frozen=True, slots=True)
class D4RuntimeStageReceipt:
    source_relative_root: str
    selected_relative_root: str
    entries: int
    files: int
    total_bytes: int
    source_identity_sha256: str
    staged_identity_sha256: str
    status: str = "ACTUAL_PRIVATE_STAGING_SOURCE_ONLY"
    staged_files_verified: bool = True
    owner_provisioner_attested: bool = False
    immutable_runner_image_attested: bool = False
    loaded_runtime_sources_proven: bool = False
    physical_child_resource_enforced: bool = False
    native_launch_allowed: bool = False


def _pinned_root(path: str) -> int:
    """Open the absolute root one component at a time, rejecting symlinks."""
    components = _parts(path, "private runtime root")
    fd = os.open("/", _DIR_FLAGS)
    try:
        for part in components:
            child = os.open(part, _DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = child
        _identity(fd, directory=True)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _relative_directory(fd: int, name: str) -> int:
    """Return owned descriptor for a relative directory, never a pathname."""
    parts = name.split("/") if name else ()
    if parts:
        _rel(name)
    selected = os.dup(fd)
    try:
        for part in parts:
            child = os.open(part, _DIR_FLAGS, dir_fd=selected)
            os.close(selected)
            selected = child
            _identity(selected, directory=True)
        return selected
    except BaseException:
        os.close(selected)
        raise


def _staged_file(
    source_dir: int, target_dir: int, name: str, digest: str,
    total_bytes: int,
) -> tuple[int, int]:
    """Copy one selected source with bounded streaming and mode pinning."""
    src = os.open(name, _FILE_FLAGS, dir_fd=source_dir)
    try:
        src_identity = _identity(src, directory=False)
        length = src_identity[2]
        if (not 0 <= length <= _MAX_SINGLE_FILE
                or total_bytes + length > _MAX_TOTAL_BYTES):
            raise D4RuntimeStageDenied("runtime source exceeds selected byte bound")
        # O_EXCL and O_NOFOLLOW: never overwrite preexisting files, aliases or
        # a previously interrupted staging attempt.
        dst = os.open(
            name, os.O_WRONLY | os.O_CREAT | os.O_EXCL
            | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=target_dir)
        try:
            staged_hash = hashlib.sha256()
            left = length
            while left:
                fragment = os.read(src, min(65536, left))
                if not fragment:
                    raise D4RuntimeStageDenied("source truncated while staging")
                staged_hash.update(fragment)
                left -= len(fragment)
                data = memoryview(fragment)
                while data:
                    written = os.write(dst, data)
                    if written <= 0:
                        raise D4RuntimeStageDenied("staged runtime write failed")
                    data = data[written:]
            if _identity(src, directory=False) != src_identity:
                raise D4RuntimeStageDenied("source inode changed during staging")
            if staged_hash.hexdigest() != digest:
                raise D4RuntimeStageDenied("source byte hash changed during staging")
            # Preserve executable intent, but not source group/other access.
            mode = 0o700 if src_identity[5] & stat.S_IXUSR else 0o600
            os.fchmod(dst, mode)
            os.fsync(dst)
            target_identity = _identity(dst, directory=False)
            if target_identity[2] != length or stat.S_IMODE(target_identity[5]) != mode:
                raise D4RuntimeStageDenied("staged source mode or size drift")
        finally:
            os.close(dst)
        return length, 1
    finally:
        os.close(src)


def stage_d4_operator_runtime_tree(
    *, private_root: str, provisioner_root: str, kind: str,
    expected: tuple[tuple[str, str | None], ...],
) -> D4RuntimeStageReceipt:
    """Exclusively stage one fixed toolchain tree using actual file bytes.

    The candidate input root is exactly <provisioner_root>/{go,bin,lib},
    placed by a separately trusted operator OUTSIDE the private runtime root.
    Both roots are owned and nofollow-walked; overlapping provisioner/runner
    roots are rejected. The output tree must NOT exist. Source is checked
    before and after
    staging, and the entire output is inspected before a receipt is returned.
    Failure leaves an unusable partial tree intact (no destructive rollback).
    No caller-controlled target path or executable permission is accepted.
    """
    if type(kind) is not str or kind not in _KINDS:
        raise D4RuntimeStageDenied("unapproved runtime staging target")
    try:
        _parts(private_root, "private runtime root")
        _parts(provisioner_root, "operator provisioner root")
        if (private_root == provisioner_root
                or private_root.startswith(provisioner_root + "/")
                or provisioner_root.startswith(private_root + "/")):
            raise D4RuntimeStageDenied(
                "trusted source and private runtime roots must not overlap")
        wanted = _manifest(expected)
        if len(wanted) > _MAX_FILES:
            raise D4RuntimeStageDenied("too many staged runtime files")
        source_rel = kind
        source_path = provisioner_root + "/" + source_rel
        target_path = private_root + "/" + kind
        source_before = inspect_d4_closed_staged_tree(
            private_root=provisioner_root, staged_root=source_path,
            expected=expected)
        root_fd = _pinned_root(private_root)
        try:
            provisioner_fd = _pinned_root(provisioner_root)
            try:
                if os.fstat(root_fd).st_dev == os.fstat(provisioner_fd).st_dev and (
                    os.fstat(root_fd).st_ino == os.fstat(provisioner_fd).st_ino
                ):
                    raise D4RuntimeStageDenied("source and runtime roots alias")
            finally:
                os.close(provisioner_fd)
            # Missing destination required. Do not follow or replace any
            # symlink/dir/file from a failed prior attempt.
            try:
                os.stat(kind, dir_fd=root_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise D4RuntimeStageDenied("staged runtime destination already exists")
            provisioner_fd = _pinned_root(provisioner_root)
            try:
                source_fd = _relative_directory(provisioner_fd, source_rel)
            finally:
                os.close(provisioner_fd)
            try:
                os.mkdir(kind, 0o700, dir_fd=root_fd)
                target_fd = _relative_directory(root_fd, kind)
                try:
                    # Parent directories always precede their children.
                    directories = sorted(
                        (path for path, sha in wanted.items()
                         if path and sha is None),
                        key=lambda p: (p.count("/"), p))
                    for path in directories:
                        parent, _sep, leaf = path.rpartition("/")
                        target_parent = _relative_directory(target_fd, parent)
                        source_parent = _relative_directory(source_fd, parent)
                        try:
                            src_child = os.open(leaf, _DIR_FLAGS,
                                                dir_fd=source_parent)
                            try:
                                _identity(src_child, directory=True)
                            finally:
                                os.close(src_child)
                            os.mkdir(leaf, 0o700, dir_fd=target_parent)
                        finally:
                            os.close(source_parent)
                            os.close(target_parent)
                    total, files = 0, 0
                    for path, sha in sorted(wanted.items()):
                        if sha is None:
                            continue
                        parent, _sep, leaf = path.rpartition("/")
                        source_parent = _relative_directory(source_fd, parent)
                        target_parent = _relative_directory(target_fd, parent)
                        try:
                            added, file_count = _staged_file(
                                source_parent, target_parent, leaf, sha, total)
                            total += added
                            files += file_count
                        finally:
                            os.close(target_parent)
                            os.close(source_parent)
                finally:
                    os.close(target_fd)
            finally:
                os.close(source_fd)
        finally:
            os.close(root_fd)
        source_after = inspect_d4_closed_staged_tree(
            private_root=provisioner_root, staged_root=source_path,
            expected=expected)
        target = inspect_d4_closed_staged_tree(
            private_root=private_root, staged_root=target_path,
            expected=expected)
        if (source_after != source_before
                or files != target.file_count
                or total != target.total_file_bytes
                or target.entry_count != len(wanted)):
            raise D4RuntimeStageDenied("source or runtime changed during staging")
        return D4RuntimeStageReceipt(
            source_relative_root=source_rel, selected_relative_root=kind,
            entries=target.entry_count, files=files, total_bytes=total,
            source_identity_sha256=source_before.observed_identity_sha256,
            staged_identity_sha256=target.observed_identity_sha256,
        )
    except (OSError, D4RuntimeTreeDenied, D4RuntimeStageDenied) as exc:
        if type(exc) is D4RuntimeStageDenied:
            raise
        raise D4RuntimeStageDenied(
            "runtime staging source, destination or admission unavailable"
        ) from None


def create_d4_fresh_runner_scratch(
    *, private_root: str, kind: str,
) -> tuple[str, ...]:
    """Create the exact EMPTY private HOME/TMP and Go cache/input domains.

    An existing path, even an empty one, is not a fresh trusted domain.
    This uses exclusively owner-held dirfds and nofollow creation. If an
    attempt fails, no cleanup, overwrite or automatic retry is performed.
    This creates directories only; it does NOT enforce CPU/RAM or network.
    """
    if type(kind) is not str or kind not in {"go", "pipenv", "python_direct"}:
        raise D4RuntimeStageDenied("unapproved scratch runtime kind")
    names = (("home", "tmp", "gopath", "modcache", "gocache", "gotmp")
             if kind == "go" else ("home", "tmp"))
    try:
        fd = _pinned_root(private_root)
        try:
            # Refuse all preexisting paths before creating any new directory.
            for name in names:
                try:
                    os.stat(name, dir_fd=fd, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                else:
                    raise D4RuntimeStageDenied(
                        "preexisting runner scratch or cache must be absent")
            for name in names:
                os.mkdir(name, 0o700, dir_fd=fd)
                child = os.open(name, _DIR_FLAGS, dir_fd=fd)
                try:
                    identity = _identity(child, directory=True)
                    if stat.S_IMODE(identity[5]) != 0o700:
                        raise D4RuntimeStageDenied(
                            "fresh scratch directory permission drift")
                    with os.scandir(child) as contents:
                        if next(contents, None) is not None:
                            raise D4RuntimeStageDenied(
                                "fresh scratch directory is not empty")
                finally:
                    os.close(child)
        finally:
            os.close(fd)
        return names
    except (OSError, D4RuntimeTreeDenied, D4RuntimeStageDenied) as exc:
        if type(exc) is D4RuntimeStageDenied:
            raise
        raise D4RuntimeStageDenied("fresh private scratch admission failed") from None
