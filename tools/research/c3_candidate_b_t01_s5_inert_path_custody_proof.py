"""B03-T01 S5 PARTIAL: inert-file pathname/FD custody evidence, NO LOAD.

Only a fresh, non-executable DATA fixture inside a 0700 private temporary
directory is inspected. No candidate C object or shared library is compiled,
linked, loaded or invoked. Descriptor/path observations cannot demonstrate
that a future OS dynamic loader will open this very inode; same-UID writers,
concurrent replacement and loader dependency resolution remain UNPROVEN.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
import tempfile

import c3_candidate_b_t01_s0_abi_proof as s0

ROOT = s0.ROOT
MANIFEST = s0.MANIFEST
PARENT_HEAD = "4f388a0344fbd2326574ba7d82f9c1eb5d6cfd1c"
PARENT_TREE = "3af5720dd01553cc189174fbd0365cdff37e1fcc"
LEAF = "inert-path-custody-observation.data"
FIXTURE = (
    b"C3_B03_T01_S5_INERT_DATA_ONLY\n"
    b"THIS_IS_NOT_A_C_OBJECT_OR_SHARED_LIBRARY\n"
    b"NO_LOAD_NO_C_EXEC_NO_GROUP_SIGNALS\n"
)
FIXTURE_SHA256 = hashlib.sha256(FIXTURE).hexdigest()
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)


def _identity(s: os.stat_result) -> tuple[int, ...]:
    return (
        s.st_dev, s.st_ino, s.st_uid, s.st_nlink, stat.S_IMODE(s.st_mode),
        s.st_size, s.st_mtime_ns, s.st_ctime_ns,
    )


def _private_directory_fd(root: Path) -> tuple[int, os.stat_result]:
    """Fail closed on symlink aliases or untrusted ancestor write permission.

    Root-owned sticky temporary parents are allowed. This is NOT equivalent
    to proving absence of same-UID writers or the future dynamic loader path.
    """
    if not (_O_NOFOLLOW and _O_DIRECTORY):
        raise ValueError("NOFOLLOW_DIRECTORY_SUPPORT_REQUIRED")
    if not root.is_absolute() or root.is_symlink():
        raise ValueError("UNCANONICAL_OR_LINKED_ROOT")
    try:
        if root.resolve(strict=True) != root:
            raise ValueError("ROOT_HAS_SYMLINK_ANCESTOR")
        observed = os.lstat(root)
        for ancestor in (root, *root.parents):
            node = os.lstat(ancestor)
            if not stat.S_ISDIR(node.st_mode):
                raise ValueError("NOT_A_DIRECTORY_ANCESTOR")
            if ancestor == root:
                if (node.st_uid != os.getuid() or
                        stat.S_IMODE(node.st_mode) != 0o700):
                    raise ValueError("ROOT_NOT_PRIVATE_OWNED_0700")
            elif stat.S_IMODE(node.st_mode) & 0o022:
                # The OS-owned sticky parent is the narrow exception for
                # macOS/Linux temporary directories, not for arbitrary
                # group/world-writable workspace ancestors.
                if not (node.st_uid == 0 and node.st_mode & stat.S_ISVTX):
                    raise ValueError("UNTRUSTED_WRITABLE_ANCESTOR")
        fd = os.open(
            root, os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW | _O_CLOEXEC
        )
    except (FileNotFoundError, PermissionError, OSError) as exc:
        raise ValueError("UNSAFE_ROOT_OBSERVATION") from exc
    after = os.fstat(fd)
    if not stat.S_ISDIR(after.st_mode) or _identity(after) != _identity(observed):
        os.close(fd)
        raise ValueError("ROOT_CHANGED_BEFORE_DIRECTORY_FD")
    return fd, after


def _create_fixture(root: Path) -> None:
    """Write only the fixed inert data bytes into a new exclusively created file."""
    dfd, _ = _private_directory_fd(root)
    try:
        fd = os.open(
            LEAF, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW |
            _O_CLOEXEC, 0o600, dir_fd=dfd
        )
        try:
            data = memoryview(FIXTURE)
            while len(data):
                n = os.write(fd, data)
                if n <= 0:
                    raise ValueError("INERT_FIXTURE_SHORT_WRITE")
                data = data[n:]
            os.fchmod(fd, 0o400)
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        os.close(dfd)


def _observe_once(root: Path) -> dict[str, object]:
    """Bind a *current read* to dir_fd, file FD and post-observation path.

    The FD is intentionally closed before returning. No loader is invoked.
    This has no right to claim future path->loader check/use atomicity.
    """
    dfd, directory = _private_directory_fd(root)
    try:
        try:
            before = os.stat(LEAF, dir_fd=dfd, follow_symlinks=False)
        except (OSError, ValueError) as exc:
            raise ValueError("INERT_FILE_MISSING") from exc
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("INERT_NOT_REGULAR")
        if (before.st_uid != os.getuid() or before.st_nlink != 1 or
                stat.S_IMODE(before.st_mode) != 0o400 or
                before.st_size != len(FIXTURE)):
            raise ValueError("INERT_FILE_OWNER_MODE_NLINK_OR_SIZE")
        try:
            fd = os.open(
                LEAF, os.O_RDONLY | _O_NOFOLLOW | _O_CLOEXEC, dir_fd=dfd
            )
        except OSError as exc:
            raise ValueError("INERT_OPEN_NOFOLLOW_FAILED") from exc
        try:
            start = os.fstat(fd)
            if (not stat.S_ISREG(start.st_mode) or
                    _identity(start) != _identity(before)):
                raise ValueError("INERT_FD_PATH_IDENTITY_MISMATCH")
            digest = hashlib.sha256()
            while True:
                part = os.read(fd, 65536)
                if not part:
                    break
                digest.update(part)
            end = os.fstat(fd)
            if _identity(end) != _identity(start):
                raise ValueError("INERT_FD_CHANGED_DURING_HASH")
            if digest.hexdigest() != FIXTURE_SHA256:
                raise ValueError("INERT_CONTENT_SHA_CHANGED")
            after = os.stat(LEAF, dir_fd=dfd, follow_symlinks=False)
            if not stat.S_ISREG(after.st_mode) or (
                _identity(after) != _identity(start)
            ):
                raise ValueError("INERT_PATH_CHANGED_DURING_HASH")
        finally:
            os.close(fd)
        root_after = os.fstat(dfd)
        if _identity(directory) != _identity(root_after):
            raise ValueError("INERT_ROOT_FD_CHANGED")
        path_dir = os.lstat(root)
        if _identity(path_dir) != _identity(directory):
            raise ValueError("INERT_ROOT_PATH_CHANGED")
        return {
            "leaf_sha256": digest.hexdigest(),
            "leaf_dev": start.st_dev, "leaf_ino": start.st_ino,
            "leaf_uid": start.st_uid, "leaf_nlink": start.st_nlink,
            "leaf_mode": stat.S_IMODE(start.st_mode),
            "leaf_size": start.st_size,
            "leaf_mtime_ns": start.st_mtime_ns,
            "leaf_ctime_ns": start.st_ctime_ns,
            "root_dev": directory.st_dev, "root_ino": directory.st_ino,
            "root_uid": directory.st_uid,
            "root_mode": stat.S_IMODE(directory.st_mode),
            "observed_fd_path_identical_during_this_read": True,
        }
    finally:
        os.close(dfd)


def _compare_observations(first: dict[str, object],
                          second: dict[str, object]) -> str:
    """Reject SAME-BYTES inode replacement and changed metadata.

    Stable before/after observations DO NOT grant future loader authority.
    """
    if type(first) is not dict or type(second) is not dict:
        raise ValueError("INVALID_CUSTODY_EVIDENCE")
    required = frozenset({
        "leaf_sha256", "leaf_dev", "leaf_ino", "leaf_uid", "leaf_nlink",
        "leaf_mode", "leaf_size", "leaf_mtime_ns", "leaf_ctime_ns",
        "root_dev", "root_ino", "root_uid", "root_mode",
        "observed_fd_path_identical_during_this_read",
    })
    if set(first) != required or set(second) != required:
        raise ValueError("INCOMPLETE_CUSTODY_EVIDENCE")
    if first != second:
        raise ValueError("INERT_IDENTITY_CHANGED_BETWEEN_OBSERVATIONS")
    if first["observed_fd_path_identical_during_this_read"] is not True:
        raise ValueError("INERT_CURRENT_FD_PATH_UNBOUND")
    return "UNCHANGED_STATIC_OBSERVATION_NOT_LOADER_CUSTODY"


def collect_static_s5_evidence() -> dict[str, object]:
    """Temporary inert-file static evidence; no object/shared image or loader."""
    items = s0.checked_manifest()
    head, tree = s0.current_revision()
    if items["./tools/research/c3_candidate_b_t01_no_signal_candidate.c"] != (
        s0.REVIEWED_C_SHA256
    ) or items["./tests/native/c3_b03_t01_no_signal_contract.h"] != (
        s0.REVIEWED_HEADER_SHA256
    ):
        raise ValueError("FROZEN_C_INPUT_CHANGED")
    with tempfile.TemporaryDirectory(
        prefix="c3b03-s5-inert-data-no-load-"
    ) as temp:
        root = Path(temp).resolve(strict=True)
        _create_fixture(root)
        observed_a = _observe_once(root)
        observed_b = _observe_once(root)
        status = _compare_observations(observed_a, observed_b)
    if root.exists():
        raise ValueError("INERT_TEMP_NOT_DISCARDED")
    return {
        "current_head": head, "current_tree": tree,
        "reviewed_s4_parent_head": PARENT_HEAD,
        "reviewed_s4_parent_tree": PARENT_TREE,
        "manifest_sha256": s0._sha_regular(MANIFEST)[0],
        "reviewed_c_source_sha256": s0._sha_regular(s0.SOURCE)[0],
        "reviewed_c_header_sha256": s0._sha_regular(s0.HEADER)[0],
        "inert_file_snapshot": observed_a,
        "inert_file_sha256": observed_a["leaf_sha256"],
        "same_content_and_inode_observed_twice": status,
        "inert_temporary_directory_discarded": True,
        "candidate_c_compiled": False, "candidate_c_executed": False,
        "candidate_shared_library_linked": False,
        "candidate_shared_library_loaded": False,
        "native_loader_invoked": False, "native_dispatches": 0,
        "future_loader_same_inode_proven": False,
        "atomic_loader_check_use_proven": False,
        "same_uid_writer_absence_proven": False,
        "loader_dependency_resolution_proven": False,
        "complete_toolchain_sdk_closure_proven": False,
        "complete_final_cfg_proven": False,
        "complete_python_ffi_import_graph_proven": False,
        "first_c_load_authorized": False,
        "group_kill_authorized": False, "reuse_proven": False,
        "g2_qualified": False, "admission": "REVIEW_REQUIRED_NO_LOAD",
    }
