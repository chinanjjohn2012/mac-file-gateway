"""R010 exact six-command finite row filesystem gates (non-operative).

Enforces the immutable R003/R010 six plan identities, checks a reviewed
selected source set twice via pinned FDs, observes a bounded private output/
cache tree before and after each row, restricts changes to the *current*
row's private cache namespace, and validates Go's new bin/app artifact.
No host-wide writes, transient mutations or descendant cleanup are proven.
This source NEVER runs a child, issues a grant, or returns T1 acceptance.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
import re
import stat

from .lbe_worker import LbeWorkPlan, LbeWorker, LbeWorkerError
from .lbe_r010_finite_integrity import (
    R010FiniteIntegrityDenied, R010GoOutputAbsent,
    R010SelectedSourceSnapshot, _directory_identity, _file_identity,
    _read_regular, inspect_go_build_artifact, recheck_selected_source_files,
)

_DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_HEX = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_MAX_ENTRIES = 4096
_MAX_DEPTH = 12
_MAX_BYTES = 128 * 1024 * 1024
_MAX_FILE_BYTES = 8 * 1024 * 1024

# Contract row order is fixed, including requested -> effective argv and cwd.
_ROWS = (
    ("py-direct", "direct", ("python", "-m", "pytest", "-q"), None),
    ("py-direct", "direct", ("python", "-m", "compileall", "-q", "./src"), None),
    ("py-pipenv", "pipenv", ("python", "-m", "pytest", "-q"), None),
    ("go-project", "direct", ("go", "test", "./..."), None),
    ("go-project", "direct", ("go", "vet", "./..."), None),
    ("go-project", "direct", ("go", "build", "-o", "bin/app", "./cmd/app"),
     "go-project/bin/app"),
)


class R010RowFiniteDenied(ValueError):
    """An exact row plan or observed private filesystem delta was unqualified."""


@dataclass(frozen=True, slots=True)
class R010PrivateTreeSnapshot:
    root_identity: tuple[int, int, int, int]
    entries: tuple[tuple[str, str, tuple[int, ...], str | None], ...]
    bytes_observed: int
    status: str = "PINNED_PRIVATE_TREE_FINITE_SNAPSHOT_ONLY"
    native_launch_allowed: bool = False


@dataclass(frozen=True, slots=True)
class R010FiniteRowObservation:
    row: int
    requested_argv: tuple[str, ...]
    effective_argv: tuple[str, ...]
    changed_private_paths: tuple[str, ...]
    private_tree_before_sha256: str
    private_tree_after_sha256: str
    go_build_artifact_sha256: str | None
    status: str = "FINITE_SOURCE_AND_PRIVATE_DELTAS_VALID_NOT_T1"
    selected_source_stable: bool = True
    finite_private_delta_valid: bool = True
    transient_mutation_absence_proven: bool = False
    unobserved_host_side_effects_proven_absent: bool = False
    native_launch_allowed: bool = False
    row_positive_success: bool = False
    six_command_product_t1_pass: bool = False


def validate_r010_fixed_row_plan(row: int, plan: LbeWorkPlan) -> None:
    """No unreviewed runner, command, workspace or output recipe."""
    if type(row) is not int or not 1 <= row <= 6:
        raise R010RowFiniteDenied("invalid six-command row")
    if type(plan) is not LbeWorkPlan:
        raise R010RowFiniteDenied("untrusted WorkPlan")
    workspace, runner, requested, output = _ROWS[row - 1]
    effective = (("pipenv", "run", *requested) if runner == "pipenv"
                 else requested)
    try:
        LbeWorker._check_plan(plan)
    except LbeWorkerError:
        raise R010RowFiniteDenied("unqualified Worker plan") from None
    # Exact type checks above must precede equality on any user-supplied type.
    if (plan.workspace != workspace or plan.cwd != workspace
            or plan.runner_project != workspace or plan.runner != runner
            or plan.requested_argv != requested
            or plan.effective_argv != effective
            or plan.planned_go_output != output
            or plan.planned_script_sha256 is not None
            or (row == 3 and
                (type(plan.planned_pipfile_sha256) is not str
                 or _HEX.fullmatch(plan.planned_pipfile_sha256) is None))
            or (row != 3 and plan.planned_pipfile_sha256 is not None)
            or plan.timeout_seconds > 120):
        raise R010RowFiniteDenied("wrong R010 fixed command/runner/fixture")


def _private_name(name: str) -> None:
    if (type(name) is not str or not 1 <= len(name) <= 255
            or name in (".", "..") or "/" in name or "\\" in name
            or any(ord(ch) < 33 or ord(ch) > 126 for ch in name)):
        raise R010RowFiniteDenied("invalid private inventory entry name")


def _mode_safe(st: os.stat_result, *, directory: bool) -> None:
    if (st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) & 0o022
            or (not stat.S_ISDIR(st.st_mode) if directory
                else (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1))):
        raise R010RowFiniteDenied("unsafe private filesystem entry")


def observe_r010_private_tree(*, root_fd: int) -> R010PrivateTreeSnapshot:
    """Observe all finite regular/dir nodes without following any symlink.

    This is only an endpoint snapshot. A deleted/transient write may escape it.
    """
    try:
        identity = _directory_identity(root_fd)
        rows: list[tuple[str, str, tuple[int, ...], str | None]] = []
        byte_count = 0

        def walk(fd: int, prefix: str, depth: int) -> None:
            nonlocal byte_count
            if depth > _MAX_DEPTH:
                raise R010RowFiniteDenied("private tree depth exceeded")
            origin = os.fstat(fd)
            _mode_safe(origin, directory=True)
            names = os.listdir(fd)
            if len(names) + len(rows) > _MAX_ENTRIES:
                raise R010RowFiniteDenied("private inventory count exceeded")
            for name in sorted(names):
                _private_name(name)
                path = prefix + name
                before = os.stat(name, dir_fd=fd, follow_symlinks=False)
                if stat.S_ISDIR(before.st_mode):
                    _mode_safe(before, directory=True)
                    child = os.open(name, _DIRECTORY, dir_fd=fd)
                    try:
                        opened = os.fstat(child)
                        if _file_identity(opened) != _file_identity(before):
                            raise R010RowFiniteDenied("private directory replaced")
                        # Directory ctime/mtime may change for valid children;
                        # preserve stable inode/owner/mode identity only.
                        # Creating a valid child directory increments
                        # its parent's st_nlink, not its inode/ownership.
                        # Compare parent inode, owner and mode, while checking
                        # every newly observed child against this row's policy.
                        ident = (before.st_dev, before.st_ino, before.st_uid,
                                 before.st_mode)
                        rows.append((path, "dir", ident, None))
                        walk(child, path + "/", depth + 1)
                        # Recheck the name -> pinned child identity after
                        # traversal; a replaced ancestor must not be trusted.
                        end_entry = os.stat(
                            name, dir_fd=fd, follow_symlinks=False)
                        if ((end_entry.st_dev, end_entry.st_ino,
                             end_entry.st_uid, end_entry.st_mode) != ident):
                            raise R010RowFiniteDenied(
                                "private directory entry replaced during scan")
                    finally:
                        os.close(child)
                elif stat.S_ISREG(before.st_mode):
                    _mode_safe(before, directory=False)
                    if before.st_size > _MAX_FILE_BYTES:
                        raise R010RowFiniteDenied("private file too large")
                    file_id, digest = _read_regular(
                        fd, name, limit=_MAX_FILE_BYTES)
                    if file_id != _file_identity(before):
                        raise R010RowFiniteDenied("private file changed")
                    byte_count += before.st_size
                    if byte_count > _MAX_BYTES:
                        raise R010RowFiniteDenied("private tree byte budget exceeded")
                    rows.append((path, "file", file_id, digest))
                else:
                    # No symlink, FIFO, socket, device, or hardlink escape.
                    raise R010RowFiniteDenied("nonregular private tree entry")
                if len(rows) > _MAX_ENTRIES:
                    raise R010RowFiniteDenied("private inventory cap exceeded")
            end = os.fstat(fd)
            if ((origin.st_dev, origin.st_ino, origin.st_uid, origin.st_mode)
                    != (end.st_dev, end.st_ino, end.st_uid, end.st_mode)):
                raise R010RowFiniteDenied("private tree directory drift")

        walk(root_fd, "", 0)
        if _directory_identity(root_fd) != identity:
            raise R010RowFiniteDenied("private tree root drift")
    except (OSError, R010FiniteIntegrityDenied):
        raise R010RowFiniteDenied("private tree snapshot unavailable") from None
    return R010PrivateTreeSnapshot(identity, tuple(rows), byte_count)


def _allowed_delta(row: int, path: str, kind: str) -> bool:
    """Only reviewed PRIVATE cache namespaces; never arbitrary host paths."""
    if row in (1, 3):
        parts = path.split("/")
        if parts[0] not in ("pytest-cache", "python-cache"):
            return False
        # Do not admit native-loader paths into a Python cache tree.
        return not (kind == "file" and parts[-1].endswith((
            ".pth", ".so", ".dylib", ".dll", ".py")))
    if row == 2:
        parts = path.split("/")
        if parts[0] != "src" or "__pycache__" not in parts:
            return False
        if kind == "dir":
            return "__pycache__" in parts
        return (kind == "file" and len(parts) >= 3
                and parts[-2] == "__pycache__" and parts[-1].endswith(".pyc"))
    if row in (4, 5, 6):
        return path.split("/")[0] in ("go-cache", "go-tmp")
    return False


def _tree_digest(snapshot: R010PrivateTreeSnapshot) -> str:
    rows = [str(snapshot.root_identity), str(snapshot.bytes_observed)]
    for row in snapshot.entries:
        rows.append(repr(row))
    return hashlib.sha256(("\n".join(rows) + "\n").encode("ascii")).hexdigest()


def _require_same_pinned_go_bin(
    *, workspace_fd: int, output_fd: int,
) -> None:
    """Prove Go row 6's bin FD is the exact workspace-relative ./bin.

    The user-selected source root must be the reviewed go-project workspace
    root. This check is *path binding*, not evidence of original Popen target.
    """
    try:
        _directory_identity(workspace_fd)
        pinned = _directory_identity(output_fd)
        entry = os.stat("bin", dir_fd=workspace_fd, follow_symlinks=False)
        observed = (entry.st_dev, entry.st_ino, entry.st_uid,
                    entry.st_mode & 0o7777)
        expected = (pinned[0], pinned[1], pinned[2], pinned[3] & 0o7777)
        if not stat.S_ISDIR(entry.st_mode) or observed != expected:
            raise R010RowFiniteDenied("Go output parent not the selected bin")
    except (OSError, R010FiniteIntegrityDenied):
        raise R010RowFiniteDenied("Go output bin path not pinned") from None


def verify_r010_finite_row_after(
    *, row: int, plan: LbeWorkPlan,
    selected_root_fd: int, selected_before: R010SelectedSourceSnapshot,
    private_root_fd: int, private_before: R010PrivateTreeSnapshot,
    go_output_parent_fd: int | None = None,
    go_output_before: R010GoOutputAbsent | None = None,
) -> R010FiniteRowObservation:
    """Real bounded post-observation; cannot convert a Worker exit into T1."""
    validate_r010_fixed_row_plan(row, plan)
    if (type(selected_before) is not R010SelectedSourceSnapshot
            or type(private_before) is not R010PrivateTreeSnapshot
            or private_before.native_launch_allowed is not False
            or private_before.status != "PINNED_PRIVATE_TREE_FINITE_SNAPSHOT_ONLY"):
        raise R010RowFiniteDenied("not a trusted finite BEFORE observation")
    if row == 6:
        if (type(go_output_parent_fd) is not int
                or type(go_output_before) is not R010GoOutputAbsent):
            raise R010RowFiniteDenied("Go build output pre-absence not proven")
    elif go_output_parent_fd is not None or go_output_before is not None:
        raise R010RowFiniteDenied("unexpected Go build artifact witness")
    try:
        recheck_selected_source_files(
            root_fd=selected_root_fd, expected=selected_before)
        private_after = observe_r010_private_tree(root_fd=private_root_fd)
        if private_after.root_identity != private_before.root_identity:
            raise R010RowFiniteDenied("private output tree identity changed")
        before = {r[0]: r for r in private_before.entries}
        after = {r[0]: r for r in private_after.entries}
        changed = tuple(sorted(
            path for path in set(before) | set(after)
            if before.get(path) != after.get(path)))
        # Changes to reviewed private cache paths, not to selected source.
        for path in changed:
            item = after.get(path) or before.get(path)
            if item is None or not _allowed_delta(row, path, item[1]):
                raise R010RowFiniteDenied("unreviewed private file delta")
        artifact = None
        if row == 6:
            _require_same_pinned_go_bin(
                workspace_fd=selected_root_fd, output_fd=go_output_parent_fd)
            artifact = inspect_go_build_artifact(
                parent_fd=go_output_parent_fd,
                output_was_absent=go_output_before)
            _require_same_pinned_go_bin(
                workspace_fd=selected_root_fd, output_fd=go_output_parent_fd)
    except (R010FiniteIntegrityDenied, OSError):
        raise R010RowFiniteDenied("finite source, tree, or artifact failed") from None
    # Even a finite PASS is not original-child exit0/Grant/native T1 evidence.
    return R010FiniteRowObservation(
        row=row, requested_argv=plan.requested_argv,
        effective_argv=plan.effective_argv,
        changed_private_paths=changed,
        private_tree_before_sha256=_tree_digest(private_before),
        private_tree_after_sha256=_tree_digest(private_after),
        go_build_artifact_sha256=None if artifact is None else artifact.sha256,
    )
