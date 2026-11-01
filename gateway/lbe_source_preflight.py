"""NONOPERATIVE M1 source-admission T0 checks for proposed Go/Pipenv.

No import/install, subprocess, egress enforcement, product grant or runtime T1.
These functions can report only SOURCE_CANDIDATE, NEVER execution permission.
The ordinary F1 WorkspaceService and lbe_native_launcher denial are unchanged.
A trusted caller must supply an independently approved private base path,
source digest map and parent PATH. No approval or runtime source identity is granted.
The same-UID race and actual loaded runtime still require separate review.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import stat
from typing import Mapping

_SHA = re.compile(r"[0-9a-f]{64}\Z")
_GO_CRITICAL = frozenset({
    "go/VERSION",
    "go/bin/go",
    "go/pkg/tool/darwin_arm64/compile",
    "go/pkg/tool/darwin_arm64/link",
    "go/src/runtime/proc.go",
})
_PIPENV_CRITICAL = frozenset({
    "project/Pipfile", "project/Pipfile.lock",
    "project/.venv/pyvenv.cfg", "project/.venv/bin/python",
})
_FORBIDDEN_SHARED = frozenset({
    "CC", "CXX", "GCCGO", "PKG_CONFIG", "BASH_ENV", "ENV",
    "PYTHONPATH", "PYTHONHOME", "PYTHONUSERBASE",
    "PYTHONSTARTUP", "PYTHONINSPECT", "PIP_CONFIG_FILE",
})
_PIPENV_SELECTORS = frozenset({
    "WORKON_HOME", "VIRTUAL_ENV", "PIPENV_ACTIVE",
    "PIPENV_PYTHON", "PIPENV_VIRTUALENV",
})
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_FLAGS = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC
_MAX_SOURCE_MEMBER_BYTES = 128 * 1024 * 1024
_MAX_SOURCE_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
_MAX_SOURCE_MEMBERS = 20000


class LbeSourcePreflightError(ValueError):
    """Candidate is not safe to select for any future native T1."""


def _relative_parts(value: str) -> tuple[str, ...]:
    if (type(value) is not str or not value or value.startswith(("/", "~"))
            or "\\" in value or "\x00" in value):
        raise LbeSourcePreflightError("relative source member required")
    parts = tuple(value.split("/"))
    if any(part in {"", ".", ".."} or not re.fullmatch(r"[A-Za-z0-9_.-]+", part)
           for part in parts):
        raise LbeSourcePreflightError("unsafe source member")
    return parts


def _open_checked_dir(parent_fd: int, part: str, *, role: str) -> int:
    """Pin one no-follow component; close on even an injected fstat failure.

    Untrusted ancestors above the approved base need only be directories with
    no symlink. The approved base/root must be private and exclusively owned;
    intermediate descendants must be owned and not writable by group/other.
    """
    child = -1
    accepted = False
    try:
        child = os.open(part, _DIR_FLAGS, dir_fd=parent_fd)
        before = os.fstat(child)
        entry = os.stat(part, dir_fd=parent_fd, follow_symlinks=False)
        if (not stat.S_ISDIR(before.st_mode)
                or not stat.S_ISDIR(entry.st_mode)
                or before.st_dev != entry.st_dev or before.st_ino != entry.st_ino
                or before.st_mode != entry.st_mode or before.st_uid != entry.st_uid):
            raise LbeSourcePreflightError("source directory identity changed")
        if role in {"private", "owned"}:
            if before.st_uid != os.getuid() or before.st_mode & 0o022:
                raise LbeSourcePreflightError("source directory owner/mode denied")
        if role == "private" and before.st_mode & 0o077:
            raise LbeSourcePreflightError("private source directory is not private")
        accepted = True
        return child
    except OSError as exc:
        raise LbeSourcePreflightError("source directory absent or unsafe") from exc
    finally:
        if child >= 0 and not accepted:
            os.close(child)


def _check_private_root(root: Path, *, trusted_base: Path) -> int:
    """Open every absolute ancestor from '/' without following any symlink.

    trusted_base must be an independently selected private staging directory,
    never a value supplied by an HTTP/MCP request or inferred from an argv.
    The same-UID path replacement risk remains outside this T0-only proof.
    """
    if (not isinstance(root, Path) or not isinstance(trusted_base, Path)
            or not root.is_absolute() or not trusted_base.is_absolute()):
        raise LbeSourcePreflightError("absolute root and trusted base required")
    root_parts, base_parts = root.parts, trusted_base.parts
    if (".." in root_parts or ".." in base_parts
            or len(base_parts) < 2
            or len(root_parts) <= len(base_parts)
            or root_parts[:len(base_parts)] != base_parts):
        raise LbeSourcePreflightError("root must be below an approved canonical base")
    held: list[int] = []
    try:
        held.append(os.open("/", _DIR_FLAGS))
        for index, part in enumerate(root_parts[1:], start=1):
            last_root = index == len(root_parts) - 1
            last_base = index == len(base_parts) - 1
            role = ("private" if last_base or last_root
                    else "ancestor" if index < len(base_parts) - 1
                    else "owned")
            held.append(_open_checked_dir(held[-1], part, role=role))
        return held.pop()
    except OSError as exc:
        raise LbeSourcePreflightError("private root not accessible") from exc
    finally:
        for fd in reversed(held):
            os.close(fd)


def _check_directory(fd: int, part: str) -> int:
    return _open_checked_dir(fd, part, role="owned")


def _validate_source_manifest(manifest: Mapping[str, str],
                              critical: frozenset[str]) -> None:
    if (not isinstance(manifest, Mapping)
            or len(manifest) < len(critical)
            or len(manifest) > _MAX_SOURCE_MEMBERS
            or not critical.issubset(manifest)):
        raise LbeSourcePreflightError("critical source manifest incomplete or oversized")
    for name, digest in manifest.items():
        _relative_parts(name)
        if type(digest) is not str or not _SHA.fullmatch(digest):
            raise LbeSourcePreflightError("invalid source digest")


def _inspect_members(root: int, expected_members: Mapping[str, str],
                     *, executables: frozenset[str]) -> dict[str, str]:
    checked: dict[str, str] = {}
    remaining = _MAX_SOURCE_TOTAL_BYTES
    for name in sorted(expected_members):
        digest, size = _verified_member(
            root, name, expected_members[name], executable=name in executables,
            max_bytes=min(_MAX_SOURCE_MEMBER_BYTES, remaining))
        checked[name] = digest
        remaining -= size
    return checked


def _verified_member(root_fd: int, name: str, expected_sha: str,
                     *, executable: bool = False,
                     max_bytes: int = _MAX_SOURCE_MEMBER_BYTES) -> tuple[str, int]:
    if type(expected_sha) is not str or not _SHA.fullmatch(expected_sha):
        raise LbeSourcePreflightError("missing exact source SHA256")
    parts = _relative_parts(name)
    held: list[int] = []
    fd = root_fd
    try:
        for part in parts[:-1]:
            fd = _check_directory(fd, part)
            held.append(fd)
        try:
            # O_NONBLOCK is required before fstat: a FIFO without a writer
            # must be rejected promptly, never hang while os.open waits.
            member = os.open(parts[-1], _FILE_FLAGS, dir_fd=fd)
            held.append(member)
            before = os.fstat(member)
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                    or before.st_uid != os.getuid()
                    or before.st_mode & 0o022
                    or (executable and not before.st_mode & 0o111)):
                raise LbeSourcePreflightError("member type, owner or mode denied")
            if max_bytes < 0 or before.st_size > max_bytes:
                raise LbeSourcePreflightError("source member exceeds byte budget")
            hash_state = hashlib.sha256()
            left = before.st_size
            while left:
                data = os.read(member, min(left, 1024 * 1024))
                if not data:
                    raise LbeSourcePreflightError("source member truncated during hash")
                hash_state.update(data)
                left -= len(data)
            if os.read(member, 1):
                raise LbeSourcePreflightError("source member grew during hash")
            after = os.fstat(member)
            leaf = os.stat(parts[-1], dir_fd=fd, follow_symlinks=False)
            def identity(st: os.stat_result) -> tuple[int, ...]:
                return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns,
                        st.st_ctime_ns, st.st_nlink, st.st_mode, st.st_uid)
            if identity(before) != identity(after) or identity(after) != identity(leaf):
                raise LbeSourcePreflightError("source member replaced during check")
            actual = hash_state.hexdigest()
            if actual != expected_sha:
                raise LbeSourcePreflightError("source byte identity mismatch")
            return actual, before.st_size
        except OSError as exc:
            raise LbeSourcePreflightError("member unavailable without links") from exc
    finally:
        for item in reversed(held):
            os.close(item)


def _check_parent_env(parent_env: Mapping[str, str], *, kind: str,
                      expected_parent_path: str) -> None:
    if (not isinstance(parent_env, Mapping)
            or type(expected_parent_path) is not str
            or not expected_parent_path.startswith("/")):
        raise LbeSourcePreflightError("trusted environment baseline missing")
    if parent_env.get("PATH") != expected_parent_path:
        raise LbeSourcePreflightError("host PATH shadow or drift")
    for name, value in parent_env.items():
        if (type(name) is not str or type(value) is not str
                or "\x00" in name or "\x00" in value):
            raise LbeSourcePreflightError("environment mapping invalid")
        if name in _FORBIDDEN_SHARED or name.startswith(("LD_", "DYLD_")):
            raise LbeSourcePreflightError("unreviewed executable selector")
        if kind == "go":
            # Merely sanitizing the CHILD mapping would hide an attempted hook.
            if name == "GOFLAGS" and value:
                raise LbeSourcePreflightError("inherited GOFLAGS toolhook denied")
            if name.startswith("GO") and name != "GOFLAGS":
                raise LbeSourcePreflightError("unreviewed inherited Go selector")
        elif kind == "pipenv":
            if name in _PIPENV_SELECTORS or name.startswith(("PIPENV_", "PIP_")):
                raise LbeSourcePreflightError("unreviewed Pipenv interpreter selector")
        else:
            raise LbeSourcePreflightError("unknown source kind")


def inspect_go_source_t0(*, private_root: Path, trusted_base: Path,
                         expected_members: Mapping[str, str],
                         parent_env: Mapping[str, str],
                         expected_parent_path: str) -> dict[str, object]:
    """Static SHA+env candidate only. Explicitly cannot grant real native Go."""
    _check_parent_env(parent_env, kind="go",
                      expected_parent_path=expected_parent_path)
    _validate_source_manifest(expected_members, _GO_CRITICAL)
    root = _check_private_root(private_root, trusted_base=trusted_base)
    try:
        checked = _inspect_members(root, expected_members, executables=frozenset({
            "go/bin/go", "go/pkg/tool/darwin_arm64/compile",
            "go/pkg/tool/darwin_arm64/link",
        }))
    finally:
        os.close(root)
    return {
        "status": "SOURCE_CANDIDATE_ONLY",
        "kind": "go",
        "checked_member_sha256": checked,
        "native_t1": "NOT_RUN",
        "egress_enforcement": "NOT_ATTESTED",
        "exec_authorized": False,
    }


def inspect_pipenv_source_t0(*, private_root: Path, trusted_base: Path,
                             expected_members: Mapping[str, str],
                             parent_env: Mapping[str, str],
                             expected_parent_path: str) -> dict[str, object]:
    """No-follow .venv directory and pinned files; never invokes Pipenv."""
    _check_parent_env(parent_env, kind="pipenv",
                      expected_parent_path=expected_parent_path)
    _validate_source_manifest(expected_members, _PIPENV_CRITICAL)
    root = _check_private_root(private_root, trusted_base=trusted_base)
    try:
        # Explicitly traverse .venv before foreign import/entrypoint. A normal
        # Pipenv .venv *file* redirect or symlink MUST fail, even if it points
        # to a valid Python interpreter elsewhere.
        dirs = []
        try:
            fd = root
            for component in ("project", ".venv"):
                fd = _check_directory(fd, component)
                dirs.append(fd)
        finally:
            for item in reversed(dirs):
                os.close(item)
        checked = _inspect_members(
            root, expected_members,
            executables=frozenset({"project/.venv/bin/python"}))
    finally:
        os.close(root)
    return {
        "status": "SOURCE_CANDIDATE_ONLY",
        "kind": "pipenv",
        "checked_member_sha256": checked,
        "selected_interpreter": str(private_root / "project/.venv/bin/python"),
        "native_t1": "NOT_RUN",
        "egress_enforcement": "NOT_ATTESTED",
        "exec_authorized": False,
    }


def require_real_egress_witness_t0(_caller_claim: object = None) -> None:
    """A client flag or unbound self-assertion cannot authorize source T1."""
    raise LbeSourcePreflightError(
        "T1=NOT_RUN: offline egress proof and owner Gate B not verified")
