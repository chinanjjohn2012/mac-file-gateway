"""NONOPERATIVE M1 source-admission T0 checks for proposed Go/Pipenv.

No import/install, subprocess, egress enforcement, product grant or runtime T1.
These functions can report only SOURCE_CANDIDATE, NEVER execution permission.
The ordinary F1 WorkspaceService and lbe_native_launcher denial are unchanged.
A trusted caller must bind the root, digest map and parent PATH independently.
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
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC


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


def _check_private_root(root: Path) -> int:
    if not isinstance(root, Path) or not root.is_absolute():
        raise LbeSourcePreflightError("private root must be an absolute Path")
    try:
        before = root.lstat()
        fd = os.open(root, _DIR_FLAGS)
        after = os.fstat(fd)
    except OSError as exc:
        raise LbeSourcePreflightError("private root not accessible without links") from exc
    if (not stat.S_ISDIR(before.st_mode) or not stat.S_ISDIR(after.st_mode)
            or before.st_dev != after.st_dev or before.st_ino != after.st_ino
            or before.st_uid != os.getuid() or after.st_uid != os.getuid()
            or (before.st_mode & 0o077) or (after.st_mode & 0o077)):
        os.close(fd)
        raise LbeSourcePreflightError("private root not exclusively owned or pinned")
    return fd


def _check_directory(fd: int, part: str) -> int:
    try:
        child = os.open(part, _DIR_FLAGS, dir_fd=fd)
        meta = os.fstat(child)
    except OSError as exc:
        raise LbeSourcePreflightError("source directory absent or unsafe") from exc
    if (not stat.S_ISDIR(meta.st_mode) or meta.st_uid != os.getuid()
            or meta.st_mode & 0o022):
        os.close(child)
        raise LbeSourcePreflightError("source directory is writable or not owned")
    return child


def _verified_member(root_fd: int, name: str, expected_sha: str,
                     *, executable: bool = False) -> str:
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
            member = os.open(parts[-1], _FILE_FLAGS, dir_fd=fd)
            held.append(member)
            before = os.fstat(member)
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                    or before.st_uid != os.getuid()
                    or before.st_mode & 0o022
                    or (executable and not before.st_mode & 0o111)):
                raise LbeSourcePreflightError("member type, owner or mode denied")
            hash_state = hashlib.sha256()
            while True:
                data = os.read(member, 1024 * 1024)
                if not data:
                    break
                hash_state.update(data)
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
            return actual
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


def inspect_go_source_t0(*, private_root: Path,
                         expected_members: Mapping[str, str],
                         parent_env: Mapping[str, str],
                         expected_parent_path: str) -> dict[str, object]:
    """Static SHA+env candidate only. Explicitly cannot grant real native Go."""
    _check_parent_env(parent_env, kind="go",
                      expected_parent_path=expected_parent_path)
    if not isinstance(expected_members, Mapping) or not _GO_CRITICAL.issubset(expected_members):
        raise LbeSourcePreflightError("Go critical member manifest incomplete")
    root = _check_private_root(private_root)
    try:
        checked = {
            name: _verified_member(root, name, expected_members[name],
                                   executable=name in {
                                       "go/bin/go",
                                       "go/pkg/tool/darwin_arm64/compile",
                                       "go/pkg/tool/darwin_arm64/link",
                                   })
            for name in sorted(expected_members)
        }
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


def inspect_pipenv_source_t0(*, private_root: Path,
                             expected_members: Mapping[str, str],
                             parent_env: Mapping[str, str],
                             expected_parent_path: str) -> dict[str, object]:
    """No-follow .venv directory and pinned files; never invokes Pipenv."""
    _check_parent_env(parent_env, kind="pipenv",
                      expected_parent_path=expected_parent_path)
    if (not isinstance(expected_members, Mapping)
            or not _PIPENV_CRITICAL.issubset(expected_members)):
        raise LbeSourcePreflightError("Pipenv private venv manifest incomplete")
    root = _check_private_root(private_root)
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
        checked = {
            name: _verified_member(root, name, expected_members[name],
                                   executable=name == "project/.venv/bin/python")
            for name in sorted(expected_members)
        }
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
