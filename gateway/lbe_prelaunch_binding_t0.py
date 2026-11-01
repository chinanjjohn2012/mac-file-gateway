"""NONOPERATIVE M1 T0 binding of source admission to closed child-env candidates.

No launcher, Popen, foreign import, network witness, owner grant or execution.
A successful result is still NOT an authorization for Native T1 or F1 Exec.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Mapping
import os

from .lbe_source_preflight import (
    LbeSourcePreflightError, inspect_go_source_t0, inspect_pipenv_source_t0,
    _check_private_root, _check_directory, _verified_member,
)
from .lbe_child_env_t0 import (
    ChildEnvCandidate, LbeChildEnvT0Error,
    make_go_child_env_t0, make_pipenv_child_env_t0,
)

_HOST_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"
_PIPENV_ENTRY = "pipenv-env/bin/pipenv"


class LbePrelaunchBindingT0Error(ValueError):
    """The proposed source and environment do not form a consistent plan."""


@dataclass(frozen=True)
class PrelaunchBindingT0:
    kind: str
    checked_member_sha256: Mapping[str, str]
    child_env: Mapping[str, str]
    status: str = "NONOPERATIVE_PRELAUNCH_CANDIDATE_ONLY"
    source_loaded_identity: str = "NOT_ATTESTED"
    network_precontact_isolation: str = "NOT_ATTESTED"
    original_child_native_t1: str = "NOT_RUN"
    exec_authorized: bool = False


def _check_inputs(*, private_root: Path, trusted_base: Path,
                  parent_env: Mapping[str, str],
                  expected_parent_path: str) -> None:
    if (type(parent_env) is not dict or
            type(expected_parent_path) is not str or
            expected_parent_path != _HOST_PATH or
            parent_env.get("PATH") != _HOST_PATH or
            not isinstance(private_root, Path) or
            not isinstance(trusted_base, Path) or
            private_root == trusted_base or
            ".." in private_root.parts or
            ".." in trusted_base.parts or
            not private_root.is_absolute() or
            not trusted_base.is_absolute()):
        raise LbePrelaunchBindingT0Error("binding input or parent PATH mismatch")


def _bind(kind: str, source: dict[str, object],
          env: ChildEnvCandidate,
          *, required: frozenset[str]) -> PrelaunchBindingT0:
    checked = source.get("checked_member_sha256")
    if (source.get("kind") != kind or source.get("status") != "SOURCE_CANDIDATE_ONLY"
            or source.get("exec_authorized") is not False
            or source.get("native_t1") != "NOT_RUN"
            or source.get("egress_enforcement") != "NOT_ATTESTED"
            or type(checked) is not dict
            or not required.issubset(checked)
            or env.kind != kind
            or env.status != "NONOPERATIVE_ENV_CANDIDATE_ONLY"
            or env.exec_authorized is not False
            or env.original_child_native_t1 != "NOT_RUN"
            or env.source_loaded_identity != "NOT_ATTESTED"
            or env.network_precontact_isolation != "NOT_ATTESTED"):
        raise LbePrelaunchBindingT0Error("candidate identity or authority mismatch")
    return PrelaunchBindingT0(
        kind=kind,
        checked_member_sha256=MappingProxyType(dict(checked)),
        child_env=MappingProxyType(dict(env.values)),
    )


def bind_go_prelaunch_t0(*, private_root: Path, trusted_base: Path,
                         expected_members: Mapping[str, str],
                         parent_env: Mapping[str, str],
                         expected_parent_path: str,
                         home: Path, temp: Path, go_path: Path,
                         mod_cache: Path, build_cache: Path) -> PrelaunchBindingT0:
    """Bind the same private Go source root and immutable closed env candidate."""
    _check_inputs(private_root=private_root, trusted_base=trusted_base,
                  parent_env=parent_env, expected_parent_path=expected_parent_path)
    try:
        source = inspect_go_source_t0(
            private_root=private_root, trusted_base=trusted_base,
            expected_members=expected_members, parent_env=parent_env,
            expected_parent_path=expected_parent_path)
        env = make_go_child_env_t0(
            private_root=private_root, go_root=private_root / "go",
            home=home, temp=temp, go_path=go_path,
            mod_cache=mod_cache, build_cache=build_cache,
            parent_env=parent_env)
        if env.values["GOROOT"] != str(private_root / "go"):
            raise LbePrelaunchBindingT0Error("Go source/env root mismatch")
        return _bind("go", source, env, required=frozenset({
            "go/VERSION", "go/bin/go", "go/pkg/tool/darwin_arm64/compile",
            "go/pkg/tool/darwin_arm64/link", "go/src/runtime/proc.go"}))
    except (LbeSourcePreflightError, LbeChildEnvT0Error, OSError) as exc:
        raise LbePrelaunchBindingT0Error("Go prelaunch binding denied") from exc


def _reject_earlier_pipenv_path_hit_t0(root_fd: int) -> None:
    """An unlisted project .venv/bin/pipenv must never precede pinned Pipenv.

    Inspect the first PATH directory by no-follow directory FDs. Any present
    name (regular file, symlink, FIFO or directory), executable or otherwise,
    is conservatively rejected, including a presently non-executable file
    whose mode could later change. This is NOT a race-free exec qualification.
    """
    held: list[int] = []
    fd = root_fd
    try:
        for part in ("project", ".venv", "bin"):
            fd = _check_directory(fd, part)
            held.append(fd)
        try:
            os.stat("pipenv", dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        raise LbePrelaunchBindingT0Error("unqualified earlier Pipenv PATH hit")
    finally:
        for item in reversed(held):
            os.close(item)


def bind_pipenv_prelaunch_t0(*, private_root: Path, trusted_base: Path,
                             expected_members: Mapping[str, str],
                             parent_env: Mapping[str, str],
                             expected_parent_path: str,
                             home: Path, temp: Path) -> PrelaunchBindingT0:
    """Require a pinned Pipenv entrypoint in addition to the reviewed venv."""
    _check_inputs(private_root=private_root, trusted_base=trusted_base,
                  parent_env=parent_env, expected_parent_path=expected_parent_path)
    try:
        if (not isinstance(expected_members, Mapping)
                or _PIPENV_ENTRY not in expected_members):
            raise LbePrelaunchBindingT0Error(
                "Pipenv executable source manifest required")
        source = inspect_pipenv_source_t0(
            private_root=private_root, trusted_base=trusted_base,
            expected_members=expected_members, parent_env=parent_env,
            expected_parent_path=expected_parent_path)
        root_fd = _check_private_root(private_root, trusted_base=trusted_base)
        try:
            _reject_earlier_pipenv_path_hit_t0(root_fd)
            _verified_member(root_fd, _PIPENV_ENTRY, expected_members[_PIPENV_ENTRY],
                             executable=True)
        finally:
            os.close(root_fd)
        env = make_pipenv_child_env_t0(
            private_root=private_root,
            project_root=private_root / "project",
            pipenv_bin=private_root / _PIPENV_ENTRY,
            home=home, temp=temp, parent_env=parent_env)
        checked_path = (
            str(private_root / "project/.venv/bin"),
            str(private_root / "pipenv-env/bin"),
            "/usr/bin", "/bin", "/usr/sbin", "/sbin",
        )
        if (env.values["PIPENV_PIPFILE"] != str(private_root / "project/Pipfile")
                or tuple(os.get_exec_path(dict(env.values))) != checked_path):
            raise LbePrelaunchBindingT0Error("Pipenv source/env path mismatch")
        return _bind("pipenv", source, env, required=frozenset({
            "project/Pipfile", "project/Pipfile.lock",
            "project/.venv/pyvenv.cfg", "project/.venv/bin/python",
            _PIPENV_ENTRY}))
    except (LbeSourcePreflightError, LbeChildEnvT0Error,
            OSError, TypeError) as exc:
        raise LbePrelaunchBindingT0Error("Pipenv prelaunch binding denied") from exc
