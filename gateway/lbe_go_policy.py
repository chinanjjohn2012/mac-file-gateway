"""Dormant Go argv/output validator for proposed local_best_effort Exec.

The existing F1 WorkspaceService hard denial and Legacy CommandRunner remain
unchanged. This module does not start subprocesses or grant execution. Its
path checks are PRE-SPAWN checks, not a confinement guarantee for trusted Go
compilers, cgo tools, module downloads or later filesystem changes.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import re
import stat
from typing import Sequence

_MAX_ARGS = 64
_MAX_ITEM_LENGTH = 1024
_MAX_TOTAL_LENGTH = 8192
_COMPONENT = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]*\Z")
_SAFE_FLAGS = frozenset({"-v", "-trimpath"})


class GoPolicyError(ValueError):
    """A proposed Go command or output location is not authorized."""


@dataclass(frozen=True)
class GoCommandPlan:
    argv: tuple[str, ...]
    runner: str  # always direct; never infer Pipenv from an unrelated Pipfile
    output_relative_to_workspace: str | None


def _components(value: str, *, allow_root: bool = False) -> tuple[str, ...]:
    if type(value) is not str:
        raise GoPolicyError("path must be a string")
    if value == "." and allow_root:
        return ()
    if not value or value.startswith(("/", "~")) or "\\" in value:
        raise GoPolicyError("path must be relative, canonical and nonempty")
    raw = value.split("/")
    if any(not _COMPONENT.fullmatch(part) or part in {".", ".."} for part in raw):
        raise GoPolicyError("invalid or traversing relative path")
    return tuple(raw)


def _scope_contains(parts: tuple[str, ...], scope: tuple[str, ...]) -> bool:
    return len(parts) >= len(scope) and parts[:len(scope)] == scope


def _package(value: str) -> bool:
    if value in {".", "./..."}:
        return True
    if not value.startswith("./"):
        return False
    body = value[2:]
    if body.endswith("/..."):
        body = body[:-4]
    if not body:
        return False
    try:
        _components(body)
    except GoPolicyError:
        return False
    return True


def _inspect_output(workspace_root: Path, cwd_parts: tuple[str, ...],
                    output_parts: tuple[str, ...]) -> None:
    """Inspect existing dirs with no-follow FDs; never create/write an output.

    All directory descriptors are closed before return. A trusted local user
    can change paths after this check: the caller must not claim race-proof
    filesystem isolation, and must revalidate before any future spawn.
    """
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    held: list[int] = []
    try:
        fd = os.open(workspace_root, flags)
        held.append(fd)
        if not stat.S_ISDIR(os.fstat(fd).st_mode):
            raise GoPolicyError("workspace root is not a directory")
        for name in (*cwd_parts, *output_parts[:-1]):
            fd = os.open(name, flags, dir_fd=fd)
            held.append(fd)
        leaf = output_parts[-1]
        try:
            metadata = os.stat(leaf, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            return  # a new regular file may be created by future Go build
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise GoPolicyError("existing output must be one regular nonlinked file")
    except OSError as exc:
        raise GoPolicyError("output parent cannot be opened without links") from exc
    finally:
        for descriptor in reversed(held):
            os.close(descriptor)


def validate_go_command(argv: Sequence[str], *, workspace_root: Path,
                        cwd: str, exec_paths: Sequence[str]) -> GoCommandPlan:
    """Produce a source-static, non-executing plan for basic Go CLI commands.

    The host must separately validate/pin Workspace identity, config, cwd,
    executable and trusted v2 admission. Calling this function is never an
    execution authorization or an exemption from the operative F1 denial.
    """
    if type(argv) not in (tuple, list) or not 2 <= len(argv) <= _MAX_ARGS:
        raise GoPolicyError("argv must have 2..64 exact string elements")
    if any(type(x) is not str or not x or len(x) > _MAX_ITEM_LENGTH
           or any(ord(ch) < 32 for ch in x) for x in argv):
        raise GoPolicyError("argv must be bounded nonempty strings without controls")
    if sum(map(len, argv)) > _MAX_TOTAL_LENGTH:
        raise GoPolicyError("argv exceeds length limit")
    if argv[0] != "go" or argv[1] not in {"test", "vet", "build"}:
        raise GoPolicyError("Go verb is not allowlisted")
    if type(exec_paths) not in (list, tuple) or not exec_paths:
        raise GoPolicyError("at least one explicit exec path is required")
    cwd_parts = _components(cwd, allow_root=True)
    scopes = tuple(_components(path, allow_root=True) for path in exec_paths)
    if not any(_scope_contains(cwd_parts, path) for path in scopes):
        raise GoPolicyError("cwd outside granted exec paths")

    output: tuple[str, ...] | None = None
    seen_packages = False
    index = 2
    while index < len(argv):
        item = argv[index]
        if item in _SAFE_FLAGS:
            if seen_packages:
                raise GoPolicyError("options must precede package operands")
        elif item == "-o" or item.startswith("-o="):
            if argv[1] != "build" or output is not None or seen_packages:
                raise GoPolicyError("-o is only allowed once for go build before packages")
            if item == "-o":
                index += 1
                if index >= len(argv):
                    raise GoPolicyError("-o requires an output path")
                value = argv[index]
            else:
                value = item[3:]
            output = _components(value)
        elif item.startswith("-"):
            # Refuse all tool hooks (-exec/-toolexec), response files,
            # alternate module/overlay inputs and unreviewed Go flags.
            raise GoPolicyError("Go option is not allowlisted")
        elif not _package(item):
            raise GoPolicyError("only canonical ./package or ./... operands are allowed")
        else:
            seen_packages = True
        index += 1
    canonical_output = None
    if output is not None:
        combined = (*cwd_parts, *output)
        if not any(_scope_contains(combined, scope) for scope in scopes):
            raise GoPolicyError("output outside granted exec paths")
        _inspect_output(Path(workspace_root), cwd_parts, output)
        canonical_output = "/".join(combined)
    return GoCommandPlan(tuple(argv), "direct", canonical_output)
