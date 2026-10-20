"""Execution declarations only; no runtime backend or activation bypass."""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from .private_fs import PrivateFileError

if TYPE_CHECKING:
    from .workspaces_config import GatewaySettings


@dataclass(frozen=True)
class WorkspaceExecSettings:
    enabled: bool = False
    paths: tuple[str, ...] = ()
    runners: tuple[tuple[str, str], ...] = ()


def path_parts(value: str) -> tuple[str, ...]:
    """Apply the existing strict configuration path rules without I/O."""
    from .workspaces_config import _relative
    if type(value) is not str or not value:
        raise PrivateFileError("Invalid execution path.")
    try:
        if len(value.encode("utf-8")) > 2048:
            raise PrivateFileError("Execution path is too long.")
    except UnicodeError:
        raise PrivateFileError("Invalid execution path encoding.") from None
    _relative(value, "exec")
    return () if value == "." else tuple(value.split("/"))


def contains_path(scope: tuple[str, ...], path: tuple[str, ...]) -> bool:
    return len(path) >= len(scope) and path[:len(scope)] == scope


def parse_exec_policy(value: object) -> WorkspaceExecSettings:
    if type(value) is not dict or set(value) - {"enabled", "paths", "runners"}:
        raise PrivateFileError("Invalid execution configuration fields.")
    enabled = value.get("enabled", False)
    paths = value.get("paths", [])
    runners = value.get("runners", {})
    if type(enabled) is not bool:
        raise PrivateFileError("Execution enabled must be boolean.")
    if type(paths) is not list or len(paths) > 128:
        raise PrivateFileError("Invalid execution path list.")
    parsed_paths = tuple(path_parts(path) for path in paths)
    if len(set(parsed_paths)) != len(parsed_paths):
        raise PrivateFileError("Duplicate execution paths.")
    if type(runners) is not dict or len(runners) > 128:
        raise PrivateFileError("Invalid execution runner map.")
    for path, runner in runners.items():
        parts = path_parts(path)
        if type(runner) is not str or runner not in {"direct", "pipenv"}:
            raise PrivateFileError("Execution runner must be direct or pipenv.")
        if not any(contains_path(scope, parts) for scope in parsed_paths):
            raise PrivateFileError("Execution runner is outside its declared scope.")
    if enabled and not paths:
        raise PrivateFileError("Execution requires an explicit nonempty scope.")
    if not enabled and (paths or runners):
        raise PrivateFileError("Execution scopes and runners require enabled=true.")
    return WorkspaceExecSettings(enabled, tuple(paths), tuple(sorted(runners.items())))


def assert_exec_runtime_unavailable(settings: GatewaySettings) -> None:
    """No public factory may turn a declaration into runtime execution yet."""
    if any(item.execution.enabled for item in settings.workspaces):
        raise PrivateFileError("Multi-Workspace execution runtime is not available.")
