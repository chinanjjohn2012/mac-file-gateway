"""Immutable execution intentions, never operating-system capabilities."""
from __future__ import annotations

from dataclasses import dataclass, field

from .core import GatewayError
from .exec_policy import path_parts
from .private_fs import PrivateFileError
from .workspaces_config import _ID


@dataclass(frozen=True)
class ExecutionRequest:
    workspace: str
    cwd: str
    argv: tuple[str, ...]
    timeout_seconds: int
    dry_run: bool


@dataclass(frozen=True)
class ExecutionIntent:
    request: ExecutionRequest
    scope: str
    runner_hint: str
    runner_project_hint: str | None
    runtime_ready: bool = field(default=False, init=False)


@dataclass(frozen=True)
class ExecutionOutcome:
    exit_code: int | None
    timed_out: bool
    error_code: str | None

    def __post_init__(self) -> None:
        if (self.exit_code is not None and type(self.exit_code) is not int or
                type(self.timed_out) is not bool or
                self.error_code is not None and type(self.error_code) is not str):
            raise GatewayError("invalid_argument", "Invalid execution outcome.")


def parse_execution_request(payload: object) -> ExecutionRequest:
    from .executor import _clean_argv, _validate_command
    fields = {"workspace", "cwd", "argv", "timeout_seconds", "dry_run"}
    if type(payload) is not dict or set(payload) - fields:
        raise GatewayError("invalid_argument", "Invalid execution request fields.")
    if "workspace" not in payload:
        raise GatewayError("workspace_required", "An explicit Workspace ID is required.")
    workspace = payload["workspace"]
    if type(workspace) is not str or _ID.fullmatch(workspace) is None:
        raise GatewayError("workspace_required", "A valid explicit Workspace ID is required.")
    cwd = payload.get("cwd", ".")
    try:
        path_parts(cwd)
    except PrivateFileError:
        raise GatewayError("invalid_argument", "Invalid execution directory.") from None
    timeout = payload.get("timeout_seconds", 60)
    dry_run = payload.get("dry_run", True)
    if type(timeout) is not int or not 1 <= timeout <= 300 or type(dry_run) is not bool:
        raise GatewayError("invalid_argument", "Invalid execution timeout or dry_run.")
    argv = _clean_argv(payload.get("argv"))
    try:
        for item in argv:
            item.encode("utf-8")
    except UnicodeError:
        raise GatewayError("invalid_argument", "Invalid command argument encoding.") from None
    _validate_command(argv)
    return ExecutionRequest(workspace, cwd, tuple(argv), timeout, dry_run)
