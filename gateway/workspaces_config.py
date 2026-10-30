"""Strict Multi-Workspace JSON schema; Git and controlled Exec opt in separately."""
from __future__ import annotations

from dataclasses import dataclass
import os
import re
from typing import Any

from .private_fs import PrivateFileError, read_private_json
from .git_policy import GIT_V1_COMMANDS
from .lbe_config_policy import LbeConfigError, parse_lbe_exec_fragment

_ID = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
_DENIED_ROOT_PARTS = frozenset({
    ".git", ".hg", ".svn", ".ssh", ".aws", ".kube", ".venv",
    ".config", ".gateway-backups", "node_modules", "__pycache__",
    "venv", "env", "vendor", "dist", "build", "target", "coverage",
    "library", "keychains", "secrets", "credentials",
})


@dataclass(frozen=True)
class WorkspaceSettings:
    name: str
    root: str
    excludes: tuple[str, ...]
    hidden_paths: tuple[str, ...]
    allow_write: bool
    write_paths: tuple[str, ...]
    backup_retention_days: int
    git_allowed_commands: tuple[str, ...] = ()
    sensitive_content_audit_paths: tuple[str, ...] = ()
    sensitive_content_audit_until: str | None = None
    exec_enabled: bool = False
    exec_paths: tuple[str, ...] = ()
    exec_runners: tuple[str, ...] = ()


@dataclass(frozen=True)
class GatewaySettings:
    port: int
    workspaces: tuple[WorkspaceSettings, ...]
    git_enabled: bool = False
    exec_enabled: bool = False
    schema_version: int = 1


def _keys(obj: Any, allowed: set[str], context: str) -> dict[str, Any]:
    if type(obj) is not dict or set(obj) - allowed:
        raise PrivateFileError("Invalid or unknown " + context + " fields.")
    return obj


def _bool_field(obj: dict[str, Any], key: str, default: bool) -> bool:
    value = obj.get(key, default)
    if type(value) is not bool:
        raise PrivateFileError("Configuration option " + key + " must be boolean.")
    return value


def _bounded_tuple(value: Any, label: str, *, count: int = 128) -> tuple[str, ...]:
    if type(value) is not list or len(value) > count or any(type(item) is not str or not item
                                                         or len(item.encode("utf-8")) > 2048 for item in value):
        raise PrivateFileError("Invalid configuration string list: " + label)
    if len(set(value)) != len(value):
        raise PrivateFileError("Duplicate configuration string list: " + label)
    return tuple(value)


def _relative(value: str, label: str, *, allow_glob: bool = False) -> None:
    if (value.startswith(("/", "~")) or ":" in value or "\\" in value or
            "\x00" in value or any(ord(char) < 32 or ord(char) == 127 for char in value)):
        raise PrivateFileError("Invalid relative path in " + label)
    if not allow_glob and any(char in value for char in "*?[]"):
        raise PrivateFileError("Wildcards not permitted in " + label)
    if value == ".":
        return
    parts = value.split("/")
    if any(not part or part in (".", "..") for part in parts):
        raise PrivateFileError("Noncanonical relative path in " + label)


def _absolute_root(root: Any) -> str:
    if type(root) is not str or len(root.encode("utf-8")) > 4096 or not root.startswith("/"):
        raise PrivateFileError("Workspace root must be an absolute directory.")
    parts = root.split("/")[1:]
    if (not parts or any(not p or p in (".", "..") or p.startswith(".") or
                         p.casefold() in _DENIED_ROOT_PARTS for p in parts)):
        raise PrivateFileError("Workspace root contains forbidden or noncanonical components.")
    if root == os.path.expanduser("~"):
        raise PrivateFileError("Home is not a valid workspace root.")
    return root


def parse_workspace_config(config: dict[str, Any]) -> GatewaySettings:
    obj = _keys(config, {"schema_version", "server", "workspaces"}, "top-level")
    schema_version = obj.get("schema_version")
    if type(schema_version) is not int or schema_version not in (1, 2):
        raise PrivateFileError("Unsupported workspace schema version.")
    server = _keys(obj.get("server", {}), {"port", "transport", "git", "exec"}, "server")
    git = _keys(server.get("git", {}), {"enabled"}, "server.git")
    git_enabled = _bool_field(git, "enabled", False)
    if schema_version == 1:
        server_exec = _keys(server.get("exec", {}), {"enabled"}, "server.exec")
        exec_enabled = _bool_field(server_exec, "enabled", False)
    else:
        # V2 has no server-level Exec authority. The shared service remains
        # F1 deny-only for positive execution until the contract is approved.
        exec_enabled = False
    port = server.get("port", 8765)
    if type(port) is not int or not 1024 <= port <= 65535:
        raise PrivateFileError("Invalid Gateway port.")
    if server.get("transport", "http") != "http":
        raise PrivateFileError("Multi-Workspace requires HTTP transport.")
    workspaces = obj.get("workspaces")
    if type(workspaces) is not dict or not 1 <= len(workspaces) <= 16:
        raise PrivateFileError("Multi-Workspace requires 1 to 16 entries.")
    result = []
    for name, raw in workspaces.items():
        if type(name) is not str or _ID.fullmatch(name) is None:
            raise PrivateFileError("Invalid Workspace ID.")
        item = _keys(raw, {"root", "read", "hidden_paths", "write", "exec", "local_skills", "git"}, "workspace")
        root = _absolute_root(item.get("root"))
        read = _keys(item.get("read", {}), {"enabled", "excludes"}, "read")
        if not _bool_field(read, "enabled", True):
            raise PrivateFileError("Phase 1 Workspace reads cannot be disabled.")
        excludes = _bounded_tuple(read.get("excludes", []), "read.excludes")
        hidden = _bounded_tuple(item.get("hidden_paths", []), "hidden_paths")
        for value in excludes:
            _relative(value, "read.excludes", allow_glob=True)
        for value in hidden:
            _relative(value, "hidden_paths")
            if not value.split("/")[-1].startswith("."):
                raise PrivateFileError("Hidden paths must specify a hidden directory.")
        write = _keys(item.get("write", {}), {"enabled", "paths", "backup_retention_days", "sensitive_content"}, "write")
        allow_write = _bool_field(write, "enabled", False)
        write_paths = _bounded_tuple(write.get("paths", []), "write.paths")
        if allow_write and not write_paths:
            raise PrivateFileError("Enabling writes requires an explicit nonempty scope.")
        if not allow_write and write_paths:
            raise PrivateFileError("Write paths require write.enabled=true.")
        for value in write_paths:
            _relative(value, "write.paths")
        retention = write.get("backup_retention_days", 15)
        if type(retention) is not int or not 1 <= retention <= 3650:
            raise PrivateFileError("Invalid backup retention days.")
        sensitive = _keys(write.get("sensitive_content", {}), {"mode", "paths", "expires_at"}, "write.sensitive_content")
        mode = sensitive.get("mode", "enforce")
        if type(mode) is not str or mode not in {"enforce", "audit"}:
            raise PrivateFileError("Invalid sensitive content write mode.")
        audit_paths = _bounded_tuple(sensitive.get("paths", []), "sensitive_content.paths")
        for audit_path in audit_paths:
            _relative(audit_path, "sensitive_content.paths")
            if audit_path == ".":
                raise PrivateFileError("Sensitive audit requires explicit subtree.")
        audit_until = sensitive.get("expires_at")
        if mode == "audit":
            if not allow_write or not audit_paths or type(audit_until) is not str:
                raise PrivateFileError("Sensitive audit requires writable scope, paths and expiry.")
        elif audit_paths or audit_until is not None:
            raise PrivateFileError("Sensitive audit paths/expiry require mode=audit.")
        if schema_version == 1:
            # Preserve every legacy v1 two-switch and validation rule.
            exec_config = _keys(item.get("exec", {}), {"enabled", "paths", "runners"}, "workspace.exec")
            workspace_exec = _bool_field(exec_config, "enabled", False)
            exec_paths = _bounded_tuple(exec_config.get("paths", []), "exec.paths", count=32)
            exec_runners = _bounded_tuple(exec_config.get("runners", []), "exec.runners", count=32)
            if workspace_exec and not exec_enabled:
                raise PrivateFileError("Workspace exec requires server.exec.enabled=true.")
            if workspace_exec and not exec_paths:
                raise PrivateFileError("Workspace exec requires an explicit nonempty path scope.")
            if not workspace_exec and (exec_paths or exec_runners):
                raise PrivateFileError("Exec paths/runners require workspace.exec.enabled=true.")
            for value in exec_paths:
                _relative(value, "exec.paths")
            for value in exec_runners:
                if value.count("=") != 1:
                    raise PrivateFileError("Exec runner must be PATH=direct or PATH=pipenv.")
                path, runner = value.split("=", 1)
                _relative(path, "exec.runners")
                if runner not in {"direct", "pipenv"}:
                    raise PrivateFileError("Unsupported exec runner.")
        else:
            # Validate the v2 scope-only grant with the same reviewed T0
            # fragment, but also retain strict validation of every other
            # root/read/write/Git/transport field in this complete loader.
            try:
                fragment = parse_lbe_exec_fragment(
                    schema_version=2, server={"exec": server.get("exec", {})},
                    workspace={"exec": item.get("exec", {})},
                )
            except LbeConfigError as exc:
                raise PrivateFileError("Invalid v2 Exec fragment: " + str(exc)) from None
            workspace_exec = fragment.enabled
            exec_paths = tuple("/".join(p) or "." for p in fragment.paths)
            exec_runners = tuple((("/".join(p) or ".") + "=" + runner)
                                 for p, runner in fragment.runners)
            exec_enabled = exec_enabled or workspace_exec
        skills = _keys(item.get("local_skills", {}), {"enabled"}, "local_skills")
        if _bool_field(skills, "enabled", False):
            raise PrivateFileError("Local Skills are not supported in Multi-Workspace.")
        git = _keys(item.get("git", {}), {"allowed_commands"}, "workspace.git")
        commands = _bounded_tuple(git.get("allowed_commands", []), "git.allowed_commands",
                                  count=len(GIT_V1_COMMANDS))
        if any(command not in GIT_V1_COMMANDS for command in commands):
            raise PrivateFileError("Unsupported Git command in Workspace allowlist.")
        if commands and not git_enabled:
            raise PrivateFileError("Git command grants require server.git.enabled=true.")
        result.append(WorkspaceSettings(name, root, excludes, hidden, allow_write,
                                        write_paths, retention, commands,
                                        audit_paths, audit_until,
                                        workspace_exec, exec_paths, exec_runners))
    return GatewaySettings(port, tuple(result), git_enabled, exec_enabled,
                           schema_version)


def read_workspace_config(path: str) -> GatewaySettings:
    return parse_workspace_config(read_private_json(path))
