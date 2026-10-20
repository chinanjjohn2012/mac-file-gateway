"""Pure Git CLI V1 schema/argv compiler. No subprocesses or repository I/O."""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any

from .core import GatewayError

GIT_V1_COMMANDS = frozenset({
    "status", "diff", "log", "branch", "switch",
    "add", "commit", "fetch", "pull", "push",
})
_OPTION_KEYS = {
    "status": {"short", "branch"},
    "diff": {"cached", "stat"},
    "log": {"limit", "oneline"},
    "branch": {"action", "name"},
    "switch": {"name", "create"},
    "add": {"all", "update"},
    "commit": {"message", "amend"},
    "fetch": {"remote", "prune"},
    "pull": {"remote", "branch", "ff_only"},
    "push": {"remote", "branch", "force_with_lease", "expected_remote_oid"},
}
_MISSING = object()
_REMOTE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z", re.ASCII)
_OID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z", re.ASCII)


def _invalid(reason: str) -> None:
    raise GatewayError("git_option_invalid", reason)


def _text(value: Any, name: str, maximum: int) -> str:
    if type(value) is not str or not value:
        _invalid(name + " must be a nonempty string.")
    try:
        length = len(value.encode("utf-8"))
    except UnicodeError:
        _invalid(name + " must be valid UTF-8.")
    if length > maximum or any(ord(c) < 32 or ord(c) == 127 for c in value):
        _invalid(name + " contains invalid characters or is too long.")
    return value


def validate_git_relative_path(value: Any) -> str:
    """Lexical check only; B-phase additionally verifies pinned physical paths."""
    if type(value) is not str or not value:
        raise GatewayError("git_path_blocked", "A relative path is required.")
    try:
        length = len(value.encode("utf-8"))
    except UnicodeError:
        raise GatewayError("git_path_blocked", "Invalid UTF-8 path.") from None
    if (length > 2048 or value.startswith(("/", "~")) or
            "\\" in value or ":" in value or
            any(ord(c) < 32 or ord(c) == 127 for c in value)):
        raise GatewayError("git_path_blocked", "Only clean relative paths are allowed.")
    if value == ".":
        return value
    parts = value.split("/")
    if (len(parts) > 128 or any(p in ("", ".", "..") for p in parts) or
            any(len(p.encode("utf-8")) > 255 for p in parts)):
        raise GatewayError("git_path_blocked", "Noncanonical relative path.")
    return value


def validate_git_branch_name(value: Any) -> str:
    name = _text(value, "Git branch", 240)
    if (name == "@" or name.startswith(("-", "/")) or name.endswith((".", "/"))
            or ".." in name or "//" in name or "@{" in name or
            any(c in name for c in " ~^:?*[\\")):
        _invalid("Invalid Git branch name.")
    if any(not p or p.startswith(".") or p.endswith((".lock", "."))
           for p in name.split("/")):
        _invalid("Invalid Git branch component.")
    return name


def _remote(value: Any) -> str:
    name = _text(value, "remote", 64)
    if not _REMOTE.fullmatch(name) or ".." in name or name.endswith((".lock", ".")):
        _invalid("Expected an existing remote name, not a URL or path.")
    return name


def _oid(value: Any) -> str:
    oid = _text(value, "expected_remote_oid", 64)
    if not _OID.fullmatch(oid) or set(oid) == {"0"}:
        _invalid("Expected a full nonzero SHA-1 or SHA-256 object ID.")
    return oid


def _required(options: dict[str, Any], field: str) -> Any:
    if field not in options:
        _invalid("Missing Git option: " + field)
    return options[field]


def _bool(options: dict[str, Any], name: str, default: bool = False) -> bool:
    value = options.get(name, default)
    if type(value) is not bool:
        _invalid(name + " must be boolean.")
    return value


@dataclass(frozen=True)
class CompiledGit:
    command: str
    argv: tuple[str, ...]  # git executable is NOT part of this tuple
    options: tuple[tuple[str, Any], ...]
    paths: tuple[str, ...]


def compile_git_command(command: Any, *, options: Any = _MISSING,
                        paths: Any = _MISSING) -> CompiledGit:
    """Strict structured arguments only. Safe for dry_run with zero Git launches."""
    if type(command) is not str or command not in GIT_V1_COMMANDS:
        raise GatewayError("git_command_not_allowed", "Git command unavailable in V1.")
    if options is _MISSING:
        options = {}
    if type(options) is not dict or set(options) - _OPTION_KEYS[command]:
        _invalid("Git options contain invalid or unknown fields.")
    if paths is _MISSING:
        paths = []
    if type(paths) is not list or len(paths) > 64:
        _invalid("Git paths must be an array of up to 64 entries.")
    checked_paths = tuple(validate_git_relative_path(p) for p in paths)
    if len(set(checked_paths)) != len(checked_paths):
        _invalid("Duplicate Git paths.")
    if command not in {"status", "diff", "add"} and checked_paths:
        _invalid("This command does not accept paths.")

    values: dict[str, Any] = {}
    argv = [command]
    if command in ("status", "diff"):
        flags = (("short", "--short"), ("branch", "--branch")) if command == "status" else (
            ("cached", "--cached"), ("stat", "--stat"))
        for key, flag in flags:
            enabled = values[key] = _bool(options, key)
            if enabled:
                argv.append(flag)
    elif command == "log":
        limit = options.get("limit", 20)
        if type(limit) is not int or not 1 <= limit <= 50:
            _invalid("log.limit must be an integer from 1 to 50.")
        values.update(limit=limit, oneline=_bool(options, "oneline"))
        argv.append("--max-count=" + str(limit))
        if values["oneline"]:
            argv.append("--oneline")
    elif command == "branch":
        action = _required(options, "action")
        if type(action) is not str or action not in {"list", "create", "delete"}:
            _invalid("Invalid branch action.")
        values["action"] = action
        if action == "list":
            if "name" in options:
                _invalid("Branch list does not take name.")
            argv.append("--list")
        else:
            name = values["name"] = validate_git_branch_name(_required(options, "name"))
            if action == "delete":
                argv.append("-d")
            argv.extend(["--", name])
    elif command == "switch":
        name = values["name"] = validate_git_branch_name(_required(options, "name"))
        create = values["create"] = _bool(options, "create")
        argv.append("--no-guess")
        argv.extend(["--no-track", "-c", name, "HEAD"] if create else [name])
    elif command == "add":
        all_ = values["all"] = _bool(options, "all")
        update = values["update"] = _bool(options, "update")
        if all_ and update or (not all_ and not update and not checked_paths):
            _invalid("Invalid add mode or missing paths.")
        if all_:
            argv.append("-A")
        elif update:
            argv.append("-u")
    elif command == "commit":
        values["message"] = _text(_required(options, "message"), "commit.message", 8192)
        values["amend"] = _bool(options, "amend")
        if values["amend"]:
            argv.append("--amend")
        argv.extend(["-m", values["message"]])
    elif command == "fetch":
        values["remote"] = _remote(_required(options, "remote"))
        values["prune"] = _bool(options, "prune")
        if values["prune"]:
            argv.append("--prune")
        argv.append(values["remote"])
    elif command == "pull":
        values["remote"] = _remote(_required(options, "remote"))
        values["branch"] = validate_git_branch_name(_required(options, "branch"))
        values["ff_only"] = _bool(options, "ff_only", True)
        if not values["ff_only"]:
            _invalid("V1 pull requires ff_only=true.")
        argv.extend(["--ff-only", values["remote"], "refs/heads/" + values["branch"]])
    else:  # push
        values["remote"] = _remote(_required(options, "remote"))
        values["branch"] = validate_git_branch_name(_required(options, "branch"))
        values["force_with_lease"] = _bool(options, "force_with_lease")
        if values["force_with_lease"]:
            values["expected_remote_oid"] = _oid(_required(options, "expected_remote_oid"))
            argv.append("--force-with-lease=refs/heads/" + values["branch"] +
                        ":" + values["expected_remote_oid"])
        elif "expected_remote_oid" in options:
            _invalid("expected_remote_oid requires force_with_lease=true.")
        argv.extend([values["remote"], "refs/heads/" + values["branch"] +
                     ":refs/heads/" + values["branch"]])
    if checked_paths:
        argv.extend(["--", *(":(literal)" + p for p in checked_paths)])
    return CompiledGit(command, tuple(argv), tuple(values.items()), checked_paths)


def preview_git(command: Any, *, cwd: Any = ".", options: Any = _MISSING,
                paths: Any = _MISSING, timeout_seconds: Any = 120,
                workspace: Any = _MISSING) -> dict[str, Any]:
    """No subprocess/rev-parse/ref checking. Physical checks belong to batch B."""
    cwd = validate_git_relative_path(cwd)
    if type(timeout_seconds) is not int or not 10 <= timeout_seconds <= 900:
        _invalid("Git timeout must be an integer from 10 to 900.")
    if workspace is not _MISSING and (
        type(workspace) is not str or
        re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", workspace) is None
    ):
        _invalid("Invalid Workspace ID.")
    compiled = compile_git_command(command, options=options, paths=paths)
    result = dict(command=compiled.command, cwd=cwd, options=dict(compiled.options),
                  paths=list(compiled.paths), effective_argv=list(compiled.argv),
                  timeout_seconds=timeout_seconds, dry_run=True,
                  execute_started=False, repository_checked=False,
                  remote_checked=False, branch_checked=False)
    if workspace is not _MISSING:
        result["workspace"] = workspace
    return result


__all__ = ["GIT_V1_COMMANDS", "CompiledGit", "compile_git_command",
           "preview_git", "validate_git_branch_name", "validate_git_relative_path"]
