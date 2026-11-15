"""Pure Git CLI V1 schema/argv compiler. No subprocesses or repository I/O."""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any

from .core import GatewayError

GIT_V1_COMMANDS = frozenset({
    "status", "diff", "log", "branch", "switch",
    "add", "commit", "fetch", "pull", "push", "rev-parse", "rev-list",
})
_DIFF_BOOL_FLAGS = (
    ("cached", "--cached"),
    ("merge_base", "--merge-base"),
    ("name_status", "--name-status"),
    ("name_only", "--name-only"),
    ("stat", "--stat"),
    ("numstat", "--numstat"),
    ("shortstat", "--shortstat"),
    ("compact_summary", "--compact-summary"),
    ("summary", "--summary"),
    ("check", "--check"),
    ("raw", "--raw"),
    ("patch", "--patch"),
    ("no_patch", "--no-patch"),
    ("full_index", "--full-index"),
    ("binary", "--binary"),
    ("histogram", "--histogram"),
    ("patience", "--patience"),
    ("minimal", "--minimal"),
    ("function_context", "-W"),
    ("ignore_all_space", "--ignore-all-space"),
    ("ignore_space_change", "--ignore-space-change"),
    ("ignore_blank_lines", "--ignore-blank-lines"),
    ("ignore_cr_at_eol", "--ignore-cr-at-eol"),
    ("find_renames", "--find-renames"),
    ("find_copies", "--find-copies"),
    ("find_copies_harder", "--find-copies-harder"),
    ("no_renames", "--no-renames"),
    ("exit_code", "--exit-code"),
    ("quiet", "--quiet"),
    ("no_color", "--no-color"),
    ("no_textconv", "--no-textconv"),
    ("no_ext_diff", "--no-ext-diff"),
)
_OPTION_KEYS = {
    "status": {"short", "branch"},
    "diff": {name for name, _flag in _DIFF_BOOL_FLAGS} | {
        "base", "end", "range", "unified", "diff_algorithm", "diff_filter",
        "pickaxe", "pickaxe_regex",
    },
    "log": {"limit", "oneline"},
    "rev-parse": {"target", "name"},
    "rev-list": {"commit", "limit"},
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
_DIFF_REV = re.compile(r"[0-9a-f]+\Z", re.ASCII)
_DIFF_HEX = re.compile(r"[0-9A-Fa-f]+\Z", re.ASCII)
_HEAD_REV = re.compile(r"HEAD(?:~\d+|\^\d*|@\{\d+\})*\Z")
_DIFF_FILTER = re.compile(r"[ACDMRTUXB*]+\Z")


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


def _commit_oid(value: Any, name: str) -> str:
    oid = _text(value, name, 240)
    if not _DIFF_REV.fullmatch(oid):
        _invalid(name + " must be lowercase hex.")
    if len(oid) in (40, 64) and set(oid) == {"0"}:
        _invalid(name + " must be a nonzero full object ID.")
    return oid


def _diff_revision(value: Any, name: str) -> tuple[str, str]:
    """Return (kind, token) for one read-only diff endpoint.

    kind is oid, head, or branch. Symbolic rev:path, arbitrary ^{}, and
    reflog dates stay closed.
    """
    text = _text(value, name, 240)
    if _HEAD_REV.fullmatch(text):
        return "head", text
    if _DIFF_HEX.fullmatch(text):
        if not _DIFF_REV.fullmatch(text):
            _invalid(name + " must use lowercase hex.")
        if len(text) in (40, 64) and set(text) == {"0"}:
            _invalid(name + " must be a nonzero full object ID.")
        return "oid", text
    return "branch", validate_git_branch_name(text)


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
    if command == "status":
        for key, flag in (("short", "--short"), ("branch", "--branch")):
            enabled = values[key] = _bool(options, key)
            if enabled:
                argv.append(flag)
    elif command == "diff":
        for key, _flag in _DIFF_BOOL_FLAGS:
            values[key] = _bool(options, key)
        if values["patch"] and values["no_patch"]:
            _invalid("diff patch and no_patch cannot both be true.")
        if values["merge_base"] and "base" not in options:
            _invalid("diff merge_base requires a revision.")
        range_op = options.get("range", None)
        if range_op is not None and range_op not in {"..", "..."}:
            _invalid("diff.range must be '..' or '...'.")
        if range_op is not None:
            values["range"] = range_op
        if "end" in options and "base" not in options:
            _invalid("diff end requires base.")
        if range_op is not None and "end" not in options:
            _invalid("diff range requires base and end.")
        if values["cached"] and ("end" in options or range_op is not None):
            _invalid("diff --cached accepts at most one revision.")
        unified = options.get("unified", None)
        if unified is not None:
            if type(unified) is not int or not 0 <= unified <= 100000:
                _invalid("diff.unified must be an integer from 0 to 100000.")
            values["unified"] = unified
        algorithm = options.get("diff_algorithm", None)
        if algorithm is not None:
            if algorithm not in {"myers", "minimal", "patience", "histogram"}:
                _invalid("diff.diff_algorithm is not a read-only algorithm.")
            values["diff_algorithm"] = algorithm
        diff_filter = options.get("diff_filter", None)
        if diff_filter is not None:
            if type(diff_filter) is not str or not _DIFF_FILTER.fullmatch(diff_filter):
                _invalid("diff.diff_filter must be letters from ACDMRTUXB*.")
            values["diff_filter"] = diff_filter
        for key, flag in (("pickaxe", "-S"), ("pickaxe_regex", "-G")):
            if key in options:
                needle = _text(options[key], "diff." + key, 1024)
                values[key] = needle
                values[key + "_flag"] = flag + needle
        endpoints: list[tuple[str, str]] = []
        if "base" in options:
            kind, token = _diff_revision(options["base"], "diff.base")
            values["base"] = token
            values["base_kind"] = kind
            endpoints.append((kind, token))
        if "end" in options:
            kind, token = _diff_revision(options["end"], "diff.end")
            values["end"] = token
            values["end_kind"] = kind
            endpoints.append((kind, token))
        if endpoints:
            argv = ["--no-lazy-fetch", "diff"]
        for key, flag in _DIFF_BOOL_FLAGS:
            if values[key]:
                argv.append(flag)
        if "unified" in values:
            argv.append("-U" + str(values["unified"]))
        if "diff_algorithm" in values:
            argv.append("--diff-algorithm=" + values["diff_algorithm"])
        if "diff_filter" in values:
            argv.append("--diff-filter=" + values["diff_filter"])
        for key in ("pickaxe", "pickaxe_regex"):
            if key + "_flag" in values:
                argv.append(values.pop(key + "_flag"))
        if endpoints:
            if range_op is None:
                argv.extend(["--end-of-options", *(token for _kind, token in endpoints)])
            else:
                argv.extend(["--end-of-options", endpoints[0][1] + range_op + endpoints[1][1]])
    elif command == "rev-parse":
        # Fixed read-only queries only. Missing promised objects must fail
        # rather than invoking a remote fetch. tree/head stay on HEAD; branch
        # resolves one lexically checked local branch and no other revision.
        target = options.get("target", "tree")
        if type(target) is not str or target not in {"tree", "head", "branch"}:
            _invalid("rev-parse.target must be 'tree', 'head', or 'branch'.")
        if "target" in options:
            values["target"] = target
        if target == "branch":
            if "name" not in options:
                _invalid("rev-parse branch target requires name.")
            name = values["name"] = validate_git_branch_name(options["name"])
            argv = ["--no-lazy-fetch", command, "--verify", "--end-of-options",
                    "refs/heads/" + name]
        else:
            if "name" in options:
                _invalid("rev-parse name is only valid when target is 'branch'.")
            revision = "HEAD^{commit}" if target == "head" else "HEAD^{tree}"
            argv = ["--no-lazy-fetch", command, "--verify", revision]
    elif command == "rev-list":
        limit = options.get("limit", 1)
        if type(limit) is not int or not 1 <= limit <= 50:
            _invalid("rev-list.limit must be an integer from 1 to 50.")
        commit = values["commit"] = _commit_oid(_required(options, "commit"), "rev-list.commit")
        values["limit"] = limit
        argv = ["--no-lazy-fetch", "rev-list", "--parents",
                "--max-count=" + str(limit), "--end-of-options", commit]
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
