"""Dormant version-2 Exec configuration fragment preflight.

This intentionally does NOT modify parse_workspace_config (schema v1), grant
execution, read a user's private configuration, check the v1 owner.lock, or
start a process. No caller in the live Gateway uses this module. The complete
version-2 configuration/Workspace identity contract still requires a separate
approved implementation and review before any positive Exec.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

_MAX_SCOPES = 32
_MAX_BYTES = 2048
_FORBIDDEN = frozenset("*?[]:\\")


class LbeConfigError(ValueError):
    """A proposed v2 Exec fragment is invalid or ambiguous."""


def _record(value: Any, label: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise LbeConfigError(label + " must be a JSON object")
    # Snapshot only exact built-in dictionaries; no user-defined mapping hooks.
    return dict(value)


def _relative_parts(value: Any, label: str) -> tuple[str, ...]:
    if type(value) is not str or not value or len(value.encode("utf-8")) > _MAX_BYTES:
        raise LbeConfigError(label + " must be a nonempty bounded path string")
    if value == ".":
        return ()
    if value.startswith(("/", "~")) or any(ch in _FORBIDDEN or ord(ch) < 32
                                           or ord(ch) == 127 for ch in value):
        raise LbeConfigError(label + " must be a canonical relative path")
    parts = tuple(value.split("/"))
    if any(part in {"", ".", ".."} for part in parts):
        raise LbeConfigError(label + " must not contain empty or dot components")
    return parts


def _within(parts: tuple[str, ...], scope: tuple[str, ...]) -> bool:
    return len(parts) >= len(scope) and parts[:len(scope)] == scope


def _unique_paths(value: Any, label: str) -> tuple[tuple[str, ...], ...]:
    if type(value) is not list:
        raise LbeConfigError(label + " must be a JSON string list")
    frozen = tuple(value)
    if len(frozen) > _MAX_SCOPES:
        raise LbeConfigError(label + " exceeds 32 entries")
    parsed = tuple(_relative_parts(x, label) for x in frozen)
    # Reject case-only ambiguous authorities even on case-sensitive hosts.
    lowered = tuple(tuple(p.casefold() for p in path) for path in parsed)
    if len(set(lowered)) != len(lowered):
        raise LbeConfigError(label + " has duplicate or case-ambiguous scopes")
    return parsed


@dataclass(frozen=True)
class LbeExecGrant:
    """Immutable v2 scope/runners *proposal*, never an actual runtime grant."""

    paths: tuple[tuple[str, ...], ...]
    runners: tuple[tuple[tuple[str, ...], str], ...]

    @property
    def enabled(self) -> bool:
        return bool(self.paths)

    def runner_for(self, cwd: str, command_kind: str) -> str:
        """Pure T0 selection; raises on an unauthorized cwd.

        This never replaces the future pinned-FD Workspace/cwd/security checks.
        Go always uses Direct even if a Pipenv runner is selected for Python.
        """
        cwd_parts = _relative_parts(cwd, "cwd")
        if not any(_within(cwd_parts, scope) for scope in self.paths):
            raise LbeConfigError("cwd is outside explicit Exec path grants")
        if command_kind == "go":
            return "direct"
        if command_kind != "python":
            raise LbeConfigError("unknown command kind")
        winner = max(
            ((len(path), runner) for path, runner in self.runners
             if _within(cwd_parts, path)),
            default=None,
        )
        return winner[1] if winner is not None else "direct"


def parse_lbe_exec_fragment(
    *, schema_version: int, server: dict[str, Any],
    workspace: dict[str, Any],
) -> LbeExecGrant:
    """Inspect v2 Exec-only fields, preserving v1's separate deny-only parser.

    Other server/workspace fields (roots, read, write, Git, transport, and
    protected private-state identity) are NOT validated by this fragment.
    Never use this function alone as complete config or Exec authorization.
    """
    if type(schema_version) is not int or schema_version != 2:
        raise LbeConfigError("this preflight accepts only schema_version=2")
    server_snapshot = _record(server, "server")
    workspace_snapshot = _record(workspace, "workspace")
    server_exec = _record(server_snapshot.get("exec", {}), "server.exec")
    if server_exec:
        # In v2 there is no server.exec.enabled, nor any other server Exec grant.
        raise LbeConfigError("schema_version=2 does not accept server.exec switches")

    raw = _record(workspace_snapshot.get("exec", {}), "workspace.exec")
    if set(raw) - {"paths", "runners"}:
        raise LbeConfigError("unknown v2 workspace.exec fields")
    paths = _unique_paths(raw.get("paths", []), "exec.paths")

    runners_value = raw.get("runners", [])
    if type(runners_value) is not list:
        raise LbeConfigError("exec.runners must be a JSON string list")
    frozen_runners = tuple(runners_value)
    if len(frozen_runners) > _MAX_SCOPES:
        raise LbeConfigError("exec.runners exceeds 32 entries")
    if frozen_runners and not paths:
        raise LbeConfigError("runners cannot create an Exec grant without paths")

    runners: list[tuple[tuple[str, ...], str]] = []
    seen: set[tuple[str, ...]] = set()
    for entry in frozen_runners:
        if type(entry) is not str or entry.count("=") != 1:
            raise LbeConfigError("runner must be PATH=direct or PATH=pipenv")
        name, runner = entry.split("=", 1)
        scope = _relative_parts(name, "exec.runners")
        if runner not in {"direct", "pipenv"}:
            raise LbeConfigError("runner must select direct or pipenv")
        if not any(_within(scope, grant) for grant in paths):
            raise LbeConfigError("runner path is outside explicit Exec grant")
        alias = tuple(x.casefold() for x in scope)
        if alias in seen:
            raise LbeConfigError("duplicate or case-ambiguous runner path")
        seen.add(alias)
        runners.append((scope, runner))
    return LbeExecGrant(paths=paths, runners=tuple(runners))

