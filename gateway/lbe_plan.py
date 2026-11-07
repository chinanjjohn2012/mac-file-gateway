"""Shared schema-v2 command plan validation for preview AND real apply.

The plan itself grants no authority: WorkspaceService performs the old-state
and per-Workspace gates before calling this validator, and the private
launcher rechecks paths and arguments immediately before native Popen.
No plan, path or runner validation is a host sandbox or descendant proof.
"""
from __future__ import annotations

import os
import stat
from typing import TYPE_CHECKING

from .core import GatewayError, _parts
from .executor import _canonical, _clean_argv, _validate_command
from .lbe_go_policy import GoPolicyError, validate_go_command
from .lbe_worker import LbeWorkPlan

if TYPE_CHECKING:
    from .workspaces import WorkspaceContext



def _check_owner_controlled_source_parents(
    root_fd: int, source_parts: tuple[str, ...],
) -> None:
    """Check actual Workspace-relative ancestor FDs of a selected source.

    Unlike a byte digest of the file itself, this rejects directories that
    another same-host user could rewrite before a future pathname launch.
    This is only a conservative preflight check, NOT an immutable source FD
    to exec binding, sandbox or evidence that imports/toolchains are closed.
    The native launcher repeats this same shared plan immediately pre-Popen.
    """
    if not source_parts:
        raise GatewayError("runner_unavailable", "Unqualified source path.")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    held: list[int] = []
    try:
        fd = os.dup(root_fd)
        held.append(fd)
        for name in (None, *source_parts[:-1]):
            if name is not None:
                fd = os.open(name, flags, dir_fd=fd)
                held.append(fd)
            metadata = os.fstat(fd)
            if (not stat.S_ISDIR(metadata.st_mode)
                    or metadata.st_uid != os.getuid()
                    or metadata.st_mode & 0o022):
                raise GatewayError(
                    "runner_unavailable",
                    "Selected source parent must be owner-controlled.",
                )
    except OSError:
        raise GatewayError(
            "runner_unavailable", "Selected source parent cannot be safely opened.",
        ) from None
    finally:
        for fd in reversed(held):
            os.close(fd)


def prepare_lbe_work_plan(
    ctx: "WorkspaceContext", *, cwd: str, argv: list[str],
    timeout_seconds: int = 60,
) -> LbeWorkPlan:
    """Compute a consistent v2 Python/Pipenv or Go Direct plan, no spawn."""
    from .workspaces import WorkspaceContext

    if type(ctx) is not WorkspaceContext:
        raise GatewayError("invalid_argument", "Expected trusted Workspace context.")
    if (not ctx.settings.exec_enabled or ctx.gateway._executor is None
            or not ctx.gateway._executor.enabled
            or ctx.gateway._executor.auto_pipenv is not False):
        raise GatewayError("exec_disabled", "Version-two Exec preview is unavailable.")
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 300:
        raise GatewayError("invalid_argument", "Invalid timeout_seconds.")
    requested = _clean_argv(argv)
    # Reuse the legacy no-follow pinned cwd and explicit execution-scope
    # checks; do not convert an invalid root to a successful preview.
    runner = ctx.gateway._executor
    cwd_parts, _cwd_path = runner._cwd(cwd)
    canonical_cwd = _canonical(cwd_parts)

    planned_go_output = None
    planned_script_sha256 = None
    planned_pipfile_sha256 = None
    if requested[0] == "go":
        try:
            validated = validate_go_command(
                requested, workspace_root=ctx.gateway._root_path,
                cwd=canonical_cwd, exec_paths=ctx.settings.exec_paths,
                output_allowed=lambda parts: ctx.gateway._allowed(
                    parts, is_file=False),
            )
        except GoPolicyError:
            raise GatewayError("command_not_allowed",
                               "Go command or output is not allowed.") from None
        effective = validated.argv
        # The Go policy has already checked Workspace scopes, exclusions
        # and a nofollow output parent. Preserve its canonical output path
        # as preview information, never as proof that a file was written.
        planned_go_output = validated.output_relative_to_workspace
        selected_runner = "direct"
        runner_project = canonical_cwd
    else:
        # Legacy CommandRunner has the authoritative Python/script/Pipfile
        # no-follow policy. Explicit dry_run=True never reaches Popen.
        preview = ctx.gateway.run_command(
            cwd, requested, timeout_seconds=timeout_seconds, dry_run=True)
        effective = tuple(preview["effective_argv"])
        selected_runner = preview["runner"]
        runner_project = preview["runner_project"]
        # Record only a bounded, permission-checked FIRST-PARTY script's
        # bytes from a pinned nofollow FD. This is not a claim about the
        # interpreter, imports, runtime loader or later path identity.
        script = _validate_command(requested)
        if script is not None:
            source_parts = (*_parts(canonical_cwd), *_parts(script))
            if not ctx.gateway._allowed(source_parts, is_file=True):
                raise GatewayError("blocked_path",
                                   "Python source path is not allowed.")
            _check_owner_controlled_source_parents(
                ctx.gateway._root_fd, source_parts)
            script_snapshot = ctx.gateway._snapshot(source_parts)
            # A digest of an unsafe, group/world-mutable or foreign-owned
            # script is not a trusted prospective launch input. Reject it
            # in the real shared preview and again in private launch replan.
            # No source digest grants F1 positive execution.
            script_meta = script_snapshot.metadata
            if (script_meta.st_uid != os.getuid()
                    or script_meta.st_mode & 0o022):
                raise GatewayError(
                    "runner_unavailable",
                    "Python source requires owner-controlled permissions.",
                )
            planned_script_sha256 = script_snapshot.sha256
        if selected_runner == "pipenv":
            # The private launcher requires a single-link regular Pipfile
            # immediately before Popen. Make the public preview reject the
            # same unsafe static input, rather than advertising a plan that
            # apply would inevitably deny. This is V2-only; v1 is unchanged.
            pipfile_parts = (*_parts(runner_project), "Pipfile")
            # This runner input must honor the Gateway path denylist and
            # Workspace excludes, just as source scripts and Go outputs do.
            # The subprocess remains operator-trusted code, not sandboxed.
            if not ctx.gateway._allowed(pipfile_parts, is_file=False):
                raise GatewayError(
                    "runner_unavailable",
                    "Configured Pipenv runner requires an allowed Pipfile.",
                )
            _check_owner_controlled_source_parents(
                ctx.gateway._root_fd, pipfile_parts)
            try:
                # Re-open the entire runner project using Gateway's pinned
                # no-follow directory traversal. A path swap between the
                # CommandRunner preview and this check must not make a
                # linked/foreign Pipfile look like the trusted source.
                with ctx.gateway._directory(_parts(runner_project)) as parent:
                    pipfile_snapshot = ctx.gateway._snapshot_at(parent, "Pipfile")
                    metadata = pipfile_snapshot.metadata
            except (OSError, GatewayError):
                raise GatewayError(
                    "runner_unavailable",
                    "Configured Pipenv runner requires a safe Pipfile.",
                ) from None
            if (not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_nlink != 1
                    or metadata.st_uid != os.getuid()
                    or metadata.st_mode & 0o022):
                raise GatewayError(
                    "runner_unavailable",
                    "Configured Pipenv runner requires a safe Pipfile.",
                )
            planned_pipfile_sha256 = pipfile_snapshot.sha256

    plan = LbeWorkPlan(
        workspace=ctx.name,
        cwd=canonical_cwd,
        requested_argv=tuple(requested),
        effective_argv=tuple(effective),
        runner=selected_runner,
        runner_project=runner_project,
        timeout_seconds=timeout_seconds,
        planned_go_output=planned_go_output,
        planned_script_sha256=planned_script_sha256,
        planned_pipfile_sha256=planned_pipfile_sha256,
    )
    # Both caller- and worker-side shape checks stay active. Neither check
    # grants Exec or bypasses the existing private state/admission gates.
    from .lbe_worker import LbeWorker, LbeWorkerError

    try:
        LbeWorker._check_plan(plan)
    except LbeWorkerError:
        # An internal Worker shape check feeds public v2 preview. Do not
        # turn an invalid plan into an uncaught REST/MCP 500 or
        # leak its internal dependency/exception messages.
        raise GatewayError("invalid_argument",
                           "Command plan is not valid for this execution mode.") from None
    return plan

