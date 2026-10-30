"""Shared schema-v2 command plan validation for preview AND real apply.

The plan itself grants no authority: WorkspaceService performs the old-state
and per-Workspace gates before calling this validator, and the private
launcher rechecks paths and arguments immediately before native Popen.
No plan, path or runner validation is a host sandbox or descendant proof.
"""
from __future__ import annotations

import stat
from typing import TYPE_CHECKING

from .core import GatewayError, _parts
from .executor import _canonical, _clean_argv
from .lbe_go_policy import GoPolicyError, validate_go_command
from .lbe_worker import LbeWorkPlan

if TYPE_CHECKING:
    from .workspaces import WorkspaceContext


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
            pipfile = ctx.gateway._root_path.joinpath(*pipfile_parts)
            try:
                metadata = pipfile.stat(follow_symlinks=False)
            except OSError:
                raise GatewayError(
                    "runner_unavailable",
                    "Configured Pipenv runner requires a safe Pipfile.",
                ) from None
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise GatewayError(
                    "runner_unavailable",
                    "Configured Pipenv runner requires a safe Pipfile.",
                )

    plan = LbeWorkPlan(
        workspace=ctx.name,
        cwd=canonical_cwd,
        requested_argv=tuple(requested),
        effective_argv=tuple(effective),
        runner=selected_runner,
        runner_project=runner_project,
        timeout_seconds=timeout_seconds,
    )
    # Both caller- and worker-side shape checks stay active. Neither check
    # grants Exec or bypasses the existing private state/admission gates.
    from .lbe_worker import LbeWorker, LbeWorkerError

    try:
        LbeWorker._check_plan(plan)
    except LbeWorkerError:
        # A dormant helper now feeds the public v2 preview. Do not turn an
        # invalid prospective Worker plan into an uncaught REST/MCP 500 or
        # leak its internal dependency/exception messages.
        raise GatewayError("invalid_argument",
                           "Command plan is not valid for this execution mode.") from None
    return plan

