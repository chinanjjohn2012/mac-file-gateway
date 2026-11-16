"""Original-child launcher: legacy Python T1 or exact-six reviewed MVP.

Ordinary public schema-v2 apply is fail-closed in WorkspaceService. Its
private hosted Python-only T1 fixture can reach this launcher; unqualified
Go/Pipenv primary executions are denied immediately before Popen even for
an internal plan. No shell, OS signal, retry or descendant-cleanup proof.
"""
from __future__ import annotations

import os
import stat
import subprocess
from typing import TYPE_CHECKING, Callable

from .core import GatewayError, _parts
from .executor import _SAFE_ENV_KEYS
from .lbe_worker import (LbeNoChildStarted, LbeWorkPlan, OriginalChild,
                         LbeWorker, LbeWorkerError)
from .lbe_mvp_tools import MvpTrustedTools
from .lbe_six_fixed_commands import match_fixed_six_command

if TYPE_CHECKING:
    from .workspaces import WorkspaceContext


def make_trusted_lbe_launcher(
    ctx: "WorkspaceContext", *, mvp_tools: MvpTrustedTools | None = None,
) -> Callable[[LbeWorkPlan], OriginalChild]:
    """Repeat the authoritative plan and path policy just before spawning.

    Any validation failure before Popen witnesses no child started. Exceptions
    in or after Popen remain ambiguous and are handled fail-closed by Worker.
    """
    from .workspaces import WorkspaceContext

    if type(ctx) is not WorkspaceContext:
        raise TypeError("Trusted WorkspaceContext required.")
    if mvp_tools is not None and type(mvp_tools) is not MvpTrustedTools:
        raise TypeError("Trusted startup tool selection required.")

    def launch(plan: LbeWorkPlan) -> OriginalChild:
        # An LbeWorkPlan dataclass does not enforce annotated field types.
        # A hostile frozen instance can use __eq__/__ne__ of a field to
        # masquerade as a canonical plan during the equality check below.
        # Validate FIRST, before any comparison of untrusted plan values,
        # including the workspace name and whole-plan equality.
        if type(plan) is not LbeWorkPlan:
            raise LbeNoChildStarted("no child: invalid internal plan")
        try:
            LbeWorker._check_plan(plan)
        except LbeWorkerError:
            raise LbeNoChildStarted("no child: invalid internal plan") from None
        if plan.workspace != ctx.name:
            raise LbeNoChildStarted("no child: invalid internal plan")
        from .lbe_plan import prepare_lbe_work_plan

        try:
            checked = prepare_lbe_work_plan(
                ctx, cwd=plan.cwd, argv=list(plan.requested_argv),
                timeout_seconds=plan.timeout_seconds,
            )
            if checked != plan:
                raise LbeNoChildStarted("no child: plan changed")
            executor = ctx.gateway._executor
            if executor is None:
                raise LbeNoChildStarted("no child: executor unavailable")
            _, cwd_path = executor._cwd(checked.cwd)
            if mvp_tools is not None:
                # Re-run the reviewed exact-six predicate immediately before
                # Popen, regardless of an earlier service-side plan match.
                # A broad preview-valid command must never execute here.
                if match_fixed_six_command(**vars(checked)) is None:
                    raise LbeNoChildStarted(
                        "no child: command not in fixed MVP execution matrix")
                argv_to_launch, env = mvp_tools.select_launch(
                    checked, workspace_root=ctx.gateway._root_path)
            else:
                # Keep the older separately authorized hosted Python-only
                # T1 behavior unchanged for its private, non-public route.
                if (checked.runner == "pipenv"
                        or (checked.effective_argv
                            and checked.effective_argv[0] in {"go", "pipenv"})):
                    raise LbeNoChildStarted(
                        "no child: Go/Pipenv executable and dependency identity "
                        "not qualified at the real launch boundary")
                env = {key: value for key in _SAFE_ENV_KEYS
                       if (value := os.environ.get(key))}
                env["PATH"] = os.environ.get(
                    "PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
                env["PYTHONUNBUFFERED"] = "1"
                argv_to_launch = list(checked.effective_argv)
        except (GatewayError, OSError, ValueError):
            raise LbeNoChildStarted("no child: prelaunch validation refused") from None

        # Boundary: Popen may have started a child even if it raises OSError.
        # Worker conservatively latches admission unavailable on ambiguity.
        return subprocess.Popen(
            argv_to_launch,
            cwd=str(cwd_path), env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True,
            start_new_session=False,
        )

    return launch
