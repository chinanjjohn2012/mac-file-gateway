"""Internal, non-public LBE original-child launcher for approved isolated T1.

This callable is not connected to the public WorkspaceService apply path.
Only a trusted Worker holding its bounded reservation may call it. There is
no default launcher, no shell, OS signal, killpg, retry, or descendant proof.
"""
from __future__ import annotations

import os
import stat
import subprocess
from typing import TYPE_CHECKING, Callable

from .core import GatewayError, _parts
from .executor import _SAFE_ENV_KEYS
from .lbe_worker import LbeNoChildStarted, LbeWorkPlan, OriginalChild

if TYPE_CHECKING:
    from .workspaces import WorkspaceContext


def make_trusted_lbe_launcher(ctx: "WorkspaceContext") -> Callable[[LbeWorkPlan], OriginalChild]:
    """Repeat the authoritative plan and path policy just before spawning.

    Any validation failure before Popen witnesses no child started. Exceptions
    in or after Popen remain ambiguous and are handled fail-closed by Worker.
    """
    from .workspaces import WorkspaceContext

    if type(ctx) is not WorkspaceContext:
        raise TypeError("Trusted WorkspaceContext required.")

    def launch(plan: LbeWorkPlan) -> OriginalChild:
        if type(plan) is not LbeWorkPlan or plan.workspace != ctx.name:
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
            env = {key: value for key in _SAFE_ENV_KEYS
                   if (value := os.environ.get(key))}
            env["PATH"] = os.environ.get("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            env["PYTHONUNBUFFERED"] = "1"
            if checked.runner == "pipenv":
                pipfile = ctx.gateway._root_path.joinpath(
                    *_parts(checked.runner_project), "Pipfile")
                st = os.stat(pipfile, follow_symlinks=False)
                if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
                    raise LbeNoChildStarted("no child: unsafe Pipfile")
                env["PIPENV_PIPFILE"] = str(pipfile)
                env["PIPENV_NOSPIN"] = "1"
        except (GatewayError, OSError, ValueError):
            raise LbeNoChildStarted("no child: prelaunch validation refused") from None

        # Boundary: Popen may have started a child even if it raises OSError.
        # Worker conservatively latches admission unavailable on ambiguity.
        return subprocess.Popen(
            list(checked.effective_argv),
            cwd=str(cwd_path), env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True,
            start_new_session=False,
        )

    return launch
