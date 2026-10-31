"""Internal LBE original-child launcher restricted to approved Python T1.

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
            # P001-P007 attest *separate CI source inputs*, not this running
            # service's PATH, installed files, module cache or Pipenv venv.
            # Never feed an unqualified Go/Pipenv primary into Popen even if
            # an internal plan or test-only Python Worker reaches this launcher.
            if (checked.runner == "pipenv"
                    or (checked.effective_argv
                        and checked.effective_argv[0] in {"go", "pipenv"})):
                raise LbeNoChildStarted(
                    "no child: Go/Pipenv executable and dependency identity "
                    "not qualified at the real launch boundary")
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
