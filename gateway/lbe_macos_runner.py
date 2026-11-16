"""Service-owned macOS Runner launch boundary for D4 R003 product SOURCE.

This is the real Worker-facing adapter for the fixed six-command recipe,
rather than a client-provided launcher callback. It binds a live Workspace,
immutable source selection and Runner observation, then repeats those facts
at the exact pre-spawn point. There is deliberately NO runnable R003 grant:
the operative F1/D0 gate, qualified whole-descendant CPU/RAM domain,
immutable macOS provider image and exact owner T1 approval are absent.

Do not replace this denial with a T0 dataclass, mocked capability, environment
variable or subprocess/rlimit alone. The separately reviewed physical domain
implementation must be introduced before this can ever launch a native child.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
from typing import TYPE_CHECKING

from .lbe_launch_recipe import D4NativeLaunchRecipe, _PROPOSED_LIMITS
from .lbe_runner_preflight import (
    D4ObservedRunnerPreflight, D4RunnerProbeDenied,
    observe_d4_runner_preflight, require_d4_native_runner_admission,
)
from .lbe_worker import LbeNoChildStarted, LbeWorkPlan, LbeWorker, LbeWorkerError

if TYPE_CHECKING:
    from .workspaces import WorkspaceContext


class D4MacOSRunnerDenied(ValueError):
    """No valid service-owned Runner launch boundary or live source."""


@dataclass(frozen=True, slots=True)
class D4MacOSRunnerLaunchIntent:
    """A real service-constructed command/host binding, NOT a grant."""

    workspace: str
    runner: str
    resolved_executable: str
    requested_argv: tuple[str, ...]
    resolved_spawn_argv: tuple[str, ...]
    closed_child_environment: tuple[tuple[str, str], ...]
    working_directory: str
    original_timeout_seconds: int
    selected_source_fingerprint: str
    required_limits: tuple[tuple[str, int], ...]
    status: str = "PRESPAWN_PRODUCT_RECIPE_READY_BUT_NATIVE_DENIED"
    source_prelaunch_recheck_required: bool = True
    real_macos_runner_attested: bool = False
    original_and_descendant_domain_enforced: bool = False
    owner_native_t1_approved: bool = False
    operative_f1_d0_exception_effective: bool = False
    native_launch_allowed: bool = False


class D4MacOSRunnerLaunchBoundary:
    """One service-owned Worker launcher, permanently nonoperative at R003.

    The Worker can use this object as its trusted injected launch callback.
    Binding it to the same one-use candidate ensures source observation occurs
    again after Worker burns the attempt. The final launch callback repeats
    the live host/runner facts and requires actual OS-domain admission
    before any possible process. A T0 input can never mint that admission.
    """
    __slots__ = ("_ctx", "_plan", "_recipe", "_host", "_root", "_pid",
                 "_intent")

    def __init__(self, ctx: "WorkspaceContext", plan: LbeWorkPlan,
                 recipe: D4NativeLaunchRecipe,
                 host: D4ObservedRunnerPreflight, *, private_root: str):
        from .workspaces import WorkspaceContext
        from .lbe_runtime_source import D4RuntimeSourceDenied, _canonical

        if (type(ctx) is not WorkspaceContext or type(plan) is not LbeWorkPlan
                or type(recipe) is not D4NativeLaunchRecipe
                or type(host) is not D4ObservedRunnerPreflight
                or type(private_root) is not str):
            raise D4MacOSRunnerDenied("untrusted Runner source binding")
        try:
            LbeWorker._check_plan(plan)
            root = _canonical(private_root, "private runner root")
        except (LbeWorkerError, D4RuntimeSourceDenied):
            raise D4MacOSRunnerDenied("Runner source path/plan invalid") from None
        if (ctx.name != plan.workspace or ctx.name != recipe.workspace
                or host.workspace != ctx.name
                or recipe.runner != plan.runner
                or recipe.requested_argv != plan.requested_argv
                or recipe.service_effective_argv != plan.effective_argv
                or recipe.original_timeout_seconds != plan.timeout_seconds
                or recipe.required_limits != _PROPOSED_LIMITS
                or host.proposed_limits != _PROPOSED_LIMITS
                or recipe.selected_source_fingerprint != host.source_fingerprint
                or not recipe.resolved_executable.startswith(root + "/")
                or not recipe.working_directory.startswith(root + "/")
                or recipe.resolved_spawn_argv != (
                    recipe.resolved_executable, *plan.effective_argv[1:])
                or type(recipe.closed_child_environment) is not tuple
                or not recipe.closed_child_environment
                or recipe.native_launch_allowed is not False
                or host.native_launch_allowed is not False
                or recipe.owner_t1_grant_present is not False
                or host.exact_owner_native_t1_authorized is not False
                or recipe.physical_cpu_memory_enforcement_proven is not False
                or host.physical_whole_child_cpu_memory_attached is not False
                or host.github_provider_attested is not False
                or host.loaded_source_graph_proven is not False):
            raise D4MacOSRunnerDenied("unqualified native Runner proposal")
        self._ctx = ctx
        self._plan = plan
        self._recipe = recipe
        self._host = host
        self._root = root
        self._pid = os.getpid()
        self._intent = D4MacOSRunnerLaunchIntent(
            workspace=ctx.name, runner=plan.runner,
            resolved_executable=recipe.resolved_executable,
            requested_argv=plan.requested_argv,
            resolved_spawn_argv=recipe.resolved_spawn_argv,
            closed_child_environment=recipe.closed_child_environment,
            working_directory=recipe.working_directory,
            original_timeout_seconds=recipe.original_timeout_seconds,
            selected_source_fingerprint=recipe.selected_source_fingerprint,
            required_limits=recipe.required_limits,
        )
        self.recheck_for(ctx, plan)

    @property
    def intent(self) -> D4MacOSRunnerLaunchIntent:
        return self._intent

    def check_binding(self, ctx: "WorkspaceContext", plan: object) -> None:
        if (ctx is not self._ctx or plan is not self._plan
                or os.getpid() != self._pid):
            raise D4MacOSRunnerDenied("Runner service or process identity changed")

    def recheck_for(self, ctx: "WorkspaceContext", plan: object) -> None:
        self.check_binding(ctx, plan)
        try:
            current = observe_d4_runner_preflight(
                self._ctx, self._recipe, private_root=self._root)
        except (D4RunnerProbeDenied, OSError):
            raise D4MacOSRunnerDenied(
                "Runner prelaunch host/source observation unavailable") from None
        if current != self._host:
            raise D4MacOSRunnerDenied(
                "Runner host, path, resource or ambient selector drift")

    def launch(self, plan: LbeWorkPlan):
        """Worker-facing exact pre-spawn path; hard deny without real T1.

        LbeNoChildStarted is valid here: NO subprocess, process registration,
        signal or OS-domain attachment is attempted. Existing Python-only
        authorized T1 uses its own original launcher, not this future R003
        PRODUCT_T1 path. Returning this witness permits Worker to release a
        reservation safely, without latching an imaginary running child.
        """
        try:
            self.recheck_for(self._ctx, plan)
            # Checking the actual host is necessary but not sufficient.
            # In particular, even genuine macOS ARM64 and finite rlimits
            # cannot establish a CPU/RAM domain for all descendants.
            if (self._host.kernel_sysname != "Darwin"
                    or self._host.machine not in ("arm64", "aarch64")
                    or self._host.ambient_sensitive_credentials_present):
                raise D4MacOSRunnerDenied(
                    "unqualified macOS Runner or exposed credentials")
            require_d4_native_runner_admission(self._host, self._recipe)
        except (D4RunnerProbeDenied, D4MacOSRunnerDenied, OSError):
            raise LbeNoChildStarted(
                "no child: macOS Runner resource/owner admission not proven"
            ) from None
        # Even if a future dependency accidentally stops raising, no
        # SOURCE/T0 build is permitted to spawn. A separately reviewed
        # change must replace BOTH this hard stop and the real admission
        # implementation with the approved OS-attached resource backend.
        raise LbeNoChildStarted(
            "no child: PRODUCT_T1 not enabled by the operative F1/D0 contract"
        )
