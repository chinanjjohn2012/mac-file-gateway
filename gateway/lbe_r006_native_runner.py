"""Private R006 native launch boundary source candidate.

This module is NOT wired to public WorkspaceService.invoke_exec, REST or MCP.
It requires a process-bound D4ConsumedOwnerGrant produced only after exact
grant/run/recipe binding and durable nonce consumption, plus the existing
one-use first-party/source marker and a fixed prior-run macOS host profile.

All rechecks happen before Popen. Known pre-Popen denial raises
LbeNoChildStarted. Exceptions from Popen itself are deliberately not converted:
the caller/Worker must treat them as ambiguous after-spawn failures.
"""
from __future__ import annotations

import os
import subprocess
import threading
from typing import TYPE_CHECKING

from .lbe_launch_recipe import D4NativeLaunchRecipe
from .lbe_owner_grant_bootstrap import (
    D4ConsumedOwnerGrant, D4OwnerBootstrapDenied,
)
from .lbe_product_fixture import (
    D4FixtureCandidate, D4FixtureDenied, D4OneUseAttemptMarker,
)
from .lbe_r006_macos_allowlist import (
    D4R006HostAllowlistDenied, D4R006HostAllowlistObservation,
    verify_r006_fixed_host_allowlist_t0,
)
from .lbe_worker import LbeNoChildStarted, LbeWorkPlan, LbeWorker, LbeWorkerError

if TYPE_CHECKING:
    from .workspaces import WorkspaceContext


class D4R006NativeRunnerDenied(ValueError):
    """R006 private native launch prerequisites are not exact."""


_PREPARED_TOKEN = object()


class D4R006PreparedAttempt:
    """One in-process staged candidate awaiting an exact owner grant."""

    __slots__ = ("_ctx", "_candidate", "_marker", "_recipe", "_host",
                 "_pid", "_lock", "_used")

    def __init__(self, token, ctx: "WorkspaceContext",
                 candidate: D4FixtureCandidate, marker: D4OneUseAttemptMarker,
                 recipe: D4NativeLaunchRecipe,
                 host: D4R006HostAllowlistObservation):
        from .workspaces import WorkspaceContext
        if token is not _PREPARED_TOKEN:
            raise D4R006NativeRunnerDenied(
                "prepared R006 attempt cannot be directly constructed")
        if (type(ctx) is not WorkspaceContext
                or type(candidate) is not D4FixtureCandidate
                or type(marker) is not D4OneUseAttemptMarker
                or type(recipe) is not D4NativeLaunchRecipe
                or type(host) is not D4R006HostAllowlistObservation
                or marker._candidate is not candidate
                or marker._ctx is not ctx
                or candidate.plan is not marker._candidate.plan
                or recipe.workspace != candidate.plan.workspace
                or recipe.runner != candidate.plan.runner
                or recipe.requested_argv != candidate.plan.requested_argv
                or recipe.service_effective_argv != candidate.plan.effective_argv
                or recipe.original_timeout_seconds != candidate.plan.timeout_seconds
                or host.selected_source_bytes_verified is not True
                or host.native_launch_allowed is not False):
            raise D4R006NativeRunnerDenied("invalid prepared R006 source candidate")
        self._ctx = ctx
        self._candidate = candidate
        self._marker = marker
        self._recipe = recipe
        self._host = host
        self._pid = os.getpid()
        self._lock = threading.Lock()
        self._used = False

    @property
    def plan(self) -> LbeWorkPlan:
        return self._candidate.plan

    @property
    def recipe_fingerprint(self) -> str:
        return self._recipe.selected_source_fingerprint

    @property
    def host_source_fingerprint(self) -> str:
        return self._host.source_fingerprint

    @property
    def runner_profile_fingerprint(self) -> str:
        return self._host.runner_profile_fingerprint

    def claim(self, ctx: "WorkspaceContext"):
        """Burn before owner/runtime binding; any failed execute needs new prep."""
        with self._lock:
            if self._used:
                raise D4R006NativeRunnerDenied("prepared R006 attempt replayed")
            self._used = True
        if (os.getpid() != self._pid or ctx is not self._ctx
                or self._marker._candidate is not self._candidate
                or self._candidate.plan is not self._recipe_plan()):
            raise D4R006NativeRunnerDenied("prepared R006 attempt binding changed")
        return (self._candidate, self._marker, self._recipe, self._host)

    def _recipe_plan(self) -> LbeWorkPlan:
        plan = self._candidate.plan
        if (self._recipe.workspace != plan.workspace
                or self._recipe.runner != plan.runner
                or self._recipe.requested_argv != plan.requested_argv
                or self._recipe.service_effective_argv != plan.effective_argv
                or self._recipe.original_timeout_seconds != plan.timeout_seconds):
            raise D4R006NativeRunnerDenied("prepared R006 recipe drift")
        return plan


def _new_r006_prepared_attempt(ctx: "WorkspaceContext",
                              candidate: D4FixtureCandidate,
                              marker: D4OneUseAttemptMarker,
                              recipe: D4NativeLaunchRecipe,
                              host: D4R006HostAllowlistObservation
                              ) -> D4R006PreparedAttempt:
    return D4R006PreparedAttempt(
        _PREPARED_TOKEN, ctx, candidate, marker, recipe, host)


class D4R006NativeLaunchBoundary:
    """One private exact-attempt launcher; no public/config grant."""

    __slots__ = ("_ctx", "_plan", "_recipe", "_host", "_consumed",
                 "_marker", "_pid")

    def __init__(self, ctx: "WorkspaceContext", plan: LbeWorkPlan,
                 recipe: D4NativeLaunchRecipe,
                 host: D4R006HostAllowlistObservation,
                 consumed: D4ConsumedOwnerGrant,
                 marker: D4OneUseAttemptMarker):
        from .workspaces import WorkspaceContext
        if (type(ctx) is not WorkspaceContext or type(plan) is not LbeWorkPlan
                or type(recipe) is not D4NativeLaunchRecipe
                or type(host) is not D4R006HostAllowlistObservation
                or type(consumed) is not D4ConsumedOwnerGrant
                or type(marker) is not D4OneUseAttemptMarker):
            raise D4R006NativeRunnerDenied("untrusted R006 launch inputs")
        try:
            LbeWorker._check_plan(plan)
        except LbeWorkerError:
            raise D4R006NativeRunnerDenied("invalid R006 work plan") from None
        if (ctx.name != plan.workspace or recipe.workspace != plan.workspace
                or recipe.runner != plan.runner
                or recipe.requested_argv != plan.requested_argv
                or recipe.service_effective_argv != plan.effective_argv
                or recipe.original_timeout_seconds != plan.timeout_seconds
                or recipe.native_launch_allowed is not False
                or recipe.owner_t1_grant_present is not False
                or recipe.actual_loaded_source_graph_proven is not False
                or recipe.physical_cpu_memory_enforcement_proven is not False
                or type(recipe.resolved_executable) is not str
                or not recipe.resolved_executable.startswith("/")
                or type(recipe.working_directory) is not str
                or not recipe.working_directory.startswith("/")
                or recipe.resolved_spawn_argv != (
                    recipe.resolved_executable, *plan.effective_argv[1:])
                or type(recipe.closed_child_environment) is not tuple
                or not recipe.closed_child_environment
                or host.selected_source_bytes_verified is not True
                or host.full_boot_image_attested is not False
                or host.actual_loaded_graph_proven is not False
                or host.native_launch_allowed is not False):
            raise D4R006NativeRunnerDenied("R006 recipe/host binding invalid")
        env = dict(recipe.closed_child_environment)
        if (len(env) != len(recipe.closed_child_environment)
                or any(type(k) is not str or type(v) is not str or not k
                       or "\x00" in k or "\x00" in v
                       for k, v in recipe.closed_child_environment)
                or any(k.startswith("GITHUB_") for k in env)
                or any(k in env for k in (
                    "GH_TOKEN", "GITHUB_TOKEN", "HTTP_PROXY", "HTTPS_PROXY",
                    "ALL_PROXY", "DYLD_INSERT_LIBRARIES", "PYTHONPATH"))):
            raise D4R006NativeRunnerDenied("unsafe closed child environment")
        try:
            consumed.check_binding(plan, recipe)
        except D4OwnerBootstrapDenied:
            raise D4R006NativeRunnerDenied(
                "consumed owner grant is not bound to recipe") from None
        self._ctx = ctx
        self._plan = plan
        self._recipe = recipe
        self._host = host
        self._consumed = consumed
        self._marker = marker
        self._pid = os.getpid()

    def check_binding(self, ctx: "WorkspaceContext", plan: object) -> None:
        if (ctx is not self._ctx or plan is not self._plan
                or os.getpid() != self._pid):
            raise D4R006NativeRunnerDenied("R006 service/process binding changed")
        try:
            self._consumed.check_binding(self._plan, self._recipe)
        except D4OwnerBootstrapDenied:
            raise D4R006NativeRunnerDenied(
                "R006 consumed grant no longer usable") from None

    def launch(self, plan: LbeWorkPlan):
        """Exact future Popen boundary; source exists but is not publicly wired."""
        try:
            self.check_binding(self._ctx, plan)
            # Burn/recheck first-party staged bytes, loader candidates and the
            # source-only runner marker. No retry even if later checks fail.
            self._marker.consume_for(plan)
            current = verify_r006_fixed_host_allowlist_t0()
            if current != self._host:
                raise D4R006NativeRunnerDenied(
                    "fixed macOS image/source changed before launch")
            self._consumed.check_binding(plan, self._recipe)
        except (D4R006NativeRunnerDenied, D4OwnerBootstrapDenied,
                D4FixtureDenied, D4R006HostAllowlistDenied, OSError):
            raise LbeNoChildStarted(
                "no child: R006 exact owner/source/runner recheck refused"
            ) from None

        # This call is intentionally unreachable from public Exec today.
        # Do not catch Popen exceptions: after entering Popen, child existence
        # can be ambiguous and LbeWorker must latch admission unavailable.
        return subprocess.Popen(
            list(self._recipe.resolved_spawn_argv),
            cwd=self._recipe.working_directory,
            env=dict(self._recipe.closed_child_environment),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            start_new_session=False,
        )
