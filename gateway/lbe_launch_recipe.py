"""Build an exact D4 R003 native child recipe from real Workspace source.

This is PRODUCT code for a future original-child launcher boundary, not a
launcher, permission or resource enforcer. It resolves a reviewed fixed
requested/effective command to a privately selected absolute executable,
Workspace project cwd, bounded timeout and freshly constructed child
environment without using os.environ, shell, or Popen. Nothing here
changes the operative F1 or Go/Pipenv NativeLauncher denial.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from typing import TYPE_CHECKING

from .lbe_product_fixture import (
    D4FixtureCandidate, D4FixtureDenied, PROFILE_GIT_BLOB, PROFILE_ID,
    check_d4_r003_fixture,
)
from .lbe_runtime_source import (
    D4RuntimeSourceObservation, D4RuntimeSourceDenied,
    _canonical, _child, _below, _stat_private_directory,
)
from .lbe_worker import LbeWorkPlan, LbeWorker, LbeWorkerError

if TYPE_CHECKING:
    from .workspaces import WorkspaceContext


class D4NativeRecipeDenied(ValueError):
    """Incomplete or out-of-contract source-only execution recipe."""


# This is the exact proposed R003 constraint tuple, NOT an OS mechanism.
_PROPOSED_LIMITS = (
    ("job_wall_seconds", 1200),
    ("original_timeout_max_seconds", 120),
    ("public_worker_timeout_max_seconds", 300),
    ("cpu_millicores_max", 2000),
    ("memory_mib_max", 4096),
    ("stdout_raw_bytes_max", 48000),
    ("stderr_raw_bytes_max", 48000),
    ("stdout_redacted_chars_max", 48000),
    ("stderr_redacted_chars_max", 48000),
)
# A separate actual macOS whole-child-domain resource enforcer is still
# mandatory and not implemented by this recipe.
_STATUS = "NATIVE_RECIPE_SOURCE_ONLY_NO_EXECUTION_AUTHORITY"


@dataclass(frozen=True, slots=True)
class D4NativeLaunchRecipe:
    workspace: str
    profile_git_blob: str
    runner: str
    requested_argv: tuple[str, ...]
    service_effective_argv: tuple[str, ...]
    resolved_executable: str
    resolved_spawn_argv: tuple[str, ...]
    working_directory: str
    closed_child_environment: tuple[tuple[str, str], ...]
    selected_source_fingerprint: str
    canonical_output_path: str | None
    original_timeout_seconds: int
    required_limits: tuple[tuple[str, int], ...] = _PROPOSED_LIMITS
    status: str = _STATUS
    real_runner_qualified: bool = False
    actual_loaded_source_graph_proven: bool = False
    physical_cpu_memory_enforcement_proven: bool = False
    owner_t1_grant_present: bool = False
    native_launch_allowed: bool = False


def prepare_d4_native_launch_recipe(
    ctx: "WorkspaceContext",
    candidate: D4FixtureCandidate,
    observed: D4RuntimeSourceObservation, *,
    private_root: str,
) -> D4NativeLaunchRecipe:
    """Resolve exact product argv/cwd/env. Never executes or enables Exec.

    Only real service-owned Workspace contexts and first-party snapshots are
    appropriate inputs. The returned frozen dataclass is not a trusted
    capability; any future Popen boundary must independently redo the
    source/loader/runner/image/budget/owner checks and require a separately
    approved operative exception and physical OS limit.
    """
    from .workspaces import WorkspaceContext

    if (type(ctx) is not WorkspaceContext
            or type(candidate) is not D4FixtureCandidate
            or type(observed) is not D4RuntimeSourceObservation
            or type(candidate.plan) is not LbeWorkPlan):
        raise D4NativeRecipeDenied("invalid trusted product inputs")
    plan = candidate.plan
    try:
        LbeWorker._check_plan(plan)
    except LbeWorkerError:
        raise D4NativeRecipeDenied("invalid canonical work plan") from None
    if (plan.workspace != ctx.name or observed.workspace != ctx.name
            or candidate.profile_id != PROFILE_ID
            or candidate.profile_git_blob != PROFILE_GIT_BLOB
            or candidate.native_launch_allowed is not False
            or candidate.owner_approval_attested is not False
            or observed.native_launch_allowed is not False
            or observed.owner_native_t1_grant is not False
            or observed.actual_import_graph_attested is not False
            or observed.physical_resource_domain_attached is not False
            or observed.runner_image_attested is not False
            or observed.bounded_staged_file_set_checked is not True
            or not observed.staged_source_trees
            or observed.requested_argv != plan.requested_argv
            or observed.effective_argv != plan.effective_argv
            or not 1 <= plan.timeout_seconds <= 120):
        raise D4NativeRecipeDenied("source-only D4 recipe cannot authorize execution")
    try:
        refreshed = check_d4_r003_fixture(ctx, plan)
    except (D4FixtureDenied, OSError):
        raise D4NativeRecipeDenied("first-party fixture is no longer qualified") from None
    if (refreshed.source_sha256 != candidate.source_sha256
            or refreshed.source_identity != candidate.source_identity
            or refreshed.directory_identity != candidate.directory_identity
            or refreshed.plan != plan):
        raise D4NativeRecipeDenied("first-party source changed before recipe selection")

    try:
        root = _canonical(private_root, "private_root")
        workspace_root = _canonical(str(ctx.gateway._root_path), "workspace")
        _below(root, workspace_root)
        _stat_private_directory(workspace_root, root)
        project_dir = _child(workspace_root, plan.cwd)
        _stat_private_directory(project_dir, root)
    except (D4RuntimeSourceDenied, OSError):
        raise D4NativeRecipeDenied("runtime/workspace root is not owner controlled") from None

    expected_label = ""
    if (plan.cwd == "go-project" and plan.runner == "direct"
            and observed.kind == "go"):
        expected_label = "go/bin/go"
        executable = _child(root, expected_label)
        wanted_trees = {"go", "home", "tmp", "gopath",
                        "modcache", "gocache", "gotmp"}
        if (plan.effective_argv[0] != "go"
                or plan.effective_argv[1:] != plan.requested_argv[1:]):
            raise D4NativeRecipeDenied("Go argv or runner selection changed")
        if plan.requested_argv[1] == "build":
            if (plan.planned_go_output != "go-project/bin/app"
                    or plan.requested_argv != (
                        "go", "build", "-o", "bin/app", "./cmd/app")):
                raise D4NativeRecipeDenied("Go output path not approved")
            output = _child(workspace_root, plan.planned_go_output)
        else:
            if plan.planned_go_output is not None:
                raise D4NativeRecipeDenied("unexpected Go output path")
            output = None
    elif (plan.cwd == "py-pipenv" and plan.runner == "pipenv"
          and observed.kind == "pipenv"):
        expected_label = "bin/pipenv"
        executable = _child(root, expected_label)
        wanted_trees = {"bin", "lib", "venv", "home", "tmp"}
        if (plan.effective_argv != (
                "pipenv", "run", "python", "-m", "pytest", "-q")
                or plan.requested_argv != (
                    "python", "-m", "pytest", "-q")
                or plan.planned_go_output is not None):
            raise D4NativeRecipeDenied("Pipenv interpreter selection changed")
        output = None
    elif (plan.cwd == "py-direct" and plan.runner == "direct"
          and observed.kind == "python_direct"):
        expected_label = "bin/python"
        executable = _child(root, expected_label)
        wanted_trees = {"bin", "lib", "home", "tmp"}
        if (plan.effective_argv[0] != "python"
                or plan.effective_argv != plan.requested_argv
                or plan.planned_go_output is not None):
            raise D4NativeRecipeDenied("direct Python argv changed")
        output = None
    else:
        raise D4NativeRecipeDenied("unqualified runner or project selection")

    receipts = observed.staged_source_trees
    if (type(receipts) is not tuple
            or set(x[0] for x in receipts if type(x) is tuple and x)
            != wanted_trees
            or len(receipts) != len(wanted_trees)
            or any(type(x) is not tuple or len(x) != 4
                   or type(x[0]) is not str
                   or type(x[1]) is not str or len(x[1]) != 64
                   or any(c not in "0123456789abcdef" for c in x[1])
                   or type(x[2]) is not int or not 1 <= x[2] <= 24000
                   or type(x[3]) is not int or x[3] < 0
                   for x in receipts)):
        raise D4NativeRecipeDenied("closed source-tree receipt incomplete")
    if (type(observed.staged_executables) is not tuple
            or expected_label not in {row[0] for row in observed.staged_executables
                                      if type(row) is tuple and len(row) == 2}):
        raise D4NativeRecipeDenied("staged executable not selected")
    if (type(observed.closed_child_environment) is not tuple
            or not observed.closed_child_environment):
        raise D4NativeRecipeDenied("closed environment unavailable")
    env = dict(observed.closed_child_environment)
    if (len(env) != len(observed.closed_child_environment)
            or any(type(k) is not str or type(v) is not str
                   or not k or (not v and not (
                       observed.kind == "go" and k == "GOFLAGS"))
                   or "\x00" in k or "\x00" in v
                   for k,v in observed.closed_child_environment)
            or any(k in env for k in ("PYTHONPATH", "GITHUB_TOKEN", "GOFLAGS_EXTRA",
                                     "DYLD_INSERT_LIBRARIES"))):
        raise D4NativeRecipeDenied("closed environment source invalid")
    if (env.get("HOME") != root + "/home"
            or env.get("TMPDIR") != root + "/tmp"
            or not env.get("PATH", "").startswith(root + "/")):
        raise D4NativeRecipeDenied("unqualified child environment")
    if observed.kind == "go":
        if (env.get("GOFLAGS") != "" or env.get("GOTOOLCHAIN") != "local"
                or env.get("GOPROXY") != "off" or env.get("GOWORK") != "off"
                or env.get("CGO_ENABLED") != "0"):
            raise D4NativeRecipeDenied("Go environment no longer closed")
    else:
        if env.get("PYTHONNOUSERSITE") != "1":
            raise D4NativeRecipeDenied("Python environment no longer closed")

    spec_argv = (executable,) + plan.effective_argv[1:]
    if type(spec_argv) is not tuple or len(spec_argv) > 64:
        raise D4NativeRecipeDenied("invalid native argument count")
    # Deterministic source-only fingerprint includes all first-party file
    # identities, staged roots, command, working directory and closed env.
    # SHA of a receipt is NOT an OS-loaded source, image, or authority proof.
    material = (ctx.name, plan, candidate.source_sha256,
                candidate.source_identity, candidate.directory_identity,
                receipts, observed.staged_executables, spec_argv,
                project_dir, tuple(sorted(env.items())))
    fingerprint = hashlib.sha256(repr(material).encode("utf-8")).hexdigest()
    return D4NativeLaunchRecipe(
        workspace=ctx.name, profile_git_blob=PROFILE_GIT_BLOB,
        runner=plan.runner, requested_argv=plan.requested_argv,
        service_effective_argv=plan.effective_argv,
        resolved_executable=executable, resolved_spawn_argv=spec_argv,
        working_directory=project_dir,
        closed_child_environment=tuple(sorted(env.items())),
        selected_source_fingerprint=fingerprint,
        canonical_output_path=output,
        original_timeout_seconds=plan.timeout_seconds,
    )


def launch_d4_native_from_recipe(_recipe: object) -> None:
    """No callable native launcher exists under SOURCE/T0 authorization."""
    raise D4NativeRecipeDenied(
        "D4 product source-only recipe cannot launch: owner native T1, "
        "actual loader, runner image and OS resource domain NOT_AUTHORIZED")
