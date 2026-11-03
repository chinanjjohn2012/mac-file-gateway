"""macOS Seatbelt runner SAFETY GATE proposal: deterministic T0 only.

This module contains no executable runner, native loading, OS resource
mutations, socket creation, signals, subprocesses, or sandbox attachment.
Its input checks are syntactic; GitHub/runner/compiler/OS provenance MUST
be established independently by a future, separately reviewed executor.
No value returned by this module is an execution authorization.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Final

from .lbe_m2_macos_canary_validation_t0 import (
    LbeM2NativeCanaryPreparationDenied,
    prepare_macos_canary_validation_t0,
)


class LbeM2RunnerGateT0Denied(ValueError):
    """Invalid nonoperative source, runner, budget or admission proposal."""


_SHA256: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")
_PRECONTACT_SEQUENCE: Final[tuple[str, ...]] = (
    "G05_HEAD_TREE_AND_SOURCE",
    "RUNNER_IMAGE_AND_WORKFLOW_ORIGIN",
    "COMPILER_SDK_AND_MACHO_SOURCE_LOCK",
    "FD_SCRUB_BEFORE_ATTACH",
    "OS_RESOURCE_SUPERVISOR_AND_SURVIVOR_LATCH",
    "SEATBELT_POLICY_ATTACHED_BEFORE_EXTERNAL_CODE",
    "PRECONTACT_DENIAL_PROBES_IN_SAME_DOMAIN",
    "NATURAL_CHILD_AND_DESCENDANT_OBSERVATION",
    "NO_NATIVE_EXECUTION_IN_T0",
)
_FINAL_BLOCKERS: Final[tuple[str, ...]] = (
    "RUNNER_IMAGE_WORKFLOW_AND_GITHUB_ORIGIN_NOT_ATTESTED",
    "COMPILER_SDK_MACHO_AND_LOADED_SOURCE_NOT_ATTESTED",
    "MACOS_KERNEL_RESOURCE_LIMITS_NOT_ENFORCED_OR_OBSERVED",
    "JOB_LEVEL_CPU_MEMORY_WALL_OUTPUT_AND_CHILD_CAPS_NOT_ATTESTED",
    "SEATBELT_PRECONTACT_AND_ALL_EGRESS_ROUTES_NOT_ATTESTED",
    "CHILD_SURVIVOR_QUARANTINE_AND_RESTART_LATCH_NOT_PROVEN",
    "CURRENT_NATIVE_RUNNABLE_HEAD_AND_BC_REVIEWS_NOT_APPROVED",
    "MACOS_CANARY_GO_PIPENV_PRODUCT_INTEGRATION_NOT_RUN",
)


@dataclass(frozen=True)
class MacOSRunnerIdentityProposalT0:
    """Caller claims ONLY; no GitHub or actual runner image is consulted."""

    proposed_head_sha: str
    proposed_tree_sha: str
    runner_os: str
    runner_label: str
    runner_arch: str
    runner_image_sha256: str
    workflow_sha256: str
    compiler_sha256: str
    sdk_sha256: str
    compiled_macho_sha256: str


@dataclass(frozen=True)
class MacOSRunnerResourceBudgetT0:
    """Ceilings to be proven by a future OS/outer-supervisor witness.

    RLIMIT_CPU/AS/RSS/NPROC/FSIZE and a YAML timeout by themselves CANNOT
    establish macOS aggregate child, wall, memory or output containment.
    """

    job_wall_seconds: int = 1200
    canary_wall_seconds: int = 10
    canary_cpu_seconds: int = 10
    canary_memory_mib: int = 128
    selected_child_wait_ms: int = 2000
    stdout_raw_bytes: int = 4096
    stderr_raw_bytes: int = 4096
    nofile_soft: int = 64
    max_canary_children: int = 1
    max_parallel_canaries: int = 1


@dataclass(frozen=True)
class MacOSSeatbeltRunnerGateT0:
    """Nonoperative structural result, NEVER a native admission token."""

    proposed_head_sha: str
    proposed_tree_sha: str
    source_sha256: tuple[str, str, str]
    proposed_runner_label: str
    budget: MacOSRunnerResourceBudgetT0
    proposed_precontact_sequence: tuple[str, ...]
    simulated_child_state: str
    identity_structure_only: str = "MATCHED_UNTRUSTED_INPUTS"
    budget_structure_only: str = "WITHIN_PROPOSED_CEILINGS"
    precontact_structure_only: str = "ORDERED_NOT_EXECUTED"
    status: str = "NONOPERATIVE_RUNNER_SECURITY_GATE_T0"
    actual_runner_verified: bool = False
    actual_os_limits_enforced: bool = False
    actual_precontact_isolation_attached: bool = False
    descendant_retirement_proven: bool = False
    native_canary_launch_allowed: bool = False
    source_t1_launch_allowed: bool = False
    product_t1_launch_allowed: bool = False
    blockers: tuple[str, ...] = _FINAL_BLOCKERS


def _valid_sha256(value: object) -> bool:
    return (type(value) is str and _SHA256.fullmatch(value) is not None
            and value != "0" * 64)


def _validate_identity(
    claim: MacOSRunnerIdentityProposalT0, head: str, tree: str,
) -> None:
    if type(claim) is not MacOSRunnerIdentityProposalT0:
        raise LbeM2RunnerGateT0Denied("unqualified runner identity type")
    if (claim.proposed_head_sha != head or claim.proposed_tree_sha != tree
            or claim.runner_os != "macOS"
            or claim.runner_label != "macos-15"
            or claim.runner_arch != "arm64"):
        raise LbeM2RunnerGateT0Denied("runner or source proposal mismatch")
    hashes = (
        claim.runner_image_sha256, claim.workflow_sha256,
        claim.compiler_sha256, claim.sdk_sha256,
        claim.compiled_macho_sha256,
    )
    if not all(_valid_sha256(v) for v in hashes) or len(set(hashes)) != 5:
        raise LbeM2RunnerGateT0Denied(
            "runner/build/artifact digests are missing or malformed")
    # This is NOT a claim the digests were observed on a Mac or GitHub.


def _validate_budget(budget: MacOSRunnerResourceBudgetT0) -> None:
    if type(budget) is not MacOSRunnerResourceBudgetT0:
        raise LbeM2RunnerGateT0Denied("unqualified budget type")
    maxima = {
        "job_wall_seconds": (10, 1200),
        "canary_wall_seconds": (1, 10),
        "canary_cpu_seconds": (1, 10),
        "canary_memory_mib": (16, 128),
        "selected_child_wait_ms": (1, 2000),
        "stdout_raw_bytes": (1, 4096),
        "stderr_raw_bytes": (1, 4096),
        "nofile_soft": (16, 64),
        "max_canary_children": (1, 1),
        "max_parallel_canaries": (1, 1),
    }
    for name, (minimum, maximum) in maxima.items():
        value = getattr(budget, name)
        if type(value) is not int or not minimum <= value <= maximum:
            raise LbeM2RunnerGateT0Denied(
                "OS budget proposal outside approved T0 ceiling: " + name)
    if (budget.canary_cpu_seconds > budget.canary_wall_seconds
            or budget.job_wall_seconds < budget.canary_wall_seconds
            or budget.selected_child_wait_ms >= budget.canary_wall_seconds * 1000):
        raise LbeM2RunnerGateT0Denied("inconsistent wall/CPU/child wait budget")
    # A valid number is NOT an applied setrlimit, cgroup or supervisor proof.


def advance_child_survivor_latch_t0(state: str, event: str) -> str:
    """Pure model: a timeout/unknown owner can never be cleared by a claim.

    Neither this function nor the earlier C bounded wait kills/reaps a child.
    The model is not durable across process restarts: native activation stays
    blocked until a reviewed, real outer-owner persistence mechanism exists.
    """
    states = {
        "NOT_STARTED", "RUNNING", "EXIT_OBSERVED_DESCENDANTS_UNPROVEN",
        "FAILED_EXIT", "POSSIBLE_SURVIVOR",
    }
    events = {
        "NO_SPAWN", "STARTED", "POLL", "EXIT_ZERO", "EXIT_NONZERO",
        "TIMEOUT", "UNKNOWN_CHILD", "ECHILD", "OWNER_LOST", "RETRY",
    }
    if type(state) is not str or state not in states:
        raise LbeM2RunnerGateT0Denied("unknown child lifecycle state")
    if type(event) is not str or event not in events:
        raise LbeM2RunnerGateT0Denied("unknown child lifecycle event")
    if state == "POSSIBLE_SURVIVOR":
        return state
    if event in {"TIMEOUT", "UNKNOWN_CHILD", "ECHILD", "OWNER_LOST", "RETRY"}:
        return "POSSIBLE_SURVIVOR"
    if state == "NOT_STARTED":
        if event == "NO_SPAWN":
            return state
        return "RUNNING" if event == "STARTED" else "POSSIBLE_SURVIVOR"
    if state == "RUNNING":
        if event == "POLL":
            return state
        if event == "EXIT_ZERO":
            return "EXIT_OBSERVED_DESCENDANTS_UNPROVEN"
        if event == "EXIT_NONZERO":
            return "FAILED_EXIT"
        return "POSSIBLE_SURVIVOR"
    # An apparently successful direct child does not prove that its forked
    # descendants have exited. Nor can a later claim reset a failed exit.
    return state


def prepare_seatbelt_runner_gate_t0(
    *, proposed_head_sha: str, proposed_tree_sha: str,
    native_helper_bytes: bytes, fd_scrub_header_bytes: bytes,
    bounded_wait_header_bytes: bytes,
    runner_identity: MacOSRunnerIdentityProposalT0,
    budget: MacOSRunnerResourceBudgetT0,
    proposed_precontact_sequence: tuple[str, ...] = _PRECONTACT_SEQUENCE,
    simulated_child_state: str = "NOT_STARTED",
) -> MacOSSeatbeltRunnerGateT0:
    """Validate a future runbook without performing any OS/native action.

    Source bytes are verified by the previously reviewed fixed-source lock,
    but even a byte match cannot attest the executable/runner origin.
    """
    try:
        source = prepare_macos_canary_validation_t0(
            proposed_head_sha=proposed_head_sha,
            proposed_tree_sha=proposed_tree_sha,
            native_helper_bytes=native_helper_bytes,
            fd_scrub_header_bytes=fd_scrub_header_bytes,
            bounded_wait_header_bytes=bounded_wait_header_bytes,
        )
    except LbeM2NativeCanaryPreparationDenied as exc:
        raise LbeM2RunnerGateT0Denied("unqualified previous T0 source") from exc
    _validate_identity(runner_identity, source.proposed_head_sha,
                       source.proposed_tree_sha)
    _validate_budget(budget)
    if (type(proposed_precontact_sequence) is not tuple or
            proposed_precontact_sequence != _PRECONTACT_SEQUENCE):
        raise LbeM2RunnerGateT0Denied(
            "missing, reordered or injected precontact isolation step")
    if (type(simulated_child_state) is not str or
            simulated_child_state not in {
                "NOT_STARTED", "RUNNING",
                "EXIT_OBSERVED_DESCENDANTS_UNPROVEN",
                "FAILED_EXIT", "POSSIBLE_SURVIVOR",
            }):
        raise LbeM2RunnerGateT0Denied("unqualified simulated child state")
    blockers = _FINAL_BLOCKERS
    if simulated_child_state == "POSSIBLE_SURVIVOR":
        blockers += ("SURVIVOR_LATCHED_NO_RETRY_OR_NATIVE_LAUNCH",)
    elif simulated_child_state != "NOT_STARTED":
        blockers += ("SIMULATED_CHILD_IS_NOT_NATIVE_OS_EVIDENCE",)
    return MacOSSeatbeltRunnerGateT0(
        proposed_head_sha=source.proposed_head_sha,
        proposed_tree_sha=source.proposed_tree_sha,
        source_sha256=(
            source.seatbelt_c_sha256, source.fd_scrub_header_sha256,
            source.bounded_wait_header_sha256,
        ),
        proposed_runner_label=runner_identity.runner_label,
        budget=budget,
        proposed_precontact_sequence=proposed_precontact_sequence,
        simulated_child_state=simulated_child_state,
        blockers=blockers,
    )


def execute_macos_seatbelt_runner_canary(
    _plan: object = None, _runner_claim: object = None,
    _os_limit_receipt: object = None, _lifecycle_receipt: object = None,
    _precontact_receipt: object = None,
) -> None:
    """UNCONDITIONAL DENIAL: no caller-supplied receipt is OS proof."""
    raise LbeM2RunnerGateT0Denied(
        "NATIVE_MACOS_CANARY=NOT_RUN: actual runner origin, image/compiler/"
        "binary, OS-enforced budgets, precontact Seatbelt and possible-live "
        "descendant containment require separate reviewed native evidence; "
        "Go/Pipenv and product Exec are DENIED"
    )
