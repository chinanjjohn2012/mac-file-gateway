"""Standalone SOURCE_TOOLCHAIN_T1 execution admission, deliberately fail-closed.

Prepared source bytes and a proposed OFFLINE_ONLY policy are not an OS-enforced
domain or an actual loaded native toolchain. This version has NO native
executor, subprocess/network calls, host firewall manipulations or external
backend adapter. Adding a real adapter requires new independently reviewed
source code, exact OWNER gate and verified same-domain isolation evidence.
"""
from __future__ import annotations

from dataclasses import dataclass
import gc
import platform
import sys
from pathlib import Path
from types import MappingProxyType

from .lbe_m2_native_t1_preflight_t0 import (
    M2SourceT1PlanT0, LbeM2T1PreflightError,
    _GO_MATRIX, _PIPENV_MATRIX, _plain_immutable_strings,
    _validate_runner, _validate_budget, _validate_offline_proposal, _HEX40,
)
from .lbe_m2_t1_source_tree_t0 import (
    LbeT1SourceTreeError, T1SourceTreeT0,
    inspect_t1_private_source_tree_t0,
)


class LbeT1SourceRunDenied(ValueError):
    """Actual execution is not allowed without a verified offline domain."""


_BLOCKERS = (
    "EXECUTABLE_RUNNER_CODE_NOT_REVIEWED",
    "ACTUAL_MACOS15_ARM64_IMAGE_AND_PYTHON_NOT_ATTESTED",
    "ACTUAL_LOADED_GO_PIPENV_SOURCE_NOT_ATTESTED",
    "G05_TEST_HEAD_AND_MERGE_EXECUTION_NOT_ATTESTED_HERE",
    "OFFLINE_ONLY_ATTACHED_CHILD_DESCENDANTS_NOT_ATTESTED",
    "SAME_DOMAIN_PRECONTACT_DENIAL_CANARY_NOT_RUN",
    "OS_CPU_MEMORY_WALL_AND_OUTPUT_CAPS_NOT_ENFORCED",
    "NEW_BC_REVIEW_OF_EXECUTABLE_NATIVE_T1_NOT_ISSUED",
)


@dataclass(frozen=True)
class SourceT1ExecutionGateT0:
    """Inspectably blocked intended test, not a token granting execution."""

    kind: str
    argv: tuple[str, ...]
    proposed_head: str
    proposed_tree: str
    source_manifest_sha256: str
    checked_source_members: int
    checked_source_bytes: int
    observed_system: str
    observed_machine: str
    observed_python: str
    status: str = "BLOCKED_PRECONTACT_EXECUTION_GATE_T0"
    domain_policy: str = "NOT_ATTESTED"
    domain_canary: str = "NOT_RUN"
    runner_image_identity: str = "NOT_ATTESTED"
    source_loaded_identity: str = "NOT_ATTESTED"
    cpu_memory_enforced: str = "NOT_ATTESTED"
    native_t1: str = "NOT_RUN"
    execution_allowed: bool = False
    product_exec_authorized: bool = False
    blockers: tuple[str, ...] = _BLOCKERS


def _copy_plain_m2_map(view: object, *, value_type: type) -> dict:
    """Never call a dict-subclass .items on an untrusted mappingproxy."""
    if type(view) is not MappingProxyType:
        raise LbeT1SourceRunDenied("canonical M2 metadata required")
    try:
        referents = gc.get_referents(view)
    except (TypeError, ValueError, OSError, RuntimeError) as exc:
        raise LbeT1SourceRunDenied("uninspectable M2 metadata") from exc
    if len(referents) != 1 or type(referents[0]) is not dict:
        raise LbeT1SourceRunDenied("custom M2 metadata denied")
    values = tuple(dict.items(referents[0]))
    if any(type(k) is not str or type(v) is not value_type
           for k, v in values):
        raise LbeT1SourceRunDenied("invalid M2 metadata type")
    return dict(values)


def prepare_source_t1_execution_gate_t0(
    *, plan: M2SourceT1PlanT0,
    private_root: Path, trusted_base: Path,
    executable_members: tuple[str, ...],
) -> SourceT1ExecutionGateT0:
    """Actually inspect staged tree bytes; do NOT launch anything.

    The plan itself is reconstructible and its head/runner values are
    user-provided descriptors, not original GitHub+OS attestation.
    The entire source tree must equal its proposed digest manifest.
    """
    if type(plan) is not M2SourceT1PlanT0:
        raise LbeT1SourceRunDenied("M2 T0 plan required")
    if (type(plan.kind) is not str or plan.kind not in {"go", "pipenv"}
            or type(plan.argv) is not tuple
            or any(type(z) is not str for z in plan.argv)
            or type(plan.status) is not str
            or type(plan.review_target) is not str
            or type(plan.native_t1) is not str
            or type(plan.loaded_source_identity) is not str
            or type(plan.precontact_egress_enforcement) is not str
            or type(plan.same_domain_canary) is not str
            or type(plan.proposed_head) is not str
            or type(plan.proposed_tree) is not str
            or not _HEX40.fullmatch(plan.proposed_head)
            or not _HEX40.fullmatch(plan.proposed_tree)
            or plan.proposed_head == plan.proposed_tree
            or plan.argv not in (
                _GO_MATRIX if plan.kind == "go" else _PIPENV_MATRIX)
            or plan.status != "NONOPERATIVE_M2_TEST_PLAN_T0"
            or plan.review_target != "STANDALONE_SOURCE_TOOLCHAIN_T1"
            or plan.launch_allowed is not False
            or plan.workspace_service_exec_authorized is not False
            or plan.native_t1 != "NOT_RUN"
            or plan.loaded_source_identity != "NOT_ATTESTED"
            or plan.precontact_egress_enforcement != "NOT_ATTESTED"
            or plan.same_domain_canary != "NOT_RUN"):
        raise LbeT1SourceRunDenied("M2 native-source T1 grant not present")
    try:
        _validate_runner(_copy_plain_m2_map(
            plan.runner_proposal, value_type=str))
        _validate_budget(_copy_plain_m2_map(
            plan.budget_proposal, value_type=int))
        _validate_offline_proposal(_copy_plain_m2_map(
            plan.egress_proposal, value_type=str))
        members = _plain_immutable_strings(plan.source_lock)
        actual: T1SourceTreeT0 = inspect_t1_private_source_tree_t0(
            private_root=private_root, trusted_base=trusted_base,
            source_lock=members, executable_members=executable_members,
        )
    except (LbeM2T1PreflightError, LbeT1SourceTreeError,
            TypeError, ValueError) as exc:
        raise LbeT1SourceRunDenied("actual staged-source closure denied") from exc
    # platform.* is diagnostic context only, never authenticated runner
    # identity. An env var can neither set an egress proof nor unlock a run.
    return SourceT1ExecutionGateT0(
        kind=plan.kind, argv=tuple(plan.argv),
        proposed_head=plan.proposed_head, proposed_tree=plan.proposed_tree,
        source_manifest_sha256=actual.manifest_sha256,
        checked_source_members=actual.regular_files,
        checked_source_bytes=actual.bytes_hashed,
        observed_system=platform.system(),
        observed_machine=platform.machine(),
        observed_python=f"{sys.version_info.major}.{sys.version_info.minor}",
    )


def execute_source_toolchain_t1(
    _gate: object = None, _owner_claim: object = None,
    _egress_claim: object = None, _runner_claim: object = None,
) -> None:
    """Hard stop: no foreign process even for a perfect or forged T0 receipt.

    Real isolated execution backend, observed loaded-source verifier,
    attached OS policy and precontact canary do not exist in this revision.
    They must be implemented and reviewed in a separate exact Head/Tree.
    No caller, CI variable, proof flag or dataclass can bypass this guard.
    """
    raise LbeT1SourceRunDenied(
        "NATIVE_T1=NOT_RUN: independently verified OFFLINE_ONLY domain, "
        "runner/source identity, resource enforcement and B/C execution "
        "review are unavailable"
    )
