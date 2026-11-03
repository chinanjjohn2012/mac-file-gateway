"""SOURCE_TOOLCHAIN_T1 macOS Seatbelt native-canary preparation, T0 only.

This module validates the *proposed* first-party source byte closure using
the prior Seatbelt T0 source lock. It is not an OS-attached witness, a native
build, a runner validator, a sandbox policy agent or an execution capability.
No subprocess, native-library load, socket, firewall or privilege operation.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Final

from .lbe_m2_seatbelt_offline_t0 import (
    LbeM2SeatbeltT0Error,
    prepare_seatbelt_offline_backend_t0,
)


class LbeM2NativeCanaryPreparationDenied(ValueError):
    """Actual native canary/T1 cannot be authorized by a T0 plan."""


_SHA40: Final[re.Pattern[str]] = re.compile(r"[a-f0-9]{40}\Z")
_BLOCKERS: Final[tuple[str, ...]] = (
    "NEW_RUNNABLE_MACOS_HELPER_AND_RUNNER_REVIEW_NOT_ISSUED",
    "MACOS15_ARM64_HOSTED_RUNNER_IMAGE_IDENTITY_NOT_ATTESTED",
    "CLANG_SDK_LIBRARY_AND_COMPILED_BINARY_NOT_ATTESTED",
    "SANDBOX_INIT_POLICY_ATTACH_NOT_TESTED",
    "ACTUAL_MACOS_DEVD_FD_ENUMERATION_NOT_TESTED",
    "SAME_DOMAIN_ORIGINAL_DESCENDANT_DENIAL_NOT_TESTED",
    "UDP_TCP_DNS_PROXY_AND_IPC_EGRESS_INHERITANCE_NOT_ATTESTED",
    "CANARY_NATIVE_CHILD_TIMEOUT_OWNERSHIP_NOT_PROVEN",
    "CANARY_UNKNOWN_CHILD_CANNOT_BE_RETIRED_OR_RETRIED",
    "OS_WALL_CPU_MEMORY_AND_OUTPUT_BUDGETS_NOT_ENFORCED",
    "ACTUAL_GO_PIPENV_LOADED_SOURCE_NOT_ATTESTED",
    "T1_SOURCE_AND_T1_PRODUCT_NOT_RUN",
)


@dataclass(frozen=True)
class MacOSCanaryValidationPlanT0:
    """Immutable descriptive input; never an authority to spawn a process."""

    proposed_head_sha: str
    proposed_tree_sha: str
    seatbelt_c_sha256: str
    fd_scrub_header_sha256: str
    bounded_wait_header_sha256: str
    candidate_runner_label: str = "macos-15"
    candidate_arch: str = "arm64"
    canary_bounded_wait_ms: int = 2000
    candidate_job_wall_seconds: int = 1200
    candidate_native_canary_wall_seconds: int = 10
    candidate_native_canary_cpu_seconds: int = 10
    candidate_native_canary_memory_mib: int = 128
    candidate_stdout_raw_bytes: int = 4096
    candidate_stderr_raw_bytes: int = 4096
    status: str = "NONOPERATIVE_MACOS_CANARY_VALIDATION_PREP_T0"
    source_bytes_status: str = "MATCHED_C_AND_TWO_HEADERS_T0"
    github_head_tree_independently_attested: bool = False
    runner_image_attested: bool = False
    compiler_and_sdk_attested: bool = False
    native_canary_compiled: bool = False
    native_canary_executed: bool = False
    macos_kernel_isolation_attested: bool = False
    network_canary_executed: bool = False
    descendant_retired_proven: bool = False
    native_go_pipenv_t1_executed: bool = False
    source_t1_launch_allowed: bool = False
    product_t1_launch_allowed: bool = False
    blockers: tuple[str, ...] = _BLOCKERS


def prepare_macos_canary_validation_t0(
    *, proposed_head_sha: str, proposed_tree_sha: str,
    native_helper_bytes: bytes, fd_scrub_header_bytes: bytes,
    bounded_wait_header_bytes: bytes,
) -> MacOSCanaryValidationPlanT0:
    """Check exact plain source inputs; do not execute or attest the runtime.

    Head/Tree values are a caller-written description only. Original GitHub
    commit/tree objects, installed compiler+SDK, binary, runner and original
    canary-denial evidence must be observed separately. Native T1 is denied.
    """
    if (type(proposed_head_sha) is not str or
            type(proposed_tree_sha) is not str or
            not _SHA40.fullmatch(proposed_head_sha) or
            not _SHA40.fullmatch(proposed_tree_sha) or
            proposed_head_sha == proposed_tree_sha):
        raise LbeM2NativeCanaryPreparationDenied(
            "proposed Head/Tree identity must be canonical distinct SHA")
    try:
        receipt = prepare_seatbelt_offline_backend_t0(
            native_helper_bytes=native_helper_bytes,
            fd_scrub_header_bytes=fd_scrub_header_bytes,
            bounded_wait_header_bytes=bounded_wait_header_bytes,
        )
    except LbeM2SeatbeltT0Error as exc:
        raise LbeM2NativeCanaryPreparationDenied(
            "unqualified first-party source closure") from exc
    if (receipt.status != "NONOPERATIVE_SEATBELT_CANARY_SOURCE_T0" or
            receipt.source_t1_authorized is not False or
            receipt.product_exec_authorized is not False or
            receipt.native_helper_executed is not False):
        raise LbeM2NativeCanaryPreparationDenied("cannot promote a T0 receipt")
    return MacOSCanaryValidationPlanT0(
        proposed_head_sha=proposed_head_sha,
        proposed_tree_sha=proposed_tree_sha,
        seatbelt_c_sha256=receipt.native_helper_source_sha256,
        fd_scrub_header_sha256=receipt.fd_scrub_header_sha256,
        bounded_wait_header_sha256=receipt.bounded_wait_header_sha256,
    )


def execute_macos_seatbelt_native_canary(
    _plan: object = None, _github_identity: object = None,
    _runner_identity: object = None, _compiler_binary: object = None,
    _precontact_policy: object = None, _owner_claim: object = None,
) -> None:
    """HARD STOP for any caller, including fake passing attestations.

    The C helper's 2-second finite wait is not descendant retirement on
    timeout, and macOS OS isolation and real canary results are unobserved.
    Only a later separately reviewed runnable implementation may attempt a
    non-destructive canary on an independently qualified disposable runner.
    """
    raise LbeM2NativeCanaryPreparationDenied(
        "NATIVE_MACOS_CANARY=NOT_RUN: missing new runnable review, "
        "source/OS/runner/build evidence, verified resource budgets and "
        "child-survivor containment; T1_SOURCE and T1_PRODUCT DENIED"
    )
