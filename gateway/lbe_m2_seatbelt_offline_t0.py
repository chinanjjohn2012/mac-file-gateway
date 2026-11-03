"""Mac Seatbelt OFFLINE_ONLY backend candidate, T0 structural admission only.

The reviewed first-party C helper is intentionally *canary-only*. It applies
sandbox_init in its own process, performs loopback-denial probes and a natural
fork/wait descendant check, and has NO way to exec Go/Pipenv.

This Python module never invokes subprocess, ctypes, socket, sandbox-exec,
sandbox_init, a host firewall or the native C helper. It neither accepts a
self-reported canary stdout string nor returns an execution entitlement.
Actual OS evidence needs a separate post-review disposable-macOS run and a
separately reviewed SAME-process canary -> native exec transition.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import platform
from typing import Final


class LbeM2SeatbeltT0Error(ValueError):
    """Unqualified source/profile/OS evidence or attempted T1 promotion."""


# Match only the literal compiled C source, never build a per-user policy.
# This default-deny canary profile intentionally has NO process-exec grant.
# No network-outbound/inbound/bind rule is granted; the helper probes a subset
# of loopback TCP/UDP and descendant inheritance. Remote egress, DNS resolver,
# AF_UNIX proxy and actual Go/Pipenv exec still require new actual evidence.
SEATBELT_CANARY_PROFILE: Final[str] = (
    "(version 1)\n"
    "(deny default)\n"
    "(allow file-read*)\n"
    "(allow process-fork)\n"
    "(allow sysctl-read)\n"
)
_CANARY_SOURCE_SHA256: Final[str] = (
    "f66b9382c32775ff14952debe94f6d20ebc45ad1a8173146c64eeee57db8bf4b"
)
_CANARY_SOURCE_PATH: Final[str] = "tools/lbe_m2_seatbelt_canary_only.c"
_FD_SCRUB_SOURCE_PATH: Final[str] = "tools/lbe_m2_fd_scrub_t0.h"
_FD_SCRUB_SOURCE_SHA256: Final[str] = (
    "af545c5da23f0b87bd90a0ce7bf5b70b28d30d82cd7cb71ecda4d886880bc435"
)
_WAIT_SOURCE_PATH: Final[str] = "tools/lbe_m2_canary_bounded_wait_t0.h"
_WAIT_SOURCE_SHA256: Final[str] = (
    "65cffa3dc3c778d06dd88cd1636dbef021bc537ea69260c46b14816b39502b1f"
)
_MAX_NATIVE_SOURCE_BYTES: Final[int] = 65536
_BLOCKERS: Final[tuple[str, ...]] = (
    "MACOS_SEATBELT_SANDBOX_INIT_DEPRECATED_AND_NOT_HOST_VALIDATED",
    "NATIVE_CANARY_BINARY_AND_COMPILER_IDENTITY_NOT_ATTESTED",
    "ACTUAL_RUNNER_OS_IMAGE_PYTHON_AND_G05_NOT_ATTESTED",
    "ACTUAL_KERNEL_POLICY_ATTACHMENT_NOT_TESTED",
    "DESCENDANT_SEATBELT_INHERITANCE_NOT_TESTED",
    "TCP_UDP_DNS_PROXY_ALL_ROUTES_NOT_ATTESTED",
    "SAME_DOMAIN_CANARY_TO_GO_PIPENV_EXEC_BINDING_MISSING",
    "ACTUAL_LOADED_GO_PIPENV_SOURCE_NOT_ATTESTED",
    "OS_CPU_RAM_WALL_AND_OUTPUT_CAPS_NOT_ENFORCED",
    "CURRENT_EXECUTABLE_TEST_CODE_BC_REVIEW_NOT_ISSUED",
    "CANARY_BOUNDED_WAIT_OS_NOT_ATTESTED_AND_CHILD_SURVIVOR_RISK",
    "NO_APPROVED_CHILD_REAP_OR_RETIREMENT_ON_DEADLINE",
    "T1_SOURCE_AND_T1_PRODUCT_NOT_RUN",
)


@dataclass(frozen=True)
class SeatbeltOfflineBackendT0:
    """Static first-party candidate, deliberately NOT an OS-proof receipt."""

    backend: str
    policy_source: str
    policy_sha256: str
    native_helper_source_path: str
    native_helper_source_sha256: str
    fd_scrub_header_path: str
    fd_scrub_header_sha256: str
    bounded_wait_header_path: str
    bounded_wait_header_sha256: str
    observed_platform: str
    observed_machine: str
    status: str = "NONOPERATIVE_SEATBELT_CANARY_SOURCE_T0"
    kernel_attachment: str = "NOT_ATTESTED"
    original_context_canary: str = "NOT_RUN"
    descendant_context_canary: str = "NOT_RUN"
    dns_and_proxy_coverage: str = "NOT_ATTESTED"
    native_helper_executed: bool = False
    native_go_pipenv_executed: bool = False
    source_t1_authorized: bool = False
    product_exec_authorized: bool = False
    blockers: tuple[str, ...] = _BLOCKERS


def prepare_seatbelt_offline_backend_t0(
    *, native_helper_bytes: bytes, fd_scrub_header_bytes: bytes,
    bounded_wait_header_bytes: bytes,
    proposed_policy: str = SEATBELT_CANARY_PROFILE,
) -> SeatbeltOfflineBackendT0:
    """Admit EXACT checked C source/profile bytes for static review only.

    A valid result does not bind the compiled executable or OS policy. Caller
    bytes may be copied; the repo's fixed Git Head/Tree + G05 checks must
    separately establish which first-party files were actually tested.
    """
    if (type(native_helper_bytes) is not bytes or
            not 1 <= len(native_helper_bytes) <= _MAX_NATIVE_SOURCE_BYTES):
        raise LbeM2SeatbeltT0Error("unreviewed native canary source input")
    if (type(fd_scrub_header_bytes) is not bytes or
            not 1 <= len(fd_scrub_header_bytes) <= _MAX_NATIVE_SOURCE_BYTES):
        raise LbeM2SeatbeltT0Error("unreviewed inherited-FD scrub source input")
    checked_fd = hashlib.sha256(fd_scrub_header_bytes).hexdigest()
    if checked_fd != _FD_SCRUB_SOURCE_SHA256:
        raise LbeM2SeatbeltT0Error("inherited-FD scrub source identity drift")
    if (type(bounded_wait_header_bytes) is not bytes or
            not 1 <= len(bounded_wait_header_bytes) <= _MAX_NATIVE_SOURCE_BYTES):
        raise LbeM2SeatbeltT0Error("unreviewed bounded wait source input")
    checked_wait = hashlib.sha256(bounded_wait_header_bytes).hexdigest()
    if checked_wait != _WAIT_SOURCE_SHA256:
        raise LbeM2SeatbeltT0Error("bounded wait source identity drift")
    if type(proposed_policy) is not str or proposed_policy != SEATBELT_CANARY_PROFILE:
        raise LbeM2SeatbeltT0Error("policy must equal immutable OFFLINE_ONLY canary")
    checked = hashlib.sha256(native_helper_bytes).hexdigest()
    if checked != _CANARY_SOURCE_SHA256:
        raise LbeM2SeatbeltT0Error("native canary source identity drift")
    return SeatbeltOfflineBackendT0(
        backend="MACOS15_ARM64_SEATBELT_C_CANARY_CANDIDATE",
        policy_source=SEATBELT_CANARY_PROFILE,
        policy_sha256=hashlib.sha256(
            SEATBELT_CANARY_PROFILE.encode("ascii")).hexdigest(),
        native_helper_source_path=_CANARY_SOURCE_PATH,
        native_helper_source_sha256=checked,
        fd_scrub_header_path=_FD_SCRUB_SOURCE_PATH,
        fd_scrub_header_sha256=checked_fd,
        bounded_wait_header_path=_WAIT_SOURCE_PATH,
        bounded_wait_header_sha256=checked_wait,
        observed_platform=platform.system(),
        observed_machine=platform.machine(),
    )


def require_verified_offline_domain_before_native_t1(
    _plan: object = None, _native_binary: object = None,
    _claimed_policy_attachment: object = None,
    _claimed_canary_output: object = None,
    _runner_witness: object = None,
) -> None:
    """No user-constructible Python receipt can grant real Go/Pipenv T1.

    The native C candidate only tests a *subset* of loopback socket denial
    in its own process and forked descendant. Bounded WNOHANG polling
    does NOT retire an unknown child or prove a safe timeout. It does not
    perform an exec of
    the target Go/Pipenv child in that same context, does not attest remote
    egress or DNS/proxy, and has never been executed on an approved macOS
    runner in this revision. Unconditionally reject until a new exact reviewed
    executable path and original OS/native canary evidence exist.
    """
    raise LbeM2SeatbeltT0Error(
        "NATIVE_SOURCE_T1=NOT_RUN: no B/C-reviewed SAME-process "
        "OFFLINE_ONLY Seatbelt attachment/canary-to-exec witness, "
        "loaded-source provenance or OS resource enforcement"
    )
