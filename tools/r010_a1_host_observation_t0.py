"""Actual macOS R010 A1 host SOURCE observation; SAFE T0 only.

This is NOT the R010 trusted PREEXEC_HOLD, does not request OIDC, does not
open SSH_AUTH_SOCK or autofs, and never launches Python/Go/Pipenv children.
R006 A0 stays unchanged: its *expected DENY* is explicitly asserted as
a negative control, never relabelled as an A0/PREEXEC/PRODUCT_T1 PASS.
"""
from __future__ import annotations

from dataclasses import asdict
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from gateway.lbe_r006_macos_allowlist import (
    D4R006HostAllowlistDenied, verify_r006_fixed_host_allowlist_t0,
)
from gateway.lbe_r010_a1_host import (
    R010A1HostDenied, inspect_r010_a1_host_source_t0,
)


_SAFE_REASONS = {
    "unqualified ambient SSH selector shape": "SSH_SELECTOR_MISSING_OR_BAD_SHAPE",
    "unreviewed Darwin ARM64 build": "DARWIN_ARCH_OR_RELEASE_DRIFT",
    "reviewed Job/image source claim mismatch": "GITHUB_IMAGE_CLAIM_DRIFT",
    "unreviewed Head/run/attempt/job source": "JOB_IDENTITY_DRIFT",
    "ambient network proxy selector present": "AMBIENT_PROXY_PRESENT",
    "injected system version invalid": "SYSTEM_VERSION_INJECTION_DENIED",
    "host OS build mismatch": "HOST_OS_BUILD_DRIFT",
    "host selected source receipt invalid": "SELECTED_SOURCE_RECEIPT_INVALID",
    "host A1 mount source invalid": "A1_MOUNT_SOURCE_INVALID",
    "A1 selected host source unavailable": "HOST_OS_OR_MOUNT_SOURCE_UNAVAILABLE",
    "not actual source-only A1 observation": "NOT_ACTUAL_OS_OBSERVATION",
    "unexpected R006 A0 result": "A0_UNEXPECTED_DENY_REASON",
    "R006 A0 unexpectedly accepted A1 source": "A0_UNEXPECTED_ALLOW",
}


def main() -> int:
    phase = "A1_SOURCE"
    try:
        a1 = inspect_r010_a1_host_source_t0()
        if (a1.status != "R010_A1_HOST_SOURCE_ONLY_NO_PRODUCT_T1"
                or a1.native_launch_allowed is not False
                or a1.host_snapshot_from_original_os is not True):
            raise R010A1HostDenied("not actual source-only A1 observation")
        phase = "A0_NEGATIVE_CONTROL"
        try:
            verify_r006_fixed_host_allowlist_t0()
        except D4R006HostAllowlistDenied as exc:
            # This is R006 A0's true refusal, not a masked CI failure.
            # Any other A0 drift/refusal remains a FAIL, including image,
            # repo, kernel or unrelated host-check errors.
            if str(exc) != "ambient credential-bearing environment is present":
                raise R010A1HostDenied("unexpected R006 A0 result") from None
            strict_a0 = "A0_EXPECTED_CREDENTIAL_DENY_UNCHANGED"
        else:
            raise R010A1HostDenied("R006 A0 unexpectedly accepted A1 source")
        report = {
            **asdict(a1),
            "r006_a0_negative_control": strict_a0,
            "preexec_real_oidc": "NOT_RUN",
            "preexec_real_environment_scrub": "NOT_RUN",
            "current_head_b_c_execution_qualification": "NOT_ISSUED",
            "owner_product_t1_grant": "NOT_ISSUED",
            "native_product_t1": "NOT_RUN",
            "integration_status": "NOT_TESTED",
        }
        print(json.dumps(report, sort_keys=True, separators=(",", ":")))
        return 0
    except (R010A1HostDenied, D4R006HostAllowlistDenied,
            OSError, ValueError) as exc:
        # Only whitelisted static error CODES may be logged, never the
        # exception body, SSH socket PATH, bearer, JWT or raw source.
        reason = _SAFE_REASONS.get(str(exc), "UNQUALIFIED_SOURCE")
        print(json.dumps({
            "status": "R010_A1_HOST_SOURCE_T0_DENY",
            "phase": phase,
            "reason_code": reason,
            "ssh_selector_name_present": bool(
                os.environ.get("SSH_AUTH_SOCK")),
            "native_launch_allowed": False,
            "r006_a0_authority_replaced": False,
        }, sort_keys=True, separators=(",", ":")))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
