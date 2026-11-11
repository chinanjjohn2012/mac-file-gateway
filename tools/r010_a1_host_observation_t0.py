"""Actual macOS R010 A1 host SOURCE observation; SAFE T0 only.

This is NOT the R010 trusted PREEXEC_HOLD, does not request OIDC, does not
open SSH_AUTH_SOCK or autofs, and never launches Python/Go/Pipenv children.
R006 A0 stays unchanged: its *expected DENY* is explicitly asserted as
a negative control, never relabelled as an A0/PREEXEC/PRODUCT_T1 PASS.
"""
from __future__ import annotations

from dataclasses import asdict
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from gateway.lbe_r006_macos_allowlist import (
    D4R006HostAllowlistDenied, verify_r006_fixed_host_allowlist_t0,
)
from gateway.lbe_r010_a1_host import (
    R010A1HostDenied, inspect_r010_a1_host_source_t0,
)


def main() -> int:
    try:
        a1 = inspect_r010_a1_host_source_t0()
        if (a1.status != "R010_A1_HOST_SOURCE_ONLY_NO_PRODUCT_T1"
                or a1.native_launch_allowed is not False
                or a1.host_snapshot_from_original_os is not True):
            raise R010A1HostDenied("not actual source-only A1 observation")
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
            OSError, ValueError):
        # No SSH socket path, agent identities, local secret value or raw
        # system source is exposed in failure output.
        print(json.dumps({
            "status": "R010_A1_HOST_SOURCE_T0_DENY",
            "native_launch_allowed": False,
            "r006_a0_authority_replaced": False,
        }, sort_keys=True, separators=(",", ":")))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
