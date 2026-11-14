"""R006 real-host identity observation ONLY (safe T0; never PRODUCT_T1).

Executed on GitHub-hosted macos-15 ARM64, after original G05 checkout.
Captures local Darwin facts and small GitHub job/image CLAIMS without spawning
a product child, contacting services or reading secrets. Never issues a
verified provider attestation, whole image proof, owner grant or launch right.
"""
from __future__ import annotations

import json
import os
import platform
import re
import sys

_SHA40 = re.compile(r"[0-9a-f]{40}\Z")
_IMAGE = re.compile(r"[0-9]{8}\.[0-9]{4}\.[0-9]+\Z")
_ID = re.compile(r"[1-9][0-9]{0,18}\Z")


def observe_r006_host_t0(*, environ=None, uname=None,
                         platform_tag=None, macos_release=None):
    """Return bounded claims and local observations; NEVER native authority."""
    env = os.environ if environ is None else environ
    actual = os.uname() if uname is None else uname
    tag = sys.platform if platform_tag is None else platform_tag
    release = platform.mac_ver()[0] if macos_release is None else macos_release
    names = (
        "GITHUB_ACTIONS", "GITHUB_EVENT_NAME", "GITHUB_REPOSITORY",
        "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "G05_EXPECTED_HEAD",
        "RUNNER_ENVIRONMENT", "RUNNER_OS", "RUNNER_ARCH",
        "ImageOS", "ImageVersion",
    )
    claimed = {}
    for name in names:
        raw = env.get(name, "")
        # Store only bounded literal strings; no arbitrary ambient environment
        # or credential/token values are ever emitted.
        claimed[name] = raw if type(raw) is str and len(raw) <= 120 else ""
    facts = {
        "sys_platform": tag if type(tag) is str and len(tag) <= 32 else "",
        "kernel": getattr(actual, "sysname", ""),
        "machine": getattr(actual, "machine", ""),
        "macos_release": release if type(release) is str and len(release) <= 48 else "",
    }
    expected = {
        "GITHUB_ACTIONS": "true",
        "GITHUB_EVENT_NAME": "pull_request",
        "GITHUB_REPOSITORY": "chinanjjohn2012/mac-file-gateway",
        "RUNNER_ENVIRONMENT": "github-hosted",
        "RUNNER_OS": "macOS",
        "RUNNER_ARCH": "ARM64",
    }
    checks = {
        "github_context_shape": all(claimed[k] == v for k, v in expected.items()),
        "run_attempt_shape": all(_ID.fullmatch(claimed[k]) is not None
                                 for k in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")),
        "head_shape": _SHA40.fullmatch(claimed["G05_EXPECTED_HEAD"]) is not None,
        "actual_darwin_arm64": (
            facts["sys_platform"] == "darwin" and facts["kernel"] == "Darwin"
            and facts["machine"] in ("arm64", "aarch64")
        ),
        "actual_macos_15": (
            type(facts["macos_release"]) is str
            and re.fullmatch(r"15\.[0-9]{1,3}(?:\.[0-9]{1,3})?", facts["macos_release"]) is not None
        ),
        "claimed_image_release_shape": (
            claimed["ImageOS"].lower() in ("macos15", "macos-15", "macos-15-arm64")
            and _IMAGE.fullmatch(claimed["ImageVersion"]) is not None
        ),
    }
    return {
        "profile": "D4_R006_HOSTED_MACOS15_ARM64_OBSERVATION_T0",
        "checks": checks,
        "claimed_job_and_image_metadata": claimed,
        "locally_observed_platform": facts,
        "source_measurements_observed": False,
        "github_provider_authenticated_from_independent_api": False,
        "full_boot_image_attested": False,
        "actual_loaded_graph_proven": False,
        "owner_signed_run_attempt_approved": False,
        "cross_process_owner_grant_validated": False,
        "native_launch_allowed": False,
        "real_product_t1_executed": False,
        "t0_platform_claims_consistent": all(checks.values()),
        "status": "NONOPERATIVE_HOSTED_RUNNER_T0_OBSERVATION_ONLY",
    }


def main():
    observation = observe_r006_host_t0()
    print(json.dumps(observation, sort_keys=True, separators=(",", ":")))
    return 0 if observation["t0_platform_claims_consistent"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
