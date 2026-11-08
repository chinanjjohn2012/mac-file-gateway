"""Fixed R006 macOS-15 ARM64 selected-host allowlist candidate.

Values are pinned from prior original GitHub-hosted macOS T0 Job
128635422796 / Run 42449482213 at ImageVersion 20261104.0514.1.
They are no longer learned from the current run. Matching this finite subset
is still NOT full-image attestation, dynamic loaded-source proof, independent
B/C code review, owner exact-run authorization, or native launch authority.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
import platform

from .lbe_hosted_source_probe import (
    D4HostedSelectedSourceObservation,
    inspect_d4_hosted_selected_source_files,
)

IMAGE_OS = "macos15"
IMAGE_VERSION = "20261104.0514.1"
MACOS_VERSION = "15.8.2"
OS_BUILD = "24H232"
_SYSTEM_EXPECTED = (
    ("Library/CoreServices/SystemVersion.plist",
     "7789975d8ee10cd0a331a22c8fded5232cdc3c4462fad0561a604cad5bb0d07e"),
)
_USR_EXPECTED = (
    ("bin/env",
     "ebda86b855682a1910382f8d03578f8df114c83277893d86082240b7e7345ed0"),
    ("lib/dyld",
     "02a4b237c9a87ea11ff4eeaac7bee360bd8cc94b07ea2e697cf88d5bd85610f9"),
)

def _fingerprint(value: object) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=True).encode("ascii")
    return hashlib.sha256(raw).hexdigest()

R006_HOST_SOURCE_FINGERPRINT = _fingerprint({
    "image_os": IMAGE_OS, "image_version": IMAGE_VERSION,
    "macos_version": MACOS_VERSION, "os_build": OS_BUILD,
    "system": _SYSTEM_EXPECTED, "usr": _USR_EXPECTED,
})
R006_RUNNER_PROFILE_FINGERPRINT = _fingerprint({
    "provider": "github-hosted", "runner_os": "macOS",
    "runner_arch": "ARM64", "image_os": IMAGE_OS,
    "image_version": IMAGE_VERSION, "macos_version": MACOS_VERSION,
    "os_build": OS_BUILD, "selected_source": R006_HOST_SOURCE_FINGERPRINT,
})

class D4R006HostAllowlistDenied(ValueError):
    """Current host is not the fixed reviewed-candidate R006 profile."""

@dataclass(frozen=True, slots=True)
class D4R006HostAllowlistObservation:
    system: D4HostedSelectedSourceObservation
    usr: D4HostedSelectedSourceObservation
    source_fingerprint: str
    runner_profile_fingerprint: str
    image_version: str
    macos_version: str
    os_build: str
    selected_source_bytes_verified: bool = True
    independently_reviewed_allowlist: bool = False
    full_boot_image_attested: bool = False
    actual_loaded_graph_proven: bool = False
    owner_exact_run_grant_verified: bool = False
    native_launch_allowed: bool = False
    status: str = "R006_FIXED_HOST_SOURCE_T0_MATCH_NOT_EXEC_AUTHORITY"

def verify_r006_fixed_host_allowlist_t0(
    *, environ=None, macos_release=None,
    system_root="/System", usr_root="/usr",
) -> D4R006HostAllowlistObservation:
    """Compare a NEW run to source constants pinned from the PRIOR run."""
    env = os.environ if environ is None else environ
    release = platform.mac_ver()[0] if macos_release is None else macos_release
    expected = {
        "GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "pull_request",
        "GITHUB_REPOSITORY": "chinanjjohn2012/mac-file-gateway",
        "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "macOS",
        "RUNNER_ARCH": "ARM64", "ImageOS": IMAGE_OS,
        "ImageVersion": IMAGE_VERSION,
    }
    if any(type(env.get(k)) is not str or env.get(k) != v
           for k, v in expected.items()):
        raise D4R006HostAllowlistDenied("current GitHub/macOS image claim mismatch")
    if release != MACOS_VERSION:
        raise D4R006HostAllowlistDenied("current macOS release mismatch")
    try:
        system = inspect_d4_hosted_selected_source_files(
            source_root=system_root, expected=_SYSTEM_EXPECTED)
        usr = inspect_d4_hosted_selected_source_files(
            source_root=usr_root, expected=_USR_EXPECTED)
    except (OSError, ValueError):
        raise D4R006HostAllowlistDenied(
            "fixed selected host source mismatch") from None
    return D4R006HostAllowlistObservation(
        system=system, usr=usr,
        source_fingerprint=R006_HOST_SOURCE_FINGERPRINT,
        runner_profile_fingerprint=R006_RUNNER_PROFILE_FINGERPRINT,
        image_version=IMAGE_VERSION, macos_version=MACOS_VERSION,
        os_build=OS_BUILD,
    )
