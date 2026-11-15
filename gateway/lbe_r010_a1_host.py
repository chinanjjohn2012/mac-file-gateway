"""R010 A1 selected-host source admission and PREEXEC environment boundary.

The current D4 R006 A0 verifier is intentionally NOT called. A1 accepts only
the fixed, Owner-chosen single autofs exception and the SSH_AUTH_SOCK *name*
in a host-source observation. It never connects, stats, enumerates or sends
data to the SSH agent, and never traverses or activates the autofs target.

This is SOURCE/T0 infrastructure, not a verified PREEXEC_HOLD or an operative
PRODUCT_T1 launcher. A1 still requires signed current Job, original Owner
Grant, independently reviewed live entrypoint, environment scrub before
product imports, and full downstream source/Worker qualification.
"""
from __future__ import annotations

from collections.abc import MutableMapping
from dataclasses import dataclass
import hashlib
import json
import os
import platform
import re
from typing import Any

from .lbe_hosted_source_probe import (
    D4HostedSelectedSourceObservation, D4HostedSourceDenied,
    inspect_d4_hosted_selected_source_files,
)
from .lbe_r006_macos_allowlist import (
    D4R006HostAllowlistDenied, IMAGE_OS, IMAGE_VERSION, MACOS_VERSION,
    OS_BUILD, R006_HOST_SOURCE_FINGERPRINT, _SYSTEM_EXPECTED,
    _USR_EXPECTED, _actual_system_version,
)
from .lbe_r010_a1_mount import (
    R010A1MountDenied, R010A1MountSnapshot, inspect_r010_a1_mounts,
)
from .lbe_r010_preexec_env import (
    R010ExpectedRunnerEnv, R010PreexecEnvDenied,
    build_closed_product_child_env, scrub_preexec_mapping,
)

_SHA40 = re.compile(r"[0-9a-f]{40}\Z", re.ASCII)
_DECIMAL = re.compile(r"[1-9][0-9]{0,17}\Z", re.ASCII)
_ATTEMPT = re.compile(r"[1-9][0-9]{0,11}\Z", re.ASCII)
_JOB = re.compile(r"[A-Za-z0-9_.-]{1,80}\Z", re.ASCII)
_PROXY = frozenset({
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "FTP_PROXY", "NO_PROXY",
})


class R010A1HostDenied(ValueError):
    """This exact A1 host-source or scrubbed helper snapshot is unavailable."""


@dataclass(frozen=True, slots=True)
class R010A1HostSource:
    head_sha: str
    run_id: str
    run_attempt: str
    job_name: str
    image_version: str
    host_source_sha256: str
    mount_table_sha256: str
    ssh_selector_observed: bool
    host_snapshot_from_original_os: bool
    status: str = "R010_A1_HOST_SOURCE_ONLY_NO_PRODUCT_T1"
    no_ambient_ssh_agent_proven: bool = False
    no_shared_writable_mounts_proven: bool = False
    full_boot_image_attested: bool = False
    current_provider_job_authenticated: bool = False
    owner_product_t1_grant_verified: bool = False
    native_launch_allowed: bool = False


@dataclass(frozen=True, slots=True)
class R010A1ClosedPreexecSource:
    head_sha: str
    run_id: str
    mount_table_sha256: str
    helper_keys: tuple[str, ...]
    child_keys: tuple[str, ...]
    # SHA of exact canonical five-key post-scrub map. This is an
    # in-process equality witness ONLY, not provider or Owner attestation.
    helper_env_sha256: str = ""
    status: str = "R010_A1_SOURCE_ONLY_SCRUBBED_NOT_LIVE_PREEXEC"
    live_oidc_token_requested: bool = False
    ssh_agent_protocol_called: bool = False
    verified_current_provider_job: bool = False
    native_launch_allowed: bool = False


def _ssh_name_only(env: dict[str, str]) -> bool:
    """Check metadata shape only. Never inspect filesystem/socket contents."""
    value = env.get("SSH_AUTH_SOCK")
    if (type(value) is not str or not 1 <= len(value) <= 4096
            or not value.startswith("/") or "\\" in value
            or "\x00" in value or ".." in value.split("/")
            or any(ord(ch) < 33 or ord(ch) >= 127 for ch in value)):
        raise R010A1HostDenied("unqualified ambient SSH selector shape")
    return True


def inspect_r010_a1_host_source_t0(
    *, environ: dict[str, str] | None = None,
    uname: Any = None, macos_release: str | None = None,
    mount_rows_t0: tuple[tuple[str, str, str, int], ...] | None = None,
    system_version_t0: tuple[str, str] | None = None,
    system_root: str = "/System", usr_root: str = "/usr",
) -> R010A1HostSource:
    """Bounded true-source host-file/mount observations; no native authority.

    Passing injected environment/OS/mounts is exclusively synthetic T0.
    With no injected inputs, this reads actual host metadata (but neither
    OIDC bearer nor agent socket). The result is never an executable token.
    """
    source_original = (
        environ is None and uname is None and macos_release is None
        and mount_rows_t0 is None and system_version_t0 is None
        and system_root == "/System" and usr_root == "/usr")
    try:
        env = dict(os.environ) if environ is None else environ
        if (type(env) is not dict or
                any(type(k) is not str or type(v) is not str
                    for k, v in env.items())):
            raise R010A1HostDenied("invalid host environment shape")
        kernel = os.uname() if uname is None else uname
        release = platform.mac_ver()[0] if macos_release is None else macos_release
        if (getattr(kernel, "sysname", None) != "Darwin"
                or getattr(kernel, "machine", None) not in ("arm64", "aarch64")
                or release != MACOS_VERSION):
            raise R010A1HostDenied("unreviewed Darwin ARM64 build")
        expected = {
            "GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "pull_request",
            "GITHUB_REPOSITORY": "chinanjjohn2012/mac-file-gateway",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "RUNNER_OS": "macOS", "RUNNER_ARCH": "ARM64",
            "ImageOS": IMAGE_OS, "ImageVersion": IMAGE_VERSION,
        }
        if any(env.get(k) != v for k, v in expected.items()):
            raise R010A1HostDenied("reviewed Job/image source claim mismatch")
        head = env.get("G05_EXPECTED_HEAD", "")
        run_id = env.get("GITHUB_RUN_ID", "")
        attempt = env.get("GITHUB_RUN_ATTEMPT", "")
        job_name = env.get("GITHUB_JOB", "")
        if (_SHA40.fullmatch(head) is None
                or _DECIMAL.fullmatch(run_id) is None
                or _ATTEMPT.fullmatch(attempt) is None
                or _JOB.fullmatch(job_name) is None):
            raise R010A1HostDenied("unreviewed Head/run/attempt/job source")
        if any(bool(value) and name.upper() in _PROXY
               for name, value in env.items()):
            raise R010A1HostDenied("ambient network proxy selector present")
        # R006 A0 rejects the following name; A1's host SOURCE probe may
        # observe the bounded metadata without touching the Unix socket.
        _ssh_name_only(env)
        if system_version_t0 is None:
            version, build = _actual_system_version(system_root)
        else:
            if (type(system_version_t0) is not tuple
                    or len(system_version_t0) != 2
                    or any(type(v) is not str for v in system_version_t0)):
                raise R010A1HostDenied("injected system version invalid")
            version, build = system_version_t0
        if (version, build) != (MACOS_VERSION, OS_BUILD):
            raise R010A1HostDenied("host OS build mismatch")
        system = inspect_d4_hosted_selected_source_files(
            source_root=system_root, expected=_SYSTEM_EXPECTED)
        usr = inspect_d4_hosted_selected_source_files(
            source_root=usr_root, expected=_USR_EXPECTED)
        for item in (system, usr):
            if (type(item) is not D4HostedSelectedSourceObservation
                    or item.source_file_bytes_verified is not True
                    or item.native_launch_allowed is not False
                    or item.full_boot_image_identity_attested is not False
                    or item.actual_loaded_source_graph_attested is not False):
                raise R010A1HostDenied("host selected source receipt invalid")
        mount = inspect_r010_a1_mounts(observed_rows=mount_rows_t0)
        if type(mount) is not R010A1MountSnapshot or mount.native_launch_allowed is not False:
            raise R010A1HostDenied("host A1 mount source invalid")
        return R010A1HostSource(
            head_sha=head, run_id=run_id, run_attempt=attempt,
            job_name=job_name, image_version=IMAGE_VERSION,
            host_source_sha256=R006_HOST_SOURCE_FINGERPRINT,
            mount_table_sha256=mount.full_table_sha256,
            ssh_selector_observed=True,
            host_snapshot_from_original_os=source_original)
    except R010A1HostDenied:
        raise
    except (OSError, TypeError, ValueError, AttributeError):
        # No user-controlled pathname, agent selector, JWT or credential
        # value may appear in an exception or diagnostic transcript.
        raise R010A1HostDenied("A1 selected host source unavailable") from None


def close_r010_a1_preexec_source_t0(
    *, host: R010A1HostSource,
    expected: R010ExpectedRunnerEnv,
    bootstrap: MutableMapping[str, str],
) -> R010A1ClosedPreexecSource:
    """Join host identity with exact 18+2 PREEXEC scrub (synthetic SOURCE).

    This function is a composition test, NOT the future true PREEXEC_HOLD.
    A genuine pre-product entrypoint must scrub OS env BEFORE importing the
    gateway package and must authenticate the original provider Job/Owner.
    """
    if not isinstance(bootstrap, MutableMapping):
        raise R010A1HostDenied("PREEXEC map cannot be scrubbed")
    try:
        if (type(host) is not R010A1HostSource
                or type(expected) is not R010ExpectedRunnerEnv
                or host.status != "R010_A1_HOST_SOURCE_ONLY_NO_PRODUCT_T1"
                or host.native_launch_allowed is not False
                or host.current_provider_job_authenticated is not False
                or host.owner_product_t1_grant_verified is not False
                or host.no_ambient_ssh_agent_proven is not False
                or host.no_shared_writable_mounts_proven is not False
                or host.full_boot_image_attested is not False
                or host.head_sha != expected.head_sha
                or host.run_id != expected.run_id
                or host.run_attempt != expected.run_attempt
                or host.job_name != expected.job_name
                or host.image_version != expected.image_version
                or host.ssh_selector_observed is not True
                or not re.fullmatch(r"[0-9a-f]{64}", host.mount_table_sha256)):
            raise R010A1HostDenied("A1 host/PREEXEC source mismatch")
        helper = scrub_preexec_mapping(bootstrap, expected)
        child = build_closed_product_child_env(helper)
        if (helper != child
                or frozenset(helper) !=
                frozenset({"PATH", "HOME", "TMPDIR", "LANG", "LC_ALL"})):
            raise R010A1HostDenied("unclosed R010 product helper environment")
        return R010A1ClosedPreexecSource(
            head_sha=host.head_sha, run_id=host.run_id,
            mount_table_sha256=host.mount_table_sha256,
            helper_keys=tuple(sorted(helper)),
            child_keys=tuple(sorted(child)),
            helper_env_sha256=hashlib.sha256(json.dumps(
                helper, sort_keys=True, separators=(",", ":"),
                ensure_ascii=True).encode("ascii")).hexdigest(),
        )
    except BaseException:
        # All failure modes remove the original selectors from mutable maps;
        # no fallback to a less strict old A0/ordinary Exec launch path.
        try:
            bootstrap.clear()
        except BaseException:
            pass
        raise R010A1HostDenied("A1 PREEXEC source scrub failed closed") from None
