"""R010 A1 tiny stdlib-only PREEXEC bootstrap environment closure.

Entry point for a FUTURE independently qualified PREEXEC_HOLD workflow.
It must be imported/executed BEFORE any gateway or product module. This
implementation validates and scrubs exact 18+2 source selectors, without
network, SSH-agent access, autofs lookup, a child or a T1 grant. Expectations
here are UNAUTHENTICATED: only later current-Job signed/provider/Owner proof
can establish the runtime identity. Do not claim a real PREEXEC qualification.
"""
from __future__ import annotations

from collections.abc import MutableMapping
from dataclasses import dataclass
import os
import re
from urllib.parse import urlsplit

_KEYS = frozenset({
    "PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "GITHUB_ACTIONS",
    "GITHUB_EVENT_NAME", "GITHUB_REPOSITORY", "GITHUB_RUN_ID",
    "GITHUB_RUN_ATTEMPT", "GITHUB_JOB", "G05_EXPECTED_HEAD",
    "RUNNER_ENVIRONMENT", "RUNNER_OS", "RUNNER_ARCH", "ImageOS",
    "ImageVersion", "SSH_AUTH_SOCK", "ACTIONS_ID_TOKEN_REQUEST_URL",
    "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
})
_HELPER = frozenset({"PATH", "HOME", "TMPDIR", "LANG", "LC_ALL"})
_ID = re.compile(r"[1-9][0-9]{0,17}\Z", re.ASCII)
_ATTEMPT = re.compile(r"[1-9][0-9]{0,11}\Z", re.ASCII)
_SHA = re.compile(r"[0-9a-f]{40}\Z", re.ASCII)
_JOB = re.compile(r"[A-Za-z0-9_.-]{1,80}\Z", re.ASCII)
_HOST = re.compile(
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.actions\.githubusercontent\.com\Z",
    re.ASCII,
)


class R010BootstrapDenied(ValueError):
    """The exact closed A1 PREEXEC bootstrap was not established."""


@dataclass(frozen=True, slots=True)
class R010BootstrapExpected:
    """Untrusted source expectations, NOT provider-verified authority."""

    head_sha: str
    run_id: str
    run_attempt: str
    job_name: str
    image_version: str
    private_home: str
    private_tmp: str


@dataclass(frozen=True, slots=True)
class R010BootstrapClosedSource:
    """Real map scrub, but no signed Job/Owner/native execution evidence."""

    helper_names: tuple[str, ...]
    status: str = "R010_A1_PREIMPORT_SCRUB_SOURCE_ONLY"
    original_oidc_token_requested: bool = False
    ssh_agent_protocol_calls: int = 0
    real_preexec_job_provider_attested: bool = False
    native_launch_allowed: bool = False


def _absolute_private(value: object, *, max_length: int = 240) -> bool:
    return (
        type(value) is str and 1 <= len(value) <= max_length
        and value.startswith("/") and "\\" not in value and "\x00" not in value
        and ".." not in value.split("/")
        and all(33 <= ord(ch) < 127 for ch in value)
    )


def _oidc_endpoint(raw: str) -> bool:
    if (type(raw) is not str or not 1 <= len(raw) <= 4096
            or any(ord(ch) < 33 or ord(ch) >= 127 for ch in raw)
            or "\\" in raw):
        return False
    try:
        u = urlsplit(raw)
        return (u.scheme == "https" and u.hostname is not None
                and _HOST.fullmatch(u.hostname) is not None
                and u.netloc == u.hostname and u.username is None
                and u.password is None and u.port is None and not u.fragment
                and u.path == "/_apis/oidc/token"
                and u.query == "api-version=2.0"
                and raw == (
                    "https://" + u.hostname
                    + "/_apis/oidc/token?api-version=2.0"))
    except ValueError:
        return False


def close_r010_a1_preimport_bootstrap(
    *, env: MutableMapping[str, str],
    expected: R010BootstrapExpected,
) -> R010BootstrapClosedSource:
    """Scrub real mutable PREEXEC map in-place, before any product import.

    This predicate NEVER accepts a passed-in source/caller assertion as
    signed GitHub provider/Job identity. A future independently reviewed
    runner MUST set the exact /usr/bin/env -i map and check live original
    provider, grant and permissions before attempting any product import.
    """
    if not isinstance(env, MutableMapping):
        raise R010BootstrapDenied("unavailable mutable pre-import environment")
    try:
        if (type(expected) is not R010BootstrapExpected
                or _SHA.fullmatch(expected.head_sha) is None
                or _ID.fullmatch(expected.run_id) is None
                or _ATTEMPT.fullmatch(expected.run_attempt) is None
                or _JOB.fullmatch(expected.job_name) is None
                or expected.image_version != "20261104.0514.1"
                or not _absolute_private(expected.private_home)
                or not _absolute_private(expected.private_tmp)):
            raise R010BootstrapDenied("unqualified bootstrap expectation")
        if (frozenset(env) != _KEYS
                or any(type(k) is not str or type(v) is not str
                       for k, v in env.items())):
            raise R010BootstrapDenied("unreviewed inherited PREEXEC keys")
        required = {
            "PATH": "/usr/bin:/bin", "HOME": expected.private_home,
            "TMPDIR": expected.private_tmp, "LANG": "C", "LC_ALL": "C",
            "GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "pull_request",
            "GITHUB_REPOSITORY": "chinanjjohn2012/mac-file-gateway",
            "GITHUB_RUN_ID": expected.run_id,
            "GITHUB_RUN_ATTEMPT": expected.run_attempt,
            "GITHUB_JOB": expected.job_name,
            "G05_EXPECTED_HEAD": expected.head_sha,
            "RUNNER_ENVIRONMENT": "github-hosted",
            "RUNNER_OS": "macOS", "RUNNER_ARCH": "ARM64",
            "ImageOS": "macos15", "ImageVersion": expected.image_version,
        }
        if any(env[key] != value for key, value in required.items()):
            raise R010BootstrapDenied("run or fixed bootstrap identity drift")
        ssh = env["SSH_AUTH_SOCK"]
        token = env["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]
        url = env["ACTIONS_ID_TOKEN_REQUEST_URL"]
        if (not _absolute_private(ssh, max_length=4096)
                or not 16 <= len(token) <= 8192
                or any(ord(c) < 33 or ord(c) > 126 for c in token)
                or not _oidc_endpoint(url)):
            raise R010BootstrapDenied("PREEXEC selector shape not reviewed")
        if any(
            selector in env[key]
            for key in _HELPER
            for selector in (ssh, token, url)
        ):
            raise R010BootstrapDenied("credential selector aliased into helper")
        helper = {key: env[key] for key in _HELPER}
        env.clear()
        env.update(helper)
        if frozenset(env) != _HELPER or dict(env) != helper:
            raise R010BootstrapDenied("bootstrap scrub not verified")
        return R010BootstrapClosedSource(helper_names=tuple(sorted(helper)))
    except BaseException:
        # Credential-bearing selector *values* are never logged or returned.
        # Clear even on invalid input; no fallback to R006 or a product Popen.
        try:
            env.clear()
        except BaseException:
            pass
        raise R010BootstrapDenied("R010 A1 source bootstrap denied") from None


# Intentionally no gateway/product import, token request or __main__ launcher.
