"""R010 A1 PREEXEC-only environment validation and irreversible scrub.

Real environment-map operations for a future separately authorized OIDC
PREEXEC_HOLD. This module never calls GitHub, opens a socket, requests a JWT,
launches a child, imports the product service, or issues a PRODUCT_T1 grant.
It is NOT an identity verifier: caller-supplied expectations alone cannot
authenticate provider-signed job identity. All positive Exec remains F1-denied.
"""
from __future__ import annotations

from dataclasses import dataclass
from collections.abc import MutableMapping, Mapping
import os
import re
from types import MappingProxyType
from urllib.parse import urlsplit

_BOOTSTRAP_KEYS = frozenset({
    "PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "GITHUB_ACTIONS",
    "GITHUB_EVENT_NAME", "GITHUB_REPOSITORY", "GITHUB_RUN_ID",
    "GITHUB_RUN_ATTEMPT", "GITHUB_JOB", "G05_EXPECTED_HEAD",
    "RUNNER_ENVIRONMENT", "RUNNER_OS", "RUNNER_ARCH", "ImageOS",
    "ImageVersion", "SSH_AUTH_SOCK", "ACTIONS_ID_TOKEN_REQUEST_URL",
    "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
})
_HELPER_KEYS = frozenset({"PATH", "HOME", "TMPDIR", "LANG", "LC_ALL"})
_CHILD_SAFE_EXTRAS = MappingProxyType({
    "PYTHONUNBUFFERED": "1",
    "PYTHONDONTWRITEBYTECODE": "1",
    "PIP_NO_INDEX": "1",
    "PIP_DISABLE_PIP_VERSION_CHECK": "1",
})
_RUN_ATTEMPT = re.compile(r"[1-9][0-9]{0,11}\Z", re.ASCII)
_SHA40 = re.compile(r"[0-9a-f]{40}\Z", re.ASCII)
_ID_TOKEN_HOST = re.compile(
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.actions\.githubusercontent\.com\Z",
    re.ASCII,
)
_HARD_DENIED_PREFIXES = (
    "ACTIONS_ID_TOKEN_", "GITHUB_", "RUNNER_", "SSH_", "GIT_",
    "AWS_", "AZURE_", "GOOGLE_", "OIDC_", "GH_", "KRB5_",
    "IMAGE_", "HTTP_", "HTTPS_", "PIPENV_", "PIP_INDEX",
    "PIP_EXTRA_INDEX", "PIP_TRUSTED", "PIP_CONFIG",
)
_HARD_DENIED_SUFFIXES = (
    "_TOKEN", "_PASSWORD", "_PASSWD", "_SECRET", "_KEY",
    "_AUTH", "_CREDENTIAL", "_CREDENTIALS", "_PROXY",
)
_FORBIDDEN_EXACT = frozenset({"SSH_AUTH_SOCK", "SSH_ASKPASS",
    "GIT_ASKPASS", "KRB5CCNAME", "HTTP_PROXY", "HTTPS_PROXY",
    "NO_PROXY", "ALL_PROXY", "PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL"})
_ASCII_ENV_NAME = re.compile(r"[A-Z][A-Z0-9_]{0,127}\Z", re.ASCII)


class R010PreexecEnvDenied(ValueError):
    """The PREEXEC or downstream closed environment is not qualified."""


@dataclass(frozen=True, slots=True)
class R010ExpectedRunnerEnv:
    """Externally supplied expected values must come from trusted Job proofs.

    This class compares provenance; it CANNOT establish it. A future PREEXEC
    verifier must bind actual signed run/job/workflow, source/image and roots.
    """
    run_id: str
    run_attempt: str
    head_sha: str
    job_name: str
    image_version: str
    private_home: str
    private_tmp: str

    def checked(self) -> "R010ExpectedRunnerEnv":
        if (type(self.run_id) is not str or _RUN_ATTEMPT.fullmatch(
                self.run_id) is None
                or type(self.run_attempt) is not str
                or _RUN_ATTEMPT.fullmatch(self.run_attempt) is None
                or type(self.head_sha) is not str
                or _SHA40.fullmatch(self.head_sha) is None
                or type(self.job_name) is not str
                or re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", self.job_name,
                                re.ASCII) is None
                or type(self.image_version) is not str
                or self.image_version != "20261104.0514.1"):
            raise R010PreexecEnvDenied("unqualified expected Job/image")
        for path in (self.private_home, self.private_tmp):
            if (type(path) is not str or not path.startswith("/")
                    or len(path) > 240 or "\x00" in path
                    or ".." in path.split("/")
                    or any(ord(c) < 33 for c in path)):
                raise R010PreexecEnvDenied("unqualified private product path")
        return self


def _reviewed_oidc_base(raw_url: str) -> None:
    """Offline exact fixture profile, not a live endpoint/TLS guarantee."""
    if (type(raw_url) is not str or not 1 <= len(raw_url) <= 4096
            or any(ord(c) < 33 or ord(c) > 126 for c in raw_url)
            or "\\" in raw_url):
        raise R010PreexecEnvDenied("unqualified runner OIDC endpoint")
    try:
        url = urlsplit(raw_url)
        host = url.hostname
        port = url.port
    except ValueError:
        raise R010PreexecEnvDenied("malformed runner OIDC endpoint") from None
    if (url.scheme != "https" or host is None
            or _ID_TOKEN_HOST.fullmatch(host) is None
            or url.username is not None or url.password is not None
            or port is not None or url.fragment
            or url.path != "/_apis/oidc/token"
            or url.query != "api-version=2.0"
            or raw_url != (
                "https://" + host + "/_apis/oidc/token?api-version=2.0")):
        raise R010PreexecEnvDenied("unreviewed OIDC endpoint version")


def _expected_bootstrap_values(identity: R010ExpectedRunnerEnv) -> dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin", "HOME": identity.private_home,
        "TMPDIR": identity.private_tmp, "LANG": "C", "LC_ALL": "C",
        "GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "pull_request",
        "GITHUB_REPOSITORY": "chinanjjohn2012/mac-file-gateway",
        "GITHUB_RUN_ID": identity.run_id,
        "GITHUB_RUN_ATTEMPT": identity.run_attempt,
        "GITHUB_JOB": identity.job_name, "G05_EXPECTED_HEAD": identity.head_sha,
        "RUNNER_ENVIRONMENT": "github-hosted",
        "RUNNER_OS": "macOS", "RUNNER_ARCH": "ARM64",
        "ImageOS": "macos15", "ImageVersion": identity.image_version,
    }


def validate_preexec_mapping(
    env: Mapping[str, str], expected: R010ExpectedRunnerEnv,
) -> None:
    """Validate exact PREEXEC-only environment with no network/agent calls."""
    if type(expected) is not R010ExpectedRunnerEnv:
        raise R010PreexecEnvDenied("wrong expected Job type")
    expected.checked()
    if not isinstance(env, Mapping):
        raise R010PreexecEnvDenied("unqualified PREEXEC mapping")
    try:
        keys = frozenset(env)
        if keys != _BOOTSTRAP_KEYS:
            raise R010PreexecEnvDenied("PREEXEC inherited extra/missing keys")
        values = dict(env)
    except (TypeError, ValueError):
        raise R010PreexecEnvDenied("unreadable PREEXEC environment") from None
    if any(type(key) is not str or type(value) is not str
           for key, value in values.items()):
        raise R010PreexecEnvDenied("non-string PREEXEC environment")
    for k, value in _expected_bootstrap_values(expected).items():
        if values[k] != value:
            raise R010PreexecEnvDenied("bootstrap differs from current Job")
    selector = values["SSH_AUTH_SOCK"]
    if (not selector.startswith("/") or len(selector) > 4096
            or "\x00" in selector or ".." in selector.split("/")
            or any(ord(c) < 33 for c in selector)):
        raise R010PreexecEnvDenied("noncanonical SSH socket selector")
    token = values["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]
    if (not 16 <= len(token) <= 8192
            or any(ord(c) < 33 or ord(c) > 126 for c in token)):
        raise R010PreexecEnvDenied("unqualified runner OIDC bearer")
    _reviewed_oidc_base(values["ACTIONS_ID_TOKEN_REQUEST_URL"])
    # Never permit a secret as an innocently renamed helper value.
    originals = (
        token, values["ACTIONS_ID_TOKEN_REQUEST_URL"], selector,
    )
    for key in _HELPER_KEYS:
        if any(secret in values[key] for secret in originals):
            raise R010PreexecEnvDenied("credential disguised in helper values")


def scrub_preexec_mapping(
    env: MutableMapping[str, str], expected: R010ExpectedRunnerEnv,
) -> dict[str, str]:
    """Consume and scrub current PREEXEC env BEFORE any product import.

    On invalid input attempt to clear selectors too; the caller must abort.
    This removes mapping entries, NOT Python string heap copies or OS secrets.
    The future tracked entrypoint needs an independently qualified OIDC step
    beforehand, and MUST separately prove no sensitive process inheritance.
    """
    if not isinstance(env, MutableMapping):
        raise R010PreexecEnvDenied("PREEXEC environment not mutable")
    try:
        validate_preexec_mapping(env, expected)
        helper = {key: env[key] for key in _HELPER_KEYS}
    except BaseException:
        try:
            env.clear()
        except Exception:
            pass
        raise
    try:
        env.clear()
        env.update(helper)
    except Exception:
        try:
            env.clear()
        except Exception:
            pass
        raise R010PreexecEnvDenied("cannot irreversibly scrub PREEXEC mapping") from None
    if dict(env) != helper or frozenset(env) != _HELPER_KEYS:
        raise R010PreexecEnvDenied("post-scrub environment mutated")
    return helper.copy()


def _forbidden_name(name: object) -> bool:
    if (type(name) is not str or _ASCII_ENV_NAME.fullmatch(name) is None
            or name in _FORBIDDEN_EXACT or name.startswith(_HARD_DENIED_PREFIXES)
            or name.endswith(_HARD_DENIED_SUFFIXES)):
        return True
    return "TOKEN" in name or "SECRET" in name or "PROXY" in name


def build_closed_product_child_env(
    helper: Mapping[str, str], *,
    requested_extra_names: frozenset[str] = frozenset(),
) -> dict[str, str]:
    """Construct a child env only from an exact scrubbed helper + safe fixed keys.

    Never inherits os.environ, REST/MCP fields, client config, or an arbitrary
    passed name=value override. Cannot spawn/authorize a PRODUCT child.
    """
    if not isinstance(helper, Mapping) or frozenset(helper) != _HELPER_KEYS:
        raise R010PreexecEnvDenied("unreviewed product helper key set")
    expected = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}
    if any(helper.get(k) != v for k, v in expected.items()):
        raise R010PreexecEnvDenied("unsafe product helper base")
    for key in ("HOME", "TMPDIR"):
        v = helper[key]
        if (type(v) is not str or not v.startswith("/") or len(v) > 240
                or "\x00" in v or ".." in v.split("/")):
            raise R010PreexecEnvDenied("invalid private product root")
    if type(requested_extra_names) is not frozenset:
        raise R010PreexecEnvDenied("child extra names must be exact")
    if (not requested_extra_names.issubset(_CHILD_SAFE_EXTRAS)
            or any(_forbidden_name(k) for k in requested_extra_names)):
        raise R010PreexecEnvDenied("forbidden child credential selector")
    child = dict(helper)
    for key in requested_extra_names:
        child[key] = _CHILD_SAFE_EXTRAS[key]
    if (any(_forbidden_name(k) for k in child if k not in _HELPER_KEYS)
            or frozenset(child) != _HELPER_KEYS | requested_extra_names):
        raise R010PreexecEnvDenied("unsafe closed product child environment")
    return child
