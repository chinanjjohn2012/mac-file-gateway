"""R010 stdlib-only pre-product-import environment scrub gate.

This module is deliberately isolated from the rest of gateway.  A future
tracked PREEXEC entrypoint may import this one module, validate and destroy
the current Job credential selectors, and only then import product modules.

The receipt is source/T0 evidence only.  It never authenticates GitHub,
Owner authority, a native child, or PRODUCT_T1.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
import json
import os
import re
import sys
from urllib.parse import urlsplit


_BOOTSTRAP_KEYS = frozenset({
    "PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "GITHUB_ACTIONS",
    "GITHUB_EVENT_NAME", "GITHUB_REPOSITORY", "GITHUB_RUN_ID",
    "GITHUB_RUN_ATTEMPT", "GITHUB_JOB", "G05_EXPECTED_HEAD",
    "RUNNER_ENVIRONMENT", "RUNNER_OS", "RUNNER_ARCH", "ImageOS",
    "ImageVersion", "SSH_AUTH_SOCK", "ACTIONS_ID_TOKEN_REQUEST_URL",
    "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
})
_HELPER_KEYS = ("HOME", "LANG", "LC_ALL", "PATH", "TMPDIR")
_HELPER_SET = frozenset(_HELPER_KEYS)
_RUN_ID = re.compile(r"[1-9][0-9]{0,17}\Z", re.ASCII)
_RUN_ATTEMPT = re.compile(r"[1-9][0-9]{0,11}\Z", re.ASCII)
_SHA40 = re.compile(r"[0-9a-f]{40}\Z", re.ASCII)
_JOB = re.compile(r"[A-Za-z0-9_.-]{1,80}\Z", re.ASCII)
_ID_TOKEN_HOST = re.compile(
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.actions\.githubusercontent\.com\Z",
    re.ASCII,
)


class R010PreimportScrubDenied(ValueError):
    """The process was not eligible to cross the pre-product import boundary."""


@dataclass(frozen=True, slots=True)
class R010PreimportExpected:
    run_id: str
    run_attempt: str
    head_sha: str
    job_name: str
    image_version: str
    private_home: str
    private_tmp: str

    def checked(self) -> "R010PreimportExpected":
        if (type(self.run_id) is not str
                or _RUN_ID.fullmatch(self.run_id) is None
                or type(self.run_attempt) is not str
                or _RUN_ATTEMPT.fullmatch(self.run_attempt) is None
                or type(self.head_sha) is not str
                or _SHA40.fullmatch(self.head_sha) is None
                or type(self.job_name) is not str
                or _JOB.fullmatch(self.job_name) is None
                or self.image_version != "20261104.0514.1"):
            raise R010PreimportScrubDenied("unqualified current Job identity")
        for value in (self.private_home, self.private_tmp):
            if (type(value) is not str or not value.startswith("/")
                    or len(value) > 240 or "\x00" in value
                    or ".." in value.split("/")
                    or any(ord(ch) < 33 or ord(ch) > 126 for ch in value)):
                raise R010PreimportScrubDenied("unqualified private helper root")
        return self


@dataclass(frozen=True, slots=True)
class R010PreimportScrubReceipt:
    head_sha: str
    run_id: str
    run_attempt: str
    job_name: str
    helper_keys: tuple[str, ...]
    helper_env_sha256: str
    selectors_scrubbed: bool
    product_modules_absent_before_scrub: bool
    source_original_os: bool
    status: str = "PREIMPORT_STDLIB_SCRUBBED_SOURCE_ONLY_NO_T1"
    native_launch_allowed: bool = False

    @property
    def receipt_sha256(self) -> str:
        raw = json.dumps({
            "version": "R010_PREIMPORT_SCRUB_RECEIPT_V1",
            "head_sha": self.head_sha,
            "run_id": self.run_id,
            "run_attempt": self.run_attempt,
            "job_name": self.job_name,
            "helper_keys": list(self.helper_keys),
            "helper_env_sha256": self.helper_env_sha256,
            "selectors_scrubbed": self.selectors_scrubbed,
            "product_modules_absent_before_scrub":
                self.product_modules_absent_before_scrub,
            "source_original_os": self.source_original_os,
            "status": self.status,
            "native_launch_allowed": self.native_launch_allowed,
        }, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        return hashlib.sha256(raw).hexdigest()


def _reviewed_oidc_base(raw_url: str) -> None:
    if (type(raw_url) is not str or not 1 <= len(raw_url) <= 4096
            or any(ord(ch) < 33 or ord(ch) > 126 for ch in raw_url)
            or "\\" in raw_url):
        raise R010PreimportScrubDenied("unqualified runner OIDC endpoint")
    try:
        url = urlsplit(raw_url)
        host = url.hostname
        port = url.port
    except ValueError:
        raise R010PreimportScrubDenied("malformed runner OIDC endpoint") from None
    if (url.scheme != "https" or host is None
            or _ID_TOKEN_HOST.fullmatch(host) is None
            or url.username is not None or url.password is not None
            or port is not None or url.fragment
            or url.path != "/_apis/oidc/token"
            or url.query != "api-version=2.0"
            or raw_url != (
                "https://" + host + "/_apis/oidc/token?api-version=2.0")):
        raise R010PreimportScrubDenied("unreviewed runner OIDC endpoint")


def _expected_values(expected: R010PreimportExpected) -> dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": expected.private_home,
        "TMPDIR": expected.private_tmp,
        "LANG": "C",
        "LC_ALL": "C",
        "GITHUB_ACTIONS": "true",
        "GITHUB_EVENT_NAME": "pull_request",
        "GITHUB_REPOSITORY": "chinanjjohn2012/mac-file-gateway",
        "GITHUB_RUN_ID": expected.run_id,
        "GITHUB_RUN_ATTEMPT": expected.run_attempt,
        "GITHUB_JOB": expected.job_name,
        "G05_EXPECTED_HEAD": expected.head_sha,
        "RUNNER_ENVIRONMENT": "github-hosted",
        "RUNNER_OS": "macOS",
        "RUNNER_ARCH": "ARM64",
        "ImageOS": "macos15",
        "ImageVersion": expected.image_version,
    }


def _product_modules_loaded() -> tuple[str, ...]:
    allowed = frozenset({"gateway", "gateway.lbe_r010_preimport_gate"})
    return tuple(sorted(
        name for name in sys.modules
        if name.startswith("gateway") and name not in allowed))


def _validate_bootstrap(
    env: Mapping[str, str], expected: R010PreimportExpected,
) -> None:
    expected.checked()
    if frozenset(env) != _BOOTSTRAP_KEYS:
        raise R010PreimportScrubDenied("PREEXEC inherited extra/missing keys")
    if any(type(k) is not str or type(v) is not str for k, v in env.items()):
        raise R010PreimportScrubDenied("non-string PREEXEC environment")
    for key, value in _expected_values(expected).items():
        if env.get(key) != value:
            raise R010PreimportScrubDenied("bootstrap differs from current Job")
    selector = env["SSH_AUTH_SOCK"]
    if (not selector.startswith("/") or len(selector) > 4096
            or "\x00" in selector or ".." in selector.split("/")
            or any(ord(ch) < 33 or ord(ch) > 126 for ch in selector)):
        raise R010PreimportScrubDenied("noncanonical SSH selector")
    token = env["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]
    if (not 16 <= len(token) <= 8192
            or any(ord(ch) < 33 or ord(ch) > 126 for ch in token)):
        raise R010PreimportScrubDenied("unqualified runner OIDC bearer")
    _reviewed_oidc_base(env["ACTIONS_ID_TOKEN_REQUEST_URL"])
    originals = (
        selector, token, env["ACTIONS_ID_TOKEN_REQUEST_URL"],
    )
    for key in _HELPER_SET:
        if any(secret in env[key] for secret in originals):
            raise R010PreimportScrubDenied("credential disguised in helper value")


def scrub_r010_preimport_environment(
    *, expected: R010PreimportExpected,
) -> R010PreimportScrubReceipt:
    """Scrub the actual process environment before any gateway product import."""
    try:
        if type(expected) is not R010PreimportExpected:
            raise R010PreimportScrubDenied("wrong expected Job type")
        loaded = _product_modules_loaded()
        if loaded:
            raise R010PreimportScrubDenied(
                "gateway product module loaded before PREEXEC scrub")
        _validate_bootstrap(os.environ, expected)
        helper = {key: os.environ[key] for key in _HELPER_SET}
        os.environ.clear()
        os.environ.update(helper)
        if (frozenset(os.environ) != _HELPER_SET
                or dict(os.environ) != helper
                or _product_modules_loaded()):
            raise R010PreimportScrubDenied("post-scrub process boundary drift")
        raw = json.dumps(
            helper, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True).encode("ascii")
        return R010PreimportScrubReceipt(
            head_sha=expected.head_sha,
            run_id=expected.run_id,
            run_attempt=expected.run_attempt,
            job_name=expected.job_name,
            helper_keys=tuple(sorted(helper)),
            helper_env_sha256=hashlib.sha256(raw).hexdigest(),
            selectors_scrubbed=True,
            product_modules_absent_before_scrub=True,
            source_original_os=True,
        )
    except R010PreimportScrubDenied:
        # Preserve only this module's fixed, reviewed denial classes after
        # destroying the process environment.  These messages never contain
        # selector values, paths from the caller, JWT bytes or response data.
        try:
            os.environ.clear()
        except BaseException:
            pass
        raise
    except BaseException:
        try:
            os.environ.clear()
        except BaseException:
            pass
        raise R010PreimportScrubDenied(
            "R010 pre-product import scrub failed closed") from None


def validate_r010_preimport_receipt_source(
    receipt: R010PreimportScrubReceipt, *,
    head_sha: str, run_id: str, run_attempt: str, job_name: str,
    helper_keys: tuple[str, ...], helper_env_sha256: str,
) -> None:
    """Bind a source receipt to later same-Job data without granting T1."""
    if (type(receipt) is not R010PreimportScrubReceipt
            or receipt.status != "PREIMPORT_STDLIB_SCRUBBED_SOURCE_ONLY_NO_T1"
            or receipt.native_launch_allowed is not False
            or receipt.selectors_scrubbed is not True
            or receipt.product_modules_absent_before_scrub is not True
            or receipt.head_sha != head_sha
            or receipt.run_id != run_id
            or receipt.run_attempt != run_attempt
            or receipt.job_name != job_name
            or receipt.helper_keys != helper_keys
            or receipt.helper_env_sha256 != helper_env_sha256
            or not re.fullmatch(r"[0-9a-f]{64}", receipt.helper_env_sha256)
            or not re.fullmatch(r"[0-9a-f]{64}", receipt.receipt_sha256)):
        raise R010PreimportScrubDenied(
            "pre-import scrub receipt does not match same Job/helper source")
