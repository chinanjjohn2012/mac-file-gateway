"""R006 current run + G05 receipt identity gate (SAFE T0 source).

The owner comment must not authorize whatever Base/Head/Tree/run values an
internal caller happens to pass. This verifier combines:
- a G05 receipt created outside the checkout after exact source admission,
- the public GitHub Actions run object fetched over system TLS/no proxy, and
- the exact already-verified owner grant.

It does not authorize a native child by itself and never accepts REST/MCP body
bytes, headers or ordinary config as execution identity.
"""
from __future__ import annotations

import json
import os
import re
import ssl
import stat
import urllib.error
import urllib.request

from .lbe_owner_grant import D4VerifiedOwnerGrant

_REPO = "chinanjjohn2012/mac-file-gateway"
_PR = 114
_RECEIPT_MARKER = "MFG_G05_R006_RECEIPT_V1"
_SHA40 = re.compile(r"[0-9a-f]{40}\Z")
_SHA64 = re.compile(r"[0-9a-f]{64}\Z")
_MAX_RECEIPT = 2048
_MAX_RESPONSE = 512 * 1024
_TOKEN = object()


class D4R006RuntimeIdentityDenied(ValueError):
    """Current checkout/run identity is absent, stale or mismatched."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class D4VerifiedRuntimeIdentity:
    """Verifier-produced current run identity; not directly constructible."""

    __slots__ = ("_base_sha", "_head_sha", "_head_tree", "_manifest_sha256",
                 "_run_id", "_run_attempt", "_pid")

    def __init__(self, token, *, base_sha, head_sha, head_tree,
                 manifest_sha256, run_id, run_attempt):
        if token is not _TOKEN:
            raise D4R006RuntimeIdentityDenied(
                "runtime identity cannot be directly constructed")
        self._base_sha = base_sha
        self._head_sha = head_sha
        self._head_tree = head_tree
        self._manifest_sha256 = manifest_sha256
        self._run_id = run_id
        self._run_attempt = run_attempt
        self._pid = os.getpid()

    @property
    def base_sha(self): return self._base_sha
    @property
    def head_sha(self): return self._head_sha
    @property
    def head_tree(self): return self._head_tree
    @property
    def manifest_sha256(self): return self._manifest_sha256
    @property
    def run_id(self): return self._run_id
    @property
    def run_attempt(self): return self._run_attempt

    def check_grant(self, grant: object) -> None:
        if os.getpid() != self._pid or type(grant) is not D4VerifiedOwnerGrant:
            raise D4R006RuntimeIdentityDenied("runtime identity process/grant changed")
        a = grant.attempt
        if (a.base_sha != self._base_sha or a.head_sha != self._head_sha
                or a.head_tree != self._head_tree
                or a.manifest_sha256 != self._manifest_sha256
                or a.run_id != self._run_id
                or a.run_attempt != self._run_attempt):
            raise D4R006RuntimeIdentityDenied(
                "owner grant does not bind current checkout/run")


def _strict_json(raw: bytes, max_size: int, label: str):
    if type(raw) is not bytes or not 0 < len(raw) <= max_size:
        raise D4R006RuntimeIdentityDenied("invalid " + label + " bytes")
    def pairs(items):
        out = {}
        for key, value in items:
            if type(key) is not str or key in out:
                raise D4R006RuntimeIdentityDenied(
                    "duplicate/non-string " + label + " field")
            out[key] = value
        return out
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise D4R006RuntimeIdentityDenied("malformed " + label + " JSON") from None


def verify_r006_runtime_identity_t0(
    grant: object, receipt_bytes: bytes, run_api_bytes: bytes, *,
    environ=None,
) -> D4VerifiedRuntimeIdentity:
    """Bind exact G05 checkout + GitHub run object to the owner grant."""
    if type(grant) is not D4VerifiedOwnerGrant:
        raise D4R006RuntimeIdentityDenied("owner grant must be verified first")
    receipt = _strict_json(receipt_bytes, _MAX_RECEIPT, "G05 receipt")
    fields = {"marker", "repo", "pr", "head_sha", "head_tree",
              "manifest_sha256"}
    if type(receipt) is not dict or set(receipt) != fields:
        raise D4R006RuntimeIdentityDenied("G05 receipt schema mismatch")
    if (receipt["marker"] != _RECEIPT_MARKER or receipt["repo"] != _REPO
            or receipt["pr"] != _PR
            or type(receipt["head_sha"]) is not str
            or _SHA40.fullmatch(receipt["head_sha"]) is None
            or type(receipt["head_tree"]) is not str
            or _SHA40.fullmatch(receipt["head_tree"]) is None
            or type(receipt["manifest_sha256"]) is not str
            or _SHA64.fullmatch(receipt["manifest_sha256"]) is None):
        raise D4R006RuntimeIdentityDenied("invalid G05 receipt identity")

    run = _strict_json(run_api_bytes, _MAX_RESPONSE, "GitHub run")
    if type(run) is not dict:
        raise D4R006RuntimeIdentityDenied("GitHub run is not an object")
    a = grant.attempt
    if (run.get("id") != a.run_id or run.get("run_attempt") != a.run_attempt
            or run.get("event") != "pull_request"
            or run.get("head_sha") != a.head_sha
            or run.get("status") != "in_progress"
            or run.get("conclusion") is not None
            or type(run.get("repository")) is not dict
            or run["repository"].get("full_name") != _REPO
            or type(run.get("head_repository")) is not dict
            or run["head_repository"].get("full_name") != _REPO):
        raise D4R006RuntimeIdentityDenied("GitHub run identity/status mismatch")
    prs = run.get("pull_requests")
    if type(prs) is not list or len(prs) != 1 or type(prs[0]) is not dict:
        raise D4R006RuntimeIdentityDenied("GitHub run PR binding missing")
    item = prs[0]
    if (item.get("number") != _PR or type(item.get("head")) is not dict
            or type(item.get("base")) is not dict
            or item["head"].get("sha") != a.head_sha
            or item["base"].get("sha") != a.base_sha):
        raise D4R006RuntimeIdentityDenied("GitHub run Base/Head/PR mismatch")

    env = os.environ if environ is None else environ
    expected = {
        "GITHUB_ACTIONS": "true",
        "GITHUB_EVENT_NAME": "pull_request",
        "GITHUB_REPOSITORY": _REPO,
        "GITHUB_RUN_ID": str(a.run_id),
        "GITHUB_RUN_ATTEMPT": str(a.run_attempt),
        "G05_EXPECTED_HEAD": a.head_sha,
        "RUNNER_ENVIRONMENT": "github-hosted",
        "RUNNER_OS": "macOS",
        "RUNNER_ARCH": "ARM64",
    }
    if any(type(env.get(k)) is not str or env.get(k) != v
           for k, v in expected.items()):
        raise D4R006RuntimeIdentityDenied("local GitHub runner claims mismatch")

    if (receipt["head_sha"] != a.head_sha
            or receipt["head_tree"] != a.head_tree
            or receipt["manifest_sha256"] != a.manifest_sha256):
        raise D4R006RuntimeIdentityDenied("G05 receipt does not match owner grant")
    return D4VerifiedRuntimeIdentity(
        _TOKEN, base_sha=a.base_sha, head_sha=a.head_sha,
        head_tree=a.head_tree, manifest_sha256=a.manifest_sha256,
        run_id=a.run_id, run_attempt=a.run_attempt)


def _read_receipt(path: str) -> bytes:
    if type(path) is not str or not path.startswith("/") or len(path) > 1024:
        raise D4R006RuntimeIdentityDenied("invalid G05 receipt path")
    fd = -1
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_uid != os.getuid()
                or stat.S_IMODE(before.st_mode) != 0o600
                or not 0 < before.st_size <= _MAX_RECEIPT):
            raise D4R006RuntimeIdentityDenied("unsafe G05 receipt file")
        data = os.read(fd, _MAX_RECEIPT + 1)
        after = os.fstat(fd)
        if (len(data) != before.st_size
                or (before.st_dev, before.st_ino, before.st_size,
                    before.st_mtime_ns, before.st_ctime_ns, before.st_mode)
                != (after.st_dev, after.st_ino, after.st_size,
                    after.st_mtime_ns, after.st_ctime_ns, after.st_mode)):
            raise D4R006RuntimeIdentityDenied("G05 receipt changed while reading")
        return data
    except OSError:
        raise D4R006RuntimeIdentityDenied("G05 receipt unavailable") from None
    finally:
        if fd >= 0:
            os.close(fd)


def fetch_verified_r006_runtime_identity(
    grant: object, receipt_path: str,
) -> D4VerifiedRuntimeIdentity:
    """Future service-owned GitHub run read + local exact G05 receipt."""
    if type(grant) is not D4VerifiedOwnerGrant:
        raise D4R006RuntimeIdentityDenied("unverified owner grant")
    receipt = _read_receipt(receipt_path)
    run_id = grant.attempt.run_id
    url = f"https://api.github.com/repos/{_REPO}/actions/runs/{run_id}"
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        _NoRedirect(),
    )
    request = urllib.request.Request(
        url, method="GET",
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "mac-file-gateway-r006-runtime-identity/1",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with opener.open(request, timeout=5) as response:
            if getattr(response, "status", None) != 200 or response.geturl() != url:
                raise D4R006RuntimeIdentityDenied("GitHub run HTTP identity mismatch")
            if not response.headers.get("Content-Type", "").lower().startswith(
                    "application/json"):
                raise D4R006RuntimeIdentityDenied("GitHub run is not JSON")
            data = response.read(_MAX_RESPONSE + 1)
            if not 0 < len(data) <= _MAX_RESPONSE:
                raise D4R006RuntimeIdentityDenied("GitHub run response oversized")
    except (OSError, urllib.error.URLError, urllib.error.HTTPError):
        raise D4R006RuntimeIdentityDenied("GitHub run transport unavailable") from None
    return verify_r006_runtime_identity_t0(
        grant, receipt, data, environ=os.environ)
