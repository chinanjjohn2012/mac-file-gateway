"""R006 owner exact-attempt grant parser (SAFE T0, no network, no Popen).

This validates a canonical GitHub PR issue-comment *response* supplied by a
future trusted bootstrap. It does not fetch GitHub, authenticate TLS, create
comments, or make a public/client token authoritative. The returned class
cannot be directly constructed without this module's verifier token.

A future executable path still must independently fetch this exact comment
through an authenticated service-owned channel, qualify current runner/source,
check the grant against the live plan, then atomically consume its nonce in the
durable journal before reservation/Worker/Popen.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from datetime import datetime, timezone

from .lbe_durable_attempt import D4AttemptIdentity
from .lbe_r006_macos_allowlist import (
    IMAGE_VERSION, OS_BUILD,
    R006_HOST_SOURCE_FINGERPRINT, R006_RUNNER_PROFILE_FINGERPRINT,
)

_REPO = "chinanjjohn2012/mac-file-gateway"
_PR = 114
_OWNER = "chinanjjohn2012"
_R006 = "b8d8a1cb32fb7130dfa6d00b37831dfddfaad11c"
_B_DESIGN = "PRR_kwDOU5v3IM8AAAABWq0I_w"
_C_DESIGN = "PRR_kwDOU5v3IM8AAAABWq0iKA"
_MARKER = "R006_OWNER_T1_GRANT_V1"
_AUTH = "PRODUCT_T1_ONE_ATTEMPT_ONLY"
_RISK = "R006_NINE_RESIDUAL_RISKS_ACCEPTED"
_SHA40 = re.compile(r"[0-9a-f]{40}\Z")
_SHA64 = re.compile(r"[0-9a-f]{64}\Z")
_REVIEW = re.compile(r"PRR_[A-Za-z0-9_-]{8,120}\Z")
_WORKSPACE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_RUNNER = re.compile(r"(?:direct|pipenv)\Z")
_IMAGE = re.compile(r"[0-9]{8}\.[0-9]{4}\.[0-9]+\Z")
_OS_BUILD = re.compile(r"[A-Za-z0-9][A-Za-z0-9._() -]{1,119}\Z")
_GRANT_TOKEN = object()
_MAX_BODY = 8192
_MAX_GRANT_SECONDS = 1800

_FIELDS = (
    "authorization", "risk_acceptance", "repo", "pr", "base_sha", "head_sha",
    "head_tree", "manifest_sha256", "r006_design_blob", "b_design_review_id",
    "c_design_review_id", "b_code_review_id", "c_code_review_id",
    "github_run_id", "github_run_attempt", "image_os", "image_version",
    "os_build", "source_fingerprint", "runner_fingerprint",
    "product_recipe_fingerprint", "workspace", "cwd",
    "runner", "requested_argv_sha256", "effective_argv_sha256",
    "timeout_seconds", "nonce", "expires_at",
)


class D4OwnerGrantDenied(ValueError):
    """Owner grant evidence is malformed, stale, ambiguous or untrusted."""


def _strict_pairs(pairs):
    result = {}
    for key, value in pairs:
        if type(key) is not str or key in result:
            raise D4OwnerGrantDenied("duplicate or non-string JSON key")
        result[key] = value
    return result


def _parse_time(value: object) -> int:
    if type(value) is not str or len(value) != 20 or not value.endswith("Z"):
        raise D4OwnerGrantDenied("grant time must be canonical UTC seconds")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc)
    except ValueError:
        raise D4OwnerGrantDenied("invalid grant timestamp") from None
    return int(parsed.timestamp())


def _sha(value: object, length: int, label: str) -> str:
    pattern = _SHA40 if length == 40 else _SHA64
    if type(value) is not str or pattern.fullmatch(value) is None:
        raise D4OwnerGrantDenied("invalid " + label)
    return value


def _positive_int(value: object, label: str) -> int:
    if type(value) is not int or not 1 <= value <= 2**63 - 1:
        raise D4OwnerGrantDenied("invalid " + label)
    return value


def _canonical_payload(body: object) -> dict:
    if type(body) is not str or not 0 < len(body) <= _MAX_BODY:
        raise D4OwnerGrantDenied("missing or oversized grant body")
    prefix = _MARKER + "\n"
    if not body.startswith(prefix) or "\r" in body:
        raise D4OwnerGrantDenied("wrong grant marker or newline form")
    raw = body[len(prefix):]
    try:
        payload = json.loads(raw, object_pairs_hook=_strict_pairs)
    except (json.JSONDecodeError, UnicodeError):
        raise D4OwnerGrantDenied("malformed canonical grant JSON") from None
    if type(payload) is not dict or tuple(sorted(payload)) != tuple(sorted(_FIELDS)):
        raise D4OwnerGrantDenied("grant fields mismatch")
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True)
    if raw != canonical:
        raise D4OwnerGrantDenied("grant body is not canonical JSON")
    return payload


class D4VerifiedOwnerGrant:
    """Verifier-produced exact owner decision; not directly constructible."""

    __slots__ = ("_attempt", "_grant_digest", "_created_at_unix")

    def __init__(self, token, attempt: D4AttemptIdentity, grant_digest: str,
                 created_at_unix: int):
        if token is not _GRANT_TOKEN:
            raise D4OwnerGrantDenied("verified grant cannot be directly constructed")
        self._attempt = attempt
        self._grant_digest = grant_digest
        self._created_at_unix = created_at_unix

    @property
    def attempt(self) -> D4AttemptIdentity:
        return self._attempt

    @property
    def grant_digest(self) -> str:
        return self._grant_digest


def verify_d4_owner_github_comment_t0(api_response: bytes) -> D4VerifiedOwnerGrant:
    """Validate exact owner/comment/body semantics, without any network call.

    The caller MUST be a future trusted bootstrap that authenticated the GitHub
    API response; arbitrary REST/MCP request bytes are never sufficient runtime
    authority. This parser deliberately cannot prove that transport property.
    """
    if type(api_response) is not bytes or not 0 < len(api_response) <= 65536:
        raise D4OwnerGrantDenied("invalid GitHub comment response bytes")
    try:
        response = json.loads(api_response.decode("utf-8"),
                              object_pairs_hook=_strict_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise D4OwnerGrantDenied("invalid GitHub comment JSON") from None
    if type(response) is not dict:
        raise D4OwnerGrantDenied("invalid GitHub comment object")
    for field in ("id", "body", "html_url", "issue_url", "created_at",
                  "updated_at", "author_association", "user"):
        if field not in response:
            raise D4OwnerGrantDenied("GitHub comment field missing: " + field)

    comment_id = _positive_int(response["id"], "owner comment id")
    if (response["author_association"] != "OWNER"
            or type(response["user"]) is not dict
            or response["user"].get("login") != _OWNER
            or response["user"].get("type") != "User"
            or response.get("performed_via_github_app") is not None):
        raise D4OwnerGrantDenied("comment is not direct repository-owner evidence")
    expected_html = (
        f"https://github.com/{_REPO}/pull/{_PR}#issuecomment-{comment_id}")
    expected_issue = f"https://api.github.com/repos/{_REPO}/issues/{_PR}"
    if response["html_url"] != expected_html or response["issue_url"] != expected_issue:
        raise D4OwnerGrantDenied("owner comment belongs to wrong repository/PR")
    if response["created_at"] != response["updated_at"]:
        raise D4OwnerGrantDenied("edited owner grants are not accepted")
    created = _parse_time(response["created_at"])

    p = _canonical_payload(response["body"])
    if p["authorization"] != _AUTH or p["risk_acceptance"] != _RISK:
        raise D4OwnerGrantDenied("wrong owner authorization/risk scope")
    if p["repo"] != _REPO or p["pr"] != _PR:
        raise D4OwnerGrantDenied("wrong repository/PR binding")
    if p["r006_design_blob"] != _R006:
        raise D4OwnerGrantDenied("wrong R006 design binding")
    if p["b_design_review_id"] != _B_DESIGN or p["c_design_review_id"] != _C_DESIGN:
        raise D4OwnerGrantDenied("wrong R006 design review binding")
    for field in ("b_code_review_id", "c_code_review_id"):
        if type(p[field]) is not str or _REVIEW.fullmatch(p[field]) is None:
            raise D4OwnerGrantDenied("missing current code review binding")
    for field in ("base_sha", "head_sha", "head_tree"):
        _sha(p[field], 40, field)
    for field in ("manifest_sha256", "source_fingerprint",
                  "runner_fingerprint", "product_recipe_fingerprint",
                  "requested_argv_sha256",
                  "effective_argv_sha256", "nonce"):
        _sha(p[field], 64, field)
    run_id = _positive_int(p["github_run_id"], "GitHub run id")
    run_attempt = _positive_int(p["github_run_attempt"], "GitHub run attempt")
    timeout = _positive_int(p["timeout_seconds"], "timeout")
    if timeout > 120:
        raise D4OwnerGrantDenied("timeout exceeds R006 original-child ceiling")
    if (p["image_os"] != "macos15" or p["image_version"] != IMAGE_VERSION
            or type(p["image_version"]) is not str
            or _IMAGE.fullmatch(p["image_version"]) is None):
        raise D4OwnerGrantDenied("unqualified macOS image")
    if (p["os_build"] != OS_BUILD or type(p["os_build"]) is not str
            or _OS_BUILD.fullmatch(p["os_build"]) is None):
        raise D4OwnerGrantDenied("unqualified macOS build")
    if (p["source_fingerprint"] != R006_HOST_SOURCE_FINGERPRINT
            or p["runner_fingerprint"] != R006_RUNNER_PROFILE_FINGERPRINT):
        raise D4OwnerGrantDenied("owner grant uses wrong fixed host/source profile")
    if type(p["workspace"]) is not str or _WORKSPACE.fullmatch(p["workspace"]) is None:
        raise D4OwnerGrantDenied("invalid Workspace")
    if (type(p["cwd"]) is not str or not p["cwd"] or len(p["cwd"]) > 240
            or p["cwd"].startswith("/") or ".." in p["cwd"].split("/")):
        raise D4OwnerGrantDenied("invalid grant cwd")
    if type(p["runner"]) is not str or _RUNNER.fullmatch(p["runner"]) is None:
        raise D4OwnerGrantDenied("invalid runner")

    expires = _parse_time(p["expires_at"])
    now = int(time.time())
    if not created <= now <= expires or not 1 <= expires - created <= _MAX_GRANT_SECONDS:
        raise D4OwnerGrantDenied("owner grant is stale, future-dated or overlong")

    attempt = D4AttemptIdentity(
        nonce=p["nonce"], run_id=run_id, run_attempt=run_attempt,
        repo=p["repo"], pr=p["pr"], base_sha=p["base_sha"],
        head_sha=p["head_sha"], head_tree=p["head_tree"],
        manifest_sha256=p["manifest_sha256"],
        r006_design_blob=p["r006_design_blob"],
        b_design_review_id=p["b_design_review_id"],
        c_design_review_id=p["c_design_review_id"],
        b_code_review_id=p["b_code_review_id"],
        c_code_review_id=p["c_code_review_id"],
        image_version=p["image_version"], os_build=p["os_build"],
        source_fingerprint=p["source_fingerprint"],
        runner_fingerprint=p["runner_fingerprint"],
        product_recipe_fingerprint=p["product_recipe_fingerprint"],
        workspace=p["workspace"], cwd=p["cwd"], runner=p["runner"],
        requested_argv_fingerprint=p["requested_argv_sha256"],
        effective_argv_fingerprint=p["effective_argv_sha256"],
        timeout_seconds=timeout, owner_comment_id=comment_id,
        expires_at_unix=expires,
    ).checked()
    digest = hashlib.sha256(api_response).hexdigest()
    return D4VerifiedOwnerGrant(_GRANT_TOKEN, attempt, digest, created)
