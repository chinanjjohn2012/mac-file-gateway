"""R006 current B/C FULL code-review gate for future native admission.

No normal product path calls the network function today. A future separately
authorized bootstrap can fetch the public GitHub PR review list over HTTPS with
no ambient proxy/auth header. This module then requires TWO distinct native
review objects whose node IDs are the exact IDs in the verified owner grant,
both bound to the same Base/Head/Tree and r006, with role-specific FULL PASS.

Logical review independence is not represented as separate human/account
identity; this gate only proves the two required role review objects and their
declared scope/commit binding.
"""
from __future__ import annotations

import json
import re
import ssl
import urllib.error
import urllib.request

from .lbe_owner_grant import D4VerifiedOwnerGrant

_REPO = "chinanjjohn2012/mac-file-gateway"
_PR = 114
_TASK = "MULTI-EXEC-LBE-FIVE-DAY-CANDIDATE-20261105"
_URL = f"https://api.github.com/repos/{_REPO}/pulls/{_PR}/reviews?per_page=100"
_MAX_RESPONSE = 512 * 1024
_TOKEN = object()
_KEY = re.compile(r"([A-Z][A-Z0-9_]*)\s*:\s*(.*)\Z")
_REQUIRED_COMMON = {
    "REPO": _REPO,
    "TASK_ID": _TASK,
    "REVIEW_ROUND": "r006",
    "RULESET_ID": "ICR-V2.0",
    "EVIDENCE_PROFILE_ID": "ETP-V2.0",
    "REVIEW_PROGRESS": "REVIEW_COMPLETE",
    "EVIDENCE_STATUS": "SUFFICIENT",
    "VERDICT": "PASS",
    "REVIEW_SCOPE": "FULL",
    "REVIEW_LEVEL": "ROLE_FULL_SCOPE_PASS",
}


class D4R006ReviewGateDenied(ValueError):
    """Current independent role review evidence is absent or mismatched."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _fields(body: object, header: str) -> dict[str, str]:
    if type(body) is not str or not body.startswith(header + "\n"):
        raise D4R006ReviewGateDenied("wrong GitHub review protocol header")
    result = {}
    for line in body.splitlines()[1:]:
        match = _KEY.fullmatch(line)
        if match is None:
            continue
        key, value = match.groups()
        if key in result:
            raise D4R006ReviewGateDenied("duplicate review protocol field")
        result[key] = value.strip()
    return result


def _one(review: object, *, expected_id: str, role: str,
         header: str, base_sha: str, head_sha: str, tree_sha: str) -> None:
    if type(review) is not dict:
        raise D4R006ReviewGateDenied("GitHub review is not an object")
    if (review.get("node_id") != expected_id
            or review.get("commit_id") != head_sha
            or review.get("state") != "COMMENTED"
            or type(review.get("submitted_at")) is not str
            or not review["submitted_at"]
            or type(review.get("user")) is not dict
            or type(review["user"].get("login")) is not str
            or not review["user"]["login"]
            or review["user"].get("type") != "User"):
        raise D4R006ReviewGateDenied("GitHub review identity/commit mismatch")
    f = _fields(review.get("body"), header)
    for key, value in _REQUIRED_COMMON.items():
        if f.get(key) != value:
            raise D4R006ReviewGateDenied("review field mismatch: " + key)
    if (f.get("ROLE") != role
            or not f.get("PR", "").startswith("#114")
            or f.get("REVIEWED_BASE_SHA") != base_sha
            or f.get("REVIEWED_HEAD_SHA") != head_sha
            or f.get("REVIEWED_TREE_SHA") != tree_sha):
        raise D4R006ReviewGateDenied("review role/snapshot mismatch")


class D4VerifiedReviewPair:
    """Verifier-produced current r006 B/C role FULL PASS pair."""

    __slots__ = ("_b_id", "_c_id", "_base", "_head", "_tree")

    def __init__(self, token, b_id, c_id, base, head, tree):
        if token is not _TOKEN:
            raise D4R006ReviewGateDenied(
                "verified review pair cannot be directly constructed")
        self._b_id = b_id
        self._c_id = c_id
        self._base = base
        self._head = head
        self._tree = tree

    def check_grant(self, grant: object) -> None:
        if type(grant) is not D4VerifiedOwnerGrant:
            raise D4R006ReviewGateDenied("unverified owner grant")
        a = grant.attempt
        if (a.b_code_review_id != self._b_id
                or a.c_code_review_id != self._c_id
                or a.base_sha != self._base or a.head_sha != self._head
                or a.head_tree != self._tree):
            raise D4R006ReviewGateDenied(
                "owner grant and code reviews are not the same snapshot")


def verify_r006_code_review_pair_t0(
    grant: object, api_response: bytes,
) -> D4VerifiedReviewPair:
    if type(grant) is not D4VerifiedOwnerGrant:
        raise D4R006ReviewGateDenied("owner grant must be verified first")
    if type(api_response) is not bytes or not 0 < len(api_response) <= _MAX_RESPONSE:
        raise D4R006ReviewGateDenied("invalid review-list bytes")
    try:
        items = json.loads(api_response.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise D4R006ReviewGateDenied("invalid review-list JSON") from None
    if type(items) is not list or len(items) > 100:
        raise D4R006ReviewGateDenied("review list is incomplete/oversized")
    attempt = grant.attempt
    wanted = (attempt.b_code_review_id, attempt.c_code_review_id)
    if wanted[0] == wanted[1]:
        raise D4R006ReviewGateDenied("Standards and Spec review IDs must differ")
    found = {}
    for item in items:
        if type(item) is dict and item.get("node_id") in wanted:
            node = item["node_id"]
            if node in found:
                raise D4R006ReviewGateDenied("duplicate requested review ID")
            found[node] = item
    if set(found) != set(wanted):
        raise D4R006ReviewGateDenied("required current role reviews not found")
    _one(found[wanted[0]], expected_id=wanted[0],
         role="STANDARDS_REVIEWER", header="GH_HANDOFF_V2 STANDARDS_REVIEW",
         base_sha=attempt.base_sha, head_sha=attempt.head_sha,
         tree_sha=attempt.head_tree)
    _one(found[wanted[1]], expected_id=wanted[1],
         role="SPEC_REVIEWER", header="GH_HANDOFF_V2 SPEC_REVIEW",
         base_sha=attempt.base_sha, head_sha=attempt.head_sha,
         tree_sha=attempt.head_tree)
    return D4VerifiedReviewPair(
        _TOKEN, wanted[0], wanted[1], attempt.base_sha,
        attempt.head_sha, attempt.head_tree)


def fetch_verified_r006_code_reviews(grant: object) -> D4VerifiedReviewPair:
    """Future public GitHub HTTPS read; not invoked by current product path."""
    if type(grant) is not D4VerifiedOwnerGrant:
        raise D4R006ReviewGateDenied("unverified owner grant")
    context = ssl.create_default_context()
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=context),
        _NoRedirect(),
    )
    request = urllib.request.Request(
        _URL, method="GET",
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "mac-file-gateway-r006-review-gate/1",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with opener.open(request, timeout=5) as response:
            if getattr(response, "status", None) != 200 or response.geturl() != _URL:
                raise D4R006ReviewGateDenied("GitHub review-list HTTP identity")
            if not response.headers.get("Content-Type", "").lower().startswith(
                    "application/json"):
                raise D4R006ReviewGateDenied("GitHub review list is not JSON")
            link = response.headers.get("Link", "")
            if 'rel="next"' in link:
                raise D4R006ReviewGateDenied("GitHub review list is paginated")
            raw_length = response.headers.get("Content-Length")
            if raw_length is not None:
                try:
                    length = int(raw_length)
                except ValueError:
                    raise D4R006ReviewGateDenied("invalid review response length") from None
                if not 0 < length <= _MAX_RESPONSE:
                    raise D4R006ReviewGateDenied("review response oversized")
            data = response.read(_MAX_RESPONSE + 1)
            if not 0 < len(data) <= _MAX_RESPONSE:
                raise D4R006ReviewGateDenied("review response empty/oversized")
    except (OSError, urllib.error.URLError, urllib.error.HTTPError):
        raise D4R006ReviewGateDenied("GitHub review transport unavailable") from None
    return verify_r006_code_review_pair_t0(grant, data)
