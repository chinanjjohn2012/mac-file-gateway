"""Safe T0 for exact current r006 B/C FULL GitHub review pair."""
from datetime import datetime, timezone
import json
import time

import pytest

from gateway.lbe_owner_grant import verify_d4_owner_github_comment_t0
from gateway.lbe_owner_grant_bootstrap import _argv_fingerprint
from gateway.lbe_r006_macos_allowlist import (
    R006_HOST_SOURCE_FINGERPRINT, R006_RUNNER_PROFILE_FINGERPRINT,
)
from gateway.lbe_r006_review_gate import (
    D4R006ReviewGateDenied, D4VerifiedReviewPair,
    verify_r006_code_review_pair_t0,
)

H = "a" * 40
M = "b" * 64
PRODUCT = "d" * 64
NOW = 1794100000
B = "PRR_fullStandardsR006ABC"
C = "PRR_fullSpecR006XYZ"


def _grant(monkeypatch):
    monkeypatch.setattr(time, "time", lambda: NOW)
    created = datetime.fromtimestamp(
        NOW, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    expires = datetime.fromtimestamp(
        NOW + 900, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    argv = ("python", "-m", "pytest", "-q")
    p = {
        "authorization": "PRODUCT_T1_ONE_ATTEMPT_ONLY",
        "risk_acceptance": "R006_NINE_RESIDUAL_RISKS_ACCEPTED",
        "repo": "chinanjjohn2012/mac-file-gateway", "pr": 114,
        "base_sha": H, "head_sha": H, "head_tree": H,
        "manifest_sha256": M,
        "r006_design_blob": "b8d8a1cb32fb7130dfa6d00b37831dfddfaad11c",
        "b_design_review_id": "PRR_kwDOU5v3IM8AAAABWq0I_w",
        "c_design_review_id": "PRR_kwDOU5v3IM8AAAABWq0iKA",
        "b_code_review_id": B, "c_code_review_id": C,
        "github_run_id": 42445537246, "github_run_attempt": 1,
        "image_os": "macos15", "image_version": "20261104.0514.1",
        "os_build": "24H232",
        "source_fingerprint": R006_HOST_SOURCE_FINGERPRINT,
        "runner_fingerprint": R006_RUNNER_PROFILE_FINGERPRINT,
        "product_recipe_fingerprint": PRODUCT,
        "workspace": "a", "cwd": "py-direct", "runner": "direct",
        "requested_argv_sha256": _argv_fingerprint(argv),
        "effective_argv_sha256": _argv_fingerprint(argv),
        "timeout_seconds": 120, "nonce": "c" * 64,
        "expires_at": expires,
    }
    cid = 7712345678
    obj = {
        "id": cid,
        "body": "R006_OWNER_T1_GRANT_V1\n" + json.dumps(
            p, sort_keys=True, separators=(",", ":")),
        "html_url": (
            "https://github.com/chinanjjohn2012/mac-file-gateway/pull/114"
            f"#issuecomment-{cid}"),
        "issue_url": (
            "https://api.github.com/repos/chinanjjohn2012/mac-file-gateway/issues/114"),
        "created_at": created, "updated_at": created,
        "author_association": "OWNER",
        "user": {"login": "chinanjjohn2012", "type": "User"},
        "performed_via_github_app": None,
    }
    return verify_d4_owner_github_comment_t0(
        json.dumps(obj, separators=(",", ":")).encode())


def _body(role, header):
    return "\n".join([
        header,
        "ROLE: " + role,
        "REPO: chinanjjohn2012/mac-file-gateway",
        "PR: #114 OPEN/DRAFT",
        "TASK_ID: MULTI-EXEC-LBE-FIVE-DAY-CANDIDATE-20261105",
        "REVIEW_ROUND: r006",
        "REVIEWED_BASE_SHA: " + H,
        "REVIEWED_HEAD_SHA: " + H,
        "REVIEWED_TREE_SHA: " + H,
        "RULESET_ID: ICR-V2.0",
        "EVIDENCE_PROFILE_ID: ETP-V2.0",
        "REVIEW_PROGRESS: REVIEW_COMPLETE",
        "EVIDENCE_STATUS: SUFFICIENT",
        "VERDICT: PASS",
        "REVIEW_SCOPE: FULL",
        "REVIEW_LEVEL: ROLE_FULL_SCOPE_PASS",
        "INTEGRATION_STATUS: NOT_TESTED",
        "R10_STATUS: BLOCKED",
    ])


def _reviews():
    return [
        {
            "node_id": B, "commit_id": H, "state": "COMMENTED",
            "submitted_at": "2026-11-08T05:30:00Z",
            "user": {"login": "review-account", "type": "User"},
            "body": _body(
                "STANDARDS_REVIEWER", "GH_HANDOFF_V2 STANDARDS_REVIEW"),
        },
        {
            "node_id": C, "commit_id": H, "state": "COMMENTED",
            "submitted_at": "2026-11-08T05:31:00Z",
            "user": {"login": "review-account", "type": "User"},
            "body": _body("SPEC_REVIEWER", "GH_HANDOFF_V2 SPEC_REVIEW"),
        },
    ]


def _verify(monkeypatch, reviews=None):
    grant = _grant(monkeypatch)
    pair = verify_r006_code_review_pair_t0(
        grant, json.dumps(_reviews() if reviews is None else reviews).encode())
    return grant, pair


def test_exact_two_role_full_reviews_match_owner_grant(monkeypatch):
    grant, pair = _verify(monkeypatch)
    assert type(pair) is D4VerifiedReviewPair
    pair.check_grant(grant)


@pytest.mark.parametrize("mutation", [
    "missing_spec", "duplicate_b", "wrong_commit", "wrong_head",
    "wrong_tree", "wrong_base", "wrong_role", "wrong_scope",
    "wrong_level", "wrong_evidence", "wrong_verdict", "wrong_round",
])
def test_review_pair_fails_closed(monkeypatch, mutation):
    rows = _reviews()
    if mutation == "missing_spec":
        rows.pop()
    elif mutation == "duplicate_b":
        rows.append(dict(rows[0]))
    elif mutation == "wrong_commit":
        rows[0]["commit_id"] = "e" * 40
    else:
        key_map = {
            "wrong_head": ("REVIEWED_HEAD_SHA", "e" * 40),
            "wrong_tree": ("REVIEWED_TREE_SHA", "e" * 40),
            "wrong_base": ("REVIEWED_BASE_SHA", "e" * 40),
            "wrong_role": ("ROLE", "SPEC_REVIEWER"),
            "wrong_scope": ("REVIEW_SCOPE", "TARGETED"),
            "wrong_level": ("REVIEW_LEVEL", "TARGETED_REVIEW_PASS"),
            "wrong_evidence": ("EVIDENCE_STATUS", "INSUFFICIENT"),
            "wrong_verdict": ("VERDICT", "CONDITIONAL"),
            "wrong_round": ("REVIEW_ROUND", "r005"),
        }
        key, value = key_map[mutation]
        old = next(line for line in rows[0]["body"].splitlines()
                   if line.startswith(key + ":"))
        rows[0]["body"] = rows[0]["body"].replace(
            old, key + ": " + value)
    with pytest.raises(D4R006ReviewGateDenied):
        _verify(monkeypatch, rows)


def test_pair_cannot_be_directly_constructed():
    with pytest.raises(D4R006ReviewGateDenied):
        D4VerifiedReviewPair(object(), B, C, H, H, H)
