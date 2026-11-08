"""Safe T0 owner-grant format and service admission binding; no network/child."""
import json
from dataclasses import replace
from datetime import datetime, timezone
import time

import pytest

from gateway.lbe_owner_grant import (
    D4OwnerGrantDenied, D4VerifiedOwnerGrant,
    verify_d4_owner_github_comment_t0,
)
from gateway.lbe_r006_macos_allowlist import (
    R006_HOST_SOURCE_FINGERPRINT, R006_RUNNER_PROFILE_FINGERPRINT,
)

B = "PRR_kwDOU5v3IM8AAAABWq0I_w"
C = "PRR_kwDOU5v3IM8AAAABWq0iKA"
R006 = "b8d8a1cb32fb7130dfa6d00b37831dfddfaad11c"
H = "a" * 40
S = "b" * 64


def payload(now):
    expiry = datetime.fromtimestamp(now + 900, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "authorization": "PRODUCT_T1_ONE_ATTEMPT_ONLY",
        "risk_acceptance": "R006_NINE_RESIDUAL_RISKS_ACCEPTED",
        "repo": "chinanjjohn2012/mac-file-gateway", "pr": 114,
        "base_sha": H, "head_sha": H, "head_tree": H,
        "manifest_sha256": S, "r006_design_blob": R006,
        "b_design_review_id": B, "c_design_review_id": C,
        "b_code_review_id": "PRR_currentStandards123",
        "c_code_review_id": "PRR_currentSpecReview123",
        "github_run_id": 42445537246, "github_run_attempt": 1,
        "image_os": "macos15", "image_version": "20261104.0514.1",
        "os_build": "24H232",
        "source_fingerprint": R006_HOST_SOURCE_FINGERPRINT,
        "runner_fingerprint": R006_RUNNER_PROFILE_FINGERPRINT,
        "product_recipe_fingerprint": "d" * 64,
        "workspace": "a", "cwd": "py-direct",
        "runner": "direct", "requested_argv_sha256": S,
        "effective_argv_sha256": S, "timeout_seconds": 120,
        "nonce": "c" * 64, "expires_at": expiry,
    }


def response(now, changes=None):
    p = payload(now)
    if changes:
        p.update(changes)
    created = datetime.fromtimestamp(now, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    cid = 7712345678
    body = "R006_OWNER_T1_GRANT_V1\n" + json.dumps(
        p, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    obj = {
        "id": cid, "body": body,
        "html_url": f"https://github.com/chinanjjohn2012/mac-file-gateway/pull/114#issuecomment-{cid}",
        "issue_url": "https://api.github.com/repos/chinanjjohn2012/mac-file-gateway/issues/114",
        "created_at": created, "updated_at": created,
        "author_association": "OWNER",
        "user": {"login": "chinanjjohn2012", "type": "User"},
        "performed_via_github_app": None,
    }
    return obj


def encode(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def test_exact_owner_comment_yields_nonconstructible_verified_grant(monkeypatch):
    now = 1794100000
    monkeypatch.setattr(time, "time", lambda: now)
    grant = verify_d4_owner_github_comment_t0(encode(response(now)))
    assert type(grant) is D4VerifiedOwnerGrant
    assert grant.attempt.r006_design_blob == R006
    assert grant.attempt.owner_comment_id == 7712345678
    assert grant.attempt.timeout_seconds == 120
    with pytest.raises(D4OwnerGrantDenied):
        D4VerifiedOwnerGrant(object(), grant.attempt, S, now)


@pytest.mark.parametrize("mutate", [
    lambda o: o.update(author_association="MEMBER"),
    lambda o: o["user"].update(login="attacker"),
    lambda o: o["user"].update(type="Bot"),
    lambda o: o.update(updated_at="2026-11-08T05:00:01Z"),
    lambda o: o.update(html_url="https://github.com/other/repo/pull/114#issuecomment-7712345678"),
    lambda o: o.update(issue_url="https://api.github.com/repos/other/repo/issues/114"),
    lambda o: o.update(performed_via_github_app={"id": 1}),
])
def test_non_owner_or_ambiguous_comment_denied(monkeypatch, mutate):
    now = 1794100000
    monkeypatch.setattr(time, "time", lambda: now)
    obj = response(now)
    mutate(obj)
    with pytest.raises(D4OwnerGrantDenied):
        verify_d4_owner_github_comment_t0(encode(obj))


@pytest.mark.parametrize("changes", [
    {"authorization": "SOURCE_TOOLCHAIN_T1"},
    {"risk_acceptance": "NONE"},
    {"repo": "other/repo"}, {"pr": 115},
    {"r006_design_blob": H}, {"b_design_review_id": "PRR_wrongwrong"},
    {"c_design_review_id": "PRR_wrongwrong"},
    {"b_code_review_id": "missing"}, {"c_code_review_id": "missing"},
    {"github_run_id": 0}, {"github_run_attempt": 0},
    {"image_os": "macos26"}, {"image_version": "unknown"},
    {"os_build": ""}, {"workspace": "../escape"}, {"cwd": "../outside"},
    {"runner": "shell"}, {"timeout_seconds": 121}, {"nonce": "bad"},
    {"product_recipe_fingerprint": "bad"},
])
def test_grant_binding_fields_fail_closed(monkeypatch, changes):
    now = 1794100000
    monkeypatch.setattr(time, "time", lambda: now)
    with pytest.raises(D4OwnerGrantDenied):
        verify_d4_owner_github_comment_t0(encode(response(now, changes)))


def test_expired_future_and_noncanonical_body_denied(monkeypatch):
    now = 1794100000
    monkeypatch.setattr(time, "time", lambda: now)
    old = response(now - 4000)
    with pytest.raises(D4OwnerGrantDenied):
        verify_d4_owner_github_comment_t0(encode(old))
    future = response(now + 60)
    with pytest.raises(D4OwnerGrantDenied):
        verify_d4_owner_github_comment_t0(encode(future))
    obj = response(now)
    obj["body"] = obj["body"].replace('"authorization":', '"authorization" : ', 1)
    with pytest.raises(D4OwnerGrantDenied):
        verify_d4_owner_github_comment_t0(encode(obj))
