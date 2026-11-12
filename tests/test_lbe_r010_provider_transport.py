"""R010 provider/Owner HTTPS transport code under offline SAFE T0 only."""

import base64
import json
import os
import socket
import subprocess
import urllib.request

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
import pytest

from gateway.lbe_r010_provider_transport import (
    R010HttpsSourceDenied, R010GithubOwnerEvidenceReader,
    _ConstrainedHttps, request_r010_provider_oidc_source,
    verify_r010_provider_oidc_original_bytes_source,
)
from gateway.lbe_r010_oidc_verify import R010OIDCExpected

REPO = "chinanjjohn2012/mac-file-gateway"
API = "https://api.github.com/repos/" + REPO
ISSUER = "https://token.actions.githubusercontent.com"
BASE = "https://pipelinesghubeus15.actions.githubusercontent.com/_apis/oidc/token?api-version=2.0"
DESIGN = "f57e39543a6fe3d64fe99b8669fc7da854b93a64"
HEAD = "0ef4671b63617c3a3519087f695cb335c67e9d9d"
TREE = "0b7f3585329b4c679ec2b200803cda762a94ec87"
NOW = 1800000000


@pytest.fixture(autouse=True)
def no_real_network_or_child(monkeypatch):
    def denied(*_a, **_kw):
        raise AssertionError("safe T0 forbids real network/child/signal")
    monkeypatch.setattr(socket.socket, "connect", denied)
    monkeypatch.setattr(subprocess, "Popen", denied)
    monkeypatch.setattr(os, "kill", denied)
    monkeypatch.setattr(os, "killpg", denied, raising=False)


class FakeResponse:
    def __init__(self, url, body, *, code=200, headers=None, redirect=None):
        self._url = url if redirect is None else redirect
        self._body = body
        self.status = code
        self.headers = headers or {}

    def geturl(self):
        return self._url

    def read(self, count):
        return self._body[:count]

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False


class FakeOpener:
    def __init__(self, bodies):
        self.bodies = bodies
        self.calls = []

    def open(self, request, timeout):
        url = request.full_url
        self.calls.append((url, request.headers, timeout))
        value = self.bodies[url]
        return value if isinstance(value, FakeResponse) else FakeResponse(url, value)


@pytest.fixture
def opener(monkeypatch):
    item = FakeOpener({})
    monkeypatch.setattr(urllib.request, "build_opener", lambda *_a: item)
    return item


def expected():
    return R010OIDCExpected(
        implementation_head_sha="a" * 40,
        job_local_secret_sha256="b" * 64, run_id="123",
        run_attempt="1", check_run_id="456",
        workflow_ref=REPO + "/.github/workflows/r010.yml@refs/heads/main",
        workflow_sha="c" * 40, signed_source_sha="a" * 40,
        subject="repo:" + REPO + ":pull_request",
    )


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def signed_jwt(key, ex):
    claims = {
        "iss": ISSUER, "aud": ex.audience, "repository": ex.repository,
        "run_id": ex.run_id, "run_attempt": ex.run_attempt,
        "check_run_id": ex.check_run_id, "workflow_ref": ex.workflow_ref,
        "workflow_sha": ex.workflow_sha, "sha": ex.signed_source_sha,
        "sub": ex.subject, "runner_environment": "github-hosted",
        "iat": NOW - 10, "nbf": NOW - 10, "exp": NOW + 100,
    }
    header = {"alg": "RS256", "typ": "JWT", "kid": "safe-key"}
    signing = (b64(json.dumps(header).encode()) + "." +
               b64(json.dumps(claims).encode())).encode()
    signature = key.sign(signing, padding.PKCS1v15(), hashes.SHA256())
    pub = key.public_key().public_numbers()
    jwks = {"keys": [{"kid": "safe-key", "kty": "RSA", "use": "sig",
                      "alg": "RS256", "n": b64(pub.n.to_bytes(256, "big")),
                      "e": b64(pub.e.to_bytes(3, "big"))}]}
    metadata = {"issuer": ISSUER, "jwks_uri": ISSUER + "/.well-known/jwks"}
    return (signing + b"." + b64(signature).encode("ascii"),
            json.dumps(metadata).encode(), json.dumps(jwks).encode())


def test_prefetched_original_jwt_bytes_verify_after_scrub_without_bearer(
        opener):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ex = expected()
    jwt, metadata, jwks = signed_jwt(key, ex)
    source = verify_r010_provider_oidc_original_bytes_source(
        original_jwt_bytes=jwt,
        issuer_metadata_bytes=metadata,
        issuer_jwks_bytes=jwks,
        expected=ex,
        now_unix=NOW,
    )
    assert source.signature.algorithm == "RS256"
    assert source.original_jwt_sha256 == source.signature.jwt_sha256
    assert source.metadata_sha256 == source.signature.issuer_metadata_sha256
    assert source.jwks_sha256 == source.signature.jwks_sha256
    assert len(source.expected_identity_sha256) == 64
    assert source.expected_identity_sha256 == (
        source.expected_identity_sha256.lower())
    assert source.current_job_independently_verified is False
    assert source.owner_product_t1_grant_verified is False
    assert source.native_launch_allowed is False
    assert opener.calls == []


@pytest.mark.parametrize("field", [
    "jwt", "metadata", "jwks",
])
def test_prefetched_original_source_bytes_drift_denied_without_network(
        opener, field):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ex = expected()
    jwt, metadata, jwks = signed_jwt(key, ex)
    values = {
        "original_jwt_bytes": jwt,
        "issuer_metadata_bytes": metadata,
        "issuer_jwks_bytes": jwks,
        "expected": ex,
        "now_unix": NOW,
    }
    key_name = {
        "jwt": "original_jwt_bytes",
        "metadata": "issuer_metadata_bytes",
        "jwks": "issuer_jwks_bytes",
    }[field]
    values[key_name] = values[key_name] + b"x"
    with pytest.raises(R010HttpsSourceDenied):
        verify_r010_provider_oidc_original_bytes_source(**values)
    assert opener.calls == []


def test_real_https_source_code_is_synthetic_network_only(opener):
    from urllib.parse import quote
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ex = expected()
    jwt, metadata, jwks = signed_jwt(key, ex)
    full_url = BASE + "&audience=" + quote(ex.audience, safe="")
    opener.bodies.update({
        full_url: json.dumps({"value": jwt.decode("ascii")}).encode(),
        ISSUER + "/.well-known/openid-configuration": metadata,
        ISSUER + "/.well-known/jwks": jwks,
    })
    source = request_r010_provider_oidc_source(
        request_base_url=BASE, bearer="synthetic-bearer-only-abc123",
        expected=ex, now_unix=NOW)
    assert source.signature.algorithm == "RS256"
    assert source.signature.checked_check_run_id == ex.check_run_id
    assert source.current_job_independently_verified is False
    assert source.owner_product_t1_grant_verified is False
    assert source.native_launch_allowed is False
    assert len(opener.calls) == 3
    assert opener.calls[0][0] == full_url
    assert opener.calls[0][1].get("Authorization") == (
        "Bearer synthetic-bearer-only-abc123")
    assert "Authorization" not in opener.calls[1][1]
    assert "Authorization" not in opener.calls[2][1]
    assert all(timeout == 8 for _, _, timeout in opener.calls)
    assert "synthetic-bearer" not in repr(source)


@pytest.mark.parametrize("bad", [
    "http://pipelinesghubeus15.actions.githubusercontent.com/_apis/oidc/token?api-version=2.0",
    BASE + "&extra=1",
    BASE.replace("actions.githubusercontent", "evil"),
    BASE.replace("_apis", "_apis%2f"),
])
def test_unqualified_runner_request_is_denied_before_bearer(opener, bad):
    with pytest.raises(R010HttpsSourceDenied):
        request_r010_provider_oidc_source(
            request_base_url=bad, bearer="synthetic-bearer-only-abc123",
            expected=expected(), now_unix=NOW)
    assert opener.calls == []


@pytest.mark.parametrize("mode", [
    "redirect", "moved", "compressed", "location", "size",
])
def test_http_redirect_or_bad_source_never_considered_original(opener, mode):
    tr = _ConstrainedHttps()
    url = API + "/issues/comments/6740275850"
    kw = {}
    if mode == "redirect":
        kw["redirect"] = "https://attacker.invalid/token"
    if mode == "moved":
        kw["code"] = 302
    if mode == "compressed":
        kw["headers"] = {"Content-Encoding": "gzip"}
    if mode == "location":
        kw["headers"] = {"Location": "https://evil.invalid/"}
    opener.bodies[url] = FakeResponse(
        url, b"x" * (90 if mode == "size" else 10), **kw)
    with pytest.raises(R010HttpsSourceDenied):
        tr.get(url, limit=64)
    assert len(opener.calls) == 1


def choice_and_reviews():
    fields = {
        "repo": REPO, "pr": "114",
        "task_id": "MULTI-EXEC-LBE-FIVE-DAY-CANDIDATE-20261105",
        "review_round": "D4-R014-AUTHORITY-CHAIN-DESIGN-013",
        "r010_design_id": "MWE-LBE-R010-AUTHORITY-CHAIN-DESIGN-013-CANDIDATE",
        "r010_design_blob": DESIGN,
        "design_base_sha": "ca90cf30095695479615e475b8440e09f02f34d9",
        "design_head_sha": HEAD, "design_head_tree": TREE,
        "b_r010_design_review_id": "PRR_kwDOU5v3IM8AAAABWtAZjQ",
        "c_r010_design_review_id": "PRR_kwDOU5v3IM8AAAABWtBPMQ",
        "host_option": "A1", "review_sequence_option": "B1",
        "state_domain": "R010_EPHEMERAL_JOB_STATE_V1",
        "risk_marker": "R010_REAFFIRM_R006_RISK1_9_PLUS_RISK10_11",
    }
    body = ("R010_OWNER_DESIGN_CHOICE_V1\n\n" +
            "\n".join(k + ": " + v for k, v in fields.items()) +
            "\n\n## 1. Source only\n"
            "RISK_10 RISK_11 A1 + B1 PRODUCT_T1: NOT_AUTHORIZED\n"
            "FULL_CODE_REVIEW_PASS: NOT_ISSUED\n"
            "INTEGRATION_STATUS: NOT_TESTED R10_STATUS: BLOCKED\n")
    comment = {
        "id": 6740275850,
        "user": {"login": "chinanjjohn2012", "id": 13314291, "type": "User"},
        "author_association": "OWNER", "issue_url": API + "/issues/114",
        "created_at": "2026-11-09T12:39:35Z",
        "updated_at": "2026-11-09T12:39:35Z",
        "body": body,
    }
    reviews = []
    for role in ("STANDARDS_REVIEWER", "SPEC_REVIEWER"):
        node = ("PRR_kwDOU5v3IM8AAAABWtAZjQ" if role == "STANDARDS_REVIEWER"
                else "PRR_kwDOU5v3IM8AAAABWtBPMQ")
        label = ("STANDARDS_REVIEW" if role == "STANDARDS_REVIEWER"
                 else "SPEC_REVIEW")
        content = (
            "GH_HANDOFF_V2 " + label + "\n"
            "ROLE: " + role + "\n"
            "REPO: " + REPO + "\n"
            "REVIEW_ROUND: D4-R014-AUTHORITY-CHAIN-DESIGN-013\n"
            "REVIEWED_BASE_SHA: ca90cf30095695479615e475b8440e09f02f34d9\n"
            "REVIEWED_HEAD_SHA: " + HEAD + "\n"
            "REVIEWED_TREE_SHA: " + TREE + "\n"
            "REVIEW_SCOPE: TARGETED\nREVIEW_PROGRESS: REVIEW_COMPLETE\n"
            "REVIEW_LEVEL: TARGETED_REVIEW_PASS\n"
            "VERDICT: PASS\nEVIDENCE_STATUS: SUFFICIENT\n"
            "CONTRACT_SCOPE: MWE-LBE-R010-AUTHORITY-CHAIN-DESIGN-013-CANDIDATE "
            + DESIGN + "\n"
            + ("INDEPENDENT_READ_ONLY_SOURCE_ONLY " * 30))
        reviews.append({
            "node_id": node, "state": "COMMENTED", "commit_id": HEAD,
            "submitted_at": "2026-11-08T16:01:21Z", "body": content,
        })
    return comment, reviews


def test_current_github_owner_choice_native_api_shape_read_is_not_grant(opener):
    comment, reviews = choice_and_reviews()
    opener.bodies.update({
        API + "/issues/comments/6740275850": json.dumps(comment).encode(),
        API + "/pulls/114/reviews?per_page=100&page=1":
            json.dumps(reviews).encode(),
    })
    reader = R010GithubOwnerEvidenceReader()
    observed = reader.read_design_choice()
    assert observed.choice.options == ("A1", "B1")
    assert observed.native_launch_allowed is False
    assert observed.current_job_independently_verified is False
    assert len(observed.raw_reviews_sha256) == 64
    assert len(opener.calls) == 2
    assert all("Authorization" not in hdrs
               for _, hdrs, _ in opener.calls)


def test_github_api_duplicates_and_incomplete_role_list_denied(opener):
    comment, reviews = choice_and_reviews()
    opener.bodies.update({
        API + "/issues/comments/6740275850": json.dumps(comment).encode(),
        API + "/pulls/114/reviews?per_page=100&page=1":
            json.dumps(reviews).encode(),
    })
    reader = R010GithubOwnerEvidenceReader()
    assert reader.read_design_choice().choice.design_blob == DESIGN
    opener.bodies[API + "/issues/comments/6740275850"] = (
        b'{"id":1,"id":2}')
    with pytest.raises(R010HttpsSourceDenied, match="duplicate"):
        reader.read_design_choice()
    opener.bodies[API + "/issues/comments/6740275850"] = (
        json.dumps(comment).encode())
    opener.bodies[API + "/pulls/114/reviews?per_page=100&page=1"] = (
        json.dumps(reviews[:1]).encode())
    with pytest.raises(R010HttpsSourceDenied):
        reader.read_design_choice()
