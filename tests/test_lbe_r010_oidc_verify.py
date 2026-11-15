"""R010 cryptographic original-JWT verification with synthetic RSA, SAFE T0."""
import base64
from dataclasses import replace
import json
import os
import socket
import subprocess

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
import pytest

from gateway.lbe_r010_oidc_verify import (
    R010OIDCDenied, R010OIDCExpected,
    verify_r010_oidc_original_bytes_offline,
    require_r010_oidc_offline_fresh_at,
)

NOW = 1800000000
ISSUER = "https://token.actions.githubusercontent.com"


@pytest.fixture(autouse=True)
def never_spawn_or_connect(monkeypatch):
    def denied(*args, **kwargs):
        raise AssertionError("SAFE T0 must not spawn, signal or contact a provider")
    monkeypatch.setattr(subprocess, "Popen", denied)
    monkeypatch.setattr(socket.socket, "connect", denied)
    monkeypatch.setattr(os, "kill", denied)
    monkeypatch.setattr(os, "killpg", denied, raising=False)


@pytest.fixture(scope="module")
def signing_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def expected():
    return R010OIDCExpected(
        implementation_head_sha="a" * 40, job_local_secret_sha256="b" * 64,
        run_id="42632639755", run_attempt="2", check_run_id="129212564566",
        workflow_ref="chinanjjohn2012/mac-file-gateway/.github/workflows/r010.yml@refs/heads/test",
        workflow_sha="c" * 40, signed_source_sha="d" * 40,
        subject="repo:chinanjjohn2012/mac-file-gateway:ref:refs/heads/test",
    )


def make_token(key, claim_changes=None, header_changes=None, *,
               raw_claims=None, raw_header=None, signing_key=None):
    ex = expected()
    payload = {
        "iss": ISSUER, "aud": ex.audience, "repository": ex.repository,
        "run_id": ex.run_id, "run_attempt": ex.run_attempt,
        "check_run_id": ex.check_run_id, "workflow_ref": ex.workflow_ref,
        "workflow_sha": ex.workflow_sha, "sha": ex.signed_source_sha,
        "sub": ex.subject, "runner_environment": "github-hosted",
        "iat": NOW - 5, "nbf": NOW - 5, "exp": NOW + 100,
    }
    payload.update(claim_changes or {})
    header = {"alg": "RS256", "kid": "fixture-key", "typ": "JWT"}
    header.update(header_changes or {})
    h = raw_header or json.dumps(header, sort_keys=True).encode()
    p = raw_claims or json.dumps(payload, sort_keys=True).encode()
    signed = (b64(h) + "." + b64(p)).encode("ascii")
    signature = (signing_key or key).sign(
        signed, padding.PKCS1v15(), hashes.SHA256())
    numbers = key.public_key().public_numbers()
    jwks = {"keys": [{"kid": "fixture-key", "kty": "RSA", "use": "sig",
                      "alg": "RS256", "n": b64(numbers.n.to_bytes(256, "big")),
                      "e": b64(numbers.e.to_bytes(3, "big"))}]}
    metadata = {"issuer": ISSUER, "jwks_uri": ISSUER + "/.well-known/jwks"}
    return signed + b"." + b64(signature).encode(), metadata, jwks


def verify_fixture(key, *, claims=None, header=None, meta=None, jmodify=None,
                   exmodify=None, token=None, raw_claims=None, raw_header=None,
                   signer=None, now=NOW):
    jwt, metadata, jwks = make_token(
        key, claims, header, raw_claims=raw_claims, raw_header=raw_header,
        signing_key=signer)
    metadata.update(meta or {})
    if jmodify:
        jwks = jmodify(jwks)
    ex = expected()
    if exmodify:
        ex = exmodify(ex)
    return verify_r010_oidc_original_bytes_offline(
        jwt_bytes=jwt if token is None else token,
        issuer_metadata_bytes=json.dumps(metadata, sort_keys=True).encode(),
        jwks_bytes=json.dumps(jwks, sort_keys=True).encode(),
        expected=ex, verified_at_unix=now,
    )


def test_valid_real_rs256_offline_signature_and_signed_job_binding(signing_key):
    receipt = verify_fixture(signing_key)
    assert receipt.algorithm == "RS256"
    assert receipt.checked_check_run_id == "129212564566"
    assert receipt.native_launch_allowed is False
    assert receipt.status == "OFFLINE_SIGNATURE_VALID_EXTERNAL_TRUST_NOT_ATTESTED"
    assert len(receipt.jwt_sha256) == 64
    assert require_r010_oidc_offline_fresh_at(
        receipt, grant_now_unix=NOW + 99) is receipt
    assert not hasattr(receipt, "start_row")


@pytest.mark.parametrize("field,value", [
    ("iss", "https://evil.example"), ("aud", "wrong"),
    ("repository", "evil/repo"), ("run_id", "1"),
    ("run_attempt", "3"), ("check_run_id", "999"),
    ("workflow_ref", "wrong@main"), ("workflow_sha", "0" * 40),
    ("sha", "1" * 40), ("sub", "repo:other/repo"),
    ("runner_environment", "self-hosted"),
])
def test_wrong_signed_provider_claim_is_deny(signing_key, field, value):
    with pytest.raises(R010OIDCDenied, match="mismatched signed"):
        verify_fixture(signing_key, claims={field: value})


@pytest.mark.parametrize("field,value", [
    ("iat", NOW + 31), ("iat", NOW - 121),
    ("nbf", NOW + 31), ("exp", NOW), ("exp", NOW + 601),
    ("iat", True), ("nbf", None), ("exp", "1800000100"),
])
def test_signed_temporal_window_denies_invalid_time(signing_key, field, value):
    with pytest.raises(R010OIDCDenied, match="temporal"):
        verify_fixture(signing_key, claims={field: value})


@pytest.mark.parametrize("header", [
    {"alg": "none"}, {"alg": "HS256"}, {"typ": "JOSE"},
    {"kid": "../key"}, {"jku": "https://evil.example/jwks"},
    {"jwk": {"kty": "RSA"}}, {"crit": ["b64"]},
])
def test_jose_algorithm_and_untrusted_key_selector_denied(signing_key, header):
    with pytest.raises(R010OIDCDenied):
        verify_fixture(signing_key, header=header)


def test_wrong_real_rsa_signature_denied(signing_key):
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(R010OIDCDenied, match="signature"):
        verify_fixture(signing_key, signer=other)


@pytest.mark.parametrize("token", [
    b"bad", b"one.two", b"one.two.three.four",
    b"ab!cd.ef.gh", b"\xff.b.c",
])
def test_untrusted_or_noncanonical_original_jwt_denied(signing_key, token):
    with pytest.raises(R010OIDCDenied):
        verify_fixture(signing_key, token=token)


def test_duplicate_signed_payload_name_denied_even_after_actual_rs256(signing_key):
    with pytest.raises(R010OIDCDenied, match="duplicate"):
        verify_fixture(signing_key, raw_claims=b'{"aud":"a","aud":"b"}')


def test_duplicate_signed_header_name_denied_even_after_actual_rs256(signing_key):
    with pytest.raises(R010OIDCDenied, match="duplicate"):
        verify_fixture(signing_key, raw_header=(
            b'{"alg":"RS256","alg":"RS256","kid":"fixture-key","typ":"JWT"}'))


@pytest.mark.parametrize("metadata", [
    {"issuer": "https://evil.example"},
    {"jwks_uri": "http://token.actions.githubusercontent.com/keys"},
    {"jwks_uri": "https://evil.example/keys"},
    {"jwks_uri": "https://token.actions.githubusercontent.com:8443/keys"},
    {"jwks_uri": "https://token.actions.githubusercontent.com/keys?x=1"},
])
def test_untrusted_issuer_discovery_denied(signing_key, metadata):
    with pytest.raises(R010OIDCDenied):
        verify_fixture(signing_key, meta=metadata)


@pytest.mark.parametrize("modify", [
    lambda j: {"keys": j["keys"] * 2},
    lambda j: {"keys": []},
    lambda j: {"keys": [{**j["keys"][0], "kid": "other"}]},
    lambda j: {"keys": [{**j["keys"][0], "kty": "oct"}]},
    lambda j: {"keys": [{**j["keys"][0], "alg": "HS256"}]},
    lambda j: {"keys": [{**j["keys"][0], "e": "AQAB=="}]},
])
def test_untrusted_or_ambiguous_issuer_key_denied(signing_key, modify):
    with pytest.raises(R010OIDCDenied):
        verify_fixture(signing_key, jmodify=modify)


@pytest.mark.parametrize("field,value", [
    ("design_blob", "1" * 40),
    ("implementation_head_sha", "A" * 40),
    ("job_local_secret_sha256", "a" * 40),
    ("run_attempt", "02"), ("check_run_id", "\u0662"),
    ("workflow_ref", "other/repo/.github/workflows/r.yml@main"),
])
def test_wrong_expected_current_design_or_job_denied(signing_key, field, value):
    with pytest.raises(R010OIDCDenied):
        verify_fixture(signing_key, exmodify=lambda ex: replace(ex, **{field: value}))


@pytest.mark.parametrize("delta", [-1, 121, 160])
def test_time_bound_is_not_an_owner_or_launch_grant(signing_key, delta):
    receipt = verify_fixture(signing_key)
    with pytest.raises(R010OIDCDenied, match="stale"):
        require_r010_oidc_offline_fresh_at(receipt, grant_now_unix=NOW + delta)
