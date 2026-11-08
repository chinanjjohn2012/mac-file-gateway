"""Safe T0 for canonical R006 owner+review+runtime bootstrap."""
import os

import pytest

from gateway import lbe_r006_trusted_bootstrap as mod
from gateway.lbe_r006_trusted_bootstrap import (
    D4TrustedBootstrapBundle, D4TrustedBootstrapDenied,
    fetch_r006_trusted_bootstrap,
)
from gateway.lbe_owner_grant import D4VerifiedOwnerGrant
from gateway.lbe_r006_review_gate import (
    D4R006ReviewGateDenied, D4VerifiedReviewPair,
)
from gateway.lbe_r006_runtime_identity import (
    D4R006RuntimeIdentityDenied, D4VerifiedRuntimeIdentity,
)

CID = 7712345678
RECEIPT = "/private/r006-g05-receipt.json"


def _fake_grant():
    item = object.__new__(D4VerifiedOwnerGrant)
    attempt = type("Attempt", (), {"owner_comment_id": CID})()
    object.__setattr__(item, "_attempt", attempt)
    object.__setattr__(item, "_grant_digest", "a" * 64)
    object.__setattr__(item, "_created_at_unix", 1)
    return item


def _fake_reviews(monkeypatch):
    item = object.__new__(D4VerifiedReviewPair)
    monkeypatch.setattr(
        D4VerifiedReviewPair, "check_grant", lambda self, grant: None)
    return item


def _fake_runtime(monkeypatch):
    item = object.__new__(D4VerifiedRuntimeIdentity)
    monkeypatch.setattr(
        D4VerifiedRuntimeIdentity, "check_grant", lambda self, grant: None)
    return item


def _wire(monkeypatch, grant, reviews, runtime, events=None):
    def owner(comment_id):
        if events is not None:
            events.append(("owner", comment_id))
        return grant

    def review(value):
        if events is not None:
            events.append(("reviews", value))
        return reviews

    def run(value, path):
        if events is not None:
            events.append(("runtime", value, path))
        return runtime

    monkeypatch.setattr(mod, "fetch_verified_owner_grant", owner)
    monkeypatch.setattr(mod, "fetch_verified_r006_code_reviews", review)
    monkeypatch.setattr(mod, "fetch_verified_r006_runtime_identity", run)


def test_canonical_fetch_orders_owner_reviews_then_runtime(monkeypatch):
    grant = _fake_grant()
    reviews = _fake_reviews(monkeypatch)
    runtime = _fake_runtime(monkeypatch)
    events = []
    _wire(monkeypatch, grant, reviews, runtime, events)
    bundle = fetch_r006_trusted_bootstrap(CID, RECEIPT)
    assert type(bundle) is D4TrustedBootstrapBundle
    assert bundle.components() == (grant, reviews, runtime)
    assert events == [
        ("owner", CID), ("reviews", grant),
        ("runtime", grant, RECEIPT),
    ]


def test_bundle_cannot_be_directly_constructed(monkeypatch):
    with pytest.raises(D4TrustedBootstrapDenied):
        D4TrustedBootstrapBundle(
            object(), _fake_grant(), _fake_reviews(monkeypatch),
            _fake_runtime(monkeypatch), CID)


def test_wrong_owner_comment_identity_denied(monkeypatch):
    grant = _fake_grant()
    grant.attempt.owner_comment_id = CID + 1
    _wire(
        monkeypatch, grant, _fake_reviews(monkeypatch),
        _fake_runtime(monkeypatch))
    with pytest.raises(D4TrustedBootstrapDenied):
        fetch_r006_trusted_bootstrap(CID, RECEIPT)


def test_review_mismatch_denied(monkeypatch):
    grant = _fake_grant()
    reviews = object.__new__(D4VerifiedReviewPair)
    monkeypatch.setattr(
        D4VerifiedReviewPair, "check_grant",
        lambda self, value: (_ for _ in ()).throw(
            D4R006ReviewGateDenied("mismatch")))
    _wire(monkeypatch, grant, reviews, _fake_runtime(monkeypatch))
    with pytest.raises(D4TrustedBootstrapDenied):
        fetch_r006_trusted_bootstrap(CID, RECEIPT)


def test_runtime_mismatch_denied(monkeypatch):
    grant = _fake_grant()
    runtime = object.__new__(D4VerifiedRuntimeIdentity)
    monkeypatch.setattr(
        D4VerifiedRuntimeIdentity, "check_grant",
        lambda self, value: (_ for _ in ()).throw(
            D4R006RuntimeIdentityDenied("mismatch")))
    _wire(monkeypatch, grant, _fake_reviews(monkeypatch), runtime)
    with pytest.raises(D4TrustedBootstrapDenied):
        fetch_r006_trusted_bootstrap(CID, RECEIPT)


def test_bundle_process_drift_denied(monkeypatch):
    grant = _fake_grant()
    reviews = _fake_reviews(monkeypatch)
    runtime = _fake_runtime(monkeypatch)
    _wire(monkeypatch, grant, reviews, runtime)
    bundle = fetch_r006_trusted_bootstrap(CID, RECEIPT)
    real = os.getpid()
    monkeypatch.setattr(os, "getpid", lambda: real + 1)
    with pytest.raises(D4TrustedBootstrapDenied):
        bundle.components()


@pytest.mark.parametrize("comment,path", [
    (0, RECEIPT), (True, RECEIPT), (CID, "relative.json"),
])
def test_invalid_bootstrap_locator_denied(comment, path):
    with pytest.raises(D4TrustedBootstrapDenied):
        fetch_r006_trusted_bootstrap(comment, path)
