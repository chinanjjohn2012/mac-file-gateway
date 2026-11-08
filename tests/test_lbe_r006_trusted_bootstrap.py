"""Safe T0 for canonical R006 owner+review trusted bootstrap bundle."""
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

CID = 7712345678


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


def test_canonical_fetch_orders_owner_then_current_reviews(monkeypatch):
    grant = _fake_grant()
    reviews = _fake_reviews(monkeypatch)
    events = []

    def owner(comment_id):
        events.append(("owner", comment_id))
        return grant

    def review(value):
        events.append(("reviews", value))
        return reviews

    monkeypatch.setattr(mod, "fetch_verified_owner_grant", owner)
    monkeypatch.setattr(mod, "fetch_verified_r006_code_reviews", review)
    bundle = fetch_r006_trusted_bootstrap(CID)
    assert type(bundle) is D4TrustedBootstrapBundle
    assert bundle.components() == (grant, reviews)
    assert events == [("owner", CID), ("reviews", grant)]


def test_bundle_cannot_be_directly_constructed(monkeypatch):
    grant = _fake_grant()
    reviews = _fake_reviews(monkeypatch)
    with pytest.raises(D4TrustedBootstrapDenied):
        D4TrustedBootstrapBundle(object(), grant, reviews, CID)


def test_wrong_owner_comment_identity_denied(monkeypatch):
    grant = _fake_grant()
    grant.attempt.owner_comment_id = CID + 1
    reviews = _fake_reviews(monkeypatch)
    monkeypatch.setattr(mod, "fetch_verified_owner_grant", lambda _cid: grant)
    monkeypatch.setattr(
        mod, "fetch_verified_r006_code_reviews", lambda _grant: reviews)
    with pytest.raises(D4TrustedBootstrapDenied):
        fetch_r006_trusted_bootstrap(CID)


def test_review_mismatch_denied(monkeypatch):
    grant = _fake_grant()
    reviews = object.__new__(D4VerifiedReviewPair)
    monkeypatch.setattr(
        D4VerifiedReviewPair, "check_grant",
        lambda self, value: (_ for _ in ()).throw(
            D4R006ReviewGateDenied("mismatch")))
    monkeypatch.setattr(mod, "fetch_verified_owner_grant", lambda _cid: grant)
    monkeypatch.setattr(
        mod, "fetch_verified_r006_code_reviews", lambda _grant: reviews)
    with pytest.raises(D4TrustedBootstrapDenied):
        fetch_r006_trusted_bootstrap(CID)


def test_bundle_process_drift_denied(monkeypatch):
    grant = _fake_grant()
    reviews = _fake_reviews(monkeypatch)
    monkeypatch.setattr(mod, "fetch_verified_owner_grant", lambda _cid: grant)
    monkeypatch.setattr(
        mod, "fetch_verified_r006_code_reviews", lambda _grant: reviews)
    bundle = fetch_r006_trusted_bootstrap(CID)
    real = os.getpid()
    monkeypatch.setattr(os, "getpid", lambda: real + 1)
    with pytest.raises(D4TrustedBootstrapDenied):
        bundle.components()
