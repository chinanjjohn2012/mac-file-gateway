"""Canonical R006 trusted bootstrap for future private native admission.

The service-owned bootstrap binds three independently checked inputs:
1. one direct repository-owner exact-attempt GitHub comment,
2. current r006 B/C FULL GitHub review objects for the same snapshot, and
3. the current G05 receipt + live GitHub Actions run identity.

Normal public WorkspaceService/REST/MCP do not call this function. A bundle is
process-bound and still does not itself authorize T1 or weaken public F1.
"""
from __future__ import annotations

import os

from .lbe_owner_grant import D4VerifiedOwnerGrant
from .lbe_owner_grant_bootstrap import (
    D4OwnerBootstrapDenied, fetch_verified_owner_grant,
)
from .lbe_r006_review_gate import (
    D4R006ReviewGateDenied, D4VerifiedReviewPair,
    fetch_verified_r006_code_reviews,
)
from .lbe_r006_runtime_identity import (
    D4R006RuntimeIdentityDenied, D4VerifiedRuntimeIdentity,
    fetch_verified_r006_runtime_identity,
)

_TOKEN = object()


class D4TrustedBootstrapDenied(ValueError):
    """Canonical owner+review+runtime bootstrap is unavailable or changed."""


class D4TrustedBootstrapBundle:
    """Process-bound owner decision, FULL reviews and current runtime identity."""

    __slots__ = ("_grant", "_reviews", "_runtime", "_pid", "_comment_id")

    def __init__(self, token, grant, reviews, runtime, comment_id):
        if token is not _TOKEN:
            raise D4TrustedBootstrapDenied(
                "trusted bootstrap bundle cannot be directly constructed")
        if (type(grant) is not D4VerifiedOwnerGrant
                or type(reviews) is not D4VerifiedReviewPair
                or type(runtime) is not D4VerifiedRuntimeIdentity
                or type(comment_id) is not int or comment_id <= 0):
            raise D4TrustedBootstrapDenied("invalid trusted bootstrap inputs")
        try:
            reviews.check_grant(grant)
            runtime.check_grant(grant)
        except (D4R006ReviewGateDenied, D4R006RuntimeIdentityDenied):
            raise D4TrustedBootstrapDenied(
                "owner, reviews and runtime do not match") from None
        if grant.attempt.owner_comment_id != comment_id:
            raise D4TrustedBootstrapDenied(
                "owner comment identity changed during bootstrap")
        self._grant = grant
        self._reviews = reviews
        self._runtime = runtime
        self._pid = os.getpid()
        self._comment_id = comment_id

    def components(self):
        if os.getpid() != self._pid:
            raise D4TrustedBootstrapDenied(
                "trusted bootstrap cannot cross process boundary")
        try:
            self._reviews.check_grant(self._grant)
            self._runtime.check_grant(self._grant)
        except (D4R006ReviewGateDenied, D4R006RuntimeIdentityDenied):
            raise D4TrustedBootstrapDenied(
                "trusted bootstrap binding changed") from None
        if self._grant.attempt.owner_comment_id != self._comment_id:
            raise D4TrustedBootstrapDenied(
                "trusted bootstrap owner identity changed")
        return self._grant, self._reviews, self._runtime


def fetch_r006_trusted_bootstrap(
    owner_comment_id: int, g05_receipt_path: str,
) -> D4TrustedBootstrapBundle:
    """Fetch canonical public GitHub evidence and private G05 run receipt."""
    if type(owner_comment_id) is not int or not 1 <= owner_comment_id <= 2**63 - 1:
        raise D4TrustedBootstrapDenied("invalid owner comment id")
    if type(g05_receipt_path) is not str or not g05_receipt_path.startswith("/"):
        raise D4TrustedBootstrapDenied("invalid G05 receipt path")
    try:
        grant = fetch_verified_owner_grant(owner_comment_id)
        reviews = fetch_verified_r006_code_reviews(grant)
        reviews.check_grant(grant)
        runtime = fetch_verified_r006_runtime_identity(
            grant, g05_receipt_path)
        runtime.check_grant(grant)
    except (D4OwnerBootstrapDenied, D4R006ReviewGateDenied,
            D4R006RuntimeIdentityDenied):
        raise D4TrustedBootstrapDenied(
            "trusted GitHub owner/review/runtime bootstrap failed") from None
    return D4TrustedBootstrapBundle(
        _TOKEN, grant, reviews, runtime, owner_comment_id)
