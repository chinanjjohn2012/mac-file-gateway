"""Canonical R006 trusted bootstrap bundle for future private native admission.

This is the ONLY high-level source candidate that combines the future
service-owned GitHub owner-comment fetch with the current r006 B/C FULL review
fetch. Normal public WorkspaceService/REST/MCP do not call it today.

Tests monkeypatch both fetchers and therefore perform no network access.
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

_TOKEN = object()


class D4TrustedBootstrapDenied(ValueError):
    """Canonical owner+review bootstrap is unavailable or no longer bound."""


class D4TrustedBootstrapBundle:
    """Process-bound owner decision plus matching current B/C FULL reviews."""

    __slots__ = ("_grant", "_reviews", "_pid", "_comment_id")

    def __init__(self, token, grant, reviews, comment_id):
        if token is not _TOKEN:
            raise D4TrustedBootstrapDenied(
                "trusted bootstrap bundle cannot be directly constructed")
        if (type(grant) is not D4VerifiedOwnerGrant
                or type(reviews) is not D4VerifiedReviewPair
                or type(comment_id) is not int or comment_id <= 0):
            raise D4TrustedBootstrapDenied("invalid trusted bootstrap inputs")
        try:
            reviews.check_grant(grant)
        except D4R006ReviewGateDenied:
            raise D4TrustedBootstrapDenied(
                "owner grant and current reviews do not match") from None
        if grant.attempt.owner_comment_id != comment_id:
            raise D4TrustedBootstrapDenied(
                "owner comment identity changed during bootstrap")
        self._grant = grant
        self._reviews = reviews
        self._pid = os.getpid()
        self._comment_id = comment_id

    def components(self):
        if os.getpid() != self._pid:
            raise D4TrustedBootstrapDenied(
                "trusted bootstrap cannot cross process boundary")
        try:
            self._reviews.check_grant(self._grant)
        except D4R006ReviewGateDenied:
            raise D4TrustedBootstrapDenied(
                "trusted bootstrap review binding changed") from None
        if self._grant.attempt.owner_comment_id != self._comment_id:
            raise D4TrustedBootstrapDenied(
                "trusted bootstrap owner identity changed")
        return self._grant, self._reviews


def fetch_r006_trusted_bootstrap(
    owner_comment_id: int,
) -> D4TrustedBootstrapBundle:
    """Future separately-authorized GitHub reads; never client-supplied bytes."""
    if type(owner_comment_id) is not int or not 1 <= owner_comment_id <= 2**63 - 1:
        raise D4TrustedBootstrapDenied("invalid owner comment id")
    try:
        grant = fetch_verified_owner_grant(owner_comment_id)
        reviews = fetch_verified_r006_code_reviews(grant)
        reviews.check_grant(grant)
    except (D4OwnerBootstrapDenied, D4R006ReviewGateDenied):
        raise D4TrustedBootstrapDenied(
            "trusted GitHub owner/review bootstrap failed") from None
    return D4TrustedBootstrapBundle(_TOKEN, grant, reviews, owner_comment_id)
