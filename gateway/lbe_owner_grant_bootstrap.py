"""Trusted-bootstrap pieces for a future exact R006 owner grant.

The network fetch function is NOT invoked by normal WorkspaceService or tests.
When separately authorized later, it fetches one fixed public GitHub issue
comment over HTTPS without ambient proxies or credentials, rejects redirects
and oversized/non-JSON responses, then applies the strict owner grant parser.

Binding is pure T0: it compares that verified grant to an internally prepared
LbeWorkPlan, the fixed current macOS host-source observation, and exact
repository/run identity. Nothing here calls Popen or enables F1.
"""
from __future__ import annotations

import hashlib
import json
import os
import ssl
import time
import urllib.error
import urllib.request

from .lbe_owner_grant import (
    D4OwnerGrantDenied, D4VerifiedOwnerGrant,
    verify_d4_owner_github_comment_t0,
)
from .lbe_r006_macos_allowlist import D4R006HostAllowlistObservation
from .lbe_r006_review_gate import (
    D4R006ReviewGateDenied, D4VerifiedReviewPair,
)
from .lbe_launch_recipe import D4NativeLaunchRecipe
from .lbe_worker import LbeWorkPlan, LbeWorker, LbeWorkerError

_REPO = "chinanjjohn2012/mac-file-gateway"
_MAX_RESPONSE = 65536
_BIND_TOKEN = object()


class D4OwnerBootstrapDenied(ValueError):
    """Owner evidence transport/runtime binding is not trustworthy."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _argv_fingerprint(argv: tuple[str, ...]) -> str:
    if (type(argv) is not tuple or not argv
            or any(type(x) is not str or not x for x in argv)):
        raise D4OwnerBootstrapDenied("invalid argv binding")
    raw = json.dumps(list(argv), separators=(",", ":"),
                     ensure_ascii=True).encode("ascii")
    return hashlib.sha256(raw).hexdigest()


def fetch_verified_owner_grant(comment_id: int) -> D4VerifiedOwnerGrant:
    """Future separately-authorized real GitHub HTTPS fetch; no token/secrets."""
    if type(comment_id) is not int or not 1 <= comment_id <= 2**63 - 1:
        raise D4OwnerBootstrapDenied("invalid owner comment id")
    url = f"https://api.github.com/repos/{_REPO}/issues/comments/{comment_id}"
    context = ssl.create_default_context()
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=context),
        _NoRedirect(),
    )
    request = urllib.request.Request(
        url, method="GET",
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "mac-file-gateway-r006-owner-grant/1",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with opener.open(request, timeout=5) as response:
            if getattr(response, "status", None) != 200:
                raise D4OwnerBootstrapDenied("GitHub owner grant HTTP status")
            if response.geturl() != url:
                raise D4OwnerBootstrapDenied("GitHub owner grant redirected")
            content_type = response.headers.get("Content-Type", "")
            if not content_type.lower().startswith("application/json"):
                raise D4OwnerBootstrapDenied("GitHub owner grant is not JSON")
            raw_length = response.headers.get("Content-Length")
            if raw_length is not None:
                try:
                    length = int(raw_length)
                except ValueError:
                    raise D4OwnerBootstrapDenied("invalid response length") from None
                if not 0 < length <= _MAX_RESPONSE:
                    raise D4OwnerBootstrapDenied("owner grant response oversized")
            data = response.read(_MAX_RESPONSE + 1)
            if not 0 < len(data) <= _MAX_RESPONSE:
                raise D4OwnerBootstrapDenied("owner grant response empty/oversized")
    except (OSError, urllib.error.URLError, urllib.error.HTTPError):
        raise D4OwnerBootstrapDenied("GitHub owner grant transport unavailable") from None
    try:
        return verify_d4_owner_github_comment_t0(data)
    except D4OwnerGrantDenied:
        raise D4OwnerBootstrapDenied("GitHub owner grant semantic verification failed") from None


class D4ConsumedOwnerGrant:
    """Service-produced witness: exact grant was durably burned in this process."""

    __slots__ = ("_attempt", "_journal_digest", "_pid", "_plan", "_recipe")

    def __init__(self, token, attempt, journal_digest, plan, recipe):
        if token is not _BIND_TOKEN:
            raise D4OwnerBootstrapDenied("consumed grant cannot be directly constructed")
        if (type(journal_digest) is not str or len(journal_digest) != 64
                or any(c not in "0123456789abcdef" for c in journal_digest)):
            raise D4OwnerBootstrapDenied("invalid durable consumption digest")
        self._attempt = attempt
        self._journal_digest = journal_digest
        self._pid = os.getpid()
        self._plan = plan
        self._recipe = recipe

    @property
    def attempt(self):
        return self._attempt

    def check_binding(self, plan: object, recipe: object) -> None:
        if (os.getpid() != self._pid or plan is not self._plan
                or recipe is not self._recipe
                or type(plan) is not LbeWorkPlan
                or type(recipe) is not D4NativeLaunchRecipe):
            raise D4OwnerBootstrapDenied("consumed grant binding changed")
        if recipe.selected_source_fingerprint != self._attempt.product_recipe_fingerprint:
            raise D4OwnerBootstrapDenied("consumed product recipe changed")
        if int(time.time()) > self._attempt.expires_at_unix:
            raise D4OwnerBootstrapDenied("consumed owner grant expired before launch")


class D4BoundOwnerGrant:
    """Exact current-runtime binding, not directly constructible."""

    __slots__ = ("_attempt", "_grant_digest")

    def __init__(self, token, attempt, grant_digest):
        if token is not _BIND_TOKEN:
            raise D4OwnerBootstrapDenied("bound grant cannot be directly constructed")
        self._attempt = attempt
        self._grant_digest = grant_digest

    @property
    def attempt(self):
        return self._attempt

    @property
    def grant_digest(self):
        return self._grant_digest


def bind_verified_owner_grant_t0(
    grant: object, reviews: object, host: object,
    plan: object, recipe: object, *,
    base_sha: str, head_sha: str, head_tree: str, manifest_sha256: str,
    run_id: int, run_attempt: int,
) -> D4BoundOwnerGrant:
    """Bind verifier output to exact current plan/host/run without execution."""
    if type(grant) is not D4VerifiedOwnerGrant:
        raise D4OwnerBootstrapDenied("unverified owner grant")
    if type(reviews) is not D4VerifiedReviewPair:
        raise D4OwnerBootstrapDenied("unverified current B/C code reviews")
    try:
        reviews.check_grant(grant)
    except D4R006ReviewGateDenied:
        raise D4OwnerBootstrapDenied(
            "owner grant and current B/C reviews do not match") from None
    if type(host) is not D4R006HostAllowlistObservation:
        raise D4OwnerBootstrapDenied("unverified current host/source observation")
    if type(plan) is not LbeWorkPlan:
        raise D4OwnerBootstrapDenied("untrusted current plan")
    if type(recipe) is not D4NativeLaunchRecipe:
        raise D4OwnerBootstrapDenied("untrusted product recipe")
    try:
        LbeWorker._check_plan(plan)
    except LbeWorkerError:
        raise D4OwnerBootstrapDenied("invalid current plan") from None
    if (recipe.workspace != plan.workspace
            or recipe.runner != plan.runner
            or recipe.requested_argv != plan.requested_argv
            or recipe.service_effective_argv != plan.effective_argv
            or recipe.original_timeout_seconds != plan.timeout_seconds
            or recipe.native_launch_allowed is not False
            or recipe.owner_t1_grant_present is not False
            or type(recipe.selected_source_fingerprint) is not str
            or len(recipe.selected_source_fingerprint) != 64
            or any(c not in "0123456789abcdef"
                   for c in recipe.selected_source_fingerprint)):
        raise D4OwnerBootstrapDenied("product recipe does not match current plan")
    for value, length, label in (
        (base_sha, 40, "base"), (head_sha, 40, "head"),
        (head_tree, 40, "tree"), (manifest_sha256, 64, "manifest"),
    ):
        if type(value) is not str or len(value) != length or any(
                c not in "0123456789abcdef" for c in value):
            raise D4OwnerBootstrapDenied("invalid current " + label)
    if (type(run_id) is not int or type(run_attempt) is not int
            or run_id <= 0 or run_attempt <= 0):
        raise D4OwnerBootstrapDenied("invalid current run identity")
    if (host.selected_source_bytes_verified is not True
            or host.actual_host_safety_verified is not True
            or host.no_ambient_credentials_observed is not True
            or host.no_ambient_proxy_observed is not True
            or host.no_writable_nonlocal_mounts_observed is not True
            or host.kernel_sysname != "Darwin"
            or host.machine not in ("arm64", "aarch64")
            or host.run_id != run_id or host.run_attempt != run_attempt
            or type(host.job_name) is not str or not host.job_name
            or type(host.mount_table_fingerprint) is not str
            or len(host.mount_table_fingerprint) != 64
            or host.full_boot_image_attested is not False
            or host.actual_loaded_graph_proven is not False
            or host.native_launch_allowed is not False):
        raise D4OwnerBootstrapDenied(
            "host observation lacks fresh run-bound safety evidence")
    attempt = grant.attempt
    current = (
        base_sha, head_sha, head_tree, manifest_sha256, run_id, run_attempt,
        host.source_fingerprint, host.runner_profile_fingerprint,
        recipe.selected_source_fingerprint,
        plan.workspace, plan.cwd, plan.runner,
        _argv_fingerprint(plan.requested_argv),
        _argv_fingerprint(plan.effective_argv), plan.timeout_seconds,
        host.image_version, host.os_build,
    )
    approved = (
        attempt.base_sha, attempt.head_sha, attempt.head_tree,
        attempt.manifest_sha256, attempt.run_id, attempt.run_attempt,
        attempt.source_fingerprint, attempt.runner_fingerprint,
        attempt.product_recipe_fingerprint,
        attempt.workspace, attempt.cwd, attempt.runner,
        attempt.requested_argv_fingerprint, attempt.effective_argv_fingerprint,
        attempt.timeout_seconds, attempt.image_version, attempt.os_build,
    )
    if current != approved or int(time.time()) > attempt.expires_at_unix:
        raise D4OwnerBootstrapDenied("owner grant does not match current run/plan")
    return D4BoundOwnerGrant(_BIND_TOKEN, attempt, grant.grant_digest)


def _new_consumed_owner_grant(bound: object, journal_digest: str,
                              plan: object, recipe: object) -> D4ConsumedOwnerGrant:
    """WorkspaceService-only constructor after D4DurableAttemptJournal.consume."""
    if (type(bound) is not D4BoundOwnerGrant or type(plan) is not LbeWorkPlan
            or type(recipe) is not D4NativeLaunchRecipe):
        raise D4OwnerBootstrapDenied("invalid durable grant source")
    if recipe.selected_source_fingerprint != bound.attempt.product_recipe_fingerprint:
        raise D4OwnerBootstrapDenied("durable grant recipe mismatch")
    return D4ConsumedOwnerGrant(
        _BIND_TOKEN, bound.attempt, journal_digest, plan, recipe)
