"""R010 exact current GitHub workflow-run / check-run source cross-check.

Queries only two fixed public GitHub Actions REST endpoints via the constrained
TLS reader. This is a real source-validation implementation, but its SAFE T0
fixtures are untrusted; a returned snapshot is NOT an authenticated native
Job execution grant, and no current WorkspaceService/Worker imports it.
No actual HTTPS requests, OIDC requests or child execution occur in T0.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib

from .lbe_r010_job_envelope import R010JobKey, R010JobEnvelopeDenied
from .lbe_r010_oidc_verify import (
    R010OIDCExpected, R010OIDCDenied,
    require_r010_oidc_offline_fresh_at,
)
from .lbe_r010_provider_transport import (
    _API, _ConstrainedHttps, _json, R010HttpsSourceDenied,
    R010ProviderOIDCSource,
)

_REPO = "chinanjjohn2012/mac-file-gateway"


class R010CurrentJobDenied(ValueError):
    """Signed-Job/current-GitHub-API source identity did not match."""


@dataclass(frozen=True, slots=True)
class R010CurrentJobSource:
    """Exact API + signed source tuple, still no native runtime authority."""

    run_id: int
    run_attempt: int
    job_id: int
    check_run_id: int
    head_sha: str
    run_body_sha256: str
    jobs_body_sha256: str
    oidc_jwt_sha256: str
    status: str = "CURRENT_RUN_JOB_SOURCE_MATCH_NO_EXECUTION_GRANT"
    current_job_source_matched: bool = True
    provider_full_provenance_attested: bool = False
    owner_product_t1_grant_verified: bool = False
    native_launch_allowed: bool = False
    six_command_product_t1_pass: bool = False


def read_r010_current_github_job_source(
    *, job_key: R010JobKey, signed_expected: R010OIDCExpected,
    source: R010ProviderOIDCSource, now_unix: int,
) -> R010CurrentJobSource:
    """Cross-check original JSON from two fixed current run/job endpoints.

    This method does NOT assume Actions Job numeric ID equals check-run ID:
    instead it selects the unique Job by its exact native check_run_url and
    matches run_id/run_attempt/Head/workflow with signed claims. It rejects
    completed/stale/sibling/foreign jobs. No source receipt is a T1 permit.
    """
    if (type(job_key) is not R010JobKey
            or type(signed_expected) is not R010OIDCExpected
            or type(source) is not R010ProviderOIDCSource
            or type(now_unix) is not int):
        raise R010CurrentJobDenied("missing typed current Job source")
    try:
        job_key.checked()
        signed_expected.checked()
        signature = require_r010_oidc_offline_fresh_at(
            source.signature, grant_now_unix=now_unix)
    except (R010JobEnvelopeDenied, R010OIDCDenied, AttributeError):
        raise R010CurrentJobDenied("unqualified Job/OIDC source") from None
    if (job_key.head_sha != signed_expected.implementation_head_sha
            or job_key.head_sha != signed_expected.signed_source_sha
            or job_key.design_blob != signed_expected.design_blob
            or str(job_key.run_id) != signed_expected.run_id
            or str(job_key.run_attempt) != signed_expected.run_attempt
            or str(job_key.check_run_id) != signed_expected.check_run_id
            or job_key.workflow_ref != signed_expected.workflow_ref
            or signature.checked_run_id != signed_expected.run_id
            or signature.checked_run_attempt != signed_expected.run_attempt
            or signature.checked_check_run_id != signed_expected.check_run_id
            or signature.signed_subject != signed_expected.subject
            or signature.status !=
            "OFFLINE_SIGNATURE_VALID_EXTERNAL_TRUST_NOT_ATTESTED"
            or source.current_job_independently_verified is not False
            or source.owner_product_t1_grant_verified is not False
            or source.native_launch_allowed is not False
            or source.original_jwt_sha256 != signature.jwt_sha256):
        raise R010CurrentJobDenied("cross-source signed Job identity drift")
    run_url = _API + "/actions/runs/" + str(job_key.run_id)
    jobs_url = (
        run_url + "/attempts/" + str(job_key.run_attempt)
        + "/jobs?per_page=100&page=1")
    https = _ConstrainedHttps()
    try:
        run_bytes = https.get(run_url, limit=131072)
        jobs_bytes = https.get(jobs_url, limit=1048576)
        run = _json(run_bytes, size=131072, kind=dict)
        listing = _json(jobs_bytes, size=1048576, kind=dict)
    except R010HttpsSourceDenied:
        raise R010CurrentJobDenied("current provider Job API unavailable") from None
    if (type(run.get("id")) is not int or
            run["id"] != job_key.run_id
            or type(run.get("run_attempt")) is not int
            or run["run_attempt"] != job_key.run_attempt
            or run.get("status") != "in_progress"
            or run.get("conclusion") is not None
            or run.get("event") != "pull_request"
            or run.get("head_sha") != signed_expected.signed_source_sha
            or type(run.get("workflow_id")) is not int
            or run["workflow_id"] != job_key.workflow_id
            or run.get("path") != job_key.workflow_path
            or type(run.get("repository")) is not dict
            or run["repository"].get("full_name") != _REPO):
        raise R010CurrentJobDenied("current workflow Run identity mismatch")
    jobs = listing.get("jobs")
    if (type(jobs) is not list or not 1 <= len(jobs) < 100
            or type(listing.get("total_count")) is not int
            or listing["total_count"] != len(jobs)
            or any(type(j) is not dict for j in jobs)):
        raise R010CurrentJobDenied("incomplete current workflow Job listing")
    check_url = _API + "/check-runs/" + str(job_key.check_run_id)
    matches = [j for j in jobs if j.get("check_run_url") == check_url]
    if len(matches) != 1:
        raise R010CurrentJobDenied("signed check run not unique in workflow")
    job = matches[0]
    if (type(job.get("id")) is not int or job["id"] <= 0
            or type(job.get("run_id")) is not int
            or job["run_id"] != job_key.run_id
            or type(job.get("run_attempt")) is not int
            or job["run_attempt"] != job_key.run_attempt
            or job.get("run_url") != run_url
            or job.get("name") != job_key.job_name
            or job.get("head_sha") != signed_expected.signed_source_sha
            or job.get("status") != "in_progress"
            or job.get("conclusion") is not None
            or job.get("completed_at") is not None
            or type(job.get("started_at")) is not str
            or not job["started_at"]):
        raise R010CurrentJobDenied("current signed check-run Job not running")
    return R010CurrentJobSource(
        run_id=job_key.run_id, run_attempt=job_key.run_attempt,
        job_id=job["id"], check_run_id=job_key.check_run_id,
        head_sha=job_key.head_sha,
        run_body_sha256=hashlib.sha256(run_bytes).hexdigest(),
        jobs_body_sha256=hashlib.sha256(jobs_bytes).hexdigest(),
        oidc_jwt_sha256=signature.jwt_sha256,
    )
