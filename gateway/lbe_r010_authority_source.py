"""R010 single-Job composed Provider/Owner/source chain, nonoperative.

This first-party composition commits exact immutable source IDs to the same
create-once Job journal as the nonce manifest. It does not authenticate the
caller-supplied typed source receipts or permit launch: the real T1 boundary
still requires separately approved live TLS/JWT/current Job/Owner evidence,
full loader/host/Worker qualification and a current Owner execution Grant.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re

from .lbe_r010_grant_candidate import (
    R010GrantExpected, R010GrantSourceObservation,
)
from .lbe_r010_job_envelope import (
    R010CreatedJobEnvelope, R010JobEnvelopeDenied,
    R010JobKey, _write_once,
)
from .lbe_r010_owner_choice import R010OwnerDesignChoiceObservation
from .lbe_r010_provider_job import R010CurrentJobSource
from .lbe_r010_provider_transport import R010GithubOwnerRead
from .lbe_r010_serial_journal import R010SerialNonceJournal

_HEX64 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)


class R010AuthoritySourceDenied(ValueError):
    """Provider/Owner/global Job chain has not earned runtime authority."""


@dataclass(frozen=True, slots=True)
class R010AuthoritySourceBinding:
    """Persistent source reference, not an execution or FULL approval."""

    job_key_sha256: str
    grant_body_sha256: str
    oidc_jwt_sha256: str
    signed_check_run_id: int
    review_nodes: tuple[str, str]
    source_digest_sha256: str
    status: str = "COMPOSED_CURRENT_SOURCE_ONLY_NO_T1"
    provider_runtime_authenticated: bool = False
    owner_runtime_authenticated: bool = False
    native_launch_allowed: bool = False
    six_command_product_t1_pass: bool = False


def bind_r010_authority_source_to_job(
    *, envelope: R010CreatedJobEnvelope, job_key: R010JobKey,
    journal: R010SerialNonceJournal,
    owner_source: R010GithubOwnerRead,
    current_job: R010CurrentJobSource,
    grant_source: R010GrantSourceObservation,
    expected: R010GrantExpected,
) -> R010AuthoritySourceBinding:
    """Write one durable non-launching Job authority candidate, no rerun.

    Contract-critical identity checks are made against the canonical current
    Job envelope, already validated design Choice and fixed B/C review nodes.
    All inputs are source candidate records; no Boolean/caller digest creates
    a trusted T1 provenance witness. The public F1/NativeLauncher deny stays.
    """
    if (type(envelope) is not R010CreatedJobEnvelope
            or type(job_key) is not R010JobKey
            or type(journal) is not R010SerialNonceJournal
            or type(owner_source) is not R010GithubOwnerRead
            or type(current_job) is not R010CurrentJobSource
            or type(grant_source) is not R010GrantSourceObservation
            or type(expected) is not R010GrantExpected):
        raise R010AuthoritySourceDenied("typed Job/Owner provenance missing")
    try:
        job_key.checked()
        expected.checked()
    except (ValueError, TypeError):
        raise R010AuthoritySourceDenied("job/source tuple unqualified") from None
    choice = owner_source.choice
    if (type(choice) is not R010OwnerDesignChoiceObservation
            or choice.status !=
            "SOURCE_ONLY_R014_CHOICE_MATCH_NOT_PROVIDER_ATTESTED"
            or choice.design_blob != job_key.design_blob
            or choice.options != ("A1", "B1")
            or choice.comment_id != job_key.owner_choice_comment_id
            or choice.native_launch_allowed is not False
            or choice.product_t1_grant_verified is not False
            or current_job.status !=
            "CURRENT_RUN_JOB_SOURCE_MATCH_NO_EXECUTION_GRANT"
            or current_job.current_job_source_matched is not True
            or current_job.provider_full_provenance_attested is not False
            or current_job.owner_product_t1_grant_verified is not False
            or current_job.native_launch_allowed is not False
            or grant_source.status !=
            "OWNER_GRANT_SOURCE_MATCH_EXTERNAL_TRUST_NOT_ATTESTED"
            or grant_source.owner_comment_authenticated is not False
            or grant_source.provider_job_authenticated is not False
            or grant_source.execution_qualification_attested is not False
            or grant_source.native_launch_allowed is not False
            or grant_source.row_positive_success is not False
            or grant_source.six_command_product_t1_pass is not False
            or owner_source.native_launch_allowed is not False
            or owner_source.current_job_independently_verified is not False):
        raise R010AuthoritySourceDenied("untrusted source promoted to authority")
    if (current_job.run_id != job_key.run_id
            or current_job.run_attempt != job_key.run_attempt
            or current_job.check_run_id != job_key.check_run_id
            or current_job.head_sha != job_key.head_sha
            or grant_source.implementation_head_sha != job_key.head_sha
            or grant_source.job_envelope_key_sha256 !=
               job_key.key_sha256()
            or grant_source.signed_jwt_sha256 !=
               current_job.oidc_jwt_sha256
            or grant_source.standards_review_node_id ==
               grant_source.spec_review_node_id
            or expected.head_sha != job_key.head_sha
            or expected.job_envelope_key_sha256 != job_key.key_sha256()
            or journal._envelope is not envelope):
        raise R010AuthoritySourceDenied("current signed Job/Grant/Journal drift")
    for value in (
        grant_source.body_sha256,
        owner_source.raw_choice_sha256,
        owner_source.raw_reviews_sha256,
        current_job.run_body_sha256,
        current_job.jobs_body_sha256,
        current_job.oidc_jwt_sha256,
        expected.manifest_sha256,
        expected.six_commands_sha256,
        expected.six_nonces_sha256,
    ):
        if type(value) is not str or _HEX64.fullmatch(value) is None:
            raise R010AuthoritySourceDenied("missing original source digest")
    with envelope._lock:
        try:
            envelope._require_live()
        except R010JobEnvelopeDenied:
            raise R010AuthoritySourceDenied("canonical Job closed") from None
        if getattr(envelope, "_r010_authority_source_claimed", False):
            raise R010AuthoritySourceDenied("current authority source already used")
        # A partial attempt consumes this Job; NEVER retry or take an
        # alternate root after a crash, even when no file was fsynced.
        envelope._r010_authority_source_claimed = True
        if (journal._burned or journal._failed
                or journal._source_recorded
                or journal._row1_capture_claimed):
            raise R010AuthoritySourceDenied("authority source came after row burn")
        data = {
            "version": "R010_CURRENT_AUTHORITY_SOURCE_BINDING_V1",
            "design_blob": choice.design_blob,
            "choice_comment_id": choice.comment_id,
            "choice_body_sha256": choice.body_sha256,
            "owner_tls_choice_response_sha256": owner_source.raw_choice_sha256,
            "owner_tls_reviews_response_sha256": owner_source.raw_reviews_sha256,
            "implementation_base_sha": expected.base_sha,
            "implementation_head_sha": expected.head_sha,
            "implementation_head_tree": expected.tree_sha,
            "manifest_sha256": expected.manifest_sha256,
            "grant_body_sha256": grant_source.body_sha256,
            "b_review_node": grant_source.standards_review_node_id,
            "c_review_node": grant_source.spec_review_node_id,
            "oidc_jwt_sha256": current_job.oidc_jwt_sha256,
            "run_id": job_key.run_id,
            "run_attempt": job_key.run_attempt,
            "check_run_id": job_key.check_run_id,
            "run_api_sha256": current_job.run_body_sha256,
            "jobs_api_sha256": current_job.jobs_body_sha256,
            "job_key_sha256": job_key.key_sha256(),
            "six_commands_sha256": expected.six_commands_sha256,
            "six_nonces_sha256": expected.six_nonces_sha256,
            "source_model_only": True,
            "native_launch_allowed": False,
            "six_command_product_t1_pass": False,
        }
        raw = (json.dumps(
            data, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
        try:
            _write_once(
                envelope._journal_fd, "r010-authority-source-binding.json", raw)
        except R010JobEnvelopeDenied:
            raise R010AuthoritySourceDenied(
                "uncertain authority source fsync; permanent denial") from None
    return R010AuthoritySourceBinding(
        job_key_sha256=job_key.key_sha256(),
        grant_body_sha256=grant_source.body_sha256,
        oidc_jwt_sha256=current_job.oidc_jwt_sha256,
        signed_check_run_id=current_job.check_run_id,
        review_nodes=(
            grant_source.standards_review_node_id,
            grant_source.spec_review_node_id),
        source_digest_sha256=hashlib.sha256(raw).hexdigest(),
    )
