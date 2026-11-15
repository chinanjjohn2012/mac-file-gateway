"""R010 A1 composed source-only product bootstrap into one Job Owner/Worker.

First-party ordering: one original-JWT-checked PREEXEC source candidate is
durably sealed in the canonical R010 Job; exact GitHub Provider/Owner SOURCE
candidate is then bound to the SAME Job journal, followed by one
WorkspaceService/DirectChildOwner/Worker SOURCE-only session.

No call fetches live OIDC, a GitHub token, agent socket or user secrets.
No real child is run. Its typed inputs do NOT establish external TLS/JWKS
or live Job/Owner authorship: this function NEVER mints a PRODUCT_T1 grant.
F1/NativeLauncher remain denied even after six successful FakeChild rows.
Any failure consumes/poisons the Job; no alternate root or second attempt.
"""
from __future__ import annotations

from dataclasses import dataclass

from .lbe_r010_a1_host import R010A1ClosedPreexecSource, R010A1HostSource
from .lbe_r010_authority_source import (
    R010AuthoritySourceBinding, bind_r010_authority_source_to_job,
)
from .lbe_r010_grant_candidate import R010GrantExpected, R010GrantSourceObservation
from .lbe_r010_job_envelope import R010CreatedJobEnvelope, R010JobKey
from .lbe_r010_preexec_journal import (
    R010PreexecSourceSeal, seal_r010_preexec_source_in_job,
)
from .lbe_r010_preexec_source import R010PreexecSourceObservation
from .lbe_r010_preimport_gate import (
    R010PreimportScrubReceipt, R010PreimportScrubDenied,
    validate_r010_preimport_receipt_source,
)
from .lbe_r010_provider_job import R010CurrentJobSource
from .lbe_r010_provider_transport import R010GithubOwnerRead
from .lbe_r010_serial_journal import R010SerialNonceJournal
from .lbe_r010_source_service import R010ServiceSourceSession
from .workspaces import WorkspaceService


class R010ProductSourcePipelineDenied(ValueError):
    """Unqualified PREEXEC/Owner/Worker source or uncertain durable state."""


@dataclass(frozen=True, slots=True)
class R010ProductSourceCandidate:
    """Private nonoperative handoff, never a public Exec or native token."""

    session: R010ServiceSourceSession
    sealed_preexec: R010PreexecSourceSeal
    authority_source: R010AuthoritySourceBinding
    preimport_receipt: R010PreimportScrubReceipt
    status: str = "ONE_JOB_PROVIDER_OWNER_WORKER_SOURCE_ONLY_NO_T1"
    current_provider_job_authenticated: bool = False
    current_owner_grant_authenticated: bool = False
    native_launch_allowed: bool = False
    six_command_product_t1_pass: bool = False


def assemble_r010_a1_source_pipeline_only(
    *, service: WorkspaceService, workspace: str,
    envelope: R010CreatedJobEnvelope, job_key: R010JobKey,
    journal: R010SerialNonceJournal,
    preimport_receipt: R010PreimportScrubReceipt,
    preexec_source: R010PreexecSourceObservation,
    host: R010A1HostSource, closed: R010A1ClosedPreexecSource,
    owner_source: R010GithubOwnerRead,
    current_job: R010CurrentJobSource,
    grant_source: R010GrantSourceObservation,
    expected: R010GrantExpected,
) -> R010ProductSourceCandidate:
    """Execute exactly one nonspawning, fail-closed private Job source bind.

    The PREEXEC source is verified against supplied original JWT/JWKS by
    the separate predicate; this function only verifies its same-Job
    source identity and commits the bounded digest receipt. The trusted
    live Provider/Owner executable path is NOT wired into this function.
    """
    if (type(service) is not WorkspaceService
            or type(workspace) is not str or not workspace
            or type(envelope) is not R010CreatedJobEnvelope
            or type(job_key) is not R010JobKey
            or type(journal) is not R010SerialNonceJournal
            or type(preimport_receipt) is not R010PreimportScrubReceipt):
        raise R010ProductSourcePipelineDenied(
            "invalid original service/Job envelope source")
    try:
        # The stdlib-only scrub receipt is the first product boundary.  A
        # mismatch fails before durable PREEXEC/Provider records or row burn.
        validate_r010_preimport_receipt_source(
            preimport_receipt,
            head_sha=job_key.head_sha,
            run_id=str(job_key.run_id),
            run_attempt=str(job_key.run_attempt),
            job_name=job_key.job_name,
            helper_keys=closed.helper_keys,
            helper_env_sha256=closed.helper_env_sha256,
        )
        if preexec_source.helper_env_sha256 != preimport_receipt.helper_env_sha256:
            raise R010PreimportScrubDenied(
                "PREEXEC helper differs from pre-import scrub receipt")
        # Seal BEFORE checking any possible later Owner grant source;
        # source validation failure cannot leave a reusable PREEXEC Job.
        sealed = seal_r010_preexec_source_in_job(
            envelope=envelope, job_key=job_key,
            preexec=preexec_source, host=host, closed=closed,
            preimport_receipt=preimport_receipt)
        authority = bind_r010_authority_source_to_job(
            envelope=envelope, job_key=job_key, journal=journal,
            owner_source=owner_source, current_job=current_job,
            grant_source=grant_source, expected=expected)
        session = service._bind_r010_a1_composed_preexec_job_source_only(
            workspace, envelope=envelope, journal=journal,
            job_key=job_key, source=authority, host=host, closed=closed,
            preexec_source=preexec_source, preexec_seal=sealed,
            preimport_receipt=preimport_receipt)
        if (type(session) is not R010ServiceSourceSession
                or session.status().native_launch_allowed is not False
                or session.status().source_model_rows_completed != 0):
            raise R010ProductSourcePipelineDenied(
                "original source product session not held")
        return R010ProductSourceCandidate(
            session=session, sealed_preexec=sealed,
            authority_source=authority,
            preimport_receipt=preimport_receipt)
    except BaseException:
        try:
            if not journal._failed:
                journal.latch_failure("source_preexec_denied")
        except BaseException:
            journal._failed = True
        raise R010ProductSourcePipelineDenied(
            "one-Job provider/owner/worker source denied; no replay") from None
