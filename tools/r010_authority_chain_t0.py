"""R010 authorization-chain SAFE T0 model.

NON_RUNTIME_AUTHORITY: this module is deliberately isolated from gateway runtime.
It models version binding, provider-attested Job identity, one Job-global lease,
state provenance, serial six-row admission, and truthful row outcomes.  It does
not spawn subprocesses, open sockets, query SSH agents, or authorize PRODUCT_T1.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import hashlib

R010_DESIGN_ID = "MWE-LBE-R010-AUTHORITY-CHAIN-DESIGN-009-CANDIDATE"
R010_CHOICE_MARKER = "R010_OWNER_DESIGN_CHOICE_V1"
R010_GRANT_MARKER = "R010_OWNER_PRODUCT_T1_GRANT_V1"
R010_STATE_DOMAIN = "R010_EPHEMERAL_JOB_STATE_V1"
R010_PROVIDER_CONTRACT = "R010_GITHUB_OIDC_CHECK_RUN_V1"
R010_ROW_CONTRACT = "R010_SERIAL_EXIT0_FINITE_OBSERVED_DELTA_V1"
LEGACY_CHOICE_MARKERS = frozenset({
    "R006_OWNER_T1_GRANT_V1",
    "R008_OWNER_DESIGN_CHOICE_V1",
    "R008_OWNER_PRODUCT_T1_GRANT_V1",
    "R009_OWNER_PRODUCT_T1_GRANT_V1",
})

SIX_COMMAND_IDS = (
    "py-direct-pytest",
    "py-direct-compileall",
    "py-pipenv-pytest",
    "go-test",
    "go-vet",
    "go-build",
)


class GateDenied(ValueError):
    pass


class RowState(str, Enum):
    NOT_RUN = "ROW_NOT_RUN"
    RUNNING = "ROW_RUNNING"
    OBSERVED_NONZERO = "ROW_OBSERVED_NONZERO"
    OBSERVED_ZERO_INVALID = "ROW_OBSERVED_ZERO_INVALID_OUTPUT_OR_FS"
    POSITIVE_SUCCESS = "ROW_POSITIVE_SUCCESS"
    AMBIGUOUS = "ROW_AMBIGUOUS"
    VOID = "ROW_VOID"


class JobState(str, Enum):
    PREEXEC_HOLD = "JOB_PREEXEC_HOLD"
    READY = "JOB_READY_FOR_ROW"
    RUNNING = "JOB_ROW_RUNNING"
    FAILED = "JOB_FAILED_LATCHED"
    COMPLETE = "JOB_SIX_COMMAND_COMPLETE"


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("ascii")).hexdigest()


@dataclass(frozen=True, slots=True)
class DesignChoice:
    marker: str
    design_id: str
    design_blob: str
    b_design_review_id: str
    c_design_review_id: str
    host_option: str
    review_sequence_option: str
    risk_marker: str
    state_domain: str


@dataclass(frozen=True, slots=True)
class ImplementationQualification:
    design_id: str
    design_blob: str
    head_sha: str
    head_tree: str
    manifest_sha256: str
    b_t1_review_id: str
    c_t1_review_id: str
    review_target_id: str
    contract_scope_id: str


@dataclass(frozen=True, slots=True)
class ProviderWitness:
    """Result of a MOCK provider JWT verifier, not a JWT implementation."""

    signature_verified: bool
    issuer: str
    audience: str
    repository: str
    run_id: int
    run_attempt: int
    check_run_id: int
    workflow_ref: str
    workflow_sha: str
    head_sha: str
    runner_environment: str
    job_local_secret_sha256: str


@dataclass(frozen=True, slots=True)
class StateProvenance:
    state_domain: str
    provider_check_run_id: int
    github_hosted_ephemeral: bool
    workflow_restores_state: bool
    earlier_positive_gateway_step: bool
    canonical_root_absent_before_create: bool
    historic_conflicting_state: bool
    offline_owner_lock_created: bool
    existing_only_open_succeeded: bool


@dataclass(frozen=True, slots=True)
class ExecutionGrant:
    marker: str
    design_id: str
    design_blob: str
    design_choice_digest: str
    b_t1_review_id: str
    c_t1_review_id: str
    review_target_id: str
    contract_scope_id: str
    head_sha: str
    head_tree: str
    manifest_sha256: str
    run_id: int
    run_attempt: int
    check_run_id: int
    workflow_ref: str
    workflow_sha: str
    provider_contract: str
    job_local_secret_sha256: str
    state_domain: str
    job_envelope_key: str
    command_nonces: tuple[str, ...]


@dataclass(slots=True)
class SharedJobRegistry:
    """Models one platform anchor shared by all services in the SAME Job."""

    claimed_keys: set[str] = field(default_factory=set)

    def claim_once(self, key: str) -> None:
        if key in self.claimed_keys:
            raise GateDenied("job envelope already exists; no adoption/retry")
        self.claimed_keys.add(key)


@dataclass(slots=True)
class JobEnvelope:
    key: str
    canonical_config_root: str
    provider_check_run_id: int
    registry: SharedJobRegistry
    active: bool = False
    state: JobState = JobState.PREEXEC_HOLD
    expected_row: int = 0
    burned_nonces: set[str] = field(default_factory=set)
    row_states: list[RowState] = field(
        default_factory=lambda: [RowState.NOT_RUN for _ in SIX_COMMAND_IDS]
    )
    whole_host_writes_proven_absent: bool = False
    transient_source_mutation_proven_absent: bool = False

    @classmethod
    def create(
        cls,
        *,
        key: str,
        requested_config_root: str,
        canonical_config_root: str,
        provider_check_run_id: int,
        registry: SharedJobRegistry,
        state_provenance: StateProvenance,
    ) -> "JobEnvelope":
        validate_state_provenance(state_provenance, provider_check_run_id)
        if requested_config_root != canonical_config_root:
            raise GateDenied("caller-selected/alternate config root cannot be positive")
        registry.claim_once(key)
        return cls(
            key=key,
            canonical_config_root=canonical_config_root,
            provider_check_run_id=provider_check_run_id,
            registry=registry,
            active=True,
            state=JobState.READY,
        )

    def lose_authority(self) -> None:
        self.active = False
        if self.state not in (JobState.COMPLETE, JobState.FAILED):
            self.state = JobState.FAILED
            self._void_remaining()

    def begin_row(self, index: int, nonce: str, expected_nonce: str) -> None:
        if not self.active or self.state != JobState.READY:
            raise GateDenied("job envelope not ready")
        if index != self.expected_row:
            raise GateDenied("rows are globally serial; unexpected row index")
        if nonce != expected_nonce or nonce in self.burned_nonces:
            raise GateDenied("wrong/duplicate command nonce")
        self.burned_nonces.add(nonce)
        self.row_states[index] = RowState.RUNNING
        self.state = JobState.RUNNING

    def finish_row(
        self,
        index: int,
        *,
        exit_code: int | None,
        stdout_eof: bool,
        stderr_eof: bool,
        stdout_truncated: bool,
        stderr_truncated: bool,
        output_within_bound: bool,
        finite_observed_fs_ok: bool,
        original_child_unambiguous: bool,
        process_may_be_running: bool,
    ) -> RowState:
        if self.state != JobState.RUNNING or index != self.expected_row:
            raise GateDenied("row is not the currently running row")
        if not original_child_unambiguous or process_may_be_running or exit_code is None:
            result = RowState.AMBIGUOUS
        elif exit_code != 0:
            result = RowState.OBSERVED_NONZERO
        elif not (
            stdout_eof
            and stderr_eof
            and not stdout_truncated
            and not stderr_truncated
            and output_within_bound
            and finite_observed_fs_ok
        ):
            result = RowState.OBSERVED_ZERO_INVALID
        else:
            result = RowState.POSITIVE_SUCCESS

        self.row_states[index] = result
        if result != RowState.POSITIVE_SUCCESS:
            self.state = JobState.FAILED
            self._void_remaining()
            return result

        self.expected_row += 1
        if self.expected_row == len(SIX_COMMAND_IDS):
            self.state = JobState.COMPLETE
        else:
            self.state = JobState.READY
        return result

    def _void_remaining(self) -> None:
        for i, state in enumerate(self.row_states):
            if state == RowState.NOT_RUN:
                self.row_states[i] = RowState.VOID

    @property
    def six_command_pass(self) -> bool:
        return (
            self.state == JobState.COMPLETE
            and all(x == RowState.POSITIVE_SUCCESS for x in self.row_states)
        )


def design_choice_digest(choice: DesignChoice) -> str:
    fields = (
        choice.marker,
        choice.design_id,
        choice.design_blob,
        choice.b_design_review_id,
        choice.c_design_review_id,
        choice.host_option,
        choice.review_sequence_option,
        choice.risk_marker,
        choice.state_domain,
    )
    return _sha256_text("\n".join(fields))


def validate_design_choice(
    choice: DesignChoice,
    *,
    expected_design_blob: str,
    expected_b_review_id: str,
    expected_c_review_id: str,
) -> None:
    if choice.marker in LEGACY_CHOICE_MARKERS or choice.marker != R010_CHOICE_MARKER:
        raise GateDenied("legacy/wrong design choice marker")
    if choice.design_id != R010_DESIGN_ID or choice.design_blob != expected_design_blob:
        raise GateDenied("design version/blob mismatch")
    if (
        choice.b_design_review_id != expected_b_review_id
        or choice.c_design_review_id != expected_c_review_id
    ):
        raise GateDenied("design review identity mismatch")
    if choice.host_option not in ("A0", "A1"):
        raise GateDenied("invalid host option")
    if choice.review_sequence_option not in ("B0", "B1"):
        raise GateDenied("invalid review sequence option")
    if choice.state_domain != R010_STATE_DOMAIN:
        raise GateDenied("wrong state domain")
    if choice.host_option == "A1":
        expected = "R010_REAFFIRM_R006_RISK1_9_PLUS_RISK10_11"
    else:
        expected = "R010_REAFFIRM_R006_RISK1_9_NO_NEW_HOST_WEAKENING"
    if choice.risk_marker != expected:
        raise GateDenied("risk acceptance marker mismatch")


def validate_provider_witness(
    witness: ProviderWitness,
    *,
    design_blob: str,
    head_sha: str,
    repository: str,
    run_id: int,
    run_attempt: int,
    check_run_id: int,
    workflow_ref: str,
    workflow_sha: str,
    job_local_secret_sha256: str,
) -> None:
    audience = "mfg-r010:%s:%s:%s" % (
        design_blob,
        head_sha,
        job_local_secret_sha256,
    )
    if not witness.signature_verified:
        raise GateDenied("provider OIDC signature not verified")
    expected = (
        "https://token.actions.githubusercontent.com",
        audience,
        repository,
        run_id,
        run_attempt,
        check_run_id,
        workflow_ref,
        workflow_sha,
        head_sha,
        "github-hosted",
        job_local_secret_sha256,
    )
    actual = (
        witness.issuer,
        witness.audience,
        witness.repository,
        witness.run_id,
        witness.run_attempt,
        witness.check_run_id,
        witness.workflow_ref,
        witness.workflow_sha,
        witness.head_sha,
        witness.runner_environment,
        witness.job_local_secret_sha256,
    )
    if actual != expected:
        raise GateDenied("provider OIDC job witness mismatch")


def validate_state_provenance(
    state: StateProvenance,
    expected_check_run_id: int,
) -> None:
    if state.state_domain != R010_STATE_DOMAIN:
        raise GateDenied("wrong state domain")
    if state.provider_check_run_id != expected_check_run_id:
        raise GateDenied("state domain belongs to different Job")
    if not state.github_hosted_ephemeral:
        raise GateDenied("R010 state domain requires disposable github-hosted Job")
    if state.workflow_restores_state or state.earlier_positive_gateway_step:
        raise GateDenied("prior/restored positive state is forbidden")
    if not state.canonical_root_absent_before_create:
        raise GateDenied("pre-existing canonical root is permanent deny")
    if state.historic_conflicting_state:
        raise GateDenied("historic UNKNOWN/conflicting state blocks R010")
    if not state.offline_owner_lock_created or not state.existing_only_open_succeeded:
        raise GateDenied("owner.lock/existing-only admission not established")


def validate_execution_grant(
    grant: ExecutionGrant,
    *,
    choice: DesignChoice,
    qualification: ImplementationQualification,
    witness: ProviderWitness,
    expected_job_envelope_key: str,
) -> None:
    if grant.marker in LEGACY_CHOICE_MARKERS or grant.marker != R010_GRANT_MARKER:
        raise GateDenied("legacy/wrong execution grant marker")
    if grant.design_id != R010_DESIGN_ID or grant.design_blob != choice.design_blob:
        raise GateDenied("execution grant design mismatch")
    if grant.design_choice_digest != design_choice_digest(choice):
        raise GateDenied("execution grant choice digest mismatch")
    if (
        grant.b_t1_review_id != qualification.b_t1_review_id
        or grant.c_t1_review_id != qualification.c_t1_review_id
        or grant.review_target_id != qualification.review_target_id
        or grant.contract_scope_id != qualification.contract_scope_id
        or grant.head_sha != qualification.head_sha
        or grant.head_tree != qualification.head_tree
        or grant.manifest_sha256 != qualification.manifest_sha256
    ):
        raise GateDenied("implementation qualification mismatch")
    if grant.provider_contract != R010_PROVIDER_CONTRACT:
        raise GateDenied("wrong provider identity contract")
    if grant.state_domain != R010_STATE_DOMAIN:
        raise GateDenied("wrong execution state domain")
    if grant.job_envelope_key != expected_job_envelope_key:
        raise GateDenied("wrong Job envelope key")
    if len(grant.command_nonces) != 6 or len(set(grant.command_nonces)) != 6:
        raise GateDenied("six unique command nonces required")
    validate_provider_witness(
        witness,
        design_blob=choice.design_blob,
        head_sha=qualification.head_sha,
        repository="chinanjjohn2012/mac-file-gateway",
        run_id=grant.run_id,
        run_attempt=grant.run_attempt,
        check_run_id=grant.check_run_id,
        workflow_ref=grant.workflow_ref,
        workflow_sha=grant.workflow_sha,
        job_local_secret_sha256=grant.job_local_secret_sha256,
    )


def strict_exec_boundary_allows(
    *,
    r010_authority_valid: bool,
    f1_default_deny: bool,
    unknown_present: bool,
    owner_lock_present: bool,
    source_identity_ok: bool,
    runner_approved: bool,
) -> bool:
    return bool(
        r010_authority_valid
        and f1_default_deny
        and not unknown_present
        and owner_lock_present
        and source_identity_ok
        and runner_approved
    )


def adjacent_file_git_allowed(*, exec_denied: bool) -> bool:
    """Exec denial must not imply denial of separately lawful File/Git paths."""
    return bool(exec_denied)
