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
import re
from types import MappingProxyType
from urllib.parse import quote, urlsplit

R010_DESIGN_ID = "MWE-LBE-R010-AUTHORITY-CHAIN-DESIGN-012-CANDIDATE"
R012_OIDC_ENDPOINT_PROFILE = "R012_GITHUB_RUNNER_PIPELINES_OIDC_BASE_V1"
R012_OIDC_ENDPOINT_PATH = "/_apis/oidc/token"
R012_OIDC_ENDPOINT_QUERY = "api-version=2.0"
R010_PREEXEC_SELECTOR_CONTRACT = "R010_OIDC_PREEXEC_SELECTOR_V2"
R010_JWT_VERIFICATION_CONTRACT = "R010_PROVIDER_JWT_TEMPORAL_VERIFICATION_V1"
R008_PREEXEC_ALLOWED_KEYS = frozenset({
    "PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "GITHUB_ACTIONS",
    "GITHUB_EVENT_NAME", "GITHUB_REPOSITORY", "GITHUB_RUN_ID",
    "GITHUB_RUN_ATTEMPT", "GITHUB_JOB", "G05_EXPECTED_HEAD",
    "RUNNER_ENVIRONMENT", "RUNNER_OS", "RUNNER_ARCH", "ImageOS",
    "ImageVersion", "SSH_AUTH_SOCK",
})
OIDC_PREEXEC_ADDITIONAL_KEYS = frozenset({
    "ACTIONS_ID_TOKEN_REQUEST_URL", "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
})
PRODUCT_HELPER_ENV_KEYS = frozenset({"PATH", "HOME", "TMPDIR", "LANG", "LC_ALL"})
# Immutable source-reviewed offline-only extra child keys for this SAFE T0
# profile. No unreviewed Go/Pipenv variable or arbitrary recipe name can
# expand this policy via approved_child_keys. Exact values are mandatory.
R013_REVIEWED_CHILD_EXTRA_VALUES = MappingProxyType({
    "PYTHONUNBUFFERED": "1",
    "PYTHONDONTWRITEBYTECODE": "1",
    "PIP_NO_INDEX": "1",
    "PIP_DISABLE_PIP_VERSION_CHECK": "1",
})
R013_FORBIDDEN_CHILD_EXACT = frozenset({
    "SSH_AUTH_SOCK", "SSH_ASKPASS", "GIT_ASKPASS", "KRB5CCNAME",
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
    "PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "PIP_TRUSTED_HOST",
    "PIP_CONFIG_FILE", "PIPENV_DOTENV_LOCATION",
})
R013_FORBIDDEN_CHILD_PREFIXES = (
    "ACTIONS_ID_TOKEN_", "GITHUB_", "RUNNER_", "SSH_", "GIT_",
    "AWS_", "AZURE_", "GOOGLE_", "OIDC_", "GH_", "KRB5_",
    "IMAGE_", "Image", "HTTP_", "HTTPS_", "ALL_PROXY",
    "PIP_INDEX", "PIP_EXTRA_INDEX", "PIP_TRUSTED", "PIP_CONFIG",
    "PIPENV_",
)
R013_FORBIDDEN_CHILD_SUFFIXES = (
    "_TOKEN", "_PASSWORD", "_PASSWD", "_SECRET", "_KEY",
    "_CREDENTIAL", "_CREDENTIALS", "_AUTH", "_PROXY",
)
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
    review_sequence_option: str
    b_review_level: str
    c_review_level: str
    b_verdict: str
    c_verdict: str
    b_evidence_status: str
    c_evidence_status: str


@dataclass(frozen=True, slots=True)
class PreexecSelectorBoundary:
    """In-memory-only simulation of the exact future PREEXEC env handoff."""

    phase: str
    env_i_used: bool
    runner_context_source: bool
    bootstrap_items: tuple[tuple[str, str], ...]
    product_helper_items: tuple[tuple[str, str], ...]
    product_child_items: tuple[tuple[str, str], ...]
    ssh_metadata_only: bool
    ssh_agent_protocol_calls: int
    foreign_popen_calls: int
    pregrant_product_popen_calls: int
    scrub_before_product_import: bool
    oidc_redirect_count: int = 0  # source-only synthetic; actual HTTP not run


def _unique_env(items: object) -> dict[str, str]:
    if type(items) is not tuple or any(
        type(row) is not tuple or len(row) != 2
        or type(row[0]) is not str or type(row[1]) is not str
        for row in items
    ):
        raise GateDenied("invalid PREEXEC environment form")
    keys = [row[0] for row in items]
    if len(set(keys)) != len(keys):
        raise GateDenied("duplicate PREEXEC environment key")
    return dict(items)


def _validated_oidc_base_url_t0(raw_url: object) -> str:
    """Versioned candidate GitHub Runner profile; NO DNS/TLS/HTTP request.

    GitHub documents the runner-supplied URL and appended audience, NOT a
    permanent public request-path ABI. This only admits the reviewed
    /_apis/oidc/token?api-version=2.0 fixture. New provider path/shape must
    FAIL CLOSED until a newly reviewed profile is approved.
    """
    if (type(raw_url) is not str or not 1 <= len(raw_url) <= 4096
            or any(ord(c) < 33 or ord(c) > 126 for c in raw_url)
            or "\\" in raw_url):
        raise GateDenied("unqualified OIDC raw request URL")
    try:
        parsed = urlsplit(raw_url)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        raise GateDenied("malformed OIDC request URL") from None
    if (parsed.scheme != "https" or not hostname or port is not None
            or parsed.username is not None or parsed.password is not None
            or parsed.fragment or parsed.path != R012_OIDC_ENDPOINT_PATH
            or parsed.query != R012_OIDC_ENDPOINT_QUERY
            or parsed.netloc != hostname
            or re.fullmatch(
                r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.actions\.githubusercontent\.com",
                hostname, flags=re.ASCII
            ) is None):
        raise GateDenied("OIDC endpoint not in reviewed path/query/host profile")
    # Direct raw equality forbids percent escapes, duplicate/extra params,
    # semicolon/path normalization, trailing #, second ? and encoded bypass.
    canonical = (
        f"https://{hostname}{R012_OIDC_ENDPOINT_PATH}"
        f"?{R012_OIDC_ENDPOINT_QUERY}"
    )
    if raw_url != canonical:
        raise GateDenied("noncanonical OIDC endpoint representation")
    return canonical


def build_oidc_token_url_t0(raw_url: str, audience: str) -> str:
    """Pure offline canonical assembly; this function cannot send a bearer."""
    base = _validated_oidc_base_url_t0(raw_url)
    if (type(audience) is not str or re.fullmatch(
        r"mfg-r010:[0-9a-f]{40}:[0-9a-f]{40}:[0-9a-f]{64}",
        audience, flags=re.ASCII
    ) is None):
        raise GateDenied("unqualified R010 audience")
    # Exactly one canonical appended audience; URL base already disallows it.
    return base + "&audience=" + quote(audience, safe="")


def _r013_forbidden_child_selector_name(key: object) -> bool:
    """Immutable hard DENY: a caller-selected recipe cannot weaken it."""
    if (type(key) is not str
            or re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", key,
                            flags=re.ASCII) is None):
        return True
    return (key in R013_FORBIDDEN_CHILD_EXACT
            or key.startswith(R013_FORBIDDEN_CHILD_PREFIXES)
            or key.endswith(R013_FORBIDDEN_CHILD_SUFFIXES)
            or "PROXY" in key
            or "TOKEN" in key
            or "SECRET" in key
            or "PASSWORD" in key)


def validate_preexec_selector_boundary_t0(
    item: PreexecSelectorBoundary, *,
    expected_run_id: str, expected_run_attempt: str,
    expected_head: str, expected_image: str,
    expected_job: str, expected_home: str, expected_tmp: str,
    approved_child_keys: frozenset[str] = PRODUCT_HELPER_ENV_KEYS,
) -> None:
    """SAFE T0 ONLY. Never reads an OS env or requests an OIDC token.

    No boolean/input field in this model is trusted runtime authority. The
    future pinned PREEXEC implementation and B/C native qualification must
    establish the observations independently before any Popen.
    """
    if type(item) is not PreexecSelectorBoundary:
        raise GateDenied("invalid PREEXEC receipt")
    if (item.phase != "PREEXEC_HOLD" or item.env_i_used is not True
            or item.runner_context_source is not True
            or item.ssh_metadata_only is not True
            or item.scrub_before_product_import is not True
            or type(item.ssh_agent_protocol_calls) is not int
            or item.ssh_agent_protocol_calls != 0
            or type(item.foreign_popen_calls) is not int
            or item.foreign_popen_calls != 0
            or type(item.pregrant_product_popen_calls) is not int
            or item.pregrant_product_popen_calls != 0
            or type(item.oidc_redirect_count) is not int
            or item.oidc_redirect_count != 0):
        raise GateDenied("PREEXEC stage/selector/zero-Popen boundary violated")
    bootstrap = _unique_env(item.bootstrap_items)
    helper = _unique_env(item.product_helper_items)
    child = _unique_env(item.product_child_items)
    if set(bootstrap) != (R008_PREEXEC_ALLOWED_KEYS | OIDC_PREEXEC_ADDITIONAL_KEYS):
        raise GateDenied("PREEXEC bootstrap keys not the exact versioned allowlist")
    if set(helper) != PRODUCT_HELPER_ENV_KEYS:
        raise GateDenied("product helper contains extra credential/selector keys")
    if type(approved_child_keys) is not frozenset:
        raise GateDenied("child recipe keys must be a reviewed exact frozenset")
    # Independently hard-reject protected names in both the requested recipe
    # and actual child. No user-configurable allowlist override can opt in.
    if any(_r013_forbidden_child_selector_name(k)
           for k in approved_child_keys | frozenset(child)):
        raise GateDenied("forbidden child credential selector name")
    reviewed = PRODUCT_HELPER_ENV_KEYS | frozenset(R013_REVIEWED_CHILD_EXTRA_VALUES)
    if (not PRODUCT_HELPER_ENV_KEYS.issubset(approved_child_keys)
            or not approved_child_keys.issubset(reviewed)
            or set(child) != approved_child_keys):
        raise GateDenied("child differs from immutable reviewed exact recipe")
    if any(child.get(k) != expected
           for k, expected in R013_REVIEWED_CHILD_EXTRA_VALUES.items()
           if k in approved_child_keys):
        raise GateDenied("reviewed child safe-key value mismatch")
    expected = {
        "PATH": "/usr/bin:/bin", "HOME": expected_home,
        "TMPDIR": expected_tmp, "LANG": "C", "LC_ALL": "C",
        "GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "pull_request",
        "GITHUB_REPOSITORY": "chinanjjohn2012/mac-file-gateway",
        "GITHUB_RUN_ID": expected_run_id,
        "GITHUB_RUN_ATTEMPT": expected_run_attempt,
        "GITHUB_JOB": expected_job, "G05_EXPECTED_HEAD": expected_head,
        "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "macOS",
        "RUNNER_ARCH": "ARM64", "ImageOS": "macos15",
        "ImageVersion": expected_image,
    }
    if (type(expected_run_attempt) is not str
            or re.fullmatch(r"[1-9][0-9]{0,11}", expected_run_attempt,
                            flags=re.ASCII) is None):
        raise GateDenied("unqualified expected run attempt")
    if any(bootstrap.get(k) != v for k, v in expected.items()):
        raise GateDenied("PREEXEC expected Job/Head/image identity mismatch")
    if (not bootstrap["SSH_AUTH_SOCK"].startswith("/")
            or "\x00" in bootstrap["SSH_AUTH_SOCK"]
            or ".." in bootstrap["SSH_AUTH_SOCK"].split("/")
            or len(bootstrap["SSH_AUTH_SOCK"]) > 4096):
        raise GateDenied("SSH selector not a bounded canonical absolute path")
    raw_token = bootstrap["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]
    raw_url = bootstrap["ACTIONS_ID_TOKEN_REQUEST_URL"]
    if not 16 <= len(raw_token) <= 8192 or any(ord(ch) < 33 for ch in raw_token):
        raise GateDenied("invalid OIDC request bearer selector")
    _validated_oidc_base_url_t0(raw_url)
    if any(helper.get(k) != bootstrap[k] for k in PRODUCT_HELPER_ENV_KEYS):
        raise GateDenied("post-PREEXEC helper environment changed")
    if any(child.get(k) != bootstrap[k] for k in PRODUCT_HELPER_ENV_KEYS & approved_child_keys):
        raise GateDenied("reviewed child base environment changed")
    # Renaming a selector does not make its literal value permissible.
    # This is still source-only: real secret transformations require a
    # later reviewed runtime origin/credential flow check.
    forbidden_values = (raw_token, raw_url, bootstrap["SSH_AUTH_SOCK"])
    if any(type(value) is not str or any(secret in value for secret in forbidden_values)
           for value in (*helper.values(), *child.values())):
        raise GateDenied("bootstrap credential/SSH selector forwarded")


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
class JWTVerificationReceipt:
    """MOCK ONLY. The future verifier must check real signed JWT bytes."""

    token_sha256: str
    jwks_sha256: str
    verification_transcript_sha256: str
    jose_alg: str
    jose_typ: str
    jose_kid: str
    github_jwks_source_verified: bool
    kid_matches_verified_jwks: bool
    original_signed_bytes_verified: bool
    original_jwt_independently_replayable: bool
    signed_check_run_id: int
    signed_subject: str
    issued_at: int
    not_before: int
    expires_at: int
    verified_at: int
    grant_checked_at: int
    current_job_in_progress: bool


def validate_provider_freshness_t0(
    item: JWTVerificationReceipt, *,
    expected_token_sha256: str,
    expected_transcript_sha256: str,
    expected_check_run_id: int,
    expected_subject: str,
) -> None:
    """Pure mocked receipt oracle, NOT JWT parsing/signature verification.

    T1 MUST reverify actual JWT signed-input bytes against trusted issuer
    discovery + JWKS and independently inspect the raw bytes nonpublicly.
    Caller-set booleans cannot create executable authority.
    """
    if type(item) is not JWTVerificationReceipt:
        raise GateDenied("invalid provider verification receipt")
    for digest in (
        item.token_sha256, item.jwks_sha256,
        item.verification_transcript_sha256, expected_token_sha256,
        expected_transcript_sha256,
    ):
        if (type(digest) is not str or len(digest) != 64
                or any(c not in "0123456789abcdef" for c in digest)):
            raise GateDenied("invalid attestation evidence digest")
    if (item.token_sha256 != expected_token_sha256
            or item.verification_transcript_sha256 != expected_transcript_sha256):
        raise GateDenied("JWT original/token transcript not bound to grant")
    if (item.jose_alg != "RS256" or item.jose_typ != "JWT"
            or type(item.jose_kid) is not str
            or not 1 <= len(item.jose_kid) <= 128
            or item.github_jwks_source_verified is not True
            or item.kid_matches_verified_jwks is not True
            or item.original_signed_bytes_verified is not True
            or item.original_jwt_independently_replayable is not True):
        raise GateDenied("JWT signature/JOSE/JWKS/original evidence not verified")
    if (type(item.signed_check_run_id) is not int
            or item.signed_check_run_id != expected_check_run_id
            or type(expected_subject) is not str or not expected_subject
            or type(item.signed_subject) is not str
            or not item.signed_subject or item.signed_subject != expected_subject
            or item.current_job_in_progress is not True):
        raise GateDenied("JWT signed Job/subject/current status mismatch")
    times = (
        item.issued_at, item.not_before, item.expires_at,
        item.verified_at, item.grant_checked_at,
    )
    if any(type(t) is not int or t <= 0 for t in times):
        raise GateDenied("JWT invalid timestamp field")
    if (item.expires_at <= item.issued_at
            or item.expires_at - item.issued_at > 600
            or item.issued_at - item.not_before > 600
            or item.not_before > item.verified_at + 30
            or item.issued_at > item.verified_at + 30
            or item.verified_at - item.issued_at > 120
            or item.verified_at >= item.expires_at
            or item.grant_checked_at < item.verified_at
            or item.grant_checked_at - item.verified_at > 120
            or item.grant_checked_at >= item.expires_at):
        raise GateDenied("JWT expired/not-yet-valid/stale/clock window")


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
    host_option: str
    review_sequence_option: str
    risk_marker: str
    b_design_review_id: str
    c_design_review_id: str
    oidc_token_sha256: str
    oidc_verification_transcript_sha256: str
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


@dataclass(frozen=True, slots=True)
class OwnedRowObservationT0:
    """Single synthetic attempt-bound Owner+Worker result. NOT runtime proof.

    In a future reviewed implementation, the owner reservation and identity
    must be pinned PRIVATE object identities from the SAME DirectChildOwner
    wait()/reap call and Worker invocation. REST/MCP/client cannot construct
    a positive record. Here the fields are wholly test-only.
    """

    attempt_nonce: str
    owner_attempt_nonce: str
    worker_attempt_nonce: str
    owner_reservation: object
    worker_reservation: object
    owner_status: str
    owner_exit_code: int | None
    original_child_reaped: bool
    original_child_unambiguous: bool
    worker_status: str
    worker_executed: bool
    worker_timed_out: bool
    worker_exit_code: int | None
    worker_cancelled: bool
    ack_lost: bool
    # Source-only evidence from the SAME private reader and Owner state.
    worker_pipe_reader_failed: bool
    owner_pipe_reader_failed: bool
    pipe_reader_finished: bool
    owner_unavailable: bool
    owner_closing: bool
    stdout_eof: bool
    stderr_eof: bool
    stdout_truncated: bool
    stderr_truncated: bool
    output_within_bound: bool
    finite_observed_fs_ok: bool
    process_may_be_running: bool
    cleanup_proven: bool
    full_descendant_tree_clean: str


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
    active_attempt_nonce: str | None = None
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
        self.active_attempt_nonce = nonce
        self.row_states[index] = RowState.RUNNING
        self.state = JobState.RUNNING

    def finish_row(self, index: int, *, observation: OwnedRowObservationT0) -> RowState:
        """One fail-closed classification of matching private Owner+Worker facts.

        This is a mock policy oracle, NOT credential source or runtime API.
        The actual Worker never claims descendant cleanup after direct reap.
        """
        if self.state != JobState.RUNNING or index != self.expected_row:
            raise GateDenied("row is not the currently running row")
        current = self.active_attempt_nonce
        valid = (
            type(observation) is OwnedRowObservationT0
            and type(current) is str and bool(current)
            and type(observation.attempt_nonce) is str
            and observation.attempt_nonce == current
            and type(observation.owner_attempt_nonce) is str
            and observation.owner_attempt_nonce == current
            and type(observation.worker_attempt_nonce) is str
            and observation.worker_attempt_nonce == current
            and observation.owner_reservation is not None
            and observation.owner_reservation is observation.worker_reservation
            and observation.owner_status == "exited"
            and observation.original_child_reaped is True
            and observation.original_child_unambiguous is True
            and observation.worker_status == "exited"
            and observation.worker_executed is True
            and observation.worker_timed_out is False
            and observation.worker_cancelled is False
            and observation.ack_lost is False
            and observation.worker_pipe_reader_failed is False
            and observation.owner_pipe_reader_failed is False
            and observation.pipe_reader_finished is True
            and observation.owner_unavailable is False
            and observation.owner_closing is False
            and type(observation.owner_exit_code) is int
            and type(observation.worker_exit_code) is int
            and observation.owner_exit_code == observation.worker_exit_code
            and type(observation.process_may_be_running) is bool
            and observation.cleanup_proven is False
            and observation.full_descendant_tree_clean == "not_proven"
        )
        if not valid:
            # Any untrusted/mismatching attempt, cancelled/lost-ACK waiter,
            # timed-out Worker, reader fault (even AFTER EOF), unhealthy
            # Owner, unfinished drain, missing reap or disagreement is
            # ambiguous,
            # even with a forged exit code zero and both streams complete.
            result = RowState.AMBIGUOUS
        elif observation.owner_exit_code != 0:
            result = RowState.OBSERVED_NONZERO
        elif not (
            observation.stdout_eof is True
            and observation.stderr_eof is True
            and observation.stdout_truncated is False
            and observation.stderr_truncated is False
            and observation.output_within_bound is True
            and observation.finite_observed_fs_ok is True
        ):
            result = RowState.OBSERVED_ZERO_INVALID
        else:
            result = RowState.POSITIVE_SUCCESS

        self.row_states[index] = result
        self.active_attempt_nonce = None
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
    verification: JWTVerificationReceipt,
    expected_design_blob: str,
    expected_b_design_review_id: str,
    expected_c_design_review_id: str,
    expected_provider_subject: str,
    expected_job_envelope_key: str,
) -> None:
    """Composed R010 SAFE-T0 version/receipt validation; not live authority."""
    if type(grant) is not ExecutionGrant or type(qualification) is not ImplementationQualification:
        raise GateDenied("invalid R010 grant/qualification object")
    # No digest may rehabilitate an invalid caller-supplied legacy Choice.
    validate_design_choice(
        choice,
        expected_design_blob=expected_design_blob,
        expected_b_review_id=expected_b_design_review_id,
        expected_c_review_id=expected_c_design_review_id,
    )
    if grant.marker in LEGACY_CHOICE_MARKERS or grant.marker != R010_GRANT_MARKER:
        raise GateDenied("legacy/wrong execution grant marker")
    if (
        grant.design_id != R010_DESIGN_ID
        or grant.design_blob != expected_design_blob
        or grant.design_blob != qualification.design_blob
        or qualification.design_id != R010_DESIGN_ID
        or qualification.review_sequence_option != choice.review_sequence_option
    ):
        raise GateDenied("execution/qualification design or option mismatch")
    if grant.design_choice_digest != design_choice_digest(choice):
        raise GateDenied("execution grant choice digest mismatch")
    if (
        grant.host_option != choice.host_option
        or grant.review_sequence_option != choice.review_sequence_option
        or grant.risk_marker != choice.risk_marker
        or grant.b_design_review_id != expected_b_design_review_id
        or grant.c_design_review_id != expected_c_design_review_id
    ):
        raise GateDenied("execution grant owner choice/review mismatch")
    expected_review_level = (
        "ROLE_FULL_SCOPE_PASS" if choice.review_sequence_option == "B0"
        else "TARGETED_REVIEW_PASS"
    )
    if (
        qualification.b_review_level != expected_review_level
        or qualification.c_review_level != expected_review_level
        or qualification.b_verdict != "PASS" or qualification.c_verdict != "PASS"
        or qualification.b_evidence_status != "SUFFICIENT"
        or qualification.c_evidence_status != "SUFFICIENT"
        or not qualification.b_t1_review_id
        or not qualification.c_t1_review_id
        or qualification.b_t1_review_id == qualification.c_t1_review_id
        or qualification.review_target_id != "R010_COMPLETE_PRE_T1_CRITICAL_PATH_V1"
        or qualification.contract_scope_id != "R010_IMPLEMENTATION_CONTRACT_V1"
    ):
        raise GateDenied("B0 FULL-before-T1 / B1 TARGETED qualification mismatch")
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
    if (type(grant.command_nonces) is not tuple
            or len(grant.command_nonces) != 6
            or len(set(grant.command_nonces)) != 6):
        raise GateDenied("six unique command nonces required")
    validate_provider_witness(
        witness,
        design_blob=expected_design_blob,
        head_sha=qualification.head_sha,
        repository="chinanjjohn2012/mac-file-gateway",
        run_id=grant.run_id,
        run_attempt=grant.run_attempt,
        check_run_id=grant.check_run_id,
        workflow_ref=grant.workflow_ref,
        workflow_sha=grant.workflow_sha,
        job_local_secret_sha256=grant.job_local_secret_sha256,
    )
    validate_provider_freshness_t0(
        verification,
        expected_token_sha256=grant.oidc_token_sha256,
        expected_transcript_sha256=grant.oidc_verification_transcript_sha256,
        expected_check_run_id=grant.check_run_id,
        expected_subject=expected_provider_subject,
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
