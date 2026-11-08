import hashlib
from dataclasses import replace
from pathlib import Path

import pytest

from tools.r010_authority_chain_t0 import (
    DesignChoice,
    ExecutionGrant,
    GateDenied,
    ImplementationQualification,
    JobEnvelope,
    JobState,
    OwnedRowObservationT0,
    JWTVerificationReceipt,
    PreexecSelectorBoundary,
    ProviderWitness,
    R010_CHOICE_MARKER,
    R010_DESIGN_ID,
    R010_GRANT_MARKER,
    R010_PROVIDER_CONTRACT,
    R010_STATE_DOMAIN,
    RowState,
    SharedJobRegistry,
    StateProvenance,
    adjacent_file_git_allowed,
    build_oidc_token_url_t0,
    design_choice_digest,
    strict_exec_boundary_allows,
    validate_design_choice,
    validate_execution_grant,
    validate_provider_witness,
    validate_preexec_selector_boundary_t0,
    validate_provider_freshness_t0,
)

def _git_object_design_blob_from_actual_source():
    """Immutable design-file bytes, not a fabricated 40-character test Blob."""
    raw = (
        Path(__file__).resolve().parents[1]
        / "docs/MULTI_WORKSPACE_EXEC_LBE_R010_AUTHORITY_CHAIN_CONTRACT.md"
    ).read_bytes()
    return hashlib.sha1(
        b"blob " + str(len(raw)).encode("ascii") + b"\x00" + raw
    ).hexdigest()


DESIGN_BLOB = _git_object_design_blob_from_actual_source()
HEAD = "b" * 40
TREE = "c" * 40
MANIFEST = "d" * 64
B_DESIGN = "PRR_r010_design_b"
C_DESIGN = "PRR_r010_design_c"
B_T1 = "PRR_r010_t1_b"
C_T1 = "PRR_r010_t1_c"
CHECK_RUN = 51725241954
RUN = 42480000000
ATTEMPT = 1
WORKFLOW_REF = (
    "chinanjjohn2012/mac-file-gateway/.github/workflows/"
    "r010-product-t1.yml@refs/pull/114/merge"
)
WORKFLOW_SHA = "e" * 40
SECRET_HASH = hashlib.sha256(b"job-local-secret").hexdigest()
ENVELOPE_KEY = hashlib.sha256(b"r010-envelope").hexdigest()
CANONICAL_CONFIG = "/private/tmp/mfg-r010-job-abc/service-config"
OIDC_TOKEN_DIGEST = "f" * 64
JWT_TRANSCRIPT_DIGEST = "9" * 64
JWKS_DIGEST = "8" * 64
EXPECTED_PROVIDER_SUBJECT = "repo:chinanjjohn2012/mac-file-gateway:pull_request"


def choice(marker=R010_CHOICE_MARKER, design_id=R010_DESIGN_ID, blob=DESIGN_BLOB):
    return DesignChoice(
        marker=marker,
        design_id=design_id,
        design_blob=blob,
        b_design_review_id=B_DESIGN,
        c_design_review_id=C_DESIGN,
        host_option="A1",
        review_sequence_option="B1",
        risk_marker="R010_REAFFIRM_R006_RISK1_9_PLUS_RISK10_11",
        state_domain=R010_STATE_DOMAIN,
    )


def qualification():
    return ImplementationQualification(
        design_id=R010_DESIGN_ID,
        design_blob=DESIGN_BLOB,
        head_sha=HEAD,
        head_tree=TREE,
        manifest_sha256=MANIFEST,
        b_t1_review_id=B_T1,
        c_t1_review_id=C_T1,
        review_target_id="R010_COMPLETE_PRE_T1_CRITICAL_PATH_V1",
        contract_scope_id="R010_IMPLEMENTATION_CONTRACT_V1",
        review_sequence_option="B1",
        b_review_level="TARGETED_REVIEW_PASS",
        c_review_level="TARGETED_REVIEW_PASS",
        b_verdict="PASS", c_verdict="PASS",
        b_evidence_status="SUFFICIENT", c_evidence_status="SUFFICIENT",
    )


def witness(**changes):
    audience = f"mfg-r010:{DESIGN_BLOB}:{HEAD}:{SECRET_HASH}"
    values = dict(
        signature_verified=True,
        issuer="https://token.actions.githubusercontent.com",
        audience=audience,
        repository="chinanjjohn2012/mac-file-gateway",
        run_id=RUN,
        run_attempt=ATTEMPT,
        check_run_id=CHECK_RUN,
        workflow_ref=WORKFLOW_REF,
        workflow_sha=WORKFLOW_SHA,
        head_sha=HEAD,
        runner_environment="github-hosted",
        job_local_secret_sha256=SECRET_HASH,
    )
    values.update(changes)
    return ProviderWitness(**values)


def verification_receipt(**changes):
    """Synthetic receipt, not actual signed JWT verification."""
    values = dict(
        token_sha256=OIDC_TOKEN_DIGEST,
        jwks_sha256=JWKS_DIGEST,
        verification_transcript_sha256=JWT_TRANSCRIPT_DIGEST,
        jose_alg="RS256", jose_typ="JWT", jose_kid="mock-provider-rsa-key-01",
        github_jwks_source_verified=True, kid_matches_verified_jwks=True,
        original_signed_bytes_verified=True,
        original_jwt_independently_replayable=True,
        signed_check_run_id=CHECK_RUN,
        signed_subject=EXPECTED_PROVIDER_SUBJECT,
        issued_at=1_000_000, not_before=999_999, expires_at=1_000_300,
        verified_at=1_000_015, grant_checked_at=1_000_025,
        current_job_in_progress=True,
    )
    values.update(changes)
    return JWTVerificationReceipt(**values)


def provenance(**changes):
    values = dict(
        state_domain=R010_STATE_DOMAIN,
        provider_check_run_id=CHECK_RUN,
        github_hosted_ephemeral=True,
        workflow_restores_state=False,
        earlier_positive_gateway_step=False,
        canonical_root_absent_before_create=True,
        historic_conflicting_state=False,
        offline_owner_lock_created=True,
        existing_only_open_succeeded=True,
    )
    values.update(changes)
    return StateProvenance(**values)


def grant(**changes):
    ch = choice()
    q = qualification()
    values = dict(
        marker=R010_GRANT_MARKER,
        design_id=R010_DESIGN_ID,
        design_blob=DESIGN_BLOB,
        design_choice_digest=design_choice_digest(ch),
        b_t1_review_id=B_T1,
        c_t1_review_id=C_T1,
        review_target_id=q.review_target_id,
        contract_scope_id=q.contract_scope_id,
        host_option=ch.host_option,
        review_sequence_option=ch.review_sequence_option,
        risk_marker=ch.risk_marker,
        b_design_review_id=B_DESIGN,
        c_design_review_id=C_DESIGN,
        oidc_token_sha256=OIDC_TOKEN_DIGEST,
        oidc_verification_transcript_sha256=JWT_TRANSCRIPT_DIGEST,
        head_sha=HEAD,
        head_tree=TREE,
        manifest_sha256=MANIFEST,
        run_id=RUN,
        run_attempt=ATTEMPT,
        check_run_id=CHECK_RUN,
        workflow_ref=WORKFLOW_REF,
        workflow_sha=WORKFLOW_SHA,
        provider_contract=R010_PROVIDER_CONTRACT,
        job_local_secret_sha256=SECRET_HASH,
        state_domain=R010_STATE_DOMAIN,
        job_envelope_key=ENVELOPE_KEY,
        command_nonces=tuple(f"{i:064x}" for i in range(1, 7)),
    )
    values.update(changes)
    return ExecutionGrant(**values)


def test_r008_owner_choice_cannot_authorize_r010_but_exact_r010_can():
    with pytest.raises(GateDenied, match="legacy/wrong"):
        validate_design_choice(
            choice(marker="R008_OWNER_DESIGN_CHOICE_V1"),
            expected_design_blob=DESIGN_BLOB,
            expected_b_review_id=B_DESIGN,
            expected_c_review_id=C_DESIGN,
        )
    validate_design_choice(
        choice(),
        expected_design_blob=DESIGN_BLOB,
        expected_b_review_id=B_DESIGN,
        expected_c_review_id=C_DESIGN,
    )


def test_provider_signed_check_run_binds_pregrant_job_and_sibling_is_denied():
    validate_provider_witness(
        witness(),
        design_blob=DESIGN_BLOB,
        head_sha=HEAD,
        repository="chinanjjohn2012/mac-file-gateway",
        run_id=RUN,
        run_attempt=ATTEMPT,
        check_run_id=CHECK_RUN,
        workflow_ref=WORKFLOW_REF,
        workflow_sha=WORKFLOW_SHA,
        job_local_secret_sha256=SECRET_HASH,
    )
    with pytest.raises(GateDenied):
        validate_provider_witness(
            witness(check_run_id=CHECK_RUN + 1),
            design_blob=DESIGN_BLOB,
            head_sha=HEAD,
            repository="chinanjjohn2012/mac-file-gateway",
            run_id=RUN,
            run_attempt=ATTEMPT,
            check_run_id=CHECK_RUN,
            workflow_ref=WORKFLOW_REF,
            workflow_sha=WORKFLOW_SHA,
            job_local_secret_sha256=SECRET_HASH,
        )
    with pytest.raises(GateDenied, match="signature"):
        validate_provider_witness(
            witness(signature_verified=False),
            design_blob=DESIGN_BLOB,
            head_sha=HEAD,
            repository="chinanjjohn2012/mac-file-gateway",
            run_id=RUN,
            run_attempt=ATTEMPT,
            check_run_id=CHECK_RUN,
            workflow_ref=WORKFLOW_REF,
            workflow_sha=WORKFLOW_SHA,
            job_local_secret_sha256=SECRET_HASH,
        )


def test_same_job_two_config_roots_only_canonical_service_can_claim():
    registry = SharedJobRegistry()
    first = JobEnvelope.create(
        key=ENVELOPE_KEY,
        requested_config_root=CANONICAL_CONFIG,
        canonical_config_root=CANONICAL_CONFIG,
        provider_check_run_id=CHECK_RUN,
        registry=registry,
        state_provenance=provenance(),
    )
    assert first.active and first.state == JobState.READY
    with pytest.raises(GateDenied, match="alternate config root"):
        JobEnvelope.create(
            key=ENVELOPE_KEY,
            requested_config_root="/private/tmp/other/service-config",
            canonical_config_root=CANONICAL_CONFIG,
            provider_check_run_id=CHECK_RUN,
            registry=registry,
            state_provenance=provenance(),
        )
    with pytest.raises(GateDenied, match="already exists"):
        JobEnvelope.create(
            key=ENVELOPE_KEY,
            requested_config_root=CANONICAL_CONFIG,
            canonical_config_root=CANONICAL_CONFIG,
            provider_check_run_id=CHECK_RUN,
            registry=registry,
            state_provenance=provenance(),
        )


def test_restart_lost_ack_or_ledger_loss_never_reacquires_job():
    registry = SharedJobRegistry()
    env = JobEnvelope.create(
        key=ENVELOPE_KEY,
        requested_config_root=CANONICAL_CONFIG,
        canonical_config_root=CANONICAL_CONFIG,
        provider_check_run_id=CHECK_RUN,
        registry=registry,
        state_provenance=provenance(),
    )
    env.lose_authority()
    assert env.state == JobState.FAILED
    with pytest.raises(GateDenied, match="already exists"):
        JobEnvelope.create(
            key=ENVELOPE_KEY,
            requested_config_root=CANONICAL_CONFIG,
            canonical_config_root=CANONICAL_CONFIG,
            provider_check_run_id=CHECK_RUN,
            registry=registry,
            state_provenance=provenance(),
        )


@pytest.mark.parametrize(
    "bad",
    [
        dict(workflow_restores_state=True),
        dict(earlier_positive_gateway_step=True),
        dict(canonical_root_absent_before_create=False),
        dict(historic_conflicting_state=True),
        dict(offline_owner_lock_created=False),
        dict(existing_only_open_succeeded=False),
        dict(provider_check_run_id=CHECK_RUN + 1),
    ],
)
def test_fresh_ephemeral_state_provenance_fails_closed_on_old_unknown_or_lock_gap(bad):
    with pytest.raises(GateDenied):
        JobEnvelope.create(
            key=ENVELOPE_KEY,
            requested_config_root=CANONICAL_CONFIG,
            canonical_config_root=CANONICAL_CONFIG,
            provider_check_run_id=CHECK_RUN,
            registry=SharedJobRegistry(),
            state_provenance=provenance(**bad),
        )


def test_execution_grant_binds_only_r010_version_reviews_and_provider_job():
    validate_execution_grant(
        grant(),
        choice=choice(),
        qualification=qualification(),
        witness=witness(),
        expected_job_envelope_key=ENVELOPE_KEY,
            verification=verification_receipt(),
            expected_design_blob=DESIGN_BLOB,
            expected_b_design_review_id=B_DESIGN,
            expected_c_design_review_id=C_DESIGN,
            expected_provider_subject=EXPECTED_PROVIDER_SUBJECT,
    )
    with pytest.raises(GateDenied, match="legacy/wrong"):
        validate_execution_grant(
            grant(marker="R009_OWNER_PRODUCT_T1_GRANT_V1"),
            choice=choice(),
            qualification=qualification(),
            witness=witness(),
            expected_job_envelope_key=ENVELOPE_KEY,
            verification=verification_receipt(),
            expected_design_blob=DESIGN_BLOB,
            expected_b_design_review_id=B_DESIGN,
            expected_c_design_review_id=C_DESIGN,
            expected_provider_subject=EXPECTED_PROVIDER_SUBJECT,
        )
    with pytest.raises(GateDenied, match="provider OIDC"):
        validate_execution_grant(
            grant(),
            choice=choice(),
            qualification=qualification(),
            witness=witness(check_run_id=CHECK_RUN + 1),
            expected_job_envelope_key=ENVELOPE_KEY,
            verification=verification_receipt(),
            expected_design_blob=DESIGN_BLOB,
            expected_b_design_review_id=B_DESIGN,
            expected_c_design_review_id=C_DESIGN,
            expected_provider_subject=EXPECTED_PROVIDER_SUBJECT,
        )


def _envelope():
    return JobEnvelope.create(
        key=ENVELOPE_KEY,
        requested_config_root=CANONICAL_CONFIG,
        canonical_config_root=CANONICAL_CONFIG,
        provider_check_run_id=CHECK_RUN,
        registry=SharedJobRegistry(),
        state_provenance=provenance(),
    )


def _row_observation(nonce, **changes):
    """Source-only frozen mock, NOT a runtime/caller-mintable witness."""
    reservation = object()
    values = dict(
        attempt_nonce=nonce,
        owner_attempt_nonce=nonce,
        worker_attempt_nonce=nonce,
        owner_reservation=reservation,
        worker_reservation=reservation,
        owner_status="exited",
        owner_exit_code=0,
        original_child_reaped=True,
        original_child_unambiguous=True,
        worker_status="exited",
        worker_executed=True,
        worker_timed_out=False,
        worker_exit_code=0,
        worker_cancelled=False,
        ack_lost=False,
        worker_pipe_reader_failed=False,
        owner_pipe_reader_failed=False,
        pipe_reader_finished=True,
        owner_unavailable=False,
        owner_closing=False,
        stdout_eof=True,
        stderr_eof=True,
        stdout_truncated=False,
        stderr_truncated=False,
        output_within_bound=True,
        finite_observed_fs_ok=True,
        process_may_be_running=True,   # descendants intentionally not proven
        cleanup_proven=False,
        full_descendant_tree_clean="not_proven",
    )
    values.update(changes)
    return OwnedRowObservationT0(**values)


def _success(env, index, nonce):
    env.begin_row(index, nonce, nonce)
    return env.finish_row(index, observation=_row_observation(nonce))


def test_rows_are_globally_serial_across_workspaces():
    env = _envelope()
    nonces = grant().command_nonces
    env.begin_row(0, nonces[0], nonces[0])
    with pytest.raises(GateDenied, match="not ready|unexpected"):
        env.begin_row(4, nonces[4], nonces[4])
    assert env.finish_row(
        0, observation=_row_observation(nonces[0]),
    ) == RowState.POSITIVE_SUCCESS
    assert env.expected_row == 1 and env.state == JobState.READY


@pytest.mark.parametrize(
    "kwargs,expected",
    [
        (dict(owner_exit_code=1, worker_exit_code=1), RowState.OBSERVED_NONZERO),
        (dict(stdout_truncated=True), RowState.OBSERVED_ZERO_INVALID),
        (dict(stderr_eof=False), RowState.OBSERVED_ZERO_INVALID),
        (dict(finite_observed_fs_ok=False), RowState.OBSERVED_ZERO_INVALID),
        (dict(owner_status="timed_out", owner_exit_code=None,
              original_child_reaped=False, worker_status="timed_out",
              worker_timed_out=True, worker_exit_code=None), RowState.AMBIGUOUS),
        (dict(original_child_reaped=False), RowState.AMBIGUOUS),
    ],
)
def test_failure_classes_latch_job_and_void_remaining_rows(kwargs, expected):
    env = _envelope()
    nonce = grant().command_nonces[0]
    env.begin_row(0, nonce, nonce)
    assert env.finish_row(
        0, observation=_row_observation(nonce, **kwargs),
    ) == expected
    assert env.state == JobState.FAILED
    assert env.active_attempt_nonce is None
    assert all(x == RowState.VOID for x in env.row_states[1:])
    with pytest.raises(GateDenied):
        env.begin_row(1, grant().command_nonces[1], grant().command_nonces[1])


@pytest.mark.parametrize("fault", [
    dict(worker_status="timed_out"),
    dict(worker_status="launch_failed"),
    dict(worker_executed=False),
    dict(worker_timed_out=True),
    dict(worker_cancelled=True),
    dict(ack_lost=True),
    dict(worker_exit_code=9),
    dict(owner_exit_code=9),
    dict(owner_status="UNREAPABLE"),
    dict(owner_attempt_nonce="other-attempt"),
    dict(worker_attempt_nonce="other-attempt"),
    dict(attempt_nonce="other-attempt"),
    dict(owner_reservation=object()),
    dict(worker_reservation=object()),
    dict(owner_exit_code=None),
    dict(worker_exit_code=None),
    dict(original_child_reaped=False),
    dict(original_child_unambiguous=False),
    dict(cleanup_proven=True),
    dict(full_descendant_tree_clean="proven"),
    dict(worker_pipe_reader_failed=True),
    dict(owner_pipe_reader_failed=True),
    dict(pipe_reader_finished=False),
    dict(owner_unavailable=True),
    dict(owner_closing=True),
])
def test_r012_same_attempt_worker_owner_contradictions_void_remaining(fault):
    env = _envelope()
    nonce = grant().command_nonces[0]
    env.begin_row(0, nonce, nonce)
    result = env.finish_row(
        0, observation=_row_observation(nonce, **fault),
    )
    assert result == RowState.AMBIGUOUS
    assert env.state == JobState.FAILED
    assert env.row_states[0] == RowState.AMBIGUOUS
    assert all(state == RowState.VOID for state in env.row_states[1:])
    with pytest.raises(GateDenied):
        env.begin_row(1, grant().command_nonces[1], grant().command_nonces[1])


def test_original_reaped_zero_success_preserves_descendant_risk_warning():
    env = _envelope()
    nonce = grant().command_nonces[0]
    assert _success(env, 0, nonce) == RowState.POSITIVE_SUCCESS
    assert env.state == JobState.READY
    assert env.expected_row == 1


def test_six_exact_positive_rows_are_required_for_six_command_pass():
    env = _envelope()
    nonces = grant().command_nonces
    for i, nonce in enumerate(nonces):
        assert _success(env, i, nonce) == RowState.POSITIVE_SUCCESS
    assert env.six_command_pass is True
    assert env.state == JobState.COMPLETE


def test_finite_observed_delta_does_not_claim_whole_host_or_transient_absence():
    env = _envelope()
    assert env.whole_host_writes_proven_absent is False
    assert env.transient_source_mutation_proven_absent is False
    # A write+delete outside observed roots or mutate+restore inside source is
    # deliberately NOT represented as a proved absence by this finite oracle.
    assert _success(env, 0, grant().command_nonces[0]) == RowState.POSITIVE_SUCCESS
    assert env.whole_host_writes_proven_absent is False
    assert env.transient_source_mutation_proven_absent is False


def test_old_security_boundaries_remain_deny_while_lawful_file_git_survive_exec_denial():
    assert strict_exec_boundary_allows(
        r010_authority_valid=True,
        f1_default_deny=True,
        unknown_present=False,
        owner_lock_present=True,
        source_identity_ok=True,
        runner_approved=True,
    ) is True
    for changes in (
        dict(r010_authority_valid=False),
        dict(unknown_present=True),
        dict(owner_lock_present=False),
        dict(source_identity_ok=False),
        dict(runner_approved=False),
    ):
        values = dict(
            r010_authority_valid=True,
            f1_default_deny=True,
            unknown_present=False,
            owner_lock_present=True,
            source_identity_ok=True,
            runner_approved=True,
        )
        values.update(changes)
        assert strict_exec_boundary_allows(**values) is False
    assert adjacent_file_git_allowed(exec_denied=True) is True


def test_contract_file_contains_single_r010_authority_root_and_supersession_table():
    root = Path(__file__).resolve().parents[1]
    text = (root / "docs" / "MULTI_WORKSPACE_EXEC_LBE_R010_AUTHORITY_CHAIN_CONTRACT.md").read_text(
        encoding="ascii"
    )
    for required in (
        "R010_OWNER_DESIGN_CHOICE_V1",
        "R010_OWNER_PRODUCT_T1_GRANT_V1",
        "R010_EPHEMERAL_JOB_STATE_V1",
        "R010_GITHUB_OIDC_CHECK_RUN_V1",
        "ROW_OBSERVED_ZERO_INVALID_OUTPUT_OR_FS",
        "SUPERSEDED_DENY",
        "R009_JOB_GLOBAL_LEASE_RETAINED",
        "UNOBSERVED_HOST_SIDE_EFFECTS_NOT_PROVEN_ABSENT",
    ):
        assert required in text


# R011 test-first regression: these must be RED under the old R010 model.
def test_r011_red_legacy_design_choice_with_recomputed_new_grant_digest_denied():
    from dataclasses import replace
    old_choice = replace(choice(), marker="R008_OWNER_DESIGN_CHOICE_V1")
    new_grant = replace(grant(), design_choice_digest=design_choice_digest(old_choice))
    with pytest.raises(GateDenied):
        validate_execution_grant(
            new_grant,
            choice=old_choice,
            qualification=qualification(),
            witness=witness(),
            expected_job_envelope_key=ENVELOPE_KEY,
            verification=verification_receipt(),
            expected_design_blob=DESIGN_BLOB,
            expected_b_design_review_id=B_DESIGN,
            expected_c_design_review_id=C_DESIGN,
            expected_provider_subject=EXPECTED_PROVIDER_SUBJECT,
        )


def test_r011_red_qualification_wrong_design_blob_denied():
    from dataclasses import replace
    wrong = replace(qualification(), design_blob="f" * 40)
    with pytest.raises(GateDenied):
        validate_execution_grant(
            grant(), choice=choice(), qualification=wrong,
            witness=witness(), expected_job_envelope_key=ENVELOPE_KEY,
            verification=verification_receipt(),
            expected_design_blob=DESIGN_BLOB,
            expected_b_design_review_id=B_DESIGN,
            expected_c_design_review_id=C_DESIGN,
            expected_provider_subject=EXPECTED_PROVIDER_SUBJECT,
        )


def test_r011_red_oidc_preexec_and_jwt_freshness_contract_is_testable():
    from tools.r010_authority_chain_t0 import (
        PreexecSelectorBoundary, validate_preexec_selector_boundary_t0,
        validate_provider_freshness_t0,
    )
    assert PreexecSelectorBoundary is not None
    assert callable(validate_preexec_selector_boundary_t0)
    assert callable(validate_provider_freshness_t0)


def test_r011_red_contract_mentions_versioned_oidc_preexec_allowlist():
    text = (
        Path(__file__).resolve().parents[1] /
        "docs/MULTI_WORKSPACE_EXEC_LBE_R010_AUTHORITY_CHAIN_CONTRACT.md"
    ).read_text(encoding="ascii")
    assert "R010_OIDC_PREEXEC_SELECTOR_V2" in text
    assert "R010_PROVIDER_JWT_TEMPORAL_VERIFICATION_V1" in text


# R011 SAFE T0: true Bootstrap uses the two OIDC selectors ONLY in PREEXEC.
def _preexec_t0(**adjust):
    bootstrap = {
        "PATH": "/usr/bin:/bin", "HOME": "/private/tmp/mfg-r010-private-home",
        "TMPDIR": "/private/tmp/mfg-r010-private-tmp", "LANG": "C", "LC_ALL": "C",
        "GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "pull_request",
        "GITHUB_REPOSITORY": "chinanjjohn2012/mac-file-gateway",
        "GITHUB_RUN_ID": str(RUN), "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_JOB": "preexec_hold", "G05_EXPECTED_HEAD": HEAD,
        "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "macOS",
        "RUNNER_ARCH": "ARM64", "ImageOS": "macos15",
        "ImageVersion": "20261104.0514.1",
        "SSH_AUTH_SOCK": "/private/tmp/ssh-A/agent.sock",
        "ACTIONS_ID_TOKEN_REQUEST_URL": (
            "https://pipelinesghubeus15.actions.githubusercontent.com/_apis/oidc/token"
            "?api-version=2.0"
        ),
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "private-fake-runner-bearer-only",
    }
    from tools.r010_authority_chain_t0 import PRODUCT_HELPER_ENV_KEYS
    helper = {k: bootstrap[k] for k in PRODUCT_HELPER_ENV_KEYS}
    child = helper.copy()
    bootstrap.update(adjust.pop("bootstrap", {}))
    helper.update(adjust.pop("helper", {}))
    child.update(adjust.pop("child", {}))
    values = dict(
        phase="PREEXEC_HOLD", env_i_used=True, runner_context_source=True,
        bootstrap_items=tuple(sorted(bootstrap.items())),
        product_helper_items=tuple(sorted(helper.items())),
        product_child_items=tuple(sorted(child.items())),
        ssh_metadata_only=True, ssh_agent_protocol_calls=0,
        foreign_popen_calls=0, pregrant_product_popen_calls=0,
        scrub_before_product_import=True,
    )
    values.update(adjust)
    return PreexecSelectorBoundary(**values)


def _check_preexec_t0(item, *, expected_run_attempt="1"):
    return validate_preexec_selector_boundary_t0(
        item, expected_run_id=str(RUN), expected_run_attempt=expected_run_attempt,
        expected_head=HEAD,
        expected_image="20261104.0514.1", expected_job="preexec_hold",
        expected_home="/private/tmp/mfg-r010-private-home",
        expected_tmp="/private/tmp/mfg-r010-private-tmp",
    )


def test_r011_preexec_exact_oidc_keys_not_present_in_product():
    item = _preexec_t0()
    _check_preexec_t0(item)
    parent = dict(item.bootstrap_items)
    child = dict(item.product_child_items)
    assert "ACTIONS_ID_TOKEN_REQUEST_TOKEN" in parent
    assert "ACTIONS_ID_TOKEN_REQUEST_TOKEN" not in child
    assert "SSH_AUTH_SOCK" not in child
    assert set(dict(item.product_helper_items)) == {"PATH", "HOME", "TMPDIR", "LANG", "LC_ALL"}


@pytest.mark.parametrize("bad", [
    dict(bootstrap={"GIT_ASKPASS": "foreign"}),
    dict(bootstrap={"HTTPS_PROXY": "https://untrusted.example"}),
    dict(bootstrap={"ACTIONS_ID_TOKEN_REQUEST_TOKEN": ""}),
    dict(bootstrap={"ACTIONS_ID_TOKEN_REQUEST_URL": "http://evil.example/token"}),
    dict(bootstrap={"ACTIONS_ID_TOKEN_REQUEST_URL":
                    "https://evil.actions.githubusercontent.com.evil.example/token"}),
    dict(bootstrap={"G05_EXPECTED_HEAD": "0" * 40}),
    dict(helper={"ACTIONS_ID_TOKEN_REQUEST_TOKEN": "private-fake-runner-bearer-only"}),
    dict(helper={"SSH_AUTH_SOCK": "/private/tmp/ssh-A/agent.sock"}),
    dict(child={"ACTIONS_ID_TOKEN_REQUEST_URL": "unapproved"}),
    dict(child={"GIT_ASKPASS": "foreign"}),
    dict(env_i_used=False), dict(runner_context_source=False),
    dict(ssh_metadata_only=False), dict(ssh_agent_protocol_calls=1),
    dict(foreign_popen_calls=1), dict(pregrant_product_popen_calls=1),
    dict(scrub_before_product_import=False), dict(phase="PRODUCT_CHILD"),
])
def test_r011_preexec_oidc_selector_fail_closed(bad):
    with pytest.raises(GateDenied):
        _check_preexec_t0(_preexec_t0(**bad))


def test_r011_jwt_freshness_model_positive_synthetic():
    validate_provider_freshness_t0(
        verification_receipt(), expected_token_sha256=OIDC_TOKEN_DIGEST,
        expected_transcript_sha256=JWT_TRANSCRIPT_DIGEST,
        expected_check_run_id=CHECK_RUN,
        expected_subject=EXPECTED_PROVIDER_SUBJECT,
    )


@pytest.mark.parametrize("bad", [
    dict(expires_at=1_000_010), dict(expires_at=1_000_015),
    dict(not_before=1_000_100), dict(issued_at=1_000_100),
    dict(issued_at=999_000), dict(expires_at=1_002_000),
    dict(grant_checked_at=1_000_140), dict(grant_checked_at=999_999),
    dict(jose_alg="HS256"), dict(jose_typ="JOSE"), dict(jose_kid=""),
    dict(kid_matches_verified_jwks=False),
    dict(github_jwks_source_verified=False),
    dict(original_signed_bytes_verified=False),
    dict(original_jwt_independently_replayable=False),
    dict(token_sha256="0" * 64),
    dict(verification_transcript_sha256="0" * 64),
    dict(signed_check_run_id=CHECK_RUN + 1),
    dict(signed_subject="repo:unrelated/example:pull_request"),
    dict(current_job_in_progress=False),
])
def test_r011_jwt_expired_wrong_key_or_fake_summary_denied(bad):
    with pytest.raises(GateDenied):
        validate_provider_freshness_t0(
            verification_receipt(**bad), expected_token_sha256=OIDC_TOKEN_DIGEST,
            expected_transcript_sha256=JWT_TRANSCRIPT_DIGEST,
            expected_check_run_id=CHECK_RUN,
        expected_subject=EXPECTED_PROVIDER_SUBJECT,
        )


@pytest.mark.parametrize("bad", [
    dict(design_blob="f" * 40),
    dict(design_id="MWE-LBE-R010-AUTHORITY-CHAIN-DESIGN-009-CANDIDATE"),
    dict(review_sequence_option="B0"), dict(b_review_level="NONE"),
    dict(c_review_level="NONE"), dict(b_verdict="BLOCKED"),
    dict(c_evidence_status="INSUFFICIENT"),
    dict(b_t1_review_id=C_T1), dict(contract_scope_id="wrong_scope"),
])
def test_r011_grant_requires_current_qualification_and_b0_b1(bad):
    with pytest.raises(GateDenied):
        validate_execution_grant(
            grant(), choice=choice(), qualification=replace(qualification(), **bad),
            witness=witness(), verification=verification_receipt(),
            expected_job_envelope_key=ENVELOPE_KEY,
            expected_design_blob=DESIGN_BLOB,
            expected_b_design_review_id=B_DESIGN,
            expected_c_design_review_id=C_DESIGN,
            expected_provider_subject=EXPECTED_PROVIDER_SUBJECT,
        )


def test_r011_b0_cannot_be_satisfied_by_targeted_t1_reviews():
    ch = replace(choice(), review_sequence_option="B0")
    g = replace(grant(), review_sequence_option="B0",
                design_choice_digest=design_choice_digest(ch))
    q = replace(qualification(), review_sequence_option="B0")
    with pytest.raises(GateDenied, match="B0 FULL-before-T1"):
        validate_execution_grant(
            g, choice=ch, qualification=q, witness=witness(),
            verification=verification_receipt(), expected_job_envelope_key=ENVELOPE_KEY,
            expected_design_blob=DESIGN_BLOB,
            expected_b_design_review_id=B_DESIGN,
            expected_c_design_review_id=C_DESIGN,
            expected_provider_subject=EXPECTED_PROVIDER_SUBJECT,
        )
    # Illustration of required FULL metadata; NOT independent real reviews.
    validate_execution_grant(
        g, choice=ch,
        qualification=replace(q, b_review_level="ROLE_FULL_SCOPE_PASS",
                              c_review_level="ROLE_FULL_SCOPE_PASS"),
        witness=witness(), verification=verification_receipt(),
        expected_job_envelope_key=ENVELOPE_KEY,
        expected_design_blob=DESIGN_BLOB,
        expected_b_design_review_id=B_DESIGN,
        expected_c_design_review_id=C_DESIGN,
            expected_provider_subject=EXPECTED_PROVIDER_SUBJECT,
    )


def test_r011_grant_cannot_accept_unbound_owner_or_receipt():
    for bad in (
        dict(host_option="A0"),
        dict(risk_marker="R010_REAFFIRM_R006_RISK1_9_NO_NEW_HOST_WEAKENING"),
        dict(b_design_review_id="old-R008-b"),
        dict(oidc_token_sha256="0" * 64),
        dict(oidc_verification_transcript_sha256="0" * 64),
    ):
        with pytest.raises(GateDenied):
            validate_execution_grant(
                grant(**bad), choice=choice(), qualification=qualification(),
                witness=witness(), verification=verification_receipt(),
                expected_job_envelope_key=ENVELOPE_KEY,
                expected_design_blob=DESIGN_BLOB,
                expected_b_design_review_id=B_DESIGN,
                expected_c_design_review_id=C_DESIGN,
            expected_provider_subject=EXPECTED_PROVIDER_SUBJECT,
            )


def test_r011_inmemory_registry_cannot_claim_cross_process_proof():
    first, second = SharedJobRegistry(), SharedJobRegistry()
    first.claim_once("same-job")
    second.claim_once("same-job")
    assert first.claimed_keys == second.claimed_keys
    # Only later native O_EXCL/fsync cross-process original evidence can prove it.


def test_r011_new_trusted_attempt_must_match_its_own_current_job():
    observed_attempt_two = _preexec_t0(bootstrap={"GITHUB_RUN_ATTEMPT": "2"})
    _check_preexec_t0(observed_attempt_two, expected_run_attempt="2")
    with pytest.raises(GateDenied):
        _check_preexec_t0(observed_attempt_two, expected_run_attempt="1")
    with pytest.raises(GateDenied):
        _check_preexec_t0(observed_attempt_two, expected_run_attempt="02")


def test_r011_forged_receipt_cannot_supply_own_expected_subject():
    forged = verification_receipt(signed_subject="repo:attacker/example:pull_request")
    with pytest.raises(GateDenied):
        validate_provider_freshness_t0(
            forged, expected_token_sha256=OIDC_TOKEN_DIGEST,
            expected_transcript_sha256=JWT_TRANSCRIPT_DIGEST,
            expected_check_run_id=CHECK_RUN,
            expected_subject=EXPECTED_PROVIDER_SUBJECT,
        )


# R012 RED: independent B R011 counterexamples; source-only / no OIDC call.
@pytest.mark.parametrize("url", [
    "https://pipelinesghubeus15.actions.githubusercontent.com/unreviewed/path?api-version=2.0",
    "https://pipelinesghubeus15.actions.githubusercontent.com/_apis/oidc/token?api-version=2.0&unexpected=1",
    "https://pipelinesghubeus15.actions.githubusercontent.com/_apis/oidc/token?api-version=2.0&api-version=2.0",
    "https://pipelinesghubeus15.actions.githubusercontent.com/_apis/oidc/token?api-version=2.0&audience=forged",
    "https://pipelinesghubeus15.actions.githubusercontent.com/_apis/oidc/%74oken?api-version=2.0",
])
def test_r012_red_oidc_same_host_wrong_path_query_or_encoding_rejected(url):
    with pytest.raises(GateDenied):
        _check_preexec_t0(_preexec_t0(bootstrap={
            "ACTIONS_ID_TOKEN_REQUEST_URL": url,
        }))


@pytest.mark.parametrize("attempt", ["\u0662", "\uff12", "00", "02", "0", "+2", " 2"])
def test_r012_red_run_attempt_is_canonical_ascii_positive_integer(attempt):
    with pytest.raises(GateDenied):
        _check_preexec_t0(
            _preexec_t0(bootstrap={"GITHUB_RUN_ATTEMPT": attempt}),
            expected_run_attempt=attempt,
        )


def test_r012_red_requires_single_owner_worker_observation_model():
    from tools.r010_authority_chain_t0 import OwnedRowObservationT0
    assert OwnedRowObservationT0.__dataclass_params__.frozen is True


def test_r012_red_requires_reviewed_audience_url_assembly():
    from tools.r010_authority_chain_t0 import build_oidc_token_url_t0
    assert callable(build_oidc_token_url_t0)


def test_r012_canonical_oidc_request_url_from_reviewed_runner_base():
    base = (
        "https://pipelinesghubeus15.actions.githubusercontent.com/"
        "_apis/oidc/token?api-version=2.0"
    )
    audience = f"mfg-r010:{DESIGN_BLOB}:{HEAD}:{SECRET_HASH}"
    expected = base + "&audience=" + audience.replace(":", "%3A")
    actual = build_oidc_token_url_t0(base, audience)
    assert actual == expected
    assert actual.count("audience=") == 1
    assert actual.count("api-version=") == 1
    assert "/_apis/oidc/token?" in actual
    with pytest.raises(GateDenied):
        build_oidc_token_url_t0(base, "forged-client-audience")
    with pytest.raises(GateDenied):
        build_oidc_token_url_t0(base + "&audience=forged", audience)


@pytest.mark.parametrize("bad", [
    dict(oidc_redirect_count=1),
    dict(oidc_redirect_count=True),
    dict(oidc_redirect_count=-1),
    dict(bootstrap={"ACTIONS_ID_TOKEN_REQUEST_URL":
                    "https://pipelinesghubeus15.actions.githubusercontent.com/"
                    "_apis/oidc/token?api-version=2.0&audience=unknown"}),
    dict(bootstrap={"ACTIONS_ID_TOKEN_REQUEST_URL":
                    "https://pipelinesghubeus15.actions.githubusercontent.com/"
                    "_apis/oidc/token?api-version=02.0"}),
    dict(bootstrap={"ACTIONS_ID_TOKEN_REQUEST_URL":
                    "https://pipelinesghubeus15.actions.githubusercontent.com/"
                    "_apis/oidc/token?api-version=%32.0"}),
])
def test_r012_oidc_redirect_and_encoding_fail_before_bearer_use(bad):
    # No network APIs or fake bearer send callback are invoked by the T0.
    sent = []
    with pytest.raises(GateDenied):
        _check_preexec_t0(_preexec_t0(**bad))
        sent.append("fake-bearer-sent")
    assert sent == []


def test_r012_owner_worker_observation_is_immutable_and_non_runtime():
    from dataclasses import FrozenInstanceError
    obs = _row_observation(grant().command_nonces[0])
    assert obs.process_may_be_running is True
    assert obs.cleanup_proven is False
    assert obs.full_descendant_tree_clean == "not_proven"
    with pytest.raises(FrozenInstanceError):
        obs.worker_status = "timed_out"


@pytest.mark.parametrize("name,value", [
    ("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "different-fake-bearer"),
    ("ACTIONS_ID_TOKEN_REQUEST_URL", "different-fake-url"),
    ("SSH_AUTH_SOCK", "/different/private/ssh.sock"),
    ("GITHUB_RUN_ID", "99999"),
    ("RUNNER_OS", "linux"),
    ("HTTPS_PROXY", "https://some.invalid:9999"),
    ("PIP_INDEX_URL", "https://some.invalid/simple"),
    ("AWS_ACCESS_KEY_ID", "fake-key-no-secret"),
    ("GIT_ASKPASS", "/fake/program"),
])
def test_r013_red_child_recipe_override_must_never_enable_credential_names(
    name, value,
):
    from tools.r010_authority_chain_t0 import (
        PRODUCT_HELPER_ENV_KEYS, validate_preexec_selector_boundary_t0,
    )
    fixture = _preexec_t0(child={name: value})
    with pytest.raises(GateDenied):
        validate_preexec_selector_boundary_t0(
            fixture, expected_run_id=str(RUN), expected_run_attempt="1",
            expected_head=HEAD, expected_image="20261104.0514.1",
            expected_job="preexec_hold",
            expected_home="/private/tmp/mfg-r010-private-home",
            expected_tmp="/private/tmp/mfg-r010-private-tmp",
            approved_child_keys=PRODUCT_HELPER_ENV_KEYS | frozenset({name}),
        )


def test_r013_preexec_renamed_original_bearer_never_becomes_child_value():
    from tools.r010_authority_chain_t0 import (
        PRODUCT_HELPER_ENV_KEYS, validate_preexec_selector_boundary_t0,
    )
    fixture = _preexec_t0(child={
        "UNRELATED_NAME": "private-fake-runner-bearer-only",
    })
    with pytest.raises(GateDenied):
        validate_preexec_selector_boundary_t0(
            fixture, expected_run_id=str(RUN), expected_run_attempt="1",
            expected_head=HEAD, expected_image="20261104.0514.1",
            expected_job="preexec_hold",
            expected_home="/private/tmp/mfg-r010-private-home",
            expected_tmp="/private/tmp/mfg-r010-private-tmp",
            approved_child_keys=PRODUCT_HELPER_ENV_KEYS | frozenset({"UNRELATED_NAME"}),
        )


@pytest.mark.parametrize("name,value", [
    ("PYTHONUNBUFFERED", "1"),
    ("PYTHONDONTWRITEBYTECODE", "1"),
    ("PIP_NO_INDEX", "1"),
    ("PIP_DISABLE_PIP_VERSION_CHECK", "1"),
])
def test_r013_reviewed_child_recipe_safe_extra_only_with_exact_value(name, value):
    from tools.r010_authority_chain_t0 import (
        PRODUCT_HELPER_ENV_KEYS, validate_preexec_selector_boundary_t0,
    )
    keys = PRODUCT_HELPER_ENV_KEYS | frozenset({name})
    good = _preexec_t0(child={name: value})
    validate_preexec_selector_boundary_t0(
        good, expected_run_id=str(RUN), expected_run_attempt="1",
        expected_head=HEAD, expected_image="20261104.0514.1",
        expected_job="preexec_hold",
        expected_home="/private/tmp/mfg-r010-private-home",
        expected_tmp="/private/tmp/mfg-r010-private-tmp",
        approved_child_keys=keys,
    )
    bad = _preexec_t0(child={name: "0"})
    with pytest.raises(GateDenied):
        validate_preexec_selector_boundary_t0(
            bad, expected_run_id=str(RUN), expected_run_attempt="1",
            expected_head=HEAD, expected_image="20261104.0514.1",
            expected_job="preexec_hold",
            expected_home="/private/tmp/mfg-r010-private-home",
            expected_tmp="/private/tmp/mfg-r010-private-tmp",
            approved_child_keys=keys,
        )


def test_r013_read_fault_or_owner_latch_invalidates_witnessed_original_exit_zero():
    from tools.r010_authority_chain_t0 import JobState, RowState
    nonce = grant().command_nonces[0]
    for poisoned in (
        dict(worker_pipe_reader_failed=True),
        dict(owner_pipe_reader_failed=True),
        dict(pipe_reader_finished=False),
        dict(owner_unavailable=True),
        dict(owner_closing=True),
    ):
        env = _envelope()
        env.begin_row(0, nonce, nonce)
        obs = _row_observation(nonce, **poisoned)
        assert env.finish_row(0, observation=obs) == RowState.AMBIGUOUS
        assert env.row_states[0] == RowState.AMBIGUOUS
        assert env.state == JobState.FAILED
        assert env.active_attempt_nonce is None
        assert all(x == RowState.VOID for x in env.row_states[1:])
        with pytest.raises(GateDenied):
            env.begin_row(1, grant().command_nonces[1], grant().command_nonces[1])


def test_r013_bearer_value_renamed_or_embedded_must_fail_even_under_safe_extension():
    from tools.r010_authority_chain_t0 import (
        PRODUCT_HELPER_ENV_KEYS, validate_preexec_selector_boundary_t0,
    )
    # Even with an independently source-reviewed innocuous variable NAME,
    # the literal GitHub Runner credential may not appear as a child VALUE.
    keys = PRODUCT_HELPER_ENV_KEYS | frozenset({"PYTHONUNBUFFERED"})
    fixture = _preexec_t0(child={
        "PYTHONUNBUFFERED": "prefix-private-fake-runner-bearer-only-suffix"
    })
    with pytest.raises(GateDenied):
        validate_preexec_selector_boundary_t0(
            fixture, expected_run_id=str(RUN), expected_run_attempt="1",
            expected_head=HEAD, expected_image="20261104.0514.1",
            expected_job="preexec_hold",
            expected_home="/private/tmp/mfg-r010-private-home",
            expected_tmp="/private/tmp/mfg-r010-private-tmp",
            approved_child_keys=keys,
        )


# R014 RED -> GREEN: the *actual frozen contract Git blob*, not a fake "a"*40.
# These tests are non-runtime model comparisons, NOT actual signed GitHub
# Owner/Review objects, original JWT signatures, or a PRODUCT_T1 authorization.
R014_DESIGN_ID = "MWE-LBE-R010-AUTHORITY-CHAIN-DESIGN-013-CANDIDATE"
R013_DESIGN_ID = "MWE-LBE-R010-AUTHORITY-CHAIN-DESIGN-012-CANDIDATE"
R012_DESIGN_ID = "MWE-LBE-R010-AUTHORITY-CHAIN-DESIGN-011-CANDIDATE"
R013_DESIGN_BLOB = "fa3f756f5876e67ff9434747c855a68fd01e7654"
R012_DESIGN_BLOB = "1dddfdaa5f610c6c02ba9b81d4d11296d2b36eb3"
R013_B_REVIEW = "PRR_kwDOU5v3IM8AAAABWs2i6Q"
R013_C_REVIEW = "PRR_kwDOU5v3IM8AAAABWs3Ieg"
R014_B_SYNTHETIC = "synthetic-r014-new-b-review-NEVER-ISSUED"
R014_C_SYNTHETIC = "synthetic-r014-new-c-review-NEVER-ISSUED"


def _r014_exact_source_blob():
    raw = (
        Path(__file__).resolve().parents[1]
        / "docs/MULTI_WORKSPACE_EXEC_LBE_R010_AUTHORITY_CHAIN_CONTRACT.md"
    ).read_bytes()
    git_object = b"blob " + str(len(raw)).encode("ascii") + b"\x00" + raw
    return hashlib.sha1(git_object).hexdigest(), raw.decode("ascii")


def _r014_synthetic_authority():
    """No real Owner Choice or current B/C Review exists in this fixture."""
    current_blob, _text = _r014_exact_source_blob()
    ch = replace(
        choice(), design_id=R014_DESIGN_ID, design_blob=current_blob,
        b_design_review_id=R014_B_SYNTHETIC,
        c_design_review_id=R014_C_SYNTHETIC,
    )
    qual = replace(
        qualification(), design_id=R014_DESIGN_ID, design_blob=current_blob,
    )
    witness_now = replace(
        witness(), audience=f"mfg-r010:{current_blob}:{HEAD}:{SECRET_HASH}",
    )
    g = replace(
        grant(), design_id=R014_DESIGN_ID, design_blob=current_blob,
        design_choice_digest=design_choice_digest(ch),
        b_design_review_id=R014_B_SYNTHETIC,
        c_design_review_id=R014_C_SYNTHETIC,
    )
    return current_blob, ch, qual, witness_now, g


def _r014_validate(g, ch, qual, witness_now, *, expected_blob=None):
    blob, _ = _r014_exact_source_blob()
    validate_execution_grant(
        g, choice=ch, qualification=qual, witness=witness_now,
        verification=verification_receipt(),
        expected_design_blob=blob if expected_blob is None else expected_blob,
        expected_b_design_review_id=R014_B_SYNTHETIC,
        expected_c_design_review_id=R014_C_SYNTHETIC,
        expected_provider_subject=EXPECTED_PROVIDER_SUBJECT,
        expected_job_envelope_key=ENVELOPE_KEY,
    )


def test_r014_red_one_current_source_blob_and_normative_version_only():
    from tools import r010_authority_chain_t0 as policy
    blob, spec = _r014_exact_source_blob()
    assert R010_DESIGN_ID == R014_DESIGN_ID
    assert policy.R010_CURRENT_DESIGN_BLOB == blob
    assert blob not in (R012_DESIGN_BLOB, R013_DESIGN_BLOB)
    assert f"DESIGN_ID: {R014_DESIGN_ID}" in spec.split("## 1.", 1)[0]
    assert "REVIEW_ROUND: D4-R014-AUTHORITY-CHAIN-DESIGN-013" in spec
    assert "CURRENT_DESIGN_ID" in spec and "CURRENT_DESIGN_BLOB" in spec
    assert "CURRENT_DESIGN_BLOB" in spec.split("### 14.1", 1)[1].split("### 14.2", 1)[0]
    auth14 = spec.split("### 14.3", 1)[1].split("### 14.4", 1)[0]
    assert "CURRENT_DESIGN_BLOB" in auth14
    assert "CURRENT_DESIGN_ID" in auth14
    assert "EXACTLY DESIGN-011" not in auth14
    assert "exact DESIGN-011" not in auth14
    assert "DESIGN-011 Blob" not in spec.split("### 14.1", 1)[1].split("### 14.2", 1)[0]
    assert "HISTORICAL" in spec.split("### 15.4", 1)[1].split("## 16.", 1)[0]
    assert "## 17. R014" in spec


def test_r014_red_real_frozen_blob_valid_synthetic_chain_only():
    blob, ch, qual, witness_now, g = _r014_synthetic_authority()
    assert len(blob) == 40
    _r014_validate(g, ch, qual, witness_now)


@pytest.mark.parametrize("old_id,old_blob,old_b,old_c", [
    (R012_DESIGN_ID, R012_DESIGN_BLOB, "PRR_OLD_R012_B", "PRR_OLD_R012_C"),
    (R013_DESIGN_ID, R013_DESIGN_BLOB, R013_B_REVIEW, R013_C_REVIEW),
])
def test_r014_red_old_version_choice_review_and_recomputed_grant_denied(
    old_id, old_blob, old_b, old_c,
):
    _, ch, qual, witness_now, g = _r014_synthetic_authority()
    old_ch = replace(
        ch, design_id=old_id, design_blob=old_blob,
        b_design_review_id=old_b, c_design_review_id=old_c,
    )
    disguised = replace(
        g, design_id=old_id, design_blob=old_blob,
        b_design_review_id=old_b, c_design_review_id=old_c,
        design_choice_digest=design_choice_digest(old_ch),
    )
    with pytest.raises(GateDenied):
        _r014_validate(disguised, old_ch, qual, witness_now)


@pytest.mark.parametrize("role", ["b", "c"])
def test_r014_red_current_blob_with_old_design_review_ids_denied(role):
    _, ch, qual, witness_now, g = _r014_synthetic_authority()
    if role == "b":
        bad_ch = replace(ch, b_design_review_id=R013_B_REVIEW)
        bad_g = replace(g, b_design_review_id=R013_B_REVIEW)
    else:
        bad_ch = replace(ch, c_design_review_id=R013_C_REVIEW)
        bad_g = replace(g, c_design_review_id=R013_C_REVIEW)
    bad_g = replace(bad_g, design_choice_digest=design_choice_digest(bad_ch))
    with pytest.raises(GateDenied):
        _r014_validate(bad_g, bad_ch, qual, witness_now)


def test_r014_red_new_choice_with_old_oidc_audience_denied():
    _, ch, qual, _, g = _r014_synthetic_authority()
    for old_blob in (R012_DESIGN_BLOB, R013_DESIGN_BLOB):
        stale = replace(
            witness(), audience=f"mfg-r010:{old_blob}:{HEAD}:{SECRET_HASH}",
        )
        with pytest.raises(GateDenied):
            _r014_validate(g, ch, qual, stale)


def test_r014_red_legacy_blob_disguised_as_current_id_even_if_expected_is_old_denied():
    _, ch, qual, witness_now, g = _r014_synthetic_authority()
    old_ch = replace(ch, design_blob=R013_DESIGN_BLOB)
    old_qual = replace(qual, design_blob=R013_DESIGN_BLOB)
    old_g = replace(
        g, design_blob=R013_DESIGN_BLOB,
        design_choice_digest=design_choice_digest(old_ch),
    )
    old_witness = replace(
        witness_now, audience=f"mfg-r010:{R013_DESIGN_BLOB}:{HEAD}:{SECRET_HASH}",
    )
    with pytest.raises(GateDenied):
        _r014_validate(
            old_g, old_ch, old_qual, old_witness,
            expected_blob=R013_DESIGN_BLOB,
        )


@pytest.mark.parametrize("bad", [
    {"run_attempt": 2},
    {"check_run_id": CHECK_RUN + 1},
    {"head_sha": "0" * 40},
])
def test_r014_red_current_authority_does_not_borrow_different_job_or_head(bad):
    _, ch, qual, witness_now, g = _r014_synthetic_authority()
    with pytest.raises(GateDenied):
        _r014_validate(replace(g, **bad), ch, qual, witness_now)



def test_r014_revoked_oidc_audience_rejected_by_endpoint_builder():
    valid_base = (
        "https://pipelinesghubeus15.actions.githubusercontent.com/"
        "_apis/oidc/token?api-version=2.0"
    )
    for old in (R012_DESIGN_BLOB, R013_DESIGN_BLOB):
        stale = f"mfg-r010:{old}:{HEAD}:{SECRET_HASH}"
        with pytest.raises(GateDenied):
            build_oidc_token_url_t0(valid_base, stale)


def test_r014_same_role_review_id_cannot_fake_two_independent_reviews():
    blob, ch, qual, witness_now, g = _r014_synthetic_authority()
    bad = replace(ch, c_design_review_id=R014_B_SYNTHETIC)
    disguised = replace(
        g, c_design_review_id=R014_B_SYNTHETIC,
        design_choice_digest=design_choice_digest(bad),
    )
    with pytest.raises(GateDenied):
        validate_execution_grant(
            disguised, choice=bad, qualification=qual, witness=witness_now,
            verification=verification_receipt(),
            expected_design_blob=blob,
            expected_b_design_review_id=R014_B_SYNTHETIC,
            expected_c_design_review_id=R014_B_SYNTHETIC,
            expected_provider_subject=EXPECTED_PROVIDER_SUBJECT,
            expected_job_envelope_key=ENVELOPE_KEY,
        )


def test_r014_normal_scope_cannot_promote_role_pass_or_real_t1_from_mock():
    # This mock ensures only version consistency: no native authenticated
    # GitHub Review, real JWT, O_EXCL/fsync, or Go/Pipenv child is performed.
    _blob, ch, qual, witness_now, g = _r014_synthetic_authority()
    _r014_validate(g, ch, qual, witness_now)
    assert R010_DESIGN_ID == R014_DESIGN_ID
    assert "NEVER-ISSUED" in ch.b_design_review_id.upper()
    assert "NEVER-ISSUED" in ch.c_design_review_id.upper()
