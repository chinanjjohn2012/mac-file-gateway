import hashlib
from pathlib import Path

import pytest

from tools.r010_authority_chain_t0 import (
    DesignChoice,
    ExecutionGrant,
    GateDenied,
    ImplementationQualification,
    JobEnvelope,
    JobState,
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
    design_choice_digest,
    strict_exec_boundary_allows,
    validate_design_choice,
    validate_execution_grant,
    validate_provider_witness,
)

DESIGN_BLOB = "a" * 40
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
    )
    with pytest.raises(GateDenied, match="legacy/wrong"):
        validate_execution_grant(
            grant(marker="R009_OWNER_PRODUCT_T1_GRANT_V1"),
            choice=choice(),
            qualification=qualification(),
            witness=witness(),
            expected_job_envelope_key=ENVELOPE_KEY,
        )
    with pytest.raises(GateDenied, match="provider OIDC"):
        validate_execution_grant(
            grant(),
            choice=choice(),
            qualification=qualification(),
            witness=witness(check_run_id=CHECK_RUN + 1),
            expected_job_envelope_key=ENVELOPE_KEY,
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


def _success(env, index, nonce):
    env.begin_row(index, nonce, nonce)
    return env.finish_row(
        index,
        exit_code=0,
        stdout_eof=True,
        stderr_eof=True,
        stdout_truncated=False,
        stderr_truncated=False,
        output_within_bound=True,
        finite_observed_fs_ok=True,
        original_child_unambiguous=True,
        process_may_be_running=False,
    )


def test_rows_are_globally_serial_across_workspaces():
    env = _envelope()
    nonces = grant().command_nonces
    env.begin_row(0, nonces[0], nonces[0])
    with pytest.raises(GateDenied, match="not ready|unexpected"):
        env.begin_row(4, nonces[4], nonces[4])
    assert env.finish_row(
        0,
        exit_code=0,
        stdout_eof=True,
        stderr_eof=True,
        stdout_truncated=False,
        stderr_truncated=False,
        output_within_bound=True,
        finite_observed_fs_ok=True,
        original_child_unambiguous=True,
        process_may_be_running=False,
    ) == RowState.POSITIVE_SUCCESS
    assert env.expected_row == 1 and env.state == JobState.READY


@pytest.mark.parametrize(
    "kwargs,expected",
    [
        (dict(exit_code=1), RowState.OBSERVED_NONZERO),
        (dict(exit_code=0, stdout_truncated=True), RowState.OBSERVED_ZERO_INVALID),
        (dict(exit_code=0, stderr_eof=False), RowState.OBSERVED_ZERO_INVALID),
        (dict(exit_code=0, finite_observed_fs_ok=False), RowState.OBSERVED_ZERO_INVALID),
        (dict(exit_code=None, original_child_unambiguous=False), RowState.AMBIGUOUS),
    ],
)
def test_failure_classes_latch_job_and_void_remaining_rows(kwargs, expected):
    env = _envelope()
    nonce = grant().command_nonces[0]
    env.begin_row(0, nonce, nonce)
    base = dict(
        exit_code=0,
        stdout_eof=True,
        stderr_eof=True,
        stdout_truncated=False,
        stderr_truncated=False,
        output_within_bound=True,
        finite_observed_fs_ok=True,
        original_child_unambiguous=True,
        process_may_be_running=False,
    )
    base.update(kwargs)
    assert env.finish_row(0, **base) == expected
    assert env.state == JobState.FAILED
    assert all(x == RowState.VOID for x in env.row_states[1:])
    with pytest.raises(GateDenied):
        env.begin_row(1, grant().command_nonces[1], grant().command_nonces[1])


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
