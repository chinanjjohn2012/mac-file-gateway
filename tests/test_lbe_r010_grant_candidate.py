"""R010 Owner PRODUCT_T1 candidate tuple: SAFE T0 only, no network/child."""

from copy import deepcopy
from datetime import datetime, timezone
import os
import socket
import subprocess

import pytest

from gateway.lbe_r010_grant_candidate import (
    R010GrantExpected, R010GrantSourceDenied,
    validate_r010_product_grant_source_offline,
)
from gateway.lbe_r010_oidc_verify import (
    R010OIDCExpected, R010OIDCSignatureReceipt,
)
from gateway.lbe_r010_owner_choice import R010OwnerDesignChoiceObservation

NOW = 1794270000
REPO = "chinanjjohn2012/mac-file-gateway"
DESIGN = "f57e39543a6fe3d64fe99b8669fc7da854b93a64"
TARGET = "R010_COMPLETE_PRE_T1_CRITICAL_PATH_V1"
SCOPE = "R010_IMPLEMENTATION_CONTRACT_V1"


@pytest.fixture(autouse=True)
def forbid_real_execution_and_connections(monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("SAFE T0 may not spawn/connect/signal")
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(os, "kill", forbidden)
    monkeypatch.setattr(os, "killpg", forbidden, raising=False)


def _stamp(seconds):
    return datetime.fromtimestamp(seconds, tz=timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ")


def _expected():
    names = set(R010GrantExpected.__dataclass_fields__)
    values = {name: "d" * 64 for name in names}
    values.update(base_sha="a" * 40, head_sha="b" * 40,
                  tree_sha="c" * 40)
    return R010GrantExpected(**values)


def _choice():
    return R010OwnerDesignChoiceObservation(
        comment_id=6740275850, body_sha256="8" * 64,
        design_id="MWE-LBE-R010-AUTHORITY-CHAIN-DESIGN-013-CANDIDATE",
        design_blob=DESIGN, b_review_node_id="PRR_design_b",
        c_review_node_id="PRR_design_c",
        options=("A1", "B1"),
        risk_marker="R010_REAFFIRM_R006_RISK1_9_PLUS_RISK10_11",
    )


def _oidc(expected):
    source = R010OIDCExpected(
        implementation_head_sha=expected.head_sha,
        job_local_secret_sha256=expected.job_local_secret_sha256,
        run_id="1001", run_attempt="1", check_run_id="2001",
        workflow_ref=REPO + "/.github/workflows/r010.yml@refs/heads/main",
        workflow_sha="e" * 40, signed_source_sha=expected.head_sha,
        subject="repo:" + REPO + ":pull_request",
    )
    receipt = R010OIDCSignatureReceipt(
        jwt_sha256="1" * 64, signing_input_sha256="2" * 64,
        signed_payload_sha256="3" * 64, issuer_metadata_sha256="4" * 64,
        jwks_sha256="5" * 64,
        issuer="https://token.actions.githubusercontent.com",
        jwks_url="https://token.actions.githubusercontent.com/.well-known/jwks",
        key_id="synthetic-key", algorithm="RS256",
        checked_run_id=source.run_id,
        checked_run_attempt=source.run_attempt,
        checked_check_run_id=source.check_run_id,
        signed_subject=source.subject,
        verified_at_unix=NOW - 35, expires_unix=NOW + 250)
    return source, receipt


def _review(role, expected):
    marker = "STANDARDS_REVIEW" if role == "STANDARDS_REVIEWER" else "SPEC_REVIEW"
    node_id = "PRR_r010_standards" if role == "STANDARDS_REVIEWER" else "PRR_r010_spec"
    fields = {
        "ROLE": role, "REPO": REPO,
        "REVIEW_ROUND": "r006-qualified-candidate",
        "REVIEWED_BASE_SHA": expected.base_sha,
        "REVIEWED_HEAD_SHA": expected.head_sha,
        "REVIEWED_TREE_SHA": expected.tree_sha,
        "REVIEW_SCOPE": "TARGETED",
        "REVIEW_PROGRESS": "REVIEW_COMPLETE",
        "EVIDENCE_STATUS": "SUFFICIENT",
        "REVIEW_LEVEL": "TARGETED_REVIEW_PASS",
        "VERDICT": "PASS",
        "REVIEW_TARGET": TARGET + " (synthetic only)",
        "CONTRACT_SCOPE": SCOPE + " (synthetic only)",
    }
    body = ("GH_HANDOFF_V2 " + marker + "\n" +
            "\n".join(k + ": " + v for k, v in fields.items()) +
            "\nTEST_FIXTURE_NO_INDEPENDENT_REAL_REVIEW_" * 10)
    return {
        "node_id": node_id,
        "commit_id": expected.head_sha,
        "state": "COMMENTED",
        "submitted_at": _stamp(NOW - 40),
        "body": body,
    }


def _fields(choice, expected, source, receipt, b, c):
    """Synthesized API-shaped data, NEVER an actual Owner execution grant."""
    return {
        "repo": REPO, "pr": "114",
        "r010_design_blob": DESIGN,
        "owner_design_choice_comment_id": str(choice.comment_id),
        "owner_design_choice_body_sha256": choice.body_sha256,
        "host_option": "A1", "review_sequence_option": "B1",
        "risk_marker": "R010_REAFFIRM_R006_RISK1_9_PLUS_RISK10_11",
        "b_r010_design_review_id": choice.b_review_node_id,
        "c_r010_design_review_id": choice.c_review_node_id,
        "implementation_base_sha": expected.base_sha,
        "implementation_head_sha": expected.head_sha,
        "implementation_head_tree": expected.tree_sha,
        "manifest_sha256": expected.manifest_sha256,
        "b_r010_t1_qualification_review_id": b["node_id"],
        "c_r010_t1_qualification_review_id": c["node_id"],
        "review_target_id": TARGET, "contract_scope_id": SCOPE,
        "provider_contract": "R010_GITHUB_OIDC_CHECK_RUN_V1",
        "oidc_issuer": receipt.issuer, "oidc_audience": source.audience,
        "oidc_token_sha256": receipt.jwt_sha256,
        "oidc_signing_input_sha256": receipt.signing_input_sha256,
        "oidc_payload_sha256": receipt.signed_payload_sha256,
        "oidc_issuer_metadata_sha256": receipt.issuer_metadata_sha256,
        "oidc_jwks_sha256": receipt.jwks_sha256,
        "oidc_algorithm": receipt.algorithm,
        "oidc_kid": receipt.key_id, "oidc_subject": receipt.signed_subject,
        "run_id": source.run_id, "run_attempt": source.run_attempt,
        "check_run_id": source.check_run_id,
        "workflow_ref": source.workflow_ref,
        "workflow_sha": source.workflow_sha,
        "runner_image_sha256": expected.runner_image_sha256,
        "source_graph_sha256": expected.source_graph_sha256,
        "host_snapshot_sha256": expected.host_snapshot_sha256,
        "state_domain": "R010_EPHEMERAL_JOB_STATE_V1",
        "state_provenance_sha256": expected.state_provenance_sha256,
        "job_envelope_key_sha256": expected.job_envelope_key_sha256,
        "job_envelope_root_sha256": expected.job_envelope_root_sha256,
        "job_lease_sha256": expected.job_lease_sha256,
        "job_local_secret_sha256": expected.job_local_secret_sha256,
        "service_instance_nonce_sha256": expected.service_instance_nonce_sha256,
        "owner_lock_sha256": expected.owner_lock_sha256,
        "exec_state_sha256": expected.exec_state_sha256,
        "command_journal_sha256": expected.command_journal_sha256,
        "config_sha256": expected.config_sha256,
        "row_contract": "R010_SERIAL_EXIT0_FINITE_OBSERVED_DELTA_V1",
        "six_commands_sha256": expected.six_commands_sha256,
        "six_nonces_sha256": expected.six_nonces_sha256,
        "expires_unix": str(NOW + 100),
    }


def _body(fields):
    return ("R010_OWNER_PRODUCT_T1_GRANT_V1\n\n" +
            "\n".join(k + ": " + v for k, v in fields.items()) +
            "\n\n## Synthetic only\nNO EXECUTION GRANT IS MADE HERE.\n")


def _case():
    expected = _expected()
    choice = _choice()
    source, receipt = _oidc(expected)
    b = _review("STANDARDS_REVIEWER", expected)
    c = _review("SPEC_REVIEWER", expected)
    comment = {
        "id": 987654321,
        "user": {"login": "chinanjjohn2012", "id": 13314291, "type": "User"},
        "author_association": "OWNER",
        "issue_url": "https://api.github.com/repos/" + REPO + "/issues/114",
        "created_at": _stamp(NOW - 20),
        "updated_at": _stamp(NOW - 20),
        "body": _body(_fields(choice, expected, source, receipt, b, c)),
    }
    return dict(comment=comment, standards_review=b, spec_review=c,
                choice=choice, expected=expected,
                oidc_expected=source, oidc_receipt=receipt, now_unix=NOW)


def test_synthetic_full_source_tuple_only_returns_nonoperative_candidate():
    example = _case()
    result = validate_r010_product_grant_source_offline(**example)
    assert result.implementation_head_sha == "b" * 40
    assert result.standards_review_node_id != result.spec_review_node_id
    assert result.status == "OWNER_GRANT_SOURCE_MATCH_EXTERNAL_TRUST_NOT_ATTESTED"
    assert result.owner_comment_authenticated is False
    assert result.provider_job_authenticated is False
    assert result.execution_qualification_attested is False
    assert result.native_launch_allowed is False
    assert result.row_positive_success is False
    assert result.six_command_product_t1_pass is False
    for method in ("run", "popen", "mint_grant", "launch", "begin_later_row"):
        assert not hasattr(result, method)


@pytest.mark.parametrize("name", [
    "implementation_head_sha", "manifest_sha256",
    "job_local_secret_sha256", "six_commands_sha256",
    "six_nonces_sha256", "owner_design_choice_body_sha256",
    "b_r010_t1_qualification_review_id", "oidc_token_sha256",
    "check_run_id", "host_snapshot_sha256", "row_contract",
    "expires_unix",
])
def test_wrong_bound_source_field_denied(name):
    example = _case()
    original = example["comment"]["body"]
    for line in original.splitlines():
        if line.startswith(name + ": "):
            example["comment"]["body"] = original.replace(
                line, name + ": forged-value")
            break
    else:
        raise AssertionError("missing test field: " + name)
    with pytest.raises(R010GrantSourceDenied):
        validate_r010_product_grant_source_offline(**example)


def test_duplicate_and_unknown_owner_fields_and_old_marker_denied():
    for mutation in ("duplicate", "unknown", "old_marker"):
        case = _case()
        body = case["comment"]["body"]
        if mutation == "duplicate":
            case["comment"]["body"] = body.replace(
                "\n\n## Synthetic", "\nrepo: " + REPO + "\n\n## Synthetic")
        elif mutation == "unknown":
            case["comment"]["body"] = body.replace(
                "\n\n## Synthetic", "\nunsafe_override: yes\n\n## Synthetic")
        else:
            case["comment"]["body"] = body.replace(
                "R010_OWNER_PRODUCT_T1_GRANT_V1",
                "R009_OWNER_PRODUCT_T1_GRANT_V1")
        with pytest.raises(R010GrantSourceDenied):
            validate_r010_product_grant_source_offline(**case)


@pytest.mark.parametrize("field,value", [
    ("author_association", "CONTRIBUTOR"),
    ("updated_at", _stamp(NOW - 15)),
    ("issue_url", "https://api.github.com/repos/other/rep/issues/114"),
    ("created_at", _stamp(NOW + 1)),
    ("id", 0),
])
def test_unqualified_native_owner_comment_denied(field, value):
    case = _case()
    case["comment"][field] = value
    with pytest.raises(R010GrantSourceDenied):
        validate_r010_product_grant_source_offline(**case)


@pytest.mark.parametrize("field,value", [
    ("commit_id", "e" * 40),
    ("state", "DISMISSED"),
    ("submitted_at", _stamp(NOW - 10)),
])
def test_review_snapshots_and_before_owner_order_required(field, value):
    case = _case()
    case["standards_review"][field] = value
    with pytest.raises(R010GrantSourceDenied):
        validate_r010_product_grant_source_offline(**case)


def test_role_independence_and_exact_review_contract_required():
    case = _case()
    case["spec_review"]["node_id"] = case["standards_review"]["node_id"]
    with pytest.raises(R010GrantSourceDenied):
        validate_r010_product_grant_source_offline(**case)
    case = _case()
    case["spec_review"]["body"] = case["spec_review"]["body"].replace(
        "REVIEWED_TREE_SHA: " + "c" * 40,
        "REVIEWED_TREE_SHA: " + "f" * 40)
    with pytest.raises(R010GrantSourceDenied):
        validate_r010_product_grant_source_offline(**case)
    case = _case()
    case["spec_review"]["body"] += "\nEVIDENCE_STATUS: SUFFICIENT\n"
    with pytest.raises(R010GrantSourceDenied):
        validate_r010_product_grant_source_offline(**case)


def test_offline_oidc_job_mismatch_cannot_be_promoted():
    from dataclasses import replace
    case = _case()
    case["oidc_receipt"] = replace(
        case["oidc_receipt"], checked_check_run_id="999")
    with pytest.raises(R010GrantSourceDenied):
        validate_r010_product_grant_source_offline(**case)
    case = _case()
    case["oidc_receipt"] = replace(
        case["oidc_receipt"], verified_at_unix=NOW - 300)
    with pytest.raises(R010GrantSourceDenied):
        validate_r010_product_grant_source_offline(**case)


def test_no_old_design_or_fabricated_candidate_flag_can_grant_runtime():
    from dataclasses import replace
    case = _case()
    case["choice"] = replace(case["choice"], options=("A0", "B1"))
    with pytest.raises(R010GrantSourceDenied):
        validate_r010_product_grant_source_offline(**case)
    case = _case()
    case["choice"] = replace(case["choice"], native_launch_allowed=True)
    with pytest.raises(R010GrantSourceDenied):
        validate_r010_product_grant_source_offline(**case)
