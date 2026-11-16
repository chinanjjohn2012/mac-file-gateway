"""SAFE T0 on RC119's separate, permanently nonoperative test control."""
from __future__ import annotations

import copy
import json
import subprocess
from pathlib import Path

import pytest

from tools.lbe_rc119_t1_control_static import (
    INGRESSES, NATIVE_EXECUTION_ENABLED, RC_HEAD, RC_PR, RC_TREE, REPO,
    REQUIRED_INPUT_IDS, SIX, inspect_event, inspect_input_lock,
    inspect_six_matrix,
)

HERE = Path(__file__).resolve().parent.parent
TEMPLATE = HERE / "docs" / "LBE_RC119_T1_INPUT_LOCK_TEMPLATE_V1.json"


def _manifest():
    return json.loads(TEMPLATE.read_text(encoding="utf-8"))


def _matrix():
    return [
        {"ingress": ingress, "id": ident, "cwd": cwd, "runner": runner,
         "requested_argv": list(argv)}
        for ingress in INGRESSSES
        for ident, cwd, runner, argv in SIX
    ]


# Declare this independently, not by importing the product's run-command list.
INGRESSSES = ("direct", "rest", "mcp")


def _event():
    return {
        "repo": REPO, "pr": RC_PR, "head": RC_HEAD, "tree": RC_TREE,
        "actor": "chinanjjohn2012", "run_id": 1001, "attempt": 1,
        "control_sha": "a" * 40, "control_tree": "b" * 40, "phase": "SIX",
    }


def _approval(event):
    return {
        **{k: event[k] for k in (
            "repo", "pr", "head", "tree", "actor", "run_id",
            "attempt", "control_sha", "control_tree")},
        "approved_phases": ["SIX", "MIXED"], "revoked": False,
        "input_lock_sha256": "c" * 64, "profile_blob_sha": "d" * 40,
    }


def test_template_is_pure_unattested_and_has_complete_required_categories(monkeypatch):
    monkeypatch.setattr(subprocess, "Popen", lambda *_a, **_k:
                        pytest.fail("STATIC T0 MUST NEVER START NATIVE"))
    lock = _manifest()
    assert len(lock["inputs"]) == len(REQUIRED_INPUT_IDS)
    assert {row["id"] for row in lock["inputs"]} == set(REQUIRED_INPUT_IDS)
    assert all(row["evidence_status"] == "NOT_ATTESTED" and
               row["expected_sha256"] is None and
               row["observed_sha256"] is None and
               row["independent_evidence_uri"] is None for row in lock["inputs"])
    decision = inspect_input_lock(lock)
    assert decision["declaration_format_valid"] is True
    assert decision["blocking_codes"] == ["external_bytes_not_attested"]
    assert decision["native_execution_authorized"] is False
    assert NATIVE_EXECUTION_ENABLED is False


@pytest.mark.parametrize("mutation,reason", [
    (lambda l: l.update(target_head="f" * 40), "wrong_target_identity"),
    (lambda l: l.update(schema_version=2), "unsupported_lock_schema"),
    (lambda l: l["inputs"].append(dict(l["inputs"][0])), "duplicate_input_id"),
    (lambda l: l["inputs"].pop(), "required_inputs_missing"),
    (lambda l: l["inputs"][0].update(expected_sha256="a"), "invalid_expected_sha256"),
    (lambda l: l["inputs"][0].update(expected_size_bytes=-1), "invalid_size"),
    (lambda l: l["inputs"][0].update(evidence_status="ATTESTED"), "unsupported_attestation_claim"),
    (lambda l: l["inputs"][0].update(independent_evidence_uri="self-asserted"), "unverified_external_evidence_claim"),
])
def test_lock_fail_closed_shape_and_fake_attestation(mutation, reason):
    value = _manifest()
    mutation(value)
    decision = inspect_input_lock(value)
    assert reason in decision["blocking_codes"]
    assert not decision["native_execution_authorized"]


def test_exact_eighteen_canonical_requests_have_only_static_grade(monkeypatch):
    monkeypatch.setattr(subprocess, "Popen", lambda *_a, **_k:
                        pytest.fail("STATIC T0 spawned original child"))
    assert INGRESSSES == INGRESSES
    plan = _matrix()
    assert len(plan) == 18
    decision = inspect_six_matrix(plan)
    assert decision["declaration_format_valid"]
    assert decision["matrix_count"] == 18
    assert not decision["native_execution_authorized"]
    assert "nonoperative_matrix_only" in decision["blocking_codes"]


@pytest.mark.parametrize("patch,reason", [
    (lambda m: m.append({
        "ingress": "rest", "id": "S7", "cwd": "go-project",
        "runner": "direct", "requested_argv": ["go", "run", "."]}),
     "seventh_or_unknown_operation"),
    (lambda m: m[0].update(requested_argv=["python", "-c", "print(1)"]),
     "argv_changed"),
    (lambda m: m[0].update(cwd="../../outside"), "cwd_or_runner_changed"),
    (lambda m: m[1].update(runner="pipenv"), "cwd_or_runner_changed"),
    (lambda m: m.pop(), "matrix_incomplete"),
    (lambda m: m.append(dict(m[0])), "duplicate_matrix_row"),
    (lambda m: m[0].update(ingress="unknown"), "seventh_or_unknown_operation"),
])
def test_nonfixed_and_duplicate_command_matrix_denied(patch, reason):
    matrix = _matrix()
    patch(matrix)
    decision = inspect_six_matrix(matrix)
    assert reason in decision["blocking_codes"]
    assert not decision["native_execution_authorized"]


def test_consistent_fake_owner_event_never_mints_native_execution(monkeypatch):
    monkeypatch.setattr(subprocess, "Popen", lambda *_a, **_k:
                        pytest.fail("STATIC T0 native Popen"))
    event = _event()
    evidence = _approval(event)
    decision = inspect_event(event, evidence)
    assert decision["declaration_format_valid"]
    assert decision["blocking_codes"] == ["owner_signature_and_atomic_lease_unverified"]
    assert decision["control_status"] == "NONOPERATIVE_STATIC_T0"
    assert not decision["native_execution_authorized"]
    assert not decision["execution_attempted"]


@pytest.mark.parametrize("changes,reason", [
    ({"head": "e" * 40}, "target_drift"),
    ({"tree": "e" * 40}, "target_drift"),
    ({"actor": "someone-else"}, "wrong_actor"),
    ({"attempt": 2}, "replay_attempt"),
    ({"run_id": 0}, "invalid_run_id"),
    ({"phase": "MIXED"}, "mixed_without_valid_six"),
    ({"control_sha": ""}, "control_identity_unfixed"),
    ({"pr": 114}, "target_drift"),
])
def test_bad_event_metadata_fails_closed(changes, reason):
    event = _event()
    approval = _approval(event)
    event.update(changes)
    out = inspect_event(event, approval)
    assert reason in out["blocking_codes"]
    assert not out["native_execution_authorized"]


def test_missing_owner_and_replay_and_revocation():
    event = _event()
    assert "owner_authorization_missing" in inspect_event(event)["blocking_codes"]
    evidence = _approval(event)
    again = inspect_event(event, evidence, prior_phases=("SIX_RESERVED",))
    assert "duplicate_or_out_of_order_phase" in again["blocking_codes"]
    fake_new_run = dict(event, run_id=1002)
    assert "approval_identity_mismatch" in inspect_event(
        fake_new_run, evidence)["blocking_codes"]
    revoked = dict(evidence, revoked=True)
    assert "approval_revoked_or_unknown" in inspect_event(
        event, revoked)["blocking_codes"]
    fake_rerun = dict(event, attempt=2)
    assert "replay_attempt" in inspect_event(
        fake_rerun, evidence)["blocking_codes"]


def test_mixed_requires_prior_six_same_run_even_if_static_metadata_matches():
    event = dict(_event(), phase="MIXED")
    evidence = _approval(event)
    rejected = inspect_event(event, evidence, prior_phases=())
    assert "mixed_without_valid_six" in rejected["blocking_codes"]
    permitted_model_only = inspect_event(
        event, evidence, prior_phases=("SIX_PASSED",))
    assert permitted_model_only["declaration_format_valid"]
    assert permitted_model_only["native_execution_authorized"] is False
    assert "owner_signature_and_atomic_lease_unverified" in (
        permitted_model_only["blocking_codes"])


def test_not_a_workflow_controller_or_ambient_exec_primitive():
    import ast
    source = (HERE / "tools" / "lbe_rc119_t1_control_static.py").read_text(
        encoding="utf-8")
    node = ast.parse(source)
    names = {n.names[0].name.split(".")[0] for n in ast.walk(node)
             if isinstance(n, ast.Import)}
    assert names == {"re"}
    assert "subprocess.Popen" not in source
    assert "os.system" not in source
    assert "workflow_dispatch" not in source
    assert "native_execution_authorized" in source
