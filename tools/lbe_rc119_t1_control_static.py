"""Nonoperative, pure-data RC119 T1 admission design oracle (SAFE T0).

This file has no workflow trigger, filesystem/network probe, child launcher or
authorization API. All results explicitly refuse native execution, including
apparently consistent simulated Owner/event/source data. A future actual T1
control requires its OWN reviewed source, authenticated one-use authority,
external byte provenance and an independently selected network profile.
"""
from __future__ import annotations

import re
from collections.abc import Mapping

REPO = "chinanjjohn2012/mac-file-gateway"
RC_PR = 119
RC_HEAD = "33c30b6c2710cac0f8533370c1ca42f31ef6747a"
RC_TREE = "27e26c423e700cdbad0aeca27efcdf82594507c1"
RC_BASE = "ec25c34492912f3a82175fa9c1060e0632814687"
OWNER = "chinanjjohn2012"
NATIVE_EXECUTION_ENABLED = False
SOURCE_GRADE = "STATIC_METADATA_ONLY_NOT_EXTERNAL_BYTE_PROOF"
_SHA = re.compile(r"^[0-9a-f]{40}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")

# Deliberately independent literal rows, not a runtime-imported product matrix.
SIX = (
    ("S1", "py-direct", "direct", ("python", "-m", "pytest", "-q")),
    ("S2", "py-direct", "direct", ("python", "-m", "compileall", "-q", "./src")),
    ("S3", "py-pipenv", "pipenv", ("python", "-m", "pytest", "-q")),
    ("S4", "go-project", "direct", ("go", "test", "./...")),
    ("S5", "go-project", "direct", ("go", "vet", "./...")),
    ("S6", "go-project", "direct",
     ("go", "build", "-o", "bin/app", "./cmd/app")),
)
INGRESSES = ("direct", "rest", "mcp")
REQUIRED_INPUT_IDS = (
    "rc_product_checkout", "control_source_checkout",
    "checkout_action", "setup_python_action", "setup_go_action",
    "macos_image_claim", "cpython_binary", "cpython_stdlib",
    "pipenv_entrypoint", "pipenv_pipfile", "pipenv_lock",
    "pipenv_venv_python", "pipenv_venv_site", "runtime_wheelhouse",
    "installed_wheel_record_closure", "go_binary", "go_stdlib_modules",
    "go_module_fixture", "python_fixture", "generated_fixture_outputs",
    "import_source_precedence", "mcp_sdk_source",
)


def inspect_input_lock(lock: object) -> dict[str, object]:
    """Validate declaration *shape*, never claim that external bytes exist."""
    issues: list[str] = []
    if not isinstance(lock, Mapping):
        return _blocked(["lock_not_mapping"])
    if lock.get("schema_version") != 1:
        issues.append("unsupported_lock_schema")
    if lock.get("target_repo") != REPO or lock.get("target_pr") != RC_PR:
        issues.append("wrong_target")
    if lock.get("target_head") != RC_HEAD or lock.get("target_tree") != RC_TREE:
        issues.append("wrong_target_identity")
    rows = lock.get("inputs")
    if not isinstance(rows, list):
        return _blocked(issues + ["inputs_not_list"])
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, Mapping):
            issues.append("invalid_input_row")
            continue
        name = row.get("id")
        if not isinstance(name, str) or name not in REQUIRED_INPUT_IDS:
            issues.append("unknown_input_id")
            continue
        if name in seen:
            issues.append("duplicate_input_id")
        seen.add(name)
        declared = row.get("expected_sha256")
        observed = row.get("observed_sha256")
        size = row.get("expected_size_bytes")
        # Template permits NULL only to show unresolved external proof;
        # arbitrary "ATTESTED" claims are not authority in this T0 parser.
        if declared is not None and (not isinstance(declared, str)
                                     or not _DIGEST.fullmatch(declared)):
            issues.append("invalid_expected_sha256")
        if observed is not None and (not isinstance(observed, str)
                                     or not _DIGEST.fullmatch(observed)):
            issues.append("invalid_observed_sha256")
        if declared is not None and observed is not None and declared != observed:
            issues.append("digest_mismatch")
        if size is not None and (type(size) is not int or size < 0):
            issues.append("invalid_size")
        if row.get("evidence_status") != "NOT_ATTESTED":
            issues.append("unsupported_attestation_claim")
        if any(row.get(field) is not None for field in
               ("fetched_bytes_location", "verified_import_location",
                "independent_evidence_uri")):
            issues.append("unverified_external_evidence_claim")
    if seen != set(REQUIRED_INPUT_IDS):
        issues.append("required_inputs_missing")
    if not issues:
        issues.append("external_bytes_not_attested")
    return _blocked(issues, declaration_format_valid=(
        issues == ["external_bytes_not_attested"]),
        input_count=len(seen))


def inspect_six_matrix(rows: object) -> dict[str, object]:
    """Check fixed plan as data; not a command dispatcher or native guard."""
    issues: list[str] = []
    if not isinstance(rows, list):
        return _blocked(["matrix_not_list"])
    expected = {(ingress, ident): (cwd, runner, argv)
                for ingress in INGRESSES
                for ident, cwd, runner, argv in SIX}
    seen: set[tuple[str, str]] = set()
    for row in rows:
        if not isinstance(row, Mapping):
            issues.append("invalid_matrix_row")
            continue
        ingress, ident = row.get("ingress"), row.get("id")
        key = (ingress, ident) if isinstance(ingress, str) and isinstance(ident, str) else None
        if key not in expected:
            issues.append("seventh_or_unknown_operation")
            continue
        if key in seen:
            issues.append("duplicate_matrix_row")
        seen.add(key)
        cwd, runner, argv = expected[key]
        if row.get("cwd") != cwd or row.get("runner") != runner:
            issues.append("cwd_or_runner_changed")
        actual = row.get("requested_argv")
        if not isinstance(actual, list) or tuple(actual) != argv:
            issues.append("argv_changed")
    if seen != set(expected):
        issues.append("matrix_incomplete")
    return _blocked(issues or ["nonoperative_matrix_only"],
                    declaration_format_valid=not issues,
                    matrix_count=len(seen))


def inspect_event(event: object, approval: object = None,
                  prior_phases: object = ()) -> dict[str, object]:
    """Pure hypothetical event matcher, NOT a lease/consent verifier.

    The in-memory prior_phases caller input does not supply atomic durable
    replay protection. No returned value authorizes an actual Job or child.
    """
    issues: list[str] = []
    if not isinstance(event, Mapping):
        return _blocked(["event_not_mapping"])
    if (event.get("repo") != REPO or event.get("pr") != RC_PR or
            event.get("head") != RC_HEAD or event.get("tree") != RC_TREE):
        issues.append("target_drift")
    if event.get("actor") != OWNER:
        issues.append("wrong_actor")
    if event.get("attempt") != 1 or type(event.get("attempt")) is not int:
        issues.append("replay_attempt")
    run_id = event.get("run_id")
    if type(run_id) is not int or run_id <= 0:
        issues.append("invalid_run_id")
    phase = event.get("phase")
    if phase not in ("SIX", "MIXED"):
        issues.append("invalid_phase")
    control_sha = event.get("control_sha")
    control_tree = event.get("control_tree")
    if (not isinstance(control_sha, str) or not _SHA.fullmatch(control_sha)
            or not isinstance(control_tree, str) or
            not _SHA.fullmatch(control_tree)):
        issues.append("control_identity_unfixed")
    if approval is None or not isinstance(approval, Mapping):
        issues.append("owner_authorization_missing")
    else:
        for field in ("repo", "pr", "head", "tree", "actor",
                      "run_id", "attempt", "control_sha", "control_tree"):
            if approval.get(field) != event.get(field):
                issues.append("approval_identity_mismatch")
                break
        if approval.get("approved_phases") != ["SIX", "MIXED"]:
            issues.append("scope_not_exact_two_phases")
        if approval.get("revoked") is not False:
            issues.append("approval_revoked_or_unknown")
        if approval.get("input_lock_sha256") is None:
            issues.append("input_lock_not_fixed")
        elif not isinstance(approval.get("input_lock_sha256"), str) or not _DIGEST.fullmatch(approval["input_lock_sha256"]):
            issues.append("input_lock_digest_invalid")
        if approval.get("profile_blob_sha") is None:
            issues.append("profile_not_fixed")
        elif not isinstance(approval.get("profile_blob_sha"), str) or not _SHA.fullmatch(approval["profile_blob_sha"]):
            issues.append("profile_blob_invalid")
    if not isinstance(prior_phases, (tuple, list)):
        issues.append("replay_record_malformed")
    else:
        if phase == "SIX" and prior_phases:
            issues.append("duplicate_or_out_of_order_phase")
        if phase == "MIXED" and tuple(prior_phases) != ("SIX_PASSED",):
            issues.append("mixed_without_valid_six")
        if phase == "MIXED" and approval is not None and isinstance(approval, Mapping) and approval.get("run_id") != run_id:
            issues.append("cross_run_mixed")
    # The approval dict, phase history and event above are UNTRUSTED data.
    # No GitHub authenticated evidence, atomic consumption, host or network
    # identity is obtained by this function. Never return a launch permit.
    return _blocked(issues or ["owner_signature_and_atomic_lease_unverified"],
                    declaration_format_valid=not issues,
                    proposed_phase=phase)


def _blocked(issues: list[str], **extra: object) -> dict[str, object]:
    return {
        "control_status": "NONOPERATIVE_STATIC_T0",
        "native_execution_authorized": False,
        "execution_attempted": False,
        "evidence_grade": SOURCE_GRADE,
        "blocking_codes": list(dict.fromkeys(issues)),
        **extra,
    }
