"""SAFE T0 ONLY: offline proof-of-identity audit of previously captured PR114 ZIPs.

No network, subprocess, external imports, runner admission or T1 execution path.
Historical test success NEVER yields an authorization/eligibility token.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parent
REPO = "chinanjjohn2012/mac-file-gateway"
PR114_HEAD = "1ef390638a5ba69802d152621544e02d89461788"
PR114_TREE = "fa51d2a7a881f8e4915badcfe0fb088f2fca0ee3"
PR119_HEAD = "33c30b6c2710cac0f8533370c1ca42f31ef6747a"
PR119_TREE = "27e26c423e700cdbad0aeca27efcdf82594507c1"
PR119_BASE = "ec25c34492912f3a82175fa9c1060e0632814687"
PROFILEB_PROPOSAL = "1df5ccf9dbf920ff243e04d0e57f45a82e1b2a13"
PROFILEB_HEAD = "22bae3bf359ccc0678a6f691b1e8188a4872cee2"
PRODUCT_CONTRACT = "d90df6de3bdbd81a314109d5f73959799b5a10a6"
PR102_GATEB = "7db3b77aadca8b0c284e28fa5ee64e315e9275d2"
ARTIFACTS = (
    ("pr114-native-18-original.zip", "mvp-six-native-t1-result.json", "5c4b167ebf922e93396f82c922f56d398855bc346abdbc8eb212253c69308344", 14106505883, 43575411697, 132388442200),
    ("pr114-mixed-original.zip", "mvp-native-mixed-t1-result.json", "3f86aa0c7f941d3232a9d61efff9d1c914b5f9a017572967e270f4a45a4b49a9", 14105873594, 43575441175, 132388535560),
)
COMMAND_IDS = {"py-direct-pytest", "py-direct-compileall", "py-pipenv-pytest", "go-test", "go-vet", "go-build"}
ROUTES = {"Direct", "REST", "MCP"}
INPUT_LOCK_CATEGORIES = (
    "rc_product_checkout", "control_source_checkout", "checkout_action", "setup_python_action",
    "setup_go_action", "macos_image_claim", "cpython_binary", "cpython_stdlib",
    "pipenv_entrypoint", "pipenv_pipfile", "pipenv_lock", "pipenv_venv_python",
    "pipenv_venv_site", "runtime_wheelhouse", "installed_wheel_record_closure",
    "go_binary", "go_stdlib_modules", "go_module_fixture", "python_fixture",
    "generated_fixture_outputs", "import_source_precedence", "mcp_sdk_source",
)


def load_original(name: str, member: str, expected_sha256: str) -> tuple[dict, int]:
    """Read only the archived JSON member. No ZIP extract-to-disk or import."""
    raw = (ROOT / name).read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError(f"ZIP_DIGEST_MISMATCH:{name}")
    with zipfile.ZipFile(ROOT / name, mode="r") as z:
        if z.namelist() != [member] or z.testzip() is not None:
            raise ValueError(f"ZIP_MEMBER_MISMATCH:{name}")
        if z.infolist()[0].file_size > 50_000:
            raise ValueError("OVERLARGE_RECEIPT")
        data = json.loads(z.read(member))
    if not isinstance(data, dict):
        raise ValueError("INVALID_RECEIPT_OBJECT")
    return data, len(raw)


def validate_old_native(x: dict) -> list[dict]:
    if x.get("source_head") != PR114_HEAD or x.get("source_tree") != PR114_TREE:
        raise ValueError("HISTORICAL_HEAD_TREE_MISMATCH")
    if x.get("contract_blob") != PRODUCT_CONTRACT:
        raise ValueError("PRODUCT_CONTRACT_MISMATCH")
    if x.get("review_target") != "PR114 LBE-SIX-COMMAND-MVP PRODUCT_T1":
        raise ValueError("HISTORICAL_TARGET_MISMATCH")
    if x.get("status") != "PASS" or x.get("expected_positive_observations") != 18 or x.get("actual_positive_observations") != 18:
        raise ValueError("HISTORICAL_RESULT_MISMATCH")
    observations = x.get("observations")
    if not isinstance(observations, list) or len(observations) != 18:
        raise ValueError("MISSING_OBSERVATIONS")
    seen = set()
    for row in observations:
        if not isinstance(row, dict):
            raise ValueError("INVALID_OBSERVATION")
        key = (row.get("mode"), row.get("command_id"))
        if key[0] not in ROUTES or key[1] not in COMMAND_IDS or key in seen:
            raise ValueError("DUPLICATE_OR_INVALID_ROW")
        seen.add(key)
        if (row.get("kind") != "NATIVE_T1" or row.get("executed") is not True or
                row.get("status") != "exited" or row.get("exit_code") != 0 or
                row.get("output_complete") is not True):
            raise ValueError("UNQUALIFIED_HISTORICAL_OUTCOME")
    if seen != {(m, c) for m in ROUTES for c in COMMAND_IDS}:
        raise ValueError("INCOMPLETE_MATRIX")
    tools = x.get("tools")
    if not isinstance(tools, dict):
        raise ValueError("INVALID_TOOLS")
    for key in ("python_sha256", "pipenv_sha256", "go_sha256", "source_pipenv_sha256", "source_python_sha256"):
        val = tools.get(key)
        if not isinstance(val, str) or len(val) != 64 or any(c not in "0123456789abcdef" for c in val):
            raise ValueError("INVALID_HISTORICAL_TOOL_SHA")
    return observations


def validate_old_mixed(x: dict) -> None:
    if x.get("head") != PR114_HEAD or x.get("tree") != PR114_TREE or x.get("contract") != PRODUCT_CONTRACT:
        raise ValueError("MIXED_HEAD_TREE_OR_CONTRACT_MISMATCH")
    if x.get("status") != "PASS" or x.get("native_exit_code") != 0 or x.get("native_original_children") != 1:
        raise ValueError("MIXED_OUTCOME_MISMATCH")
    if x.get("original_child_overlapped_real_git_file") is not True or x.get("real_git_file_independent_under_unknown") is not True:
        raise ValueError("MIXED_ADJACENT_EVIDENCE_INCOMPLETE")
    if x.get("full_descendant_tree_clean") != "not_proven":
        raise ValueError("FALSE_CLEANUP_CLAIM")
    if {p.get("phase") for p in x.get("phases", [])} != {"before", "during", "after", "under-UNKNOWN"}:
        raise ValueError("MIXED_PHASES_INCOMPLETE")


def selftest(native: dict, mixed: dict) -> int:
    """Negative cases are in-memory changes only; no native or OS experiments."""
    cases = []
    a = copy.deepcopy(native); a["source_head"] = PR119_HEAD
    cases.append(("borrow_old_evidence_as_current_head", validate_old_native, a))
    a = copy.deepcopy(native); a["observations"][1]["command_id"] = a["observations"][0]["command_id"]
    cases.append(("duplicate_six_route_row", validate_old_native, a))
    a = copy.deepcopy(native); a["observations"][2]["exit_code"] = 1
    cases.append(("nonzero_original_exit", validate_old_native, a))
    a = copy.deepcopy(native); a["tools"]["go_sha256"] = "unproven"
    cases.append(("tool_hash_invalid", validate_old_native, a))
    a = copy.deepcopy(mixed); a["full_descendant_tree_clean"] = "yes"
    cases.append(("false_cleanup_promotion", validate_old_mixed, a))
    for label, validate, sample in cases:
        try:
            validate(sample)
        except ValueError:
            print("SAFE_T0_NEGATIVE_REJECTED", label)
        else:
            raise AssertionError("FAILED_TO_DENY:" + label)
    return len(cases)


def main(archive_dir: Path | None = None, output_path: Path | None = None) -> None:
    global ROOT
    if archive_dir is not None:
        ROOT = Path(archive_dir)
    native, ns = load_original(*ARTIFACTS[0][:3])
    mixed, ms = load_original(*ARTIFACTS[1][:3])
    rows = validate_old_native(native)
    validate_old_mixed(mixed)
    negative_count = selftest(native, mixed)
    tool_observations = native["tools"]
    grade = {
        "evidence_mode": "HISTORICAL_COMMITTED_NATIVE_RECEIPTS_PLUS_CURRENT_SOURCE_SAFE_T0",
        "historical_pr114_original_child_observed": True,
        "historical_native_routes_x_commands": len(rows),
        "historical_mixed_observed": True,
        "historical_source_head": PR114_HEAD,
        "historical_source_tree": PR114_TREE,
        "current_rc119_head": PR119_HEAD,
        "current_rc119_tree": PR119_TREE,
        "same_head_as_current_rc": False,
        "same_tree_as_current_rc": PR114_TREE == PR119_TREE,
        "historical_tool_sha256_observed": {k:tool_observations[k] for k in (
          "python_sha256", "pipenv_sha256", "go_sha256", "source_pipenv_sha256", "source_python_sha256")},
        "current_rc_toolchain_selected_bytes_proven": False,
        "current_rc_complete_installed_loader_graph_attested": False,
        "historical_full_descendant_cleanup_proven": False,
        "current_rc_native_six_plus_mixed_executed": False,
        "owner_exact_blob_six_risks_direct_chat_relay": True,
        "owner_exact_blob_acceptance_independently_authenticated": False,
        "profileb_effective_approved_exception": False,
        "actual_one_shot_owner_native_run_authorized": False,
        "full_code_review_pass": False,
        "integration_pass": False,
        "native_execution_decision": "DENY_UNAUTHORIZED_AND_UNQUALIFIED",
        "release_decision": "BLOCKED",
    }
    assert not any(grade[k] for k in (
        "same_head_as_current_rc", "current_rc_toolchain_selected_bytes_proven",
        "current_rc_complete_installed_loader_graph_attested", "current_rc_native_six_plus_mixed_executed",
        "owner_exact_blob_acceptance_independently_authenticated", "profileb_effective_approved_exception",
        "actual_one_shot_owner_native_run_authorized", "full_code_review_pass", "integration_pass"
    )), "EVIDENCE_GRADE_MUST_STAY_FAIL_CLOSED"
    output = {
        "kind": "RC119_PROFILEB_NATIVE_QUALIFICATION_PREPARATION_NONOPERATIVE",
        "authority": "A_DEVELOPER_STATIC_SAFE_T0_ONLY",
        "target": {"repo":REPO,"pr":119,"base_sha":PR119_BASE,"head_sha":PR119_HEAD,"tree_sha":PR119_TREE,"files":173},
        "contract": {"product_blob":PRODUCT_CONTRACT,"retained_pr102_gateb_blob":PR102_GATEB,
                     "proposed_profileb_blob":PROFILEB_PROPOSAL,"profileb_pr_head":PROFILEB_HEAD,
                     "profileb_status":"PROPOSED_NOT_EFFECTIVE", "owner_exact_risk_ratification":"DIRECT_OWNER_CHAT_ACCEPTED_A_RELAY_NOT_AUTHENTICATED_GITHUB",
                     "owner_a_relay":"https://github.com/chinanjjohn2012/mac-file-gateway/pull/121#issuecomment-6954483933"},
        "original_artifacts": [
            {"artifact_id":z[3],"workflow_run":z[4],"job_id":z[5],"zip_name":z[0],
             "zip_sha256":z[2],"zip_bytes":sz,"member":z[1],"source":"GH_ORIGINAL_ZIP_HASH_VERIFIED"}
            for z,sz in zip(ARTIFACTS,(ns,ms))
        ],
        "historical_tool_observations": {
            "go": {"path":tool_observations["go_path"],"sha256":tool_observations["go_sha256"]},
            "python": {"path":tool_observations["python_path"],"sha256":tool_observations["python_sha256"]},
            "pipenv": {"path":tool_observations["pipenv_path"],"sha256":tool_observations["pipenv_sha256"]},
            "historical_only":True, "current_rc119_attestation": "NOT_ATTESTED"
        },
        "input_lock": {"parent_pr":120,"template_blob":"205122891870f753718c807975b6a09319e8a1b8",
                       "categories_total":len(INPUT_LOCK_CATEGORIES),
                       "categories":[{"id":i,"actual_current_rc_selected_bytes":"NOT_ATTESTED"} for i in INPUT_LOCK_CATEGORIES],
                       "owner_native_test_permission":"NOT_GRANTED","global_one_shot_controller":"NOT_IMPLEMENTED"},
        "current_original_ci": {
          "linux":{"run":43838736072,"job":133201796713,"checkout":PR119_HEAD,"tree":PR119_TREE,
                   "g05_blob_mode":"PASS 433","g05_manifest":"PASS 432","pytest":"4239 PASSED / 19 SKIPPED / 52 subtests", "third_party_provenance":"NOT_ATTESTED","integration":"NOT_TESTED"},
          "macos_strict_r006":{"run":43838736229,"job":133201797399,"checkout":PR119_HEAD,
                                "conclusion":"FAIL", "exception":"D4R006HostAllowlistDenied: ambient credential-bearing environment is present"}
        },
        "blocked_role_verdicts":{"pr119_standards":"BLOCKED / INSUFFICIENT / FULL","pr119_spec":"BLOCKED / INSUFFICIENT / FULL",
                                 "pr113_standards_p2_evid_02":"OPEN","pr120_standards":"BLOCKED / INSUFFICIENT / TARGETED"},
        "grades":grade,
        "safe_t0_audit":{"historical_matrix_checked":18,"deliberate_negative_cases_rejected":negative_count,
                         "exec_or_network_test":"NOT_RUN","result":"PASS_ONLY_FOR_OFFLINE_RECEIPT_CONSISTENCY"},
        "missing_gate_oracles":[
          "OWNER_CHAT_ACCEPTANCE_PROVENANCE_INDEPENDENT_VERIFICATION_AND_CONTRACT_ACTIVATION",
          "REVIEWED_OPERATIVE_N1B_EXCEPTION_AND_APPLICABILITY",
          "QUALIFIED_SELECTED_CURRENT_FOREIGN_BYTES_IMPORT_LOADER_AND_FIXTURE",
          "SAME_UID_NO_ACCESSIBLE_SECRETS_PRE_FIRST_FOREIGN_INSTRUCTION",
          "GLOBAL_ATOMIC_OWNER_RUN_ID_ATTEMPT_ONE_USE_AND_PHASE_LEASE",
          "FIXED_CONTROL_HEAD_TREE_HOST_AND_INPUT_LOCK_DIGEST",
          "MACOS_STRICT_R006_HONEST_DISPOSITION",
          "ACTUAL_AUTHORIZED_CURRENT_HEAD_NATIVE_SIX_AND_MIXED_OBSERVATIONS",
          "SAME_SNAPSHOT_INDEPENDENT_BC_FULL_AND_R10",
          "REAL_INTEGRATION_AND_SEPARATE_RELEASE_PERMISSION",
        ]
    }
    p = Path(output_path) if output_path is not None else ROOT / "rc119_profileb_t1_qualification_preparation_20261118.json"
    p.write_text(json.dumps(output,indent=2,ensure_ascii=False,sort_keys=True)+"\n",encoding="utf-8")
    print("SAFE_T0_ORIGINAL_ARCHIVE_DIGESTS=PASS")
    print("SAFE_T0_HISTORICAL_SIX_ROUTE_MATRIX=PASS 18/18 HISTORICAL_ONLY")
    print("SAFE_T0_HISTORICAL_MIXED_RECEIPT=PASS HISTORICAL_ONLY")
    print("SAFE_T0_NEGATIVE_CASES=PASS",negative_count)
    print("RC119_T1_NATIVE_EXECUTION=NOT_RUN_NOT_AUTHORIZED")
    print("RC119_RELEASE_READY=NO")
    print("OUTPUT",p)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="T0-only historical receipts: never authorizes native T1")
    parser.add_argument("--archive-dir", type=Path, required=True, help="Directory with two separately preserved PR114 ZIPs")
    parser.add_argument("--output", type=Path, default=None, help="Local JSON report path")
    args = parser.parse_args()
    main(archive_dir=args.archive_dir, output_path=args.output)
