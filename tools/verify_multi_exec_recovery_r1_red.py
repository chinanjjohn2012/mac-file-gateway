"""R1 fixed-node deterministic RED verifier, intentionally NOT a GREEN check.

Exact JUnit test *parameter IDs* and per-test failure markers are pinned.
No set-size-only accounting, generic substring acceptance, collection/fixture
errors, accidental passing tests, or swapped parameter IDs. Status success
means test contracts are unimplemented, not that recovery is functional.
"""
from __future__ import annotations

from collections import Counter
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

CONTRACT = Path("tests/r1_contracts/contract_multi_exec_recovery_r1.py")
RED = {
    "test_normal_two_grants_do_not_authorize_apply": "NORMAL_PROOF_GATE",
    "test_normal_rest_apply_is_503_before_runner": "REST_PROOF_GATE",
    "test_normal_mcp_apply_rejects_cleanup_proof": "MCP_PROOF_GATE",
    "test_normal_denial_is_no_spawn_and_no_false_unknown":
        "NORMAL_DENIAL_ZERO_SPAWN",
    "test_mcp_transport_structured_exec_cleanup_denial":
        "MCP_TRANSPORT_ACCEPTED_UNQUALIFIED_EXEC",
    "test_info_false_available_when_proof_missing": "AVAILABLE_WITHOUT_PROOF",
    "test_info_health_same_exec_policy": "HEALTH_STATUS_PARITY",
    "test_nonqualified_status_never_exposes_full_tree_capability":
        "NO_FULL_TREE_PROOF_BY_DEFAULT",
    "test_quarantined_dry_run_is_not_misleading_preview":
        "QUARANTINED_PREVIEW",
    "test_quarantined_other_workspace_read_still_works":
        "FILE_READ_INDEPENDENT_OF_EXEC",
    "test_state_root_is_not_allowed_to_be_a_symlink":
        "SYMLINK_STATE_UNAVAILABLE",
    "test_foreign_hardlinked_record_fails_closed":
        "HARDLINK_STATE_UNAVAILABLE",
    "test_conflicting_second_owner_cannot_admit_exec": "OWNER_LOCK",
    "test_unreadable_state_root_cannot_fall_back_to_inmemory":
        "STATE_IO_FAIL_CLOSED",
    "test_ambiguous_sync_worker_failure_latches_quarantine":
        "PRIVATE_FACTORY_MISSING",
    "test_ambiguous_state_survives_service_restart":
        "CANONICAL_STATE_CODEC_MISSING",
    "test_quarantine_never_triggers_stale_pid_signal":
        "UNKNOWN_NO_STALE_PID_SIGNAL",
}
for env in ("GATEWAY_EXEC_TEST_GRANT", "GATEWAY_R1_TEST_ONLY",
            "PYTEST_CURRENT_TEST"):
    RED["test_environment_cannot_grant_test_only_retirement[" + env + "]"] = (
        "ENV_PROOF_BYPASS")
for name in ("unexpected-control.json", "temp-crash-after-write.tmp",
             "r-stale-running.json", "unknown-unretired.json"):
    RED["test_boot_untrusted_state_entry_quarantines[" + name + "]"] = (
        "BOOT_SCAN_QUARANTINE")
for phase in ("PREPARED", "RUNNING", "UNKNOWN"):
    RED["test_boot_well_formed_historical_attempt_is_quarantined[" +
        phase + "]"] = "CANONICAL_STATE_CODEC_MISSING"

# The exact 24 scenario IDs match the contract file. A swapped or duplicate
# ID fails even if the number of cases remains 24.
SCENARIOS = (
    "intent_file_fsync_failure",
    "intent_directory_fsync_failure",
    "intent_atomic_rename_failure",
    "deadline_before_popen",
    "ambiguous_popen_failure",
    "stream_drain_failure",
    "leader_wait_failure",
    "post_spawn_finalization_fsync_failure",
    "restart_after_prepared_before_popen",
    "restart_after_popen_before_identity",
    "restart_after_leader_reap",
    "restart_after_retire_before_response",
    "valid_internal_test_grant_group_retirement",
    "forged_or_client_supplied_grant",
    "grant_bound_to_other_service",
    "grant_bound_to_other_workspace_inode",
    "grant_invalidated_by_restart",
    "grant_invalidated_during_finalization",
    "detached_descendant_observed",
    "quota_full_without_retired",
    "retired_only_prune_and_dir_fsync",
    "retired_prune_directory_fsync_failure",
    "quota_exact_4096_records_16mib",
    "cancellation_during_final_state_fsync",
)
for case in SCENARIOS:
    if case == "forged_or_client_supplied_grant":
        marker = "FORGED_GRANT_ACCEPTED"
    elif case == "quota_full_without_retired":
        marker = "CANONICAL_STATE_CODEC_MISSING"
    else:
        marker = "PRIVATE_FACTORY_MISSING"
    RED["test_internal_state_fault_injection_contract[" + case + "]"] = marker

GREEN_GUARDS = (
    "test_config_test_only_grant_is_not_a_public_option",
    "test_rest_test_grant_request_field_is_rejected",
    "test_unrelated_git_authority_not_inferred",
    "test_no_remote_unquarantine_route",
)
EXPECTED = set(RED) | set(GREEN_GUARDS)
assert len(RED) == 51 and len(GREEN_GUARDS) == 4, (
    "R1_NODE_LEDGER_CHANGED_WITHOUT_EXPLICIT_REVIEW")


def main() -> int:
    if not CONTRACT.is_file():
        raise SystemExit("R1 verifier: contract file missing")
    with tempfile.TemporaryDirectory(prefix="mfg-r1-junit-") as temp:
        xml = Path(temp) / "r1.xml"
        command = [
            sys.executable, "-m", "pytest", "-q", "--tb=short",
            "-p", "no:cacheprovider", "--junitxml=" + str(xml),
            str(CONTRACT),
        ]
        result = subprocess.run(
            command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, timeout=180, check=False,
        )
        print(result.stdout[-22000:], flush=True)
        if not xml.is_file():
            raise SystemExit("R1 verification FAIL: no JUnit from pytest")
        root = ET.parse(xml).getroot()
        nodes = root.findall(".//testcase")
        found = Counter(node.get("name", "") for node in nodes)
        bad = []
        for name in sorted(EXPECTED | set(found)):
            if found[name] != (1 if name in EXPECTED else 0):
                bad.append("NodeID " + name + ": got " + str(found[name]))
        red_count = 0
        guard_count = 0
        missing_fixture_count = 0
        live_red_count = 0
        for node in nodes:
            name = node.get("name", "")
            # No parameters or class/filename spoofing.
            classname = node.get("classname", "")
            if not classname.endswith("contract_multi_exec_recovery_r1"):
                bad.append("Wrong testcase class: " + classname + "::" + name)
            errors = node.findall("error")
            skipped = node.findall("skipped")
            failure = node.find("failure")
            if errors or skipped:
                bad.append(name + ": error/skip not an allowed contract RED")
                continue
            if name in RED:
                if failure is None:
                    bad.append(name + ": unexpected GREEN (R2 work not yet gated)")
                    continue
                message = failure.get("message", "")
                match = re.search(r"R1_RED_[A-Z0-9_]+", message)
                marker = "R1_RED_" + RED[name]
                if match is None or match.group(0) != marker:
                    bad.append(name + ": unexpected RED marker " +
                               repr(message[:170]) + "; expected " + marker)
                    continue
                red_count += 1
                if RED[name] in ("PRIVATE_FACTORY_MISSING",
                                 "CANONICAL_STATE_CODEC_MISSING"):
                    missing_fixture_count += 1
                else:
                    live_red_count += 1
            elif name in GREEN_GUARDS:
                if failure is not None:
                    bad.append(name + ": existing guard failed")
                else:
                    guard_count += 1
            else:
                bad.append("Unexpected testcase " + name)
        if result.returncode != 1:
            bad.append("Expected pytest assertion exit=1, got " +
                       str(result.returncode))
        if red_count != 51 or guard_count != 4:
            bad.append("Observed RED/GREEN counts wrong: " +
                       repr((red_count, guard_count)))
        if bad:
            for item in bad:
                print("R1_RED_VERIFICATION_FAIL: " + item, flush=True)
            return 1
        print("R1_EXPECTED_RED=" + str(red_count))
        print("R1_EXISTING_GUARDS_GREEN=" + str(guard_count))
        print("R1_LIVE_CONTRACT_RED=" + str(live_red_count))
        print("R1_PRIVATE_FIXTURE_NOT_YET_IMPLEMENTED=" +
              str(missing_fixture_count))
        print("R1_CONTRACT_STAGE=RED_CONFIRMED_NOT_IMPLEMENTED")
        print("R1_NO_REAL_SUBPROCESS_OR_SIGNAL=TRUE")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
