"""Strict verification that the isolated R1 contract suite is intentionally RED.

A successful job proves existing product regressions GREEN and precisely named
new contracts fail with controlled R1_RED markers. It does NOT prove the
future implementation. Unexpected GREEN, import/collection error, skipped
test or unrelated runtime crash makes this verification FAIL.
"""
from __future__ import annotations

from collections import Counter
from pathlib import Path
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

CONTRACT = Path("tests/r1_contracts/contract_multi_exec_recovery_r1.py")

# Test groups and exact parameter counts are part of the R1 contract ledger.
EXPECTED_RED = {
    "test_normal_two_grants_do_not_authorize_apply": 1,
    "test_normal_rest_apply_is_503_before_runner": 1,
    "test_normal_mcp_apply_rejects_cleanup_proof": 1,
    "test_environment_cannot_grant_test_only_retirement": 3,
    "test_info_false_available_when_proof_missing": 1,
    "test_info_health_same_exec_policy": 1,
    "test_nonqualified_status_never_exposes_full_tree_capability": 1,
    "test_boot_untrusted_state_entry_quarantines": 4,
    "test_quarantined_dry_run_is_not_misleading_preview": 1,
    "test_quarantined_other_workspace_read_still_works": 1,
    "test_state_root_is_not_allowed_to_be_a_symlink": 1,
    "test_foreign_hardlinked_record_fails_closed": 1,
    "test_conflicting_second_owner_cannot_admit_exec": 1,
    "test_unreadable_state_root_cannot_fall_back_to_inmemory": 1,
    "test_ambiguous_sync_worker_failure_latches_quarantine": 1,
    "test_ambiguous_state_survives_service_restart": 1,
    "test_quarantine_never_triggers_stale_pid_signal": 1,
    "test_internal_state_fault_injection_contract": 24,
}
EXPECTED_GREEN_GUARDS = {
    "test_config_test_only_grant_is_not_a_public_option": 1,
    "test_rest_test_grant_request_field_is_rejected": 1,
    "test_unrelated_git_authority_not_inferred": 1,
    "test_no_remote_unquarantine_route": 1,
}


def main() -> int:
    if not CONTRACT.is_file():
        raise SystemExit("R1 verification: required contract file is missing")
    with tempfile.TemporaryDirectory(prefix="mfg-r1-junit-") as temp:
        xml = Path(temp) / "red.xml"
        command = [
            sys.executable, "-m", "pytest", "-q",
            "--tb=short", "-p", "no:cacheprovider",
            "--junitxml=" + str(xml), str(CONTRACT),
        ]
        p = subprocess.run(command, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, text=True, check=False,
                           timeout=180)
        print(p.stdout[-19000:], flush=True)
        if not xml.exists():
            raise SystemExit("R1 verification FAIL: pytest did not produce JUnit")
        root = ET.parse(xml).getroot()
        cases = root.findall(".//testcase")
        counts = Counter()
        bad = []
        observed_red = 0
        observed_green = 0
        for case in cases:
            test_name = case.attrib.get("name", "")
            group = test_name.split("[", 1)[0]
            counts[group] += 1
            failure = case.find("failure")
            error = case.find("error")
            skipped = case.find("skipped")
            if error is not None or skipped is not None:
                bad.append(group + ": error/skip is NOT a controlled RED")
                continue
            if group in EXPECTED_RED:
                if failure is None:
                    bad.append(group + ": unexpected GREEN; cannot claim R1 RED")
                    continue
                message = failure.attrib.get("message", "") + " " + (
                    failure.text or "")
                if "R1_RED_" not in message:
                    bad.append(group + ": failed without R1_RED marker ("
                               + message[:120] + ")")
                    continue
                observed_red += 1
            elif group in EXPECTED_GREEN_GUARDS:
                if failure is not None:
                    bad.append(group + ": existing safety guard became RED")
                else:
                    observed_green += 1
            else:
                bad.append(group + ": unexpected/unregistered test")
        expected = {**EXPECTED_RED, **EXPECTED_GREEN_GUARDS}
        for name in sorted(set(expected) | set(counts)):
            if counts[name] != expected.get(name, 0):
                bad.append(name + ": count " + str(counts[name]) +
                           ", expected " + str(expected.get(name, 0)))
        if p.returncode != 1:
            bad.append("pytest exit code " + str(p.returncode)
                       + ", expected exactly 1 for assertion RED")
        if bad:
            for problem in bad:
                print("R1_RED_VERIFICATION_FAIL: " + problem, flush=True)
            return 1
        print("R1_EXPECTED_RED=" + str(observed_red))
        print("R1_EXISTING_GUARDS_GREEN=" + str(observed_green))
        print("R1_CONTRACT_STAGE=RED_CONFIRMED_NOT_IMPLEMENTED")
        print("R1_NO_REAL_SUBPROCESS_OR_SIGNAL=TRUE")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
