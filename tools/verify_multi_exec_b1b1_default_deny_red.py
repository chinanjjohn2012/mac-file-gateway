"""Strict B1-B1-A *expected RED*, not product-default-DENY success.

Never normalize all failing tests as expected. Every NodeID must match the
specific absent-product-contract marker, all existing guard NodeIDs must
pass, no skip/collection errors are accepted, and no unexpected test runs.
The next B1-B1 implementation must change this gate to actual GREEN rather
than altering the already-reviewed test/blob or exempting product tests.
"""
from __future__ import annotations

from collections import Counter
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

SUITE = Path("tests/b1b1_contracts/contract_multi_exec_default_deny_b1b1.py")
RED = {
    "test_b1b1_normal_direct_apply_denies_before_any_intent": "DEFAULT_DIRECT",
    "test_b1b1_normal_rest_apply_503_denied_before_any_intent": "DEFAULT_REST",
    "test_b1b1_normal_mcp_apply_structured_proof_error": "DEFAULT_MCP",
    "test_b1b1_info_health_report_same_unavailable_proof_policy": "POLICY_PARITY",
    "test_b1b1_missing_proof_precedes_worker_busy_slot": "PROOF_BEFORE_BUSY",
    "test_b1b1_env_cannot_mint_cleanup_proof[GATEWAY_EXEC_TEST_GRANT]": "ENV_BYPASS",
    "test_b1b1_env_cannot_mint_cleanup_proof[GATEWAY_R1_TEST_ONLY]": "ENV_BYPASS",
    "test_b1b1_rest_header_cannot_mint_cleanup_proof[x-gateway-test-mode]": "REST_HEADER_BYPASS",
    "test_b1b1_rest_header_cannot_mint_cleanup_proof[x-internal-group-retirement-grant]": "REST_HEADER_BYPASS",
    "test_b1b1_mcp_header_cannot_mint_cleanup_proof[x-gateway-test-mode]": "MCP_HEADER_BYPASS",
    "test_b1b1_mcp_header_cannot_mint_cleanup_proof[x-internal-group-retirement-grant]": "MCP_HEADER_BYPASS",
}
GREEN = {
    "test_b1b1_guard_ordinary_preview_remains_allowed",
    "test_b1b1_guard_global_off_precedes_proof",
    "test_b1b1_guard_file_read_independent_of_missing_exec_proof",
    "test_b1b1_guard_client_fields_cannot_select_private_proof[test_grant]",
    "test_b1b1_guard_client_fields_cannot_select_private_proof[listener_host]",
    "test_b1b1_guard_client_fields_cannot_select_private_proof[full_descendant_tree_clean]",
    "test_b1b1_guard_client_fields_cannot_select_private_proof[test_mode]",
    "test_b1b1_guard_client_fields_cannot_select_private_proof[group_only_test_grant]",
    "test_b1b1_guard_client_fields_cannot_select_private_proof[_trusted_bound_listener]",
    "test_b1b1_guard_client_fields_cannot_select_private_proof[transport]",
    "test_b1b1_guard_mcp_arguments_cannot_mint_private_proof[test_mode]",
    "test_b1b1_guard_mcp_arguments_cannot_mint_private_proof[test_grant]",
    "test_b1b1_guard_mcp_arguments_cannot_mint_private_proof[group_only_test_grant]",
    "test_b1b1_guard_mcp_arguments_cannot_mint_private_proof[_trusted_bound_listener]",
    "test_b1b1_guard_mcp_arguments_cannot_mint_private_proof[listener_host]",
    "test_b1b1_guard_status_policy_oracle_rejects_private_metadata",
    "test_b1b1_guard_busy_intent_witness_detects_transient_write_delete",
    "test_b1b1_guard_transient_intent_witness_rejects_write_then_delete",
    "test_b1b1_guard_python_file_io_detects_transient_prepared[path.open]",
    "test_b1b1_guard_python_file_io_detects_transient_prepared[path.write_bytes]",
    "test_b1b1_guard_python_file_io_detects_transient_prepared[builtins.open]",
    "test_b1b1_guard_physical_alias_intent_cannot_look_clean",
    "test_b1b1_guard_moved_root_pinned_fd_intent_cannot_look_clean",
    "test_b1b1_guard_root_rename_roundtrip_alone_is_not_zero_intent",
    "test_b1b1_guard_nested_config_fd_record_write_delete[exec-state]",
    "test_b1b1_guard_nested_config_fd_record_write_delete[state-alias]",
    "test_b1b1_guard_hardlinked_prepared_moved_out[rename]",
    "test_b1b1_guard_hardlinked_prepared_moved_out[replace]",
    "test_b1b1_guard_illegal_symlink_record_visible_in_snapshot[absolute]",
    "test_b1b1_guard_illegal_symlink_record_visible_in_snapshot[pinned_fd]",
    "test_b1b1_guard_host_interceptor_is_type_preserving",
}
assert len(RED) == 11 and len(GREEN) == 31
EXPECTED = set(RED) | GREEN


def main() -> int:
    if not SUITE.is_file():
        print("B1B1_EXPECTED_RED_FAIL: missing contract suite", flush=True)
        return 1
    with tempfile.TemporaryDirectory(prefix="b1b1-expected-red-") as tmp:
        xml = Path(tmp) / "junit.xml"
        run = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "--tb=short",
             "-p", "no:cacheprovider", "--junitxml=" + str(xml), str(SUITE)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            check=False, timeout=210)
        print(run.stdout[-35000:], flush=True)
        if not xml.exists():
            print("B1B1_EXPECTED_RED_FAIL: no JUnit XML", flush=True)
            return 1
        tests = ET.parse(xml).getroot().findall(".//testcase")
        counts = Counter(tc.get("name", "") for tc in tests)
        problems = []
        for nodeid in sorted(EXPECTED | set(counts)):
            if counts[nodeid] != (1 if nodeid in EXPECTED else 0):
                problems.append("Expected exact NodeID once: " + nodeid +
                                " observed=" + str(counts[nodeid]))
        red = green = 0
        for tc in tests:
            name = tc.get("name", "")
            if not tc.get("classname", "").endswith(
                    "contract_multi_exec_default_deny_b1b1"):
                problems.append(name + ": unexpected test class")
            if tc.find("error") is not None or tc.find("skipped") is not None:
                problems.append(name + ": setup/collection error or skipped")
                continue
            failed = tc.find("failure")
            if name in RED:
                if failed is None:
                    problems.append(name + ": unexpectedly GREEN")
                    continue
                message = failed.get("message", "")
                matches = re.findall(r"B1B1_RED_[A-Z0-9_]+", message)
                if matches != ["B1B1_RED_" + RED[name]]:
                    problems.append(name + ": unrelated RED " + repr(message[:180]))
                    continue
                red += 1
            elif name in GREEN:
                if failed is not None:
                    problems.append(name + ": required guard not GREEN: " +
                                    str(failed.get("message", ""))[:180])
                else:
                    green += 1
            else:
                problems.append(name + ": unexpected NodeID")
        if run.returncode != 1:
            problems.append("Expected pytest exit 1 from missing product behavior; got " +
                            str(run.returncode))
        if red != len(RED) or green != len(GREEN):
            problems.append("RED/GREEN mismatch: " + repr((red, green)))
        if problems:
            for problem in problems:
                print("B1B1_EXPECTED_RED_FAIL: " + problem, flush=True)
            return 1
        print("B1B1_DEFAULT_DENY_EXPECTED_RED=11")
        print("B1B1_EXISTING_GUARDS_GREEN=31")
        print("B1B1_CONTRACT_STAGE=RED_NOT_IMPLEMENTED")
        print("B1B1_NO_HOST_SPAWN_OR_SIGNAL=TRUE")
        print("B1B1_EXISTING_REAL_EXEC_PRODUCT_TESTS=UNCHANGED")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
