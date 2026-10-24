"""Strict expected-RED classifier for the B1-B1-B/R0 internal bridge.

An intentionally failed admission assertion is NOT a subprocess cleanup
proof. The frozen B1-B1-A verifier and original product suite run separately.
"""
from __future__ import annotations

from collections import Counter
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

SUITE = Path("tests/b1b1b_contracts/contract_multi_exec_private_bridge_b1b1b.py")
RED = {
    "test_b1b1b_private_direct_untrusted_apply_denied_before_runner":
        "PRIVATE_DIRECT_DENY",
    "test_b1b1b_private_wire_rest_apply_requires_nonclient_proof[plain]":
        "PRIVATE_WIRE_REST_DENY",
    "test_b1b1b_private_wire_rest_apply_requires_nonclient_proof[forged]":
        "PRIVATE_WIRE_REST_DENY",
    "test_b1b1b_private_wire_mcp_apply_requires_nonclient_proof[plain]":
        "PRIVATE_WIRE_MCP_DENY",
    "test_b1b1b_private_wire_mcp_apply_requires_nonclient_proof[forged]":
        "PRIVATE_WIRE_MCP_DENY",
    "test_b1b1b_bridge_factory_rejects_caller_selected_scope":
        "BRIDGE_FACTORY_NO_ARGS",
    "test_b1b1b_trusted_bridge_factory_is_live_and_instance_bound":
        "TRUSTED_BRIDGE_FACTORY",
    "test_b1b1b_bridge_wire_apply_denies_every_untrusted_client":
        "BRIDGE_WIRE_DENY",
    "test_b1b1b_bridge_real_wire_mcp_nonpreview_denied[plain]":
        "BRIDGE_WIRE_MCP_DENY",
    "test_b1b1b_bridge_real_wire_mcp_nonpreview_denied[forged]":
        "BRIDGE_WIRE_MCP_DENY",
    "test_b1b1b_bridge_rest_body_cannot_mint_private_scope[test_mode]":
        "BRIDGE_BODY_REST_DENY",
    "test_b1b1b_bridge_rest_body_cannot_mint_private_scope[group_only_test_grant]":
        "BRIDGE_BODY_REST_DENY",
    "test_b1b1b_bridge_rest_body_cannot_mint_private_scope[_trusted_bound_listener]":
        "BRIDGE_BODY_REST_DENY",
    "test_b1b1b_bridge_rest_body_cannot_mint_private_scope[_internal_exec_grant]":
        "BRIDGE_BODY_REST_DENY",
    "test_b1b1b_bridge_mcp_arguments_cannot_mint_private_scope[test_mode]":
        "BRIDGE_BODY_MCP_DENY",
    "test_b1b1b_bridge_mcp_arguments_cannot_mint_private_scope[group_only_test_grant]":
        "BRIDGE_BODY_MCP_DENY",
    "test_b1b1b_bridge_mcp_arguments_cannot_mint_private_scope[_trusted_bound_listener]":
        "BRIDGE_BODY_MCP_DENY",
    "test_b1b1b_bridge_mcp_arguments_cannot_mint_private_scope[_internal_exec_grant]":
        "BRIDGE_BODY_MCP_DENY",
    "test_b1b1b_bridge_foreign_instance_never_borrows_grant":
        "BRIDGE_FOREIGN_INSTANCE",
    "test_b1b1b_trusted_inprocess_asgi_preview_is_not_network_auth":
        "TRUSTED_ASGI_PREVIEW",
    "test_b1b1b_trusted_inprocess_route_canary_is_not_network_reachable":
        "BRIDGE_TRUSTED_ROUTE_CANARY",
    "test_b1b1b_bridge_close_revokes_one_way":
        "BRIDGE_CLOSE_REVOKE",
    "test_b1b1b_bridge_close_preserves_real_inflight_ownership_on_fault[join_exception]":
        "BRIDGE_CLOSE_OWNER_RETAIN",
    "test_b1b1b_bridge_close_preserves_real_inflight_ownership_on_fault[join_returns_alive]":
        "BRIDGE_CLOSE_OWNER_RETAIN",
}
GREEN = {
    "test_b1b1b_guard_real_listener_loopback_preview_without_execution",
    "test_b1b1b_guard_foreign_listener_cannot_transfer_qualification",
    "test_b1b1b_guard_request_fields_cannot_set_internal_proof[test_mode]",
    "test_b1b1b_guard_request_fields_cannot_set_internal_proof[group_only_test_grant]",
    "test_b1b1b_guard_nested_import_or_initialization_error_is_not_expected_red",
    "test_b1b1b_guard_factory_signature_rejects_optional_untrusted_scope",
    "test_b1b1b_guard_network_mount_or_wrapper_graph_is_detectable",
    "test_b1b1b_guard_owner_lock_release_with_live_fd_is_detected",
    "test_b1b1b_guard_dynamic_dispatcher_and_metadata_route_are_rejected",
    "test_b1b1b_guard_closure_forwarding_private_asgi_is_rejected",
    "test_b1b1b_guard_route_app_header_forwarding_is_detected",
    "test_b1b1b_guard_mutated_middleware_and_exception_handlers_rejected",
    "test_b1b1b_guard_mcp_structured_error_precedence_selfcheck",
    "test_b1b1b_guard_fake_mcp_sdk_handler_origin_rejected",
    "test_b1b1b_guard_route_handle_instance_override_detected",
    "test_b1b1b_guard_cloned_route_app_foreign_globals_detected",
    "test_b1b1b_guard_sdk_manager_proxy_or_foreign_service_rejected",
    "test_b1b1b_guard_body_sourced_parser_proxy_bypass_is_not_denial",
    "test_b1b1b_guard_historical_real_subprocess_tests_are_present",
    "test_b1b1b_guard_normal_product_has_no_private_bridge_factory_import",
    "test_b1b1b_guard_existing_test_grant_not_serializable_or_reusable",
}
assert len(RED) == 24 and len(GREEN) == 21
EXPECTED = set(RED) | GREEN


def main():
    if not SUITE.is_file():
        print("B1B1B_EXPECTED_RED_FAIL: suite absent")
        return 1
    with tempfile.TemporaryDirectory(prefix="b1b1b-red-") as tmp:
        xml = Path(tmp) / "junit.xml"
        run = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "--tb=short",
             "-p", "no:cacheprovider", "--junitxml=" + str(xml), str(SUITE)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            check=False, timeout=210)
        print(run.stdout[-35000:], flush=True)
        if not xml.is_file():
            print("B1B1B_EXPECTED_RED_FAIL: no JUnit")
            return 1
        cases = ET.parse(xml).getroot().findall(".//testcase")
        counts = Counter(tc.get("name", "") for tc in cases)
        issues = []
        for name in sorted(EXPECTED | set(counts)):
            if counts[name] != (1 if name in EXPECTED else 0):
                issues.append("NodeID must occur exactly once: " + name +
                              " count=" + str(counts[name]))
        red = green = 0
        for tc in cases:
            name = tc.get("name", "")
            if not tc.get("classname", "").endswith(
                    "contract_multi_exec_private_bridge_b1b1b"):
                issues.append(name + ": wrong class")
            if tc.find("error") is not None or tc.find("skipped") is not None:
                issues.append(name + ": error/skip")
                continue
            failed = tc.find("failure")
            if name in RED:
                if failed is None:
                    issues.append(name + ": unexpectedly GREEN")
                    continue
                found = re.findall(r"B1B1B_RED_[A-Z0-9_]+",
                                   failed.get("message", ""))
                if found != ["B1B1B_RED_" + RED[name]]:
                    issues.append(name + ": wrong marker " + repr(found))
                    continue
                red += 1
            elif name in GREEN:
                if failed is not None:
                    issues.append(name + ": guard not GREEN: " +
                                  str(failed.get("message", ""))[:130])
                else:
                    green += 1
            else:
                issues.append(name + ": unexpected test")
        if run.returncode != 1 or red != 24 or green != 21:
            issues.append("wrong pytest status/counts: " +
                          repr((run.returncode, red, green)))
        if issues:
            for issue in issues:
                print("B1B1B_EXPECTED_RED_FAIL: " + issue, flush=True)
            return 1
        print("B1B1B_PRIVATE_BRIDGE_EXPECTED_RED=24")
        print("B1B1B_EXISTING_GUARDS_GREEN=21")
        print("B1B1B_CONTRACT_STAGE=RED_NOT_IMPLEMENTED")
        print("B1B1B_NO_HOST_SPAWN_OR_SIGNAL=TRUE")
        print("B1B1B_HISTORICAL_REAL_EXEC_TESTS=UNCHANGED")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
