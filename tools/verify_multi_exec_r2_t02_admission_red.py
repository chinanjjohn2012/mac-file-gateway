"""T02-A exact-node expected RED gate (not an implementation GREEN gate)."""
from __future__ import annotations

from collections import Counter
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

SUITE = Path("tests/t02_contracts/contract_multi_exec_admission_t02.py")
RED = {
    "test_t02_boot_pins_state_and_owns_exclusive_lock":
        "BOOT_STATE_NOT_OPENED",
    "test_t02_normal_apply_requires_proof_before_worker_or_intent":
        "NORMAL_PROOF_GATE",
    "test_t02_rest_apply_is_structured_503_and_zero_runner_calls":
        "REST_PROOF_GATE",
    "test_t02_mcp_tools_call_structured_proof_error_before_runner":
        "MCP_PROOF_GATE",
    "test_t02_normal_policy_reports_no_available_cleanup_qualification":
        "NORMAL_STATUS_AVAILABILITY",
    "test_t02_health_and_info_return_identical_sanitized_policy":
        "HEALTH_INFO_POLICY_PARITY",
    "test_t02_corrupt_disk_record_is_quarantined_without_mutation":
        "BOOT_CORRUPT_RECORD_IGNORED",
    "test_t02_competing_owner_latches_unavailable_and_refuses_preview":
        "OWNER_LOCK_FAIL_CLOSED",
    "test_t02_quarantined_preview_and_apply_both_deny_before_runner":
        "QUARANTINE_PREVIEW_OR_APPLY",
    "test_t02_exec_disabled_status_is_distinct_from_unavailable":
        "DISABLED_STATUS_DISTINCTION",
    "test_t02_external_environment_cannot_grant_cleanup_proof":
        "ENV_PROOF_BYPASS",
}
for phase in ("PREPARED", "RUNNING", "UNKNOWN"):
    RED[
        "test_t02_boot_replays_no_unresolved_attempt_and_quarantines[" +
        phase + "]"
    ] = "BOOT_UNRESOLVED_NOT_QUARANTINED"

GREEN = (
    "test_t02_guard_preview_keeps_ordinary_validation",
    "test_t02_guard_file_read_independent_of_exec_quarantine",
    "test_t02_guard_external_configuration_cannot_inject_private_grant",
    "test_t02_guard_host_interceptor_rejects_process_and_group_signal",
    "test_t02_guard_witness_rejects_write_then_delete_even_if_denial[store.prepare]",
    "test_t02_guard_witness_rejects_write_then_delete_even_if_denial[raw.replace]",
)
assert len(RED) == 14 and len(GREEN) == 6
EXPECTED = set(RED) | set(GREEN)


def main() -> int:
    if not SUITE.is_file():
        print("T02_ADMISSION_RED_FAIL: contract file not found")
        return 1
    with tempfile.TemporaryDirectory(prefix="t02-red-") as root:
        xml = Path(root) / "junit.xml"
        result = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "--tb=short",
             "-p", "no:cacheprovider", "--junitxml=" + str(xml),
             str(SUITE)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            timeout=180, check=False,
        )
        print(result.stdout[-30000:], flush=True)
        if not xml.exists():
            print("T02_ADMISSION_RED_FAIL: no JUnit XML")
            return 1
        testcase = ET.parse(xml).getroot().findall(".//testcase")
        counts = Counter(x.get("name", "") for x in testcase)
        problems = []
        for name in sorted(EXPECTED | set(counts)):
            if counts[name] != (1 if name in EXPECTED else 0):
                problems.append("NodeID " + name + " observed " +
                                str(counts[name]))
        red = green = 0
        for node in testcase:
            name = node.get("name", "")
            if not node.get("classname", "").endswith(
                    "contract_multi_exec_admission_t02"):
                problems.append("unexpected testcase class: " + name)
            if node.find("error") is not None or node.find("skipped") is not None:
                problems.append(name + ": collection/setup error or skipped")
                continue
            failed = node.find("failure")
            if name in RED:
                if failed is None:
                    problems.append(name + ": unexpectedly GREEN (not yet integrated)")
                    continue
                message = failed.get("message", "")
                match = re.search(r"T02_RED_[A-Z0-9_]+", message)
                expected = "T02_RED_" + RED[name]
                if match is None or match.group(0) != expected:
                    problems.append(name + ": unrelated failure " +
                                    repr(message[:170]) + " != " + expected)
                    continue
                red += 1
            elif name in GREEN:
                if failed is not None:
                    problems.append(name + ": existing guard not GREEN")
                else:
                    green += 1
            else:
                problems.append("unexpected testcase: " + name)
        if result.returncode != 1:
            problems.append("expected pytest assertion exit=1; got " +
                            str(result.returncode))
        if red != 14 or green != 6:
            problems.append("incorrect RED/GREEN counts: " +
                            repr((red, green)))
        if problems:
            for x in problems:
                print("T02_ADMISSION_RED_FAIL: " + x, flush=True)
            return 1
        print("T02_ADMISSION_EXPECTED_RED=14")
        print("T02_ADMISSION_GUARDS_GREEN=6")
        print("T02_ADMISSION_STAGE=CONTRACT_RED_NOT_IMPLEMENTATION")
        print("T02_NO_HOST_POPEN_OR_SIGNAL=TRUE")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
