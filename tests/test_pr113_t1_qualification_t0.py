"""T0-only regression: no product import, no child, network or package install."""
from __future__ import annotations

import copy
from contextlib import redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest

from tools.pr113_t1_control_t0 import GateDenied
from tools.pr113_t1_qualification_t0 import (
    COMMANDS, CONTROL_SOURCE_HEAD, EVENT_ORIGINS, NETWORK_DESIGN_BLOB,
    PROFILE_A, PROFILE_B, REQUIRED_INPUT_CLASSES, TRANSPORTS,
    canonical_vector, check_command_vector, check_qualification_lock,
    classify_event, digest_existing_regular, grade_observation,
    native_execution_decision, preflight_report, main,
)

LOCK = Path(__file__).resolve().parents[1] / "docs" / "PR113_T1_QUALIFICATION_LOCK_002.json"


def event(code: str, observed: bool = True) -> dict:
    return dict(code=code, origin=EVENT_ORIGINS[code], observed=observed)


class CanonicalMatrixT0(unittest.TestCase):
    def test_18_exact_vectors(self):
        seen = set()
        for cmd in COMMANDS:
            for transport in TRANSPORTS:
                with self.subTest(cmd=cmd, transport=transport):
                    vec = canonical_vector(cmd, transport)
                    check_command_vector(vec)
                    seen.add((vec["command_id"], vec["transport"]))
        self.assertEqual(len(seen), 18)

    def test_pipenv_request_not_equal_actual_effective_vector(self):
        vec = canonical_vector("S3", "REST")
        self.assertEqual(vec["request_argv"], ["python", "-m", "pytest", "-q"])
        self.assertEqual(vec["effective_argv"], ["pipenv", "run", "python", "-m", "pytest", "-q"])
        self.assertEqual(vec["runner"], "pipenv")

    def test_illegal_command_or_transport_denies(self):
        for code, mode in (("S7", "Direct"), ("S1", "Shell"), ([], "REST"), ("S1", {})):
            with self.subTest(code=str(code), mode=str(mode)), self.assertRaises(GateDenied):
                canonical_vector(code, mode)

    def test_all_six_fields_reject_drift(self):
        example = canonical_vector("S6", "MCP_SERVER_JSON_RPC")
        for field, bad in (("command_id", "S7"), ("transport", "shell"),
                           ("workspace", "other"), ("runner", "go"),
                           ("request_argv", ["go", "run", "."]),
                           ("effective_argv", ["go", "build", "./other"])):
            with self.subTest(field=field), self.assertRaises(GateDenied):
                check_command_vector({**example, field: bad})

    def test_s3_client_cannot_switch_runner_or_pipenv(self):
        vec = canonical_vector("S3", "Direct")
        for changed in ({**vec, "runner": "direct"},
                        {**vec, "effective_argv": vec["request_argv"]},
                        {**vec, "request_argv": vec["effective_argv"]},
                        {**vec, "effective_argv": vec["effective_argv"]+["--unsafe"]}):
            with self.assertRaises(GateDenied):
                check_command_vector(changed)

    def test_missing_field_or_bool_argv_reject(self):
        vec = canonical_vector("S1", "REST")
        del vec["workspace"]
        with self.assertRaises(GateDenied):
            check_command_vector(vec)
        vec = canonical_vector("S1", "REST")
        vec["request_argv"][0] = True
        with self.assertRaises(GateDenied):
            check_command_vector(vec)


class NetworkGradeT0(unittest.TestCase):
    def test_twelve_unique_event_origins(self):
        self.assertEqual(tuple(EVENT_ORIGINS), tuple("T%02d" % i for i in range(1, 13)))
        self.assertEqual(len(EVENT_ORIGINS), 12)

    def test_all_A_B_event_rules_consistent_nonexecuting(self):
        for code in EVENT_ORIGINS:
            for profile in (PROFILE_A, PROFILE_B):
                with self.subTest(code=code, profile=profile):
                    out = classify_event(event(code), profile=profile)
                    self.assertEqual(out.code, code)
                    self.assertFalse(out.no_egress_proven)
                    self.assertFalse(out.source_closed_proven)

    def test_B_public_dns_risk_vs_A_security_failure(self):
        a = classify_event(event("T04"), profile=PROFILE_A)
        b = classify_event(event("T04"), profile=PROFILE_B)
        self.assertEqual(a.rule, "SECURITY_FAIL")
        self.assertEqual(b.rule, "ACCEPTED_NETWORK_RISK")
        self.assertTrue(a.stop_new_admissions)
        self.assertFalse(b.stop_new_admissions)

    def test_controller_late_download_not_child_accepted_risk(self):
        self.assertEqual(classify_event(event("T02"), profile=PROFILE_B).rule, "CONTROL_FAIL")
        with self.assertRaises(GateDenied):
            classify_event({**event("T02"), "origin": "native_child"}, profile=PROFILE_B)

    def test_child_dynamic_source_blocks_even_exit_zero(self):
        r = grade_observation(original_child_exit=0, events=[event("T04"), event("T06")], profile=PROFILE_B)
        self.assertEqual(r["original_child_observation"], "OBSERVED_EXIT0")
        self.assertEqual(r["first_disqualifier"], "SOURCE_INTEGRITY_FAIL")
        self.assertTrue(r["stop_new_admissions"])
        self.assertEqual(r["qualified_t1"], "NOT_QUALIFIED_T0_ONLY")

    def test_unknown_network_input_changes_result_and_blocks(self):
        r = grade_observation(original_child_exit=0, events=[event("T05")], profile=PROFILE_B)
        self.assertEqual(r["first_disqualifier"], "SOURCE_RESULT_PROVENANCE_FAIL")

    def test_secret_attempt_outweighs_accepted_dns_or_bad_source(self):
        r = grade_observation(original_child_exit=0,
                              events=[event("T04"), event("T06"), event("T08")], profile=PROFILE_B)
        self.assertEqual(r["first_disqualifier"], "SECURITY_FAIL")
        self.assertTrue(r["stop_new_admissions"])

    def test_private_service_contact_is_not_waived(self):
        self.assertEqual(classify_event(event("T09"), profile=PROFILE_B).rule, "SECURITY_FAIL")

    def test_missing_monitor_does_not_claim_no_egress(self):
        r = grade_observation(original_child_exit=None, events=[event("T11")], profile=PROFILE_B)
        self.assertEqual(r["network_observability"], "NOT_ASSESSED")
        self.assertEqual(r["original_child_observation"], "NOT_OBSERVED")
        self.assertFalse(r["no_egress_proven"])
        self.assertFalse(r["source_closed_proven"])

    def test_a_has_no_auto_b_fallback(self):
        self.assertEqual(classify_event(event("T10"), profile=PROFILE_A).rule, "PRELAUNCH_BLOCKED")
        self.assertEqual(classify_event(event("T10"), profile=PROFILE_B).rule, "NOT_APPLICABLE_TO_B")

    def test_unobserved_is_not_absence_proof(self):
        a = classify_event(event("T06", observed=False), profile=PROFILE_B)
        self.assertEqual(a.rule, "UNVERIFIED_EVENT")
        self.assertTrue(a.stop_new_admissions)

    def test_invalid_event_metadata_denies(self):
        bad = [
            {**event("T06"), "origin": "controller_acquisition"},
            {**event("T06"), "observed": 1},
            {**event("T06"), "extra": "untrusted"},
            {**event("T06"), "code": "T13"},
            {"code": "T06", "origin": "native_child"},
        ]
        for obj in bad:
            with self.subTest(obj=str(obj)), self.assertRaises(GateDenied):
                classify_event(obj, profile=PROFILE_B)
        with self.assertRaises(GateDenied):
            classify_event(event("T06"), profile="BOUNDED_EGRESS")

    def test_ambiguous_or_duplicate_receipt_fails_closed(self):
        for events in ([], [event("T04"), event("T04")], [{}]):
            with self.assertRaises(GateDenied):
                grade_observation(original_child_exit=0, events=events, profile=PROFILE_B)
        for invalid in (True, "0", 300, -260, 1.0):
            with self.assertRaises(GateDenied):
                grade_observation(original_child_exit=invalid, events=[event("T04")], profile=PROFILE_B)

    def test_exit0_never_automatically_qualified(self):
        r = grade_observation(original_child_exit=0, events=[event("T03")], profile=PROFILE_B)
        self.assertEqual(r["first_disqualifier"], "NO_DISQUALIFYING_EVENT_OBSERVED")
        self.assertEqual(r["qualified_t1"], "NOT_QUALIFIED_T0_ONLY")


class ByteInputLockT0(unittest.TestCase):
    def setUp(self):
        self.lock = json.loads(LOCK.read_text(encoding="utf-8"))

    def test_full_nine_input_classes_but_all_unqualified(self):
        pending = check_qualification_lock(self.lock)
        self.assertEqual(set(x["class"] for x in self.lock["inputs"]), REQUIRED_INPUT_CLASSES)
        self.assertTrue(REQUIRED_INPUT_CLASSES.issubset(set(pending)))
        self.assertIn("owner_t1_authorized", pending)
        self.assertIn("credential_absence_proven", pending)
        self.assertIn("global_one_use_proven", pending)
        self.assertIn("executable_controller_reviewed", pending)
        self.assertIn("runner_context_qualified", pending)

    def test_network_user_approval_does_not_grant_native(self):
        self.assertEqual(self.lock["network_design_blob"], NETWORK_DESIGN_BLOB)
        self.assertEqual(self.lock["network_profile"], PROFILE_B)
        self.assertFalse(self.lock["owner_t1_authorized"])
        with self.assertRaises(GateDenied):
            native_execution_decision(self.lock)

    def test_forged_all_true_cannot_grant(self):
        obj = copy.deepcopy(self.lock)
        for key in ("owner_t1_authorized", "credential_absence_proven",
                    "global_one_use_proven", "executable_controller_reviewed", "runner_context_qualified"):
            obj[key] = True
        self.assertEqual(len(check_qualification_lock(obj)), 9)
        with self.assertRaises(GateDenied):
            native_execution_decision(obj)

    def test_machine_readable_safe_preflight_has_no_allow(self):
        report = preflight_report(self.lock)
        self.assertEqual(report["decision"], "DENY")
        self.assertFalse(report["native_execution_authorized"])
        self.assertEqual(report["input_classes_pending"], 9)
        self.assertIn("owner_t1_authorized", report["blockers"])

    def test_safe_cli_returns_nonzero_and_never_emits_permit(self):
        out = io.StringIO()
        with redirect_stdout(out):
            status = main([])
        self.assertEqual(status, 3)
        result = json.loads(out.getvalue())
        self.assertEqual(result["decision"], "DENY")
        self.assertFalse(result["native_execution_authorized"])
        self.assertNotIn("ALLOW", out.getvalue())

    def test_cli_rejects_any_extra_arguments(self):
        out = io.StringIO()
        with redirect_stdout(out):
            status = main(["--run-native"])
        self.assertEqual(status, 3)
        self.assertEqual(json.loads(out.getvalue())["decision"], "DENY")

    def test_old_ambiguous_network_enum_denies(self):
        obj = copy.deepcopy(self.lock)
        obj["network_profile"] = "BOUNDED_TRUSTED_LOCAL"
        with self.assertRaises(GateDenied):
            check_qualification_lock(obj)

    def test_wrong_source_design_version_denies(self):
        obj = copy.deepcopy(self.lock)
        obj["network_design_blob"] = "0"*40
        with self.assertRaises(GateDenied):
            check_qualification_lock(obj)

    def test_duplicate_or_missing_input_classes_denies(self):
        obj = copy.deepcopy(self.lock)
        obj["inputs"][0] = copy.deepcopy(obj["inputs"][1])
        with self.assertRaises(GateDenied):
            check_qualification_lock(obj)
        obj = copy.deepcopy(self.lock)
        obj["inputs"].pop()
        with self.assertRaises(GateDenied):
            check_qualification_lock(obj)

    def test_forged_future_qualification_status_denies(self):
        obj = copy.deepcopy(self.lock)
        obj["inputs"][0]["status"] = "VERIFIED_NEW_INPUT"
        with self.assertRaises(GateDenied):
            check_qualification_lock(obj)

    def test_malformed_sha_or_bool_size_denies(self):
        obj = copy.deepcopy(self.lock)
        obj["inputs"][0]["selected_sha256"] = "abc"
        with self.assertRaises(GateDenied):
            check_qualification_lock(obj)
        obj = copy.deepcopy(self.lock)
        obj["inputs"][0]["selected_size_bytes"] = True
        with self.assertRaises(GateDenied):
            check_qualification_lock(obj)

    def test_source_blob_is_only_source_not_loaded_input(self):
        obj = copy.deepcopy(self.lock)
        obj["inputs"][5]["source_git_blob"] = "f"*40
        obj["inputs"][5]["status"] = "SOURCE_BLOB_ONLY"
        pending = check_qualification_lock(obj)
        self.assertIn(obj["inputs"][5]["class"], pending)


class FdDigestT0(unittest.TestCase):
    def test_private_root_regular_file_sha256(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            root.chmod(0o700)
            file = root / "wheel.bin"
            file.write_bytes(b"safe small offline fixture")
            self.assertEqual(digest_existing_regular(file, root),
                             (hashlib.sha256(file.read_bytes()).hexdigest(), file.stat().st_size))

    def test_hardlink_or_symlink_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "owned"
            root.mkdir(mode=0o700)
            f = root / "source.bin"
            f.write_bytes(b"fixture")
            (root / "symlink").symlink_to(f)
            os.link(f, root / "hardlink")
            for path in (root / "symlink", root / "hardlink"):
                with self.subTest(path=str(path)), self.assertRaises(GateDenied):
                    digest_existing_regular(path, root)

    def test_outside_or_relative_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            root.chmod(0o700)
            f = root / "in"
            f.write_bytes(b"safe")
            with self.assertRaises(GateDenied):
                digest_existing_regular(Path("in"), root)
            with self.assertRaises(GateDenied):
                digest_existing_regular(root, root)
            with self.assertRaises(GateDenied):
                digest_existing_regular(Path(tmp).parent / "external", root)

    def test_nonprivate_root_and_parent_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            f = root / "safe"
            f.write_bytes(b"hi")
            root.chmod(0o755)
            with self.assertRaises(GateDenied):
                digest_existing_regular(f, root)
            root.chmod(0o700)
            sub = root / "public"
            sub.mkdir(mode=0o755)
            (sub / "safe").write_bytes(b"hi")
            with self.assertRaises(GateDenied):
                digest_existing_regular(sub / "safe", root)

    def test_symlink_ancestor_of_private_root_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            actual = Path(tmp) / "actual"
            actual.mkdir(mode=0o700)
            (actual / "f").write_bytes(b"safe")
            (Path(tmp) / "parent_link").symlink_to(actual, target_is_directory=True)
            with self.assertRaises(GateDenied):
                digest_existing_regular(Path(tmp) / "parent_link" / "f",
                                        Path(tmp) / "parent_link")

    def test_symlink_intermediate_directory_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            root.chmod(0o700)
            actual = root / "actual"
            actual.mkdir(mode=0o700)
            (actual / "f").write_bytes(b"ok")
            (root / "linked").symlink_to(actual, target_is_directory=True)
            with self.assertRaises(GateDenied):
                digest_existing_regular(root / "linked" / "f", root)

    def test_directory_as_file_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            root.chmod(0o700)
            (root / "dir").mkdir(mode=0o700)
            with self.assertRaises(GateDenied):
                digest_existing_regular(root / "dir", root)


if __name__ == "__main__":
    unittest.main()
