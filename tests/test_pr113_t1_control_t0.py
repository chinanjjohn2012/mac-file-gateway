"""Offline, no-product-process T0 checks for the separate PR113 control draft.

These tests never invoke real Python/Pipenv/Go S1-S6. The intentionally
fail-open policy callback is always placed behind a mock subprocess.Popen.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tools.pr113_t1_control_t0 import (
    BASE_SHA, DESIGN_BLOB, HEAD_SHA, HEAD_TREE, REPO, GateDenied, SIX_COMMANDS,
    TRANSPORTS, check_deadline, check_event_shape, check_lock_metadata,
    check_phase_order, check_product_identity, consume_local_once_t0,
    exact_product_identity, load_lock_json, native_execution_decision,
    probe_denied_argv_t0, verify_temp_file_digest,
)

LOCK_SOURCE = Path(__file__).resolve().parents[1] / "docs" / "PR113_T1_FOREIGN_INPUT_LOCK_001.json"
CONTROL_SHA = "1" * 40


def make_event() -> dict:
    return {
        "repository": REPO, "pr": 113, "head_sha": HEAD_SHA,
        "head_tree": HEAD_TREE, "actor": "chinanjjohn2012",
        "event_name": "workflow_dispatch", "run_id": 1234567,
        "run_attempt": 1, "control_sha": CONTROL_SHA, "phase": "six",
    }


class SnapshotShapeT0(unittest.TestCase):
    def test_exact_identity_shape_only(self):
        check_product_identity(exact_product_identity())

    def test_each_identity_drift_denied(self):
        identity = exact_product_identity()
        for key, bad in [("repository", "other/repo"), ("pr", 114),
                         ("base_sha", "0" * 40), ("head_sha", "0" * 40),
                         ("head_tree", "0" * 40), ("design_blob", "0" * 40)]:
            with self.subTest(field=key):
                mutated = {**identity, key: bad}
                with self.assertRaises(GateDenied):
                    check_product_identity(mutated)

    def test_bool_is_not_pr_number(self):
        with self.assertRaises(GateDenied):
            check_product_identity({**exact_product_identity(), "pr": True})

    def test_unknown_or_missing_fields_denied(self):
        for mutated in ({**exact_product_identity(), "source": "shadow"},
                        {"repository": REPO}):
            with self.assertRaises(GateDenied):
                check_product_identity(mutated)

    def test_real_18_row_matrix_is_data_only(self):
        self.assertEqual(len(SIX_COMMANDS), 6)
        self.assertEqual(len(TRANSPORTS), 3)
        self.assertEqual({k[0] for k in SIX_COMMANDS}, {"S1", "S2", "S3", "S4", "S5", "S6"})
        self.assertEqual(len({(command[0], mode) for command in SIX_COMMANDS for mode in TRANSPORTS}), 18)


class OneUseShapeT0(unittest.TestCase):
    def test_syntactic_claim_ok_but_not_authorized(self):
        check_event_shape(make_event(), approved_run_id=1234567,
                          control_sha=CONTROL_SHA, expected_phase="six")

    def test_all_event_drift_denied(self):
        event = make_event()
        bad = [
            ("repository", "fake/repo"), ("pr", 114), ("head_sha", "0" * 40),
            ("head_tree", "0" * 40), ("actor", "intruder"),
            ("event_name", "pull_request"), ("run_id", 1234568),
            ("run_attempt", 2), ("control_sha", "0" * 40), ("phase", "mixed"),
        ]
        for key, value in bad:
            with self.subTest(field=key):
                with self.assertRaises(GateDenied):
                    check_event_shape({**event, key: value}, approved_run_id=1234567,
                                      control_sha=CONTROL_SHA, expected_phase="six")

    def test_new_run_id_duplicate_label_denied(self):
        with self.assertRaises(GateDenied):
            check_event_shape(make_event(), approved_run_id=7654321,
                              control_sha=CONTROL_SHA, expected_phase="six")

    def test_unauthenticated_missing_approval_denied(self):
        for run_id in (None, 0, True):
            with self.subTest(run_id=run_id):
                with self.assertRaises(GateDenied):
                    check_event_shape(make_event(), approved_run_id=run_id,
                                      control_sha=CONTROL_SHA, expected_phase="six")
        with self.assertRaises(GateDenied):
            check_event_shape(make_event(), approved_run_id=1234567,
                              control_sha=None, expected_phase="six")

    def test_extra_claim_or_boolean_run_denied(self):
        with self.assertRaises(GateDenied):
            check_event_shape({**make_event(), "user_input_override": 1},
                              approved_run_id=1234567, control_sha=CONTROL_SHA,
                              expected_phase="six")
        with self.assertRaises(GateDenied):
            check_event_shape({**make_event(), "run_attempt": True},
                              approved_run_id=1234567, control_sha=CONTROL_SHA,
                              expected_phase="six")

    def test_phase_sequence(self):
        check_phase_order("six", previous=None)
        check_phase_order("mixed", previous="six_pass")

    def test_duplicate_and_mixed_without_success_denied(self):
        for phase, previous in [("six", "six_pass"), ("six", "mixed_pass"),
                                ("mixed", None), ("mixed", "six_failed"),
                                ("mixed", "mixed_pass"), ("unknown", None)]:
            with self.subTest(phase=phase, previous=previous):
                with self.assertRaises(GateDenied):
                    check_phase_order(phase, previous=previous)

    def test_once_per_local_phase(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            root.chmod(0o700)
            x = consume_local_once_t0(root, 1234567, "six")
            self.assertTrue(x.is_file())
            with self.assertRaises(GateDenied):
                consume_local_once_t0(root, 1234567, "six")
            consume_local_once_t0(root, 1234567, "mixed")

    def test_local_once_concurrent_only_one_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            root.chmod(0o700)
            def attempt(_):
                try:
                    consume_local_once_t0(root, 1234567, "six")
                    return "claimed"
                except GateDenied:
                    return "blocked"
            with ThreadPoolExecutor(max_workers=8) as pool:
                results = list(pool.map(attempt, range(16)))
            self.assertEqual(results.count("claimed"), 1)
            self.assertEqual(results.count("blocked"), 15)

    def test_private_ledger_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            root.chmod(0o755)
            with self.assertRaises(GateDenied):
                consume_local_once_t0(root, 1234567, "six")
            root.chmod(0o700)
            with self.assertRaises(GateDenied):
                consume_local_once_t0(root, 0, "six")


class BudgetT0(unittest.TestCase):
    def test_with_margin(self):
        check_deadline(elapsed_seconds=0, request_timeout_seconds=120)
        check_deadline(elapsed_seconds=899, request_timeout_seconds=120)

    def test_boundary_reserve_fail_closed(self):
        for elapsed in (900, 901, 1080, 1200, 1201):
            with self.subTest(elapsed=elapsed):
                with self.assertRaises(GateDenied):
                    check_deadline(elapsed_seconds=elapsed, request_timeout_seconds=120)

    def test_no_extra_budget_or_nonfinite(self):
        bad = [dict(elapsed_seconds=float('nan'), request_timeout_seconds=5),
               dict(elapsed_seconds=0, request_timeout_seconds=121),
               dict(elapsed_seconds=0, request_timeout_seconds=10, reserve_seconds=0),
               dict(elapsed_seconds=False, request_timeout_seconds=1),
               dict(elapsed_seconds=-1, request_timeout_seconds=5),
               dict(elapsed_seconds=0, request_timeout_seconds=5, total_seconds=1201)]
        for args in bad:
            with self.subTest(args=args):
                with self.assertRaises(GateDenied):
                    check_deadline(**args)


class LockT0(unittest.TestCase):
    def setUp(self):
        self.lock = load_lock_json(LOCK_SOURCE)

    def test_incomplete_lock_is_explicit(self):
        pend = check_lock_metadata(self.lock)
        self.assertIn("network_profile", pend)
        self.assertIn("owner_t1_authorized", pend)
        self.assertIn("control_commit", pend)
        self.assertIn("control_tree", pend)
        self.assertTrue(any("wheel" in x for x in pend))
        self.assertGreaterEqual(len(pend), 9)

    def test_native_gate_unconditionally_denies(self):
        with self.assertRaises(GateDenied):
            native_execution_decision(self.lock)

    def test_untrusted_lock_status_cannot_authorize(self):
        changed = copy.deepcopy(self.lock)
        changed["status"] = "READY"
        changed["owner_t1_authorized"] = True
        changed["network_profile"] = "BOUNDED_TRUSTED_LOCAL"
        with self.assertRaises(GateDenied):
            native_execution_decision(changed)

    def test_history_is_not_future_locked_input(self):
        references = [x for x in self.lock["inputs"] if x["status"] == "HISTORICAL_REFERENCE"]
        self.assertGreater(len(references), 0)
        for x in references:
            self.assertIsNone(x["expected_sha256"])
            self.assertIsNotNone(x["historical_observed_sha256"])

    def test_fake_verified_hash_denied(self):
        changed = copy.deepcopy(self.lock)
        changed["inputs"][0]["status"] = "VERIFIED_NEW_INPUT"
        with self.assertRaises(GateDenied):
            check_lock_metadata(changed)

    def test_duplicate_json_keys_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            x = Path(tmp) / "lock.json"
            x.write_text('{"schema":1,"schema":2}', encoding="utf-8")
            with self.assertRaises(GateDenied):
                load_lock_json(x)

    def test_symlink_lock_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            link = Path(tmp) / "lock.json"
            link.symlink_to(LOCK_SOURCE)
            with self.assertRaises(GateDenied):
                load_lock_json(link)

    def test_bad_hash_and_unexpected_field_denied(self):
        changed = copy.deepcopy(self.lock)
        changed["inputs"][1]["historical_observed_sha256"] = "bad"
        with self.assertRaises(GateDenied):
            check_lock_metadata(changed)
        changed = copy.deepcopy(self.lock)
        changed["secret_proof"] = "fake"
        with self.assertRaises(GateDenied):
            check_lock_metadata(changed)

    def test_read_file_hash_only_disposable_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            item = root / "read_only.dat"
            item.write_bytes(b"disposable fixture")
            digest = hashlib.sha256(item.read_bytes()).hexdigest()
            self.assertTrue(verify_temp_file_digest(item, digest, root))
            self.assertFalse(verify_temp_file_digest(item, "0" * 64, root))

    def test_file_symlink_or_outside_root_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "root"
            root.mkdir()
            external = Path(tmp) / "outside.txt"
            external.write_bytes(b"external")
            digest = hashlib.sha256(external.read_bytes()).hexdigest()
            link = root / "shadow"
            link.symlink_to(external)
            for item in (link, external):
                with self.subTest(item=str(item)):
                    with self.assertRaises(GateDenied):
                        verify_temp_file_digest(item, digest, root)


class NegativeNoSpawnT0(unittest.TestCase):
    def test_clean_rejection_with_no_popen(self):
        for transport in TRANSPORTS:
            with self.subTest(transport=transport):
                obs = probe_denied_argv_t0(lambda: "command_not_allowed")
                self.assertEqual(obs.attempted_popen, 0)
                self.assertEqual(obs.result_code, "command_not_allowed")

    def test_false_positive_gate_must_not_spawn_seventh_command(self):
        for transport in TRANSPORTS:
            with self.subTest(transport=transport):
                def fail_open():
                    subprocess.Popen(["go", "test", "./another"])
                    return "command_not_allowed"
                with self.assertRaisesRegex(GateDenied, "unauthorized launch"):
                    probe_denied_argv_t0(fail_open)

    def test_no_reject_result_denied(self):
        for outcome in ("ok", "launch_failed", "", None, 200):
            with self.subTest(outcome=outcome):
                with self.assertRaises(GateDenied):
                    probe_denied_argv_t0(lambda: outcome)

    def test_exception_propogates_as_failure_not_pass(self):
        def crashed():
            raise RuntimeError("bad service")
        with self.assertRaises(RuntimeError):
            probe_denied_argv_t0(crashed)

    def test_patch_restored_after_probe(self):
        original = subprocess.Popen
        probe_denied_argv_t0(lambda: "command_not_allowed")
        self.assertIs(subprocess.Popen, original)


if __name__ == "__main__":
    unittest.main()
