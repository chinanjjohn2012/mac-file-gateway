"""N3-F0 T0: the ONLY executed boot scans consume synthetic observations.

No real private root/owner.lock, OS stat/open/fsync/flock, Git, SDK, runner,
process, signals, cleanup or imported production Gateway service is exercised.
"""
from __future__ import annotations

import ast
from dataclasses import replace
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from gateway.r2n_n3f0_offline import (  # noqa: E402
    N3F0Node, N3F0Observation, N3F0SyntheticTopology,
    N3F0OfflinePrivateFSAdapter,
    N3F0NotAuthorized, N3F0Scan,
)


def node(kind: str, ino: int, *, mode: int | None = None, nlink: int = 1,
         uid: int = 501, dev: int = 9) -> N3F0Node:
    if mode is None:
        mode = 0o700 if kind == "directory" else 0o600
    return N3F0Node(kind, dev, ino, uid, mode, nlink)


def control(**changes: object) -> bytes:
    data = {
        "schema_id": "native-n3-v1", "namespace_id": "n3ns1",
        "lineage_generation": 2, "owner_generation": 3,
        "state_generation": 4, "consent_epoch": 0,
        "consent_record_id": "initial", "consent_active": False,
        "consent_expiry_or_null": None, "consent_binding_digest": "a" * 64,
        "owner_lock_dev": 9, "owner_lock_ino": 60,
        "global_quarantined": False, "global_quarantine_reason": "none",
        "max_attempts": 4096, "max_attempt_bytes": 4096,
        "max_total_attempt_payload": 16 * 1024 * 1024,
        "unresolved_retired_tombstone_count": 0,
    }
    data.update(changes)
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def witness(**changes: object) -> bytes:
    data = {"schema_id": "native-n3-lineage-v1", "namespace_id": "n3ns1",
            "lineage_generation": 2, "state_generation": 4,
            "operator_provisioned": True}
    data.update(changes)
    return json.dumps(data, sort_keys=True).encode("utf-8")


def observed(**changes: object) -> N3F0Observation:
    data = {
        "service_uid": 501,
        "state_parent": node("directory", 10, mode=0o775),
        "lineage_parent": node("directory", 11, mode=0o775),
        "state_root": node("directory", 20),
        "lineage_root": node("directory", 21),
        "owner_lock": node("file", 60),
        "owner_lock_fd_dev": 9, "owner_lock_fd_ino": 60,
        "exclusive_lock_held": True, "verified_pinned_parents": True,
        "roots_disjoint_from_workspaces": True,
        "state_entries": ("owner.lock", "control.v1", "attempts", "responses"),
        "lineage_entries": ("provision-witness.v1", "owner-authority.v1"),
        "attempt_entries": (), "response_entries": (),
        "control_bytes": control(), "witness_bytes": witness(),
        # T0-only fake FULL ancestry: shared gateway control parent (9,2),
        # distinct sibling parent/root chains, no cross-parent containment.
        "topology": N3F0SyntheticTopology(
            state_ancestor_ids=((9, 2), (9, 10), (9, 20)),
            lineage_ancestor_ids=((9, 2), (9, 11), (9, 21))),
    }
    data.update(changes)
    return N3F0Observation(**data)


class N3F0PureMemoryT0(unittest.TestCase):
    def scan(self, **changes: object) -> N3F0Scan:
        return N3F0OfflinePrivateFSAdapter.scan_observation(observed(**changes))

    def deny(self, reason: str, **changes: object) -> None:
        result = self.scan(**changes)
        self.assertEqual(result.quarantine_reason_code, reason)
        self.assertIn(result.durability_state, ("unavailable", "quarantined"))
        self.assertIs(result.available, False)
        self.assertEqual(result.completion_capability, "none")
        self.assertIs(result.t0_model_only, True)

    def test_01_valid_modeled_metadata_never_exec_ready(self):
        result = self.scan()
        self.assertEqual(result.durability_state, "healthy_metadata_only")
        self.assertEqual(result.quarantine_reason_code, "metadata_only_no_exec_proof")
        self.assertFalse(result.available)
        self.assertEqual(result.completion_capability, "none")

    def test_02_physical_port_is_forbidden(self):
        with self.assertRaisesRegex(N3F0NotAuthorized, "t1_resources_not_authorized"):
            N3F0OfflinePrivateFSAdapter.open_physical_private_store("/root/forbidden")

    def test_03_boot_order_never_provisions_or_unquarantines(self):
        order = N3F0OfflinePrivateFSAdapter.boot_read_order()
        self.assertEqual(order[0], "verify_separate_existing_parents")
        self.assertIn("acquire_existing_owner_lock_exclusively", order)
        self.assertFalse(any("create" in action or "reset" in action or "spawn" in action
                             for action in order))

    def test_04_both_roots_deleted_cannot_be_first_install(self):
        self.deny("state_io_unavailable", state_root=None, lineage_root=None)

    def test_05_lineage_missing_never_autoinit(self):
        self.deny("state_io_unavailable", lineage_root=None)

    def test_06_namespace_missing_with_old_witness(self):
        self.deny("state_io_unavailable", state_root=None)

    def test_07_same_parent_cannot_prove_independent_witness(self):
        self.deny("lineage_not_independent", lineage_parent=node("directory", 10))

    def test_08_same_root_inode_fails(self):
        self.deny("lineage_not_independent", lineage_root=node("directory", 20))

    def test_09_unpinned_root_or_workspace_overlap_fails(self):
        self.deny("private_boundary_unverified", verified_pinned_parents=False)
        self.deny("private_boundary_unverified", roots_disjoint_from_workspaces=False)

    def test_10_missing_owner_lock_fails(self):
        self.deny("owner_lock_unavailable", owner_lock=None)

    def test_11_second_owner_cannot_claim_lock(self):
        self.deny("owner_lock_unavailable", exclusive_lock_held=False)

    def test_12_lock_fd_identity_aba_fails(self):
        self.deny("owner_lock_unavailable", owner_lock_fd_ino=61)
        self.deny("owner_lock_unavailable", owner_lock_fd_dev=10)

    def test_13_owner_lock_hardlink_or_symbolic_type_fails(self):
        self.deny("owner_lock_unavailable", owner_lock=node("file", 60, nlink=2))
        self.deny("owner_lock_unavailable", owner_lock=node("symlink", 60))

    def test_14_n3_roots_strict_private_not_phase1_workspace_modes(self):
        self.deny("state_io_unavailable", state_root=node("directory", 20, mode=0o777))
        self.deny("state_io_unavailable", lineage_root=node("directory", 21, uid=502))
        self.deny("state_io_unavailable", state_root=node("symlink", 20))
        self.assertEqual(self.scan().durability_state, "healthy_metadata_only")

    def test_15_state_unknown_and_pending_names_quarantine(self):
        for name in ("unknown.xyz", "pending-123", "final-fence-123", "tmp-123", "exec-state"):
            with self.subTest(name=name):
                self.deny("corrupt_record", state_entries=observed().state_entries + (name,))

    def test_16_boot_deny_is_never_unlatched(self):
        self.deny("restart_hazard", state_entries=observed().state_entries + ("boot-deny.v1",))

    def test_17_incomplete_or_duplicate_layout_denies(self):
        self.deny("corrupt_record", state_entries=("owner.lock", "control.v1"))
        self.deny("corrupt_record", lineage_entries=("provision-witness.v1",))
        self.deny("corrupt_record", state_entries=observed().state_entries + ("control.v1",))

    def test_18_surviving_any_attempt_or_response_denies(self):
        self.deny("unresolved_attempt", attempt_entries=("r-old.json",))
        self.deny("unresolved_attempt", response_entries=("d-old.json",))
        self.deny("unresolved_attempt", attempt_entries=("r-retired-limited.json",))

    def test_19_old_v1_and_s2_control_not_imported(self):
        self.deny("corrupt_record", control_bytes=control(schema_id="exec-state-v1"))
        self.deny("corrupt_record", control_bytes=control(schema_id="s2-offline-fake"))

    def test_20_duplicate_and_unknown_json_keys_denied(self):
        raw = control()
        self.deny("corrupt_record", control_bytes=raw[:-1] + b',"schema_id":"native-n3-v1"}')
        self.deny("corrupt_record", control_bytes=raw[:-1] + b',"extra":1}')
        self.deny("corrupt_record", witness_bytes=witness()[:-1] + b',"new":"field"}')

    def test_21_nonfinite_and_wrong_type_denied(self):
        self.deny("corrupt_record", control_bytes=control(consent_epoch=True))
        self.deny("corrupt_record", control_bytes=control(global_quarantined=1))
        self.deny("corrupt_record", control_bytes=control(max_attempts=False))
        self.deny("corrupt_record", control_bytes=control(consent_expiry_or_null=float("nan")))

    def test_22_strict_limits_and_record_bytes(self):
        self.deny("corrupt_record", control_bytes=control(max_attempts=4097))
        self.deny("corrupt_record", control_bytes=control(max_attempt_bytes=4097))
        self.deny("corrupt_record", control_bytes=control(max_total_attempt_payload=16 * 1024 * 1024 + 1))
        self.deny("corrupt_record", control_bytes=b"{" + b" " * 4096 + b"}")

    def test_23_wrong_namespace_lineage_generation_rejected(self):
        self.deny("lineage_mismatch", witness_bytes=witness(namespace_id="foreign"))
        self.deny("lineage_mismatch", witness_bytes=witness(lineage_generation=1))
        self.deny("lineage_mismatch", witness_bytes=witness(state_generation=3))

    def test_24_control_lock_inodes_must_match(self):
        self.deny("owner_lock_unavailable", control_bytes=control(owner_lock_ino=80))
        self.deny("owner_lock_unavailable", control_bytes=control(owner_lock_dev=8))

    def test_25_control_quarantine_preserved(self):
        self.deny("cleanup_unknown", control_bytes=control(global_quarantined=True,
                                                           global_quarantine_reason="cleanup_unknown"))

    def test_26_active_consent_is_not_a_fake_positive_grant(self):
        self.deny("consent_not_qualified", control_bytes=control(consent_active=True,
                                                                consent_epoch=1))

    def test_27_tombstones_cannot_be_evicted_for_readiness(self):
        self.deny("unresolved_attempt",
                  control_bytes=control(unresolved_retired_tombstone_count=1))

    def test_28_witness_can_never_self_issue_consent(self):
        self.deny("corrupt_record", witness_bytes=witness(operator_provisioned=False))
        self.deny("corrupt_record", witness_bytes=witness(operator_provisioned=1))
        self.deny("corrupt_record", witness_bytes=witness(schema_id="s2-v2"))

    def test_29_untrusted_input_and_bad_node_types_are_denied(self):
        result = N3F0OfflinePrivateFSAdapter.scan_observation({"state":"healthy"})
        self.assertFalse(result.available)
        self.deny("state_io_unavailable", service_uid=True)
        self.deny("state_io_unavailable", state_parent={"dev":9})

    def test_30_malformed_or_oversized_name_lists_denied(self):
        self.deny("corrupt_record", state_entries=["owner.lock"])
        self.deny("corrupt_record", attempt_entries=("x",) * 4097)
        self.deny("corrupt_record", lineage_entries=("owner-authority.v1", 23))

    def test_31_scan_result_cannot_be_constructed_as_permission(self):
        with self.assertRaises(ValueError):
            N3F0Scan("healthy", "none", available=True)
        with self.assertRaises(ValueError):
            N3F0Scan("healthy", "none", completion_capability="original_group_only")

    def test_32_source_static_imports_no_io_or_process_modules(self):
        source = (ROOT / "gateway" / "r2n_n3f0_offline.py").read_text("utf-8")
        parsed = ast.parse(source)
        imported = set()
        for n in ast.walk(parsed):
            if isinstance(n, ast.Import):
                imported.update(name.name.split(".")[0] for name in n.names)
            elif isinstance(n, ast.ImportFrom) and n.module:
                imported.add(n.module.split(".")[0])
        self.assertFalse(imported & {"os", "fcntl", "subprocess", "socket", "pathlib",
                                     "signal", "ctypes", "threading", "multiprocessing"})
        self.assertEqual(imported, {"__future__", "dataclasses", "json", "re"})


if __name__ == "__main__":
    unittest.main()
