"""N3-F0 r002 T0 regressions: true cross-node identity and fake ancestry.

The test-only model is NOT a physical private-FS/FD scan or Native grant.
No real os/openat/stat/flock/fsync, Git, SDK, network, subprocess or signal.
"""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
from gateway.r2n_n3f0_offline import (  # noqa: E402
    N3F0NotAuthorized, N3F0OfflinePrivateFSAdapter, N3F0SyntheticTopology,
)
from test_r2n_n3f0_offline import node, observed, control  # noqa: E402


class N3F0TopologyReviewR002T0(unittest.TestCase):
    def scanned(self, **changes: object):
        return N3F0OfflinePrivateFSAdapter.scan_observation(observed(**changes))

    def denied(self, **changes: object):
        r = self.scanned(**changes)
        self.assertIn(r.durability_state, ("unavailable", "quarantined"))
        self.assertFalse(r.available)
        self.assertEqual(r.completion_capability, "none")
        self.assertTrue(r.t0_model_only)
        return r

    def test_01_c_state_root_file_devino_collision(self):
        r = self.denied(state_root=node("directory", 60))
        self.assertEqual(r.quarantine_reason_code, "lineage_not_independent")

    def test_02_c_lineage_root_file_devino_collision(self):
        self.denied(lineage_root=node("directory", 60))

    def test_03_c_state_root_equals_lineage_parent(self):
        self.denied(state_root=node("directory", 11))

    def test_04_c_lineage_root_equals_state_parent(self):
        self.denied(lineage_root=node("directory", 10))

    def test_05_c_state_parent_equals_own_state_root(self):
        self.denied(state_parent=node("directory", 20, mode=0o775))

    def test_06_c_lineage_parent_collides_with_owner_file(self):
        self.denied(lineage_parent=node("directory", 60, mode=0o775))

    def test_07_b_lineage_parent_is_state_root(self):
        self.denied(lineage_parent=node("directory", 20, mode=0o775))

    def test_08_b_state_parent_is_lineage_root(self):
        self.denied(state_parent=node("directory", 21, mode=0o775))

    def test_09_parent_root_reverse_alias_and_foreign_owner(self):
        self.denied(lineage_parent=node("directory", 20, mode=0o775),
                    owner_lock=node("file", 60))
        self.denied(state_parent=node("directory", 21, mode=0o775))

    def test_10_missing_topology_cannot_be_healthy(self):
        self.assertEqual(self.denied(topology=None).quarantine_reason_code,
                         "private_boundary_unverified")

    def test_11_untrusted_topology_type_cannot_be_healthy(self):
        self.denied(topology={"state_ancestor_ids": (), "lineage_ancestor_ids": ()})
        self.denied(topology=True)

    def test_12_truncated_or_wrong_parent_chain_denied(self):
        t = observed().topology
        self.denied(topology=replace(t, lineage_ancestor_ids=((9, 11), (9, 21))))
        self.denied(topology=replace(t, state_ancestor_ids=((9, 2), (9, 77), (9, 20))))
        self.denied(topology=replace(t, state_ancestor_ids=((9, 2), (9, 10))))

    def test_13_noncanonical_fake_ancestry_types_denied(self):
        t = observed().topology
        self.denied(topology=replace(t, state_ancestor_ids=[(9, 2), (9, 10), (9, 20)]))
        self.denied(topology=replace(t, state_ancestor_ids=((9, True), (9, 10), (9, 20))))
        self.denied(topology=replace(t, state_ancestor_ids=((9, 2), [9, 10], (9, 20))))
        self.denied(topology=replace(t, lineage_ancestor_ids=((9, 2), (9, 11), (9, 21)) * 40))

    def test_14_duplicate_pinned_ancestor_does_not_mint_health(self):
        t = observed().topology
        self.denied(topology=replace(t, state_ancestor_ids=((9, 2), (9, 10), (9, 10), (9, 20))))

    def test_15_deep_lineage_root_inside_state_root_denied(self):
        t = observed().topology
        self.denied(topology=replace(t, lineage_ancestor_ids=(
            (9, 2), (9, 20), (9, 11), (9, 21))))

    def test_16_deep_state_root_inside_lineage_root_denied(self):
        t = observed().topology
        self.denied(topology=replace(t, state_ancestor_ids=(
            (9, 2), (9, 21), (9, 10), (9, 20))))

    def test_17_diverged_then_rejoined_ancestry_denied(self):
        t = observed().topology
        self.denied(topology=replace(t,
            state_ancestor_ids=((9, 2), (9, 31), (9, 10), (9, 20)),
            lineage_ancestor_ids=((9, 2), (9, 32), (9, 31), (9, 11), (9, 21))))

    def test_18_file_colliding_with_hidden_ancestor_denied(self):
        self.denied(owner_lock=node("file", 2),
                    owner_lock_fd_ino=2, control_bytes=control(owner_lock_ino=2))

    def test_19_forged_flags_cannot_replace_missing_real_chain(self):
        self.denied(topology=None, verified_pinned_parents=True,
                    roots_disjoint_from_workspaces=True, exclusive_lock_held=True)

    def test_20_valid_existing_distinct_sibling_roots_are_metadata_only(self):
        r = self.scanned()
        self.assertEqual(r.durability_state, "healthy_metadata_only")
        self.assertFalse(r.available)
        self.assertEqual(r.completion_capability, "none")

    def test_21_valid_deep_common_ancestor_only_metadata(self):
        t = observed().topology
        r = self.scanned(topology=replace(t,
            state_ancestor_ids=((9, 1), (9, 2), (9, 10), (9, 20)),
            lineage_ancestor_ids=((9, 1), (9, 2), (9, 11), (9, 21))))
        self.assertEqual(r.durability_state, "healthy_metadata_only")
        self.assertFalse(r.available)

    def test_22_valid_separate_device_children_only_metadata(self):
        t = observed().topology
        r = self.scanned(state_parent=node("directory", 10, mode=0o775, dev=10),
                         state_root=node("directory", 20, dev=10),
                         topology=replace(t, state_ancestor_ids=((9, 2), (10, 10), (10, 20))))
        self.assertEqual(r.durability_state, "healthy_metadata_only")
        self.assertFalse(r.available)

    def test_23_missing_roots_never_reprovisioned(self):
        self.denied(state_root=None, lineage_root=None)
        self.denied(state_root=None)
        self.denied(lineage_root=None)

    def test_24_physical_port_still_unconditionally_raises(self):
        with self.assertRaises(N3F0NotAuthorized):
            N3F0OfflinePrivateFSAdapter.open_physical_private_store(
                "irrelevant", topology=N3F0SyntheticTopology((), ()))


if __name__ == "__main__":
    unittest.main()
