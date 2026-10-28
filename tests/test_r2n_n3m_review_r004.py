"""PR95 r004: T0 legal input-order and effective Runner precedence contracts.

Pure memory only: no process, real filesystem, Native, network or subprocess.
"""
from __future__ import annotations

from dataclasses import replace
import unittest

from gateway.r2n_n3m_offline import N3MBinding, N3MBlocked, N3MOfflineModel


def authority(**changes):
    values = dict(
        workspace="demo", profile="native_limited",
        trust_scope="mutable_workspace",
        root_dev=12, root_ino=34, server_exec_enabled=True,
        workspace_exec_enabled=True,
        workspace_exec_paths=("src", "src/tools"),
        workspace_exec_runners=("src=direct", "src/tools=pipenv"),
        runner_cwd="src/tools/deep", runner_id="pipenv",
        runner_project="src/tools",
        runner_fallback="nearest_pipfile_else_direct",
        backend_id="futuredisabled", backend_version="v1",
        backend_config_sha256="a" * 64, risk_contract_sha256="b" * 64,
        consent_format="v1", operator_issuer="localowner",
        risk_ack=("host_user_scope", "irreversible_effects", "detached_survivors"),
        expiry_epoch=1000,
    )
    return N3MBinding(**(values | changes))


class N3MReviewR004T0(unittest.TestCase):

    def test_b95_r003_unsorted_exec_paths_are_valid(self):
        valid = authority(workspace_exec_paths=("src/tools", "src"))
        self.assertEqual(valid.runner_id, "pipenv")
        self.assertEqual(valid.runner_project, "src/tools")
        self.assertEqual(valid.digest(), authority().digest())

    def test_b95_r003_unsorted_runner_maps_are_valid(self):
        reversed_map = authority(
            workspace_exec_runners=("src/tools=pipenv", "src=direct"))
        self.assertEqual(reversed_map.runner_id, "pipenv")
        self.assertEqual(reversed_map.digest(), authority().digest())

    def test_c95_r003_both_unique_valid_permutations_are_canonically_equal(self):
        equivalent = authority(
            workspace_exec_paths=("src/tools", "src"),
            workspace_exec_runners=("src/tools=pipenv", "src=direct"))
        expected = authority()
        self.assertEqual(equivalent.encoded_binding(), expected.encoded_binding())
        self.assertEqual(equivalent.digest(), expected.digest())
        self.assertIn("src/tools", equivalent.encoded_binding())

    def test_c95_r003_effective_child_mapping_wins_both_orders(self):
        for mapping in (("src=direct", "src/tools=pipenv"),
                        ("src/tools=pipenv", "src=direct")):
            with self.subTest(mapping=mapping):
                b = authority(workspace_exec_runners=mapping)
                self.assertEqual((b.runner_id, b.runner_project), ("pipenv", "src/tools"))
                with self.assertRaises(ValueError):
                    authority(workspace_exec_runners=mapping,
                              runner_id="direct", runner_project="src")

    def test_b95_r003_unordered_dot_root_scope_is_valid(self):
        b = authority(
            workspace_exec_paths=("src", "."),
            workspace_exec_runners=(".=direct",),
            runner_cwd="src/tools", runner_id="direct", runner_project=".")
        self.assertEqual(b.digest(), authority(
            workspace_exec_paths=(".", "src"),
            workspace_exec_runners=(".=direct",),
            runner_cwd="src/tools", runner_id="direct", runner_project=".").digest())

    def test_c95_r003_exact_duplicate_configuration_still_denied(self):
        with self.assertRaisesRegex(ValueError, "invalid_workspace_exec_paths"):
            authority(workspace_exec_paths=("src", "src"))
        with self.assertRaisesRegex(ValueError, "invalid_workspace_exec_runners"):
            authority(workspace_exec_runners=("src=direct", "src=direct"))

    def test_c95_r003_invalid_map_or_ambiguous_runner_claim_denied(self):
        for bad in (
            ("../other=direct",),
            ("src/tools=unknown",),
            ("outside=pipenv",),
        ):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                authority(workspace_exec_runners=bad)
        with self.assertRaises(ValueError):
            authority(runner_cwd="src/tools/deep", runner_id="direct",
                      runner_project="src")

    def test_b95_r003_same_path_overwritten_by_later_mapping_matches_runtime(self):
        # Config _bounded_tuple only rejects identical strings; current
        # CommandRunner.__init__ stores a dict, hence last PATH=mode wins.
        prior = authority(workspace_exec_runners=(
            "src=direct", "src/tools=direct", "src/tools=pipenv"))
        self.assertEqual((prior.runner_project, prior.runner_id), ("src/tools", "pipenv"))
        reverse = authority(workspace_exec_runners=(
            "src=direct", "src/tools=pipenv", "src/tools=direct"),
            runner_id="direct")
        self.assertEqual((reverse.runner_project, reverse.runner_id), ("src/tools", "direct"))
        self.assertNotEqual(prior.digest(), reverse.digest())

    def test_b95_r003_equivalent_overwritten_map_matches_effective_fingerprint(self):
        with_extra = authority(workspace_exec_runners=(
            "src=direct", "src/tools=direct", "src/tools=pipenv"))
        without_extra = authority(workspace_exec_runners=(
            "src=direct", "src/tools=pipenv"))
        self.assertEqual(with_extra.digest(), without_extra.digest())

    def test_c95_r003_changed_effective_order_invalidates_issued_fake_ticket(self):
        model = N3MOfflineModel("testnamespace", 7)
        model.provision_offline_fake()
        current = authority()
        model.approve_fake(current, now=100)
        ticket = model.prepare_fake(current, now=101)
        reordered = authority(workspace_exec_paths=("src/tools", "src"),
                              workspace_exec_runners=("src/tools=pipenv", "src=direct"))
        self.assertEqual(current.digest(), reordered.digest())
        model.validate_binding_fake(reordered, now=102)
        changed = authority(workspace_exec_runners=(
            "src=direct", "src/tools=pipenv", "src/tools=direct"),
            runner_id="direct")
        with self.assertRaises(N3MBlocked):
            model.validate_binding_fake(changed, now=103)
        self.assertEqual(model.snapshot()["phases"][ticket.attempt_id], "UNKNOWN")
        self.assertEqual(model.snapshot()["hypothetical_dispatches"], 0)

    def test_b95_r003_selected_mode_mismatch_never_fake_dispatches(self):
        with self.assertRaises(ValueError):
            authority(workspace_exec_runners=("src/tools=pipenv", "src=direct"),
                      runner_id="direct", runner_project="src")
        model = N3MOfflineModel("testnamespace", 7)
        model.provision_offline_fake()
        with self.assertRaises(N3MBlocked):
            model.deny_apply(None)
        self.assertEqual(model.snapshot()["hypothetical_dispatches"], 0)


if __name__ == "__main__":
    unittest.main()
