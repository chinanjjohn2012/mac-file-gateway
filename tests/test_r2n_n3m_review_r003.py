"""PR #95 r003 exact-source T0 contract regression vectors; no IO or Native."""
from __future__ import annotations
from dataclasses import replace
import unittest

from gateway.r2n_n3m_offline import N3MBinding, N3MBlocked, N3MOfflineModel, strict_json


def effective(**updates):
    data = {
        "workspace": "demo", "profile": "native_limited",
        "trust_scope": "mutable_workspace", "root_dev": 12, "root_ino": 34,
        "server_exec_enabled": True, "workspace_exec_enabled": True,
        "workspace_exec_paths": ("src",), "workspace_exec_runners": ("src=direct",),
        "runner_cwd": "src/tools", "runner_id": "direct", "runner_project": "src",
        "runner_fallback": "nearest_pipfile_else_direct",
        "backend_id": "futuredisabled", "backend_version": "v1",
        "backend_config_sha256": "a" * 64, "risk_contract_sha256": "b" * 64,
        "consent_format": "v1", "operator_issuer": "localowner",
        "risk_ack": ("host_user_scope", "irreversible_effects", "detached_survivors"),
        "expiry_epoch": 1000,
    }
    return N3MBinding(**(data | updates))


class N3MReviewR003T0(unittest.TestCase):

    def test_c95_r002_parent_direct_rejects_false_child_pipenv(self):
        with self.assertRaises(ValueError):
            effective(runner_id="pipenv", runner_project="src/tools")

    def test_c95_r002_valid_parent_direct_uses_parent_project(self):
        self.assertEqual(effective().runner_project, "src")
        self.assertEqual(effective().runner_id, "direct")

    def test_c95_r002_nearest_override_pipenv_and_mutation_fence(self):
        b = effective(
            workspace_exec_runners=("src=direct", "src/tools=pipenv"),
            runner_cwd="src/tools/deep", runner_id="pipenv", runner_project="src/tools")
        self.assertEqual(b.runner_id, "pipenv")
        with self.assertRaises(ValueError):
            effective(workspace_exec_runners=("src=direct", "src/tools=pipenv"),
                      runner_cwd="src/tools/deep", runner_id="direct", runner_project="src")
        replacement = effective(workspace_exec_runners=("src=direct", "src/tools=direct"),
                                runner_cwd="src/tools/deep", runner_id="direct", runner_project="src/tools")
        self.assertNotEqual(b.digest(), replacement.digest())

    def test_c95_r002_root_dot_mapping_binds_all_children(self):
        with self.assertRaises(ValueError):
            effective(workspace_exec_paths=(".", "src"), workspace_exec_runners=(".=direct",),
                      runner_id="pipenv", runner_project="src/tools")
        b = effective(workspace_exec_paths=(".", "src"), workspace_exec_runners=(".=direct",),
                      runner_id="direct", runner_project=".")
        self.assertEqual(b.runner_project, ".")

    def test_c95_r002_no_configured_map_nearest_scope_direct(self):
        b = effective(workspace_exec_paths=("src", "src/tools"),
                      workspace_exec_runners=(), runner_cwd="src/tools/sub",
                      runner_id="direct", runner_project="src/tools")
        self.assertEqual(b.runner_project, "src/tools")
        with self.assertRaises(ValueError):
            effective(workspace_exec_paths=("src", "src/tools"),
                      workspace_exec_runners=(), runner_cwd="src/tools/sub",
                      runner_id="direct", runner_project="src")

    def test_c95_r002_no_configured_map_pipenv_fallback_hypothetical_only(self):
        b = effective(workspace_exec_runners=(), runner_cwd="src/tools", runner_id="pipenv",
                      runner_project="src")
        self.assertEqual(b.runner_project, "src")
        self.assertNotEqual(b.digest(), effective(workspace_exec_runners=()).digest())
        with self.assertRaises(ValueError):
            effective(workspace_exec_runners=(), runner_cwd="src/tools", runner_id="pipenv",
                      runner_project="src/sibling")

    def test_c95_r002_cwd_mutation_changes_digest_and_fences_prepared(self):
        b = effective()
        other = replace(b, runner_cwd="src/elsewhere")
        self.assertNotEqual(b.digest(), other.digest())
        m = N3MOfflineModel("testnamespace", 7)
        m.provision_offline_fake()
        m.approve_fake(b, now=100)
        ticket = m.prepare_fake(b, now=101)
        with self.assertRaises(N3MBlocked):
            m.validate_binding_fake(other, now=102)
        self.assertEqual(m.snapshot()["phases"][ticket.attempt_id], "UNKNOWN")
        self.assertEqual(m.snapshot()["hypothetical_dispatches"], 0)

    def test_c95_r002_invalid_cwd_and_nonancestor_project_rejected(self):
        for bad in ("../bad", "/root", "src//tools", "src/../tools", "src\\tools", ""):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                effective(runner_cwd=bad)
        with self.assertRaises(ValueError):
            effective(runner_project="src/tools")

    def test_b95_r002_surrogate_json_normalized_to_blocked(self):
        with self.assertRaises(N3MBlocked) as ex:
            strict_json(chr(0xd800), frozenset({"schema_id"}))
        self.assertIn("invalid_json", str(ex.exception))


if __name__ == "__main__":
    unittest.main()
