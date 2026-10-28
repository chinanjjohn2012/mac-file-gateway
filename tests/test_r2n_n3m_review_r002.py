"""PR95 r002: independent-targetable, pure-memory T0 regressions only.

These do NOT prove runtime Native, physical FDs/FS, operator authority or transport.
"""
from __future__ import annotations

from dataclasses import asdict, replace
import unittest

from gateway.r2n_n3m_offline import (
    N3MBinding, N3MBlocked, N3MControl, N3MOfflineModel,
)


def scope(**changes):
    data = {
        "workspace": "demo",
        "profile": "native_limited",
        "trust_scope": "mutable_workspace",
        "root_dev": 12,
        "root_ino": 34,
        "server_exec_enabled": True,
        "workspace_exec_enabled": True,
        "workspace_exec_paths": ("runner", "src/tools"),
        "workspace_exec_runners": ("src/tools=pipenv",),
        "runner_cwd": "runner", "runner_id": "direct",
        "runner_project": "runner",
        "runner_fallback": "nearest_pipfile_else_direct",
        "backend_id": "futuredisabled",
        "backend_version": "v1",
        "backend_config_sha256": "a" * 64,
        "risk_contract_sha256": "b" * 64,
        "consent_format": "v1",
        "operator_issuer": "localowner",
        "risk_ack": ("host_user_scope", "irreversible_effects", "detached_survivors"),
        "expiry_epoch": 1000,
    }
    return N3MBinding(**(data | changes))


def running(*, expiry=1000):
    m = N3MOfflineModel("testnamespace", 7)
    m.provision_offline_fake()
    b = scope(expiry_epoch=expiry)
    m.approve_fake(b, now=100)
    t = m.prepare_fake(b, now=101)
    m.fake_first_dispatch(t, now=102)
    return m, t, b


class N3MReviewR002T0(unittest.TestCase):

    def blocked(self, cb, message=None):
        with self.assertRaises(N3MBlocked) as ctx:
            cb()
        if message is not None:
            self.assertIn(message, str(ctx.exception))

    def test_b95_expired_after_dispatch_before_retirement_quarantines(self):
        m, t, b = running()
        m.content_changed_fake(now=1000)  # mutable code does NOT extend consent
        self.blocked(lambda: m.retire_limited_fake(t, b, now=1000), "expired")
        self.assertTrue(m.snapshot()["quarantined_fake"])
        self.assertEqual(m.snapshot()["phases"][t.attempt_id], "UNKNOWN")
        self.assertEqual(m.snapshot()["hypothetical_dispatches"], 1)
        self.assertEqual(m.decide_fake(t).phase_at_decision, "UNKNOWN")

    def test_b95_exact_expiry_boundary_has_no_limited_outcome(self):
        m, t, b = running(expiry=103)
        self.blocked(lambda: m.retire_limited_fake(t, b, now=103), "expired")
        self.assertEqual(m.decide_fake(t).kind, "QUARANTINED_OR_CLEANUP_UNKNOWN")

    def test_b95_just_before_expiry_is_valid_historical_limited_only(self):
        m, t, b = running(expiry=104)
        m.retire_limited_fake(t, b, now=103)
        d = m.decide_fake(t)
        self.assertEqual(d.phase_at_decision, "RETIRED_LIMITED")
        self.assertEqual(d.cleanup_scope, "original_group_only")
        self.assertEqual(d.full_descendant_tree_clean, "not_proven")
        self.assertIsNone(d.transport_ack)

    def test_b95_changed_backend_after_dispatch_denies_retirement(self):
        m, t, b = running()
        new = replace(b, backend_config_sha256="c" * 64)
        self.blocked(lambda: m.retire_limited_fake(t, new, now=103), "changed")
        self.assertEqual(m.snapshot()["phases"][t.attempt_id], "UNKNOWN")
        self.assertTrue(m.snapshot()["quarantined_fake"])

    def test_b95_revoked_after_dispatch_no_replay(self):
        m, t, b = running()
        m.revoke_fake()
        self.blocked(lambda: m.retire_limited_fake(t, b, now=103))
        self.assertEqual(m.snapshot()["hypothetical_dispatches"], 1)
        self.assertEqual(m.snapshot()["phases"][t.attempt_id], "UNKNOWN")
        self.assertEqual(m.decide_fake(t).phase_at_decision, "UNKNOWN")

    def test_b95_mutable_script_change_does_not_rotate_consent(self):
        m, t, b = running()
        before = m.consent_epoch
        m.content_changed_fake(now=102)
        m.retire_limited_fake(t, b, now=103)
        self.assertEqual(m.consent_epoch, before)
        self.assertEqual(m.decide_fake(t).phase_at_decision, "RETIRED_LIMITED")

    def test_c95_security_profile_and_trust_scope_are_typed_exact(self):
        b = scope()
        self.assertEqual((b.profile, b.trust_scope), ("native_limited", "mutable_workspace"))
        for changed in ({"profile": "preview_only"}, {"profile": "strict_f3"},
                        {"profile": "unknown"}, {"trust_scope": "immutable_workspace"},
                        {"trust_scope": "test"}, {"profile": None},
                        {"trust_scope": True}):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                scope(**changed)
        self.assertIn('"profile":"native_limited"', b.encoded_binding())
        self.assertIn('"trust_scope":"mutable_workspace"', b.encoded_binding())

    def test_c95_legal_nested_scope_and_root_dot_are_accepted(self):
        self.assertEqual(scope(workspace_exec_paths=(".", "src/tools"),
                               runner_project=".").workspace_exec_paths,
                         (".", "src/tools"))
        self.assertEqual(scope(workspace_exec_paths=("src/tools",),
                               workspace_exec_runners=("src/tools=pipenv",),
                               runner_cwd="src/tools", runner_id="pipenv",
                               runner_project="src/tools").runner_project, "src/tools")

    def test_c95_scope_and_runner_modes_change_canonical_digest(self):
        b = scope()
        changes = ({"workspace_exec_paths": ("runner", "src/tools", "tests")},
                   {"workspace_exec_runners": ("src/tools=direct",)},
                   {"workspace_exec_runners": ("src/tools=direct", "tests=pipenv"),
                    "workspace_exec_paths": ("runner", "src/tools", "tests")},
                   {"runner_id": "pipenv"},
                   {"runner_cwd": "src/tools", "runner_project": "src/tools",
                    "runner_id": "pipenv"})
        for change in changes:
            with self.subTest(change=change):
                self.assertNotEqual(scope(**change).digest(), b.digest())

    def test_c95_server_only_boolean_grant_no_fake_server_paths(self):
        b = scope()
        self.assertIn("server_exec_enabled", asdict(b))
        self.assertNotIn("server_exec_paths", asdict(b))
        self.assertNotIn("server_exec_runners", asdict(b))

    def test_c95_invalid_and_noncanonical_scope_denied(self):
        wrong = ("../outside", "src//tools", "src/./tools", "/root", "src/../tools",
                 "src/tools/", "~", "with:colon", "bad\\sep", "src/*", "", "src\x01")
        for path in wrong:
            with self.subTest(path=path), self.assertRaises(ValueError):
                scope(workspace_exec_paths=(path,))

    def test_c95_invalid_runner_map_or_ambiguous_duplicate_denied(self):
        # Exact duplicate full strings are invalid in workspaces_config._bounded_tuple.
        # Distinct PATH=mode strings targeting one PATH are legal: the real
        # CommandRunner dict uses last assignment for that PATH.
        invalid = (("src/tools=shell",), ("src/tools=pipenv", "src/tools=pipenv"),
                   ("outside=direct",), ("../bad=direct",), ("src/tools=direct=oops",))
        for modes in invalid:
            with self.subTest(modes=modes), self.assertRaises(ValueError):
                scope(workspace_exec_runners=modes)
        direct_last = scope(workspace_exec_runners=(
            "src/tools=pipenv", "src/tools=direct"),
            runner_cwd="src/tools", runner_id="direct", runner_project="src/tools")
        pipenv_last = scope(workspace_exec_runners=(
            "src/tools=direct", "src/tools=pipenv"),
            runner_cwd="src/tools", runner_id="pipenv", runner_project="src/tools")
        self.assertNotEqual(direct_last.digest(), pipenv_last.digest())
        with self.assertRaises(ValueError):
            scope(workspace_exec_runners=("src/tools=direct", "src/tools=pipenv"),
                  runner_cwd="src/tools", runner_id="direct", runner_project="src/tools")

    def test_c95_starting_commit_fail_before_any_dispatch(self):
        m = N3MOfflineModel("testnamespace", 7)
        m.provision_offline_fake()
        b = scope()
        m.approve_fake(b, now=100)
        t = m.prepare_fake(b, now=101)
        m.fault_next_fake_commit("starting")
        self.blocked(lambda: m.fake_first_dispatch(t, now=102), "starting")
        self.assertEqual(m.snapshot()["hypothetical_dispatches"], 0)
        self.assertEqual(m.snapshot()["phases"][t.attempt_id], "UNKNOWN")
        self.assertTrue(m.snapshot()["quarantined_fake"])

    def test_c95_starting_then_revoke_before_dispatch_denies(self):
        m = N3MOfflineModel("testnamespace", 7)
        m.provision_offline_fake()
        b = scope()
        m.approve_fake(b, now=100)
        t = m.prepare_fake(b, now=101)
        m.fake_starting_commit(t, now=102)
        self.assertEqual(m.snapshot()["phases"][t.attempt_id], "STARTING")
        m.revoke_fake()
        self.blocked(lambda: m.fake_first_dispatch(t, now=103))
        self.assertEqual(m.snapshot()["hypothetical_dispatches"], 0)
        self.assertEqual(m.snapshot()["phases"][t.attempt_id], "UNKNOWN")

    def test_c95_starting_then_late_event_denies_dispatch(self):
        m = N3MOfflineModel("testnamespace", 7)
        m.provision_offline_fake()
        b = scope()
        m.approve_fake(b, now=100)
        t = m.prepare_fake(b, now=101)
        m.fake_starting_commit(t, now=102)
        m.late_positive_fake(None)
        self.blocked(lambda: m.fake_first_dispatch(t, now=103))
        self.assertEqual(m.snapshot()["hypothetical_dispatches"], 0)
        self.assertEqual(m.snapshot()["phases"][t.attempt_id], "UNKNOWN")

    def test_c95_dispatch_fake_commit_failure_after_starting_denies(self):
        m = N3MOfflineModel("testnamespace", 7)
        m.provision_offline_fake()
        b = scope()
        m.approve_fake(b, now=100)
        t = m.prepare_fake(b, now=101)
        m.fake_starting_commit(t, now=102)
        m.fault_next_fake_commit("dispatch")
        self.blocked(lambda: m.fake_first_dispatch(t, now=103), "dispatch")
        self.assertEqual(m.snapshot()["hypothetical_dispatches"], 0)
        self.assertEqual(m.snapshot()["phases"][t.attempt_id], "UNKNOWN")

    def test_b95_control_reason_conflict_fails_closed_in_memory(self):
        kwargs = {
            "schema_id": "native-n3-v1", "namespace_id": "testnamespace",
            "lineage_generation": 7, "owner_generation": 1,
            "state_generation": 1, "consent_epoch": 1,
            "consent_record_id": "c1", "consent_active": True,
            "consent_expiry_or_null": 1000, "consent_binding_digest": scope().digest(),
            "owner_lock_dev": 10, "owner_lock_ino": 11,
            "global_quarantined": False, "global_quarantine_reason": "none",
            "max_attempts": 4096, "max_attempt_bytes": 4096,
            "max_total_attempt_payload": 16 * 1024 * 1024,
            "unresolved_retired_tombstone_count": 0,
        }
        for diff in ({"global_quarantine_reason": "cleanup_unknown"},
                     {"global_quarantined": True}):
            with self.subTest(diff=diff), self.assertRaises(ValueError):
                N3MControl(**(kwargs | diff))


if __name__ == "__main__":
    unittest.main()
