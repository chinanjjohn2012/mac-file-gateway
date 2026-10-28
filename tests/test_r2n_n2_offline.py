"""R2-N N2 strict T0: ONLY pure-memory Fake event order and structural checks.

No subprocess, signal, filesystem, network, real backend, transport or SDK.
These tests do NOT prove fsync, process ownership, termination or delivery.
"""
from __future__ import annotations

from dataclasses import FrozenInstanceError
import unittest

from gateway.r2n_n2_offline import (
    FakeResponseDecision, FakeScope, FakeTicket, N2Blocked, N2MemoryFake,
)


def scope(**kw):
    return FakeScope(**({"workspace": "demo", "root_dev": 12,
                         "root_ino": 34, "exec_paths": ("runner",),
                         "backend_version": "disabled-future-v1",
                         "risk_version": "r2n-approved-design-v1"} | kw))


def ready(**kw):
    m = N2MemoryFake(**kw)
    m.provision_initial_fake()
    m.approve_fake(scope())
    return m


class N2T0Contract(unittest.TestCase):
    def denied(self, action, expected=""):
        with self.assertRaisesRegex(N2Blocked, expected):
            action()

    def test_no_positive_runtime_authority_even_when_fake_active(self):
        m = ready()
        t = m.prepare_fake(scope())
        m.simulate_first_dispatch_fake(t)
        self.denied(lambda: m.deny_apply(t, profile="native_limited"), "exec_cleanup_proof_required")
        self.assertFalse(m.snapshot()["available_for_real_exec"])
        self.assertEqual(m.snapshot()["completion_capability"], "none")
        self.assertEqual(m.snapshot()["profile"], "preview_only")
        self.assertEqual(m.snapshot()["hypothetical_dispatches"], 1)

    def test_scope_strict_validation_and_immutable_structural_ticket(self):
        for fields in (dict(workspace=".."), dict(root_dev=True),
                       dict(root_ino=0), dict(exec_paths=["runner"]),
                       dict(exec_paths=("runner", "runner")),
                       dict(backend_version=""), dict(risk_version="")):
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                scope(**fields)
        t = ready().prepare_fake(scope())
        with self.assertRaises(FrozenInstanceError):
            t.attempt_id = 42
        forged = FakeTicket(t.attempt_id, t.attempt_generation,
                            t.owner_generation, t.consent_epoch, t.scope)
        m = ready()
        real = m.prepare_fake(scope())
        self.denied(lambda: m.simulate_first_dispatch_fake(forged), "stale_or_forged")
        self.assertEqual(real.attempt_generation, 1)

    def test_no_implicit_init_and_no_reprovision_after_entire_namespace_loss(self):
        m = N2MemoryFake()
        self.denied(lambda: m.approve_fake(scope()), "namespace_or_provisioning")
        self.denied(lambda: m.prepare_fake(scope()))
        m.provision_initial_fake()
        self.denied(m.provision_initial_fake, "offline_first_init")
        m.approve_fake(scope())
        m.lose_namespace_fake()
        self.denied(m.provision_initial_fake, "offline_first_init")
        m.restart_fake()
        self.assertTrue(m.snapshot()["quarantined"])
        self.assertTrue(m.snapshot()["provisioning_witness_fake"])
        self.assertFalse(m.snapshot()["namespace_present_fake"])
        self.denied(lambda: m.prepare_fake(scope()))

    def test_lost_witness_with_old_consent_is_not_a_new_install(self):
        m = ready()
        m.lose_witness_fake()
        m.restart_fake()
        self.assertTrue(m.snapshot()["quarantined"])
        self.denied(m.provision_initial_fake)
        self.denied(lambda: m.prepare_fake(scope()))

    def test_mutable_content_does_not_rotate_epoch_but_binding_does(self):
        m = ready()
        before = m.snapshot()["consent_epoch"]
        m.fake_content_changed()
        self.assertEqual(m.snapshot()["consent_epoch"], before)
        m.change_effective_scope_fake(scope())
        self.assertTrue(m.snapshot()["consent_active_fake"])
        m.change_effective_scope_fake(scope(exec_paths=("another",)))
        self.assertEqual(m.snapshot()["consent_epoch"], before + 1)
        self.assertFalse(m.snapshot()["consent_active_fake"])
        self.denied(lambda: m.prepare_fake(scope(exec_paths=("another",))))
        m.approve_fake(scope(exec_paths=("another",)))
        self.assertEqual(m.snapshot()["consent_epoch"], before + 2)

    def test_foreign_scope_and_absent_consent_are_denied(self):
        m = N2MemoryFake()
        m.provision_initial_fake()
        self.denied(lambda: m.prepare_fake(scope()))
        m.approve_fake(scope())
        self.denied(lambda: m.prepare_fake(scope(root_ino=35)), "binding_invalid")
        self.assertEqual(m.snapshot()["hypothetical_dispatches"], 0)

    def test_revoke_before_prepare_has_no_record_and_no_dispatch(self):
        m = ready()
        m.revoke_fake()
        self.denied(lambda: m.prepare_fake(scope()))
        self.assertFalse(m.snapshot()["phases"])
        self.assertEqual(m.snapshot()["hypothetical_dispatches"], 0)
        self.assertFalse(m.snapshot()["quarantined"])

    def test_revoke_after_prepare_before_first_dispatch_fences_unknown(self):
        m = ready()
        t = m.prepare_fake(scope())
        m.revoke_fake()
        self.assertEqual(m.snapshot()["phases"][t.attempt_id], "UNKNOWN")
        self.denied(lambda: m.simulate_first_dispatch_fake(t))
        self.assertTrue(m.snapshot()["quarantined"])
        self.assertEqual(m.snapshot()["hypothetical_dispatches"], 0)
        self.assertTrue(m.snapshot()["boot_fence_armed_fake"])

    def test_start_first_then_revoke_admits_at_most_one_fake_dispatch(self):
        m = ready()
        t = m.prepare_fake(scope())
        m.simulate_first_dispatch_fake(t)
        self.denied(lambda: m.simulate_first_dispatch_fake(t), "not_qualified")
        m.revoke_fake()
        self.denied(lambda: m.simulate_first_dispatch_fake(t))
        self.assertEqual(m.snapshot()["hypothetical_dispatches"], 1)
        self.assertEqual(m.snapshot()["phases"][t.attempt_id], "UNKNOWN")
        self.assertTrue(m.snapshot()["quarantined"])

    def test_late_event_first_blocks_pending_response_and_pending_b(self):
        m = ready()
        a = m.prepare_fake(scope())
        m.simulate_first_dispatch_fake(a)
        m.retire_limited_fake(a)
        b = m.prepare_fake(scope())
        m.late_survivor_fake(a)
        d = m.decide_response_fake(a)
        self.assertEqual(d.kind, "QUARANTINED_OR_CLEANUP_UNKNOWN")
        self.assertEqual(d.cleanup_scope, "none")
        self.assertEqual(d.full_descendant_tree_clean, "not_proven")
        self.assertIsNone(d.transport_ack)
        self.denied(lambda: m.simulate_first_dispatch_fake(b))
        self.assertEqual(m.snapshot()["hypothetical_dispatches"], 1)
        self.assertEqual(m.snapshot()["phases"][a.attempt_id], "UNKNOWN")

    def test_response_decision_first_remains_bounded_historical_after_event(self):
        m = ready()
        a = m.prepare_fake(scope())
        m.simulate_first_dispatch_fake(a)
        m.retire_limited_fake(a)
        before = m.decide_response_fake(a)
        self.assertEqual(before.kind, "LIMITED_HISTORICAL_COMPLETION_COMMITTED")
        self.assertEqual(before.cleanup_scope, "original_group_only")
        self.assertEqual(before.full_descendant_tree_clean, "not_proven")
        m.late_survivor_fake(a)
        after = m.decide_response_fake(a)
        self.assertIs(before, after)
        self.assertTrue(m.snapshot()["quarantined"])
        self.assertEqual(m.snapshot()["phases"][a.attempt_id], "UNKNOWN")
        self.assertIsNone(after.transport_ack)
        with self.assertRaises(FrozenInstanceError):
            after.transport_ack = True

    def test_failed_response_decision_never_emits_success(self):
        m = ready()
        t = m.prepare_fake(scope())
        m.simulate_first_dispatch_fake(t)
        m.retire_limited_fake(t)
        m.fault_next_fake_commit("response")
        self.denied(lambda: m.decide_response_fake(t), "fake_commit_unavailable:response")
        self.assertTrue(m.snapshot()["quarantined"])
        self.assertNotIn(t.attempt_id, m.snapshot()["decisions"])

    def test_late_positive_after_b_already_dispatched_does_not_erase_effects(self):
        m = ready()
        a = m.prepare_fake(scope())
        m.simulate_first_dispatch_fake(a)
        m.retire_limited_fake(a)
        b = m.prepare_fake(scope())
        m.simulate_first_dispatch_fake(b)
        m.late_survivor_fake(a)
        self.assertEqual(m.snapshot()["hypothetical_dispatches"], 2)
        self.assertEqual(m.snapshot()["phases"][b.attempt_id], "UNKNOWN")
        self.denied(lambda: m.simulate_first_dispatch_fake(b))

    def test_orphan_positive_fails_closed_no_guessed_identity(self):
        m = ready()
        m.late_survivor_fake(None)
        self.assertTrue(m.snapshot()["orphan_positive"])
        self.assertTrue(m.snapshot()["quarantined"])
        self.assertEqual(m.snapshot()["hypothetical_dispatches"], 0)

    def test_prearmed_marker_survives_retirement_and_restart(self):
        m = ready()
        consent = m.snapshot()["consent_epoch"]
        t = m.prepare_fake(scope())
        m.simulate_first_dispatch_fake(t)
        m.retire_limited_fake(t)
        m.restart_fake()
        self.assertEqual(m.snapshot()["consent_epoch"], consent)
        self.assertTrue(m.snapshot()["consent_active_fake"])  # record data only
        self.assertTrue(m.snapshot()["boot_fence_armed_fake"])
        self.assertTrue(m.snapshot()["quarantined"])
        self.denied(lambda: m.prepare_fake(scope()))

    def test_restart_rotates_owner_and_fences_old_prepared(self):
        m = ready()
        t = m.prepare_fake(scope())
        owner = m.snapshot()["owner_generation"]
        m.restart_fake()
        self.assertNotEqual(owner, m.snapshot()["owner_generation"])
        self.assertEqual(m.snapshot()["phases"][t.attempt_id], "UNKNOWN")
        self.denied(lambda: m.simulate_first_dispatch_fake(t))
        self.assertEqual(m.snapshot()["hypothetical_dispatches"], 0)

    def test_quota_exhaustion_retains_existing_records(self):
        m = ready(max_records=1)
        first = m.prepare_fake(scope())
        self.denied(lambda: m.prepare_fake(scope()), "fake_forensic_quota_full")
        self.assertIn(first.attempt_id, m.snapshot()["phases"])
        self.assertTrue(m.snapshot()["quarantined"])
        self.assertTrue(m.snapshot()["boot_fence_armed_fake"])
        self.denied(lambda: m.simulate_first_dispatch_fake(first))

    def test_fake_commit_failures_never_grant_dispatch(self):
        for stage in ("arm", "prepare", "starting", "dispatch"):
            with self.subTest(stage=stage):
                m = ready()
                if stage in ("arm", "prepare"):
                    m.fault_next_fake_commit(stage)
                    self.denied(lambda: m.prepare_fake(scope()), "fake_commit_unavailable")
                else:
                    t = m.prepare_fake(scope())
                    m.fault_next_fake_commit(stage)
                    self.denied(lambda: m.simulate_first_dispatch_fake(t), "fake_commit_unavailable")
                self.assertEqual(m.snapshot()["hypothetical_dispatches"], 0)
                self.assertTrue(m.snapshot()["quarantined"])
                m.restart_fake()
                self.assertTrue(m.snapshot()["quarantined"])
                self.denied(lambda: m.prepare_fake(scope()))

    def test_failed_late_event_commit_keeps_prearmed_reboot_denial(self):
        m = ready()
        t = m.prepare_fake(scope())
        m.simulate_first_dispatch_fake(t)
        m.retire_limited_fake(t)
        m.fault_next_fake_commit("late_event")
        self.denied(lambda: m.late_survivor_fake(t), "fake_commit_unavailable")
        self.assertTrue(m.snapshot()["failed_late_event_durability_fake"])
        self.assertTrue(m.snapshot()["boot_fence_armed_fake"])
        m.restart_fake()
        self.assertTrue(m.snapshot()["quarantined"])
        self.denied(lambda: m.prepare_fake(scope()))

    def test_snapshot_does_not_mutate_underlying_model(self):
        m = ready()
        snapshot = m.snapshot()
        snapshot["phases"][111] = "RETIRED_PROVEN"
        snapshot["decisions"][222] = FakeResponseDecision(222, 1, "fake", "none")
        snapshot["quarantined"] = False
        self.assertFalse(m.snapshot()["phases"])
        self.assertFalse(m.snapshot()["decisions"])
        self.assertFalse(m.snapshot()["quarantined"])

    def test_no_runtime_backend_api_exists(self):
        for key in ("start_once", "run_command", "terminate_and_prove",
                    "kill", "killpg", "open", "create_subprocess", "run_git"):
            self.assertFalse(hasattr(N2MemoryFake, key), key)
        self.denied(lambda: N2MemoryFake.deny_apply())
        self.assertEqual(N2MemoryFake().snapshot()["profile"], "preview_only")


if __name__ == "__main__":
    unittest.main()
