"""N3-M T0-only memory and JSON contract tests. No physical N3 state tests."""
from __future__ import annotations

from dataclasses import asdict, FrozenInstanceError, replace
import json
import unittest

from gateway.r2n_n3m_offline import (
    N3MBlocked, N3MBinding, N3MControl, N3MAttempt, N3MDecision,
    N3MOfflineModel, decode_control, strict_json, verify_attempt, verify_decision,
)


def binding(**kw):
    return N3MBinding(**({
        "workspace": "demo", "profile": "native_limited",
        "trust_scope": "mutable_workspace",
        "root_dev": 12, "root_ino": 34,
        "server_exec_enabled": True, "workspace_exec_enabled": True,
        "workspace_exec_paths": ("runner", "tools"),
        "workspace_exec_runners": (),
        "runner_id": "direct", "runner_project": "runner",
        "runner_fallback": "nearest_pipfile_else_direct",
        "backend_id": "futuredisabled",
        "backend_version": "v1", "backend_config_sha256": "a" * 64,
        "risk_contract_sha256": "b" * 64, "consent_format": "v1",
        "operator_issuer": "localowner", "risk_ack": (
            "host_user_scope", "irreversible_effects", "detached_survivors"),
        "expiry_epoch": 1000,
    } | kw))


def ready(**opts):
    m = N3MOfflineModel("testnamespace", 7, **opts)
    m.provision_offline_fake()
    m.approve_fake(binding(), now=100)
    return m


def persisted_control(**fields):
    return N3MControl(**({
        "schema_id": "native-n3-v1", "namespace_id": "testnamespace",
        "lineage_generation": 7, "owner_generation": 1,
        "state_generation": 1, "consent_epoch": 1, "consent_record_id": "consent1",
        "consent_active": True, "consent_binding_digest": binding().digest(),
        "consent_expiry_or_null": 1000, "owner_lock_dev": 21, "owner_lock_ino": 22,
        "global_quarantined": False, "global_quarantine_reason": "none",
        "max_attempts": 4096, "max_attempt_bytes": 4096,
        "max_total_attempt_payload": 16 * 1024 * 1024,
        "unresolved_retired_tombstone_count": 0,
    } | fields))


class N3MContractT0(unittest.TestCase):
    def assert_blocked(self, fn, msg=None):
        with self.assertRaises(N3MBlocked) as err:
            fn()
        if msg is not None:
            self.assertIn(msg, str(err.exception))

    def test_all_fakes_never_enable_exec(self):
        m = ready()
        t = m.prepare_fake(binding(), now=101)
        m.fake_first_dispatch(t, now=102)
        m.retire_limited_fake(t, binding(), now=103)
        self.assert_blocked(lambda: m.deny_apply(t), "exec_cleanup_proof_required")
        self.assertEqual(m.snapshot()["profile"], "preview_only")
        self.assertEqual(m.snapshot()["completion_capability"], "none")
        self.assertFalse(m.snapshot()["available_for_real_exec"])
        self.assertEqual(m.snapshot()["hypothetical_dispatches"], 1)

    def test_binding_digest_deterministic_and_script_mutability(self):
        self.assertEqual(binding().digest(), binding().digest())
        m = ready()
        before = m.consent_epoch
        m.content_changed_fake(now=101)
        self.assertEqual(m.consent_epoch, before)
        self.assertEqual(binding().digest(), binding().digest())

    def test_all_binding_fields_change_digest(self):
        before = binding()
        alternatives = {
            "workspace": "different", "root_dev": 99, "root_ino": 99,
            "server_exec_enabled": False, "workspace_exec_enabled": False,
            "workspace_exec_paths": ("runner",),
            "workspace_exec_runners": ("tools=pipenv",),
            "runner_id": "pipenv", "runner_project": "tools",
            "backend_id": "newbackend",
            "backend_version": "v2", "backend_config_sha256": "c" * 64,
            "risk_contract_sha256": "c" * 64, "consent_format": "v2",
            "operator_issuer": "differentowner", "expiry_epoch": 999,
        }
        for field, value in alternatives.items():
            with self.subTest(field=field):
                replacement = replace(before, **{field: value})
                self.assertNotEqual(before.digest(), replacement.digest())

    def test_grant_and_scope_change_fences_prepared(self):
        m = ready()
        t = m.prepare_fake(binding(), now=101)
        self.assert_blocked(lambda: m.validate_binding_fake(binding(root_ino=99), now=102), "fake_binding")
        self.assertTrue(m.snapshot()["quarantined_fake"])
        self.assertEqual(m.snapshot()["phases"][t.attempt_id], "UNKNOWN")
        self.assert_blocked(lambda: m.fake_first_dispatch(t, now=103))
        self.assertEqual(m.snapshot()["hypothetical_dispatches"], 0)

    def test_grants_require_both_server_and_workspace_true(self):
        for f in ("server_exec_enabled", "workspace_exec_enabled"):
            m = N3MOfflineModel("testnamespace", 7)
            m.provision_offline_fake()
            self.assert_blocked(lambda: m.approve_fake(binding(**{f: False}), now=100), "invalid_grants")

    def test_runner_must_be_in_effective_grants(self):
        with self.assertRaises(ValueError):
            binding(workspace_exec_paths=("tools",))
        with self.assertRaises(ValueError):
            binding(workspace_exec_runners=("outside=direct",))

    def test_reject_bad_scope_types_order_and_ack(self):
        bad = ({"workspace": "../other"}, {"root_dev": True},
               {"server_exec_enabled": 1}, {"workspace_exec_enabled": "true"},
               {"workspace_exec_paths": ("tools", "runner")},
               {"workspace_exec_paths": ("runner", "runner")},
               {"workspace_exec_paths": ("../outside",)},
               {"workspace_exec_runners": ("outside=direct",)},
               {"runner_id": "notsupported"},
               {"profile": "strict_f3"},
               {"trust_scope": "nonmutable"},
               {"backend_config_sha256": "notsha"}, {"risk_ack": ()},
               {"operator_issuer": ""}, {"expiry_epoch": True},
               {"backend_id": "has space"})
        for obj in bad:
            with self.subTest(obj=obj), self.assertRaises(ValueError):
                binding(**obj)

    def test_strict_control_json_valid_and_no_extra_fields(self):
        control = persisted_control()
        self.assertEqual(decode_control(control.encoded()), control)
        extras = asdict(control) | {"api_grant": "activate"}
        self.assert_blocked(lambda: decode_control(json.dumps(extras)), "unexpected_json_schema")

    def test_control_wrong_schema_and_unsafe_types_fail_closed(self):
        for changes in ({"schema_id": "v1"}, {"consent_epoch": True},
                        {"consent_active": 1}, {"owner_generation": 0},
                        {"owner_lock_ino": False}, {"global_quarantined": "false"},
                        {"consent_expiry_or_null": -2},
                        {"consent_record_id": ""}, {"global_quarantine_reason": "bad text"},
                        {"max_attempts": 4097}, {"max_attempt_bytes": 4097},
                        {"max_total_attempt_payload": 16*1024*1024+1},
                        {"unresolved_retired_tombstone_count": 4097}):
            with self.subTest(changes=changes):
                data = asdict(persisted_control()) | changes
                self.assert_blocked(lambda: decode_control(json.dumps(data)), "invalid_control_data")

    def test_json_duplicate_fields_and_nonfinite_numbers_rejected(self):
        data = persisted_control().encoded()
        bad = data.replace('"schema_id":', '"schema_id":"native-n3-v1","schema_id":', 1)
        self.assert_blocked(lambda: decode_control(bad), "duplicate_json_key")
        self.assert_blocked(lambda: decode_control(data.replace('"state_generation":1', '"state_generation":NaN')), "nonfinite_json")

    def test_json_missing_field_trailing_and_large_string_rejected(self):
        data = asdict(persisted_control())
        data.pop("namespace_id")
        self.assert_blocked(lambda: decode_control(json.dumps(data)), "unexpected_json_schema")
        self.assert_blocked(lambda: decode_control("[1, 2]"), "unexpected_json_schema")
        self.assert_blocked(lambda: decode_control("{" + "x" * 65537 + "}"), "invalid_json_size")

    def test_expired_consent_fails_approval_and_prepare(self):
        m = N3MOfflineModel("testnamespace", 7)
        m.provision_offline_fake()
        self.assert_blocked(lambda: m.approve_fake(binding(expiry_epoch=100), now=100), "expired")
        m.approve_fake(binding(), now=101)
        self.assert_blocked(lambda: m.prepare_fake(binding(), now=1000), "expired")

    def test_fake_clock_rollback_latches_quarantine(self):
        m = ready()
        m.prepare_fake(binding(), now=150)
        self.assert_blocked(lambda: m.prepare_fake(binding(), now=149), "clock_rollback")
        self.assertTrue(m.snapshot()["quarantined_fake"])

    def test_expiry_rechecked_before_hypothetical_dispatch(self):
        m = ready()
        t = m.prepare_fake(binding(), now=999)
        self.assert_blocked(lambda: m.fake_first_dispatch(t, now=1000), "expired")
        self.assertEqual(m.snapshot()["hypothetical_dispatches"], 0)

    def test_absent_provision_and_no_automatic_first_install(self):
        m = N3MOfflineModel("testnamespace", 7)
        self.assert_blocked(lambda: m.approve_fake(binding(), now=100))
        self.assert_blocked(lambda: m.prepare_fake(binding(), now=101))
        m.provision_offline_fake()
        self.assert_blocked(m.provision_offline_fake, "offline_recovery_required")

    def test_loss_entire_namespace_with_retained_fake_consent(self):
        m = ready()
        m.lose_provenance_fake(namespace=True)
        m.restart_fake()
        self.assertTrue(m.snapshot()["quarantined_fake"])
        self.assertFalse(m.snapshot()["namespace_present_fake"])
        self.assertTrue(m.snapshot()["witness_present_fake"])
        self.assert_blocked(lambda: m.prepare_fake(binding(), now=102))
        self.assert_blocked(m.provision_offline_fake)

    def test_loss_both_roots_never_becomes_healthy_install(self):
        m = ready()
        m.lose_provenance_fake(namespace=True, witness=True)
        m.restart_fake()
        self.assertTrue(m.snapshot()["quarantined_fake"])
        self.assert_blocked(m.provision_offline_fake)

    def test_revoke_after_prepared_before_first_dispatch(self):
        m = ready()
        t = m.prepare_fake(binding(), now=101)
        m.revoke_fake()
        self.assertEqual(m.snapshot()["phases"][t.attempt_id], "UNKNOWN")
        self.assert_blocked(lambda: m.fake_first_dispatch(t, now=102))
        self.assertEqual(m.snapshot()["hypothetical_dispatches"], 0)

    def test_prepared_response_never_emits_clean_decision_or_starts(self):
        m = ready()
        t = m.prepare_fake(binding(), now=101)
        self.assert_blocked(lambda: m.decide_fake(t), "response_before_terminal")
        self.assertNotIn(t.attempt_id, m.snapshot()["decisions"])
        self.assertEqual(m.snapshot()["phases"][t.attempt_id], "UNKNOWN")
        self.assert_blocked(lambda: m.fake_first_dispatch(t, now=102))
        self.assertEqual(m.snapshot()["hypothetical_dispatches"], 0)

    def test_completed_hypothetical_limited_history_is_not_full_cleanup(self):
        m = ready()
        t = m.prepare_fake(binding(), now=101)
        m.fake_first_dispatch(t, now=102)
        m.retire_limited_fake(t, binding(), now=103)
        d = m.decide_fake(t)
        self.assertEqual(d.kind, "LIMITED_HISTORICAL_COMPLETION_COMMITTED")
        self.assertEqual(d.cleanup_scope, "original_group_only")
        self.assertEqual(d.full_descendant_tree_clean, "not_proven")
        self.assertIsNone(d.transport_ack)
        with self.assertRaises(FrozenInstanceError):
            d.kind = "grant"

    def test_late_positive_before_response_is_nonclean(self):
        m = ready()
        t = m.prepare_fake(binding(), now=101)
        m.fake_first_dispatch(t, now=102)
        m.retire_limited_fake(t, binding(), now=103)
        m.late_positive_fake(t)
        d = m.decide_fake(t)
        self.assertEqual(d.kind, "QUARANTINED_OR_CLEANUP_UNKNOWN")
        self.assertEqual(d.phase_at_decision, "UNKNOWN")

    def test_late_positive_after_response_preserves_historical_only(self):
        m = ready()
        t = m.prepare_fake(binding(), now=101)
        m.fake_first_dispatch(t, now=102)
        m.retire_limited_fake(t, binding(), now=103)
        before = m.decide_fake(t)
        m.late_positive_fake(t)
        self.assertIs(m.decide_fake(t), before)
        self.assertTrue(m.snapshot()["quarantined_fake"])
        self.assertEqual(m.snapshot()["phases"][t.attempt_id], "UNKNOWN")

    def test_late_a_survivor_when_b_only_prepared(self):
        m = ready()
        a = m.prepare_fake(binding(), now=101)
        m.fake_first_dispatch(a, now=102)
        m.retire_limited_fake(a, binding(), now=103)
        b = m.prepare_fake(binding(), now=103)
        m.late_positive_fake(a)
        self.assertEqual(m.snapshot()["phases"][b.attempt_id], "UNKNOWN")
        self.assert_blocked(lambda: m.fake_first_dispatch(b, now=104))
        self.assertEqual(m.snapshot()["hypothetical_dispatches"], 1)

    def test_late_a_survivor_after_b_already_dispatched(self):
        m = ready()
        a = m.prepare_fake(binding(), now=101)
        m.fake_first_dispatch(a, now=102)
        m.retire_limited_fake(a, binding(), now=103)
        b = m.prepare_fake(binding(), now=103)
        m.fake_first_dispatch(b, now=104)
        m.late_positive_fake(a)
        self.assertEqual(m.snapshot()["hypothetical_dispatches"], 2)
        self.assertEqual(m.snapshot()["phases"][b.attempt_id], "UNKNOWN")

    def test_unattributed_positive_latches_orphan_quarantine(self):
        m = ready()
        m.late_positive_fake(None)
        self.assertTrue(m.snapshot()["quarantined_fake"])
        self.assertTrue(m.snapshot()["orphan_positive_fake"])

    def test_old_owner_attempt_after_restart_is_not_resumed(self):
        m = ready()
        t = m.prepare_fake(binding(), now=101)
        old_owner = t.owner_generation
        m.restart_fake()
        self.assertNotEqual(m.owner_generation, old_owner)
        self.assertTrue(m.snapshot()["boot_deny_armed_fake"])
        self.assertEqual(m.snapshot()["phases"][t.attempt_id], "UNKNOWN")
        self.assert_blocked(lambda: m.fake_first_dispatch(t, now=102))

    def test_record_count_quota_fail_closed(self):
        m = ready(max_attempts=1)
        a = m.prepare_fake(binding(), now=101)
        self.assert_blocked(lambda: m.prepare_fake(binding(), now=102), "fake_record_count_full")
        self.assertIn(a.attempt_id, m.snapshot()["phases"])
        self.assertTrue(m.snapshot()["quarantined_fake"])

    def test_record_byte_quota_fail_closed_no_eviction(self):
        m = ready(max_record_bytes=350)
        self.assert_blocked(lambda: m.prepare_fake(binding(), now=101, evidence_ref="z" * 300), "fake_record_byte_quota_full")
        self.assertTrue(m.snapshot()["quarantined_fake"])

    def test_total_payload_quota_overflow(self):
        m = ready(max_payload_bytes=500)
        first = m.prepare_fake(binding(), now=101)
        self.assert_blocked(lambda: m.prepare_fake(binding(), now=102), "fake_record_byte_quota_full")
        self.assertIn(first.attempt_id, m.snapshot()["phases"])

    def test_fault_before_prepared_and_after_fence(self):
        for stage in ("arm", "prepare"):
            with self.subTest(stage=stage):
                m = ready()
                m.fault_next_fake_commit(stage)
                self.assert_blocked(lambda: m.prepare_fake(binding(), now=101), "fake_commit_unavailable")
                self.assertEqual(m.snapshot()["hypothetical_dispatches"], 0)
                self.assertTrue(m.snapshot()["quarantined_fake"])

    def test_failed_response_commit_does_not_publish(self):
        m = ready()
        t = m.prepare_fake(binding(), now=101)
        m.fake_first_dispatch(t, now=102)
        m.retire_limited_fake(t, binding(), now=103)
        m.fault_next_fake_commit("response")
        self.assert_blocked(lambda: m.decide_fake(t), "fake_commit_unavailable")
        self.assertNotIn(t.attempt_id, m.snapshot()["decisions"])
        self.assertTrue(m.snapshot()["quarantined_fake"])

    def test_failed_late_event_commit_still_quarantines(self):
        m = ready()
        t = m.prepare_fake(binding(), now=101)
        m.fake_first_dispatch(t, now=102)
        m.retire_limited_fake(t, binding(), now=103)
        m.fault_next_fake_commit("late_event")
        self.assert_blocked(lambda: m.late_positive_fake(t), "fake_commit_unavailable")
        self.assertTrue(m.snapshot()["quarantined_fake"])
        m.restart_fake()
        self.assertTrue(m.snapshot()["quarantined_fake"])

    def test_decision_json_roundtrip_only_historical(self):
        m = ready()
        t = m.prepare_fake(binding(), now=101)
        m.fake_first_dispatch(t, now=102)
        m.retire_limited_fake(t, binding(), now=103)
        d = m.decide_fake(t)
        self.assertEqual(m.read_decision_fake(d.encoded(), t), d)
        self.assertFalse(m.snapshot()["available_for_real_exec"])

    def test_foreign_response_binding_rejected_every_identity(self):
        m = ready()
        t = m.prepare_fake(binding(), now=101)
        m.fake_first_dispatch(t, now=102)
        m.retire_limited_fake(t, binding(), now=103)
        d = m.decide_fake(t)
        changes = {"namespace_id": "foreignnamespace", "lineage_generation": 88,
                   "owner_generation": 88, "consent_epoch": 88,
                   "binding_digest": "e" * 64, "attempt_id": "a9999",
                   "attempt_generation": 88, "decision_sequence": 99,
                   "decision_id": "d999"}
        for key, new in changes.items():
            with self.subTest(key=key):
                forged = asdict(d) | {key: new}
                self.assert_blocked(lambda: m.read_decision_fake(json.dumps(forged), t),
                                    "foreign_or_replayed_decision")

    def test_response_rejects_copy_from_another_attempt_same_binding(self):
        m = ready()
        a = m.prepare_fake(binding(), now=101)
        m.fake_first_dispatch(a, now=102)
        m.retire_limited_fake(a, binding(), now=103)
        d = m.decide_fake(a)
        b = m.prepare_fake(binding(), now=103)
        self.assert_blocked(lambda: m.read_decision_fake(d.encoded(), b), "missing_registered_decision")

    def test_response_unknown_and_duplicate_fields_rejected(self):
        m = ready()
        t = m.prepare_fake(binding(), now=101)
        m.fake_first_dispatch(t, now=102)
        m.retire_limited_fake(t, binding(), now=103)
        d = m.decide_fake(t)
        self.assert_blocked(lambda: m.read_decision_fake(d.encoded().replace('"decision_id":', '"decision_id":"d1","decision_id":', 1), t), "duplicate_json_key")
        self.assert_blocked(lambda: m.read_decision_fake(json.dumps(asdict(d) | {"ACK": True}), t), "unexpected_json_schema")

    def test_response_must_not_claim_ack_or_full_descendants(self):
        m = ready()
        t = m.prepare_fake(binding(), now=101)
        m.fake_first_dispatch(t, now=102)
        m.retire_limited_fake(t, binding(), now=103)
        d = m.decide_fake(t)
        for change in ({"transport_ack": True}, {"full_descendant_tree_clean": "proven"},
                       {"cleanup_scope": "all_descendants"}):
            self.assert_blocked(lambda: m.read_decision_fake(json.dumps(asdict(d) | change), t), "invalid_decision_data")

    def test_attempt_json_verified_and_copied_attempt_rejected(self):
        m = ready()
        a = m.prepare_fake(binding(), now=101)
        data = json.dumps(asdict(a), sort_keys=True)
        self.assertEqual(verify_attempt(data, a), a)
        self.assert_blocked(lambda: verify_attempt(json.dumps(asdict(a) | {"attempt_id": "foreign"}), a),
                            "foreign_or_replayed_attempt")
        duplicate = data.replace('"attempt_id":', '"attempt_id":"a1","attempt_id":', 1)
        self.assert_blocked(lambda: verify_attempt(duplicate, a), "duplicate_json_key")

    def test_immutable_attempt_and_forged_ticket_rejected(self):
        m = ready()
        a = m.prepare_fake(binding(), now=101)
        with self.assertRaises(FrozenInstanceError):
            a.owner_generation = 99
        forged = replace(a)
        self.assert_blocked(lambda: m.fake_first_dispatch(forged, now=102), "foreign_or_forged_attempt")

    def test_legacy_shaped_ticket_is_not_accepted(self):
        # A non-authoritative v1/N2-shaped fixture, NOT an actual N2 import.
        m = ready()
        ticket = {"attempt_id": 1, "attempt_generation": 1, "owner_generation": 1,
                  "consent_epoch": 1, "workspace": "demo"}
        self.assert_blocked(lambda: m.fake_first_dispatch(ticket, now=102), "invalid_attempt_type")

    def test_no_actual_backend_spawn_signal_or_io_methods(self):
        for name in ("run_command", "start_once", "spawn", "kill", "killpg", "open",
                     "fsync", "flock", "run_git", "reset_unknown", "apply"):
            self.assertFalse(hasattr(N3MOfflineModel, name), name)
        self.assert_blocked(N3MOfflineModel.deny_apply, "exec_cleanup_proof_required")

    def test_quarantined_retirement_cannot_emit_limited_clean(self):
        m = ready()
        a = m.prepare_fake(binding(), now=101)
        m.fake_first_dispatch(a, now=102)
        m.retire_limited_fake(a, binding(), now=103)
        m.late_positive_fake(None)
        d = m.decide_fake(a)
        self.assertEqual(d.kind, "QUARANTINED_OR_CLEANUP_UNKNOWN")
        self.assertEqual(d.phase_at_decision, "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
