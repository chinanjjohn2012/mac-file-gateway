"""Additional B03-T01-R2a pure gate tests; never spawn or signal a process."""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "tools/research/c3_candidate_b_kill_t01_gate.py"
FIXTURE = "fixture:synthetic-owned-anchor-group-T01"
NOW = 108_000
SENT = 108_000
KILL_NOW = 108_300

from test_c3_candidate_b_t01_contract_red import TERM_FACTS, KILL_FACTS


def module():
    spec = importlib.util.spec_from_file_location("t01_pure_gate_r2a", GATE)
    assert spec and spec.loader
    target = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(target)
    return target


def policy(m):
    return m.derive_cutoffs(100_000, 12_000, 3_000, 200, 300)


class Recorder:
    def __init__(self, result="OK", raises=False):
        self.calls = []
        self.result = result
        self.raises = raises

    def send(self, action, target):
        self.calls.append((action, target))
        if self.raises:
            raise RuntimeError("synthetic recorder exception")
        return self.result


@pytest.mark.parametrize("invalid", (
    -1, 0, 123, True, False, None, "", "123", "fixture:other",
    "fixture:synthetic-owned-anchor-group-T01-other", (), [], {},
))
def test_unowned_or_numeric_target_never_calls_fake_transport(invalid):
    m = module()
    recorder = Recorder()
    ledger = m.attempt_term_no_signal(
        policy(m), NOW, TERM_FACTS, m.begin_ledger(), recorder, invalid
    )
    assert recorder.calls == []
    assert ledger["term_attempts"] == 0
    assert ledger["signals_closed"] is True


def test_original_authority_cannot_be_reused_after_kill():
    m = module()
    p = policy(m)
    recorder = Recorder()
    ledger = m.begin_ledger()
    old_alias = ledger
    good = m.attempt_term_no_signal(
        p, NOW, TERM_FACTS, ledger, recorder, FIXTURE
    )
    assert old_alias is good
    good = m.attempt_kill_no_signal(
        p, KILL_NOW, SENT, KILL_FACTS, good, recorder, FIXTURE
    )
    assert good["kill_attempts"] == 1
    assert good["signals_closed"] is True
    m.attempt_kill_no_signal(
        p, KILL_NOW, SENT, KILL_FACTS, old_alias, recorder, FIXTURE
    )
    m.attempt_term_no_signal(
        p, NOW, TERM_FACTS, old_alias, recorder, FIXTURE
    )
    assert recorder.calls == [("TERM", FIXTURE), ("KILL", FIXTURE)]


def test_simulated_transport_exception_closes_one_use_term_authority():
    m = module()
    recorder = Recorder(raises=True)
    ledger = m.attempt_term_no_signal(
        policy(m), NOW, TERM_FACTS, m.begin_ledger(), recorder, FIXTURE
    )
    assert recorder.calls == [("TERM", FIXTURE)]
    assert ledger["term_attempts"] == 1
    assert ledger["term_succeeded"] is False
    assert ledger["signals_closed"] is True
    after = m.attempt_kill_no_signal(
        policy(m), KILL_NOW, SENT, KILL_FACTS, ledger, recorder, FIXTURE
    )
    assert after["kill_attempts"] == 0
    assert recorder.calls == [("TERM", FIXTURE)]


def test_simulated_transport_exception_closes_one_use_kill_authority():
    m = module()
    p = policy(m)
    term = Recorder()
    ledger = m.attempt_term_no_signal(
        p, NOW, TERM_FACTS, m.begin_ledger(), term, FIXTURE
    )
    assert term.calls == [("TERM", FIXTURE)]
    kill = Recorder(raises=True)
    after = m.attempt_kill_no_signal(
        p, KILL_NOW, SENT, KILL_FACTS, ledger, kill, FIXTURE
    )
    assert after["term_attempts"] == 1
    assert after["kill_attempts"] == 1
    assert after["kill_succeeded"] is False
    assert after["signals_closed"] is True
    again = m.attempt_kill_no_signal(
        p, KILL_NOW, SENT, KILL_FACTS, after, kill, FIXTURE
    )
    assert again["kill_attempts"] == 1
    assert kill.calls == [("KILL", FIXTURE)]


def test_wrong_policy_schema_is_fail_closed_before_fake_transport():
    m = module()
    p = policy(m)
    for mutant in (
        {**p, "kill_cutoff_ms": p["kill_cutoff_ms"] + 1},
        {**p, "term_cutoff_ms": p["term_cutoff_ms"] + 1},
        {**p, "extra": True},
        {**p, "outer_deadline_ms": True},
        {**p, "cleanup_reserve_ms": 0},
    ):
        assert m.term_admitted(mutant, NOW, TERM_FACTS) is False
        assert m.kill_admitted(mutant, KILL_NOW, SENT, KILL_FACTS) is False
        rec = Recorder()
        out = m.attempt_term_no_signal(
            mutant, NOW, TERM_FACTS, m.begin_ledger(), rec, FIXTURE
        )
        assert rec.calls == []
        assert out["term_attempts"] == 0
        assert out["signals_closed"] is True


def test_fake_term_event_does_not_allow_kill_in_different_ledger():
    m = module()
    p = policy(m)
    event_recorder = Recorder()
    authorized = m.attempt_term_no_signal(
        p, NOW, TERM_FACTS, m.begin_ledger(), event_recorder, FIXTURE
    )
    assert authorized["term_sent_at_ms"] == SENT
    forged = dict(authorized)
    kill_recorder = Recorder()
    wrong = m.attempt_kill_no_signal(
        p, KILL_NOW, SENT, KILL_FACTS, forged, kill_recorder, FIXTURE
    )
    assert kill_recorder.calls == []
    assert wrong["kill_attempts"] == 0
    assert wrong["signals_closed"] is True
    # The legitimate event is still permitted exactly once.
    live = m.attempt_kill_no_signal(
        p, KILL_NOW, SENT, KILL_FACTS, authorized, kill_recorder, FIXTURE
    )
    assert live["kill_attempts"] == 1
    assert kill_recorder.calls == [("KILL", FIXTURE)]


def test_mode_flag_wrong_types_are_not_truthy_authority():
    m = module()
    for bad in (None, 0, 1, "true", [], {}, ()):
        assert m.t01_mode_admitted(
            "escalate-positive", orphan_preflight_proven=bad
        ) is False
    assert m.t01_mode_admitted(
        "escalate-positive", orphan_preflight_proven=True
    ) is True
