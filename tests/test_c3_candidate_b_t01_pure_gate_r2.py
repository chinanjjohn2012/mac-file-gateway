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

def test_ledger_public_methods_cannot_forge_a_simulated_term_event():
    """P2-01: public mutating helpers must NOT exist on a returned Ledger."""
    m = module()
    ledger = m.begin_ledger()
    assert ledger["term_attempts"] == 0
    assert ledger["term_succeeded"] is False
    for forbidden in ("_set", "_mark_term_event", "_term_event_recorded"):
        assert not hasattr(ledger, forbidden), forbidden
    with pytest.raises(AttributeError):
        ledger._set(
            term_attempts=1, term_succeeded=True,
            term_sent_at_ms=SENT, term_target_ref=FIXTURE,
        )
    with pytest.raises(AttributeError):
        ledger._mark_term_event()
    with pytest.raises((TypeError, AttributeError)):
        ledger["term_succeeded"] = True
    with pytest.raises(AttributeError):
        ledger.signals_closed = False
    with pytest.raises(AttributeError):
        ledger._Ledger__snapshot = object()
    assert ledger["term_attempts"] == 0
    assert ledger["term_succeeded"] is False

    # Caller-supplied public flags never create private event provenance.
    forged = {**dict(ledger), "term_attempts": 1,
              "term_succeeded": True, "term_sent_at_ms": SENT,
              "term_target_ref": FIXTURE}
    recorder = Recorder()
    denied = m.attempt_kill_no_signal(
        policy(m), KILL_NOW, SENT, KILL_FACTS, forged, recorder, FIXTURE
    )
    assert recorder.calls == []
    assert denied["kill_attempts"] == 0
    assert denied["signals_closed"] is True

    # The original unspent Ledger has no event either; a KILL attempt
    # must fail even though the public dict had every expected value.
    direct = Recorder()
    denied_original = m.attempt_kill_no_signal(
        policy(m), KILL_NOW, SENT, KILL_FACTS, ledger, direct, FIXTURE
    )
    assert direct.calls == []
    assert denied_original["kill_attempts"] == 0
    assert denied_original["signals_closed"] is True
    retry_term = Recorder()
    m.attempt_term_no_signal(
        policy(m), NOW, TERM_FACTS, denied_original, retry_term, FIXTURE
    )
    assert retry_term.calls == []


def test_ledger_no_public_reopen_after_first_fake_kill():
    """P2-01: closed authority + an old alias cannot send twice."""
    m = module()
    p = policy(m)
    recorder = Recorder()
    ledger = m.begin_ledger()
    alias_before_term = ledger
    result = m.attempt_term_no_signal(
        p, NOW, TERM_FACTS, ledger, recorder, FIXTURE
    )
    assert result is alias_before_term
    result = m.attempt_kill_no_signal(
        p, KILL_NOW, SENT, KILL_FACTS, result, recorder, FIXTURE
    )
    assert result["kill_attempts"] == 1
    assert result["signals_closed"] is True
    assert recorder.calls == [("TERM", FIXTURE), ("KILL", FIXTURE)]
    with pytest.raises(AttributeError):
        result._set(signals_closed=False, kill_attempts=0)
    with pytest.raises(AttributeError):
        result.signals_closed = False
    with pytest.raises((TypeError, AttributeError)):
        result["kill_attempts"] = 0
    with pytest.raises(AttributeError):
        del result._Ledger__snapshot

    # Reusing any prior alias and providing otherwise valid evidence
    # must not revive TERM or KILL after SIGNALS_CLOSED.
    more = Recorder()
    replay = m.attempt_kill_no_signal(
        p, KILL_NOW, SENT, KILL_FACTS, alias_before_term, more, FIXTURE
    )
    m.attempt_term_no_signal(
        p, NOW, TERM_FACTS, alias_before_term, more, FIXTURE
    )
    assert replay["kill_attempts"] == 1
    assert replay["signals_closed"] is True
    assert more.calls == []
    assert recorder.calls == [("TERM", FIXTURE), ("KILL", FIXTURE)]


def test_original_deadline_cannot_be_rebased_with_self_consistent_new_policy():
    """P2-02 exact reviewer counterexample: t=112100 after old outer."""
    m = module()
    original = policy(m)  # original outer=112000, kill cutoff=109000
    recorder_term = Recorder()
    ledger = m.attempt_term_no_signal(
        original, NOW, TERM_FACTS,
        m.begin_ledger(), recorder_term, FIXTURE
    )
    assert recorder_term.calls == [("TERM", FIXTURE)]
    assert ledger["term_sent_at_ms"] == SENT
    assert ledger["signals_closed"] is False

    # p1 is entirely valid as a *separate* policy. The standalone
    # predicate must be true, isolating missing event-to-policy binding.
    rebased = m.derive_cutoffs(107_000, 12_000, 3_000, 200, 300)
    assert rebased["outer_deadline_ms"] == 119_000
    assert rebased["kill_cutoff_ms"] == 116_000
    assert m.kill_admitted(rebased, 112_100, SENT, KILL_FACTS) is True
    assert 112_100 > original["outer_deadline_ms"]
    kill_recorder = Recorder()
    refused = m.attempt_kill_no_signal(
        rebased, 112_100, SENT, KILL_FACTS, ledger, kill_recorder, FIXTURE
    )
    assert kill_recorder.calls == []
    assert refused["kill_attempts"] == 0
    assert refused["signals_closed"] is True
    retry = Recorder()
    m.attempt_kill_no_signal(
        original, KILL_NOW, SENT, KILL_FACTS, refused, retry, FIXTURE
    )
    assert retry.calls == []


@pytest.mark.parametrize("variant", (
    (107_000, 12_000, 3_000, 200, 300),
    (100_000, 12_001, 3_000, 200, 300),
    (100_000, 12_000, 2_000, 200, 300),
    (100_000, 12_000, 3_000, 201, 300),
    (100_000, 12_000, 3_000, 200, 301),
))
def test_simulated_term_binds_all_original_policy_fields(variant):
    """Changing any of the seven complete cutoff fields is a hard refusal."""
    m = module()
    original = policy(m)
    first = Recorder()
    ledger = m.attempt_term_no_signal(
        original, NOW, TERM_FACTS, m.begin_ledger(), first, FIXTURE
    )
    assert first.calls == [("TERM", FIXTURE)]
    foreign = m.derive_cutoffs(*variant)
    assert foreign != original
    assert m.kill_admitted(foreign, KILL_NOW, SENT, KILL_FACTS) is True
    kill_recorder = Recorder()
    refused = m.attempt_kill_no_signal(
        foreign, KILL_NOW, SENT, KILL_FACTS, ledger, kill_recorder, FIXTURE
    )
    assert kill_recorder.calls == []
    assert refused["kill_attempts"] == 0
    assert refused["signals_closed"] is True
    later = Recorder()
    m.attempt_kill_no_signal(
        original, KILL_NOW, SENT, KILL_FACTS, refused, later, FIXTURE
    )
    assert later.calls == []


def test_caller_mutation_of_same_policy_dict_cannot_reset_term_deadline():
    """The stored policy is an immutable VALUE snapshot, not a dict alias."""
    m = module()
    mutable = policy(m)
    term = Recorder()
    ledger = m.attempt_term_no_signal(
        mutable, NOW, TERM_FACTS, m.begin_ledger(), term, FIXTURE
    )
    assert term.calls == [("TERM", FIXTURE)]
    mutable.update(m.derive_cutoffs(107_000, 12_000, 3_000, 200, 300))
    assert m.kill_admitted(mutable, 112_100, SENT, KILL_FACTS) is True
    recorder = Recorder()
    refused = m.attempt_kill_no_signal(
        mutable, 112_100, SENT, KILL_FACTS, ledger, recorder, FIXTURE
    )
    assert recorder.calls == []
    assert refused["kill_attempts"] == 0
    assert refused["signals_closed"] is True


def test_value_identical_policy_copy_still_allows_one_simulated_kill():
    """Matching policy VALUES, not Python dictionary identity, are required."""
    m = module()
    original = policy(m)
    recorder = Recorder()
    ledger = m.attempt_term_no_signal(
        original, NOW, TERM_FACTS, m.begin_ledger(), recorder, FIXTURE
    )
    equal_copy = dict(original)
    assert equal_copy == original and equal_copy is not original
    after = m.attempt_kill_no_signal(
        equal_copy, KILL_NOW, SENT, KILL_FACTS, ledger, recorder, FIXTURE
    )
    assert after["kill_attempts"] == 1
    assert after["kill_succeeded"] is True
    assert after["signals_closed"] is True
    assert recorder.calls == [("TERM", FIXTURE), ("KILL", FIXTURE)]

