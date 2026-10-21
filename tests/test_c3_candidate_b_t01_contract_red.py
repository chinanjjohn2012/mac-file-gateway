"""B03-T01-R1 contractual RED: signal-free gates and mutation interceptors.

Frozen design: PR #37 @ 30c74b50d12e9d5763054da48be1d612b4b9fc02.
No Darwin processes, group signals, shell, native helper, or real numeric
PID/PGID are used. The T01 pure gate module is deliberately ABSENT at R1.
All unit-contract failures must therefore be genuine missing-implementation
RED, never skipped, xfailed, or converted into false GREEN.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DESIGN = ROOT / "docs/research/phase2-lite-c3/candidate-b-b03-t01-gate-design.md"
FROZEN_R1 = ROOT / "tests/test_c3_candidate_b_kill.py"
GATE = ROOT / "tools/research/c3_candidate_b_kill_t01_gate.py"
NATIVE = ROOT / "tools/research/c3_candidate_b_kill.c"
RUNNER = ROOT / "tools/research/run_c3_candidate_b_kill.py"
WORKFLOW = ROOT / ".github/workflows/c3-candidate-b-t01-contract-red.yml"

# Deliberately an opaque nonnumeric label; never pass a host PID or PGID.
OWNED_REF = "fixture:synthetic-owned-anchor-group-T01"
T0_MS = 100_000
OUTER_BUDGET_MS = 12_000
CLEANUP_RESERVE_MS = 3_000
TERM_GRACE_MS = 200
KILL_ENTRY_MARGIN_MS = 300
OUTER_DEADLINE_MS = 112_000
KILL_CUTOFF_MS = 109_000
TERM_CUTOFF_MS = 108_500
TERM_NOW_MS = 108_000
TERM_SENT_AT_MS = 108_000
GRACE_END_MS = 108_200
KILL_NOW_MS = 108_300

# Boolean *claims* about native evidence. They are test fixtures, not evidence
# of actual Darwin identity. Native implementation must independently prove
# these claims before any signal-capable path can be enabled at later R2/R3.
TERM_FACTS = {
    "private_root_owned_0700": True,
    "owner_unique_signal_authority": True,
    "owner_outside_anchor_group": True,
    "anchor_exact_spawn_child": True,
    "anchor_unreaped_live": True,
    "anchor_pid_equals_pgid": True,
    "anchor_sid_and_ppid_match": True,
    "anchor_sigterm_ign_ready": True,
    "controller_exact_spawn_child": True,
    "controller_self_led_outside_group": True,
    "controller_live_and_same_sid": True,
    "worker_controller_child": True,
    "worker_armed": True,
    "worker_joined_anchor_pgid": True,
    "worker_term_resistant_native": True,
    "trusted_ipc_writer_isolated": True,
    "kernel_identity_fresh": True,
}
KILL_FACTS = {
    **TERM_FACTS,
    "anchor_sigterm_ign_after_term": True,
    "anchor_post_term_seq_new": True,
    "anchor_live_after_grace": True,
    "anchor_wait_not_consumed": True,
    "controller_live_after_grace": True,
    "controller_self_group_rechecked": True,
    "worker_live_after_grace": True,
    "worker_parent_pgid_sid_rechecked": True,
    "native_entry_identity_fresh": True,
}
ERRORS = ("ESRCH", "EPERM", "EINTR")


def t01_module():
    """Only future pure Python gate code, never a native-run executable."""
    assert GATE.is_file(), (
        "EXPECTED RED: B03-T01 pure gate implementation is missing; "
        "do not create a fake module or skip this contract"
    )
    spec = importlib.util.spec_from_file_location("b03_t01_gate", GATE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def freeze_r1():
    assert FROZEN_R1.is_file()
    spec = importlib.util.spec_from_file_location("b03_original_r1_red", FROZEN_R1)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def cutoffs(m):
    return m.derive_cutoffs(
        T0_MS, OUTER_BUDGET_MS, CLEANUP_RESERVE_MS,
        TERM_GRACE_MS, KILL_ENTRY_MARGIN_MS,
    )


class NoSignalRecorder:
    """Test-only transport; cannot operate on any real numeric host PID/PGID."""

    def __init__(self, response="OK"):
        self.response = response
        self.calls = []

    def send(self, action, target_ref):
        assert action in ("TERM", "KILL"), "unexpected simulated action"
        assert target_ref == OWNED_REF, "signal target was not enrolled fixture"
        assert not isinstance(target_ref, int), "host PID/PGID is prohibited"
        self.calls.append((action, target_ref))
        return self.response


def test_t01_r1_no_native_execution_surface():
    assert DESIGN.is_file()
    assert FROZEN_R1.is_file()
    assert WORKFLOW.is_file()
    assert not NATIVE.exists(), "T01-R1 must not add a live B03 group helper"
    assert not RUNNER.exists(), "T01-R1 must not add a native-run driver"
    assert not GATE.exists(), "T01-R1 pure gate is intentionally not implemented"
    assert "POSITIVE_EXPERIMENT" in DESIGN.read_text(encoding="utf-8")


def test_t01_r1_frozen_b03_schemas_stay_untouched():
    f = freeze_r1()
    assert len(f.MODES) == 11 and f.MODES[0] == "escalate-positive"
    assert f.PENDING_CONTAINMENT == (
        "controller-loss-before-worker-wait",
        "controller-lost-after-term",
        "known-descendant-observation",
    )
    assert set(f.NO_SIGNAL_MUTATIONS) == {
        "omit-anchor-kill-gate", "omit-controller-kill-gate",
        "omit-controller-own-pgid", "omit-kill-cutoff", "allow-second-kill",
    }
    assert "worker_result" in f.ENUM_FIELDS
    assert "controller_final_trusted" in f.BOOL_FIELDS


def test_t01_r1_workflow_is_signal_free_and_uses_real_red_exit_status():
    wf = WORKFLOW.read_text(encoding="utf-8")
    for required in (
        "macos-15", "ubuntu-latest", '"3.13"', '"3.14"',
        "persist-credentials: false", "T01-R1", "MANIFEST.sha256",
        "tests/test_c3_candidate_b_t01_contract_red.py",
    ):
        assert required in wf, required
    assert "|| true" not in wf and "continue-on-error:" not in wf
    assert "pytest -q tests/test_c3_candidate_b_t01_contract_red.py" in wf
    assert "run_c3_candidate_b_kill.py --evidence-dir" not in wf
    assert "kill -9" not in wf and "killpg" not in wf


def test_t01_deadline_frozen_absolute_values_and_not_rebased():
    m = t01_module()  # expected RED until independent R2 implementation
    p = cutoffs(m)
    assert p == {
        "t0_ms": T0_MS,
        "outer_deadline_ms": OUTER_DEADLINE_MS,
        "kill_cutoff_ms": KILL_CUTOFF_MS,
        "term_cutoff_ms": TERM_CUTOFF_MS,
        "cleanup_reserve_ms": CLEANUP_RESERVE_MS,
        "term_grace_ms": TERM_GRACE_MS,
        "kill_entry_margin_ms": KILL_ENTRY_MARGIN_MS,
    }
    assert m.term_admitted(p, TERM_NOW_MS, TERM_FACTS)
    assert m.kill_admitted(p, KILL_NOW_MS, TERM_SENT_AT_MS, KILL_FACTS)


@pytest.mark.parametrize("param", ("outer_budget", "reserve", "grace", "margin"))
def test_t01_nonpositive_or_unsatisfiable_time_budget_is_refused(param):
    m = t01_module()
    data = [T0_MS, OUTER_BUDGET_MS, CLEANUP_RESERVE_MS,
            TERM_GRACE_MS, KILL_ENTRY_MARGIN_MS]
    slot = {"outer_budget": 1, "reserve": 2, "grace": 3, "margin": 4}[param]
    data[slot] = 0
    with pytest.raises(ValueError):
        m.derive_cutoffs(*data)
    data[slot] = -1
    with pytest.raises(ValueError):
        m.derive_cutoffs(*data)
    if param == "reserve":
        data = [T0_MS, 200, 200, 100, 100]
        with pytest.raises(ValueError):
            m.derive_cutoffs(*data)


@pytest.mark.parametrize("now", (
    TERM_CUTOFF_MS, TERM_CUTOFF_MS + 1, KILL_CUTOFF_MS,
    OUTER_DEADLINE_MS, OUTER_DEADLINE_MS + 1,
))
def test_t01_term_cutoff_equality_and_late_entry_are_denied(now):
    m = t01_module()
    assert not m.term_admitted(cutoffs(m), now, TERM_FACTS)


@pytest.mark.parametrize("now,sent", (
    (GRACE_END_MS - 1, TERM_SENT_AT_MS),
    (KILL_CUTOFF_MS, TERM_SENT_AT_MS),
    (KILL_CUTOFF_MS + 1, TERM_SENT_AT_MS),
    (OUTER_DEADLINE_MS, TERM_SENT_AT_MS),
    (KILL_NOW_MS, KILL_CUTOFF_MS),  # fraudulent late TERM
))
def test_t01_kill_grace_and_cutoff_boundaries_are_denied(now, sent):
    m = t01_module()
    assert not m.kill_admitted(cutoffs(m), now, sent, KILL_FACTS)


def test_t01_term_eligibility_is_fail_closed_for_every_native_fact():
    m = t01_module()
    p = cutoffs(m)
    assert m.term_admitted(p, TERM_NOW_MS, TERM_FACTS)
    for key in TERM_FACTS:
        partial = {k: v for k, v in TERM_FACTS.items() if k != key}
        assert not m.term_admitted(p, TERM_NOW_MS, partial), key
        assert not m.term_admitted(p, TERM_NOW_MS,
                                   {**TERM_FACTS, key: False}), key
        assert not m.term_admitted(p, TERM_NOW_MS,
                                   {**TERM_FACTS, key: 1}), key


def test_t01_kill_eligibility_requires_fresh_held_lawful_parentage():
    m = t01_module()
    p = cutoffs(m)
    assert m.kill_admitted(p, KILL_NOW_MS, TERM_SENT_AT_MS, KILL_FACTS)
    for key in KILL_FACTS:
        assert not m.kill_admitted(p, KILL_NOW_MS, TERM_SENT_AT_MS,
                                   {k: v for k, v in KILL_FACTS.items()
                                    if k != key}), key
        assert not m.kill_admitted(p, KILL_NOW_MS, TERM_SENT_AT_MS,
                                   {**KILL_FACTS, key: False}), key
        assert not m.kill_admitted(p, KILL_NOW_MS, TERM_SENT_AT_MS,
                                   {**KILL_FACTS, key: 1}), key


def test_t01_native_witness_must_be_post_term_not_old_ready_or_note_exit():
    m = t01_module()
    p = cutoffs(m)
    for key in (
        "anchor_sigterm_ign_after_term", "anchor_post_term_seq_new",
        "anchor_live_after_grace", "anchor_wait_not_consumed",
        "controller_live_after_grace", "worker_live_after_grace",
        "native_entry_identity_fresh", "worker_parent_pgid_sid_rechecked",
    ):
        assert not m.kill_admitted(
            p, KILL_NOW_MS, TERM_SENT_AT_MS,
            {**KILL_FACTS, key: False},
        ), key


def test_t01_term_and_kill_attempts_have_distinct_no_signal_ledger():
    m = t01_module()
    recorder = NoSignalRecorder()
    ledger = m.begin_ledger()
    after_term = m.attempt_term_no_signal(
        cutoffs(m), TERM_NOW_MS, TERM_FACTS, ledger, recorder, OWNED_REF
    )
    assert recorder.calls == [("TERM", OWNED_REF)]
    assert after_term["term_attempts"] == 1
    assert after_term["term_succeeded"] is True
    assert after_term["kill_attempts"] == 0
    assert after_term["signals_closed"] is False
    after_kill = m.attempt_kill_no_signal(
        cutoffs(m), KILL_NOW_MS, TERM_SENT_AT_MS, KILL_FACTS,
        after_term, recorder, OWNED_REF
    )
    assert recorder.calls == [("TERM", OWNED_REF), ("KILL", OWNED_REF)]
    assert after_kill["kill_attempts"] == 1
    assert after_kill["kill_succeeded"] is True
    assert after_kill["signals_closed"] is True
    again = m.attempt_kill_no_signal(
        cutoffs(m), KILL_NOW_MS, TERM_SENT_AT_MS, KILL_FACTS,
        after_kill, recorder, OWNED_REF
    )
    assert again["kill_attempts"] == 1
    assert recorder.calls == [("TERM", OWNED_REF), ("KILL", OWNED_REF)]


@pytest.mark.parametrize("errno", ERRORS)
def test_t01_no_signal_errno_failures_close_authority_without_retry(errno):
    m = t01_module()
    ledger = m.begin_ledger()
    term = NoSignalRecorder(response="OK")
    ledger = m.attempt_term_no_signal(
        cutoffs(m), TERM_NOW_MS, TERM_FACTS, ledger, term, OWNED_REF
    )
    failed_kill = NoSignalRecorder(response=errno)
    after = m.attempt_kill_no_signal(
        cutoffs(m), KILL_NOW_MS, TERM_SENT_AT_MS, KILL_FACTS,
        ledger, failed_kill, OWNED_REF
    )
    assert failed_kill.calls == [("KILL", OWNED_REF)]
    assert after["kill_attempts"] == 1
    assert after["kill_succeeded"] is False
    assert after["signals_closed"] is True
    assert after["kill_errno_class"] == errno
    next_record = m.attempt_kill_no_signal(
        cutoffs(m), KILL_NOW_MS, TERM_SENT_AT_MS, KILL_FACTS,
        after, failed_kill, OWNED_REF
    )
    assert next_record["kill_attempts"] == 1
    assert failed_kill.calls == [("KILL", OWNED_REF)]


def test_t01_term_failure_never_proceeds_to_kill_or_retries():
    m = t01_module()
    recorder = NoSignalRecorder(response="ESRCH")
    after = m.attempt_term_no_signal(
        cutoffs(m), TERM_NOW_MS, TERM_FACTS,
        m.begin_ledger(), recorder, OWNED_REF
    )
    assert after["term_attempts"] == 1
    assert after["term_succeeded"] is False
    assert after["kill_attempts"] == 0
    assert after["signals_closed"] is True
    after = m.attempt_kill_no_signal(
        cutoffs(m), KILL_NOW_MS, TERM_SENT_AT_MS, KILL_FACTS,
        after, recorder, OWNED_REF
    )
    assert after["kill_attempts"] == 0
    assert recorder.calls == [("TERM", OWNED_REF)]


@pytest.mark.parametrize("mutant", (
    "omit-anchor-kill-gate", "omit-controller-kill-gate",
    "omit-controller-own-pgid", "omit-kill-cutoff", "allow-second-kill",
    "omit-anchor-post-term-witness", "omit-worker-parent-proof",
    "forge-controller-final", "omit-private-root-ownership",
))
def test_t01_mutant_cannot_reach_even_a_no_signal_stub(mutant):
    """If implementation bypasses admission, stub records it: test FAILS."""
    m = t01_module()
    proof = dict(KILL_FACTS)
    policy = cutoffs(m)
    now = KILL_NOW_MS
    if mutant == "omit-anchor-kill-gate":
        proof["anchor_live_after_grace"] = False
    elif mutant == "omit-controller-kill-gate":
        proof["controller_live_after_grace"] = False
    elif mutant == "omit-controller-own-pgid":
        proof["controller_self_group_rechecked"] = False
    elif mutant == "omit-kill-cutoff":
        now = KILL_CUTOFF_MS
    elif mutant == "omit-anchor-post-term-witness":
        proof["anchor_post_term_seq_new"] = False
    elif mutant == "omit-worker-parent-proof":
        proof["worker_parent_pgid_sid_rechecked"] = False
    elif mutant == "forge-controller-final":
        proof["trusted_ipc_writer_isolated"] = False
    elif mutant == "omit-private-root-ownership":
        proof["private_root_owned_0700"] = False
    ledger = m.begin_ledger()
    ledger = {**ledger, "term_attempts": 1, "term_succeeded": True}
    if mutant == "allow-second-kill":
        ledger.update(kill_attempts=1, kill_succeeded=True,
                      signals_closed=True)
    stub = NoSignalRecorder()
    out = m.attempt_kill_no_signal(
        policy, now, TERM_SENT_AT_MS, proof, ledger, stub, OWNED_REF
    )
    assert out["signals_closed"] is True
    assert stub.calls == [], "BYPASS REACHED NO-SIGNAL TRANSPORT"
    assert out["kill_attempts"] == ledger["kill_attempts"]


def test_t01_kill_success_without_lawful_wait_is_never_verified():
    m, frozen = t01_module(), freeze_r1()
    record = frozen.fixed("escalate-positive")
    assert m.classify_t01(record) == "POSITIVE_EXPERIMENT"
    for changed in (
        {"controller_waited_worker": 0},
        {"controller_final_trusted": 0},
        {"worker_result": "UNKNOWN"},
        {"anchor_sigkill_observed": 0},
        {"anchor_reaped": 0},
        {"owner_children_reaped": 0},
        {"owner_fds_closed": 0},
        {"controller_worker_fds_closed": 0},
        {"cleanup": "UNRESOLVED"},
        {"positive_kill_margin": 0},
        {"signals_closed": 0},
        {"group_signals_after_close": 1},
        {"reuse_proven": 1},
        {"g2_qualified": 1},
    ):
        assert m.classify_t01({**record, **changed}) == "BLOCK"
    for key in frozen.BOOL_FIELDS + frozen.ENUM_FIELDS:
        assert m.classify_t01({k: v for k, v in record.items()
                               if k != key}) == "BLOCK", key
    assert m.classify_t01({**record, "worker_result": "KILL_SENT"}) == "BLOCK"
    assert m.classify_t01({**record, "anchor_result": "NOTE_EXIT"}) == "BLOCK"
    assert m.classify_t01({**record, "unknown_field": 1}) == "BLOCK"


def test_t01_orphan_modes_never_gain_admission_from_t01_positive():
    m, frozen = t01_module(), freeze_r1()
    for mode in frozen.PENDING_CONTAINMENT:
        assert m.t01_mode_admitted(mode, orphan_preflight_proven=False) is False
        assert m.t01_mode_admitted(mode, orphan_preflight_proven=True) is False
    assert m.t01_mode_admitted("escalate-positive",
                              orphan_preflight_proven=False) is True
    assert m.t01_mode_admitted("kill-canary-isolation",
                              orphan_preflight_proven=True) is False
