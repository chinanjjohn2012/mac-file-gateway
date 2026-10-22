"""C3 Candidate B T01-R2b-R1 native contract RED; NO real group signal.

Shared forward-compatible contract. R1 *workflow*, not shared pytest, checks
native C/adapter absent. Behavior tests stay usable by a later approved R2
no-signal-only implementation: never mark them xfail or skip.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
import secrets
import subprocess

import pytest

from test_c3_candidate_b_kill import MODES, PENDING_CONTAINMENT

ROOT = Path(__file__).resolve().parents[1]
DESIGN = ROOT / "docs/research/phase2-lite-c3/candidate-b-b03-t01-r2b-native-admission-design.md"
CONTRACT = ROOT / "docs/research/phase2-lite-c3/candidate-b-b03-t01-r2b-r1-contract.md"
HEADER = ROOT / "tests/native/c3_b03_t01_no_signal_contract.h"
WORKFLOW = ROOT / ".github/workflows/c3-candidate-b-t01-r2b-r1-contract-red.yml"
NATIVE = ROOT / "tools/research/c3_candidate_b_kill.c"
PROBE = ROOT / "tools/research/c3_candidate_b_kill_t01_no_signal_probe.py"
TARGET = "fixture:synthetic-owned-anchor-group-T01"

FIRST_T0 = 100_000
FIRST_BUDGET = 12_000
FIRST_RESERVE = 3_000
FIRST_GRACE = 200
FIRST_MARGIN = 300
FIRST_TERM = 108_000
FIRST_KILL = 108_300

TERM_DENIALS = (
    "root-unsafe",
    "anchor-not-direct-owned-child",
    "anchor-exited",
    "anchor-reaped-or-wait-consumed",
    "anchor-pid-pgid-mismatch",
    "anchor-sid-ppid-drift",
    "anchor-initial-sigterm-ignore-missing",
    "controller-in-anchor-group",
    "controller-not-owned-child",
    "worker-not-controller-child",
    "worker-not-armed",
    "worker-not-in-anchor-group",
    "worker-term-resistant-unproven",
    "ipc-writer-spoofed",
    "term-cutoff-equal",
    "term-cutoff-late",
)
KILL_DENIALS = (
    "anchor-post-term-ignore-missing",
    "anchor-post-term-sequence-stale",
    "anchor-early-exit",
    "anchor-reaped-before-kill",
    "anchor-identity-reused",
    "controller-not-live-after-grace",
    "controller-entered-anchor-group",
    "controller-lost-worker-wait",
    "worker-parent-changed",
    "worker-pgid-changed",
    "worker-exited-during-grace",
    "native-identity-recheck-missing",
    "ipc-post-term-forged",
    "grace-not-finished",
    "kill-cutoff-equal",
    "kill-cutoff-late",
    "late-term-with-finished-grace",
    "rebase-original-policy",
    "incorrect-term-timestamp",
    "forged-successful-term-ledger",
    "kill-without-term",
)
SIGNAL_FAILURES = (
    ("term", "EINTR"), ("term", "ESRCH"), ("term", "EPERM"),
    ("kill", "EINTR"), ("kill", "ESRCH"), ("kill", "EPERM"),
)
EVIDENCE_DENIALS = (
    "worker-wait-not-by-controller",
    "anchor-wait-not-by-owner",
    "controller-final-forged",
    "controller-final-missing",
    "fd-close-unproven",
    "outer-deadline-exceeded",
    "only-note-exit-observed",
    "worker-wait-unknown",
)
TERM_GATE_MUTANTS = (
    "omit-anchor-term-ignore",
    "omit-controller-outside-group",
    "omit-worker-legal-parent",
    "omit-worker-group-check",
)
KILL_GATE_MUTANTS = (
    "omit-anchor-post-term-witness",
    "omit-anchor-reap-check",
    "omit-controller-live-check",
    "omit-kill-cutoff",
    "omit-grace",
    "allow-policy-rebase",
)
REPLAY_MUTANTS = ("allow-second-term", "allow-second-kill")
GATE_MUTANTS = TERM_GATE_MUTANTS + KILL_GATE_MUTANTS + REPLAY_MUTANTS
EVIDENCE_MUTANTS = ("accept-fake-final", "ignore-fd-close")

# Immutable 1-based native test scenario IDs, NOT runtime-selected mutants.
# Adapter converts these strictly-validated (phase, fault) pairs into the
# C header's scenario_fault_id. The C ABI has NO generic string/PID channel.
FAULT_CATALOG = (
    tuple(("TERM", fault) for fault in TERM_DENIALS)
    + tuple(("KILL", fault) for fault in KILL_DENIALS)
    + tuple(("ERRNO", phase + "-" + err) for phase, err in SIGNAL_FAILURES)
    + tuple(("EVIDENCE", fault) for fault in EVIDENCE_DENIALS)
    + tuple(("MUTATION", fault) for fault in GATE_MUTANTS)
    + tuple(("EVIDENCE_MUTATION", fault) for fault in EVIDENCE_MUTANTS)
    + (("MODE", "different-mode"), ("KILL", "nominal-synthetic"))
)
FAULT_IDS = {item: i for i, item in enumerate(FAULT_CATALOG, 1)}
assert len(FAULT_CATALOG) == len(FAULT_IDS) == 67

REQUEST_FIELDS = frozenset((
    "abi_version", "mode", "fixture_target", "phase", "fault",
    "nonce", "original_policy", "attempt_policy", "now_ms",
    "term_sent_at_ms", "mock_only", "attempt_sequence",
))
POLICY_FIELDS = frozenset((
    "t0_ms", "outer_budget_ms", "cleanup_reserve_ms",
    "term_grace_ms", "kill_entry_margin_ms", "outer_deadline_ms",
    "kill_cutoff_ms", "term_cutoff_ms",
))
_ISSUED_NONCES = set()


def fresh_nonce() -> int:
    """A fresh nonzero uint64 per distinct scenario in this test process.

    The value is not a credential or a kernel process identifier. Intentional
    replay tests copy the same nonce to the SAME adapter instance.
    """
    for _ in range(64):
        n = secrets.randbits(64)
        if n and n not in _ISSUED_NONCES:
            _ISSUED_NONCES.add(n)
            return n
    raise AssertionError("test-only nonce issuer exhausted")


def steps_for(phase: str, fault: str) -> tuple[str, ...]:
    """Native ABI's at-most-3 operations on ONE synthetic ledger."""
    if phase in {"TERM", "MODE"}:
        return ("TERM",)
    if phase == "ERRNO" and fault.startswith("term-"):
        return ("TERM",)
    if phase == "MUTATION":
        if fault in TERM_GATE_MUTANTS:
            return ("TERM",)
        if fault == "allow-second-term":
            return ("TERM", "TERM")
        if fault == "allow-second-kill":
            return ("TERM", "KILL", "KILL")
    return ("TERM", "KILL")



def policy(*, t0=FIRST_T0, outer=FIRST_BUDGET, reserve=FIRST_RESERVE,
           grace=FIRST_GRACE, margin=FIRST_MARGIN) -> dict:
    kill_cutoff = t0 + outer - reserve
    return {
        "t0_ms": t0,
        "outer_budget_ms": outer,
        "cleanup_reserve_ms": reserve,
        "term_grace_ms": grace,
        "kill_entry_margin_ms": margin,
        "outer_deadline_ms": t0 + outer,
        "kill_cutoff_ms": kill_cutoff,
        "term_cutoff_ms": kill_cutoff - grace - margin,
    }


def case(phase: str, fault: str, *, now: int | None = None, original=None,
         replacement=None) -> dict:
    assert (phase, fault) in FAULT_IDS, "only frozen test scenarios allowed"
    p = policy() if original is None else dict(original)
    return {
        "abi_version": 1,
        "mode": "escalate-positive",
        "fixture_target": TARGET,
        "phase": phase,
        "fault": fault,
        "nonce": fresh_nonce(),
        "original_policy": p,
        "attempt_policy": dict(p if replacement is None else replacement),
        "now_ms": (FIRST_TERM if phase == "TERM" else FIRST_KILL)
        if now is None else now,
        "term_sent_at_ms": FIRST_TERM,
        "mock_only": True,
        "attempt_sequence": steps_for(phase, fault),
    }


def probe():
    # R1 RED due solely to missing native no-signal implementation/adapter;
    # R1-specific CI already checks neither exists. NO compile/load/run now.
    assert NATIVE.is_file(), (
        "EXPECTED RED: R2b Native C Helper absent; no group signal allowed"
    )
    assert PROBE.is_file(), (
        "EXPECTED RED: R2b no-signal C contract adapter absent"
    )
    spec = importlib.util.spec_from_file_location("c3_t01_native_stub", PROBE)
    assert spec and spec.loader
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    assert m.C3B03_TEST_NO_SIGNAL_STUB is True
    assert m.NATIVE_SOURCE_REL == "tools/research/c3_candidate_b_kill.c"
    assert m.TEST_ABI_HEADER_REL == (
        "tests/native/c3_b03_t01_no_signal_contract.h"
    )
    assert callable(m.run_no_signal_case)
    return m


def check_no_signal(result: object, request: dict) -> dict:
    assert type(result) is dict
    assert set(result) == {
        "abi_version", "nonce", "stub_mode", "synthetic_only",
        "real_group_signal_syscalls", "fake_term_transport_calls",
        "fake_kill_transport_calls", "term_attempts", "kill_attempts",
        "signals_closed", "group_signals_after_close",
        "decision", "cleanup", "worker_lawful_wait",
        "anchor_lawful_wait", "reuse_proven", "g2_qualified",
        "mutation_detected", "c_adapter_dispatches",
    }
    assert type(result["abi_version"]) is int and result["abi_version"] == 1
    raw_nonce = request.get("nonce") if type(request) is dict else None
    expected_nonce = (
        raw_nonce if type(raw_nonce) is int and 0 < raw_nonce < (1 << 64)
        else 0
    )
    # Bad/missing/Boolean nonce is returned as canonical 0, not echoed
    # as True==1 or as a misleading live task identity.
    assert type(result["nonce"]) is int and result["nonce"] == expected_nonce
    assert result["stub_mode"] == "C3B03_TEST_NO_SIGNAL_STUB"
    for name in ("synthetic_only", "signals_closed", "worker_lawful_wait",
                 "anchor_lawful_wait", "reuse_proven", "g2_qualified",
                 "mutation_detected"):
        assert type(result[name]) is bool, name
    assert result["synthetic_only"] is True
    assert result["real_group_signal_syscalls"] == 0
    assert type(result["real_group_signal_syscalls"]) is int
    for key in ("fake_term_transport_calls", "fake_kill_transport_calls",
                "term_attempts", "kill_attempts", "group_signals_after_close"):
        assert type(result[key]) is int and result[key] >= 0, key
    assert result["fake_term_transport_calls"] <= 1
    assert result["fake_kill_transport_calls"] <= 1
    assert result["term_attempts"] <= 1
    assert result["kill_attempts"] <= 1
    assert result["group_signals_after_close"] == 0
    assert type(result["c_adapter_dispatches"]) is int
    assert 0 <= result["c_adapter_dispatches"] <= 1
    assert result["reuse_proven"] is False
    assert result["g2_qualified"] is False
    # Synthetic syscalls never provide actual lawful waitpid or VERIFIED.
    assert result["worker_lawful_wait"] is False
    assert result["anchor_lawful_wait"] is False
    assert result["cleanup"] == "UNRESOLVED"
    assert result["decision"] in {"BLOCK", "SIMULATED_GATE_ONLY"}
    return result


def run_mock(request: dict, *, adapter=None, expected_dispatch=1) -> dict:
    """Keep the SAME loaded adapter for deliberate nonce replay tests."""
    module = probe() if adapter is None else adapter
    output = module.run_no_signal_case(request)
    result = check_no_signal(output, request)
    assert result["c_adapter_dispatches"] == expected_dispatch
    return result


def assert_input_rejected(request: dict, *, adapter=None) -> dict:
    r = run_mock(request, adapter=adapter, expected_dispatch=0)
    assert r["decision"] == "BLOCK"
    assert r["fake_term_transport_calls"] == 0
    assert r["fake_kill_transport_calls"] == 0
    assert r["term_attempts"] == 0
    assert r["kill_attempts"] == 0
    assert r["signals_closed"] is True
    assert r["group_signals_after_close"] == 0
    assert r["mutation_detected"] is False
    return r


def test_r2b_r1_contract_has_only_one_owned_fixture_and_frozen_modes():
    s = CONTRACT.read_text(encoding="utf-8")
    assert DESIGN.is_file()
    assert HEADER.is_file()
    assert len(MODES) == 11 and len(set(MODES)) == 11
    assert MODES[0] == "escalate-positive"
    assert PENDING_CONTAINMENT == (
        "controller-loss-before-worker-wait",
        "controller-lost-after-term",
        "known-descendant-observation",
    )
    for name in ("C3B03_TEST_NO_SIGNAL_STUB", "no kernel signal",
                 "Controller", "anchor", "worker",
                 "ORIGINAL_POLICY", "probe adapter",
                 "R2b-R1", "R2b-R2", "NOT_RUN/BLOCK"):
        assert name in s, name


def test_r2b_r1_c_header_compiles_without_linking_or_executing():
    # Declaration header only. The C compiler is never asked to link or run.
    code = (
        '#include "c3_b03_t01_no_signal_contract.h"\n'
        '_Static_assert(C3B03_T01_NO_SIGNAL_ABI_VERSION == 1, "ABI");\n'
        '_Static_assert(C3B03_T01_MAX_ATTEMPT_STEPS == 3, "steps");\n'
        '_Static_assert(C3B03_T01_MAX_SCENARIO_ID == 67, "scenarios");\n'
        'int contract_syntax(c3b03_t01_mock_input_t *in) {\n'
        '  c3b03_t01_mock_output_t out = {0};\n'
        '  return (int)in->original_policy.kill_cutoff_ms +\n'
        '         (int)in->attempt_sequence_len + (int)out.abi_version;\n'
        '}\n'
    )
    base_args = [
        "cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic",
        "-fsyntax-only", "-I", str(HEADER.parent), "-x", "c", "-",
    ]
    for value in ("1", None, "0", "2"):
        cmd = list(base_args)
        if value is not None:
            cmd.insert(6, "-DC3B03_TEST_NO_SIGNAL_STUB=" + value)
        compiled = subprocess.run(
            cmd, input=code, text=True, capture_output=True,
            timeout=15, check=False,
        )
        if value == "1":
            assert compiled.returncode == 0, compiled.stderr
        else:
            assert compiled.returncode != 0, (
                f"unsafe macro={value!r} unexpectedly accepted"
            )
            assert "C3B03_TEST_NO_SIGNAL_STUB must be exactly 1" in compiled.stderr


def test_r2b_r1_workflow_is_R1_only_and_never_launches_native_C():
    y = WORKFLOW.read_text(encoding="utf-8")
    for item in (
        "C3B03_T01_R2B_R1_CONTRACT_RED=true",
        "C3B03_T01_R2B_R1_REAL_GROUP_SIGNAL_AUTHORIZED=false",
        "test ! -e tools/research/c3_candidate_b_kill.c",
        "test ! -e tools/research/c3_candidate_b_kill_t01_no_signal_probe.py",
        "test ! -e tools/research/run_c3_candidate_b_kill.py",
        "tests/test_c3_candidate_b_t01_r2b_contract_red.py",
        "tests/native/c3_b03_t01_no_signal_contract.h",
        "MANIFEST.sha256", "persist-credentials: false",
    ):
        assert item in y, item
    assert "continue-on-error:" not in y
    assert "|| true" not in y
    assert "workflow_dispatch" not in y
    assert "kill -9" not in y
    assert "SIGKILL" not in y
    assert "cc -o " not in y


@pytest.mark.parametrize("fault", TERM_DENIALS, ids=TERM_DENIALS)
def test_no_signal_native_term_entry_refuses_faults(fault):
    p = policy()
    now = p["term_cutoff_ms"] if fault == "term-cutoff-equal" else (
        p["term_cutoff_ms"] + 1 if fault == "term-cutoff-late" else FIRST_TERM
    )
    r = run_mock(case("TERM", fault, now=now))
    assert r["decision"] == "BLOCK"
    assert r["fake_term_transport_calls"] == 0
    assert r["fake_kill_transport_calls"] == 0
    assert r["term_attempts"] == 0
    assert r["kill_attempts"] == 0
    assert r["signals_closed"] is True


@pytest.mark.parametrize("fault", KILL_DENIALS, ids=KILL_DENIALS)
def test_no_signal_native_kill_entry_refuses_faults_after_genuine_mock_term(fault):
    original = policy()
    override = None
    now = FIRST_KILL
    if fault == "kill-cutoff-equal":
        now = original["kill_cutoff_ms"]
    elif fault == "kill-cutoff-late":
        now = original["kill_cutoff_ms"] + 1
    elif fault == "late-term-with-finished-grace":
        now = 108_702  # grace ended at 108701; before cutoff 109000
    elif fault == "grace-not-finished":
        now = FIRST_TERM + FIRST_GRACE - 1
    elif fault == "rebase-original-policy":
        now = 112_100
        override = policy(t0=107_000)
        assert now > original["outer_deadline_ms"]
        assert now < override["kill_cutoff_ms"]
    q = case("KILL", fault, now=now, replacement=override)
    if fault == "late-term-with-finished-grace":
        q["term_sent_at_ms"] = 108_501  # after TERM cutoff 108500
        assert now - q["term_sent_at_ms"] > FIRST_GRACE
    r = run_mock(q)
    assert r["decision"] == "BLOCK"
    assert r["fake_kill_transport_calls"] == 0
    assert r["kill_attempts"] == 0
    # An impossible/late TERM cannot become a genuine recorder event.
    if fault in {
        "kill-without-term", "forged-successful-term-ledger",
        "late-term-with-finished-grace",
    }:
        assert r["fake_term_transport_calls"] == 0
    else:
        assert r["fake_term_transport_calls"] == 1
    assert r["signals_closed"] is True


@pytest.mark.parametrize("phase,error", SIGNAL_FAILURES,
                         ids=[a + "-" + b for a,b in SIGNAL_FAILURES])
def test_one_attempt_errno_does_not_retry_or_resume(phase, error):
    r = run_mock(case("ERRNO", f"{phase.lower()}-{error}"))
    assert r["decision"] == "BLOCK"
    assert r["fake_term_transport_calls"] == 1
    if phase == "term":
        assert r["term_attempts"] == 1
        assert r["fake_kill_transport_calls"] == 0
        assert r["kill_attempts"] == 0
    else:
        assert r["term_attempts"] == 1
        assert r["fake_kill_transport_calls"] == 1
        assert r["kill_attempts"] == 1
    assert r["signals_closed"] is True


@pytest.mark.parametrize("fault", EVIDENCE_DENIALS, ids=EVIDENCE_DENIALS)
def test_simulated_transport_never_forges_lawful_wait_or_cleanup(fault):
    r = run_mock(case("EVIDENCE", fault))
    assert r["fake_term_transport_calls"] == 1
    assert r["fake_kill_transport_calls"] == 1
    assert r["decision"] == "BLOCK"
    assert r["cleanup"] == "UNRESOLVED"
    assert r["signals_closed"] is True


@pytest.mark.parametrize("mutant", TERM_GATE_MUTANTS, ids=TERM_GATE_MUTANTS)
def test_term_gate_mutant_never_reaches_either_fake_transport(mutant):
    q = case("MUTATION", mutant)
    assert q["attempt_sequence"] == ("TERM",)
    r = run_mock(q)
    assert r["mutation_detected"] is True
    assert r["decision"] == "BLOCK"
    assert r["fake_term_transport_calls"] == 0
    assert r["fake_kill_transport_calls"] == 0
    assert r["term_attempts"] == 0
    assert r["kill_attempts"] == 0
    assert r["signals_closed"] is True


@pytest.mark.parametrize("mutant", KILL_GATE_MUTANTS, ids=KILL_GATE_MUTANTS)
def test_kill_gate_mutant_stops_after_exact_one_valid_fake_term(mutant):
    q = case("MUTATION", mutant)
    assert q["attempt_sequence"] == ("TERM", "KILL")
    r = run_mock(q)
    assert r["mutation_detected"] is True
    assert r["decision"] == "BLOCK"
    assert r["fake_term_transport_calls"] == 1
    assert r["term_attempts"] == 1
    assert r["fake_kill_transport_calls"] == 0
    assert r["kill_attempts"] == 0
    assert r["signals_closed"] is True


@pytest.mark.parametrize(
    "mutant,steps,expected_term,expected_kill",
    (
        ("allow-second-term", ("TERM", "TERM"), 1, 0),
        ("allow-second-kill", ("TERM", "KILL", "KILL"), 1, 1),
    ),
)
def test_repeat_signal_attempt_in_same_ledger_cannot_rearm(
    mutant, steps, expected_term, expected_kill,
):
    # One request -> one fresh nonce -> one owned ledger -> ordered attempts.
    q = case("MUTATION", mutant)
    assert q["attempt_sequence"] == steps
    r = run_mock(q)
    assert r["mutation_detected"] is True
    assert r["decision"] == "BLOCK"
    assert r["term_attempts"] == expected_term
    assert r["kill_attempts"] == expected_kill
    assert r["fake_term_transport_calls"] == expected_term
    assert r["fake_kill_transport_calls"] == expected_kill
    assert r["signals_closed"] is True
    assert r["group_signals_after_close"] == 0


@pytest.mark.parametrize("mutant", EVIDENCE_MUTANTS, ids=EVIDENCE_MUTANTS)
def test_post_signal_evidence_mutants_cannot_upgrade_cleanup(mutant):
    # FINAL and FD close happen after a simulated send, so these checks
    # must block VERIFIED but do not retroactively make the send ineligible.
    q = case("EVIDENCE_MUTATION", mutant)
    assert q["attempt_sequence"] == ("TERM", "KILL")
    r = run_mock(q)
    assert r["mutation_detected"] is True
    assert r["fake_term_transport_calls"] == 1
    assert r["term_attempts"] == 1
    assert r["fake_kill_transport_calls"] == 1
    assert r["kill_attempts"] == 1
    assert r["decision"] == "BLOCK"
    assert r["cleanup"] == "UNRESOLVED"
    assert r["signals_closed"] is True

@pytest.mark.parametrize("mode", MODES[1:], ids=MODES[1:])
def test_non_T01_modes_always_denied_even_if_orphan_preflight_true(mode):
    q = case("MODE", "different-mode")
    q["mode"] = mode
    r = run_mock(q, expected_dispatch=0)
    assert r["decision"] == "BLOCK"
    assert r["fake_term_transport_calls"] == 0
    assert r["fake_kill_transport_calls"] == 0


def test_positive_synthetic_gate_never_claims_native_wait_or_G2():
    r = run_mock(case("KILL", "nominal-synthetic"))
    assert r["fake_term_transport_calls"] == 1
    assert r["fake_kill_transport_calls"] == 1
    assert r["term_attempts"] == 1 and r["kill_attempts"] == 1
    assert r["decision"] == "SIMULATED_GATE_ONLY"
    assert r["signals_closed"] is True
    assert r["cleanup"] == "UNRESOLVED"


@pytest.mark.parametrize("t0,budget,reserve,grace,margin,term,kill_at", (
    (100_000, 12_000, 3_000, 200, 300, 108_000, 108_300),
    (230_000, 21_000, 6_000, 900, 600, 242_900, 244_000),
))
def test_t01_native_stub_uses_exact_original_monotonic_vector(
    t0,budget,reserve,grace,margin,term,kill_at,
):
    initial = policy(t0=t0,outer=budget,reserve=reserve,grace=grace,margin=margin)
    request = case("KILL", "nominal-synthetic", now=kill_at, original=initial)
    request["term_sent_at_ms"] = term
    r = run_mock(request)
    assert r["decision"] == "SIMULATED_GATE_ONLY"
    assert r["fake_term_transport_calls"] == 1
    assert r["fake_kill_transport_calls"] == 1
    assert r["signals_closed"] is True

def test_every_mock_task_has_fresh_nonzero_uint64_even_same_fault_and_vector():
    a = case("KILL", "nominal-synthetic")
    b = case("KILL", "nominal-synthetic")
    c = case(
        "KILL", "nominal-synthetic", now=244_000,
        original=policy(
            t0=230_000, outer=21_000, reserve=6_000, grace=900, margin=600
        ),
    )
    assert len({a["nonce"], b["nonce"], c["nonce"]}) == 3
    assert all(type(x["nonce"]) is int and 0 < x["nonce"] < (1 << 64)
               for x in (a, b, c))
    assert all(set(x) == REQUEST_FIELDS for x in (a, b, c))
    assert len(FAULT_IDS) == 67
    assert FAULT_IDS[("TERM", TERM_DENIALS[0])] == 1
    assert FAULT_IDS[("KILL", "nominal-synthetic")] == 67


@pytest.mark.parametrize("field", sorted(REQUEST_FIELDS))
def test_missing_adapter_input_field_cannot_reach_c_probe(field):
    q = case("KILL", "nominal-synthetic")
    del q[field]
    assert_input_rejected(q)


@pytest.mark.parametrize("name,corrupt", (
    ("abi_version", 0),
    ("abi_version", 2),
    ("abi_version", True),
    ("abi_version", 1.0),
    ("abi_version", "1"),
    ("abi_version", None),
    ("fixture_target", "fixture:synthetic-owned-anchor-group-T01-other"),
    ("fixture_target", "host:123"),
    ("fixture_target", 0),
    ("fixture_target", True),
    ("fixture_target", None),
    ("fixture_target", []),
    ("mock_only", False),
    ("mock_only", 0),
    ("mock_only", "true"),
    ("mock_only", None),
    ("nonce", 0),
    ("nonce", -1),
    ("nonce", True),
    ("nonce", False),
    ("nonce", 1 << 64),
    ("nonce", 1.0),
    ("nonce", "1"),
    ("nonce", None),
    ("nonce", []),
    ("mode", ""),
    ("mode", "Escalate-positive"),
    ("mode", "unknown-mode"),
    ("mode", 1),
    ("mode", True),
    ("mode", None),
    ("mode", []),
    ("phase", "UNKNOWN"),
    ("phase", "signal"),
    ("phase", 1),
    ("phase", True),
    ("phase", None),
    ("fault", "unknown-fault"),
    ("fault", ""),
    ("fault", 1),
    ("fault", True),
    ("fault", None),
    ("now_ms", True),
    ("now_ms", None),
    ("now_ms", "108300"),
    ("now_ms", -1),
    ("term_sent_at_ms", True),
    ("term_sent_at_ms", None),
    ("term_sent_at_ms", "108000"),
    ("term_sent_at_ms", -1),
    ("attempt_sequence", ()),
    ("attempt_sequence", []),
    ("attempt_sequence", None),
    ("attempt_sequence", ("KILL",)),
    ("attempt_sequence", ("TERM", "TERM")),
    ("attempt_sequence", ("TERM", "KILL", "TERM", "KILL")),
    ("attempt_sequence", ("TERM", True)),
))
def test_bad_type_or_value_denied_at_adapter_before_c(name, corrupt):
    q = case("KILL", "nominal-synthetic")
    q[name] = corrupt
    assert_input_rejected(q)


@pytest.mark.parametrize("field", ("original_policy", "attempt_policy"))
@pytest.mark.parametrize("damage", (
    "not-mapping", "missing", "extra", "wrong-type", "negative",
    "overflow", "inconsistent",
))
def test_adapter_policy_schema_and_type_validation_before_native_c(
    field, damage,
):
    q = case("KILL", "nominal-synthetic")
    source = q[field]
    if damage == "not-mapping":
        q[field] = []
    elif damage == "missing":
        q[field] = {k: v for k, v in source.items() if k != "t0_ms"}
    elif damage == "extra":
        q[field] = {**source, "untrusted_extra": 1}
    elif damage == "wrong-type":
        q[field] = {**source, "term_grace_ms": True}
    elif damage == "negative":
        q[field] = {**source, "cleanup_reserve_ms": -1}
    elif damage == "overflow":
        q[field] = {**source, "outer_deadline_ms": 1 << 63}
    elif damage == "inconsistent":
        q[field] = {**source, "kill_cutoff_ms": source["kill_cutoff_ms"] + 1}
    assert_input_rejected(q)


def test_extra_adapter_input_field_denied_before_any_native_dispatch():
    q = case("KILL", "nominal-synthetic")
    q["untrusted_extra"] = "not-an-authority"
    assert_input_rejected(q)


@pytest.mark.parametrize("bad_request", (
    None, True, [], (), "payload", 1,
))
def test_non_dict_adapter_request_must_fail_closed_without_exception(bad_request):
    assert_input_rejected(bad_request)


@pytest.mark.parametrize("replay_kind", ("exact", "different-fault", "different-phase"))
def test_repeated_nonce_rejected_before_c_even_with_new_facts(replay_kind):
    # Same adapter instance maintains per-task nonce consumption. Two
    # independent adapter imports would incorrectly bypass replay detection.
    adapter = probe()
    first = case("KILL", "nominal-synthetic")
    accepted = run_mock(first, adapter=adapter)
    assert accepted["decision"] == "SIMULATED_GATE_ONLY"
    assert accepted["fake_term_transport_calls"] == 1
    assert accepted["fake_kill_transport_calls"] == 1
    if replay_kind == "exact":
        replay = dict(first)
    elif replay_kind == "different-fault":
        replay = case("KILL", "anchor-early-exit")
        replay["nonce"] = first["nonce"]
    else:
        replay = case("TERM", "root-unsafe")
        replay["nonce"] = first["nonce"]
    refused = assert_input_rejected(replay, adapter=adapter)
    assert refused["nonce"] == first["nonce"]
    assert refused["c_adapter_dispatches"] == 0


def test_malformed_input_consumes_valid_nonce_and_cannot_rearm_it():
    adapter = probe()
    malformed = case("KILL", "nominal-synthetic")
    malformed["mock_only"] = False
    assert_input_rejected(malformed, adapter=adapter)
    repaired = dict(malformed)
    repaired["mock_only"] = True
    assert_input_rejected(repaired, adapter=adapter)

def test_adapter_to_header_identity_mapping_and_scenario_table_are_frozen():
    """Pre-native static check; should remain GREEN at the R1 RED Head."""
    h = HEADER.read_text(encoding="utf-8")
    d = CONTRACT.read_text(encoding="utf-8")
    for token in (
        "C3B03_T01_MAX_SCENARIO_ID UINT32_C(67)",
        "C3B03_T01_MAX_ATTEMPT_STEPS UINT32_C(3)",
        "uint32_t scenario_fault_id;",
        "uint64_t scenario_nonce;",
        "uint32_t attempt_sequence_len;",
        "c3b03_t01_phase_t attempt_sequence[3];",
        "c3b03_t01_deadline_t original_policy;",
        "c3b03_t01_deadline_t attempt_policy;",
        "#elif C3B03_TEST_NO_SIGNAL_STUB != 1",
    ):
        assert token in h, token
    for token in (
        "exact 12-field request shape", "Fixed IDs:",
        "ORIGINAL_POLICY", "c_adapter_dispatches", "nonce=0",
    ):
        assert token in d, token
    assert len(FAULT_IDS) == 67 and set(FAULT_IDS.values()) == set(range(1, 68))
    assert steps_for("MUTATION", "allow-second-term") == ("TERM", "TERM")
    assert steps_for("MUTATION", "allow-second-kill") == (
        "TERM", "KILL", "KILL"
    )
    assert steps_for("MUTATION", TERM_GATE_MUTANTS[0]) == ("TERM",)
    assert steps_for("MUTATION", KILL_GATE_MUTANTS[0]) == ("TERM", "KILL")
    assert set(case("KILL", "nominal-synthetic")) == REQUEST_FIELDS

