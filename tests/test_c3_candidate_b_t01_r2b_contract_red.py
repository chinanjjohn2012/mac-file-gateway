"""C3 Candidate B T01-R2b-R1 native contract RED; NO real group signal.

Shared forward-compatible contract. R1 *workflow*, not shared pytest, checks
native C/adapter absent. Behavior tests stay usable by a later approved R2
no-signal-only implementation: never mark them xfail or skip.
"""
from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
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
GATE_MUTANTS = (
    "omit-anchor-term-ignore",
    "omit-anchor-post-term-witness",
    "omit-anchor-reap-check",
    "omit-controller-outside-group",
    "omit-controller-live-check",
    "omit-worker-legal-parent",
    "omit-worker-group-check",
    "omit-kill-cutoff",
    "omit-grace",
    "allow-policy-rebase",
    "allow-second-term",
    "allow-second-kill",
)
EVIDENCE_MUTANTS = ("accept-fake-final", "ignore-fd-close")


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
    # Deterministic one-use synthetic nonce: never interpreted as an OS PID.
    digest = hashlib.sha256((phase + ":" + fault).encode()).digest()
    token = int.from_bytes(digest[:8], "big") or 1
    p = policy() if original is None else dict(original)
    return {
        "abi_version": 1,
        "mode": "escalate-positive",
        "fixture_target": TARGET,
        "phase": phase,
        "fault": fault,
        "nonce": token,
        "original_policy": p,
        "attempt_policy": dict(p if replacement is None else replacement),
        "now_ms": (FIRST_TERM if phase == "TERM" else FIRST_KILL)
        if now is None else now,
        "term_sent_at_ms": FIRST_TERM,
        "mock_only": True,
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
        "mutation_detected",
    }
    assert type(result["abi_version"]) is int and result["abi_version"] == 1
    assert type(result["nonce"]) is int and result["nonce"] == request["nonce"]
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
    assert result["reuse_proven"] is False
    assert result["g2_qualified"] is False
    # Synthetic syscalls never provide actual lawful waitpid or VERIFIED.
    assert result["worker_lawful_wait"] is False
    assert result["anchor_lawful_wait"] is False
    assert result["cleanup"] == "UNRESOLVED"
    assert result["decision"] in {"BLOCK", "SIMULATED_GATE_ONLY"}
    return result


def run_mock(request: dict) -> dict:
    output = probe().run_no_signal_case(request)
    return check_no_signal(output, request)


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
                 "controller", "anchor", "worker",
                 "ORIGINAL_POLICY", "no-signal C probe",
                 "R2b-R1", "R2b-R2", "NOT_RUN/BLOCK"):
        assert name in s, name


def test_r2b_r1_c_header_compiles_without_linking_or_executing():
    # Only test-owned header: a compile-time syntax check, no executable,
    # native process launch, group signal or OS target involved.
    code = (
        '#include "c3_b03_t01_no_signal_contract.h"\n'
        '_Static_assert(C3B03_T01_NO_SIGNAL_ABI_VERSION == 1, "ABI");\n'
        'int contract_syntax(c3b03_t01_mock_input_t *in) {\n'
        '  c3b03_t01_mock_output_t out = {0};\n'
        '  return (int)in->policy.kill_cutoff_ms + (int)out.abi_version;\n'
        '}\n'
    )
    cmd = [
        "cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic",
        "-DC3B03_TEST_NO_SIGNAL_STUB=1", "-fsyntax-only",
        "-I", str(HEADER.parent), "-x", "c", "-",
    ]
    good = subprocess.run(
        cmd, input=code, text=True, capture_output=True,
        timeout=15, check=False,
    )
    assert good.returncode == 0, good.stderr
    forbidden = subprocess.run(
        [p for p in cmd if not p.startswith("-DC3B03_TEST_NO_SIGNAL_STUB")],
        input=code, text=True, capture_output=True, timeout=15, check=False,
    )
    assert forbidden.returncode != 0
    assert "C3B03_TEST_NO_SIGNAL_STUB required" in forbidden.stderr


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


@pytest.mark.parametrize("mutant", GATE_MUTANTS, ids=GATE_MUTANTS)
def test_each_gate_deletion_mutant_stays_before_fake_transport(mutant):
    # The mutation is a *fixed compile-time test enum*; never runtime
    # permission to signal a numeric host PGID. Independent R2 C reviews
    # must verify compiled mutation binaries and symbol tables.
    r = run_mock(case("MUTATION", mutant))
    assert r["mutation_detected"] is True
    assert r["decision"] == "BLOCK"
    assert r["fake_kill_transport_calls"] == 0
    assert r["signals_closed"] is True




@pytest.mark.parametrize("mutant", EVIDENCE_MUTANTS, ids=EVIDENCE_MUTANTS)
def test_post_signal_evidence_mutants_cannot_upgrade_cleanup(mutant):
    # FINAL and FD close happen after a simulated send, so these checks
    # must block VERIFIED but do not retroactively make the send ineligible.
    r = run_mock(case("EVIDENCE_MUTATION", mutant))
    assert r["mutation_detected"] is True
    assert r["decision"] == "BLOCK"
    assert r["cleanup"] == "UNRESOLVED"
    assert r["signals_closed"] is True

@pytest.mark.parametrize("mode", MODES[1:], ids=MODES[1:])
def test_non_T01_modes_always_denied_even_if_orphan_preflight_true(mode):
    q = case("MODE", "different-mode")
    q["mode"] = mode
    q["nonce"] = int.from_bytes(
        hashlib.sha256(("MODE:" + mode).encode()).digest()[:8], "big"
    )
    r = run_mock(q)
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
