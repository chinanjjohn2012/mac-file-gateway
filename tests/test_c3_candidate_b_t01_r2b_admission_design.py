"""B03-T01-R2b-D0 design-only static contract; NO native group signals.

This test is intentionally *phase specific*: it verifies that this DESIGN PR
does NOT yet contain a Native forced-group KILL Helper/Runner. Later native
research PRs must use their own reviewed contracts and do not amend R2a.
"""
from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DESIGN = ROOT / "docs/research/phase2-lite-c3/candidate-b-b03-t01-r2b-native-admission-design.md"
T01_D1 = ROOT / "docs/research/phase2-lite-c3/candidate-b-b03-t01-gate-design.md"
B03_D0 = ROOT / "docs/research/phase2-lite-c3/candidate-b-b03-kill-design.md"
FROZEN_R1 = ROOT / "tests/test_c3_candidate_b_kill.py"
PURE_R1 = ROOT / "tests/test_c3_candidate_b_t01_contract_red.py"
PURE_R2A = ROOT / "tools/research/c3_candidate_b_kill_t01_gate.py"
NATIVE = ROOT / "tools/research/c3_candidate_b_kill.c"
DRIVER = ROOT / "tools/research/run_c3_candidate_b_kill.py"
WORKFLOW = ROOT / ".github/workflows/c3-candidate-b-t01-r2b-design.yml"


def text():
    assert DESIGN.is_file(), "no R2b design freeze"
    return DESIGN.read_text(encoding="utf-8")


def test_r2b_design_upstream_reviewed_parent_fixed():
    s = text()
    assert T01_D1.is_file() and B03_D0.is_file()
    assert PURE_R1.is_file() and PURE_R2A.is_file()
    for sha in (
        "829a8e12ec8583a07a0f854c5a4f2479635e072b",
        "30c74b50d12e9d5763054da48be1d612b4b9fc02",
        "d6ca7afa15642c82da263ffa6bb75063bbe0ac29",
        "50400831bb10483c8ce67a9a0cb66ea29173e3c7",
    ):
        assert sha in s
    assert "Standards/Spec design PASS" in s
    assert "Review #5607469692" in s


def test_r2b_phase_is_design_only_with_absent_forced_kill_executable():
    s = text()
    assert not NATIVE.exists(), "design stage cannot create forced-KILL C Helper"
    assert not DRIVER.exists(), "design stage cannot create forced-KILL Runner"
    for marker in (
        "DESIGN ONLY", "group_kill_authorized=false",
        "reuse_proven=false", "g2_qualified=false",
        "R2B_NATIVE_ADMISSION_DESIGN_REVIEW_PENDING",
        "T04/T08b/T10", "NOT_RUN/BLOCK",
    ):
        assert marker in s, marker
    assert "group_kill_authorized=true" not in s
    assert "g2_qualified=true" not in s


def test_r2b_exact_role_tree_and_single_legal_waiters():
    s = text()
    for fact in (
        "Anchor", "Controller", "Worker", "Native Owner",
        "PID=PGID", "0700", "finite fixed enums",
        "Controller alone", "waitpid", "CLOEXEC",
        "posix_spawn", "trusted Controller FINAL",
        "No host-selected PID, PGID, command",
    ):
        assert fact in s, fact


def test_r2b_term_and_kill_native_identity_gates_not_from_python_bool():
    s = text()
    for fact in (
        "Owner-only serial state", "SIGTERM=SIG_IGN",
        "proc_pidinfo", "getpgid", "getsid",
        "SIG_IGN", "ARMED", "post-TERM",
        "term_attempts=1,term_succeeded=0,kill_attempts=0,SIGNALS_CLOSED",
        "kill_attempts", "SIGNALS_CLOSED",
        "EINTR", "ESRCH", "EPERM", "no retry",
    ):
        assert fact in s, fact
    assert "must not be imported or accepted as authorization" in s


def test_r2b_no_signal_mutation_interceptor_contract():
    s = text()
    for marker in (
        "C3B03_TEST_NO_SIGNAL_STUB", "opaque synthetic token",
        "negative mutant", "before even reaching the fake transport",
        "no linkable live negative-PGID signal path",
        "disassembly / symbol", "error",
        "omitted Anchor", "Controller lost",
        "missed FD closure", "forged trusted FINAL",
    ):
        assert marker in s, marker


def test_r2b_immutable_clock_and_measured_future_budget_only():
    s = text()
    for item in (
        "CLOCK_MONOTONIC", "outer_deadline = t0 + outer_budget_ms",
        "kill_cutoff   = outer_deadline - cleanup_reserve_ms",
        "term_cutoff   = kill_cutoff - term_grace_ms - kill_entry_margin_ms",
        "grace_end     = native_term_sent_at + term_grace_ms",
        "No numeric production/native timing vector is approved",
        "native calibration", "macOS ARM64 Python 3.13 and 3.14",
        "Owner self-watchdog", "UNRESOLVED",
        "outer_budget=12000,reserve=3000,grace=200,margin=300",
    ):
        assert item in s, item


def test_r2b_distinct_wait_and_cleanup_axes():
    s = text()
    for value in (
        "worker_result=OBSERVED_SIGNAL_SIGKILL",
        "anchor_result=OBSERVED_SIGNAL_SIGKILL",
        "WIFSIGNALED", "WTERMSIG==SIGKILL", "controller_final_trusted=1",
        "owner_children_reaped=1", "cleanup=VERIFIED",
        "UNKNOWN", "UNRESOLVED",
        "NOTE_EXIT", "POSITIVE_EXPERIMENT",
        "True == 1",
    ):
        assert value in s, value


def test_r2b_future_signal_workflow_not_implicitly_enabled():
    s = text()
    for control in (
        "workflow_dispatch", "protected GitHub environment",
        "explicit human approval", "exact frozen reviewed Head",
        "binary SHA allowlist", "one hard-coded T01 mode",
        "No automatic PR/push-triggered workflow",
        "do not create or enable such a workflow in R2b-D0",
    ):
        assert control in s, control
    assert "R2b-R3" in s and "T01-R3" in s and "T01-R4" in s


def test_r2b_existing_11_mode_contract_still_frozen():
    assert FROZEN_R1.is_file()
    spec = importlib.util.spec_from_file_location("b03_r1_frozen", FROZEN_R1)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert len(module.MODES) == 11
    assert len(set(module.MODES)) == 11
    assert module.MODES[0] == "escalate-positive"
    assert module.PENDING_CONTAINMENT == (
        "controller-loss-before-worker-wait",
        "controller-lost-after-term",
        "known-descendant-observation",
    )


def test_r2b_design_workflow_has_no_signal_capability():
    assert WORKFLOW.is_file()
    y = WORKFLOW.read_text(encoding="utf-8")
    for item in (
        "macos-15", "ubuntu-latest", '"3.13"', '"3.14"',
        "persist-credentials: false",
        "c3-candidate-b-t01-r2b-design.yml",
        "tests/test_c3_candidate_b_t01_r2b_admission_design.py",
        "tests/test_c3_candidate_b_t01_contract_red.py",
        "tests/test_c3_candidate_b_t01_pure_gate_r2.py",
        "MANIFEST.sha256",
        "test ! -e tools/research/c3_candidate_b_kill.c",
        "test ! -e tools/research/run_c3_candidate_b_kill.py",
        "C3B03_T01_R2B_DESIGN_ONLY=true",
        "C3B03_T01_R2B_REAL_GROUP_SIGNAL_AUTHORIZED=false",
    ):
        assert item in y, item
    assert "|| true" not in y
    assert "continue-on-error:" not in y
    assert "workflow_dispatch" not in y
    assert "kill -9" not in y
    assert "SIGKILL" not in y


def test_r2b_design_manifest_sha256_for_every_tracked_file():
    manifest = ROOT / "MANIFEST.sha256"
    lines = manifest.read_text(encoding="utf-8").strip().splitlines()
    assert lines == sorted(lines, key=lambda line: line[66:])
    known = set()
    for line in lines:
        checksum, path = line.split("  ", 1)
        assert path.startswith("./") and path not in known
        known.add(path)
        file = ROOT / path
        assert file.is_file(), path
        assert hashlib.sha256(file.read_bytes()).hexdigest() == checksum, path
    assert "./docs/research/phase2-lite-c3/candidate-b-b03-t01-r2b-native-admission-design.md" in known
    assert "./tests/test_c3_candidate_b_t01_r2b_admission_design.py" in known
    assert "./.github/workflows/c3-candidate-b-t01-r2b-design.yml" in known
