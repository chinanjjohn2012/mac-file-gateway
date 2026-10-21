"""B03-R1 RED contracts: Candidate B test-owned Darwin TERM -> final group KILL.

RESEARCH ONLY. At this initial RED Head there MUST BE NO B-03 C Helper or
Python Runner. Tests freeze the approved independent B03-D0 design; native
signal observations must be collected only after a later R2 safety gate.
No arbitrary PID/PGID, command, Workspace, existing process or SIGKILL is
issued by this test module.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "tools/research/c3_candidate_b_kill.c"
RUNNER = ROOT / "tools/research/run_c3_candidate_b_kill.py"
WORKFLOW = ROOT / ".github/workflows/c3-candidate-b-kill-native.yml"
DESIGN = ROOT / "docs/research/phase2-lite-c3/candidate-b-b03-kill-design.md"

# Ten numbered experiments, with two INDEPENDENT T08 modes: 11 fixed modes.
MODES = (
    "escalate-positive",                   # T01
    "worker-exits-before-kill",            # T02
    "anchor-lost-before-kill",             # T03
    "controller-loss-before-worker-wait",  # T04
    "kill-syscall-error",                  # T05
    "controller-final-lost-after-wait",    # T06
    "kill-cutoff-expired",                 # T07
    "controller-group-invalid-before-term",  # T08a
    "controller-lost-after-term",          # T08b
    "kill-canary-isolation",               # T09
    "known-descendant-observation",        # T10
)
PENDING_CONTAINMENT = (
    "controller-loss-before-worker-wait",
    "controller-lost-after-term",
    "known-descendant-observation",
)
# Compile-time variants. A bypass must NEVER issue a real group SIGKILL.
NO_SIGNAL_MUTATIONS = (
    "omit-anchor-kill-gate",
    "omit-controller-kill-gate",
    "omit-controller-own-pgid",
    "omit-kill-cutoff",
    "allow-second-kill",
)
EVIDENCE_MUTATIONS = (
    "forge-worker-wait",
    "omit-anchor-term-ignore",
    "omit-anchor-post-term-witness",
    "omit-worker-final",
    "forged-owned-fd-close",
    "inherited-controller-writer",
)
MUTATIONS = NO_SIGNAL_MUTATIONS + EVIDENCE_MUTATIONS

# Native observations, not inferred from TERM_SENT, KILL_SENT or stdout.
BOOL_FIELDS = (
    "anchor_ignore_ready", "anchor_ignore_after_term",
    "anchor_live_at_kill_gate", "anchor_reaped",
    "anchor_sigkill_observed", "controller_own_pgid_at_term",
    "controller_own_pgid_at_kill", "controller_live_at_kill_gate",
    "worker_spawned", "worker_armed", "worker_term_resistant",
    "worker_live_after_grace", "term_gate_checked", "term_attempts",
    "term_succeeded", "kill_gate_checked", "kill_attempts",
    "kill_succeeded", "signals_closed", "group_signals_after_close",
    "after_loss_kill_attempts", "controller_waited_worker",
    "controller_final_trusted", "owner_children_reaped",
    "owner_fds_closed", "controller_worker_fds_closed",
    "canary_survived", "known_descendant_observed",
    "independent_exit_observer_ready", "orphan_preflight_proven",
    "audit_post_wait_without_final", "kill_cutoff_expired",
    "outer_live_at_refusal", "positive_kill_margin",
    "reuse_proven", "g2_qualified",
)
ENUM_FIELDS = ("worker_result", "anchor_result", "cleanup", "kill_errno_class")
WORKER_RESULTS = frozenset((
    "OBSERVED_SIGNAL_SIGKILL", "OBSERVED_EXIT_24", "UNKNOWN", "NOT_SPAWNED",
))
ANCHOR_RESULTS = frozenset((
    "OBSERVED_SIGNAL_SIGKILL", "OBSERVED_EXIT_0", "UNKNOWN",
))
CLEANUP_RESULTS = frozenset(("VERIFIED", "UNRESOLVED"))
KILL_ERRNO_CLASSES = frozenset(("NONE", "ESRCH", "EPERM"))

# Explicit fixed contracts. Absent flags are zero, never "probably safe".
# All numeric flags are verified as exact integers (bool is NOT an int).
_ENROLLED = dict(
    anchor_ignore_ready=1, controller_own_pgid_at_term=1,
    worker_spawned=1, worker_armed=1, worker_term_resistant=1,
    term_gate_checked=1, owner_children_reaped=1, owner_fds_closed=1,
    controller_worker_fds_closed=1, positive_kill_margin=1,
)
_TERM = dict(_ENROLLED, anchor_ignore_after_term=1,
             term_attempts=1, term_succeeded=1)
_LIVE = dict(_TERM, anchor_live_at_kill_gate=1,
             controller_own_pgid_at_kill=1,
             controller_live_at_kill_gate=1,
             worker_live_after_grace=1, kill_gate_checked=1)
_KILLED = dict(_LIVE, kill_attempts=1, kill_succeeded=1,
               signals_closed=1, controller_waited_worker=1,
               controller_final_trusted=1, anchor_reaped=1,
               anchor_sigkill_observed=1)

# (native evidence overrides, classification). Any changed field must BLOCK.
EXPECTED = {
    "escalate-positive": (
        dict(_KILLED, worker_result="OBSERVED_SIGNAL_SIGKILL",
             anchor_result="OBSERVED_SIGNAL_SIGKILL", cleanup="VERIFIED"),
        "POSITIVE_EXPERIMENT",
    ),
    "worker-exits-before-kill": (
        dict(_TERM, anchor_reaped=1, controller_waited_worker=1,
             controller_final_trusted=1, signals_closed=1,
             worker_result="OBSERVED_EXIT_24",
             anchor_result="OBSERVED_EXIT_0", cleanup="VERIFIED"),
        "SAFE_REFUSAL",
    ),
    "anchor-lost-before-kill": (
        dict(_LIVE, anchor_live_at_kill_gate=0, anchor_reaped=1,
             controller_waited_worker=1, controller_final_trusted=1,
             worker_result="OBSERVED_EXIT_24",
             anchor_result="OBSERVED_EXIT_0", cleanup="VERIFIED",
             signals_closed=1),
        "SAFE_REFUSAL",
    ),
    "controller-loss-before-worker-wait": (
        dict(_KILLED, controller_waited_worker=0,
             controller_final_trusted=0, controller_worker_fds_closed=0,
             independent_exit_observer_ready=1, orphan_preflight_proven=1,
             worker_result="UNKNOWN",
             anchor_result="OBSERVED_SIGNAL_SIGKILL",
             cleanup="UNRESOLVED"),
        "EXPECTED_BLOCK",
    ),
    "kill-syscall-error": (
        dict(_LIVE, kill_attempts=1, kill_succeeded=0, signals_closed=1,
             anchor_reaped=1, controller_waited_worker=1,
             controller_final_trusted=1, kill_errno_class="ESRCH",
             worker_result="OBSERVED_EXIT_24",
             anchor_result="OBSERVED_EXIT_0", cleanup="VERIFIED"),
        "EXPECTED_BLOCK",
    ),
    "controller-final-lost-after-wait": (
        dict(_KILLED, controller_waited_worker=0,
             controller_final_trusted=0, controller_worker_fds_closed=0,
             audit_post_wait_without_final=1, worker_result="UNKNOWN",
             anchor_result="OBSERVED_SIGNAL_SIGKILL", cleanup="UNRESOLVED"),
        "EXPECTED_BLOCK",
    ),
    "kill-cutoff-expired": (
        dict(_LIVE, kill_cutoff_expired=1, outer_live_at_refusal=1,
             kill_attempts=0, signals_closed=1, anchor_reaped=1,
             controller_waited_worker=1, controller_final_trusted=1,
             worker_result="OBSERVED_EXIT_24",
             anchor_result="OBSERVED_EXIT_0", cleanup="VERIFIED"),
        "SAFE_REFUSAL",
    ),
    "controller-group-invalid-before-term": (
        dict(_ENROLLED, controller_own_pgid_at_term=0,
             worker_spawned=0, worker_armed=0,
             worker_term_resistant=0, term_gate_checked=1,
             term_attempts=0, kill_gate_checked=0, kill_attempts=0,
             anchor_reaped=1, signals_closed=1,
             worker_result="NOT_SPAWNED",
             anchor_result="OBSERVED_EXIT_0", cleanup="VERIFIED"),
        "SAFE_REFUSAL",
    ),
    "controller-lost-after-term": (
        dict(_LIVE, controller_live_at_kill_gate=0,
             controller_own_pgid_at_kill=0, kill_attempts=0,
             signals_closed=1, anchor_reaped=1,
             controller_waited_worker=0, controller_final_trusted=0,
             controller_worker_fds_closed=0,
             independent_exit_observer_ready=1, orphan_preflight_proven=1,
             worker_result="UNKNOWN",
             anchor_result="OBSERVED_EXIT_0", cleanup="UNRESOLVED"),
        "EXPECTED_BLOCK",
    ),
    "kill-canary-isolation": (
        dict(_KILLED, canary_survived=1,
             worker_result="OBSERVED_SIGNAL_SIGKILL",
             anchor_result="OBSERVED_SIGNAL_SIGKILL", cleanup="VERIFIED"),
        "POSITIVE_EXPERIMENT",
    ),
    "known-descendant-observation": (
        dict(_KILLED, known_descendant_observed=1,
             independent_exit_observer_ready=1, orphan_preflight_proven=1,
             worker_result="OBSERVED_SIGNAL_SIGKILL",
             anchor_result="OBSERVED_SIGNAL_SIGKILL", cleanup="VERIFIED"),
        "POSITIVE_EXPERIMENT",
    ),
}


def fixed(mode: str) -> dict:
    data = {"mode": mode, **dict.fromkeys(BOOL_FIELDS, 0),
            "worker_result": "UNKNOWN", "anchor_result": "UNKNOWN",
            "cleanup": "UNRESOLVED", "kill_errno_class": "NONE"}
    data.update(EXPECTED[mode][0])
    return data


def driver():
    assert RUNNER.is_file(), "EXPECTED RED: B-03 standalone Python Runner absent"
    spec = importlib.util.spec_from_file_location("c3_b03_kill", RUNNER)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_b03_R1_fixed_11_modes_and_two_distinct_T08_contracts():
    assert len(MODES) == 11 and len(set(MODES)) == 11
    assert MODES[7:9] == (
        "controller-group-invalid-before-term", "controller-lost-after-term",
    )
    a, b = fixed(MODES[7]), fixed(MODES[8])
    assert a["term_attempts"] == 0 and a["kill_gate_checked"] == 0
    assert a["cleanup"] == "VERIFIED" and a["worker_result"] == "NOT_SPAWNED"
    assert b["term_attempts"] == 1 and b["kill_gate_checked"] == 1
    assert b["kill_attempts"] == 0
    assert b["worker_result"] == "UNKNOWN" and b["cleanup"] == "UNRESOLVED"
    assert b["independent_exit_observer_ready"] == 1
    assert b["orphan_preflight_proven"] == 1


def test_b03_R1_approved_design_and_red_only_workflow():
    assert DESIGN.is_file()
    s = DESIGN.read_text()
    for item in ("B03-T01", "B03-T08a", "B03-T08b",
                 "SIGTERM=SIG_IGN", "kill_entry_margin_ms",
                 "NOT_RUN", "BLOCK", "outer_deadline"):
        assert item in s
    y = WORKFLOW.read_text()
    for item in ("macos-15", "arm64", "3.13", "3.14",
                 "tests/test_c3_candidate_b_kill.py", "B03-R1",
                 "test ! -f tools/research/c3_candidate_b_kill.c",
                 "test ! -f tools/research/run_c3_candidate_b_kill.py",
                 "persist-credentials: false"):
        assert item in y
    assert "run_c3_candidate_b_kill.py --evidence-dir" not in y
    assert "cc -std=" not in y and "kill -9" not in y
    assert not NATIVE.exists() and not RUNNER.exists(), (
        "B03-R1 RED must not contain a native group-KILL executable"
    )


def test_b03_native_contract_requires_new_isolated_C_helper():
    assert NATIVE.is_file(), "EXPECTED RED: B-03 KILL C Helper absent"
    c = NATIVE.read_text()
    for native in ("POSIX_SPAWN_SETPGROUP", "posix_spawnattr_setpgroup",
                   "SIGKILL", "SIGTERM", "SIG_IGN", "sigaction(",
                   "waitpid(", "WIFSIGNALED", "WTERMSIG",
                   "getpgid(", "getsid(", "proc_pidinfo(",
                   "send_kill_to_owned_group",
                   "kill_attempts", "SIGNALS_CLOSED",
                   "kill_admission_cutoff", "kill_entry_margin_ms",
                   "CLOCK_MONOTONIC"):
        assert native in c, f"missing live Darwin evidence {native}"
    assert "system(" not in c and "popen(" not in c
    assert "C3B03_TEST_NO_SIGNAL_STUB" in c
    assert "C3B03_MUT_SKIP_ANCHOR_KILL_GATE" in c
    assert "C3B03_MUT_SKIP_CONTROLLER_KILL_GATE" in c


def test_b03_runner_strict_schema_is_required():
    m = driver()
    assert m.MODES == MODES
    assert m.BOOL_FIELDS == BOOL_FIELDS
    assert m.ENUM_FIELDS == ENUM_FIELDS
    assert m.MUTATIONS == MUTATIONS
    assert m.PENDING_CONTAINMENT == PENDING_CONTAINMENT


@pytest.mark.parametrize("mode", MODES, ids=MODES)
def test_b03_each_native_mode_has_falsifiable_strict_outcome(mode: str):
    m = driver()  # R1 RED: intentionally absent, no native signals run
    record = fixed(mode)
    assert m.classify(mode, record) == EXPECTED[mode][1]
    for field, value in record.items():
        if field == "mode":
            continue
        partial = {k: v for k, v in record.items() if k != field}
        assert m.classify(mode, partial) == "BLOCK"
        if field in BOOL_FIELDS:
            assert m.classify(mode, {**record, field: 1 - value}) == "BLOCK"
            assert m.classify(mode, {**record, field: bool(value)}) == "BLOCK"
    assert m.classify(mode, {**record, "extra_field": 1}) == "BLOCK"
    assert m.classify(mode, {**record, "mode": "other"}) == "BLOCK"


def test_b03_kernel_wait_truth_cannot_be_promoted_from_kill_sent():
    m = driver()
    good = fixed("escalate-positive")
    for bad in (
        {**good, "controller_waited_worker": 0},
        {**good, "controller_final_trusted": 0},
        {**good, "worker_result": "UNKNOWN"},
        {**good, "anchor_sigkill_observed": 0},
        {**good, "owner_children_reaped": 0},
        {**good, "controller_worker_fds_closed": 0},
        {**good, "owner_fds_closed": 0},
        {**good, "group_signals_after_close": 1},
        {**good, "kill_attempts": 0},
        {**good, "kill_succeeded": 0},
        {**good, "reuse_proven": 1},
        {**good, "g2_qualified": 1},
    ):
        assert m.classify("escalate-positive", bad) == "BLOCK"
    lost = fixed("controller-final-lost-after-wait")
    assert lost["audit_post_wait_without_final"] == 1
    assert lost["worker_result"] == "UNKNOWN"
    assert lost["cleanup"] == "UNRESOLVED"
    assert m.classify(lost["mode"], {**lost,
                      "worker_result": "OBSERVED_SIGNAL_SIGKILL"}) == "BLOCK"
    assert m.classify(lost["mode"], {**lost,
                      "cleanup": "VERIFIED"}) == "BLOCK"


def test_b03_native_parser_rejects_duplicate_stdout_and_forged_final():
    m = driver()
    v = fixed("escalate-positive")
    one = ("C3B03_RESULT mode=escalate-positive " +
           " ".join(f"{k}={v[k]}" for k in BOOL_FIELDS + ENUM_FIELDS) + "\n")
    assert m.parse_native(one) == v
    for bad in (
        "", one + one, "forged stdout\n" + one,
        one + "other", one[:-1], one.replace(
            "kill_attempts=1", "kill_attempts=2"),
        one.replace("worker_result=OBSERVED_SIGNAL_SIGKILL",
                    "worker_result=KILL_SENT"),
    ):
        with pytest.raises(ValueError):
            m.parse_native(bad)


def test_b03_deadline_math_positive_margin_and_exact_equal_refusal():
    m = driver()
    outer, reserve, grace, margin = 15000, 4000, 1400, 300
    term, kill_cutoff = m.derive_cutoffs(outer, reserve, grace, margin)
    assert kill_cutoff == outer - reserve
    assert term == kill_cutoff - grace - margin
    assert m.kill_admitted(term + grace + 1, term + grace,
                           kill_cutoff, outer)
    assert not m.kill_admitted(kill_cutoff, term + grace,
                              kill_cutoff, outer)
    assert not m.kill_admitted(kill_cutoff + 1, term + grace,
                              kill_cutoff, outer)
    assert not m.kill_admitted(outer, term + grace, kill_cutoff, outer)
    assert not m.kill_admitted(term + grace - 1, term + grace,
                              kill_cutoff, outer)
    with pytest.raises(ValueError):
        m.derive_cutoffs(outer, reserve, grace, 0)
    assert fixed("kill-cutoff-expired")["kill_attempts"] == 0
    assert fixed("kill-cutoff-expired")["outer_live_at_refusal"] == 1


def test_b03_orphan_modes_need_proven_preflight_not_fake_wait():
    m = driver()
    for mode in PENDING_CONTAINMENT:
        record = fixed(mode)
        assert record["independent_exit_observer_ready"] == 1
        assert record["orphan_preflight_proven"] == 1
        assert m.classify(mode, {**record, "orphan_preflight_proven": 0}) == "BLOCK"
        assert m.classify(mode, {**record,
                                "independent_exit_observer_ready": 0}) == "BLOCK"
    b = fixed("controller-lost-after-term")
    assert b["kill_gate_checked"] == 1 and b["kill_attempts"] == 0
    assert b["controller_final_trusted"] == 0
    assert b["worker_result"] == "UNKNOWN"
    assert b["cleanup"] == "UNRESOLVED"
    # Native mode must be refused as NOT_RUN, not faked success, absent preflight.
    assert m.preflight_orphan_mode(False, False) == "NOT_RUN"
    assert m.preflight_orphan_mode(True, True) == "ELIGIBLE"


def test_b03_real_sigkill_must_have_11_named_safe_mutation_failures():
    m = driver()
    assert set(m.NO_SIGNAL_MUTATIONS) == set(NO_SIGNAL_MUTATIONS)
    assert set(m.EVIDENCE_MUTATIONS) == set(EVIDENCE_MUTATIONS)
    code = NATIVE.read_text()
    for token in ("C3B03_TEST_NO_SIGNAL_STUB",
                  "C3B03_MUT_SKIP_ANCHOR_KILL_GATE",
                  "C3B03_MUT_SKIP_CONTROLLER_KILL_GATE",
                  "C3B03_MUT_SKIP_KILL_CUTOFF",
                  "C3B03_MUT_RETRY_KILL",
                  "C3B03_MUT_OMIT_ANCHOR_TERM_IGNORE"):
        assert token in code
    runner = RUNNER.read_text()
    for token in ("mutation_detected", "C3B03_MUTATIONS_DETECTED",
                  "NOT_RUN", "BLOCK_RESEARCH", "reuse_proven",
                  "g2_qualified"):
        assert token in runner


def test_b03_non_darwin_runner_must_not_write_or_launch(tmp_path):
    if sys.platform == "darwin":
        pytest.skip("native-only refusal tested on Linux")
    assert RUNNER.is_file(), "EXPECTED RED: B-03 Runner absent"
    p = subprocess.run(
        [sys.executable, str(RUNNER), "--evidence-dir", str(tmp_path)],
        text=True, capture_output=True, timeout=12, check=False,
    )
    assert p.returncode == 3
    assert "C3B03_NOT_RUN_NON_DARWIN" in p.stdout
    assert not list(tmp_path.iterdir())


@pytest.mark.skipif(
    sys.platform != "darwin" or not NATIVE.is_file() or not RUNNER.is_file(),
    reason="B03-R1 has no native KILL executable; R2 requires separate gate",
)
def test_b03_darwin_real_wait_and_11_enrolled_modes(tmp_path):
    tmp_path.chmod(0o700)
    p = subprocess.run(
        [sys.executable, str(RUNNER), "--evidence-dir", str(tmp_path)],
        text=True, capture_output=True, timeout=180, check=False,
    )
    assert p.returncode == 0, p.stdout + p.stderr
    data = json.loads((tmp_path / "c3_b03_kill_private.json").read_text())
    assert data["decision"] == "PARTIAL_B03_NATIVE_NOT_G2"
    assert data["g2_qualified"] is False and data["reuse_proven"] is False
    assert [c["mode"] for c in data["cases"]] == list(MODES)
    assert [(c["mode"], c["status"]) for c in data["cases"]] == [
        (mode, EXPECTED[mode][1]) for mode in MODES
    ]
    assert data["mutation_detected"] == {name: True for name in MUTATIONS}
    assert all(c["group_signals_after_close"] == 0 for c in data["cases"])
    assert all(c["reuse_proven"] == 0 and c["g2_qualified"] == 0
               for c in data["cases"])
    assert data["cases"][0]["worker_result"] == "OBSERVED_SIGNAL_SIGKILL"
    assert data["cases"][0]["anchor_sigkill_observed"] == 1
    assert data["cases"][7]["term_attempts"] == 0
    assert data["cases"][7]["kill_gate_checked"] == 0
    assert data["cases"][8]["term_attempts"] == 1
    assert data["cases"][8]["kill_gate_checked"] == 1
    assert data["cases"][8]["kill_attempts"] == 0
    assert data["cases"][8]["worker_result"] == "UNKNOWN"
    assert data["cases"][8]["cleanup"] == "UNRESOLVED"
