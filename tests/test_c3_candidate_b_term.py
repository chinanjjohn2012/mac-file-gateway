"""B-02 RED contracts for *synthetic-only* Darwin Controller-survives-TERM.

These are deliberately failing until isolated TERM C Helper and Python Runner
exist. Never target a caller-selected host PID/PGID or execute product work.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "tools/research/c3_candidate_b_term.c"
RUNNER = ROOT / "tools/research/run_c3_candidate_b_term.py"
WORKFLOW = ROOT / ".github/workflows/c3-candidate-b-term-native.yml"

MODES = (
    "term-positive",
    "missing-sigdef",
    "missing-sigmask",
    "controller-group-regression",
    "anchor-lost-before-term",
    "deadline-before-term",
    "canary-isolation",
    "controller-result-lost",
)
MUTATIONS = ("omit-sigdef", "omit-sigmask", "omit-controller-group")
SAFETY_FAULTS = ("stale-anchor-gate", "owner-fd-close", "controller-fd-close")
FIELDS = (
    "anchor_held", "controller_group_leader",
    "controller_inherited_ignore", "controller_inherited_block",
    "worker_spawned", "worker_default_term", "worker_unblocked_term",
    "worker_armed", "term_attempts", "term_succeeded",
    "controller_waited", "worker_observed_term",
    "admission_cutoff_expired", "outer_live_at_refusal",
    "gate_opened", "cleanup_complete", "canary_survived",
    "worker_result_unknown", "result_lost_after_wait",
    "owner_children_reaped", "anchor_loss_gate_checked",
    "after_loss_attempts", "owner_fds_closed", "controller_worker_fds_closed",
    "reuse_proven", "g2_qualified",
)
# Each bit is a *native observable* fixed by the design, never inferred from EOF.
EXPECTED = {
    "term-positive": (
        (1,1,1,1,1,1,1,1,1,1,1,1,0,0,1,1,0,0,0,1,0,0,1,1,0,0), "POSITIVE_EXPERIMENT",
    ),
    "missing-sigdef": (
        (1,1,1,1,1,0,1,1,1,1,1,0,0,0,1,1,0,0,0,1,0,0,1,1,0,0), "EXPECTED_BLOCK",
    ),
    "missing-sigmask": (
        (1,1,1,1,1,1,0,1,1,1,1,0,0,0,1,1,0,0,0,1,0,0,1,1,0,0), "EXPECTED_BLOCK",
    ),
    "controller-group-regression": (
        (1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,1,0,0,1,0,0,0), "SAFE_REFUSAL",
    ),
    "anchor-lost-before-term": (
        (0,1,1,1,1,1,1,1,0,0,1,0,0,0,1,1,0,0,0,1,1,0,1,1,0,0), "SAFE_REFUSAL",
    ),
    "deadline-before-term": (
        (1,1,1,1,1,1,1,1,0,0,1,0,1,1,1,1,0,0,0,1,0,0,1,1,0,0), "EXPECTED_BLOCK",
    ),
    "canary-isolation": (
        (1,1,1,1,1,1,1,1,1,1,1,1,0,0,1,1,1,0,0,1,0,0,1,1,0,0), "POSITIVE_EXPERIMENT",
    ),
    "controller-result-lost": (
        (1,1,1,1,1,1,1,1,1,1,0,0,0,0,1,0,0,1,1,1,0,0,1,0,0,0), "EXPECTED_BLOCK",
    ),
}


def driver():
    assert RUNNER.is_file(), "RED: isolated B-02 TERM Python Runner absent"
    spec = importlib.util.spec_from_file_location("c3_b02_term", RUNNER)
    assert spec and spec.loader
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def fixed(mode):
    return {"mode": mode, **dict(zip(FIELDS, EXPECTED[mode][0]))}


def test_b02_synthetic_native_companion_declares_safe_signal_boundary():
    assert NATIVE.is_file(), "RED: B-02 Darwin-only TERM C Helper absent"
    src = NATIVE.read_text()
    for required in (
        "POSIX_SPAWN_SETPGROUP", "posix_spawnattr_setpgroup",
        "POSIX_SPAWN_SETSIGDEF", "posix_spawnattr_setsigdefault",
        "POSIX_SPAWN_SETSIGMASK", "posix_spawnattr_setsigmask",
        "sigaction(", "sigprocmask(", "SIG_IGN", "SIG_DFL",
        "WIFSIGNALED", "WTERMSIG", "waitpid(", "SIGTERM",
        "getpgid(", "getsid(", "proc_pidinfo(", "PROC_PIDTBSDINFO",
        "outer_deadline", "term_admission_cutoff", "cleanup_reserve_ms",
        "CLOCK_MONOTONIC", "term_attempts", "worker_armed",
        "send_term_to_owned_group", "O_EXCL",
        "__canary", "C3B02_AFTER_WAIT_BEFORE_FINAL",
        "worker_result_unknown", "owner_children_reaped",
    ):
        assert required in src, f"native code lacks {required}"
    # No forced group KILL escalation in the B-02 experiment.
    assert "SIGKILL" not in src and "killpg(" not in src
    assert "system(" not in src and "popen(" not in src


def test_b02_strict_native_parsing_and_complete_observations():
    m = driver()
    assert m.MODES == MODES
    for mode in MODES:
        record = fixed(mode)
        assert m.classify(mode, record) == EXPECTED[mode][1]
        for key in record:
            assert m.classify(mode, {k: v for k, v in record.items() if k != key}) == "BLOCK"
        assert m.classify(mode, {**record, "unexpected": 1}) == "BLOCK"
        for flag in ("reuse_proven", "g2_qualified", "cleanup_complete"):
            assert m.classify(mode, {**record, flag: 1 - record[flag]}) == "BLOCK"


def test_b02_parse_rejects_forged_EOF_and_TERM_sent_without_wait():
    m = driver()
    good = "C3B02_RESULT mode=term-positive " + " ".join(
        f"{field}={value}" for field, value
        in zip(FIELDS, EXPECTED["term-positive"][0])
    ) + "\n"
    assert m.parse_native(good) == fixed("term-positive")
    assert m.classify(
        "term-positive", {**fixed("term-positive"), "controller_waited": 0}
    ) == "BLOCK"
    assert m.classify(
        "term-positive", {**fixed("term-positive"), "worker_observed_term": 0}
    ) == "BLOCK"
    for bad in (
        "", good + good, "spoof from stdout\n" + good,
        good + "extra", good.replace("term_attempts=1", "term_attempts=2"),
    ):
        with pytest.raises(ValueError):
            m.parse_native(bad)


def test_b02_one_outer_deadline_and_reserved_cleanup_gate():
    m = driver()
    assert m.MODES[5] == "deadline-before-term"
    outer, reserve = 15000, 4000
    cutoff = outer - reserve
    assert m.term_admitted(9000, cutoff, outer)
    assert not m.term_admitted(cutoff, cutoff, outer)
    assert not m.term_admitted(outer, cutoff, outer)
    assert not m.term_admitted(outer + 10, cutoff, outer)
    assert EXPECTED["deadline-before-term"][0][FIELDS.index("term_attempts")] == 0
    assert EXPECTED["deadline-before-term"][0][FIELDS.index("outer_live_at_refusal")] == 1
    assert EXPECTED["deadline-before-term"][0][FIELDS.index("cleanup_complete")] == 1


def test_b02_T01_and_T02_T03_adverse_controller_signal_inheritance():
    positive = fixed("term-positive")
    for key in ("controller_inherited_ignore", "controller_inherited_block",
                "worker_default_term", "worker_unblocked_term", "worker_armed"):
        assert positive[key] == 1
    assert fixed("missing-sigdef")["worker_default_term"] == 0
    assert fixed("missing-sigdef")["worker_unblocked_term"] == 1
    assert fixed("missing-sigmask")["worker_default_term"] == 1
    assert fixed("missing-sigmask")["worker_unblocked_term"] == 0
    for mode in MODES[:3]:
        assert fixed(mode)["controller_inherited_ignore"] == 1
        assert fixed(mode)["controller_inherited_block"] == 1


def test_b02_T07_canary_survives_and_T08_missing_result_is_unknown():
    canary = fixed("canary-isolation")
    assert canary["canary_survived"] == 1
    assert canary["worker_observed_term"] == 1
    assert canary["term_attempts"] == 1
    lost = fixed("controller-result-lost")
    assert lost["term_attempts"] == 1
    assert lost["worker_result_unknown"] == 1
    assert lost["result_lost_after_wait"] == 1
    assert lost["controller_waited"] == 0
    assert lost["worker_observed_term"] == 0
    assert lost["cleanup_complete"] == 0
    assert lost["owner_children_reaped"] == 1
    m = driver()
    assert m.classify("controller-result-lost",
                      {**lost, "worker_observed_term": 1}) == "BLOCK"
    assert m.classify("controller-result-lost",
                      {**lost, "cleanup_complete": 1}) == "BLOCK"


def test_b02_restricted_mutations_must_reject_missing_restoration():
    m = driver()
    assert m.MUTATIONS == MUTATIONS
    src = NATIVE.read_text()
    for marker in (
        "C3B02_MUT_OMIT_SIGDEF", "C3B02_MUT_OMIT_SIGMASK",
        "C3B02_MUT_CTRL_GROUP",
    ):
        assert marker in src
    runner = RUNNER.read_text()
    assert "mutation_detected" in runner
    assert "C3B02_MUTATIONS_DETECTED" in runner



def test_b02_T05_actual_owned_group_admission_after_worker_armed():
    """T05 must exercise the real admission function AFTER its group Worker ARMS.

    This must fail on the reviewed prior code: T05 exited without Controller
    spawn, Worker gate, or send_term_to_owned_group() call.
    """
    v = fixed("anchor-lost-before-term")
    assert v["worker_spawned"] == 1
    assert v["worker_armed"] == 1
    assert v["controller_group_leader"] == 1
    assert v["controller_waited"] == 1
    assert v["anchor_held"] == 0
    assert v["anchor_loss_gate_checked"] == 1
    assert v["after_loss_attempts"] == 0
    assert v["term_attempts"] == 0
    assert v["term_succeeded"] == 0
    assert v["cleanup_complete"] == 1
    m = driver()
    assert m.classify("anchor-lost-before-term", {
        **v, "anchor_loss_gate_checked": 0,
    }) == "BLOCK"
    assert m.classify("anchor-lost-before-term", {
        **v, "after_loss_attempts": 1,
    }) == "BLOCK"
    source = NATIVE.read_text()
    assert "C3B02_MUT_SKIP_ANCHOR_CHECK" in source
    assert "C3B02_TEST_STALE_KILL_STUB" in source
    assert "anchor_loss_gate_checked" in source
    assert "after_loss_attempts" in source


def test_b02_Owner_Controller_fd_close_errors_cannot_report_verified():
    """Test-only injected close errors must be detected AFTER actual close.

    The underlying owned FD is still closed; only return evidence is faulted.
    Neither Controller's Worker cleanup nor Owner's controlled IPC cleanup
    may set cleanup_complete=1 after a negative close result.
    """
    src = NATIVE.read_text()
    assert "static int close_child(" in src
    assert "worker_fds_closed" in src
    assert "owner_fds_closed" in src
    assert "controller_worker_fds_closed" in src
    assert "C3B02_FAULT_OWNER_CLOSE" in src
    assert "C3B02_FAULT_CONTROLLER_CLOSE" in src
    runner = driver()
    assert runner.SAFETY_FAULTS == SAFETY_FAULTS
    assert "fault_detected" in RUNNER.read_text()
    assert "C3B02_FAULTS_DETECTED" in RUNNER.read_text()
    normal = fixed("term-positive")
    assert normal["owner_fds_closed"] == 1
    assert normal["controller_worker_fds_closed"] == 1
    assert runner.classify("term-positive", {
        **normal, "owner_fds_closed": 0,
    }) == "BLOCK"
    assert runner.classify("term-positive", {
        **normal, "controller_worker_fds_closed": 0,
    }) == "BLOCK"


def test_b02_workflow_two_arm64_versions_and_no_production_launch():
    s = WORKFLOW.read_text()
    for marker in (
        "macos-15", "arm64", "3.13", "3.14",
        "tests/test_c3_candidate_b_term.py",
        "run_c3_candidate_b_term.py", "C3B02_NATIVE_RESULT",
        "term-positive", "missing-sigdef", "missing-sigmask",
        "controller-group-regression", "anchor-lost-before-term",
        "deadline-before-term", "canary-isolation",
        "controller-result-lost",
    ):
        assert marker in s


def test_b02_non_darwin_refuses_to_launch_or_create_evidence(tmp_path):
    if sys.platform == "darwin":
        return
    p = subprocess.run(
        [sys.executable, str(RUNNER), "--evidence-dir", str(tmp_path)],
        text=True, capture_output=True, timeout=12, check=False,
    )
    assert p.returncode == 3
    assert "C3B02_NOT_RUN_NON_DARWIN" in p.stdout
    assert list(tmp_path.iterdir()) == []


@pytest.mark.skipif(sys.platform != "darwin", reason="Darwin ARM64 synthetic TERM-only")
def test_b02_actual_Darwin_TERM_and_legitimate_wait(tmp_path):
    tmp_path.chmod(0o700)
    p = subprocess.run(
        [sys.executable, str(RUNNER), "--evidence-dir", str(tmp_path)],
        text=True, capture_output=True, timeout=110, check=False,
    )
    assert p.returncode == 0, p.stdout + p.stderr
    data = json.loads((tmp_path / "c3_b02_term_private.json").read_text())
    assert data["decision"] == "PARTIAL_B02_TERM_NOT_G2"
    assert data["g2_qualified"] is False and data["reuse_proven"] is False
    assert data["mutation_detected"] == {name: True for name in MUTATIONS}
    assert data["fault_detected"] == {name: True for name in SAFETY_FAULTS}
    assert [item["mode"] for item in data["cases"]] == list(MODES)
    assert [item["status"] for item in data["cases"]] == [EXPECTED[m][1] for m in MODES]
    assert all(item["cleanup_complete"] == 1 for item in data["cases"][:-1])
    assert data["cases"][-1]["cleanup_complete"] == 0
    assert data["cases"][-1]["worker_result_unknown"] == 1
    assert data["cases"][-1]["result_lost_after_wait"] == 1
    assert data["cases"][-1]["owner_children_reaped"] == 1
    assert data["cases"][0]["worker_observed_term"] == 1
    assert data["cases"][0]["controller_waited"] == 1
    assert data["cases"][0]["term_attempts"] == 1
    assert data["cases"][5]["term_attempts"] == 0
    assert data["cases"][5]["outer_live_at_refusal"] == 1
    assert data["cases"][6]["canary_survived"] == 1
    assert data["cases"][4]["worker_spawned"] == 1
    assert data["cases"][4]["worker_armed"] == 1
    assert data["cases"][4]["anchor_loss_gate_checked"] == 1
    assert data["cases"][4]["after_loss_attempts"] == 0
    assert data["cases"][4]["term_attempts"] == 0
    assert all(c["owner_fds_closed"] == 1 for c in data["cases"])
    assert data["cases"][4]["controller_worker_fds_closed"] == 1
