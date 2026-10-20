"""C3 trusted Relay research — contract-first RED, NOT production G2 qualification.

The native experiments are deliberately absent in the first RED commit.
Linux contract tests do NOT count as real Darwin PID/PGID race evidence.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
DRIVER = ROOT / "tools/research/run_c3_relay_probe.py"
NATIVE = ROOT / "tools/research/c3_relay_probe.c"
WORKFLOW = ROOT / ".github/workflows/c3-native-research.yml"
DESIGN = ROOT / "docs/research/phase2-lite-c3/README.md"
XNU_NOTE = ROOT / "docs/research/phase2-lite-c3/xnu-identity-observations.md"

# Research experiments, NOT proof of arbitrary process containment or actual PID reuse.
MODES = (
    "term-default", "kill-unknown", "leader-exit",
    "competing-reap", "ipc-forgery", "identity-loss",
)
EXPECTED = {
    "term-default":      ("OBSERVED_SIGNAL", "VERIFIED",   1, 0, 1, "SIGNALS_CLOSED", "POSITIVE_EXPERIMENT"),
    "kill-unknown":      ("UNKNOWN",         "UNRESOLVED", 1, 1, 1, "SIGNALS_CLOSED", "POSITIVE_EXPERIMENT"),
    "leader-exit":       ("UNKNOWN",         "UNRESOLVED", 0, 0, 1, "QUARANTINED",    "SAFE_REFUSAL"),
    "competing-reap":    ("UNKNOWN",         "UNRESOLVED", 0, 0, 0, "QUARANTINED",    "EXPECTED_BLOCK"),
    "ipc-forgery":       ("OBSERVED_EXIT",   "VERIFIED",   0, 0, 1, "SIGNALS_CLOSED", "EXPECTED_BLOCK"),
    "identity-loss":     ("UNKNOWN",         "UNRESOLVED", 0, 0, 0, "QUARANTINED",    "SAFE_REFUSAL"),
}


def _module():
    assert DRIVER.is_file(), "RED: C3 driver not implemented"
    spec = importlib.util.spec_from_file_location("c3_relay_research", DRIVER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _record(mode):
    worker, cleanup, term, kill, ipc, state, _ = EXPECTED[mode]
    return {
        "mode": mode, "worker": worker, "cleanup": cleanup, "term": term,
        "kill": kill, "owner_reaped": 1, "after_loss_signals": 0,
        "ipc_proven": ipc, "state": state,
    }


def test_design_approval_is_narrow_and_has_result_limits():
    text = DESIGN.read_text()
    for must in ("OBSERVED_EXIT", "OBSERVED_SIGNAL", "UNKNOWN", "QUARANTINED",
                 "C3-05", "C3-06", "C3-09", "C3-13", "NOT_RUN", "G2 BLOCK"):
        assert must in text


def test_python_classifier_requires_exact_native_evidence():
    m = _module()
    for mode in MODES:
        event = _record(mode)
        assert m.classify_native_result(mode, event) == EXPECTED[mode][-1]
        for key in event:
            mutated = {k: v for k, v in event.items() if k != key}
            assert m.classify_native_result(mode, mutated) == "BLOCK"
        assert m.classify_native_result(mode, {**event, "forged": 1}) == "BLOCK"
        assert m.classify_native_result(mode, {**event, "after_loss_signals": 1}) == "BLOCK"
    assert m.classify_native_result("kill-unknown",
                                    {**_record("kill-unknown"), "worker": "OBSERVED_SIGNAL"}) == "BLOCK"
    assert m.classify_native_result("competing-reap",
                                    {**_record("competing-reap"), "term": 1}) == "BLOCK"


def test_native_report_rejects_stdout_forgery_and_duplicates():
    m = _module()
    valid = ("C3_RESULT mode=kill-unknown worker=UNKNOWN cleanup=UNRESOLVED "
             "term=1 kill=1 owner_reaped=1 after_loss_signals=0 "
             "ipc_proven=1 state=SIGNALS_CLOSED\n")
    assert m.parse_native_result(valid) == _record("kill-unknown")
    for invalid in ("", "FINAL worker=OBSERVED_EXIT\n", valid + valid,
                    "spoof\n" + valid, valid + "junk", valid.replace("UNKNOWN", "OBSERVED_SIGNAL"),
                    valid.replace("after_loss_signals=0", "after_loss_signals=1")):
        try:
            event = m.parse_native_result(invalid)
        except ValueError:
            continue
        assert m.classify_native_result("kill-unknown", event) == "BLOCK"


def test_no_non_darwin_execution_or_side_effects(tmp_path):
    if sys.platform == "darwin":
        assert DRIVER.is_file()
        return
    run = subprocess.run([sys.executable, str(DRIVER), "--evidence-dir", str(tmp_path)],
                         capture_output=True, text=True, timeout=12, check=False)
    assert run.returncode == 3, run.stderr
    assert "NOT_RUN_NON_DARWIN" in run.stdout
    assert list(tmp_path.iterdir()) == []


def test_native_probe_linux_stub_is_research_only(tmp_path):
    assert NATIVE.is_file(), "RED: no C3 native executable"
    if sys.platform == "darwin":
        return
    binary = tmp_path / "c3_stub"
    built = subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                            str(NATIVE), "-o", str(binary)],
                           capture_output=True, text=True, timeout=12, check=False)
    assert built.returncode == 0, built.stderr
    run = subprocess.run([str(binary)], capture_output=True, text=True, timeout=10)
    assert run.returncode == 77 and "C3_NOT_RUN_NON_DARWIN" in run.stderr


def test_native_source_holds_anchor_and_restores_worker_term():
    text = NATIVE.read_text()
    for token in ("C3_TEST_MARKER", "O_NOFOLLOW", "POSIX_SPAWN_SETPGROUP",
                  "posix_spawnattr_setsigdefault", "posix_spawnattr_setsigmask",
                  "POSIX_SPAWN_SETSIGDEF", "POSIX_SPAWN_SETSIGMASK",
                  "SIGCHLD", "SA_NOCLDWAIT", "waitpid(",
                  "SIGNALS_CLOSED", "QUARANTINED"):
        assert token in text
    for forbidden in ("killpg(", "preexec_fn", "/dev/fd/", "shell=True"):
        assert forbidden not in text


def test_native_workflow_only_uses_isolated_fresh_research_processes():
    flow = WORKFLOW.read_text()
    for token in ("macos-15", "arm64", '"3.13"', '"3.14"',
                  "persist-credentials: false", "run_c3_relay_probe.py",
                  "g2_qualified", "NOT_G2", "identity-loss"):
        assert token in flow
    assert "release/ms1" not in flow
    assert "G2 PASS" not in flow


def test_xnu_evidence_separates_hypothesis_from_qualification():
    note = XNU_NOTE.read_text()
    for token in ("xnu-11417.140.69", "kern_fork.c", "kern_exit.c",
                  "kern_proc.c", "PID", "PGID", "waitpid",
                  "G2 BLOCK", "not proven"):
        assert token in note
