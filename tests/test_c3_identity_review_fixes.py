"""Review-directed C3-05/06/13 fault controls (P2x3), synthetic only.

Contract-first RED: demand invalid syscall attempt accounting even when a stub
returns ESRCH, actual EPIPE handling, and bounded contested-waiter cleanup.
No fault is allowed to signal a stale numeric process group in the kernel.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tools/research/c3_identity_probe.c"
DRIVER = ROOT / "tools/research/run_c3_identity_probe.py"
FAULTS = ROOT / "tools/research/run_c3_identity_faults.py"
WORKFLOW = ROOT / ".github/workflows/c3-identity-native.yml"

MODES = (
    "fault-unauthorized-esrch",
    "fault-broken-pipe",
    "fault-waiter-ready",
    "fault-waiter-timeout",
    "fault-waiter-result",
)
# attempt count, after-loss attempts, direct-PID signals, EPIPE, contested, waiter
EXPECTED = {
    "fault-unauthorized-esrch": (1, 1, 0, 0, 0, 0, 0),
    "fault-broken-pipe": (0, 0, 0, 1, 0, 0, 1),
    "fault-waiter-ready": (0, 0, 0, 0, 1, 1, 1),
    "fault-waiter-timeout": (0, 0, 0, 0, 1, 0, 0),
    "fault-waiter-result": (0, 0, 0, 0, 1, 0, 0),
}


def load(path: Path, name: str):
    assert path.is_file(), f"RED: missing {path.name}"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def record(mode):
    attempts, late, pid_signal, epipe, contested, waiter_done, cleanup = EXPECTED[mode]
    return {
        "mode": mode, "attempts": attempts, "after_loss_attempts": late,
        "pid_signals": pid_signal, "epipe": epipe,
        "waiter_contested": contested, "waiter_done": waiter_done,
        "cleanup_complete": cleanup, "reuse_proven": 0,
    }


def test_real_native_result_reports_group_attempts_not_only_success():
    driver = load(DRIVER, "c3_identity_current")
    assert "group_attempts" in driver._FIELDS
    assert "after_loss_attempts" in driver._FIELDS
    assert "after_loss_signals" in driver._FIELDS
    for mode in driver.MODES:
        expected = driver.EXPECTED[mode]
        evidence = {
            "mode": mode,
            **dict(zip(driver._FIELDS, expected[:-1] + (0,))),
        }
        assert driver.classify(mode, evidence) == expected[-1]
        assert driver.classify(mode, {**evidence, "after_loss_attempts": 1}) == "BLOCK"
        assert driver.classify(mode, {**evidence, "group_attempts": 1 if mode != "group-isolation" else 2}) == "BLOCK"


def test_fault_runner_rejects_missing_or_forged_attempts():
    faults = load(FAULTS, "c3_faults")
    assert faults.MODES == MODES
    for mode in MODES:
        good = record(mode)
        assert faults.classify(mode, good) == "EXPECTED_BLOCK"
        assert faults.classify(mode, {**good, "reuse_proven": 1}) == "BLOCK"
        for key in good:
            assert faults.classify(mode, {k: v for k, v in good.items() if k != key}) == "BLOCK"
        assert faults.classify(mode, {**good, "surplus": 1}) == "BLOCK"
    spoof = record("fault-unauthorized-esrch")
    assert faults.classify("fault-unauthorized-esrch", {**spoof, "attempts": 0}) == "BLOCK"
    assert faults.classify("fault-unauthorized-esrch", {**spoof, "after_loss_attempts": 0}) == "BLOCK"


def test_fault_native_line_strict_single_record():
    faults = load(FAULTS, "c3_faults")
    good = ("C3_ID_FAULT mode=fault-unauthorized-esrch attempts=1 "
            "after_loss_attempts=1 pid_signals=0 epipe=0 "
            "waiter_contested=0 waiter_done=0 cleanup_complete=0 "
            "reuse_proven=0\n")
    assert faults.parse_native(good) == record("fault-unauthorized-esrch")
    for bad in ("", good + good, "spoof\n" + good, good + "extra",
                good.replace("attempts=1", "attempts=0"),
                good.replace("reuse_proven=0", "reuse_proven=1")):
        try:
            value = faults.parse_native(bad)
        except ValueError:
            continue
        assert faults.classify("fault-unauthorized-esrch", value) == "BLOCK"


def test_native_source_isolation_and_failure_accounting():
    c = SOURCE.read_text()
    for marker in (
        "group_attempts", "after_loss_attempts",
        "C3_ID_TEST_KILL_STUB", "ESRCH", "SIGPIPE", "EPIPE",
        "ownership_contested", "fault-waiter-ready", "fault-waiter-timeout",
        "fault-waiter-result", "fault-broken-pipe",
        "waiter_done", "cleanup_complete",
    ):
        assert marker in c
    assert "pthread_join(" not in c
    assert "killpg(" not in c
    assert "preexec_fn" not in c


def test_fault_workflow_has_explicit_native_witness():
    yml = WORKFLOW.read_text()
    for marker in (
        "run_c3_identity_faults.py",
        "fault-unauthorized-esrch", "fault-broken-pipe",
        "fault-waiter-ready", "fault-waiter-timeout", "fault-waiter-result",
        "C3_ID_FAULT_RESULT", "g2_qualified",
    ):
        assert marker in yml


def test_fault_driver_no_native_side_effect_on_linux(tmp_path):
    if sys.platform == "darwin":
        assert FAULTS.is_file()
        return
    script = subprocess.run(
        [sys.executable, str(FAULTS), "--evidence-dir", str(tmp_path)],
        capture_output=True, text=True, timeout=12, check=False,
    )
    assert script.returncode == 3
    assert "C3_ID_FAULT_NOT_RUN_NON_DARWIN" in script.stdout
    assert list(tmp_path.iterdir()) == []


@pytest.mark.skipif(sys.platform != "darwin", reason="requires real Darwin synthetic tests")
def test_native_fault_modes_block_and_bound_cleanup(tmp_path):
    # This runs only newly created native test children; no existing PID/PGID.
    tmp_path.chmod(0o700)
    proc = subprocess.run(
        [sys.executable, str(FAULTS), "--evidence-dir", str(tmp_path)],
        capture_output=True, text=True, timeout=75, check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    import json
    data = json.loads((tmp_path / "c3_identity_faults_private.json").read_text())
    assert data["g2_qualified"] is False
    assert data["decision"] == "FAULT_CONTROLS_PASS_NOT_G2"
    assert data["mutation_detected"] is True
    assert [c["mode"] for c in data["cases"]] == list(MODES)
    assert all(c["status"] == "EXPECTED_BLOCK" for c in data["cases"])
    assert all(c["pid_signals"] == 0 for c in data["cases"])
    assert all(c["after_loss_attempts"] == (1 if c["mode"] == "fault-unauthorized-esrch" else 0)
               for c in data["cases"])
    assert all(c["elapsed_ms"] < 6500 for c in data["cases"])
