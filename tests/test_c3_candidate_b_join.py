"""B-01: independent test-first Darwin cross-parent PGID join contracts.

Review scope: fresh synthetic Anchor/Controller/Worker, no group signals,
no real Workspaces. Tests intentionally RED until the native C/runner exists.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
C = ROOT / "tools/research/c3_candidate_b_anchor.c"
DRIVER = ROOT / "tools/research/run_c3_candidate_b.py"
WORKFLOW = ROOT / ".github/workflows/c3-candidate-b-native.yml"

MODES = (
    "join-positive", "owner-reject-missing", "join-nonexistent",
    "join-cross-session", "gate-denied",
)

# anchor_held, controller_outside, sid_distinct, spawn_attempted,
# worker_spawned, joined, parentage, owner_granted, gate_opened,
# workload_started, controller_waited, cleanup_complete, expected status
EXPECTED = {
    "join-positive":        (1,1,0,1,1,1,1,1,1,1,1,1,"POSITIVE_EXPERIMENT"),
    "owner-reject-missing": (0,0,0,0,0,0,0,0,0,0,0,1,"EXPECTED_BLOCK"),
    "join-nonexistent":    (0,1,0,1,0,0,0,0,0,0,0,1,"EXPECTED_BLOCK"),
    "join-cross-session":  (1,1,1,1,0,0,0,0,0,0,0,1,"EXPECTED_BLOCK"),
    "gate-denied":         (1,1,0,1,1,1,1,0,0,0,1,1,"EXPECTED_BLOCK"),
}
FIELDS = (
    "anchor_held", "controller_outside", "sid_distinct", "spawn_attempted",
    "worker_spawned", "join_verified", "parentage_verified", "owner_granted",
    "gate_opened", "workload_started", "controller_waited",
    "cleanup_complete",
)


def module():
    assert DRIVER.is_file(), "RED: native B-01 driver has not been implemented"
    spec = importlib.util.spec_from_file_location("candidate_b_join", DRIVER)
    assert spec and spec.loader
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


def fixture(mode):
    return {
        "mode": mode, **dict(zip(FIELDS, EXPECTED[mode][:-1])),
        "reuse_proven": 0, "g2_qualified": 0,
    }


def test_b01_fixed_native_source_contract():
    assert C.is_file(), "RED: C Native Owner + Anchor/Controller/Worker absent"
    src = C.read_text()
    for required in (
        "posix_spawnattr_setpgroup", "POSIX_SPAWN_SETPGROUP",
        "posix_spawn_file_actions_addfchdir_np",
        "proc_pidinfo", "PROC_PIDTBSDINFO",
        "getpgid(", "getsid(", "getppid(",
        "waitpid(", "owner-grant", "worker-gate",
        "C3B_WORK_STARTED", "join-cross-session",
        "join-nonexistent", "owner-reject-missing", "gate-denied",
    ):
        assert required in src
    assert "kill(-" not in src and "killpg(" not in src
    assert "preexec_fn" not in src
    assert "system(" not in src
    assert "popen(" not in src


def test_b01_driver_strict_verdict_and_no_externally_chosen_pid():
    m = module()
    assert m.MODES == MODES
    for mode in MODES:
        record = fixture(mode)
        assert m.classify(mode, record) == EXPECTED[mode][-1]
        for key in record:
            assert m.classify(mode, {k: v for k, v in record.items() if k != key}) == "BLOCK"
        assert m.classify(mode, {**record, "extra": 1}) == "BLOCK"
        assert m.classify(mode, {**record, "reuse_proven": 1}) == "BLOCK"
        assert m.classify(mode, {**record, "g2_qualified": 1}) == "BLOCK"
    assert m.classify("join-positive",
                      {**fixture("join-positive"), "controller_waited": 0}) == "BLOCK"
    assert m.classify("join-cross-session",
                      {**fixture("join-cross-session"), "sid_distinct": 0}) == "BLOCK"
    assert m.classify("join-nonexistent",
                      {**fixture("join-nonexistent"), "spawn_attempted": 0}) == "BLOCK"


def test_b01_driver_parses_one_complete_native_record_only():
    m = module()
    good = (
        "C3B_RESULT mode=join-positive anchor_held=1 controller_outside=1 "
        "sid_distinct=0 spawn_attempted=1 worker_spawned=1 "
        "join_verified=1 parentage_verified=1 owner_granted=1 "
        "gate_opened=1 workload_started=1 controller_waited=1 "
        "cleanup_complete=1 reuse_proven=0 g2_qualified=0\n"
    )
    assert m.parse_native(good) == fixture("join-positive")
    for bad in ("", good+good, "spoof\n"+good, good+"junk",
                good.replace("controller_waited=1", "controller_waited=0"),
                good.replace("mode=join-positive", "mode=arbitrary")):
        try:
            parsed = m.parse_native(bad)
        except ValueError:
            continue
        assert m.classify("join-positive", parsed) == "BLOCK"


def test_b01_real_negative_preconditions_and_gate_contract():
    c = C.read_text()
    # These are not mocked failures: C code must observe genuinely distinct
    # SID, real spawn error for a reaped/no-longer-existing PGID, and a strict
    # Owner-only grant followed by Controller-only Worker-gate opening.
    for required in (
        "setsid(", "sid_distinct", "spawn_attempted",
        "owner-grant", "worker-gate", "O_EXCL",
        "getpgid(", "ECHILD", "ESRCH",
        "join-nonexistent", "owner-reject-missing",
    ):
        assert required in c


def test_b01_native_workflow_has_dual_arm64_and_private_evidence():
    s = WORKFLOW.read_text()
    for marker in (
        "macos-15", "arm64", "3.13", "3.14",
        "tests/test_c3_candidate_b_join.py",
        "run_c3_candidate_b.py", "C3B_NATIVE_RESULT",
        "join-positive", "join-nonexistent", "join-cross-session",
        "owner-reject-missing", "gate-denied",
    ):
        assert marker in s


def test_b01_linux_must_not_run_native_or_create_evidence(tmp_path):
    if sys.platform == "darwin":
        return
    p = subprocess.run(
        [sys.executable, str(DRIVER), "--evidence-dir", str(tmp_path)],
        text=True, capture_output=True, check=False, timeout=12,
    )
    assert p.returncode == 3
    assert "C3B_NOT_RUN_NON_DARWIN" in p.stdout
    assert list(tmp_path.iterdir()) == []


@pytest.mark.skipif(sys.platform != "darwin", reason="actual macOS ARM64 C B-01 only")
def test_b01_hosted_darwin_actual_cross_parent_join(tmp_path):
    tmp_path.chmod(0o700)
    p = subprocess.run(
        [sys.executable, str(DRIVER), "--evidence-dir", str(tmp_path)],
        text=True, capture_output=True, check=False, timeout=100,
    )
    assert p.returncode == 0, p.stdout + p.stderr
    record = json.loads((tmp_path / "c3_candidate_b_private.json").read_text())
    assert record["decision"] == "PARTIAL_B01_NATIVE_NOT_G2"
    assert record["g2_qualified"] is False
    assert record["reuse_proven"] is False
    assert [x["mode"] for x in record["cases"]] == list(MODES)
    assert [x["status"] for x in record["cases"]] == [EXPECTED[m][-1] for m in MODES]
    assert all(x["cleanup_complete"] == 1 for x in record["cases"])
