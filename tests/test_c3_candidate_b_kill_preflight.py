"""B03-R2 isolated pre-signal safety preflight contracts (NOT G2).

This module must never send SIGTERM/SIGKILL. It does not run B03-T01 KILL.
The eleven RED contracts remain frozen in PR #34; these tests only establish
prerequisites for a subsequent separately gated synthetic native experiment.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "tools/research/c3_candidate_b_kill_preflight.c"
RUNNER = ROOT / "tools/research/run_c3_candidate_b_kill_preflight.py"
B03_KILL = ROOT / "tools/research/c3_candidate_b_kill.c"
B03_KILL_RUNNER = ROOT / "tools/research/run_c3_candidate_b_kill.py"
WORKFLOW = ROOT / ".github/workflows/c3-candidate-b-kill-preflight.yml"


def module():
    assert RUNNER.is_file()
    spec = importlib.util.spec_from_file_location("c3_b03_r2_preflight", RUNNER)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_r2_no_product_or_native_group_signal_in_preflight():
    assert NATIVE.is_file() and RUNNER.is_file()
    assert not B03_KILL.exists() and not B03_KILL_RUNNER.exists(), (
        "R2 preflight cannot ship a SIGKILL experiment"
    )
    source = NATIVE.read_text(encoding="utf-8")
    for token in (
        "posix_spawnattr_setpgroup", "POSIX_SPAWN_SETPGROUP",
        "posix_spawn_file_actions_adddup2",
        "POSIX_SPAWN_SETSIGDEF", "POSIX_SPAWN_SETSIGMASK",
        "sigaction(", "SIG_IGN", "SIGCHLD", "SA_NOCLDWAIT",
        "proc_pidinfo(", "PROC_PIDTBSDINFO",
        "getpgid(", "getsid(", "waitpid(", "CLOCK_MONOTONIC",
        "O_NOFOLLOW", "O_CLOEXEC",
        "C3B03_R2_SYNTHETIC", "controller_role", "worker_role",
        "owner_role", "C3B03_R2_PREFLIGHT",
    ):
        assert token in source
    # This must catch an attempted group signal, even one inserted by mistake.
    assert "kill(" not in source and "killpg(" not in source
    assert "system(" not in source and "popen(" not in source
    assert "execvp(" not in source and "fork(" not in source


def test_r2_truthful_strict_parser_refuses_missing_or_forged_records():
    m = module()
    assert len(m.FIELDS) == 15
    assert m.EXPECTED["term_attempts"] == 0
    assert m.EXPECTED["kill_attempts"] == 0
    assert m.EXPECTED["orphan_preflight_proven"] == 0
    good = m.PREFIX + " " + " ".join(
        f"{k}={v}" for k, v in m.EXPECTED.items()
    ) + "\n"
    assert m.parse_native(good) == m.EXPECTED
    assert m.classify(m.EXPECTED.copy()) == m.RESULT
    for key, val in m.EXPECTED.items():
        bad = dict(m.EXPECTED)
        del bad[key]
        assert m.classify(bad) == "BLOCK"
        bad = dict(m.EXPECTED)
        bad[key] = 1 - val
        assert m.classify(bad) == "BLOCK"
        bad = dict(m.EXPECTED)
        bad[key] = bool(val)
        assert m.classify(bad) == "BLOCK"
    assert m.classify({**m.EXPECTED, "unexpected": 1}) == "BLOCK"
    assert m.classify({**m.EXPECTED, "kill_attempts": 1}) == "BLOCK"
    for payload in (
        "", good + good, "stdout forgery\n" + good, good + "extra",
        good.rstrip("\n"), good.replace("worker_joined=1", "worker_joined=0"),
        good.replace("kill_attempts=0", "kill_attempts=2"),
        good.replace("owner_reaped=1", "owner_reaped=true"),
        good.replace("owner_granted=1", "owner_granted=1 owner_granted=1"),
    ):
        try:
            parsed = m.parse_native(payload)
        except ValueError:
            continue
        assert m.classify(parsed) == "BLOCK"


def test_r2_orphan_modes_remain_hard_blocked_after_preflight():
    m = module()
    assert m.eligible_for_group_kill(m.EXPECTED.copy()) is False
    for mode in (
        "controller-loss-before-worker-wait",
        "controller-lost-after-term",
        "known-descendant-observation",
    ):
        assert mode in m.ORPHAN_MODES
    src = RUNNER.read_text(encoding="utf-8")
    assert "NOT_RUN/BLOCK" in src
    assert "group_kill_authorized" in src
    assert '"g2_qualified": False' in src
    assert '"reuse_proven": False' in src
    assert "proc.kill(" not in src and "proc.terminate(" not in src


def test_r2_ci_separately_qualifies_preflight_without_removing_R1_RED():
    y = WORKFLOW.read_text(encoding="utf-8")
    for marker in (
        "macos-15", "arm64", "3.13", "3.14", "ubuntu-latest",
        "B03-R2", "persist-credentials: false",
        "tests/test_c3_candidate_b_kill_preflight.py",
        "c3_candidate_b_kill_preflight.c",
        "c3_candidate_b_kill_preflight.py",
        "MANIFEST.sha256",
    ):
        assert marker in y
    assert "run_c3_candidate_b_kill.py --evidence-dir" not in y
    assert "kill -9" not in y


def test_r2_non_darwin_refuses_before_evidence_dir_access(tmp_path):
    if sys.platform == "darwin":
        pytest.skip("Linux-specific no-native-signal contract")
    cmd = [sys.executable, str(RUNNER),
           "--evidence-dir", str(tmp_path)]
    p = subprocess.run(cmd, capture_output=True, text=True,
                       check=False, timeout=10)
    assert p.returncode == 3
    assert "C3B03_R2_NOT_RUN_NON_DARWIN" in p.stdout
    assert not list(tmp_path.iterdir())


@pytest.mark.skipif(sys.platform != "darwin",
                    reason="Darwin-only synthetic process creation, no signals")
def test_r2_native_cross_parent_held_group_and_legitimate_wait(tmp_path):
    tmp_path.chmod(0o700)
    p = subprocess.run(
        [sys.executable, str(RUNNER),
         "--evidence-dir", str(tmp_path)],
        capture_output=True, text=True, check=False, timeout=100,
    )
    assert p.returncode == 0, p.stdout + p.stderr
    doc = json.loads(
        (tmp_path / "c3_b03_r2_preflight_private.json").read_text()
    )
    assert doc["decision"] == "PRE_SIGNAL_PREFLIGHT_ONLY_NOT_G2"
    assert doc["native_os"] == "Darwin"
    assert doc["native_arch"] == "arm64"
    assert doc["preflight"] == module().EXPECTED
    assert doc["orphan_modes"] == {
        mode: "NOT_RUN/BLOCK" for mode in module().ORPHAN_MODES
    }
    assert doc["orphan_preflight_proven"] is False
    assert doc["group_kill_authorized"] is False
    assert doc["reuse_proven"] is False
    assert doc["g2_qualified"] is False
