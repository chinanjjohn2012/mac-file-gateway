"""C3-05/06/13: synthetic Darwin identity-barrier RED contracts, NOT G2.

A correctly implemented native probe must demonstrate event ordering rather than
substituting an invalid expected PID or a sleep-based approximation.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
DRIVER = ROOT / "tools/research/run_c3_identity_probe.py"
NATIVE = ROOT / "tools/research/c3_identity_probe.c"
FLOW = ROOT / ".github/workflows/c3-identity-native.yml"
XNU = ROOT / "docs/research/phase2-lite-c3/identity-barriers.md"

MODES = (
    "exit-unreaped", "competing-reap", "group-isolation",
    "stale-after-reap",
)
EXPECTED = {
    "exit-unreaped": (1, 1, 0, 0, 0, 1, "SAFE_REFUSAL"),
    "competing-reap": (1, 0, 0, 0, 0, 1, "EXPECTED_BLOCK"),
    "group-isolation": (1, 1, 1, 0, 1, 0, "POSITIVE_EXPERIMENT"),
    "stale-after-reap": (1, 1, 0, 0, 1, 1, "EXPECTED_BLOCK"),
}


def _module():
    assert DRIVER.is_file(), "RED: C3 identity-barrier runner not implemented"
    spec = importlib.util.spec_from_file_location("c3_identity", DRIVER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _record(mode):
    observed, owned_reap, signals, late, canary, refused, _ = EXPECTED[mode]
    return {
        "mode": mode, "exit_observed": observed, "owner_reaped": owned_reap,
        "group_signals": signals, "after_loss_signals": late,
        "canary_alive": canary, "refused": refused,
        "reuse_proven": 0,
    }


def test_strict_contract_and_no_pg_reuse_promotion():
    m = _module()
    for mode in MODES:
        good = _record(mode)
        assert m.classify(mode, good) == EXPECTED[mode][-1]
        assert m.classify(mode, {**good, "reuse_proven": 1}) == "BLOCK"
        assert m.classify(mode, {**good, "after_loss_signals": 1}) == "BLOCK"
        assert m.classify(mode, {**good, "surplus": 1}) == "BLOCK"
        for field in good:
            assert m.classify(mode, {k: v for k, v in good.items() if k != field}) == "BLOCK"


def test_native_line_requires_single_exact_unforgeable_schema():
    m = _module()
    exact = ("C3_ID_RESULT mode=competing-reap exit_observed=1 owner_reaped=0 "
             "group_signals=0 after_loss_signals=0 canary_alive=0 "
             "refused=1 reuse_proven=0\n")
    assert m.parse_native(exact) == _record("competing-reap")
    for invalid in ("", exact + exact, "fake\n" + exact, exact + "garbage",
                    exact.replace("refused=1", "refused=2"),
                    exact.replace("reuse_proven=0", "reuse_proven=1")):
        try:
            parsed = m.parse_native(invalid)
        except ValueError:
            continue
        assert m.classify("competing-reap", parsed) == "BLOCK"


def test_linux_does_not_launch_research_processes(tmp_path):
    if sys.platform == "darwin":
        assert DRIVER.is_file()
        return
    r = subprocess.run([sys.executable, str(DRIVER), "--evidence-dir", str(tmp_path)],
                       text=True, capture_output=True, timeout=12, check=False)
    assert r.returncode == 3
    assert "C3_ID_NOT_RUN_NON_DARWIN" in r.stdout
    assert list(tmp_path.iterdir()) == []


def test_native_source_has_real_exit_event_and_competing_reap():
    source = NATIVE.read_text()
    for marker in ("C3_ID_TEST_MARKER", "O_NOFOLLOW", "POSIX_SPAWN_SETPGROUP",
                   "posix_spawn_file_actions_addfchdir_np", "NOTE_EXIT",
                   "EVFILT_PROC", "pthread_create(", "waitpid(", "getpgid(",
                   "SIGCHLD", "SA_NOCLDWAIT", "kill(-", "after_loss_signals"):
        assert marker in source
    for forbidden in ("killpg(", "preexec_fn", "/dev/fd/", "shell=True"):
        assert forbidden not in source


def test_native_linux_stub_explicitly_not_run(tmp_path):
    assert NATIVE.is_file()
    if sys.platform == "darwin":
        return
    exe = tmp_path / "c3_id_stub"
    c = subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                        str(NATIVE), "-o", str(exe)],
                       text=True, capture_output=True, timeout=12, check=False)
    assert c.returncode == 0, c.stderr
    x = subprocess.run([str(exe)], text=True, capture_output=True, timeout=10)
    assert x.returncode == 77 and "C3_ID_NOT_RUN_NON_DARWIN" in x.stderr


def test_native_workflow_and_xnu_limits():
    flow = FLOW.read_text()
    for literal in ("macos-15", "arm64", '"3.13"', '"3.14"',
                    "persist-credentials: false", "run_c3_identity_probe.py",
                    "PARTIAL_C3_IDENTITY_NOT_G2", "g2_qualified"):
        assert literal in flow
    note = XNU.read_text()
    for literal in ("C3-05", "C3-06", "C3-13", "xnu-11417.140.69",
                    "NOT_PROVEN", "G2 BLOCK", "competing", "barrier"):
        assert literal in note
