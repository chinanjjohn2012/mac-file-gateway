"""C2 synthetic group-owner contract: never a product G2 qualification."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "tools/research/run_c2_pgid_probe.py"
NATIVE = ROOT / "tools/research/c2_pgid_anchor.c"
CHILD = ROOT / "tools/research/c2_group_child.py"
WORKFLOW = ROOT / ".github/workflows/c2-native-research.yml"
MODES = ("term", "kill", "worker-first", "leader-exit", "stale")


def _module():
    assert RUNNER.is_file(), "Expected RED before C2 implementation"
    spec = importlib.util.spec_from_file_location("c2_probe", RUNNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _expected(mode):
    return {"mode": mode, "term": int(mode in ("term", "kill", "worker-first")),
            "kill": int(mode == "kill"), "refused": int(mode in ("leader-exit", "stale")),
            "held": int(mode != "leader-exit"), "reaped": 1, "drain": 1,
            "descendant_verified": 1}


def test_positive_cases_and_safe_refusals_only():
    m = _module()
    for mode in MODES:
        verdict = m.classify_observation(mode, _expected(mode))
        assert verdict == ("SAFE_REFUSAL" if mode in ("leader-exit", "stale") else "POSITIVE_EXPERIMENT")


def test_all_mismatches_or_missing_fields_are_blocked():
    m = _module()
    for mode in MODES:
        good = _expected(mode)
        for field, original in good.items():
            changed = "not-" + mode if field == "mode" else 1 - original
            assert m.classify_observation(mode, {**good, field: changed}) == "BLOCK"
            assert m.classify_observation(mode, {k: v for k, v in good.items() if k != field}) == "BLOCK"
        assert m.classify_observation(mode, {**good, "term": True}) == "BLOCK"


def test_strict_native_report_parsing():
    m = _module()
    line = ("C2_RESULT mode=term term=1 kill=0 refused=0 held=1 "
            "reaped=1 drain=1 descendant_verified=1\n")
    assert m.parse_native_result(line) == _expected("term")
    for malformed in ("", line + line, "noise\n" + line, line + "junk",
                      line.replace("term=1", "term=2"), line.replace("drain=1", "drain=-1")):
        try:
            m.parse_native_result(malformed)
        except ValueError:
            continue
        assert False, f"accepted malformed report: {malformed!r}"


def test_non_darwin_is_explicit_not_run(tmp_path):
    if sys.platform == "darwin":
        assert RUNNER.is_file()
        return
    proc = subprocess.run([sys.executable, str(RUNNER), "--evidence-dir", str(tmp_path)],
                          capture_output=True, text=True, timeout=10, check=False)
    assert proc.returncode == 3 and "NOT_RUN_NON_DARWIN" in proc.stdout
    assert not list(tmp_path.iterdir())


def test_native_linux_stub_fail_closed(tmp_path):
    assert NATIVE.is_file()
    if sys.platform == "darwin":
        return
    binary = tmp_path / "c2_stub"
    proc = subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                           str(NATIVE), "-o", str(binary)], capture_output=True, text=True,
                          timeout=10, check=False)
    assert proc.returncode == 0, proc.stderr
    result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=10)
    assert result.returncode == 77 and "C2_NOT_RUN_NON_DARWIN" in result.stderr


def test_native_signal_gate_and_synthetic_boundary():
    source = NATIVE.read_text()
    for marker in ("C2_TEST_MARKER", "O_NOFOLLOW", "posix_spawn_file_actions_addfchdir_np",
                   "POSIX_SPAWN_SETPGROUP", "signal_owned_group(", "getpgid(owner->pid)",
                   "waitpid(owner->pid,", "owner->reaped", "kill(-owner->pid,",
                   "kill(owner->pid, SIGKILL)"):
        assert marker in source
    for forbidden in ("killpg(", "preexec_fn", "/dev/fd/", "shell=True"):
        assert forbidden not in source


def test_descendant_script_is_bounded_and_exercises_worker_leader_exit():
    source = CHILD.read_text()
    for marker in ("MAX_LIFETIME_SECONDS", "os.fork()", "os.waitpid(worker_pid,",
                   "worker-first", "leader-exit", "SIGTERM"):
        assert marker in source


def test_runner_never_claims_g2_and_workflow_is_native():
    source = RUNNER.read_text()
    for marker in ('"g2_qualified": False', "PARTIAL_NATIVE_OBSERVATION_NOT_G2",
                   "SAFE_REFUSAL", "TemporaryDirectory(", "check=False"):
        assert marker in source
    assert all(mode in source for mode in MODES)
    flow = WORKFLOW.read_text()
    for marker in ("macos-15", "arm64", '"3.13"', '"3.14"',
                   "run_c2_pgid_probe.py", "G2", "persist-credentials: false"):
        assert marker in flow


def test_exited_group_leader_refusal_still_has_live_descendant():
    source = NATIVE.read_text()
    start = source.index('if (strcmp(mode, "leader-exit") == 0) {')
    end = source.index('} else if (strcmp(mode, "stale") == 0)', start)
    branch = source[start:end]
    assert "bounded_reap(&owner, 2500)" in branch
    assert "getpgid(descendant) != owner.pid" in branch
    assert branch.index("getpgid(descendant) != owner.pid") < branch.index("signal_owned_group(")


def test_positive_drain_cannot_wait_for_synthetic_self_expiry():
    helper = NATIVE.read_text()
    synthetic = CHILD.read_text()
    assert "MAX_LIFETIME_SECONDS = 5.0" in synthetic
    assert "long drain_budget_ms = refused ? 4000 : 2000;" in helper
    assert "drain_to_eof(output[0], drain_budget_ms)" in helper
