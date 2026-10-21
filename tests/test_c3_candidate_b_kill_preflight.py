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
    assert ".kill(" not in src and ".terminate(" not in src


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


def test_r2_controller_loss_orphan_kernel_observer_contract():
    """No group signal; prepare a kernel observer BEFORE losing the waiter."""
    m = module()
    assert m.ORPHAN_PREFIX == "C3B03_R2_ORPHAN"
    assert m.ORPHAN_RESULT == "ORPHAN_EXIT_OBSERVED_NOT_WORKER_WAIT"
    assert m.ORPHAN_EXPECTED["watcher_registered_before_loss"] == 1
    assert m.ORPHAN_EXPECTED["worker_identity_verified"] == 1
    assert m.ORPHAN_EXPECTED["controller_legal_wait"] == 0
    assert m.ORPHAN_EXPECTED["worker_wait_status_unknown"] == 1
    assert m.ORPHAN_EXPECTED["cleanup_unresolved"] == 1
    assert m.ORPHAN_EXPECTED["worker_reparented"] == 1
    assert m.ORPHAN_EXPECTED["worker_note_exit"] == 1
    assert m.ORPHAN_EXPECTED["worker_self_expiry_witness"] == 1
    assert m.ORPHAN_EXPECTED["group_term_attempts"] == 0
    assert m.ORPHAN_EXPECTED["group_kill_attempts"] == 0
    good = m.ORPHAN_PREFIX + " " + " ".join(
        f"{k}={v}" for k, v in m.ORPHAN_EXPECTED.items()
    ) + "\n"
    assert m.parse_orphan_native(good) == m.ORPHAN_EXPECTED
    assert m.classify_orphan(m.ORPHAN_EXPECTED.copy()) == m.ORPHAN_RESULT
    for k in m.ORPHAN_EXPECTED:
        bad = dict(m.ORPHAN_EXPECTED)
        bad[k] = 1 - bad[k]
        assert m.classify_orphan(bad) == "BLOCK"
    for text in ("", good + good, "forged\n" + good, good.rstrip("\n")):
        with pytest.raises(ValueError):
            m.parse_orphan_native(text)
    source = NATIVE.read_text(encoding="utf-8")
    for symbol in ("kqueue(", "kevent(", "EVFILT_PROC", "NOTE_EXIT",
                   "watcher_registered_before_loss", "orphan_owner_role",
                   "worker_self_expiry_witness", "bsd_parent(worker,ctrl.pid,worker)",
                   "MAGIC_ORPHAN_CANCEL", "C3B03_R2_FAULT_KQUEUE_OPEN",
                   "C3B03_R2_FAULT_KEVENT_ADD", "C3B03_R2_REFUSED"):
        assert symbol in source
    assert "kill(" not in source and "killpg(" not in source


@pytest.mark.skipif(sys.platform != "darwin",
                    reason="Darwin native kqueue orphan lifecycle only")
def test_r2_actual_controller_loss_orphan_lifecycle(tmp_path):
    """The controller truly exits; no orphan worker wait is fabricated."""
    tmp_path.chmod(0o700)
    proc = subprocess.run(
        [sys.executable, str(RUNNER),
         "--evidence-dir", str(tmp_path)],
        capture_output=True, text=True, timeout=115, check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    record = json.loads(
        (tmp_path / "c3_b03_r2_preflight_private.json").read_text()
    )
    assert record["orphan_lifecycle"] == module().ORPHAN_EXPECTED
    assert record["orphan_lifecycle_result"] == module().ORPHAN_RESULT
    assert record["orphan_worker_exit_observed"] is True
    assert record["orphan_preflight_proven"] is False  # T10 still pending
    assert record["group_kill_authorized"] is False
    assert record["orphan_modes"] == {
        mode: "NOT_RUN/BLOCK" for mode in module().ORPHAN_MODES
    }


@pytest.mark.parametrize("fault", ("kqueue-open", "kevent-add"))
@pytest.mark.skipif(sys.platform != "darwin",
                    reason="Darwin-only actual watcher failure injection")
def test_r2_watcher_failure_keeps_controller_legal_wait_and_no_orphan(
    tmp_path, fault
):
    """Cause registration failure BEFORE releasing Controller, never KILL."""
    m = module()
    tmp_path.chmod(0o700)
    binary = tmp_path / ("fault-" + fault)
    assert m.compile_preflight(binary, fault=fault)
    private = tmp_path / ("root-" + fault)
    private.mkdir(mode=0o700)
    executable = m.create_root(private, binary)
    p = subprocess.run(
        [str(executable), "orphan-preflight", str(executable.parent)],
        text=True, capture_output=True, check=False, timeout=14,
    )
    assert p.returncode == 75, p.stdout + p.stderr
    assert p.stdout == (
        "C3B03_R2_REFUSED reason=observer_not_ready "
        "controller_waited_worker=1 worker_exit_24=1 "
        "fds_closed=1 term_attempts=0 kill_attempts=0\n"
    )
    assert p.stderr == ""
    assert not (executable.parent / "C3B03_ORPHAN_REPARENTED").exists()
    assert not (executable.parent / "C3B03_ORPHAN_SELF_EXIT").exists()


def test_r2_fault_compiler_rejects_arbitrary_mutation_flags(tmp_path):
    m = module()
    assert not m.compile_preflight(tmp_path / "out", fault="skip-gate")
    assert not (tmp_path / "out").exists()


def test_r2_owner_timeout_reaps_only_owned_child_without_signaling(monkeypatch):
    m = module()

    class FakeProcess:
        returncode = 0
        def __init__(self):
            self.calls = []
        def communicate(self, timeout):
            self.calls.append(timeout)
            if len(self.calls) == 1:
                raise subprocess.TimeoutExpired("synthetic-owner", timeout)
            return "", ""
        def poll(self):
            return self.returncode

    p = FakeProcess()
    monkeypatch.setattr(m.subprocess, "Popen", lambda *a, **kw: p)
    value, reason = m.run_preflight(Path("/synthetic/preflight"))
    assert value is None and reason == "owner_timeout_reaped"
    assert p.calls == [12, 3]


def test_r2_owner_timeout_unresolved_is_not_a_cleanup_claim(monkeypatch):
    m = module()

    class FakeProcess:
        def __init__(self):
            self.calls = []
        def communicate(self, timeout):
            self.calls.append(timeout)
            raise subprocess.TimeoutExpired("synthetic-owner", timeout)

    p = FakeProcess()
    monkeypatch.setattr(m.subprocess, "Popen", lambda *a, **kw: p)
    value, reason = m.run_preflight(Path("/synthetic/preflight"))
    assert value is None and reason == "owner_timeout_unresolved"
    assert p.calls == [12, 3]


@pytest.mark.parametrize("owner_reason, expected_cleanup", (
    ("owner_timeout_unresolved", "UNRESOLVED"),
    ("owner_timeout_reaped", "OWNER_REAPED_AFTER_TIMEOUT"),
))
def test_r2_runner_failure_never_launches_second_mode_and_tracks_owner(
    tmp_path, monkeypatch, owner_reason, expected_cleanup
):
    """Stub only Runner logic; no native process, no PID operation."""
    m = module()
    private = tmp_path / "private"
    calls = []

    def stub_run(executable, mode="preflight"):
        calls.append(mode)
        return None, owner_reason

    def stub_mkdtemp(*a, **kw):
        private.mkdir(mode=0o700)
        return str(private)

    monkeypatch.setattr(m.sys, "platform", "darwin")
    monkeypatch.setattr(m.platform, "machine", lambda: "arm64")
    monkeypatch.setattr(m, "private_evidence_root", lambda path: True)
    monkeypatch.setattr(m, "compile_preflight", lambda target: True)
    monkeypatch.setattr(m, "create_root", lambda root, binary: root / "dummy")
    monkeypatch.setattr(m, "run_preflight", stub_run)
    monkeypatch.setattr(m.tempfile, "mkdtemp", stub_mkdtemp)
    monkeypatch.setattr(m.sys, "argv", [
        "runner", "--evidence-dir", str(tmp_path),
    ])
    rc = m.main()
    assert rc == 2
    assert calls == ["preflight"]  # NEVER enroll orphan after bad Owner
    document = json.loads(
        (tmp_path / "c3_b03_r2_preflight_private.json").read_text()
    )
    assert document["decision"] == "BLOCK_RESEARCH"
    assert document["orphan_lifecycle"] is None
    assert document["orphan_lifecycle_result"] == "BLOCK"
    assert document["orphan_lifecycle_reason"] == "NOT_RUN_PRIOR_OWNER_UNVERIFIED"
    assert document["native_owner_cleanup"] == expected_cleanup
    assert document["group_kill_authorized"] is False
    assert private.exists() is (owner_reason == "owner_timeout_unresolved")
