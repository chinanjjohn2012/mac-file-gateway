"""Research harness contract tests; not a Multi exec qualification."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "tools/research/run_c1_fd_probe.py"
NATIVE = ROOT / "tools/research/c1_fd_spawn.c"


def _module():
    spec = importlib.util.spec_from_file_location("c1_fd_probe", RUNNER)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_parse_rejects_missing_and_spoofed_native_anchor():
    p = _module()
    for text in ("", "C1_ANCHOR pid=0 pgid=0", "C1_ANCHOR pid=42 pgid=43 dir_dev=1 dir_ino=7", "C1_ANCHOR pid=42 pgid=42 dir_dev=-1 dir_ino=7"):
        try:
            p.parse_anchor(text)
        except ValueError:
            continue
        assert False, f"accepted malformed anchor: {text!r}"
    assert p.parse_anchor("C1_ANCHOR pid=42 pgid=42 dir_dev=1 dir_ino=7") == (42, 1, 7)


def test_evaluate_requires_exact_inode_and_group_and_handshake():
    p = _module()
    expected = {"cwd_dev": 123, "cwd_ino": 456, "pgid": 789, "handshake": "R"}
    assert p.evaluate_observation(expected, expected) is True
    for override in ({"cwd_ino": 457}, {"cwd_dev": 124}, {"pgid": 788}, {"handshake": ""}, {"cwd_ino": True}):
        actual = {**expected, **override}
        assert p.evaluate_observation(expected, actual) is False
    assert p.evaluate_observation(expected, {"cwd_dev": 123}) is False


def test_non_mac_refuses_without_making_output(tmp_path):
    if sys.platform == "darwin":
        # The real native invocation is explicit and never occurs during pytest collection.
        assert RUNNER.read_text().index('if sys.platform != "darwin"') < RUNNER.read_text().index("tempfile.TemporaryDirectory")
        return
    result = subprocess.run([sys.executable, str(RUNNER), "--evidence-dir", str(tmp_path)], capture_output=True, text=True)
    assert result.returncode == 3
    assert "NOT_RUN_NON_DARWIN" in result.stdout
    assert not list(tmp_path.iterdir())


def test_no_product_execution_or_signal_fallback():
    source = NATIVE.read_text()
    runner = RUNNER.read_text()
    assert "posix_spawn_file_actions_addfchdir_np" in source
    assert "POSIX_SPAWN_SETPGROUP" in source
    assert "O_NOFOLLOW" in source
    assert "getpgid" in source
    assert "waitpid" in source
    for forbidden in ("killpg(", "preexec_fn", "os.chdir(", "/dev/fd/", "shell=True"):
        assert forbidden not in source
        assert forbidden not in runner


def test_linux_native_stub_refuses_to_claim_positive(tmp_path):
    if sys.platform == "darwin":
        assert NATIVE.is_file()
        return
    proc = subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", str(NATIVE), "-o", str(tmp_path / "stub")], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    result = subprocess.run([str(tmp_path / "stub")], capture_output=True, text=True)
    assert result.returncode == 77
    assert "C1_NOT_RUN_NON_DARWIN" in result.stderr


def test_native_helper_has_bounded_child_owner_cleanup_without_group_signals():
    source = NATIVE.read_text()
    assert "waitpid(pid, status, WNOHANG)" in source
    assert "kill(pid, SIGKILL)" in source
    assert "nanosleep(" in source
    assert "killpg(" not in source


def test_native_probe_requires_synthetic_test_marker_before_rename():
    source = NATIVE.read_text()
    assert 'openat(dirfd, "C1_TEST_MARKER"' in source
    assert 'memcmp(marker_data, "synthetic"' in source
    assert source.index('openat(dirfd, "C1_TEST_MARKER"') < source.index('rename(argv[2], held)')


def test_research_result_cannot_self_qualify_g2():
    content = RUNNER.read_text()
    assert '"g2_qualified": False' in content
    assert '"PARTIAL_NATIVE_OBSERVATION_NOT_G2"' in content
    assert "leader-exits-before-descendants" in content
