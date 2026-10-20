"""C2 independent-review regression contracts: SIGCHLD may not auto-reap."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "tools/research/c2_pgid_anchor.c"
PROBE = ROOT / "tools/research/c2_sigchld_probe.c"
DRIVER = ROOT / "tools/research/run_c2_sigchld_probe.py"


def test_c2_owner_explicitly_sets_waitable_sigchld():
    source = NATIVE.read_text(encoding="utf-8")
    assert "configure_waitable_sigchld(" in source
    assert "sigaction(SIGCHLD," in source
    assert "SIG_DFL" in source
    assert "SA_NOCLDWAIT" in source
    assert source.index("configure_waitable_sigchld(") < source.index("posix_spawn(&owner.pid")


def test_native_injection_covers_ignore_and_nocldwait():
    source = PROBE.read_text(encoding="utf-8")
    for marker in ("SIG_IGN", "SA_NOCLDWAIT", "SIG_DFL", "waitpid(",
                   "DEFAULT", "IGNORE", "NOCLDWAIT", "C2_SIGCHLD_PASS"):
        assert marker in source


def test_sigchld_native_driver_refuses_linux_as_not_run():
    source = DRIVER.read_text(encoding="utf-8")
    assert 'if sys.platform != "darwin":' in source
    assert "NOT_RUN_NON_DARWIN" in source
    assert "g2_qualified" in source
    assert "C2_SIGCHLD_PASS" in source
