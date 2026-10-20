"""C2 T02/T03 RED contracts: descendant exit ≠ inherited stdout EOF."""
from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "tools/research/c2_pgid_anchor.c"
CHILD = ROOT / "tools/research/c2_group_child.py"
DRIVER = ROOT / "tools/research/run_c2_pgid_probe.py"
WORKFLOW = ROOT / ".github/workflows/c2-review-native.yml"


def _driver():
    spec = importlib.util.spec_from_file_location("c2_exit_probe", DRIVER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_native_descendant_exit_witness_is_required():
    source = HELPER.read_text()
    for symbol in ("#include <sys/event.h>", "EVFILT_PROC", "NOTE_EXIT",
                   "register_descendant_exit(", "wait_descendant_exit(", "kevent("):
        assert symbol in source
    assert source.index("wait_descendant_exit(") < source.index('printf("C2_RESULT')


def test_descendant_lifetime_begins_after_witness_registration():
    native = HELPER.read_text()
    child = CHILD.read_text()
    assert 'write(gate[1], "A", 1)' in native
    assert 'os.read(0, 1) != b"A"' in child
    assert native.index("register_descendant_exit(") < native.index('write(gate[1], "A", 1)')
    assert native.index("read_ready(output[0]") < native.index('write(gate[1], "A", 1)')


def test_adversarial_descendant_can_close_stdout_while_alive():
    native = HELPER.read_text()
    child = CHILD.read_text()
    runner = DRIVER.read_text()
    assert '"close-stdout"' in native and '"close-stdout"' in child
    assert '"close-stdout"' in runner
    assert "os.close(1)" in child
    assert "signal.SIG_IGN" in child
    assert "descendant_still_alive" in native
    assert "EXPECTED_BLOCK" in runner


def test_fake_eof_without_native_exit_witness_cannot_be_success(monkeypatch, tmp_path):
    module = _driver()
    # The adversarial helper must emit this *exact* independent negative observation.
    exact = ("C2_EXPECTED_BLOCK phase=descendant_still_alive "
             "stdout_eof=1 witness_before_eof=0 descendant_alive=1\n")
    def fake(**overrides):
        item = dict(returncode=0, stdout=exact, stderr="")
        item.update(overrides)
        return SimpleNamespace(**item)
    monkeypatch.setattr(module.subprocess, "run", lambda *a, **kw: fake())
    assert module.run_case(tmp_path / "helper", tmp_path, "close-stdout")["status"] == "EXPECTED_BLOCK"
    for forged in (exact + exact, exact.replace("descendant_alive=1", "descendant_alive=0"),
                   exact.replace("witness_before_eof=0", "witness_before_eof=1"),
                   "C2_RESULT mode=term term=1 kill=0 refused=0 held=1 reaped=1 drain=1 descendant_verified=1\n"):
        monkeypatch.setattr(module.subprocess, "run", lambda *a, s=forged, **kw: fake(stdout=s))
        assert module.run_case(tmp_path / "helper", tmp_path, "close-stdout")["status"] == "BLOCK"


def test_g2_remains_block_and_review_workflow_checks_adversarial_case():
    driver = DRIVER.read_text()
    flow = WORKFLOW.read_text()
    assert '"g2_qualified": False' in driver
    assert "PARTIAL_NATIVE_OBSERVATION_NOT_G2" in driver
    assert '"EXPECTED_BLOCK"' in flow
    assert '"close-stdout"' in flow
    assert "persist-credentials: false" in flow


def test_c2_readme_does_not_claim_eof_or_pgid_proves_complete_cleanup():
    readme = (ROOT / "docs/research/phase2-lite-c2/README.md").read_text()
    assert "independent descendant exit" in readme
    assert "G2 BLOCK" in readme
