"""C2 round-2 review regression contracts. Intentionally RED before native repairs."""
from __future__ import annotations

from pathlib import Path
import importlib.util
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "tools/research/c2_pgid_anchor.c"
CHILD = ROOT / "tools/research/c2_group_child.py"
RUNNER = ROOT / "tools/research/run_c2_pgid_probe.py"
WORKFLOW = ROOT / ".github/workflows/c2-review-native.yml"
README = ROOT / "docs/research/phase2-lite-c2/README.md"


def _module():
    spec = importlib.util.spec_from_file_location("c2_round2", RUNNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_signal_paths_have_deadline_guard_before_group_signal():
    native = HELPER.read_text()
    definition = native[native.index("static int signal_owned_group("):native.index("static int bounded_reap(")]
    assert "remaining_ms(deadline_at)" in definition
    assert definition.index("remaining_ms(deadline_at)") < definition.index("kill(-owner->pid,")
    assert '"deadline-before-term"' in native
    assert "group_signals=0" in native


def test_deadline_negative_parser_requires_zero_signals_and_reaped_owner(monkeypatch, tmp_path):
    module = _module()
    expected = ("C2_EXPECTED_BLOCK phase=deadline_before_term "
                "group_signals=0 owner_reaped=1 descendant_exit=1\n")
    def report(line):
        return SimpleNamespace(returncode=0, stdout=line, stderr="")
    monkeypatch.setattr(module.subprocess, "run", lambda *a, **kw: report(expected))
    assert module.run_case(tmp_path / "helper", tmp_path, "deadline-before-term")["status"] == "EXPECTED_BLOCK"
    for corrupted in (expected.replace("group_signals=0", "group_signals=1"),
                      expected.replace("owner_reaped=1", "owner_reaped=0"),
                      expected + expected):
        monkeypatch.setattr(module.subprocess, "run", lambda *a, s=corrupted, **kw: report(s))
        assert module.run_case(tmp_path / "helper", tmp_path, "deadline-before-term")["status"] == "BLOCK"


def test_adversarial_child_traverses_normal_term_witness_branch():
    native = HELPER.read_text()
    child = CHILD.read_text()
    driver = RUNNER.read_text()
    assert '"term-false-eof"' in native
    assert '"term-false-eof"' in child
    assert '"term-false-eof"' in driver
    normal = native[native.index('} else if (strcmp(mode, "stale") == 0) {'):]
    assert 'strcmp(mode, "term-false-eof")' not in normal.split('failure = "descendant_exit_witness";', 1)[0]
    assert 'C2_BLOCK phase=descendant_exit_witness' in driver


def test_native_mutation_check_removing_normal_witness_must_be_detected():
    source = RUNNER.read_text()
    assert "run_mutation_check(" in source
    assert "C2_TEST_OMIT_POSITIVE_WITNESS" in HELPER.read_text()
    assert "C2_TEST_OMIT_POSITIVE_WITNESS" in source
    assert '"mutation_detected": True' in source


def test_failure_cleanup_tracks_known_descendant_and_owned_direct_child():
    native = HELPER.read_text()
    for fragment in ("cleanup_known_descendant(", "known_descendant_exit",
                     "owner_final_state", "cleanup_fd_count"):
        assert fragment in native
    assert 'if (owner.pid > 0 && !owner.reaped)' in native
    assert "EINTR" in native


def test_native_fault_modes_and_bounded_eintr_retries():
    native = HELPER.read_text()
    driver = RUNNER.read_text()
    for mode in ("fault-register", "fault-before-arm", "fault-after-arm",
                 "fault-waitpid-eintr", "fault-kevent-eintr"):
        assert '"'+mode+'"' in native
        assert '"'+mode+'"' in driver
    assert "waitpid_with_eintr_retry(" in native
    assert "kevent_with_eintr_retry(" in native
    assert "cleanup_incomplete" in driver


def test_six_case_documentation_and_native_suite():
    readme = README.read_text()
    flow = WORKFLOW.read_text()
    assert "six-case" in readme
    assert "close-stdout" in readme
    assert "deadline-before-term" in flow
    assert "term-false-eof" in flow
    assert "run_mutation_check" in flow
