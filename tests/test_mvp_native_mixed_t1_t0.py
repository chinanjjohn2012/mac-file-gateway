"""PR114 native-mixed approval guard and receipt predicates: SAFE T0 only."""
from __future__ import annotations

import subprocess
import pytest
from tools.mvp_native_mixed_t1 import require_approved_runner, _native_exit


def test_mixed_gate_denies_outside_owner_label_before_running_git(monkeypatch):
    monkeypatch.setenv("GITHUB_ACTIONS", "false")
    monkeypatch.setattr(
        subprocess, "check_output",
        lambda *_a, **_k: pytest.fail("unapproved runner reached Git"),
    )
    with pytest.raises(RuntimeError, match="outside exact approved"):
        require_approved_runner()


def test_mixed_native_exit_never_accepts_fault_as_clean_result():
    healthy = {
        "executed": True, "status": "exited", "exit_code": 0,
        "output_complete": True, "pipe_reader_failed": False,
        "pipe_reader_finished": True,
        "stdout_truncated": False, "stderr_truncated": False,
        "cleanup_proven": False,
        "full_descendant_tree_clean": "not_proven",
    }
    owner = {"unavailable": False, "closing": False, "reserved_slots": 0}
    assert _native_exit(healthy, owner) is None
    for defect in (
        {"pipe_reader_failed": True}, {"pipe_reader_finished": False},
        {"output_complete": False},
        {"exit_code": 1}, {"cleanup_proven": True},
        {"full_descendant_tree_clean": "proven"},
    ):
        with pytest.raises(AssertionError):
            _native_exit({**healthy, **defect}, owner)
    with pytest.raises(AssertionError):
        _native_exit(healthy, {**owner, "unavailable": True})
