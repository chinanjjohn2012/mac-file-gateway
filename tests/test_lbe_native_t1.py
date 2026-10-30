"""Approved T1 only: natural-exit Python child in hosted disposable macOS CI.

This source is skipped by default; no existing F1 public Exec gate changes.
No shell, network fixtures, user Mac/Tunnel, process/group signal or T2.
All real commands are fixed local Python scripts under runner scratch.
"""
from __future__ import annotations

import os
from pathlib import Path
import time

import pytest

from gateway.core import GatewayError
from gateway.exec_state import ExecStateStore
from gateway.lbe_native_launcher import make_trusted_lbe_launcher
from gateway.lbe_plan import prepare_lbe_work_plan
from gateway.lbe_worker import LbeWorker, LbeWorkerError
from gateway.workspaces import ActiveRuntimeInventory, WorkspaceService
from gateway.workspaces_config import parse_workspace_config

_GRANT = "PR101_R002_MACOS15_ARM64_DISPOSABLE_PYTHON_ONLY"


@pytest.fixture
def native_scene(tmp_path: Path):
    if os.environ.get("LBE_NATIVE_T1_AUTHORIZED") != _GRANT:
        pytest.skip("T1 NOT_RUN outside specifically authorized hosted macOS job")
    if (os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("RUNNER_OS") != "macOS"
            or os.environ.get("RUNNER_ARCH") != "ARM64"):
        pytest.fail("T1 runner is not an authorized hosted macOS ARM64")
    runner_temp = Path(os.environ["RUNNER_TEMP"]).resolve()
    assert tmp_path.resolve().is_relative_to(runner_temp)

    root = tmp_path / "project-a"
    work = root / "python-project"
    work.mkdir(parents=True)
    (work / "ok.py").write_text(
        "import sys\nprint('T1_ORIGINAL_STDOUT')\n"
        "print('T1_ORIGINAL_STDERR', file=sys.stderr)\n"
    )
    (work / "fail.py").write_text(
        "import sys\nprint('T1_EXIT_NONZERO')\nsys.exit(7)\n"
    )
    (work / "bounded_sleep.py").write_text(
        "import time\nprint('T1_SAFE_SLEEP')\ntime.sleep(1.5)\n"
    )
    private = tmp_path / "private-control"
    private.mkdir(mode=0o700)
    private.chmod(0o700)
    runtime = tmp_path / "runtime-inventory"
    runtime.mkdir()
    state = ExecStateStore(private / "exec-state",
                           workspace_roots=(str(root),))
    assert state.durability_state == "healthy"
    state.close()
    config = {
        "schema_version": 2,
        "server": {"port": 8765, "transport": "http"},
        "workspaces": {
            "a": {"root": str(root),
                  "exec": {"paths": ["python-project"], "runners": []}},
        },
    }
    svc = WorkspaceService(
        parse_workspace_config(config), config_dir=private,
        inventory=ActiveRuntimeInventory(paths=(runtime,)))
    try:
        assert svc.info()["exec_policy"]["durability_state"] == "healthy"
        yield svc, root
    finally:
        svc.close()


def _internal(svc):
    ctx = svc.require_exec("a")
    worker = LbeWorker(
        svc._lbe_owner, launcher=make_trusted_lbe_launcher(ctx),
    )
    return ctx, worker


def _plan(ctx, script, timeout=5):
    return prepare_lbe_work_plan(
        ctx, cwd="python-project", argv=["python", script],
        timeout_seconds=timeout,
    )


@pytest.mark.parametrize("script,code,expected", [
    ("ok.py", 0, "T1_ORIGINAL_STDOUT"),
    ("fail.py", 7, "T1_EXIT_NONZERO"),
])
def test_original_exit_and_redacted_bounded_pipes(
    native_scene, script, code, expected,
):
    svc, root = native_scene
    ctx, worker = _internal(svc)
    result = worker.run(_plan(ctx, script))
    assert result["status"] == "exited"
    assert result["executed"] is True
    assert result["exit_code"] == code
    assert result["timed_out"] is False
    assert expected in result["stdout"]
    assert result["output_complete"] is True
    assert result["cleanup_proven"] is False
    assert result["full_descendant_tree_clean"] == "not_proven"
    assert result["process_may_be_running"] is True
    assert svc._lbe_owner.snapshot()["reserved_slots"] == 0
    assert not (root / "python-project" / "unexpected-child").exists()


def test_timeout_retains_slot_until_natural_direct_exit(native_scene):
    svc, _ = native_scene
    ctx, worker = _internal(svc)
    start = time.monotonic()
    result = worker.run(_plan(ctx, "bounded_sleep.py", timeout=1))
    assert time.monotonic() - start < 4.5
    assert result["status"] == "timed_out"
    assert result["executed"] is True
    assert result["exit_code"] is None
    assert result["timed_out"] is True
    assert result["process_may_be_running"] is True
    assert result["cleanup_proven"] is False
    if svc._lbe_owner.snapshot()["reserved_slots"] == 1:
        with pytest.raises(LbeWorkerError) as error:
            worker.run(_plan(ctx, "ok.py"))
        assert error.value.code == "busy"
    deadline = time.monotonic() + 4
    while svc._lbe_owner.snapshot()["reserved_slots"] and time.monotonic() < deadline:
        time.sleep(0.01)
    assert svc._lbe_owner.snapshot()["reserved_slots"] == 0
    assert svc._lbe_owner.snapshot()["unavailable"] is False


def test_invalid_relative_script_has_zero_launch(native_scene):
    svc, root = native_scene
    ctx, _worker = _internal(svc)
    with pytest.raises(GatewayError):
        _plan(ctx, "../escape.py")
    assert svc._lbe_owner.snapshot()["reserved_slots"] == 0
    assert svc.info()["exec_policy"]["durability_state"] == "healthy"
    assert not (root / "escape.py").exists()
