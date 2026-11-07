"""Safe T0 of actual private WorkspaceService D4 R003 fixture preflight.

The tests never start Go/Pipenv/Python children or create a new public
authorization. A source-only candidate cannot change F1 positive denial.
"""
from __future__ import annotations

from dataclasses import replace
import os
from pathlib import Path
import subprocess
import threading

import pytest

from gateway.core import GatewayError
from gateway.exec_state import ExecStateStore
from gateway.lbe_product_fixture import D4FixtureDenied, check_d4_r003_fixture
from gateway.workspaces import ActiveRuntimeInventory, WorkspaceService
from gateway.workspaces_config import parse_workspace_config


_ROWS = (
    ("py-direct", ["python", "-m", "pytest", "-q"]),
    ("py-direct", ["python", "-m", "compileall", "-q", "./src"]),
    ("py-pipenv", ["python", "-m", "pytest", "-q"]),
    ("go-project", ["go", "test", "./..."]),
    ("go-project", ["go", "vet", "./..."]),
    ("go-project", ["go", "build", "-o", "bin/app", "./cmd/app"]),
)


@pytest.fixture
def product_service(tmp_path: Path):
    workspace = tmp_path / "projects" / "a"
    workspace.mkdir(parents=True)
    (workspace / "py-direct" / "src").mkdir(parents=True)
    (workspace / "py-direct" / "src" / "main.py").write_bytes(b"x = 123\n")
    pipenv = workspace / "py-pipenv"
    (pipenv / ".venv" / "bin").mkdir(parents=True)
    (pipenv / "Pipfile").write_bytes(b"[packages]\n")
    (pipenv / "Pipfile.lock").write_bytes(b"{}\n")
    (pipenv / ".venv" / "pyvenv.cfg").write_bytes(b"home = private\n")
    (pipenv / ".venv" / "bin" / "python").write_bytes(b"fixed test-only bytes\n")
    go = workspace / "go-project"
    (go / "cmd" / "app").mkdir(parents=True)
    (go / "cmd" / "app" / "main.go").write_bytes(b"package main\nfunc main() {}\n")
    (go / "go.mod").write_bytes(b"module firstparty.test/app\ngo 1.27\n")
    (go / "bin").mkdir()
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    private.chmod(0o700)
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    store = ExecStateStore(private / "exec-state",
                           workspace_roots=(str(workspace),))
    store.close()
    config = {
        "schema_version": 2,
        "server": {"port": 8765, "transport": "http"},
        "workspaces": {
            "a": {
                "root": str(workspace),
                "exec": {
                    "paths": ["py-direct", "py-pipenv", "go-project"],
                    "runners": ["py-pipenv=pipenv"],
                },
            },
        },
    }
    service = WorkspaceService(
        parse_workspace_config(config), config_dir=private,
        inventory=ActiveRuntimeInventory(paths=(runtime,)))
    try:
        yield service, workspace
    finally:
        service.close()


@pytest.mark.parametrize("cwd,argv", _ROWS)
def test_d4_actual_service_preflight_checks_six_exact_inputs(
        product_service, monkeypatch, cwd, argv):
    service, root = product_service

    def forbidden(*_args, **_kwargs):
        raise AssertionError("D4 SAFE T0 may not spawn or signal")

    with monkeypatch.context() as m:
        m.setattr(subprocess, "Popen", forbidden)
        m.setattr(os, "kill", forbidden)
        m.setattr(os, "killpg", forbidden, raising=False)
        candidate = service._prepare_d4_r003_fixture_candidate(
            "a", cwd, argv, timeout_seconds=120)
        assert candidate.native_launch_allowed is False
        assert candidate.actual_loaded_sources_proven is False
        assert candidate.runner_qualified is False
        assert candidate.resource_enforcement_proven is False
        assert candidate.owner_approval_attested is False
        assert candidate.status == (
            "SELECTED_FIRST_PARTY_SOURCE_ONLY_NO_NATIVE_AUTHORITY")
        assert candidate.plan.workspace == "a"
        assert candidate.plan.cwd == cwd
        assert candidate.source_sha256
        assert all(len(digest) == 64
                   for _, digest in candidate.source_sha256)
        if cwd == "py-pipenv":
            assert candidate.plan.runner == "pipenv"
            assert candidate.plan.requested_argv[0] == "python"
            assert candidate.plan.effective_argv[:2] == ("pipenv", "run")
        else:
            assert candidate.plan.runner == "direct"
        if argv[:3] == ["python", "-m", "compileall"]:
            assert candidate.plan.effective_argv[-1] == "./src"
            assert candidate.source_sha256[0][0] == "py-direct/src/main.py"
        if argv[:2] == ["go", "build"]:
            assert candidate.plan.planned_go_output == "go-project/bin/app"

        # Shared source preview is nonspawning, but no positive product grant.
        preview = service.invoke_exec("a", cwd, argv, dry_run=True)
        assert preview["status"] == "preview"
        assert preview["executed"] is False
        assert tuple(preview["effective_argv"]) == candidate.plan.effective_argv
        with pytest.raises(GatewayError) as denied:
            service.invoke_exec("a", cwd, argv, dry_run=False)
        assert denied.value.code == "exec_cleanup_proof_required"
    assert not (root / "go-project" / "bin" / "app").exists()


@pytest.mark.parametrize("bad", [
    ["python", "-m", "compileall"],
    ["python", "-m", "compileall", "-q"],
    ["python", "-m", "compileall", "-q", "../outside"],
    ["python", "-m", "compileall", "-q", "/tmp/outside"],
    ["python", "-m", "compileall", "-q", "./src", "../outside"],
    ["python", "-m", "compileall", "-b", "-q", "./src"],
    ["python", "-c", "x=1"],
    ["pipenv", "run", "python", "-m", "pytest", "-q"],
])
def test_d4_service_candidate_rejects_outside_or_client_pipenv(
        product_service, bad):
    service, _root = product_service
    with pytest.raises((D4FixtureDenied, GatewayError)):
        service._prepare_d4_r003_fixture_candidate("a", "py-direct", bad)


@pytest.mark.parametrize("argv", [
    ["go", "run", "./cmd/app"],
    ["go", "build", "-toolexec=/outside/tool", "./cmd/app"],
    ["go", "build", "-o", "../outside", "./cmd/app"],
    ["go", "build", "-o=bin/app", "./cmd/app"],
    ["go", "test", "-v", "./..."],
])
def test_d4_go_command_matrix_cannot_be_extended_by_public_argv(
        product_service, argv):
    service, _root = product_service
    with pytest.raises((D4FixtureDenied, GatewayError)):
        service._prepare_d4_r003_fixture_candidate("a", "go-project", argv)


@pytest.mark.parametrize("mutation", ["src_symlink", "file_symlink",
                                      "extra_subdir", "world_writable",
                                      "hardlink", "unqualified_cache"])
def test_d4_compileall_rejects_unsafe_selected_first_party_sources(
        product_service, mutation):
    service, root = product_service
    src = root / "py-direct" / "src"
    if mutation == "src_symlink":
        (src / "main.py").unlink()
        src.rmdir()
        (root / "py-direct" / "outside").mkdir()
        src.symlink_to("outside", target_is_directory=True)
    elif mutation == "file_symlink":
        (src / "linked.py").symlink_to("main.py")
    elif mutation == "extra_subdir":
        (src / "unknown").mkdir()
    elif mutation == "world_writable":
        (src / "main.py").chmod(0o666)
    elif mutation == "hardlink":
        os.link(src / "main.py", src / "second.py")
    else:
        cache = src / "__pycache__"
        cache.mkdir()
        (cache / "main.cpython-313.pyc").write_bytes(b"unknown bytecode")
    with pytest.raises((D4FixtureDenied, GatewayError)):
        service._prepare_d4_r003_fixture_candidate(
            "a", "py-direct",
            ["python", "-m", "compileall", "-q", "./src"])


@pytest.mark.parametrize("mutation", ["venv_pointer", "venv_symlink",
                                      "missing_lock", "linked_python"])
def test_d4_pipenv_source_selection_rejects_indirection(
        product_service, mutation):
    service, root = product_service
    project = root / "py-pipenv"
    if mutation == "venv_pointer":
        import shutil
        shutil.rmtree(project / ".venv")
        (project / ".venv").write_text("../other-env\n")
    elif mutation == "venv_symlink":
        import shutil
        shutil.rmtree(project / ".venv")
        (project / ".venv").symlink_to(root / "py-direct", target_is_directory=True)
    elif mutation == "missing_lock":
        (project / "Pipfile.lock").unlink()
    else:
        python = project / ".venv" / "bin" / "python"
        python.unlink()
        python.symlink_to("/bin/true")
    with pytest.raises((D4FixtureDenied, GatewayError)):
        service._prepare_d4_r003_fixture_candidate(
            "a", "py-pipenv", ["python", "-m", "pytest", "-q"])


@pytest.mark.parametrize("mutation", ["missing_module", "linked_go_source",
                                      "linked_bin"])
def test_d4_go_source_selection_rejects_unowned_or_missing_paths(
        product_service, mutation):
    service, root = product_service
    project = root / "go-project"
    if mutation == "missing_module":
        (project / "go.mod").unlink()
    elif mutation == "linked_go_source":
        os.link(project / "cmd" / "app" / "main.go",
                project / "cmd" / "app" / "duplicate.go")
    else:
        (project / "bin").rmdir()
        (project / "bin").symlink_to(root / "py-direct", target_is_directory=True)
    with pytest.raises((D4FixtureDenied, GatewayError)):
        service._prepare_d4_r003_fixture_candidate(
            "a", "go-project", ["go", "test", "./..."])


def test_d4_preflight_refuses_wrong_service_scope_and_forged_plan(
        product_service):
    service, _root = product_service
    with pytest.raises(GatewayError) as wrong_workspace:
        service._prepare_d4_r003_fixture_candidate(
            "absent", "py-direct", ["python", "-m", "pytest", "-q"])
    assert wrong_workspace.value.code == "workspace_not_found"
    c = service._prepare_d4_r003_fixture_candidate(
        "a", "py-direct", ["python", "-m", "pytest", "-q"])
    ctx = service.get("a")
    with pytest.raises(D4FixtureDenied):
        check_d4_r003_fixture(ctx, replace(c.plan, workspace="other"))
    with pytest.raises(D4FixtureDenied):
        check_d4_r003_fixture(ctx, replace(c.plan, timeout_seconds=121))
    with pytest.raises(D4FixtureDenied):
        check_d4_r003_fixture(ctx, replace(c.plan, runner_project="go-project"))


def test_d4_no_private_exec_state_disallows_candidate_even_if_fixture_exists(
        product_service):
    service, _root = product_service
    service._exec_state.close()
    service._exec_state = None
    with pytest.raises(GatewayError) as exc:
        service._prepare_d4_r003_fixture_candidate(
            "a", "py-direct", ["python", "-m", "pytest", "-q"])
    assert exc.value.code == "exec_state_unavailable"

def _no_child_launcher(_plan):
    from gateway.lbe_worker import LbeNoChildStarted
    raise LbeNoChildStarted("safe test-only negative launcher")


def test_d4_one_use_marker_consumed_before_any_possible_child(product_service):
    from gateway.lbe_direct_owner import DirectChildOwner
    from gateway.lbe_product_fixture import D4OneUseAttemptMarker
    from gateway.lbe_worker import LbeWorker, LbeWorkerError

    service, _root = product_service
    candidate = service._prepare_d4_r003_fixture_candidate(
        "a", "py-direct", ["python", "-m", "pytest", "-q"])
    marker = D4OneUseAttemptMarker(candidate)
    worker = LbeWorker(DirectChildOwner(), launcher=_no_child_launcher)
    first = worker.run(candidate.plan, product_attempt=marker)
    assert first["status"] == "launch_failed"
    assert first["executed"] is False
    with pytest.raises(LbeWorkerError) as duplicate:
        worker.run(candidate.plan, product_attempt=marker)
    assert duplicate.value.code == "attempt_replay_denied"


def test_d4_one_use_marker_denies_concurrent_same_attempt(product_service):
    from gateway.lbe_direct_owner import DirectChildOwner
    from gateway.lbe_product_fixture import D4OneUseAttemptMarker
    from gateway.lbe_worker import LbeWorker, LbeWorkerError

    service, _root = product_service
    candidate = service._prepare_d4_r003_fixture_candidate(
        "a", "py-direct", ["python", "-m", "pytest", "-q"])
    marker = D4OneUseAttemptMarker(candidate)
    worker = LbeWorker(DirectChildOwner(), launcher=_no_child_launcher)
    gate = threading.Barrier(2)
    outcomes = []

    def compete():
        gate.wait()
        try:
            outcomes.append(worker.run(
                candidate.plan, product_attempt=marker)["status"])
        except LbeWorkerError as exc:
            outcomes.append(exc.code)

    left = threading.Thread(target=compete)
    right = threading.Thread(target=compete)
    left.start()
    right.start()
    left.join(timeout=3)
    right.join(timeout=3)
    assert not left.is_alive() and not right.is_alive()
    assert sorted(outcomes) == ["attempt_replay_denied", "launch_failed"]


def test_d4_one_use_marker_burns_on_mismatch_or_cancel(product_service):
    from gateway.lbe_direct_owner import DirectChildOwner
    from gateway.lbe_product_fixture import D4OneUseAttemptMarker
    from gateway.lbe_worker import LbeWorker, LbeWorkerError

    service, _root = product_service
    candidate = service._prepare_d4_r003_fixture_candidate(
        "a", "py-direct", ["python", "-m", "pytest", "-q"])
    worker = LbeWorker(DirectChildOwner(), launcher=_no_child_launcher)
    marker = D4OneUseAttemptMarker(candidate)
    with pytest.raises(LbeWorkerError) as mismatch:
        worker.run(replace(candidate.plan, timeout_seconds=119),
                   product_attempt=marker)
    assert mismatch.value.code == "attempt_replay_denied"
    with pytest.raises(LbeWorkerError) as replay:
        worker.run(candidate.plan, product_attempt=marker)
    assert replay.value.code == "attempt_replay_denied"

    separate = D4OneUseAttemptMarker(candidate)
    cancelled = threading.Event()
    cancelled.set()
    with pytest.raises(LbeWorkerError) as stopped:
        worker.run(candidate.plan, product_attempt=separate,
                   cancelled=cancelled)
    assert stopped.value.code == "waiter_disconnected"
    with pytest.raises(LbeWorkerError) as replay_after_cancel:
        worker.run(candidate.plan, product_attempt=separate)
    assert replay_after_cancel.value.code == "attempt_replay_denied"


def test_d4_attempt_marker_not_a_client_or_native_authority(product_service):
    from gateway.lbe_direct_owner import DirectChildOwner
    from gateway.lbe_product_fixture import D4OneUseAttemptMarker
    from gateway.lbe_worker import LbeWorker, LbeWorkerError

    service, _root = product_service
    candidate = service._prepare_d4_r003_fixture_candidate(
        "a", "go-project", ["go", "test", "./..."])
    with pytest.raises(D4FixtureDenied):
        D4OneUseAttemptMarker(object())
    worker = LbeWorker(DirectChildOwner(), launcher=_no_child_launcher)
    with pytest.raises(LbeWorkerError) as bad_input:
        worker.run(candidate.plan, product_attempt=object())
    assert bad_input.value.code == "invalid_argument"
    with pytest.raises(GatewayError) as public:
        service.invoke_exec("a", "go-project", ["go", "test", "./..."],
                            dry_run=False)
    assert public.value.code == "exec_cleanup_proof_required"
