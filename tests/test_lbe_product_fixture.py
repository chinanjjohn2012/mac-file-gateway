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
    (pipenv / "Pipfile.lock").write_bytes(
        b'{"_meta":{"hash":{"sha256":"' + b"a" * 64 + b'"}}}\n')
    (pipenv / ".venv" / "pyvenv.cfg").write_bytes(b"home = private\n")
    (pipenv / ".venv" / "bin" / "python").write_bytes(b"fixed test-only bytes\n")
    (pipenv / ".venv" / "bin" / "python").chmod(0o700)
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
    marker = D4OneUseAttemptMarker(candidate, service.get("a"))
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
    marker = D4OneUseAttemptMarker(candidate, service.get("a"))
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
    marker = D4OneUseAttemptMarker(candidate, service.get("a"))
    with pytest.raises(LbeWorkerError) as mismatch:
        worker.run(replace(candidate.plan, timeout_seconds=119),
                   product_attempt=marker)
    assert mismatch.value.code == "attempt_replay_denied"
    with pytest.raises(LbeWorkerError) as replay:
        worker.run(candidate.plan, product_attempt=marker)
    assert replay.value.code == "attempt_replay_denied"

    separate = D4OneUseAttemptMarker(candidate, service.get("a"))
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
        D4OneUseAttemptMarker(object(), service.get("a"))
    worker = LbeWorker(DirectChildOwner(), launcher=_no_child_launcher)
    with pytest.raises(LbeWorkerError) as bad_input:
        worker.run(candidate.plan, product_attempt=object())
    assert bad_input.value.code == "invalid_argument"
    with pytest.raises(GatewayError) as public:
        service.invoke_exec("a", "go-project", ["go", "test", "./..."],
                            dry_run=False)
    assert public.value.code == "exec_cleanup_proof_required"

@pytest.mark.parametrize("cwd,argv,excluded", [
    ("py-direct", ["python", "-m", "compileall", "-q", "./src"],
     ("py-direct", "src", "main.py")),
    ("py-pipenv", ["python", "-m", "pytest", "-q"],
     ("py-pipenv", "Pipfile.lock")),
    ("go-project", ["go", "test", "./..."],
     ("go-project", "go.mod")),
])
@pytest.mark.parametrize("blocked_answer", [False, 1, "yes"])
def test_d4_first_party_candidate_respects_workspace_source_excludes(
        product_service, monkeypatch, cwd, argv, excluded, blocked_answer):
    service, _root = product_service
    ctx = service.get("a")
    previous = ctx.gateway._allowed
    called = []

    def selective_policy(parts, *, is_file):
        if tuple(parts) == excluded:
            called.append((tuple(parts), is_file))
            return blocked_answer
        return previous(parts, is_file=is_file)

    with monkeypatch.context() as m:
        m.setattr(ctx.gateway, "_allowed", selective_policy)
        with pytest.raises(GatewayError) as exc:
            service._prepare_d4_r003_fixture_candidate("a", cwd, argv)
        assert exc.value.code == "command_not_allowed"
    assert called == [(excluded, False)]
    assert service.info()["exec_policy"]["available"] is False


@pytest.mark.parametrize("cwd,argv", _ROWS)
def test_d4_service_bound_attempt_rechecks_all_six_without_native(
        product_service, monkeypatch, cwd, argv):
    from gateway.lbe_direct_owner import DirectChildOwner
    from gateway.lbe_worker import LbeWorker

    service, _root = product_service
    candidate, marker = service._prepare_d4_r003_attempt(
        "a", cwd, argv, timeout_seconds=120)
    assert len(candidate.source_sha256) == len(candidate.source_identity)
    assert all(len(identity) == 8 for _, identity in candidate.source_identity)

    def never_popen(*args, **kwargs):
        raise AssertionError("D4 SAFE T0 cannot launch any native child")

    with monkeypatch.context() as m:
        m.setattr(subprocess, "Popen", never_popen)
        worker = LbeWorker(DirectChildOwner(), launcher=_no_child_launcher)
        result = worker.run(candidate.plan, product_attempt=marker)
    assert result["status"] == "launch_failed"
    assert result["executed"] is False
    assert result["cleanup_proven"] is False


@pytest.mark.parametrize("cwd,argv,relative", [
    ("py-direct", ["python", "-m", "compileall", "-q", "./src"], "src/main.py"),
    ("py-pipenv", ["python", "-m", "pytest", "-q"], "Pipfile.lock"),
    ("go-project", ["go", "test", "./..."], "go.mod"),
    ("go-project", ["go", "build", "-o", "bin/app", "./cmd/app"], "cmd/app/main.go"),
])
def test_d4_bound_attempt_rejects_modified_source_before_launcher(
        product_service, cwd, argv, relative):
    from gateway.lbe_direct_owner import DirectChildOwner
    from gateway.lbe_worker import LbeWorker, LbeWorkerError

    service, root = product_service
    candidate, marker = service._prepare_d4_r003_attempt("a", cwd, argv)
    target = root / cwd / relative
    old_bytes = target.read_bytes()
    target.write_bytes(old_bytes + b"# stale source\n")
    launched = []
    def forbidden(_plan):
        launched.append(True)
        raise AssertionError("stale source must not reach launcher")

    worker = LbeWorker(DirectChildOwner(), launcher=forbidden)
    with pytest.raises(LbeWorkerError) as exc:
        worker.run(candidate.plan, product_attempt=marker)
    assert exc.value.code == "attempt_replay_denied"
    assert launched == []
    # Source drift burns the exact attempt once; restoring bytes cannot
    # reuse its previous authorization candidate or child reservation.
    target.write_bytes(old_bytes)
    with pytest.raises(LbeWorkerError) as replay:
        worker.run(candidate.plan, product_attempt=marker)
    assert replay.value.code == "attempt_replay_denied"


def test_d4_source_identity_rejects_in_place_same_byte_inode_replacement(
        product_service):
    from gateway.lbe_direct_owner import DirectChildOwner
    from gateway.lbe_worker import LbeWorker, LbeWorkerError

    service, root = product_service
    candidate, marker = service._prepare_d4_r003_attempt(
        "a", "py-direct",
        ["python", "-m", "compileall", "-q", "./src"])
    selected = root / "py-direct" / "src" / "main.py"
    before = selected.read_bytes()
    selected.unlink()
    selected.write_bytes(before)
    launched = []
    def forbidden(_plan):
        launched.append(True)
        raise AssertionError("source inode replacement must not launch")
    with pytest.raises(LbeWorkerError) as exc:
        LbeWorker(DirectChildOwner(), launcher=forbidden).run(
            candidate.plan, product_attempt=marker)
    assert exc.value.code == "attempt_replay_denied"
    assert launched == []


def test_d4_marker_fails_closed_on_wrong_workspace_and_wrong_context(
        product_service):
    from gateway.lbe_product_fixture import D4OneUseAttemptMarker
    service, _root = product_service
    candidate = service._prepare_d4_r003_fixture_candidate(
        "a", "py-direct", ["python", "-m", "pytest", "-q"])
    with pytest.raises(D4FixtureDenied):
        D4OneUseAttemptMarker(candidate, object())
    with pytest.raises(D4FixtureDenied):
        D4OneUseAttemptMarker(replace(candidate, source_identity=()),
                             service.get("a"))
    with pytest.raises(D4FixtureDenied):
        D4OneUseAttemptMarker(replace(candidate, status="NATIVE_AUTHORIZED"),
                             service.get("a"))


def test_d4_marker_recomputes_plan_selection_and_burns_on_policy_drift(
        product_service, monkeypatch):
    from gateway.lbe_direct_owner import DirectChildOwner
    from gateway.lbe_worker import LbeWorker, LbeWorkerError

    service, _root = product_service
    candidate, marker = service._prepare_d4_r003_attempt(
        "a", "py-direct", ["python", "-m", "pytest", "-q"])
    ctx = service.get("a")
    original = ctx.gateway._allowed
    def changed(parts, *, is_file):
        if tuple(parts) == ("py-direct", "src", "main.py"):
            return False
        return original(parts, is_file=is_file)
    launched = []
    def forbidden(_plan):
        launched.append(True)
        raise AssertionError("policy drift cannot reach launcher")
    with monkeypatch.context() as m:
        m.setattr(ctx.gateway, "_allowed", changed)
        with pytest.raises(LbeWorkerError) as exc:
            LbeWorker(DirectChildOwner(), launcher=forbidden).run(
                candidate.plan, product_attempt=marker)
    assert exc.value.code == "attempt_replay_denied"
    assert launched == []


def test_d4_python_pytest_inventory_covers_nested_first_party_test_inputs(
        product_service):
    from gateway.lbe_direct_owner import DirectChildOwner
    from gateway.lbe_worker import LbeWorker, LbeWorkerError

    service, root = product_service
    py = root / "py-direct"
    (py / "src" / "pkg").mkdir()
    (py / "src" / "pkg" / "__init__.py").write_bytes(b"value=7\n")
    (py / "tests").mkdir()
    (py / "tests" / "test_runtime.py").write_bytes(b"def test_x(): assert True\n")
    (py / "conftest.py").write_bytes(b"from pathlib import Path\n")
    c, attempt = service._prepare_d4_r003_attempt(
        "a", "py-direct", ["python", "-m", "pytest", "-q"])
    names = {name for name, _digest in c.source_sha256}
    assert names == {
        "py-direct/src/main.py",
        "py-direct/src/pkg/__init__.py",
        "py-direct/tests/test_runtime.py",
        "py-direct/conftest.py",
    }
    assert len(c.source_identity) == 4
    (py / "tests" / "test_runtime.py").write_bytes(b"def test_x(): assert False\n")
    spawned = []
    def must_not_run(_plan):
        spawned.append(True)
        raise AssertionError("new test input must block original child")
    with pytest.raises(LbeWorkerError) as denied:
        LbeWorker(DirectChildOwner(), launcher=must_not_run).run(
            c.plan, product_attempt=attempt)
    assert denied.value.code == "attempt_replay_denied"
    assert spawned == []


def test_d4_go_recursive_package_inventory_covers_go_test_and_build(
        product_service):
    from gateway.lbe_direct_owner import DirectChildOwner
    from gateway.lbe_worker import LbeWorker, LbeWorkerError

    service, root = product_service
    project = root / "go-project"
    (project / "pkg" / "math").mkdir(parents=True)
    (project / "pkg" / "math" / "value.go").write_bytes(
        b"package math\nfunc Value() int { return 2 }\n")
    (project / "cmd" / "app" / "main_test.go").write_bytes(
        b"package main\n")
    (project / "go.sum").write_bytes(b"firstparty.test/lib v1.0 h1:a\n")
    for argv in (["go", "test", "./..."],
                 ["go", "build", "-o", "bin/app", "./cmd/app"]):
        c, attempt = service._prepare_d4_r003_attempt("a", "go-project", argv)
        names = {name for name, _digest in c.source_sha256}
        assert names == {
            "go-project/go.mod",
            "go-project/go.sum",
            "go-project/cmd/app/main.go",
            "go-project/cmd/app/main_test.go",
            "go-project/pkg/math/value.go",
        }
        (project / "pkg" / "math" / "value.go").write_bytes(
            b"package math\nfunc Value() int { return 3 }\n")
        was_called = []
        def no_launcher(_plan):
            was_called.append(True)
            raise AssertionError("undetected package drift")
        with pytest.raises(LbeWorkerError) as denied:
            LbeWorker(DirectChildOwner(), launcher=no_launcher).run(
                c.plan, product_attempt=attempt)
        assert denied.value.code == "attempt_replay_denied"
        assert was_called == []
        (project / "pkg" / "math" / "value.go").write_bytes(
            b"package math\nfunc Value() int { return 2 }\n")


@pytest.mark.parametrize("mutation", [
    "sitecustomize", "untracked_config", "hidden_hook",
    "symlink_nested", "unrecognized_file", "empty_nested",
])
def test_d4_python_rejects_unlisted_or_linked_import_source(
        product_service, mutation):
    service, root = product_service
    py = root / "py-direct"
    if mutation == "sitecustomize":
        (py / "sitecustomize.py").write_bytes(b"danger=True\n")
    elif mutation == "untracked_config":
        (py / "tox.ini").write_bytes(b"[testenv]\n")
    elif mutation == "hidden_hook":
        (py / ".pth").write_bytes(b"/other\n")
    elif mutation == "symlink_nested":
        (py / "src" / "indirect").symlink_to(
            root / "go-project", target_is_directory=True)
    elif mutation == "unrecognized_file":
        (py / "src" / "module.so").write_bytes(b"unqualified native module\n")
    else:
        (py / "src" / "empty").mkdir()
    with pytest.raises(GatewayError) as denied:
        service._prepare_d4_r003_fixture_candidate(
            "a", "py-direct", ["python", "-m", "pytest", "-q"])
    assert denied.value.code == "command_not_allowed"


@pytest.mark.parametrize("mutation", [
    "go_work", "unlisted_pkg", "native_asm", "embed_asset",
    "output_preexisting", "symlink_module", "empty_pkg",
])
def test_d4_go_fails_closed_on_untracked_module_or_build_inputs(
        product_service, mutation):
    service, root = product_service
    go = root / "go-project"
    if mutation == "go_work":
        (go / "go.work").write_bytes(b"go 1.27\n")
    elif mutation == "unlisted_pkg":
        (go / "shadowpkg").mkdir()
        (go / "shadowpkg" / "main.go").write_bytes(b"package shadowpkg\n")
    elif mutation == "native_asm":
        (go / "cmd" / "app" / "arm64.s").write_bytes(b"TEXT begin(SB),0,$0\n")
    elif mutation == "embed_asset":
        (go / "cmd" / "app" / "secret.bin").write_bytes(b"unqualified\n")
    elif mutation == "output_preexisting":
        (go / "bin" / "app").write_bytes(b"stale binary\n")
    elif mutation == "symlink_module":
        (go / "pkg").symlink_to(go / "cmd", target_is_directory=True)
    else:
        (go / "internal" / "empty").mkdir(parents=True)
    with pytest.raises(GatewayError) as denied:
        service._prepare_d4_r003_fixture_candidate(
            "a", "go-project", ["go", "test", "./..."])
    assert denied.value.code == "command_not_allowed"


def test_d4_pipenv_selected_python_streams_large_dummy_bytes_no_spawn(
        product_service, monkeypatch):
    import hashlib

    service, root = product_service
    location = root / "py-pipenv" / ".venv" / "bin" / "python"
    data = b"test-only, never executable!\n" * 100000
    assert len(data) > 1024 * 1024
    location.write_bytes(data)
    location.chmod(0o700)
    with monkeypatch.context() as m:
        def no_spawn(*_args, **_kwargs):
            raise AssertionError("No fake interpreter must be launched")
        m.setattr(subprocess, "Popen", no_spawn)
        candidate = service._prepare_d4_r003_fixture_candidate(
            "a", "py-pipenv", ["python", "-m", "pytest", "-q"])
    assert dict(candidate.source_sha256)[
        "py-pipenv/.venv/bin/python"] == hashlib.sha256(data).hexdigest()
    assert candidate.native_launch_allowed is False
    assert candidate.actual_loaded_sources_proven is False


@pytest.mark.parametrize("mutation", ["non_executable", "empty", "too_large"])
def test_d4_pipenv_selected_interpreter_requires_bounded_owner_executable(
        product_service, mutation):
    service, root = product_service
    python = root / "py-pipenv" / ".venv" / "bin" / "python"
    if mutation == "non_executable":
        python.chmod(0o600)
    elif mutation == "empty":
        python.write_bytes(b"")
    else:
        # Sparse fixture, no need to allocate a 128 MiB string or run Python.
        with python.open("r+b") as f:
            f.truncate(128 * 1024 * 1024 + 1)
    with pytest.raises(GatewayError) as denied:
        service._prepare_d4_r003_fixture_candidate(
            "a", "py-pipenv", ["python", "-m", "pytest", "-q"])
    assert denied.value.code == "command_not_allowed"


def test_d4_directory_changes_during_snapshot_are_rejected(
        product_service, monkeypatch):
    import gateway.lbe_product_fixture as selected

    service, root = product_service
    src = root / "py-direct" / "src"
    real_digest = selected._file_digest
    mutated = []
    def mutate_after_original_read(parent_fd, name, **kwargs):
        row = real_digest(parent_fd, name, **kwargs)
        if name == "main.py" and not mutated:
            (src / "other.py").write_bytes(b"shadow=1\n")
            mutated.append(True)
        return row
    with monkeypatch.context() as m:
        m.setattr(selected, "_file_digest", mutate_after_original_read)
        with pytest.raises(GatewayError) as denied:
            service._prepare_d4_r003_fixture_candidate(
                "a", "py-direct", ["python", "-m", "pytest", "-q"])
    assert denied.value.code == "command_not_allowed"
    assert mutated == [True]


def test_d4_pipenv_tests_directory_is_included_before_one_use_marker(
        product_service):
    service, root = product_service
    tests = root / "py-pipenv" / "tests"
    tests.mkdir()
    (tests / "test_x.py").write_bytes(b"def test_x(): assert True\n")
    c, marker = service._prepare_d4_r003_attempt(
        "a", "py-pipenv", ["python", "-m", "pytest", "-q"])
    assert "py-pipenv/tests/test_x.py" in dict(c.source_sha256)
    (tests / "test_x.py").write_bytes(b"def test_x(): assert False\n")
    from gateway.lbe_direct_owner import DirectChildOwner
    from gateway.lbe_worker import LbeWorker, LbeWorkerError

    with pytest.raises(LbeWorkerError) as denied:
        LbeWorker(DirectChildOwner(), launcher=lambda plan: (_ for _ in ()).throw(
            AssertionError("Stale Pipenv test cannot run"))).run(
            c.plan, product_attempt=marker)
    assert denied.value.code == "attempt_replay_denied"


@pytest.mark.parametrize("additional", [
    b"require example.com/other v1.2.3\n",
    b"replace example.com/other => ../outside\n",
    b"toolchain go1.99.0\n",
    b"exclude example.com/old v1.1.0\n",
    b"retract v0.1.0\n",
    b"replace (\n  example.com/a => ../../a\n)\n",
    b"go 1.28\n",
    b"module another.test/example\n",
    b"// go:generate untrusted\n",
    b"\x00unsafe\n",
])
def test_d4_go_minimal_module_rejects_unqualified_graph_directives(
        product_service, additional):
    service, root = product_service
    (root / "go-project" / "go.mod").write_bytes(
        b"module firstparty.test/app\ngo 1.27\n" + additional)
    with pytest.raises(GatewayError) as denied:
        service._prepare_d4_r003_fixture_candidate(
            "a", "go-project", ["go", "test", "./..."])
    assert denied.value.code == "command_not_allowed"


@pytest.mark.parametrize("module", [
    b"module ../outside\ngo 1.27\n",
    b"module example.com/../outside\ngo 1.27\n",
    b"module \n go 1.27\n",
    b"module firstparty.test/app\n",
    b"go 1.27\n",
    b"module firstparty.test/app\ngo 1.invalid\n",
    b"module firstparty.test/app\r\ngo 1.27\n",
    b"module firstparty.test/app\t\ngo 1.27\n",
    b"module firstparty.test/app\ngo 1.27\n" + b"A" * 65536,
])
def test_d4_go_minimal_module_rejects_malformed_or_oversized_source(
        product_service, module):
    service, root = product_service
    (root / "go-project" / "go.mod").write_bytes(module)
    with pytest.raises(GatewayError) as denied:
        service._prepare_d4_r003_fixture_candidate(
            "a", "go-project", ["go", "vet", "./..."])
    assert denied.value.code == "command_not_allowed"


def test_d4_go_module_changes_between_inventory_and_validation_rejected(
        product_service, monkeypatch):
    import gateway.lbe_product_fixture as guarded

    service, root = product_service
    module = root / "go-project" / "go.mod"
    real_file_digest = guarded._file_digest
    modified = []

    def after_initial_hash(parent_fd, name, **kwargs):
        result = real_file_digest(parent_fd, name, **kwargs)
        if name == "go.mod" and not modified:
            # The other files still exist, but the actual module data is now
            # different from the pinned first-party bytes.
            module.write_bytes(
                b"module firstparty.test/app\ngo 1.27\n"
                b"replace fake.dev/x => ../outside\n")
            modified.append(True)
        return result

    with monkeypatch.context() as m:
        m.setattr(guarded, "_file_digest", after_initial_hash)
        with pytest.raises(GatewayError) as denied:
            service._prepare_d4_r003_fixture_candidate(
                "a", "go-project", ["go", "test", "./..."])
    assert denied.value.code == "command_not_allowed"
    assert modified == [True]


def test_d4_go_qualified_simple_module_has_no_native_authority(
        product_service, monkeypatch):
    service, _root = product_service
    with monkeypatch.context() as m:
        m.setattr(subprocess, "Popen", lambda *_a, **_k: (
            _ for _ in ()).throw(AssertionError("no Go execution allowed")))
        c = service._prepare_d4_r003_fixture_candidate(
            "a", "go-project", ["go", "test", "./..."])
        assert c.native_launch_allowed is False
        assert c.actual_loaded_sources_proven is False
        assert c.owner_approval_attested is False
        with pytest.raises(GatewayError) as denied:
            service.invoke_exec(
                "a", "go-project", ["go", "test", "./..."],
                dry_run=False)
    assert denied.value.code == "exec_cleanup_proof_required"


@pytest.mark.parametrize("cwd,argv", _ROWS)
def test_d4_first_party_inventory_includes_checked_directory_identity(
        product_service, cwd, argv):
    service, root = product_service
    candidate = service._prepare_d4_r003_fixture_candidate(
        "a", cwd, argv)
    directories = dict(candidate.directory_identity)
    assert cwd in directories
    assert all(len(identity) == 8 and all(type(x) is int for x in identity)
               for identity in directories.values())
    if cwd == "py-direct":
        assert cwd + "/src" in directories
    elif cwd == "py-pipenv":
        assert cwd + "/.venv" in directories
        assert cwd + "/.venv/bin" in directories
    else:
        assert cwd + "/cmd" in directories
        assert cwd + "/cmd/app" in directories
        assert cwd + "/bin" in directories
    assert candidate.native_launch_allowed is False


@pytest.mark.parametrize("cwd,argv,relative", [
    ("go-project", ["go", "test", "./..."], "bin"),
    ("go-project", ["go", "build", "-o", "bin/app", "./cmd/app"], "cmd"),
    ("py-direct", ["python", "-m", "compileall", "-q", "./src"], "src"),
    ("py-pipenv", ["python", "-m", "pytest", "-q"], ".venv"),
    ("py-pipenv", ["python", "-m", "pytest", "-q"], ".venv/bin"),
])
def test_d4_directory_mode_drift_denies_one_use_attempt_without_child(
        product_service, cwd, argv, relative):
    from gateway.lbe_direct_owner import DirectChildOwner
    from gateway.lbe_worker import LbeWorker, LbeWorkerError

    service, root = product_service
    candidate, marker = service._prepare_d4_r003_attempt("a", cwd, argv)
    chosen = root / cwd / relative
    chosen.chmod(0o700)
    invoked = []
    def cannot_launch(_plan):
        invoked.append(True)
        raise AssertionError("directory metadata drift must deny before Popen")
    with pytest.raises(LbeWorkerError) as denied:
        LbeWorker(DirectChildOwner(), launcher=cannot_launch).run(
            candidate.plan, product_attempt=marker)
    assert denied.value.code == "attempt_replay_denied"
    assert invoked == []


def test_d4_added_empty_cache_directory_is_detected_before_worker_launch(
        product_service):
    from gateway.lbe_direct_owner import DirectChildOwner
    from gateway.lbe_worker import LbeWorker, LbeWorkerError

    service, root = product_service
    candidate, marker = service._prepare_d4_r003_attempt(
        "a", "py-direct",
        ["python", "-m", "compileall", "-q", "./src"])
    (root / "py-direct" / "src" / "__pycache__").mkdir()
    invoked = []
    def cannot_launch(_plan):
        invoked.append(True)
        raise AssertionError("new input directory must be bound into snapshot")
    with pytest.raises(LbeWorkerError) as denied:
        LbeWorker(DirectChildOwner(), launcher=cannot_launch).run(
            candidate.plan, product_attempt=marker)
    assert denied.value.code == "attempt_replay_denied"
    assert invoked == []


def test_d4_forged_directory_identity_is_not_a_product_authorization(
        product_service):
    from gateway.lbe_product_fixture import D4OneUseAttemptMarker

    service, _root = product_service
    candidate = service._prepare_d4_r003_fixture_candidate(
        "a", "go-project", ["go", "test", "./..."])
    with pytest.raises(D4FixtureDenied):
        D4OneUseAttemptMarker(
            replace(candidate, directory_identity=()), service.get("a"))
    with pytest.raises(D4FixtureDenied):
        D4OneUseAttemptMarker(
            replace(candidate, directory_identity=(("other", (0,) * 8),)),
            service.get("a"))
    assert candidate.native_launch_allowed is False


def _stage_d4_native_bytes_in_private_runner(root, *, kind):
    import hashlib

    private = root.parent.parent
    def stage(relative, data):
        location = private / relative
        location.parent.mkdir(parents=True, exist_ok=True)
        location.write_bytes(data)
        location.chmod(0o700)
        return hashlib.sha256(data).hexdigest()

    for name in ("home", "tmp"):
        (private / name).mkdir(exist_ok=True)
    if kind == "go":
        for name in ("gopath", "modcache", "gocache", "gotmp"):
            (private / name).mkdir(exist_ok=True)
        return str(private), {
            "go": stage("go/bin/go", b"staged Go primary test bytes"),
            "compile": stage(
                "go/pkg/tool/darwin_arm64/compile",
                b"staged Go compiler test bytes"),
            "link": stage(
                "go/pkg/tool/darwin_arm64/link",
                b"staged Go linker test bytes"),
        }
    if kind == "python_direct":
        return str(private), {
            "python": stage("bin/python", b"staged direct Python test bytes"),
        }
    if kind != "pipenv":
        raise AssertionError("unsupported test fixture")
    py_project = root / "py-pipenv"
    return str(private), {
        "Pipfile": hashlib.sha256(
            (py_project / "Pipfile").read_bytes()).hexdigest(),
        "Pipfile.lock": hashlib.sha256(
            (py_project / "Pipfile.lock").read_bytes()).hexdigest(),
        "pyvenv.cfg": hashlib.sha256(
            (py_project / ".venv" / "pyvenv.cfg").read_bytes()).hexdigest(),
        "python": hashlib.sha256(
            (py_project / ".venv" / "bin" / "python").read_bytes()).hexdigest(),
        "pipenv": stage("bin/pipenv", b"staged Pipenv entrypoint test bytes"),
    }


@pytest.mark.parametrize("kind,cwd,argv", [
    ("go", "go-project", ["go", "test", "./..."]),
    ("go", "go-project", ["go", "vet", "./..."]),
    ("go", "go-project", ["go", "build", "-o", "bin/app", "./cmd/app"]),
    ("pipenv", "py-pipenv", ["python", "-m", "pytest", "-q"]),
])
def test_d4_service_observes_real_staged_sources_and_closed_child_environment(
        product_service, monkeypatch, kind, cwd, argv):
    from gateway.lbe_runtime_source import (
        D4RuntimeSourceDenied, authorize_d4_native_from_observation,
    )

    service, root = product_service
    private, hashes = _stage_d4_native_bytes_in_private_runner(root, kind=kind)
    with monkeypatch.context() as m:
        m.setattr(os, "environ", {"PATH": "/usr/bin:/bin"})
        m.setattr(subprocess, "Popen", lambda *_a, **_k: (
            _ for _ in ()).throw(AssertionError("T0 cannot spawn native Go/Pipenv")))
        actual = service._inspect_d4_r003_staged_runtime(
            "a", cwd, argv, private_root=private, expected_hashes=hashes,
            timeout_seconds=120)
    assert actual.kind == kind
    assert actual.workspace == "a"
    assert actual.staged_file_bytes_checked is True
    assert actual.child_environment_constructed is True
    assert actual.actual_import_graph_attested is False
    assert actual.runner_image_attested is False
    assert actual.credentials_and_mounts_attested is False
    assert actual.physical_resource_domain_attached is False
    assert actual.owner_native_t1_grant is False
    assert actual.native_launch_allowed is False
    assert actual.blockers
    assert actual.observed_kernel == os.uname().sysname
    assert actual.observed_machine == os.uname().machine
    env = dict(actual.closed_child_environment)
    assert env["HOME"] == private + "/home"
    assert env["TMPDIR"] == private + "/tmp"
    assert "GITHUB_TOKEN" not in env and "PYTHONPATH" not in env
    if kind == "go":
        assert env["GOFLAGS"] == ""
        assert env["GOTOOLCHAIN"] == "local"
        assert env["GOPROXY"] == "off"
        assert len(actual.staged_executables) == 3
    else:
        assert env["PIP_NO_INDEX"] == "1"
        assert env["PIPENV_PIPFILE"] == str(root / "py-pipenv" / "Pipfile")
        assert len(actual.staged_executables) == 2
    with pytest.raises(D4RuntimeSourceDenied, match="NOT_AUTHORIZED"):
        authorize_d4_native_from_observation(actual)
    with pytest.raises(GatewayError) as refused:
        service.invoke_exec("a", cwd, argv, dry_run=False)
    assert refused.value.code == "exec_cleanup_proof_required"


@pytest.mark.parametrize("kind,cwd,argv,changed_key,changed_relative", [
    ("go", "go-project", ["go", "test", "./..."],
     "compile", "go/pkg/tool/darwin_arm64/compile"),
    ("go", "go-project", ["go", "build", "-o", "bin/app", "./cmd/app"],
     "link", "go/pkg/tool/darwin_arm64/link"),
    ("pipenv", "py-pipenv", ["python", "-m", "pytest", "-q"],
     "pipenv", "bin/pipenv"),
])
def test_d4_service_source_bytes_changed_after_pinning_deny_before_launch(
        product_service, monkeypatch, kind, cwd, argv, changed_key,
        changed_relative):
    service, root = product_service
    private, hashes = _stage_d4_native_bytes_in_private_runner(root, kind=kind)
    (root.parent.parent / changed_relative).write_bytes(b"unqualified replacement")
    with monkeypatch.context() as m:
        m.setattr(os, "environ", {"PATH": "/usr/bin:/bin"})
        m.setattr(subprocess, "Popen", lambda *_a, **_k: (
            _ for _ in ()).throw(AssertionError("No native child allowed")))
        with pytest.raises(GatewayError) as denied:
            service._inspect_d4_r003_staged_runtime(
                "a", cwd, argv, private_root=private, expected_hashes=hashes)
    assert denied.value.code == "runner_unavailable"
    assert hashes[changed_key] != ""


@pytest.mark.parametrize("key,value", [
    ("GOFLAGS", "-toolexec=/outside/untrusted"),
    ("GOCACHEPROG", "/outside/loader"),
    ("PIPENV_PYTHON", "/outside/python"),
    ("PYTHONPATH", "/outside/site"),
    ("DYLD_INSERT_LIBRARIES", "/outside/lib.dylib"),
    ("GITHUB_TOKEN", "fake-token-not-logged"),
    ("GH_TOKEN", "fake-token-not-logged"),
    ("AWS_SECRET_ACCESS_KEY", "fake-secret-not-logged"),
    ("GIT_ASKPASS", "/outside/credential"),
])
def test_d4_live_parent_selector_or_credentials_refuse_staged_observation(
        product_service, monkeypatch, key, value):
    service, root = product_service
    private, hashes = _stage_d4_native_bytes_in_private_runner(root, kind="go")
    with monkeypatch.context() as m:
        m.setattr(os, "environ", {"PATH": "/usr/bin:/bin", key: value})
        with pytest.raises(GatewayError) as denied:
            service._inspect_d4_r003_staged_runtime(
                "a", "go-project", ["go", "test", "./..."],
                private_root=private, expected_hashes=hashes)
    assert denied.value.code == "runner_unavailable"


@pytest.mark.parametrize("violation", [
    "wrong_root", "incomplete_hashes", "false_hash", "symlink_tool",
    "outside_workspace", "private_root_is_workspace",
])
def test_d4_staged_runtime_fails_closed_on_unqualified_runner_sources(
        product_service, monkeypatch, violation):
    service, root = product_service
    private, hashes = _stage_d4_native_bytes_in_private_runner(root, kind="go")
    if violation == "wrong_root":
        private = str(root.parent)
    elif violation == "incomplete_hashes":
        del hashes["link"]
    elif violation == "false_hash":
        hashes["go"] = "f" * 64
    elif violation == "symlink_tool":
        target = root.parent.parent / "go" / "bin" / "go"
        target.unlink()
        target.symlink_to("/bin/sh")
    elif violation == "outside_workspace":
        private = "/outside/runner"
    else:
        private = str(root)
    with monkeypatch.context() as m:
        m.setattr(os, "environ", {"PATH": "/usr/bin:/bin"})
        with pytest.raises(GatewayError) as denied:
            service._inspect_d4_r003_staged_runtime(
                "a", "go-project", ["go", "test", "./..."],
                private_root=private, expected_hashes=hashes)
    assert denied.value.code == "runner_unavailable"


def test_d4_staged_runtime_not_client_mintable_or_executable_on_python_direct(
        product_service, monkeypatch):
    service, root = product_service
    private, hashes = _stage_d4_native_bytes_in_private_runner(root, kind="go")
    with monkeypatch.context() as m:
        m.setattr(os, "environ", {"PATH": "/usr/bin:/bin"})
        with pytest.raises(GatewayError) as denied:
            service._inspect_d4_r003_staged_runtime(
                "a", "py-direct", ["python", "-m", "pytest", "-q"],
                private_root=private, expected_hashes=hashes)
    assert denied.value.code == "runner_unavailable"
    assert service.info()["exec_policy"]["available"] is False


@pytest.mark.parametrize("kind,cwd,argv", [
    ("go", "go-project", ["go", "test", "./..."]),
    ("go", "go-project", ["go", "vet", "./..."]),
    ("go", "go-project", ["go", "build", "-o", "bin/app", "./cmd/app"]),
    ("pipenv", "py-pipenv", ["python", "-m", "pytest", "-q"]),
])
def test_d4_staged_source_binding_rechecks_real_selected_files_before_worker(
        product_service, monkeypatch, kind, cwd, argv):
    from gateway.lbe_direct_owner import DirectChildOwner
    from gateway.lbe_worker import LbeWorker, LbeWorkerError

    service, root = product_service
    private, hashes = _stage_d4_native_bytes_in_private_runner(root, kind=kind)
    with monkeypatch.context() as m:
        m.setattr(os, "environ", {"PATH": "/usr/bin:/bin"})
        m.setattr(subprocess, "Popen", lambda *_a, **_k: (
            _ for _ in ()).throw(AssertionError("No actual T1 child allowed")))
        candidate, marker, observed = service._prepare_d4_r003_staged_attempt(
            "a", cwd, argv, private_root=private, expected_hashes=hashes)
        assert observed.native_launch_allowed is False
        worker = LbeWorker(DirectChildOwner(), launcher=_no_child_launcher)
        first = worker.run(candidate.plan, product_attempt=marker)
        assert first["status"] == "launch_failed"
        assert first["executed"] is False
        with pytest.raises(LbeWorkerError) as denied:
            worker.run(candidate.plan, product_attempt=marker)
        assert denied.value.code == "attempt_replay_denied"


@pytest.mark.parametrize("kind,argv,changed", [
    ("go", ["go", "test", "./..."], "go/bin/go"),
    ("go", ["go", "vet", "./..."], "go/pkg/tool/darwin_arm64/link"),
    ("pipenv", ["python", "-m", "pytest", "-q"], "bin/pipenv"),
])
def test_d4_staged_source_drift_burns_original_attempt_without_any_launch(
        product_service, monkeypatch, kind, argv, changed):
    from gateway.lbe_direct_owner import DirectChildOwner
    from gateway.lbe_worker import LbeWorker, LbeWorkerError

    service, root = product_service
    private, hashes = _stage_d4_native_bytes_in_private_runner(root, kind=kind)
    cwd = "go-project" if kind == "go" else "py-pipenv"
    launcher_calls = []
    def forbidden(_plan):
        launcher_calls.append(True)
        raise AssertionError("Staged-source drift must not reach launcher")
    with monkeypatch.context() as m:
        m.setattr(os, "environ", {"PATH": "/usr/bin:/bin"})
        candidate, marker, observation = service._prepare_d4_r003_staged_attempt(
            "a", cwd, argv, private_root=private, expected_hashes=hashes)
        assert observation.native_launch_allowed is False
        (root.parent.parent / changed).write_bytes(
            b"replaced staged bytes without any native execution")
        worker = LbeWorker(DirectChildOwner(), launcher=forbidden)
        with pytest.raises(LbeWorkerError) as denied:
            worker.run(candidate.plan, product_attempt=marker)
        assert denied.value.code == "attempt_replay_denied"
        with pytest.raises(LbeWorkerError) as replay:
            worker.run(candidate.plan, product_attempt=marker)
        assert replay.value.code == "attempt_replay_denied"
    assert launcher_calls == []


def test_d4_live_parent_go_selector_after_staging_denies_before_launcher(
        product_service, monkeypatch):
    from gateway.lbe_direct_owner import DirectChildOwner
    from gateway.lbe_worker import LbeWorker, LbeWorkerError

    service, root = product_service
    private, hashes = _stage_d4_native_bytes_in_private_runner(root, kind="go")
    seen = []
    def forbidden(_plan):
        seen.append(True)
        raise AssertionError("Changed parent environment may not launch")
    with monkeypatch.context() as m:
        m.setattr(os, "environ", {"PATH": "/usr/bin:/bin"})
        candidate, marker, _observed = service._prepare_d4_r003_staged_attempt(
            "a", "go-project", ["go", "test", "./..."],
            private_root=private, expected_hashes=hashes)
        os.environ["GOFLAGS"] = "-toolexec=/outside/host"
        with pytest.raises(LbeWorkerError) as denied:
            LbeWorker(DirectChildOwner(), launcher=forbidden).run(
                candidate.plan, product_attempt=marker)
        assert denied.value.code == "attempt_replay_denied"
    assert seen == []


def test_d4_user_supplied_staged_callback_cannot_replace_internal_recheck(
        product_service):
    from gateway.lbe_product_fixture import D4OneUseAttemptMarker
    service, _root = product_service
    candidate = service._prepare_d4_r003_fixture_candidate(
        "a", "go-project", ["go", "test", "./..."])
    with pytest.raises(D4FixtureDenied):
        D4OneUseAttemptMarker(
            candidate, service.get("a"), staged_source=lambda *_: None)
    assert service.info()["exec_policy"]["available"] is False


def _d4_tree_expected(path):
    import hashlib

    entries = [("", None)]
    for leaf in sorted(path.rglob("*")):
        name = leaf.relative_to(path).as_posix()
        if leaf.is_dir() and not leaf.is_symlink():
            entries.append((name, None))
        else:
            entries.append((name, hashlib.sha256(leaf.read_bytes()).hexdigest()))
    return tuple(sorted(entries))


def _d4_staged_trees(root, kind):
    private = root.parent.parent
    scratch = {
        name: _d4_tree_expected(private / name)
        for name in ("home", "tmp")
    }
    if kind == "go":
        scratch.update({
            name: _d4_tree_expected(private / name)
            for name in ("gopath", "modcache", "gocache", "gotmp")
        })
        return {"go": _d4_tree_expected(private / "go"), **scratch}
    if kind == "python_direct":
        (private / "lib").mkdir(exist_ok=True)
        return {
            "bin": _d4_tree_expected(private / "bin"),
            "lib": _d4_tree_expected(private / "lib"),
            **scratch,
        }
    if kind != "pipenv":
        raise AssertionError("invalid private source kind")
    (private / "lib").mkdir(exist_ok=True)
    return {
        "venv": _d4_tree_expected(root / "py-pipenv" / ".venv"),
        "bin": _d4_tree_expected(private / "bin"),
        "lib": _d4_tree_expected(private / "lib"),
        **scratch,
    }


@pytest.mark.parametrize("kind,cwd,argv", [
    ("go", "go-project", ["go", "test", "./..."]),
    ("go", "go-project", ["go", "vet", "./..."]),
    ("go", "go-project", ["go", "build", "-o", "bin/app", "./cmd/app"]),
    ("pipenv", "py-pipenv", ["python", "-m", "pytest", "-q"]),
])
def test_d4_product_stage_binds_entire_staged_source_tree_to_worker(
        product_service, monkeypatch, kind, cwd, argv):
    from gateway.lbe_direct_owner import DirectChildOwner
    from gateway.lbe_worker import LbeWorker, LbeWorkerError

    service, root = product_service
    private, hashes = _stage_d4_native_bytes_in_private_runner(root, kind=kind)
    trees = _d4_staged_trees(root, kind)
    with monkeypatch.context() as m:
        m.setattr(os, "environ", {"PATH": "/usr/bin:/bin"})
        m.setattr(subprocess, "Popen", lambda *_a, **_k: (
            _ for _ in ()).throw(AssertionError("no real T1 child")))
        candidate, marker, observation = service._prepare_d4_r003_staged_attempt(
            "a", cwd, argv, private_root=private, expected_hashes=hashes,
            expected_trees=trees)
        assert observation.bounded_staged_file_set_checked is True
        assert len(observation.staged_source_trees) == (7 if kind == "go" else 5)
        assert all(entry_count > 0 and len(digest) == 64
                   for _label, digest, entry_count, _total in
                   observation.staged_source_trees)
        assert observation.actual_import_graph_attested is False
        assert observation.physical_resource_domain_attached is False
        assert observation.owner_native_t1_grant is False
        assert observation.native_launch_allowed is False
        result = LbeWorker(DirectChildOwner(), launcher=_no_child_launcher).run(
            candidate.plan, product_attempt=marker)
        assert result["status"] == "launch_failed"
        assert result["executed"] is False
        with pytest.raises(LbeWorkerError) as replay:
            LbeWorker(DirectChildOwner(), launcher=_no_child_launcher).run(
                candidate.plan, product_attempt=marker)
        assert replay.value.code == "attempt_replay_denied"


@pytest.mark.parametrize("kind,added_path", [
    ("go", "go/src/new-package/extra.go"),
    ("go", "go/pkg/tool/darwin_arm64/new_tool"),
    ("pipenv", "lib/shadow.py"),
    ("pipenv", "projects/a/py-pipenv/.venv/lib/site.py"),
    ("go", "gocache/unknown-built-package.a"),
    ("go", "modcache/unlisted-module.go"),
    ("pipenv", "home/.pipenv_unapproved"),
    ("pipenv", "tmp/unqualified-site.py"),
])
def test_d4_product_staged_tree_extra_source_denied_before_launcher(
        product_service, monkeypatch, kind, added_path):
    from gateway.lbe_direct_owner import DirectChildOwner
    from gateway.lbe_worker import LbeWorker, LbeWorkerError

    service, root = product_service
    private, hashes = _stage_d4_native_bytes_in_private_runner(root, kind=kind)
    trees = _d4_staged_trees(root, kind)
    cwd = "go-project" if kind == "go" else "py-pipenv"
    argv = (["go", "test", "./..."] if kind == "go"
            else ["python", "-m", "pytest", "-q"])
    launcher_count = []
    def blocked(_plan):
        launcher_count.append(True)
        raise AssertionError("never launch after source tree drift")
    with monkeypatch.context() as m:
        m.setattr(os, "environ", {"PATH": "/usr/bin:/bin"})
        candidate, marker, observation = service._prepare_d4_r003_staged_attempt(
            "a", cwd, argv, private_root=private,
            expected_hashes=hashes, expected_trees=trees)
        assert observation.bounded_staged_file_set_checked
        extra = root.parent.parent / added_path
        extra.parent.mkdir(parents=True, exist_ok=True)
        extra.write_bytes(b"unqualified staged extra input")
        with pytest.raises(LbeWorkerError) as denied:
            LbeWorker(DirectChildOwner(), launcher=blocked).run(
                candidate.plan, product_attempt=marker)
        assert denied.value.code == "attempt_replay_denied"
    assert launcher_count == []


@pytest.mark.parametrize("kind", ["go", "pipenv"])
def test_d4_product_stage_rejects_missing_tree_even_when_binaries_hash_match(
        product_service, monkeypatch, kind):
    service, root = product_service
    private, hashes = _stage_d4_native_bytes_in_private_runner(root, kind=kind)
    cwd = "go-project" if kind == "go" else "py-pipenv"
    argv = (["go", "test", "./..."] if kind == "go"
            else ["python", "-m", "pytest", "-q"])
    with monkeypatch.context() as m:
        m.setattr(os, "environ", {"PATH": "/usr/bin:/bin"})
        with pytest.raises(GatewayError) as denied:
            service._inspect_d4_r003_staged_runtime(
                "a", cwd, argv, private_root=private,
                expected_hashes=hashes, expected_trees={})
    assert denied.value.code == "runner_unavailable"


def test_d4_product_stage_rejects_trusted_manifest_with_pth_startup_code(
        product_service, monkeypatch):
    service, root = product_service
    private, hashes = _stage_d4_native_bytes_in_private_runner(root, kind="pipenv")
    (root.parent.parent / "lib").mkdir(exist_ok=True)
    (root.parent.parent / "lib" / "custom.pth").write_bytes(
        b"import unexpected_site_startup\n")
    trees = _d4_staged_trees(root, "pipenv")
    with monkeypatch.context() as m:
        m.setattr(os, "environ", {"PATH": "/usr/bin:/bin"})
        with pytest.raises(GatewayError) as denied:
            service._inspect_d4_r003_staged_runtime(
                "a", "py-pipenv", ["python", "-m", "pytest", "-q"],
                private_root=private, expected_hashes=hashes,
                expected_trees=trees)
    assert denied.value.code == "runner_unavailable"


@pytest.mark.parametrize("kind,name", [
    ("go", "gopath"),
    ("go", "modcache"),
    ("go", "gocache"),
    ("go", "gotmp"),
    ("go", "home"),
    ("go", "tmp"),
    ("pipenv", "home"),
    ("pipenv", "tmp"),
])
def test_d4_product_denies_prepopulated_native_scratch_even_with_approved_digest(
        product_service, monkeypatch, kind, name):
    # Hashing a cache can never establish that foreign generated modules or
    # startup files are allowed. Preexisting scratch inputs must be absent.
    service, root = product_service
    private, hashes = _stage_d4_native_bytes_in_private_runner(root, kind=kind)
    extra = root.parent.parent / name / "preexisting.txt"
    extra.write_bytes(b"prepopulated scratch is not an approved source")
    trees = _d4_staged_trees(root, kind)
    assert any(row[0] == "preexisting.txt" for row in trees[name])
    cwd = "go-project" if kind == "go" else "py-pipenv"
    argv = (["go", "test", "./..."] if kind == "go"
            else ["python", "-m", "pytest", "-q"])
    with monkeypatch.context() as m:
        m.setattr(os, "environ", {"PATH": "/usr/bin:/bin"})
        with pytest.raises(GatewayError) as denied:
            service._inspect_d4_r003_staged_runtime(
                "a", cwd, argv, private_root=private, expected_hashes=hashes,
                expected_trees=trees)
    assert denied.value.code == "runner_unavailable"


@pytest.mark.parametrize("kind,cwd,argv,first", [
    ("python_direct", "py-direct", ["python", "-m", "pytest", "-q"], "python"),
    ("python_direct", "py-direct",
     ["python", "-m", "compileall", "-q", "./src"], "python"),
    ("pipenv", "py-pipenv", ["python", "-m", "pytest", "-q"], "pipenv"),
    ("go", "go-project", ["go", "test", "./..."], "go"),
    ("go", "go-project", ["go", "vet", "./..."], "go"),
    ("go", "go-project",
     ["go", "build", "-o", "bin/app", "./cmd/app"], "go"),
])
def test_d4_all_six_commands_produce_private_source_only_native_recipe(
        product_service, monkeypatch, kind, cwd, argv, first):
    from gateway.lbe_launch_recipe import (
        D4NativeRecipeDenied, launch_d4_native_from_recipe,
    )
    from gateway.lbe_direct_owner import DirectChildOwner
    from gateway.lbe_worker import LbeWorker, LbeWorkerError

    service, workspace = product_service
    private, hashes = _stage_d4_native_bytes_in_private_runner(
        workspace, kind=kind)
    trees = _d4_staged_trees(workspace, kind)
    with monkeypatch.context() as m:
        m.setattr(os, "environ", {"PATH": "/usr/bin:/bin"})
        m.setattr(subprocess, "Popen", lambda *_a, **_kw: (
            _ for _ in ()).throw(AssertionError("native T1 forbidden")))
        candidate, marker, observation, recipe = (
            service._prepare_d4_r003_native_recipe(
                "a", cwd, argv, private_root=private,
                expected_hashes=hashes, expected_trees=trees,
                timeout_seconds=120))
        assert recipe.workspace == "a"
        assert recipe.profile_git_blob == candidate.profile_git_blob
        assert recipe.runner == candidate.plan.runner
        assert recipe.requested_argv == tuple(argv)
        assert recipe.service_effective_argv == candidate.plan.effective_argv
        assert recipe.working_directory == str(workspace / cwd)
        assert recipe.resolved_spawn_argv[0] == recipe.resolved_executable
        assert recipe.resolved_executable.startswith(private + "/")
        assert recipe.resolved_executable.endswith("/" + first)
        assert recipe.resolved_spawn_argv[1:] == candidate.plan.effective_argv[1:]
        assert recipe.original_timeout_seconds == 120
        assert len(recipe.selected_source_fingerprint) == 64
        assert recipe.native_launch_allowed is False
        assert recipe.real_runner_qualified is False
        assert recipe.actual_loaded_source_graph_proven is False
        assert recipe.physical_cpu_memory_enforcement_proven is False
        assert recipe.owner_t1_grant_present is False
        assert observation.native_launch_allowed is False
        assert dict(recipe.required_limits)["cpu_millicores_max"] == 2000
        assert dict(recipe.required_limits)["memory_mib_max"] == 4096
        assert dict(recipe.closed_child_environment)["HOME"] == private + "/home"
        assert "GITHUB_TOKEN" not in dict(recipe.closed_child_environment)
        if kind == "go" and argv[1] == "build":
            assert recipe.canonical_output_path == str(
                workspace / "go-project" / "bin" / "app")
        else:
            assert recipe.canonical_output_path is None
        if kind == "python_direct":
            assert observation.kind == "python_direct"
            assert dict(recipe.closed_child_environment)["PYTHONSAFEPATH"] == "1"
            assert len(observation.staged_executables) == 1
        if kind == "pipenv":
            assert recipe.resolved_executable == private + "/bin/pipenv"
            assert recipe.resolved_spawn_argv[:3] == (
                private + "/bin/pipenv", "run", "python")
        with pytest.raises(D4NativeRecipeDenied, match="cannot launch"):
            launch_d4_native_from_recipe(recipe)
        with pytest.raises(GatewayError) as denied:
            service.invoke_exec("a", cwd, argv, dry_run=False)
        assert denied.value.code == "exec_cleanup_proof_required"
        result = LbeWorker(DirectChildOwner(), launcher=_no_child_launcher).run(
            candidate.plan, product_attempt=marker)
        assert result["status"] == "launch_failed"
        assert result["executed"] is False
        with pytest.raises(LbeWorkerError) as replay:
            LbeWorker(DirectChildOwner(), launcher=_no_child_launcher).run(
                candidate.plan, product_attempt=marker)
        assert replay.value.code == "attempt_replay_denied"


@pytest.mark.parametrize("mutation", [
    "wrong_python_hash", "extra_site", "bad_pth", "source_replacement",
    "foreign_parent_selector",
])
def test_d4_python_direct_recipe_rejects_changed_real_inputs_before_launch(
        product_service, monkeypatch, mutation):
    service, workspace = product_service
    private, hashes = _stage_d4_native_bytes_in_private_runner(
        workspace, kind="python_direct")
    trees = _d4_staged_trees(workspace, "python_direct")
    if mutation == "wrong_python_hash":
        hashes["python"] = "b" * 64
    elif mutation == "extra_site":
        (workspace.parent.parent / "lib" / "shadow.py").write_bytes(
            b"unqualified module import input\n")
    elif mutation == "bad_pth":
        (workspace.parent.parent / "lib" / "x.pth").write_bytes(
            b"import os; os.system('not allowed')\n")
    elif mutation == "source_replacement":
        (workspace.parent.parent / "bin" / "python").write_bytes(
            b"unqualified changed source\n")
    with monkeypatch.context() as m:
        env = {"PATH": "/usr/bin:/bin"}
        if mutation == "foreign_parent_selector":
            env["PYTHONPATH"] = "/tmp/unqualified"
        m.setattr(os, "environ", env)
        m.setattr(subprocess, "Popen", lambda *_a, **_kw: (
            _ for _ in ()).throw(AssertionError("no native child")))
        with pytest.raises(GatewayError) as denied:
            service._prepare_d4_r003_native_recipe(
                "a", "py-direct", ["python", "-m", "pytest", "-q"],
                private_root=private, expected_hashes=hashes,
                expected_trees=trees)
    assert denied.value.code == "runner_unavailable"


@pytest.mark.parametrize("timeout", [0, 121, 300, True, "120"])
def test_d4_recipe_rejects_timeout_outside_original_child_budget(
        product_service, monkeypatch, timeout):
    service, workspace = product_service
    private, hashes = _stage_d4_native_bytes_in_private_runner(
        workspace, kind="python_direct")
    trees = _d4_staged_trees(workspace, "python_direct")
    with monkeypatch.context() as m:
        m.setattr(os, "environ", {"PATH": "/usr/bin:/bin"})
        m.setattr(subprocess, "Popen", lambda *_a, **_kw: (
            _ for _ in ()).throw(AssertionError("native T1 forbidden")))
        with pytest.raises(GatewayError) as denied:
            service._prepare_d4_r003_native_recipe(
                "a", "py-direct",
                ["python", "-m", "compileall", "-q", "./src"],
                private_root=private, expected_hashes=hashes,
                expected_trees=trees, timeout_seconds=timeout)
    assert denied.value.code in {"runner_unavailable", "invalid_argument"}


def test_d4_native_recipe_rejects_forged_observation_and_cannot_mint_grant(
        product_service, monkeypatch):
    from gateway.lbe_launch_recipe import (
        D4NativeRecipeDenied, launch_d4_native_from_recipe,
        prepare_d4_native_launch_recipe,
    )

    service, workspace = product_service
    private, hashes = _stage_d4_native_bytes_in_private_runner(
        workspace, kind="python_direct")
    trees = _d4_staged_trees(workspace, "python_direct")
    with monkeypatch.context() as m:
        m.setattr(os, "environ", {"PATH": "/usr/bin:/bin"})
        candidate, _marker, observed, recipe = (
            service._prepare_d4_r003_native_recipe(
                "a", "py-direct", ["python", "-m", "pytest", "-q"],
                private_root=private, expected_hashes=hashes,
                expected_trees=trees))
        for field, val in (
            ("native_launch_allowed", True),
            ("actual_import_graph_attested", True),
            ("bounded_staged_file_set_checked", False),
            ("staged_source_trees", ()),
        ):
            with pytest.raises(D4NativeRecipeDenied):
                prepare_d4_native_launch_recipe(
                    service.get("a"), candidate,
                    replace(observed, **{field: val}),
                    private_root=private)
        with pytest.raises(D4NativeRecipeDenied):
            launch_d4_native_from_recipe(replace(recipe, native_launch_allowed=True))
    assert recipe.native_launch_allowed is False


def test_d4_python_direct_worker_prelaunch_rechecks_real_private_python(
        product_service, monkeypatch):
    from gateway.lbe_direct_owner import DirectChildOwner
    from gateway.lbe_worker import LbeWorker, LbeWorkerError

    service, workspace = product_service
    private, hashes = _stage_d4_native_bytes_in_private_runner(
        workspace, kind="python_direct")
    trees = _d4_staged_trees(workspace, "python_direct")
    called = []
    def should_not_launch(_plan):
        called.append(True)
        raise AssertionError("source changed before Worker launch")
    with monkeypatch.context() as m:
        m.setattr(os, "environ", {"PATH": "/usr/bin:/bin"})
        candidate, marker, _obs, recipe = service._prepare_d4_r003_native_recipe(
            "a", "py-direct", ["python", "-m", "pytest", "-q"],
            private_root=private, expected_hashes=hashes,
            expected_trees=trees)
        assert recipe.native_launch_allowed is False
        (workspace.parent.parent / "bin" / "python").write_bytes(
            b"replaced right before source recheck\n")
        with pytest.raises(LbeWorkerError) as denied:
            LbeWorker(DirectChildOwner(), launcher=should_not_launch).run(
                candidate.plan, product_attempt=marker)
        assert denied.value.code == "attempt_replay_denied"
    assert called == []
