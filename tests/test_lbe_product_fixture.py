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
    # The future Pipenv source-only profile selects ONLY the privately staged
    # bin home; never a host base interpreter or system site-packages.
    (pipenv / ".venv" / "pyvenv.cfg").write_bytes(
        ("home = " + str(tmp_path / "bin")
         + "\ninclude-system-site-packages = false\n").encode("ascii"))
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
        "pipenv": stage(
            "bin/pipenv",
            ("#!" + str(py_project / ".venv" / "bin" / "python") +
             "\n# controlled Pipenv test-only script bytes\n").encode("ascii")),
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
        assert recipe.selected_image_sha256 == tuple(
            sorted(observation.staged_executables))
        assert recipe.selected_venv_home == (
            private + "/bin" if kind == "pipenv" else None)
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
        if kind == "go":
            assert dict(recipe.closed_child_environment)["GOFLAGS"] == ""
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
    assert denied.value.code in {
        "runner_unavailable", "invalid_argument", "command_not_allowed"}


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


def test_d4_go_recipe_rejects_untrusted_nonempty_goflags_even_if_observation_forged(
        product_service, monkeypatch):
    from gateway.lbe_launch_recipe import (
        D4NativeRecipeDenied, prepare_d4_native_launch_recipe,
    )

    service, workspace = product_service
    private, hashes = _stage_d4_native_bytes_in_private_runner(workspace, kind="go")
    trees = _d4_staged_trees(workspace, "go")
    with monkeypatch.context() as m:
        m.setattr(os, "environ", {"PATH": "/usr/bin:/bin"})
        candidate, _marker, observed = service._prepare_d4_r003_staged_attempt(
            "a", "go-project", ["go", "test", "./..."],
            private_root=private, expected_hashes=hashes,
            expected_trees=trees,
        )
        env = dict(observed.closed_child_environment)
        assert env["GOFLAGS"] == ""
        env["GOFLAGS"] = "-toolexec=/outside/forbidden"
        forged = replace(observed, closed_child_environment=tuple(sorted(env.items())))
        with pytest.raises(D4NativeRecipeDenied, match="Go environment"):
            prepare_d4_native_launch_recipe(
                service.get("a"), candidate, forged, private_root=private)
    assert service.info()["exec_policy"]["available"] is False


@pytest.mark.parametrize("kind,cwd,argv,bad_key,bad_value", [
    ("go", "go-project", ["go", "test", "./..."],
     "LD_PRELOAD", "/outside/host_inject"),
    ("go", "go-project", ["go", "vet", "./..."],
     "PATH", "/outside/untrusted:/usr/bin:/bin"),
    ("pipenv", "py-pipenv", ["python", "-m", "pytest", "-q"],
     "PIPENV_PYTHON", "/outside/interpreter"),
    ("pipenv", "py-pipenv", ["python", "-m", "pytest", "-q"],
     "PATH", "/outside/host/untrusted"),
    ("python_direct", "py-direct", ["python", "-m", "pytest", "-q"],
     "LD_LIBRARY_PATH", "/outside/library"),
    ("python_direct", "py-direct",
     ["python", "-m", "compileall", "-q", "./src"],
     "PYTHONINSPECT", "1"),
])
def test_d4_native_recipe_rejects_any_unapproved_child_environment_key_or_path(
        product_service, monkeypatch, kind, cwd, argv, bad_key, bad_value):
    from gateway.lbe_launch_recipe import (
        D4NativeRecipeDenied, prepare_d4_native_launch_recipe,
    )

    service, workspace = product_service
    private, hashes = _stage_d4_native_bytes_in_private_runner(
        workspace, kind=kind)
    trees = _d4_staged_trees(workspace, kind)
    with monkeypatch.context() as m:
        m.setattr(os, "environ", {"PATH": "/usr/bin:/bin"})
        candidate, _marker, observed = service._prepare_d4_r003_staged_attempt(
            "a", cwd, argv, private_root=private,
            expected_hashes=hashes, expected_trees=trees)
        env = dict(observed.closed_child_environment)
        env[bad_key] = bad_value
        forged = replace(observed, closed_child_environment=tuple(sorted(env.items())))
        with pytest.raises(D4NativeRecipeDenied):
            prepare_d4_native_launch_recipe(
                service.get("a"), candidate, forged, private_root=private)
    assert service.info()["exec_policy"]["available"] is False


@pytest.mark.parametrize("kind,cwd,argv", [
    ("python_direct", "py-direct", ["python", "-m", "pytest", "-q"]),
    ("python_direct", "py-direct",
     ["python", "-m", "compileall", "-q", "./src"]),
    ("pipenv", "py-pipenv", ["python", "-m", "pytest", "-q"]),
    ("go", "go-project", ["go", "test", "./..."]),
    ("go", "go-project", ["go", "vet", "./..."]),
    ("go", "go-project", ["go", "build", "-o", "bin/app", "./cmd/app"]),
])
def test_d4_host_preflight_observes_actual_kernel_and_private_root_not_t1(
        product_service, monkeypatch, kind, cwd, argv):
    from gateway.lbe_runner_preflight import (
        D4RunnerProbeDenied, require_d4_native_runner_admission,
    )

    service, workspace = product_service
    private, hashes = _stage_d4_native_bytes_in_private_runner(
        workspace, kind=kind)
    trees = _d4_staged_trees(workspace, kind)
    with monkeypatch.context() as m:
        m.setattr(os, "environ", {"PATH": "/usr/bin:/bin"})
        m.setattr(subprocess, "Popen", lambda *_a, **_kw: (
            _ for _ in ()).throw(AssertionError("No native T1 authorized")))
        candidate, marker, observed, recipe, host = (
            service._prepare_d4_r003_runner_preflight(
                "a", cwd, argv, private_root=private,
                expected_hashes=hashes, expected_trees=trees,
                timeout_seconds=120))
        assert host.workspace == "a"
        assert host.source_fingerprint == recipe.selected_source_fingerprint
        assert host.kernel_sysname == os.uname().sysname
        assert host.machine == os.uname().machine
        assert host.uid == os.getuid()
        assert host.effective_uid == os.geteuid()
        assert host.pid == os.getpid()
        assert host.kernel_and_private_paths_observed is True
        assert len(host.private_root_inode) == 6
        assert len(host.workspace_inode) == 6
        assert host.proposed_limits == recipe.required_limits
        assert dict(host.proposed_limits)["cpu_millicores_max"] == 2000
        assert dict(host.proposed_limits)["memory_mib_max"] == 4096
        assert host.immutable_github_image_observed is False
        assert host.github_provider_attested is False
        assert host.no_shared_mounts_proven is False
        assert host.no_host_credentials_proven is False
        assert host.loaded_source_graph_proven is False
        assert host.physical_whole_child_cpu_memory_attached is False
        assert host.exact_owner_native_t1_authorized is False
        assert host.native_launch_allowed is False
        assert not recipe.native_launch_allowed
        with pytest.raises(D4RunnerProbeDenied, match="NOT_AUTHORIZED"):
            require_d4_native_runner_admission(host, recipe)
        with pytest.raises(GatewayError) as denial:
            service.invoke_exec("a", cwd, argv, dry_run=False)
        assert denial.value.code == "exec_cleanup_proof_required"


def test_d4_host_probe_real_rlimits_and_ci_labels_never_equal_domain_proof(
        product_service, monkeypatch):
    from gateway import lbe_runner_preflight as source

    service, workspace = product_service
    private, hashes = _stage_d4_native_bytes_in_private_runner(
        workspace, kind="python_direct")
    trees = _d4_staged_trees(workspace, "python_direct")
    with monkeypatch.context() as m:
        m.setattr(os, "environ", {"PATH": "/usr/bin:/bin"})
        candidate, marker, _obs, recipe = service._prepare_d4_r003_native_recipe(
            "a", "py-direct", ["python", "-m", "pytest", "-q"],
            private_root=private, expected_hashes=hashes, expected_trees=trees)
        m.setattr(source.resource, "getrlimit", lambda _resource: (10, 10))
        os.environ.update({
            "GITHUB_ACTIONS": "true",
            "GITHUB_TOKEN": "fake-test-value-never-serialized",
            "HTTPS_PROXY": "http://fake.test.invalid:1234",
        })
        host = source.observe_d4_runner_preflight(
            service.get("a"), recipe, private_root=private)
    assert host.claimed_ci_label_present is True
    assert host.ambient_sensitive_credentials_present is True
    assert host.ambient_proxy_settings_present is True
    assert host.rlimit_cpu_seconds_soft == 10
    assert host.rlimit_as_bytes_soft == 10
    assert host.physical_whole_child_cpu_memory_attached is False
    assert host.github_provider_attested is False
    assert host.native_launch_allowed is False
    assert "fake-test-value" not in repr(host)


def test_d4_host_preflight_rejects_insecure_workspace_after_native_recipe(
        product_service, monkeypatch):
    from gateway.lbe_runner_preflight import (
        D4RunnerProbeDenied, observe_d4_runner_preflight,
    )

    service, workspace = product_service
    private, hashes = _stage_d4_native_bytes_in_private_runner(
        workspace, kind="python_direct")
    trees = _d4_staged_trees(workspace, "python_direct")
    with monkeypatch.context() as m:
        m.setattr(os, "environ", {"PATH": "/usr/bin:/bin"})
        _candidate, _marker, _obs, recipe = (
            service._prepare_d4_r003_native_recipe(
                "a", "py-direct", ["python", "-m", "pytest", "-q"],
                private_root=private, expected_hashes=hashes, expected_trees=trees))
        workspace.chmod(0o777)
        with pytest.raises(D4RunnerProbeDenied, match="owner controlled"):
            observe_d4_runner_preflight(
                service.get("a"), recipe, private_root=private)


def test_d4_host_probe_forged_resource_and_image_claim_is_still_hard_denied(
        product_service, monkeypatch):
    from gateway.lbe_runner_preflight import (
        D4RunnerProbeDenied, observe_d4_runner_preflight,
        require_d4_native_runner_admission,
    )

    service, workspace = product_service
    private, hashes = _stage_d4_native_bytes_in_private_runner(
        workspace, kind="go")
    trees = _d4_staged_trees(workspace, "go")
    with monkeypatch.context() as m:
        m.setattr(os, "environ", {"PATH": "/usr/bin:/bin"})
        _candidate, _marker, _obs, recipe = (
            service._prepare_d4_r003_native_recipe(
                "a", "go-project", ["go", "vet", "./..."],
                private_root=private, expected_hashes=hashes,
                expected_trees=trees))
        host = observe_d4_runner_preflight(
            service.get("a"), recipe, private_root=private)
        forged = replace(host,
            github_provider_attested=True,
            immutable_github_image_observed=True,
            physical_whole_child_cpu_memory_attached=True,
            exact_owner_native_t1_authorized=True,
            native_launch_allowed=True,
            blockers=())
        with pytest.raises(D4RunnerProbeDenied, match="NOT_AUTHORIZED"):
            require_d4_native_runner_admission(forged, recipe)
        with pytest.raises(D4RunnerProbeDenied, match="promoted"):
            observe_d4_runner_preflight(
                service.get("a"), replace(recipe, native_launch_allowed=True),
                private_root=private)
    assert service.info()["exec_policy"]["available"] is False


@pytest.mark.parametrize("mutation", [
    "outside_python", "env_python", "wrong_private_python",
    "interpreter_flags", "crlf_shebang", "no_shebang",
])
def test_d4_pipenv_script_interpreter_must_be_exact_staged_private_python(
        product_service, monkeypatch, mutation):
    import hashlib

    service, workspace = product_service
    private, hashes = _stage_d4_native_bytes_in_private_runner(
        workspace, kind="pipenv")
    pinned_python = str(workspace / "py-pipenv" / ".venv" / "bin" / "python")
    if mutation == "outside_python":
        data = b"#!/usr/bin/python3\n#not trusted\n"
    elif mutation == "env_python":
        data = b"#!/usr/bin/env python3\n#not trusted\n"
    elif mutation == "wrong_private_python":
        data = ("#!" + private + "/bin/python\n#wrong private interpreter\n"
                ).encode("ascii")
    elif mutation == "interpreter_flags":
        data = ("#!" + pinned_python + " -I\n#extra argument\n").encode("ascii")
    elif mutation == "crlf_shebang":
        data = ("#!" + pinned_python + "\r\n#wrong line ending\n").encode("ascii")
    else:
        data = b"no-shebang-even-if-content-hash-is-pinned\n"
    entrypoint = workspace.parent.parent / "bin" / "pipenv"
    entrypoint.write_bytes(data)
    hashes["pipenv"] = hashlib.sha256(data).hexdigest()
    # The EXACT bad bytes are included in the supplied manifest: digest
    # matching is not enough to qualify the kernel-selected interpreter.
    trees = _d4_staged_trees(workspace, "pipenv")
    with monkeypatch.context() as m:
        m.setattr(os, "environ", {"PATH": "/usr/bin:/bin"})
        m.setattr(subprocess, "Popen", lambda *_a, **_kw: (
            _ for _ in ()).throw(AssertionError("foreign script must not spawn")))
        with pytest.raises(GatewayError) as denied:
            service._prepare_d4_r003_native_recipe(
                "a", "py-pipenv", ["python", "-m", "pytest", "-q"],
                private_root=private, expected_hashes=hashes,
                expected_trees=trees)
    assert denied.value.code == "runner_unavailable"


@pytest.mark.parametrize("kind,cwd,argv", [
    ("python_direct", "py-direct", ["python", "-m", "pytest", "-q"]),
    ("python_direct", "py-direct",
     ["python", "-m", "compileall", "-q", "./src"]),
    ("pipenv", "py-pipenv", ["python", "-m", "pytest", "-q"]),
    ("go", "go-project", ["go", "test", "./..."]),
    ("go", "go-project", ["go", "vet", "./..."]),
    ("go", "go-project", ["go", "build", "-o", "bin/app", "./cmd/app"]),
])
def test_d4_product_stages_real_runtime_bytes_then_prepares_six_recipes(
        product_service, monkeypatch, kind, cwd, argv):
    import hashlib

    from gateway.lbe_direct_owner import DirectChildOwner
    from gateway.lbe_worker import LbeWorker
    from gateway.lbe_runner_preflight import require_d4_native_runner_admission
    from gateway.lbe_runtime_stage import D4RuntimeStageReceipt

    service, workspace = product_service
    private = workspace.parent.parent
    provisioner_root = private.parent / (private.name + "-provisioner")
    for folder in ("home", "tmp"):
        (private / folder).mkdir(exist_ok=True)
    if kind == "go":
        for folder in ("gopath", "modcache", "gocache", "gotmp"):
            (private / folder).mkdir(exist_ok=True)
        selections = {
            "go": {
                "bin/go": b"inert primary Go bytes",
                "pkg/tool/darwin_arm64/compile": b"inert Go compiler bytes",
                "pkg/tool/darwin_arm64/link": b"inert Go linker bytes",
                "src/runtime/runtime.go": b"package runtime\n",
            }
        }
    elif kind == "pipenv":
        firstparty = workspace / "py-pipenv"
        selections = {
            "bin": {
                "pipenv": (
                    "#!" + str(firstparty / ".venv" / "bin" / "python") +
                    "\n# trusted test-only Pipenv script bytes\n").encode("ascii"),
            },
            "lib": {"python/stdlib.py": b"x = 1\n"},
        }
    else:
        selections = {
            "bin": {"python": b"inert direct Python bytecode executable"},
            "lib": {"python/stdlib.py": b"x = 1\n"},
        }
    expected_hashes = {}
    with monkeypatch.context() as m:
        m.setattr(os, "environ", {"PATH": "/usr/bin:/bin"})
        m.setattr(subprocess, "Popen", lambda *_a, **_kw: (
            _ for _ in ()).throw(AssertionError("native PRODUCT_T1 must not execute")))
        for stage_kind, files in selections.items():
            provisioned = provisioner_root / stage_kind
            provisioned.mkdir(parents=True)
            for relative, content in files.items():
                source = provisioned / relative
                source.parent.mkdir(parents=True, exist_ok=True)
                source.write_bytes(content)
                source.chmod(0o700 if not relative.endswith((".go", ".py")) else 0o600)
            receipt = service._stage_d4_r003_operator_source(
                "a", cwd, argv, private_root=str(private),
                provisioner_root=str(provisioner_root),
                kind=stage_kind, expected=_d4_tree_expected(provisioned))
            assert type(receipt) is D4RuntimeStageReceipt
            assert receipt.staged_files_verified is True
            assert receipt.native_launch_allowed is False
            assert receipt.loaded_runtime_sources_proven is False
        if kind == "go":
            expected_hashes = {
                key: hashlib.sha256((private / relative).read_bytes()).hexdigest()
                for key, relative in (
                    ("go", "go/bin/go"),
                    ("compile", "go/pkg/tool/darwin_arm64/compile"),
                    ("link", "go/pkg/tool/darwin_arm64/link"),
                )
            }
        elif kind == "pipenv":
            firstparty = workspace / "py-pipenv"
            expected_hashes = {
                "Pipfile": hashlib.sha256((firstparty / "Pipfile").read_bytes()).hexdigest(),
                "Pipfile.lock": hashlib.sha256((firstparty / "Pipfile.lock").read_bytes()).hexdigest(),
                "pyvenv.cfg": hashlib.sha256((firstparty / ".venv/pyvenv.cfg").read_bytes()).hexdigest(),
                "python": hashlib.sha256((firstparty / ".venv/bin/python").read_bytes()).hexdigest(),
                "pipenv": hashlib.sha256((private / "bin/pipenv").read_bytes()).hexdigest(),
            }
        else:
            expected_hashes = {
                "python": hashlib.sha256((private / "bin/python").read_bytes()).hexdigest()
            }
        trees = _d4_staged_trees(workspace, kind)
        candidate, marker, observation, recipe, runner = (
            service._prepare_d4_r003_runner_preflight(
                "a", cwd, argv, private_root=str(private),
                expected_hashes=expected_hashes, expected_trees=trees))
        assert candidate.plan.requested_argv == tuple(argv)
        assert recipe.resolved_executable.startswith(str(private) + "/")
        assert recipe.native_launch_allowed is False
        assert observation.native_launch_allowed is False
        assert runner.physical_whole_child_cpu_memory_attached is False
        assert runner.native_launch_allowed is False
        with pytest.raises(Exception, match="NOT_AUTHORIZED"):
            require_d4_native_runner_admission(runner, recipe)
        result = LbeWorker(DirectChildOwner(), launcher=_no_child_launcher).run(
            candidate.plan, product_attempt=marker)
        assert result["status"] == "launch_failed"
        assert result["executed"] is False
        with pytest.raises(GatewayError) as denied:
            service.invoke_exec("a", cwd, argv, dry_run=False)
        assert denied.value.code == "exec_cleanup_proof_required"


def test_d4_service_staging_cannot_select_foreign_source_kind(
        product_service):
    service, workspace = product_service
    private = workspace.parent.parent
    provisioner_root = private.parent / (private.name + "-provisioner")
    with pytest.raises(GatewayError) as denied:
        service._stage_d4_r003_operator_source(
            "a", "go-project", ["go", "test", "./..."],
            private_root=str(private), provisioner_root=str(provisioner_root),
            kind="bin",
            expected=(("", None),))
    assert denied.value.code == "runner_unavailable"
    assert not (private / "bin").exists()


@pytest.mark.parametrize("kind,cwd,argv,strict_p007,strict_record,record_drift", [
    ("go", "go-project", ["go", "test", "./..."], False, False, None),
    ("go", "go-project", ["go", "build", "-o", "bin/app", "./cmd/app"], False, False, None),
    ("go", "go-project", ["go", "test", "./..."], True, False, None),
    ("go", "go-project", ["go", "build", "-o", "bin/app", "./cmd/app"], True, False, None),
    ("python_direct", "py-direct", ["python", "-m", "pytest", "-q"], False, False, None),
    ("python_direct", "py-direct",
     ["python", "-m", "compileall", "-q", "./src"], False, False, None),
    ("pipenv", "py-pipenv", ["python", "-m", "pytest", "-q"], False, False, None),
    ("pipenv", "py-pipenv", ["python", "-m", "pytest", "-q"], False, True, None),
    ("pipenv", "py-pipenv", ["python", "-m", "pytest", "-q"], False, True, "source_bytes"),
    ("pipenv", "py-pipenv", ["python", "-m", "pytest", "-q"], False, True, "record_hash"),
    ("pipenv", "py-pipenv", ["python", "-m", "pytest", "-q"], False, True, "same_bytes_new_inode"),
])
def test_d4_product_assembles_full_source_only_runner_from_separate_provisioner(
        product_service, monkeypatch, kind, cwd, argv, strict_p007,
        strict_record, record_drift):
    from gateway.lbe_direct_owner import DirectChildOwner
    from gateway.lbe_worker import LbeWorker, LbeWorkerError

    import struct

    def private_macho(label, *, install_name=None, file_type=2):
        install = (install_name or ("/usr/lib/" + label + ".dylib")).encode(
            "ascii") + b"\x00"
        size = (24 + len(install) + 3) & ~3
        cmd = (struct.pack("<III", 0x0C, size, 24) + b"\x00" * 12
               + install + b"\x00" * (size - 24 - len(install)))
        return struct.pack(
            "<IIIIIIII", 0xFEEDFACF, 0x0100000C, 0, file_type,
            1, len(cmd), 0, 0) + cmd

    service, workspace = product_service
    private = workspace.parent.parent
    provisioner = private.parent / (private.name + "-operator")
    if kind == "go":
        trees_data = {"go": {
            "bin/go": private_macho("Go"),
            "pkg/tool/darwin_arm64/compile": private_macho("Compile"),
            "pkg/tool/darwin_arm64/link": private_macho("Link"),
            "src/runtime/runtime.go": b"package runtime\n",
        }}
        needed_scratch = {"home", "tmp", "gopath", "modcache", "gocache", "gotmp"}
    elif kind == "python_direct":
        trees_data = {
            "bin": {"python": private_macho(
                "Python", install_name="@loader_path/../lib/libPrivate.dylib")},
            "lib": {
                "python/stdlib.py": b"x=1\n",
                "libPrivate.dylib": private_macho("PrivateLib", file_type=6),
            },
        }
        needed_scratch = {"home", "tmp"}
    else:
        interpreter = str(workspace / "py-pipenv" / ".venv/bin/python")
        trees_data = {
            "bin": {
                "pipenv": ("#!" + interpreter +
                           "\n# preselected inert Pipenv source bytes\n").encode("ascii"),
            },
            "lib": {"python/stdlib.py": b"x=1\n"},
        }
        needed_scratch = {"home", "tmp"}

    manifests = {}
    for source_kind, files in trees_data.items():
        root = provisioner / source_kind
        root.mkdir(parents=True, exist_ok=True)
        for name, data in files.items():
            f = root / name
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_bytes(data)
            f.chmod(0o600 if name.endswith((".py", ".go", ".dylib"))
                    else 0o700)
        manifests[source_kind] = _d4_tree_expected(root)
    if kind == "pipenv":
        # The Pipenv executable is an inspected #! script; the kernel's
        # selected private Python interpreter must ALSO be Mach-O ARM64.
        private_python = workspace / "py-pipenv" / ".venv/bin/python"
        private_python.write_bytes(private_macho("PipenvPython"))
        if strict_record:
            _d4_record_site_fixture(workspace)
    venv_manifest = (
        _d4_tree_expected(workspace / "py-pipenv" / ".venv")
        if kind == "pipenv" else None)
    with monkeypatch.context() as m:
        m.setattr(os, "environ", {"PATH": "/usr/bin:/bin"})
        m.setattr(subprocess, "Popen", lambda *_a, **_kw: (
            _ for _ in ()).throw(AssertionError("no native child in T0")))
        # The separately known fixture manifest is the test's reviewed
        # expected input; actual operator-observed inode identities must ALSO
        # match across observation and source materialization.
        offered = service._observe_d4_r003_operator_provisioner(
            "a", cwd, argv, provisioner_root=str(provisioner))
        assert set(offered) == (set(manifests) | (
            {"venv"} if kind == "pipenv" else set()))
        assert all(offered[kind_name].proposed_manifest == tuple(
            sorted(manifests[kind_name])) for kind_name in manifests)
        if kind == "pipenv":
            assert offered["venv"].proposed_manifest == tuple(sorted(venv_manifest))
        identity_pins = {
            name: view.observed_source_identity_sha256
            for name, view in offered.items() if name in manifests
        }
        if strict_p007:
            # A positive T0 check of the ACTUAL service staging path only.
            # The synthetic pin override is scoped to this disposable test;
            # it is NOT the real 15657-member Go release or owner signature.
            import gateway.lbe_runtime_tree as source_tree
            m.setattr(source_tree, "_P007_GO_STAGE_FILE_COUNT",
                      offered["go"].file_count)
            m.setattr(source_tree, "_P007_GO_STAGE_SHA256",
                      offered["go"].go_p007_stage_manifest_sha256)
            m.setattr(source_tree, "_P007_GO_CRITICAL_FILES",
                      frozenset({
                          "bin/go", "pkg/tool/darwin_arm64/compile",
                          "pkg/tool/darwin_arm64/link",
                          "src/runtime/runtime.go",
                      }))
            assert source_tree._d4_p007_go_stage_matches(manifests["go"])
        candidate, marker, observed, recipe, runner, native, graph, receipts = (
            service._assemble_d4_r003_source_only_runner(
                "a", cwd, argv, private_root=str(private),
                provisioner_root=str(provisioner),
                staged_manifests=manifests, venv_manifest=venv_manifest,
                expected_source_identities=identity_pins,
                expected_venv_identity_sha256=(
                    offered["venv"].observed_source_identity_sha256
                    if kind == "pipenv" else None),
                require_go_p007_stage_source=strict_p007,
                expected_venv_record_distributions=(
                    (("example-pkg", "1.0"),) if strict_record else None)))
        assert candidate.plan.requested_argv == tuple(argv)
        assert len(receipts) == len(manifests)
        assert all(x.staged_files_verified and not x.native_launch_allowed
                   and x.review_source_identity_bound for x in receipts)
        for name in needed_scratch:
            assert (private / name).is_dir()
            assert not list((private / name).iterdir())
        assert not (private / "provisioned").exists()
        assert observed.bounded_staged_file_set_checked is True
        assert observed.native_launch_allowed is False
        assert recipe.native_launch_allowed is False
        assert runner.native_launch_allowed is False
        assert runner.physical_whole_child_cpu_memory_attached is False
        assert native.native_launch_allowed is False
        assert native.actual_loaded_source_graph_proven is False
        assert len(native.static_selected_executables) == (
            3 if kind == "go" else 1)
        assert all(item.selected_cpu == "arm64"
                   and item.native_launch_allowed is False
                   for _, item in native.static_selected_executables)
        assert graph.native_launch_allowed is False
        assert graph.dynamically_loaded_all_sources_proven is False
        if kind == "python_direct":
            assert tuple(path for path, _ in graph.private_native_images) == (
                "lib/libPrivate.dylib",)
        else:
            assert graph.private_native_images == ()
        if record_drift is None:
            result = LbeWorker(DirectChildOwner(), launcher=_no_child_launcher).run(
                candidate.plan, product_attempt=marker)
            assert result["status"] == "launch_failed"
            assert result["executed"] is False
        else:
            assert kind == "pipenv" and strict_record
            site = workspace / "py-pipenv/.venv/lib/python3.13/site-packages"
            entry = site / "example_pkg/entry.py"
            if record_drift == "source_bytes":
                entry.write_bytes(b"answer = 43\n")
            elif record_drift == "record_hash":
                record = site / "example_pkg-1.0.dist-info/RECORD"
                record.write_text(
                    record.read_text("utf-8").replace("sha256=", "sha256=AAAA", 1),
                    encoding="utf-8")
            else:
                assert record_drift == "same_bytes_new_inode"
                original_inode = entry.stat().st_ino
                replacement = entry.with_name("new-entry.py")
                replacement.write_bytes(entry.read_bytes())
                os.chmod(replacement, entry.stat().st_mode & 0o777)
                os.replace(replacement, entry)
                assert entry.stat().st_ino != original_inode
            attempted = []
            def forbidden(_plan):
                attempted.append(True)
                raise AssertionError("Pipenv RECORD drift must deny before launcher")
            with pytest.raises(LbeWorkerError) as denial:
                LbeWorker(DirectChildOwner(), launcher=forbidden).run(
                    candidate.plan, product_attempt=marker)
            assert denial.value.code == "attempt_replay_denied"
            with pytest.raises(LbeWorkerError) as replay:
                LbeWorker(DirectChildOwner(), launcher=forbidden).run(
                    candidate.plan, product_attempt=marker)
            assert replay.value.code == "attempt_replay_denied"
            assert attempted == []
        with pytest.raises(GatewayError) as refused:
            service.invoke_exec("a", cwd, argv, dry_run=False)
        assert refused.value.code == "exec_cleanup_proof_required"


def test_d4_bundle_invalid_manifest_selection_denied_before_any_staging(
        product_service):
    service, workspace = product_service
    private = workspace.parent.parent
    provisioner = private.parent / (private.name + "-operator")
    with pytest.raises(GatewayError) as denied:
        service._assemble_d4_r003_source_only_runner(
            "a", "go-project", ["go", "vet", "./..."],
            private_root=str(private), provisioner_root=str(provisioner),
            staged_manifests={"bin": (("", None),)})
    assert denied.value.code == "runner_unavailable"
    assert not (private / "go").exists()
    assert not (private / "home").exists()


def test_d4_pipenv_bundle_without_venv_sources_denied_before_staging(
        product_service):
    service, workspace = product_service
    private = workspace.parent.parent
    provisioner = private.parent / (private.name + "-operator")
    with pytest.raises(GatewayError) as denied:
        service._assemble_d4_r003_source_only_runner(
            "a", "py-pipenv", ["python", "-m", "pytest", "-q"],
            private_root=str(private), provisioner_root=str(provisioner),
            staged_manifests={"bin": (("", None),), "lib": (("", None),)})
    assert denied.value.code == "runner_unavailable"
    assert not (private / "bin").exists()


@pytest.mark.parametrize("kind,cwd,argv,drift", [
    ("python_direct", "py-direct", ["python", "-m", "pytest", "-q"],
     "ambient_proxy"),
    ("pipenv", "py-pipenv", ["python", "-m", "pytest", "-q"],
     "soft_cpu_limit"),
    ("go", "go-project", ["go", "test", "./..."],
     "ambient_proxy"),
])
def test_d4_real_runner_observation_rechecked_once_after_marker_burn(
        product_service, monkeypatch, kind, cwd, argv, drift):
    from gateway.lbe_direct_owner import DirectChildOwner
    from gateway.lbe_worker import LbeWorker, LbeWorkerError
    from gateway import lbe_runner_preflight

    service, workspace = product_service
    private, hashes = _stage_d4_native_bytes_in_private_runner(
        workspace, kind=kind)
    trees = _d4_staged_trees(workspace, kind)
    launched = []
    def forbidden(_plan):
        launched.append(True)
        raise AssertionError("Changed real Runner state must never launch")
    with monkeypatch.context() as m:
        m.setattr(os, "environ", {"PATH": "/usr/bin:/bin"})
        candidate, marker, _observed, recipe, runner = (
            service._prepare_d4_r003_runner_preflight(
                "a", cwd, argv, private_root=private,
                expected_hashes=hashes, expected_trees=trees))
        assert runner.native_launch_allowed is False
        assert recipe.native_launch_allowed is False
        if drift == "ambient_proxy":
            os.environ["HTTPS_PROXY"] = "http://untrusted-proxy.invalid"
        else:
            m.setattr(lbe_runner_preflight.resource, "getrlimit",
                      lambda _kind: (10, 10))
        with pytest.raises(LbeWorkerError) as denied:
            LbeWorker(DirectChildOwner(), launcher=forbidden).run(
                candidate.plan, product_attempt=marker)
        assert denied.value.code == "attempt_replay_denied"
        with pytest.raises(LbeWorkerError) as replay:
            LbeWorker(DirectChildOwner(), launcher=forbidden).run(
                candidate.plan, product_attempt=marker)
        assert replay.value.code == "attempt_replay_denied"
    assert launched == []


def test_d4_runner_source_recheck_cannot_be_attached_from_generic_callback(
        product_service):
    from gateway.lbe_product_fixture import D4OneUseAttemptMarker

    service, _workspace = product_service
    candidate, marker = service._prepare_d4_r003_attempt(
        "a", "py-direct", ["python", "-m", "pytest", "-q"])
    assert type(marker) is D4OneUseAttemptMarker
    with pytest.raises(D4FixtureDenied):
        marker.attach_runner_source(lambda *_args: None)
    assert candidate.native_launch_allowed is False
    assert service.info()["exec_policy"]["available"] is False


@pytest.mark.parametrize("kind,cwd,argv", [
    ("python_direct", "py-direct", ["python", "-m", "pytest", "-q"]),
    ("python_direct", "py-direct",
     ["python", "-m", "compileall", "-q", "./src"]),
    ("pipenv", "py-pipenv", ["python", "-m", "pytest", "-q"]),
    ("go", "go-project", ["go", "test", "./..."]),
    ("go", "go-project", ["go", "vet", "./..."]),
    ("go", "go-project", ["go", "build", "-o", "bin/app", "./cmd/app"]),
])
def test_d4_service_selects_real_static_arm64_loader_in_six_source_recipes(
        product_service, monkeypatch, kind, cwd, argv):
    import hashlib
    import struct
    from gateway.lbe_macho_loader import (
        D4MachOLoaderDenied, authorize_d4_native_from_static_macho,
    )

    service, workspace = product_service
    private, hashes = _stage_d4_native_bytes_in_private_runner(
        workspace, kind=kind)
    if kind == "go":
        selected = Path(private) / "go/bin/go"
    elif kind == "pipenv":
        selected = workspace / "py-pipenv/.venv/bin/python"
    else:
        selected = Path(private) / "bin/python"
    lib = b"/usr/lib/libSystem.B.dylib\x00"
    cmdsize = (24 + len(lib) + 3) & ~3
    cmd = (struct.pack("<III", 0x0C, cmdsize, 24)
           + b"\x00" * 12 + lib
           + b"\x00" * (cmdsize - 24 - len(lib)))
    native_data = struct.pack(
        "<IIIIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 1, len(cmd), 0, 0) + cmd
    selected.write_bytes(native_data)
    hashes["go" if kind == "go" else "python"] = (
        hashlib.sha256(native_data).hexdigest())
    trees = _d4_staged_trees(workspace, kind)
    with monkeypatch.context() as m:
        m.setattr(os, "environ", {"PATH": "/usr/bin:/bin"})
        m.setattr(subprocess, "Popen", lambda *_a, **_kw: (
            _ for _ in ()).throw(AssertionError("no T1 for Mach-O source T0")))
        candidate, marker, observation, recipe, host, macho = (
            service._prepare_d4_r003_selected_macho_source(
                "a", cwd, argv, private_root=private,
                expected_hashes=hashes, expected_trees=trees))
        assert macho.selected_cpu == "arm64"
        assert macho.selected_sha256 == hashlib.sha256(native_data).hexdigest()
        assert macho.selected_relative_executable == str(selected)[len(private) + 1:]
        assert macho.declared_direct_libraries == ("/usr/lib/libSystem.B.dylib",)
        assert macho.full_loaded_source_graph_attested is False
        assert macho.actual_dyld_resolution_attested is False
        assert macho.native_launch_allowed is False
        assert observation.native_launch_allowed is False
        assert recipe.native_launch_allowed is False
        assert host.native_launch_allowed is False
        with pytest.raises(D4MachOLoaderDenied, match="NOT_AUTHORIZED"):
            authorize_d4_native_from_static_macho(macho)
        with pytest.raises(GatewayError) as denied:
            service.invoke_exec("a", cwd, argv, dry_run=False)
        assert denied.value.code == "exec_cleanup_proof_required"


def test_d4_service_macho_loader_rejects_non_macho_even_with_exact_source_hash(
        product_service, monkeypatch):
    import hashlib

    service, workspace = product_service
    private, hashes = _stage_d4_native_bytes_in_private_runner(
        workspace, kind="python_direct")
    interpreter = Path(private) / "bin/python"
    data = b"not a Darwin ARM64 executable" + b"x" * 80
    interpreter.write_bytes(data)
    hashes["python"] = hashlib.sha256(data).hexdigest()
    trees = _d4_staged_trees(workspace, "python_direct")
    with monkeypatch.context() as m:
        m.setattr(os, "environ", {"PATH": "/usr/bin:/bin"})
        with pytest.raises(GatewayError) as denied:
            service._prepare_d4_r003_selected_macho_source(
                "a", "py-direct", ["python", "-m", "pytest", "-q"],
                private_root=private,
                expected_hashes=hashes, expected_trees=trees)
    assert denied.value.code == "runner_unavailable"
    assert service.info()["exec_policy"]["available"] is False


@pytest.mark.parametrize("kind,cwd,argv", [
    ("go", "go-project", ["go", "test", "./..."]),
    ("go", "go-project", ["go", "vet", "./..."]),
    ("go", "go-project", ["go", "build", "-o", "bin/app", "./cmd/app"]),
    ("python_direct", "py-direct", ["python", "-m", "pytest", "-q"]),
    ("python_direct", "py-direct",
     ["python", "-m", "compileall", "-q", "./src"]),
    ("pipenv", "py-pipenv", ["python", "-m", "pytest", "-q"]),
])
def test_d4_actual_static_selected_native_set_and_one_use_worker(
        product_service, monkeypatch, kind, cwd, argv):
    import hashlib
    import struct
    from gateway.lbe_direct_owner import DirectChildOwner
    from gateway.lbe_worker import LbeWorker
    from gateway.lbe_native_loader_set import (
        D4NativeLoaderSetDenied, authorize_d4_native_from_loader_set,
    )

    service, workspace = product_service
    private, hashes = _stage_d4_native_bytes_in_private_runner(
        workspace, kind=kind)

    def mach_o(data_name):
        name = ("/usr/lib/" + data_name + ".dylib").encode("ascii") + b"\x00"
        command_size = (24 + len(name) + 3) & ~3
        load = (struct.pack("<III", 0x0C, command_size, 24)
                + b"\x00" * 12 + name
                + b"\x00" * (command_size - 24 - len(name)))
        return (struct.pack("<IIIIIIII",
                            0xFEEDFACF, 0x0100000C, 0, 2,
                            1, len(load), 0, 0) + load)

    if kind == "go":
        selected = (
            ("go", Path(private) / "go/bin/go"),
            ("compile", Path(private) / "go/pkg/tool/darwin_arm64/compile"),
            ("link", Path(private) / "go/pkg/tool/darwin_arm64/link"),
        )
    elif kind == "pipenv":
        selected = (("python", workspace / "py-pipenv/.venv/bin/python"),)
    else:
        selected = (("python", Path(private) / "bin/python"),)

    for key, file_path in selected:
        file_bytes = mach_o(key)
        file_path.write_bytes(file_bytes)
        hashes[key] = hashlib.sha256(file_bytes).hexdigest()
    trees = _d4_staged_trees(workspace, kind)
    with monkeypatch.context() as m:
        m.setattr(os, "environ", {"PATH": "/usr/bin:/bin"})
        m.setattr(subprocess, "Popen", lambda *_a, **_kw: (
            _ for _ in ()).throw(AssertionError("no Mach-O executed")))
        candidate, marker, _observed, recipe, host, native = (
            service._prepare_d4_r003_selected_loader_set(
                "a", cwd, argv, private_root=private,
                expected_hashes=hashes, expected_trees=trees))
        assert native.runtime_kind == kind
        assert len(native.static_selected_executables) == (
            3 if kind == "go" else 1)
        assert all(item.selected_cpu == "arm64"
                   and item.native_launch_allowed is False
                   for _label, item in native.static_selected_executables)
        assert native.actual_loaded_source_graph_proven is False
        assert native.native_launch_allowed is False
        assert host.native_launch_allowed is False
        assert recipe.native_launch_allowed is False
        with pytest.raises(D4NativeLoaderSetDenied, match="NOT_AUTHORIZED"):
            authorize_d4_native_from_loader_set(native)
        no_child = LbeWorker(DirectChildOwner(), launcher=_no_child_launcher).run(
            candidate.plan, product_attempt=marker)
        assert no_child["status"] == "launch_failed"
        assert no_child["executed"] is False
        with pytest.raises(GatewayError) as refused:
            service.invoke_exec("a", cwd, argv, dry_run=False)
        assert refused.value.code == "exec_cleanup_proof_required"


def test_d4_go_compiler_invalid_macho_blocks_full_selected_loader_set(
        product_service, monkeypatch):
    import hashlib
    import struct

    service, workspace = product_service
    private, hashes = _stage_d4_native_bytes_in_private_runner(
        workspace, kind="go")
    tool_paths = {
        "go": Path(private) / "go/bin/go",
        "compile": Path(private) / "go/pkg/tool/darwin_arm64/compile",
        "link": Path(private) / "go/pkg/tool/darwin_arm64/link",
    }
    header = struct.pack("<IIIIIIII", 0xFEEDFACF, 0x0100000C,
                         0, 2, 0, 0, 0, 0)
    for key, file_path in tool_paths.items():
        value = (b"bad compiler binary but SHA matches"
                 if key == "compile" else header)
        file_path.write_bytes(value)
        hashes[key] = hashlib.sha256(value).hexdigest()
    trees = _d4_staged_trees(workspace, "go")
    with monkeypatch.context() as m:
        m.setattr(os, "environ", {"PATH": "/usr/bin:/bin"})
        with pytest.raises(GatewayError) as denied:
            service._prepare_d4_r003_selected_loader_set(
                "a", "go-project", ["go", "test", "./..."],
                private_root=private, expected_hashes=hashes,
                expected_trees=trees)
    assert denied.value.code == "runner_unavailable"
    assert service.info()["exec_policy"]["available"] is False


def test_d4_selected_loader_set_changes_after_marker_burn_denied_before_child(
        product_service, monkeypatch):
    import hashlib
    import struct
    from gateway import lbe_native_loader_set
    from gateway.lbe_direct_owner import DirectChildOwner
    from gateway.lbe_worker import LbeWorker, LbeWorkerError

    service, workspace = product_service
    private, hashes = _stage_d4_native_bytes_in_private_runner(
        workspace, kind="python_direct")
    interpreter = Path(private) / "bin/python"
    value = struct.pack("<IIIIIIII", 0xFEEDFACF, 0x0100000C,
                        0, 2, 0, 0, 0, 0)
    interpreter.write_bytes(value)
    hashes["python"] = hashlib.sha256(value).hexdigest()
    trees = _d4_staged_trees(workspace, "python_direct")
    called = []
    def impossible(_plan):
        called.append(True)
        raise AssertionError("untrusted loader recheck never launches")
    with monkeypatch.context() as m:
        m.setattr(os, "environ", {"PATH": "/usr/bin:/bin"})
        candidate, marker, _observed, _recipe, _host, loader_set = (
            service._prepare_d4_r003_selected_loader_set(
                "a", "py-direct", ["python", "-m", "pytest", "-q"],
                private_root=private, expected_hashes=hashes,
                expected_trees=trees))
        # The independently pinned selected-Mach-O observation, not just
        # first-party and host snapshots, must be consumed once before Worker.
        m.setattr(lbe_native_loader_set, "inspect_d4_native_loader_set",
                  lambda *_a, **_kw: replace(
                      loader_set, unresolved_declared_install_names=("changed",)))
        with pytest.raises(LbeWorkerError) as denied:
            LbeWorker(DirectChildOwner(), launcher=impossible).run(
                candidate.plan, product_attempt=marker)
        assert denied.value.code == "attempt_replay_denied"
        with pytest.raises(LbeWorkerError) as replay:
            LbeWorker(DirectChildOwner(), launcher=impossible).run(
                candidate.plan, product_attempt=marker)
        assert replay.value.code == "attempt_replay_denied"
    assert called == []


def test_d4_generic_callback_cannot_claim_selected_loader_set(
        product_service):
    service, _workspace = product_service
    _candidate, marker = service._prepare_d4_r003_attempt(
        "a", "py-direct", ["python", "-m", "pytest", "-q"])
    with pytest.raises(D4FixtureDenied):
        marker.attach_macho_loader_set(lambda *_: None)


def test_d4_product_bundle_rejects_hash_matched_non_macho_go_compiler(
        product_service, monkeypatch):
    import struct
    from gateway.core import GatewayError

    service, workspace = product_service
    private = workspace.parent.parent
    source = private.parent / (private.name + "-operator")
    go_root = source / "go"
    fields = {
        "bin/go": struct.pack(
            "<IIIIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 0, 0, 0, 0),
        "pkg/tool/darwin_arm64/compile": b"bad compiler, exact hash still selected",
        "pkg/tool/darwin_arm64/link": struct.pack(
            "<IIIIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 0, 0, 0, 0),
        "src/runtime/runtime.go": b"package runtime\n",
    }
    go_root.mkdir(parents=True)
    for name, data in fields.items():
        file = go_root / name
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_bytes(data)
        file.chmod(0o600 if name.endswith(".go") else 0o700)
    manifests = {"go": _d4_tree_expected(go_root)}
    with monkeypatch.context() as m:
        m.setattr(os, "environ", {"PATH": "/usr/bin:/bin"})
        m.setattr(subprocess, "Popen", lambda *_a, **_kw: (
            _ for _ in ()).throw(AssertionError("bad toolchain cannot spawn")))
        with pytest.raises(GatewayError) as denied:
            service._assemble_d4_r003_source_only_runner(
                "a", "go-project", ["go", "test", "./..."],
                private_root=str(private), provisioner_root=str(source),
                staged_manifests=manifests)
        assert denied.value.code == "runner_unavailable"
        assert service.info()["exec_policy"]["available"] is False
        with pytest.raises(GatewayError) as public:
            service.invoke_exec("a", "go-project", ["go", "test", "./..."],
                                dry_run=False)
        assert public.value.code == "exec_cleanup_proof_required"


def test_d4_private_dylib_recheck_burns_one_use_attempt_before_launcher(
        product_service, monkeypatch):
    import hashlib
    import struct
    from gateway import lbe_dylib_sources
    from gateway.lbe_direct_owner import DirectChildOwner
    from gateway.lbe_worker import LbeWorker, LbeWorkerError

    service, workspace = product_service
    private = workspace.parent.parent
    provisioner = private.parent / (private.name + "-operator")
    (provisioner / "bin").mkdir(parents=True)
    (provisioner / "lib").mkdir()

    def macho(name, *, file_type=2):
        path = name.encode("ascii") + b"\x00"
        size = (24 + len(path) + 3) & ~3
        command = (struct.pack("<III", 0x0C, size, 24)
                   + b"\x00" * 12 + path
                   + b"\x00" * (size - 24 - len(path)))
        return (struct.pack("<IIIIIIII", 0xFEEDFACF, 0x0100000C,
                            0, file_type, 1, len(command), 0, 0) + command)

    (provisioner / "bin/python").write_bytes(
        macho("@loader_path/../lib/libPrivate.dylib"))
    (provisioner / "bin/python").chmod(0o700)
    (provisioner / "lib/libPrivate.dylib").write_bytes(
        macho("/usr/lib/libSystem.B.dylib", file_type=6))
    (provisioner / "lib/libPrivate.dylib").chmod(0o600)
    manifests = {
        "bin": _d4_tree_expected(provisioner / "bin"),
        "lib": _d4_tree_expected(provisioner / "lib"),
    }
    launched = []
    def impossible(_plan):
        launched.append(True)
        raise AssertionError("private dylib graph drift cannot spawn")
    with monkeypatch.context() as m:
        m.setattr(os, "environ", {"PATH": "/usr/bin:/bin"})
        candidate, marker, _source, _recipe, _runner, _macho, graph, _receipts = (
            service._assemble_d4_r003_source_only_runner(
                "a", "py-direct", ["python", "-m", "pytest", "-q"],
                private_root=str(private),
                provisioner_root=str(provisioner),
                staged_manifests=manifests))
        assert len(graph.private_native_images) == 1
        m.setattr(lbe_dylib_sources, "inspect_d4_private_dylib_candidates",
                  lambda *_a, **_kw: replace(
                      graph, unresolved_dynamic_loader_names=("changed",)))
        with pytest.raises(LbeWorkerError) as denied:
            LbeWorker(DirectChildOwner(), launcher=impossible).run(
                candidate.plan, product_attempt=marker)
        assert denied.value.code == "attempt_replay_denied"
    assert launched == []


@pytest.mark.parametrize("bad_config", [
    "outside_home", "relative_home", "system_site_true", "missing_system_site",
    "duplicate_home", "executable_selector", "command_selector",
    "invalid_version", "unrecognized_selector",
])
def test_d4_pipenv_source_rejects_unqualified_pyvenv_loader_selectors(
        product_service, monkeypatch, bad_config):
    """A pinned hash of an unsafe pyvenv.cfg is NOT imported-source authority."""
    import hashlib

    service, root = product_service
    private, hashes = _stage_d4_native_bytes_in_private_runner(
        root, kind="pipenv")
    cfg = root / "py-pipenv" / ".venv" / "pyvenv.cfg"
    valid_home = private + "/bin"
    safe = ("home = " + valid_home
            + "\ninclude-system-site-packages = false\n")
    variants = {
        "outside_home": "home = /usr/local/bin\ninclude-system-site-packages = false\n",
        "relative_home": "home = ../bin\ninclude-system-site-packages = false\n",
        "system_site_true": "home = " + valid_home
                            + "\ninclude-system-site-packages = true\n",
        "missing_system_site": "home = " + valid_home + "\n",
        "duplicate_home": safe + "home = /usr/local/bin\n",
        "executable_selector": safe + "executable = /usr/local/bin/python\n",
        "command_selector": safe + "command = /usr/local/bin/python -m venv\n",
        "invalid_version": safe + "version = surprise\n",
        "unrecognized_selector": safe + "anything = host\n",
    }
    data = variants[bad_config].encode("ascii")
    cfg.write_bytes(data)
    hashes["pyvenv.cfg"] = hashlib.sha256(data).hexdigest()
    def no_spawn(*_args, **_kwargs):
        raise AssertionError("unqualified venv source may never spawn")
    with monkeypatch.context() as m:
        m.setattr(os, "environ", {"PATH": "/usr/bin:/bin"})
        m.setattr(subprocess, "Popen", no_spawn)
        m.setattr(os, "kill", no_spawn)
        with pytest.raises(GatewayError) as denied:
            service._inspect_d4_r003_staged_runtime(
                "a", "py-pipenv", ["python", "-m", "pytest", "-q"],
                private_root=private, expected_hashes=hashes)
    assert denied.value.code == "runner_unavailable"
    with pytest.raises(GatewayError) as public:
        service.invoke_exec(
            "a", "py-pipenv", ["python", "-m", "pytest", "-q"],
            dry_run=False)
    assert public.value.code == "exec_cleanup_proof_required"


def test_d4_pipenv_source_pins_private_home_without_claiming_import_attestation(
        product_service, monkeypatch):
    service, root = product_service
    private, hashes = _stage_d4_native_bytes_in_private_runner(
        root, kind="pipenv")
    def no_spawn(*_args, **_kwargs):
        raise AssertionError("private config snapshot cannot grant T1")
    with monkeypatch.context() as m:
        m.setattr(os, "environ", {"PATH": "/usr/bin:/bin"})
        m.setattr(subprocess, "Popen", no_spawn)
        observed = service._inspect_d4_r003_staged_runtime(
            "a", "py-pipenv", ["python", "-m", "pytest", "-q"],
            private_root=private, expected_hashes=hashes)
    assert observed.selected_venv_home == private + "/bin"
    assert observed.actual_import_graph_attested is False
    assert observed.owner_native_t1_grant is False
    assert observed.native_launch_allowed is False


@pytest.mark.parametrize("kind,cwd,argv,mutation", [
    ("go", "go-project", ["go", "test", "./..."], "missing_compile"),
    ("go", "go-project", ["go", "vet", "./..."], "renamed_link"),
    ("pipenv", "py-pipenv", ["python", "-m", "pytest", "-q"],
     "missing_interpreter"),
    ("pipenv", "py-pipenv", ["python", "-m", "pytest", "-q"],
     "wrong_interpreter"),
    ("pipenv", "py-pipenv", ["python", "-m", "pytest", "-q"],
     "host_venv_home"),
    ("pipenv", "py-pipenv", ["python", "-m", "pytest", "-q"],
     "missing_venv_home"),
    ("python_direct", "py-direct", ["python", "-m", "pytest", "-q"],
     "unlisted_binary"),
])
def test_d4_native_recipe_pins_all_selected_toolchain_and_interpreter_entries(
        product_service, monkeypatch, kind, cwd, argv, mutation):
    """A real nonexecuting launch recipe must not lose secondary image identity.

    The validated live D4 source observation contains Go's compile/link tools
    or Pipenv's selected Python interpreter and private venv base home. No
    caller-mutable source-only dataclass may silently drop these requirements.
    """
    from gateway.lbe_launch_recipe import (
        D4NativeRecipeDenied, prepare_d4_native_launch_recipe,
    )

    service, workspace = product_service
    private, hashes = _stage_d4_native_bytes_in_private_runner(
        workspace, kind=kind)
    expected_trees = _d4_staged_trees(workspace, kind)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("SOURCE/T0 must not start a native child")

    with monkeypatch.context() as m:
        m.setattr(os, "environ", {"PATH": "/usr/bin:/bin"})
        m.setattr(subprocess, "Popen", forbidden)
        candidate, _marker, observed, _recipe = (
            service._prepare_d4_r003_native_recipe(
                "a", cwd, argv, private_root=private,
                expected_hashes=hashes, expected_trees=expected_trees))
        chosen = list(observed.staged_executables)
        if mutation == "missing_compile":
            chosen = [row for row in chosen if not row[0].endswith("/compile")]
            altered = replace(observed, staged_executables=tuple(chosen))
        elif mutation == "renamed_link":
            chosen = [(("go/pkg/tool/darwin_arm64/surprise" if
                        label.endswith("/link") else label), digest)
                      for label, digest in chosen]
            altered = replace(observed, staged_executables=tuple(chosen))
        elif mutation == "missing_interpreter":
            chosen = [row for row in chosen if not row[0].endswith(
                "/.venv/bin/python")]
            altered = replace(observed, staged_executables=tuple(chosen))
        elif mutation == "wrong_interpreter":
            chosen = [(label, "e" * 64 if label.endswith(
                "/.venv/bin/python") else digest)
                      for label, digest in chosen]
            altered = replace(observed, staged_executables=tuple(chosen))
        elif mutation == "host_venv_home":
            altered = replace(observed, selected_venv_home="/usr/local/bin")
        elif mutation == "missing_venv_home":
            altered = replace(observed, selected_venv_home=None)
        else:
            chosen.append(("lib/foreign-interpreter", "f" * 64))
            altered = replace(observed, staged_executables=tuple(chosen))
        with pytest.raises(D4NativeRecipeDenied):
            prepare_d4_native_launch_recipe(
                service.get("a"), candidate, altered, private_root=private)


def test_d4_native_recipe_retains_exact_private_pipenv_base_home(
        product_service, monkeypatch):
    """The selected real pyvenv.cfg home must survive into the bound recipe."""
    service, workspace = product_service
    private, hashes = _stage_d4_native_bytes_in_private_runner(
        workspace, kind="pipenv")
    with monkeypatch.context() as m:
        m.setattr(os, "environ", {"PATH": "/usr/bin:/bin"})
        m.setattr(subprocess, "Popen", lambda *_a, **_kw: (
            _ for _ in ()).throw(AssertionError("no T1 launch")))
        _candidate, _marker, observed, recipe = (
            service._prepare_d4_r003_native_recipe(
                "a", "py-pipenv", ["python", "-m", "pytest", "-q"],
                private_root=private, expected_hashes=hashes,
                expected_trees=_d4_staged_trees(workspace, "pipenv")))
    assert observed.selected_venv_home == private + "/bin"
    assert recipe.selected_venv_home == observed.selected_venv_home
    assert recipe.native_launch_allowed is False


def test_d4_fixture_inventory_bounds_entries_before_bulk_materialization(
        product_service, monkeypatch):
    """A hostile source directory must not force an unlimited listdir result."""
    import gateway.lbe_product_fixture as product

    service, workspace = product_service
    candidate = service._prepare_d4_r003_fixture_candidate(
        "a", "py-direct", ["python", "-m", "pytest", "-q"])
    for index in range(12):
        (workspace / "py-direct/src" / ("extra_%02d.py" % index)).write_bytes(
            b"source = 1\\n")

    with monkeypatch.context() as m:
        m.setattr(product, "_MAX_SRC_ENTRIES", 8)
        m.setattr(os, "listdir", lambda *_a, **_kw: (
            _ for _ in ()).throw(AssertionError("bulk listdir forbidden")))
        with pytest.raises(D4FixtureDenied, match="first-party D4 source identity unavailable"):
            product.check_d4_r003_fixture(
                service.get("a"), candidate.plan)


@pytest.mark.parametrize("cwd,argv,kinds", [
    ("go-project", ["go", "test", "./..."], ("go",)),
    ("go-project", ["go", "vet", "./..."], ("go",)),
    ("go-project", ["go", "build", "-o", "bin/app", "./cmd/app"],
     ("go",)),
    ("py-direct", ["python", "-m", "pytest", "-q"], ("bin", "lib")),
    ("py-direct", ["python", "-m", "compileall", "-q", "./src"],
     ("bin", "lib")),
    ("py-pipenv", ["python", "-m", "pytest", "-q"], ("bin", "lib", "venv")),
])
def test_d4_service_observes_operator_sources_for_six_reviewable_recipes(
        product_service, monkeypatch, cwd, argv, kinds):
    """The actual WorkspaceService can prepare reviewable source manifests.

    No operator, image, manifest signature or native permission is claimed.
    The caller must separately review any manifest before staging.
    """
    import hashlib

    service, workspace = product_service
    operator = workspace.parent.parent / "operator-source"
    for kind in kinds:
        if kind == "venv":
            continue  # Real source is the first-party project .venv, not operator.
        folder = operator / kind
        folder.mkdir(parents=True, exist_ok=True)
        if kind == "go":
            selected = folder / "bin/go"
            selected.parent.mkdir()
        elif kind == "bin":
            selected = folder / ("pipenv" if cwd == "py-pipenv" else "python")
        else:
            selected = folder / "python/stdlib.py"
            selected.parent.mkdir()
        selected.write_bytes(("inert-" + kind).encode("ascii"))
        selected.chmod(0o700 if kind != "lib" else 0o600)
    def no_spawn(*_args, **_kwargs):
        raise AssertionError("operator source observation cannot execute")
    with monkeypatch.context() as m:
        m.setattr(subprocess, "Popen", no_spawn)
        observed = service._observe_d4_r003_operator_provisioner(
            "a", cwd, argv, provisioner_root=str(operator))
    assert set(observed) == set(kinds)
    for kind in kinds:
        item = observed[kind]
        selected = "bin/go" if kind == "go" else (
            "pipenv" if kind == "bin" and cwd == "py-pipenv" else
            "python" if kind == "bin" else
            "pyvenv.cfg" if kind == "venv" else "python/stdlib.py")
        expected = ((workspace / "py-pipenv/.venv/pyvenv.cfg").read_bytes()
                    if kind == "venv" else ("inert-" + kind).encode("ascii"))
        assert (selected, hashlib.sha256(expected).hexdigest()) in item.proposed_manifest
        if kind == "venv":
            assert item.status == "OBSERVED_FIRST_PARTY_VENV_ONLY_NOT_ATTESTED"
        assert item.manifest_independently_approved is False
        assert item.trusted_operator_attested is False
        assert item.native_launch_allowed is False
        if kind == "go":
            assert len(item.go_p007_stage_manifest_sha256) == 64
            assert item.go_1_27_3_p007_stage_manifest_matched is False
        else:
            assert item.go_p007_stage_manifest_sha256 is None
            assert item.go_1_27_3_p007_stage_manifest_matched is False
    with pytest.raises(GatewayError) as denied:
        service.invoke_exec("a", cwd, argv, dry_run=False)
    assert denied.value.code == "exec_cleanup_proof_required"


def test_d4_service_operator_source_selection_does_not_self_approve_workspace(
        product_service):
    service, workspace = product_service
    with pytest.raises(GatewayError) as denied:
        service._observe_d4_r003_operator_provisioner(
            "a", "py-direct", ["python", "-m", "pytest", "-q"],
            provisioner_root=str(workspace / "py-direct"))
    assert denied.value.code == "runner_unavailable"



@pytest.mark.parametrize("identity_pins", [
    {"bin": "f" * 64}, {"go": "f" * 64},
    {"go": "0" * 64}, {"go": 12}, [], None,
])
def test_d4_assembled_operator_identity_shape_denies_before_staging(
        product_service, identity_pins):
    """Wrong review identity keys/values cannot trigger partial materialization."""
    service, workspace = product_service
    private = workspace.parent.parent
    provisioner = private.parent / (private.name + "-operator")
    with pytest.raises(GatewayError) as denied:
        service._assemble_d4_r003_source_only_runner(
            "a", "go-project", ["go", "test", "./..."],
            private_root=str(private), provisioner_root=str(provisioner),
            staged_manifests={"go": (("", None),)},
            expected_source_identities=identity_pins)
    assert denied.value.code == "runner_unavailable"
    assert not (private / "go").exists()
    assert not (private / "home").exists()



def test_d4_pipenv_first_party_venv_source_manifest_includes_real_site_files(
        product_service, monkeypatch):
    """Product prepares an inspectable .venv manifest, not import authority."""
    import hashlib
    from gateway.lbe_runtime_tree import observe_d4_pipenv_venv_manifest

    service, workspace = product_service
    project = workspace / "py-pipenv"
    site = project / ".venv/lib/python3.13/site-packages/example_pkg"
    site.mkdir(parents=True)
    (site / "__init__.py").write_bytes(b"x = 'inert'\n")
    (site / "entry.py").write_bytes(b"answer = 42\n")
    with monkeypatch.context() as m:
        m.setattr(subprocess, "Popen", lambda *_a, **_kw: (
            _ for _ in ()).throw(AssertionError("venv manifest must not import or spawn")))
        observed = observe_d4_pipenv_venv_manifest(project_root=str(project))
    assert observed.kind == "venv"
    assert ("lib/python3.13/site-packages/example_pkg/entry.py",
            hashlib.sha256(b"answer = 42\n").hexdigest()
            ) in observed.proposed_manifest
    assert ("", None) in observed.proposed_manifest
    assert observed.file_count >= 4
    assert observed.entry_count == len(observed.proposed_manifest)
    assert observed.status == "OBSERVED_FIRST_PARTY_VENV_ONLY_NOT_ATTESTED"
    assert observed.manifest_independently_approved is False
    assert observed.actual_loaded_source_graph_proven is False
    assert observed.native_launch_allowed is False
    with pytest.raises(GatewayError) as refused:
        service.invoke_exec("a", "py-pipenv",
                            ["python", "-m", "pytest", "-q"], dry_run=False)
    assert refused.value.code == "exec_cleanup_proof_required"


@pytest.mark.parametrize("mutation", ["pth", "symlink_interpreter",
                                    "hardlinked_interpreter", "unsafe_site_dir"])
def test_d4_pipenv_venv_source_manifest_denies_unqualified_inputs(
        product_service, mutation):
    from gateway.lbe_runtime_tree import (
        D4RuntimeTreeDenied, observe_d4_pipenv_venv_manifest,
    )

    _service, workspace = product_service
    project = workspace / "py-pipenv"
    venv = project / ".venv"
    if mutation == "pth":
        site = venv / "lib/python3.13/site-packages"
        site.mkdir(parents=True)
        (site / "evil.pth").write_bytes(b"import os\n")
    elif mutation == "symlink_interpreter":
        (venv / "bin/python").unlink()
        (venv / "bin/python").symlink_to("/bin/sh")
    elif mutation == "hardlinked_interpreter":
        os.link(venv / "bin/python", venv / "bin/copy")
    else:
        site = venv / "lib"
        site.mkdir()
        site.chmod(0o777)
    with pytest.raises(D4RuntimeTreeDenied):
        observe_d4_pipenv_venv_manifest(project_root=str(project))


@pytest.mark.parametrize("bad_identity", ["f" * 64, "0" * 64,
                                          "not-a-sha", 17, [], True])
def test_d4_assembled_pipenv_source_rejects_wrong_venv_identity_before_copy(
        product_service, bad_identity):
    from gateway.lbe_runtime_tree import observe_d4_pipenv_venv_manifest

    service, workspace = product_service
    private = workspace.parent.parent
    project = workspace / "py-pipenv"
    observed = observe_d4_pipenv_venv_manifest(project_root=str(project))
    source = private.parent / (private.name + "-operator")
    with pytest.raises(GatewayError) as err:
        service._assemble_d4_r003_source_only_runner(
            "a", "py-pipenv", ["python", "-m", "pytest", "-q"],
            private_root=str(private), provisioner_root=str(source),
            staged_manifests={"bin": (("", None),), "lib": (("", None),)},
            venv_manifest=observed.proposed_manifest,
            expected_venv_identity_sha256=bad_identity)
    assert err.value.code == "runner_unavailable"
    assert not (private / "bin").exists()
    assert not (private / "home").exists()


def test_d4_assembled_pipenv_source_rejects_same_bytes_new_inode_of_venv(
        product_service):
    """A hash-matched first-party .venv replacement must not transfer approval."""
    import hashlib
    from gateway.lbe_runtime_tree import observe_d4_pipenv_venv_manifest

    service, workspace = product_service
    private = workspace.parent.parent
    project = workspace / "py-pipenv"
    observed = observe_d4_pipenv_venv_manifest(project_root=str(project))
    interpreter = project / ".venv/bin/python"
    old_stat = interpreter.stat()
    replacement = project / ".venv/bin/new-python"
    replacement.write_bytes(interpreter.read_bytes())
    replacement.chmod(0o700)
    os.replace(replacement, interpreter)
    assert interpreter.stat().st_ino != old_stat.st_ino
    assert hashlib.sha256(interpreter.read_bytes()).hexdigest() == (
        dict(observed.proposed_manifest)["bin/python"])
    source = private.parent / (private.name + "-operator")
    with pytest.raises(GatewayError) as err:
        service._assemble_d4_r003_source_only_runner(
            "a", "py-pipenv", ["python", "-m", "pytest", "-q"],
            private_root=str(private), provisioner_root=str(source),
            staged_manifests={"bin": (("", None),), "lib": (("", None),)},
            venv_manifest=observed.proposed_manifest,
            expected_venv_identity_sha256=(
                observed.observed_source_identity_sha256))
    assert err.value.code == "runner_unavailable"
    assert not (private / "bin").exists()



@pytest.mark.parametrize("cwd,argv", [
    ("go-project", ["go", "test", "./..."]),
    ("go-project", ["go", "vet", "./..."]),
    ("go-project", ["go", "build", "-o", "bin/app", "./cmd/app"]),
])
def test_d4_go_strict_p007_source_bundle_rejects_incomplete_toolchain_before_copy(
        product_service, cwd, argv):
    """A real operator manifest must match ALL 15657 Go source bytes.

    Three selected executable hashes are not the complete compiler/stdlib
    source inventory. This opt-in SOURCE-only gate never enables native Go.
    """
    service, workspace = product_service
    private = workspace.parent.parent
    provisioner = private.parent / (private.name + "-operator")
    go = provisioner / "go"
    (go / "bin").mkdir(parents=True)
    (go / "bin/go").write_bytes(b"inert Go binary")
    (go / "bin/go").chmod(0o700)
    (go / "pkg/tool/darwin_arm64").mkdir(parents=True)
    for name in ("compile", "link"):
        tool = go / "pkg/tool/darwin_arm64" / name
        tool.write_bytes(("inert " + name).encode("ascii"))
        tool.chmod(0o700)
    (go / "src/runtime").mkdir(parents=True)
    (go / "src/runtime/proc.go").write_bytes(b"package runtime\n")
    manifest = _d4_tree_expected(go)
    observed = service._observe_d4_r003_operator_provisioner(
        "a", cwd, argv, provisioner_root=str(provisioner))
    assert observed["go"].go_1_27_3_p007_stage_manifest_matched is False
    with pytest.raises(GatewayError) as stopped:
        service._assemble_d4_r003_source_only_runner(
            "a", cwd, argv, private_root=str(private),
            provisioner_root=str(provisioner),
            staged_manifests={"go": manifest},
            expected_source_identities={
                "go": observed["go"].observed_source_identity_sha256},
            require_go_p007_stage_source=True)
    assert stopped.value.code == "runner_unavailable"
    assert not (private / "go").exists()
    assert not (private / "home").exists()
    with pytest.raises(GatewayError) as public:
        service.invoke_exec("a", cwd, argv, dry_run=False)
    assert public.value.code == "exec_cleanup_proof_required"


@pytest.mark.parametrize("cwd,argv,required,expected_error", [
    ("go-project", ["go", "test", "./..."], "yes",
     "D4 Go source profile selection invalid"),
    ("py-direct", ["python", "-m", "pytest", "-q"], True,
     "D4 complete Go source not selected"),
    ("py-pipenv", ["python", "-m", "pytest", "-q"], True,
     "D4 complete Go source not selected"),
])
def test_d4_p007_strict_profile_cannot_select_other_runner_or_truthy_flag(
        product_service, cwd, argv, required, expected_error):
    """Strict P007 Go SOURCE selection never becomes a public Exec grant."""
    service, workspace = product_service
    private = workspace.parent.parent
    provisioner = private.parent / (private.name + "-operator")
    manifests = ({"go": (("", None),)} if cwd == "go-project"
                 else {"bin": (("", None),), "lib": (("", None),)})
    with pytest.raises(GatewayError) as denied:
        service._assemble_d4_r003_source_only_runner(
            "a", cwd, argv, private_root=str(private),
            provisioner_root=str(provisioner), staged_manifests=manifests,
            venv_manifest=((("", None),) if cwd == "py-pipenv" else None),
            require_go_p007_stage_source=required)
    assert denied.value.code == "runner_unavailable"
    assert expected_error in str(denied.value)
    assert not (private / "go").exists()
    assert not (private / "bin").exists()



def _d4_record_site_fixture(workspace):
    """Inert first-party test distribution with a complete real RECORD."""
    import base64
    import csv
    import io
    import hashlib

    site = workspace / "py-pipenv/.venv/lib/python3.13/site-packages"
    pkg = site / "example_pkg"
    dist = site / "example_pkg-1.0.dist-info"
    pkg.mkdir(parents=True, exist_ok=True)
    dist.mkdir()
    (pkg / "__init__.py").write_bytes(b"from .entry import answer\n")
    (pkg / "entry.py").write_bytes(b"answer = 42\n")
    (dist / "METADATA").write_bytes(b"Name: example-pkg\nVersion: 1.0\n")
    record = dist / "RECORD"
    rows = []
    for member in (pkg / "__init__.py", pkg / "entry.py", dist / "METADATA"):
        data = member.read_bytes()
        sha = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(
            b"=").decode("ascii")
        rows.append((member.relative_to(site).as_posix(), "sha256=" + sha,
                     str(len(data))))
    rows.append(("example_pkg-1.0.dist-info/RECORD", "", ""))
    text = io.StringIO()
    writer = csv.writer(text, lineterminator="\n")
    writer.writerows(rows)
    record.write_bytes(text.getvalue().encode("utf-8"))
    # RECORD-selected Pipenv source must be traceable to the exact pinned
    # first-party lock default/develop entries, not only a self-made RECORD.
    (workspace / "py-pipenv/Pipfile.lock").write_bytes(
        b'{"_meta":{"hash":{"sha256":"' + b"a" * 64
        + b'"}},"default":{"example-pkg":{"version":"==1.0"}},"develop":{}}\n')
    (workspace / "py-pipenv/Pipfile").write_bytes(
        b'[packages]\nexample-pkg = "==1.0"\n')
    return site, pkg, dist, record


def test_d4_product_pipenv_record_source_observer_prepares_closed_site(
        product_service, monkeypatch):
    from gateway.lbe_runtime_tree import (
        observe_d4_pipenv_venv_manifest,
        inspect_d4_pipenv_installed_record_sources,
    )

    service, workspace = product_service
    site, _pkg, _dist, _record = _d4_record_site_fixture(workspace)
    project = workspace / "py-pipenv"
    assert site.is_dir()
    with monkeypatch.context() as m:
        m.setattr(subprocess, "Popen", lambda *_a, **_kw: (
            _ for _ in ()).throw(AssertionError("source-only cannot spawn")))
        observed = observe_d4_pipenv_venv_manifest(project_root=str(project))
        record_view = inspect_d4_pipenv_installed_record_sources(
            project_root=str(project), expected_venv_manifest=observed.proposed_manifest,
            expected_distributions=(("example-pkg", "1.0"),))
    assert record_view.distributions == (("example-pkg", "1.0"),)
    assert record_view.record_members_checked == 4
    assert record_view.importable_members_checked == 2
    assert record_view.venv_identity_sha256 == (
        observed.observed_source_identity_sha256)
    assert len(record_view.record_manifest_sha256) == 64
    assert record_view.status == "RECORD_LISTED_SITE_BYTES_NOT_IMPORT_CLOSURE"
    assert record_view.actual_loaded_source_graph_proven is False
    assert record_view.external_source_provenance_attested is False
    assert record_view.native_launch_allowed is False
    with pytest.raises(GatewayError) as denied:
        service.invoke_exec(
            "a", "py-pipenv", ["python", "-m", "pytest", "-q"],
            dry_run=False)
    assert denied.value.code == "exec_cleanup_proof_required"


@pytest.mark.parametrize("mutation", [
    "missing_record", "unlisted_py", "unlisted_resource",
    "record_bad_hash", "record_bad_size", "record_traversal",
    "record_absolute", "record_duplicate", "metadata_version",
    "unlisted_zip", "unlisted_other_dist", "record_missing_member",
])
def test_d4_pipenv_record_source_rejects_unlisted_or_forged_site(
        product_service, mutation):
    from gateway.lbe_runtime_tree import (
        D4RuntimeTreeDenied, observe_d4_pipenv_venv_manifest,
        inspect_d4_pipenv_installed_record_sources,
    )

    _service, workspace = product_service
    _site, pkg, dist, record = _d4_record_site_fixture(workspace)
    body = record.read_text("utf-8")
    if mutation == "missing_record":
        record.unlink()
    elif mutation == "unlisted_py":
        (pkg / "injected.py").write_text("import os\n", "utf-8")
    elif mutation == "unlisted_resource":
        (pkg / "payload.json").write_text("{}", "utf-8")
    elif mutation == "record_bad_hash":
        record.write_text(body.replace("sha256=", "sha256=AAAA", 1), "utf-8")
    elif mutation == "record_bad_size":
        line = next(line for line in body.splitlines() if "entry.py" in line)
        record.write_text(body.replace(line, line.rsplit(",", 1)[0] + ",999"),
                          "utf-8")
    elif mutation == "record_traversal":
        record.write_text(body.replace("example_pkg/entry.py",
                                       "../example_pkg/entry.py"), "utf-8")
    elif mutation == "record_absolute":
        record.write_text(body.replace("example_pkg/entry.py",
                                       "/etc/passwd"), "utf-8")
    elif mutation == "record_duplicate":
        record.write_text(body + body.splitlines()[0] + "\n", "utf-8")
    elif mutation == "metadata_version":
        (dist / "METADATA").write_bytes(b"Name: example-pkg\nVersion: 2.0\n")
    elif mutation == "unlisted_zip":
        (pkg / "other.zip").write_bytes(b"PK\x03\x04")
    elif mutation == "unlisted_other_dist":
        foreign = _site / "extra-1.0.dist-info"
        foreign.mkdir()
        (foreign / "METADATA").write_bytes(b"Name: extra\nVersion: 1.0\n")
    elif mutation == "record_missing_member":
        record.write_text(body.replace(
            next(x for x in body.splitlines() if "entry.py" in x) + "\n", ""),
            "utf-8")
    observed = observe_d4_pipenv_venv_manifest(
        project_root=str(workspace / "py-pipenv"))
    with pytest.raises(D4RuntimeTreeDenied):
        inspect_d4_pipenv_installed_record_sources(
            project_root=str(workspace / "py-pipenv"),
            expected_venv_manifest=observed.proposed_manifest,
            expected_distributions=(("example-pkg", "1.0"),))


@pytest.mark.parametrize("wrong", [
    None, [], {}, True, "example-pkg==1.0", (), (("example-pkg", "2.0"),),
    (("example-pkg", "1.0"), ("other", "1.0")),
])
def test_d4_pipenv_record_sources_require_explicit_distribution_identity(
        product_service, wrong):
    from gateway.lbe_runtime_tree import (
        D4RuntimeTreeDenied, observe_d4_pipenv_venv_manifest,
        inspect_d4_pipenv_installed_record_sources,
    )

    _service, workspace = product_service
    _d4_record_site_fixture(workspace)
    project = str(workspace / "py-pipenv")
    source = observe_d4_pipenv_venv_manifest(project_root=project)
    with pytest.raises(D4RuntimeTreeDenied):
        inspect_d4_pipenv_installed_record_sources(
            project_root=project,
            expected_venv_manifest=source.proposed_manifest,
            expected_distributions=wrong)


def test_d4_strict_pipenv_record_selection_denies_before_operator_copy(
        product_service):
    from gateway.lbe_runtime_tree import (
        observe_d4_pipenv_venv_manifest,
    )

    service, workspace = product_service
    private = workspace.parent.parent
    provisioner = private.parent / (private.name + "-operator")
    project = workspace / "py-pipenv"
    site, pkg, _dist, _record = _d4_record_site_fixture(workspace)
    source = observe_d4_pipenv_venv_manifest(project_root=str(project))
    (pkg / "unrecorded.py").write_text("import os\n", "utf-8")
    with pytest.raises(GatewayError) as denied:
        service._assemble_d4_r003_source_only_runner(
            "a", "py-pipenv", ["python", "-m", "pytest", "-q"],
            private_root=str(private), provisioner_root=str(provisioner),
            staged_manifests={"bin": (("", None),), "lib": (("", None),)},
            venv_manifest=source.proposed_manifest,
            expected_venv_identity_sha256=source.observed_source_identity_sha256,
            expected_venv_record_distributions=(("example-pkg", "1.0"),))
    assert denied.value.code == "runner_unavailable"
    assert not (private / "bin").exists()
    assert not (private / "home").exists()



def test_d4_service_observes_pipenv_records_in_real_source_bundle(
        product_service, monkeypatch):
    """The actual operator preparation surface includes its RECORD receipt."""
    service, workspace = product_service
    _d4_record_site_fixture(workspace)
    operator = workspace.parent.parent / "operator-record-bundle"
    binroot = operator / "bin"
    binroot.mkdir(parents=True)
    (binroot / "pipenv").write_bytes(b"inert signed-looking script data")
    (binroot / "pipenv").chmod(0o700)
    stdlib = operator / "lib/python"
    stdlib.mkdir(parents=True)
    (stdlib / "stdlib.py").write_bytes(b"x = 1\n")
    with monkeypatch.context() as m:
        m.setattr(subprocess, "Popen", lambda *_a, **_kw: (
            _ for _ in ()).throw(AssertionError("observation cannot spawn")))
        result = service._observe_d4_r003_operator_provisioner(
            "a", "py-pipenv", ["python", "-m", "pytest", "-q"],
            provisioner_root=str(operator),
            expected_venv_record_distributions=(("example-pkg", "1.0"),))
    assert set(result) == {"bin", "lib", "venv"}
    venv = result["venv"]
    receipt = venv.pipenv_record_sources
    assert receipt is not None
    assert receipt.distributions == (("example-pkg", "1.0"),)
    assert receipt.record_members_checked == 4
    assert receipt.importable_members_checked == 2
    assert receipt.venv_identity_sha256 == (
        venv.observed_source_identity_sha256)
    assert receipt.actual_loaded_source_graph_proven is False
    assert receipt.native_launch_allowed is False
    locked = venv.pipenv_lock_sources
    assert locked is not None
    assert locked.locked_distributions == (("example-pkg", "1.0"),)
    assert locked.selected_installed_distributions == (("example-pkg", "1.0"),)
    assert locked.direct_pipfile_requirements_checked is True
    assert locked.pipfile_sha256 == dict(
        service._prepare_d4_r003_fixture_candidate(
            "a", "py-pipenv", ["python", "-m", "pytest", "-q"]).source_sha256)[
                "py-pipenv/Pipfile"]
    assert locked.actual_loaded_source_graph_proven is False
    assert locked.native_launch_allowed is False
    assert venv.manifest_independently_approved is False
    assert venv.native_launch_allowed is False
    with pytest.raises(GatewayError) as denied:
        service.invoke_exec(
            "a", "py-pipenv", ["python", "-m", "pytest", "-q"],
            dry_run=False)
    assert denied.value.code == "exec_cleanup_proof_required"


def test_d4_service_record_selection_denies_wrong_command_without_source_access(
        product_service):
    """Pipenv installation metadata cannot be selected for Go or Direct."""
    service, workspace = product_service
    operator = workspace.parent.parent / "operator-record-wrong-flavor"
    for cwd, argv in (
        ("go-project", ["go", "test", "./..."]),
        ("py-direct", ["python", "-m", "pytest", "-q"]),
    ):
        with pytest.raises(GatewayError) as denied:
            service._observe_d4_r003_operator_provisioner(
                "a", cwd, argv, provisioner_root=str(operator),
                expected_venv_record_distributions=(("example-pkg", "1.0"),))
        assert denied.value.code == "runner_unavailable"
    assert not operator.exists()




@pytest.mark.parametrize("argv", [
    ["go", "test", "./..."],
    ["go", "vet", "./..."],
    ["go", "build", "-o", "bin/app", "./cmd/app"],
])
@pytest.mark.parametrize("location", ["main", "nested", "module_root"])
def test_d4_go_embed_directive_rejects_uninventoried_compiler_input(
        product_service, monkeypatch, argv, location):
    """Go embed directives can read additional files absent from the fixture.

    A selected .go byte can request a resource at compile-time. Merely
    rejecting extra directory entries without inspecting the directives
    creates a falsely complete source candidate for ALL fixed Go verbs.
    """
    service, workspace = product_service
    go = workspace / "go-project"
    if location == "main":
        selected = go / "cmd/app/main.go"
    elif location == "nested":
        selected = go / "pkg/snapshot/resource.go"
        selected.parent.mkdir(parents=True)
    else:
        selected = go / "entry.go"
    selected.write_bytes(
        b"package main\nimport _ \"embed\"\n"
        b"//go:embed hidden.txt\nvar hidden string\n"
        b"func main() {}\n")
    with monkeypatch.context() as m:
        m.setattr(subprocess, "Popen", lambda *_a, **_kw: (
            _ for _ in ()).throw(AssertionError("source inspection cannot spawn")))
        with pytest.raises(GatewayError) as denied:
            service._prepare_d4_r003_fixture_candidate(
                "a", "go-project", argv)
        assert denied.value.code == "command_not_allowed"
        with pytest.raises(GatewayError) as apply:
            service.invoke_exec("a", "go-project", argv, dry_run=False)
        assert apply.value.code == "exec_cleanup_proof_required"


def test_d4_go_source_regular_comment_and_string_are_not_embed_directives(
        product_service):
    """Ordinary source remains a supported first-party Go candidate."""
    service, workspace = product_service
    (workspace / "go-project/cmd/app/main.go").write_bytes(
        b"package main\n// go:embed in an ordinary comment is not a directive\n"
        b"func main() { _ = \"//go:embed literal\" }\n")
    candidate = service._prepare_d4_r003_fixture_candidate(
        "a", "go-project", ["go", "test", "./..."])
    assert candidate.native_launch_allowed is False
    assert candidate.actual_loaded_sources_proven is False



def test_d4_go_embed_input_crlf_and_tab_indented_directive_denied(product_service):
    """Compiler may process tab-indented directives with CRLF line endings."""
    service, workspace = product_service
    (workspace / "go-project/cmd/app/main.go").write_bytes(
        b"package main\r\nimport _ \"embed\"\r\n"
        b"\t//go:embed missing.txt\r\nvar data string\r\n"
        b"func main() {}\r\n")
    with pytest.raises(GatewayError) as denied:
        service._prepare_d4_r003_fixture_candidate(
            "a", "go-project", ["go", "build", "-o", "bin/app", "./cmd/app"])
    assert denied.value.code == "command_not_allowed"


@pytest.mark.parametrize("argv", [
    ["go", "test", "./..."],
    ["go", "vet", "./..."],
    ["go", "build", "-o", "bin/app", "./cmd/app"],
])
@pytest.mark.parametrize("cgo_syntax", [
    b'import "C"\n',
    b'import (\n "fmt"\n "C"\n)\n',
    b'import ("C")\n',
    b'import _ "C"\n',
])
def test_d4_go_cgo_pseudo_import_requires_unqualified_compiler(
        product_service, monkeypatch, argv, cgo_syntax):
    """cgo may invoke a separate C toolchain or consume headers outside .go.

    Reject that source at the real service admission boundary before any
    source-only recipe or future launcher; CGO_ENABLED=0 is not a proof.
    """
    service, workspace = product_service
    (workspace / "go-project/cmd/app/main.go").write_bytes(
        b"package main\n" + cgo_syntax + b"func main() {}\n")
    with monkeypatch.context() as m:
        m.setattr(subprocess, "Popen", lambda *_a, **_kw: (
            _ for _ in ()).throw(AssertionError("No Go/C compiler can run")))
        with pytest.raises(GatewayError) as denied:
            service._prepare_d4_r003_fixture_candidate(
                "a", "go-project", argv)
    assert denied.value.code == "command_not_allowed"
    with pytest.raises(GatewayError) as apply:
        service.invoke_exec("a", "go-project", argv, dry_run=False)
    assert apply.value.code == "exec_cleanup_proof_required"


def test_d4_go_non_cgo_imports_and_C_text_remain_legal_source(
        product_service):
    """Ordinary Go imports and literals should not be rejected as cgo."""
    service, workspace = product_service
    (workspace / "go-project/cmd/app/main.go").write_bytes(
        b'package main\nimport "fmt"\n'
        b'func main() { fmt.Println("C and import C are only strings") }\n')
    candidate = service._prepare_d4_r003_fixture_candidate(
        "a", "go-project", ["go", "test", "./..."])
    assert candidate.native_launch_allowed is False
    assert candidate.actual_loaded_sources_proven is False


@pytest.mark.parametrize("decl,accepted", [
    (b"go 1.26\n", True),
    (b"go 1.27\n", True),
    (b"go 1.27.3\n", True),
    (b"go 1.27.4\n", False),
    (b"go 1.28\n", False),
    (b"go 1.999\n", False),
])
def test_d4_go_module_version_cannot_exceed_pinned_P007_toolchain(
        product_service, decl, accepted):
    """A future Go language version is not satisfied by pinned Go 1.27.3."""
    service, workspace = product_service
    (workspace / "go-project/go.mod").write_bytes(
        b"module firstparty.test/app\n" + decl)
    if accepted:
        candidate = service._prepare_d4_r003_fixture_candidate(
            "a", "go-project", ["go", "vet", "./..."])
        assert candidate.native_launch_allowed is False
    else:
        with pytest.raises(GatewayError) as denied:
            service._prepare_d4_r003_fixture_candidate(
                "a", "go-project", ["go", "vet", "./..."])
        assert denied.value.code == "command_not_allowed"



@pytest.mark.parametrize("invalid", [
    b'"version":"==2.0"', b'"version":">=1.0"',
    b'"version":"==1.0","path":"../outside"',
])
def test_d4_service_pipenv_record_mismatched_pinned_lock_refused_no_spawn(
        product_service, monkeypatch, invalid):
    """Real service must not call a lock/RECORD mismatch an approved source."""
    service, workspace = product_service
    _d4_record_site_fixture(workspace)
    lock = workspace / "py-pipenv/Pipfile.lock"
    lock.write_bytes(lock.read_bytes().replace(b'"version":"==1.0"', invalid))
    operator = workspace.parent.parent / "operator-lock-mismatch"
    (operator / "bin").mkdir(parents=True)
    (operator / "lib/python").mkdir(parents=True)
    (operator / "bin/pipenv").write_bytes(b"inert script")
    (operator / "lib/python/stdlib.py").write_bytes(b"x = 1\n")
    with monkeypatch.context() as m:
        m.setattr(subprocess, "Popen", lambda *_a, **_kw: (
            _ for _ in ()).throw(AssertionError("no native child permitted")))
        with pytest.raises(GatewayError) as denied:
            service._observe_d4_r003_operator_provisioner(
                "a", "py-pipenv", ["python", "-m", "pytest", "-q"],
                provisioner_root=str(operator),
                expected_venv_record_distributions=(("example-pkg", "1.0"),))
    assert denied.value.code == "runner_unavailable"
    with pytest.raises(GatewayError) as apply:
        service.invoke_exec(
            "a", "py-pipenv", ["python", "-m", "pytest", "-q"], dry_run=False)
    assert apply.value.code == "exec_cleanup_proof_required"


def test_d4_service_pipenv_lock_denied_before_staging_private_runner(
        product_service):
    """No stage files should appear for a mismatched locked package."""
    from gateway.lbe_runtime_tree import observe_d4_pipenv_venv_manifest

    service, workspace = product_service
    _d4_record_site_fixture(workspace)
    project = workspace / "py-pipenv"
    lock = project / "Pipfile.lock"
    lock.write_bytes(lock.read_bytes().replace(b"==1.0", b"==2.0"))
    source = observe_d4_pipenv_venv_manifest(project_root=str(project))
    private = workspace.parent.parent
    provisioner = private.parent / (private.name + "-uncreated-lock-operator")
    with pytest.raises(GatewayError) as denied:
        service._assemble_d4_r003_source_only_runner(
            "a", "py-pipenv", ["python", "-m", "pytest", "-q"],
            private_root=str(private), provisioner_root=str(provisioner),
            staged_manifests={"bin": (("", None),), "lib": (("", None),)},
            venv_manifest=source.proposed_manifest,
            expected_venv_identity_sha256=source.observed_source_identity_sha256,
            expected_venv_record_distributions=(("example-pkg", "1.0"),))
    assert denied.value.code == "runner_unavailable"
    assert not (private / "bin").exists()
    assert not (private / "home").exists()



@pytest.mark.parametrize("argv", [
    ["go", "test", "./..."],
    ["go", "vet", "./..."],
    ["go", "build", "-o", "bin/app", "./cmd/app"],
])
def test_d4_go_direct_import_source_maps_pinned_stdlib_without_native(
        product_service, monkeypatch, argv):
    from gateway.lbe_go_import_sources import inspect_d4_go_direct_import_sources

    service, workspace = product_service
    (workspace / "go-project/cmd/app/main.go").write_bytes(
        b'package main\nimport "fmt"\nfunc main() {fmt.Println("safe")}\n')
    with monkeypatch.context() as m:
        m.setattr(subprocess, "Popen", lambda *_a, **_kw: (
            _ for _ in ()).throw(AssertionError("no native Go subprocess allowed")))
        candidate = service._prepare_d4_r003_fixture_candidate(
            "a", "go-project", argv)
        record = inspect_d4_go_direct_import_sources(
            service.get("a"), candidate,
            staged_go_manifest=(("src/fmt/print.go", "a" * 64),))
    assert record.module_path == "firstparty.test/app"
    assert record.selected_imports == ("fmt",)
    assert record.stdlib_stage_members == (("fmt", ("src/fmt/print.go",)),)
    assert record.transitive_import_closure_proven is False
    assert record.actual_loaded_source_graph_proven is False
    assert record.native_launch_allowed is False
    with pytest.raises(GatewayError) as denied:
        service.invoke_exec("a", "go-project", argv, dry_run=False)
    assert denied.value.code == "exec_cleanup_proof_required"


def test_d4_go_direct_import_local_package_mapping_from_selected_tree(
        product_service):
    from gateway.lbe_go_import_sources import inspect_d4_go_direct_import_sources

    service, workspace = product_service
    go = workspace / "go-project"
    (go / "pkg/util").mkdir(parents=True)
    (go / "pkg/util/value.go").write_bytes(b"package util\nconst Value = 9\n")
    (go / "cmd/app/main.go").write_bytes(
        b'package main\nimport "firstparty.test/app/pkg/util"\n'
        b'func main() { _ = util.Value }\n')
    candidate = service._prepare_d4_r003_fixture_candidate(
        "a", "go-project", ["go", "test", "./..."])
    selected = inspect_d4_go_direct_import_sources(
        service.get("a"), candidate, staged_go_manifest=())
    assert selected.first_party_members == (
        ("firstparty.test/app/pkg/util", ("go-project/pkg/util/value.go",)),)
    assert selected.stdlib_stage_members == ()


@pytest.mark.parametrize("import_path,missing_stdlib", [
    ("external.example/malicious", False),
    ("firstparty.test/app/pkg/not-here", False),
    ("fmt", True),
])
def test_d4_go_direct_import_source_deny_external_or_missing_source(
        product_service, import_path, missing_stdlib):
    from gateway.lbe_go_import_sources import (
        D4GoImportSourceDenied, inspect_d4_go_direct_import_sources,
    )
    service, workspace = product_service
    (workspace / "go-project/cmd/app/main.go").write_bytes(
        ('package main\nimport "' + import_path + '"\n').encode("ascii"))
    candidate = service._prepare_d4_r003_fixture_candidate(
        "a", "go-project", ["go", "vet", "./..."])
    with pytest.raises(D4GoImportSourceDenied):
        inspect_d4_go_direct_import_sources(
            service.get("a"), candidate, staged_go_manifest=()
            if missing_stdlib else (("src/fmt/print.go", "a" * 64),))


def test_d4_go_source_import_recheck_denies_inode_replacement(
        product_service):
    from gateway.lbe_go_import_sources import (
        D4GoImportSourceDenied, inspect_d4_go_direct_import_sources,
    )
    service, workspace = product_service
    go = workspace / "go-project"
    original = go / "cmd/app/main.go"
    original.write_bytes(b'package main\nimport "fmt"\n')
    candidate = service._prepare_d4_r003_fixture_candidate(
        "a", "go-project", ["go", "test", "./..."])
    replacement = original.with_name("replacement.go")
    replacement.write_bytes(original.read_bytes())
    os.replace(replacement, original)
    with pytest.raises(D4GoImportSourceDenied):
        inspect_d4_go_direct_import_sources(
            service.get("a"), candidate,
            staged_go_manifest=(("src/fmt/print.go", "a" * 64),))


def test_d4_service_strict_p007_direct_import_failure_before_operator_copy(
        product_service, monkeypatch):
    """A simulated P007 match must not bypass missing direct stdlib source."""
    import gateway.lbe_runtime_tree as stage_tree
    service, workspace = product_service
    (workspace / "go-project/cmd/app/main.go").write_bytes(
        b'package main\nimport "fmt"\n')
    private = workspace.parent.parent
    source = private.parent / (private.name + "-go-import-operator")
    with monkeypatch.context() as m:
        m.setattr(stage_tree, "_d4_p007_go_stage_matches", lambda _rows: True)
        m.setattr(subprocess, "Popen", lambda *_a, **_kw: (
            _ for _ in ()).throw(AssertionError("no native Go permitted")))
        with pytest.raises(GatewayError) as denied:
            service._assemble_d4_r003_source_only_runner(
                "a", "go-project", ["go", "test", "./..."],
                private_root=str(private), provisioner_root=str(source),
                staged_manifests={"go": (("", None),)},
                expected_source_identities={"go": "a" * 64},
                require_go_p007_stage_source=True)
    assert denied.value.code == "runner_unavailable"
    assert not (private / "go").exists()
    assert not (private / "home").exists()



@pytest.mark.parametrize("content", [
    b'[packages]\nexample-pkg = "==2.0"\n',
    b'[packages]\nexample-pkg = {path="../outside"}\n',
    b'[dev-packages]\nexample-pkg = "==1.0"\n',
])
def test_d4_service_pipfile_to_lock_to_record_mismatch_denied(
        product_service, monkeypatch, content):
    service, workspace = product_service
    _d4_record_site_fixture(workspace)
    (workspace / "py-pipenv/Pipfile").write_bytes(content)
    operator = workspace.parent.parent / "operator-pipfile-intent-mismatch"
    (operator / "bin").mkdir(parents=True)
    (operator / "bin/pipenv").write_bytes(b"inert")
    (operator / "lib/python").mkdir(parents=True)
    (operator / "lib/python/stdlib.py").write_bytes(b"source = 1\n")
    with monkeypatch.context() as m:
        m.setattr(subprocess, "Popen", lambda *_a, **_kw: (
            _ for _ in ()).throw(AssertionError("no Pipenv execution allowed")))
        with pytest.raises(GatewayError) as rejected:
            service._observe_d4_r003_operator_provisioner(
                "a", "py-pipenv", ["python", "-m", "pytest", "-q"],
                provisioner_root=str(operator),
                expected_venv_record_distributions=(("example-pkg", "1.0"),))
    assert rejected.value.code == "runner_unavailable"
    with pytest.raises(GatewayError) as public:
        service.invoke_exec(
            "a", "py-pipenv", ["python", "-m", "pytest", "-q"], dry_run=False)
    assert public.value.code == "exec_cleanup_proof_required"



def test_d4_actual_service_selects_python_first_party_import_edges_without_spawn(
        product_service, monkeypatch):
    """Real candidate binds import AST to the already hashed first-party files."""
    service, workspace = product_service
    package = workspace / "py-direct/src/pkg"
    package.mkdir()
    (package / "__init__.py").write_bytes(b"# selected package\n")
    (package / "util.py").write_bytes(b"value = 42\n")
    (package / "entry.py").write_bytes(
        b"from .util import value\nimport os\n")
    argv = ["python", "-m", "compileall", "-q", "./src"]
    with monkeypatch.context() as m:
        m.setattr(subprocess, "Popen", lambda *_a, **_kw: (
            _ for _ in ()).throw(AssertionError("T0 cannot run Python")))
        candidate = service._prepare_d4_r003_fixture_candidate(
            "a", "py-direct", argv)
        receipt = candidate.python_import_sources
        assert receipt is not None
        assert receipt.first_party_import_edges == (
            ("src/pkg/entry.py", "src/pkg/__init__.py"),
            ("src/pkg/entry.py", "src/pkg/util.py"),
        )
        assert "os" in receipt.unresolved_external_imports
        assert receipt.actual_sys_path_proven is False
        assert receipt.actual_loaded_source_graph_proven is False
        assert receipt.native_launch_allowed is False
        with pytest.raises(GatewayError) as denied:
            service.invoke_exec("a", "py-direct", argv, dry_run=False)
        assert denied.value.code == "exec_cleanup_proof_required"


def test_d4_actual_pipenv_without_tests_has_empty_truthful_python_import_receipt(
        product_service):
    service, _workspace = product_service
    candidate = service._prepare_d4_r003_fixture_candidate(
        "a", "py-pipenv", ["python", "-m", "pytest", "-q"])
    receipt = candidate.python_import_sources
    assert receipt is not None
    assert receipt.selected_source_files == ()
    assert receipt.imported_external_sources_proven is False
    assert receipt.native_launch_allowed is False


@pytest.mark.parametrize("source", [
    b"from ..escape import secret\n",
    b"import src.missing\n",
    b"from .missing import value\n",
    b"def broken(:\n",
])
def test_d4_actual_service_refuses_unsafe_python_selected_imports(
        product_service, monkeypatch, source):
    service, workspace = product_service
    (workspace / "py-direct/src/main.py").write_bytes(source)
    with monkeypatch.context() as m:
        m.setattr(subprocess, "Popen", lambda *_a, **_kw: (
            _ for _ in ()).throw(AssertionError("T0 no Python subprocess")))
        with pytest.raises(GatewayError) as denied:
            service._prepare_d4_r003_fixture_candidate(
                "a", "py-direct",
                ["python", "-m", "compileall", "-q", "./src"])
        assert denied.value.code == "command_not_allowed"
        with pytest.raises(GatewayError) as public:
            service.invoke_exec(
                "a", "py-direct", ["python", "-m", "pytest", "-q"],
                dry_run=False)
        assert public.value.code == "exec_cleanup_proof_required"


def test_d4_python_source_recheck_catches_same_bytes_new_inode(
        product_service):
    from gateway.lbe_python_import_sources import (
        D4PythonImportDenied, inspect_d4_python_first_party_import_sources,
    )

    service, workspace = product_service
    source = workspace / "py-direct/src/main.py"
    candidate = service._prepare_d4_r003_fixture_candidate(
        "a", "py-direct",
        ["python", "-m", "compileall", "-q", "./src"])
    replacement = source.with_name("replacement.py")
    replacement.write_bytes(source.read_bytes())
    os.replace(replacement, source)
    with pytest.raises(D4PythonImportDenied):
        inspect_d4_python_first_party_import_sources(
            service.get("a"), candidate)


def test_d4_python_source_recheck_catches_replaced_package_directory(
        product_service):
    from gateway.lbe_python_import_sources import (
        D4PythonImportDenied, inspect_d4_python_first_party_import_sources,
    )

    service, workspace = product_service
    src_dir = workspace / "py-direct/src"
    candidate = service._prepare_d4_r003_fixture_candidate(
        "a", "py-direct", ["python", "-m", "pytest", "-q"])
    old = src_dir.with_name("renamed")
    os.rename(src_dir, old)
    src_dir.mkdir()
    (src_dir / "main.py").write_bytes((old / "main.py").read_bytes())
    with pytest.raises(D4PythonImportDenied):
        inspect_d4_python_first_party_import_sources(service.get("a"), candidate)


def test_d4_python_dynamic_import_recorded_as_unqualified_source(
        product_service):
    service, workspace = product_service
    (workspace / "py-direct/src/main.py").write_bytes(
        b"import importlib\nimportlib.import_module('external')\n")
    candidate = service._prepare_d4_r003_fixture_candidate(
        "a", "py-direct", ["python", "-m", "pytest", "-q"])
    receipt = candidate.python_import_sources
    assert receipt.dynamic_import_sites == ("src/main.py",)
    assert receipt.unresolved_external_imports == ("importlib",)
    assert receipt.dynamic_import_closure_proven is False
    assert receipt.native_launch_allowed is False



def test_d4_real_service_first_party_from_import_submodule_is_selected(
        product_service, monkeypatch):
    service, workspace = product_service
    package = workspace / "py-direct/src/pkg"
    package.mkdir()
    (package / "__init__.py").write_bytes(b"# package initializer\n")
    (package / "util.py").write_bytes(b"value = 42\n")
    (workspace / "py-direct/src/main.py").write_bytes(
        b"from src.pkg import util\nvalue = util.value\n")
    with monkeypatch.context() as m:
        m.setattr(subprocess, "Popen", lambda *_a, **_kw: (
            _ for _ in ()).throw(AssertionError("no native Python allowed")))
        candidate, marker = service._prepare_d4_r003_attempt(
            "a", "py-direct", ["python", "-m", "pytest", "-q"])
        receipt = candidate.python_import_sources
        assert receipt is not None
        assert ("src/main.py", "src/pkg/__init__.py") in receipt.first_party_import_edges
        assert ("src/main.py", "src/pkg/util.py") in receipt.first_party_import_edges
        assert receipt.actual_loaded_source_graph_proven is False
        marker.consume_for(candidate.plan)
        with pytest.raises(GatewayError) as blocked:
            service.invoke_exec(
                "a", "py-direct", ["python", "-m", "pytest", "-q"], dry_run=False)
        assert blocked.value.code == "exec_cleanup_proof_required"


@pytest.mark.parametrize("forge", ["unselected", "native", "missing"])
def test_d4_python_one_use_marker_rejects_forged_import_receipt(
        product_service, forge):
    from gateway.lbe_product_fixture import D4OneUseAttemptMarker

    service, _workspace = product_service
    candidate = service._prepare_d4_r003_fixture_candidate(
        "a", "py-direct", ["python", "-m", "pytest", "-q"])
    receipt = candidate.python_import_sources
    assert receipt is not None
    if forge == "unselected":
        changed = replace(
            receipt, first_party_import_edges=(("src/main.py", "src/outside.py"),))
    elif forge == "native":
        changed = replace(receipt, native_launch_allowed=True)
    else:
        changed = None
    with pytest.raises(D4FixtureDenied):
        D4OneUseAttemptMarker(
            replace(candidate, python_import_sources=changed),
            service.get("a"))


def test_d4_python_one_use_burns_before_launcher_on_import_receipt_drift(
        product_service, monkeypatch):
    from gateway.lbe_direct_owner import DirectChildOwner
    import gateway.lbe_python_import_sources as first_party
    from gateway.lbe_worker import LbeWorker, LbeWorkerError

    service, _workspace = product_service
    candidate, marker = service._prepare_d4_r003_attempt(
        "a", "py-direct", ["python", "-m", "pytest", "-q"])
    receipt = candidate.python_import_sources
    assert receipt is not None
    calls = []
    def never_launch(_plan):
        calls.append("launched")
        raise AssertionError("stale import receipt cannot reach child launcher")
    with monkeypatch.context() as m:
        m.setattr(first_party, "inspect_d4_python_first_party_import_sources",
                  lambda *_a: replace(
                      receipt, unresolved_external_imports=("outside",)))
        worker = LbeWorker(DirectChildOwner(), launcher=never_launch)
        with pytest.raises(LbeWorkerError) as denied:
            worker.run(candidate.plan, product_attempt=marker)
        assert denied.value.code == "attempt_replay_denied"
        with pytest.raises(LbeWorkerError) as replay:
            worker.run(candidate.plan, product_attempt=marker)
        assert replay.value.code == "attempt_replay_denied"
    assert calls == []


def test_d4_go_plan_rejects_forged_python_import_binding(product_service):
    from gateway.lbe_product_fixture import D4OneUseAttemptMarker
    service, _workspace = product_service
    python = service._prepare_d4_r003_fixture_candidate(
        "a", "py-direct", ["python", "-m", "pytest", "-q"])
    go = service._prepare_d4_r003_fixture_candidate(
        "a", "go-project", ["go", "test", "./..."])
    assert python.python_import_sources is not None
    with pytest.raises(D4FixtureDenied):
        D4OneUseAttemptMarker(
            replace(go, python_import_sources=python.python_import_sources),
            service.get("a"))



def test_d4_go_darwin_arm64_source_selection_ignores_unbuilt_platform_imports(
        product_service, monkeypatch):
    """Actual source candidate includes all bytes, but imports only target files."""
    from gateway.lbe_go_import_sources import inspect_d4_go_direct_import_sources

    service, workspace = product_service
    go = workspace / "go-project/cmd/app"
    (go / "platform_linux.go").write_bytes(
        b'package main\nimport "unapproved.example/foreign"\n')
    (go / "platform_windows_amd64.go").write_bytes(
        b'package main\nimport "unapproved.example/win"\n')
    (go / "platform_darwin_arm64.go").write_bytes(
        b'package main\nimport "fmt"\n')
    with monkeypatch.context() as m:
        m.setattr(subprocess, "Popen", lambda *_a, **_kw: (
            _ for _ in ()).throw(AssertionError("no Go child permitted")))
        candidate, attempt = service._prepare_d4_r003_attempt(
            "a", "go-project", ["go", "build", "-o", "bin/app", "./cmd/app"])
        all_sources = {name for name, _ in candidate.source_sha256}
        assert "go-project/cmd/app/platform_linux.go" in all_sources
        assert "go-project/cmd/app/platform_windows_amd64.go" in all_sources
        selected = inspect_d4_go_direct_import_sources(
            service.get("a"), candidate,
            staged_go_manifest=(("src/fmt/print.go", "a" * 64),))
        assert selected.selected_imports == ("fmt",)
        assert selected.stdlib_stage_members == (
            ("fmt", ("src/fmt/print.go",)),)
        assert selected.inactive_first_party_sources == (
            "go-project/cmd/app/platform_linux.go",
            "go-project/cmd/app/platform_windows_amd64.go",
        )
        assert selected.target_goos == "darwin"
        assert selected.target_goarch == "arm64"
        assert selected.build_constraint_closure_proven is False
        assert selected.native_launch_allowed is False
        attempt.consume_for(candidate.plan)
        with pytest.raises(GatewayError) as denied:
            service.invoke_exec(
                "a", "go-project",
                ["go", "build", "-o", "bin/app", "./cmd/app"],
                dry_run=False)
        assert denied.value.code == "exec_cleanup_proof_required"
    assert not (workspace / "go-project/bin/app").exists()


@pytest.mark.parametrize("filename,source,active", [
    ("platform.go", b'//go:build darwin && arm64\n\npackage main\n'
     b'import "fmt"\n', True),
    ("platform_darwin.go", b'// +build darwin,arm64\n\npackage main\n'
     b'import "fmt"\n', True),
    ("platform.go", b'//go:build linux\n\npackage main\n'
     b'import "unreviewed.example/linux"\n', False),
    ("platform.go", b'//go:build windows || amd64\n\npackage main\n'
     b'import "unreviewed.example/win"\n', False),
])
def test_d4_go_real_service_explicit_build_tags_select_only_target_sources(
        product_service, filename, source, active):
    from gateway.lbe_go_import_sources import inspect_d4_go_direct_import_sources

    service, workspace = product_service
    selected_path = workspace / "go-project/cmd/app" / filename
    selected_path.write_bytes(source)
    candidate = service._prepare_d4_r003_fixture_candidate(
        "a", "go-project", ["go", "vet", "./..."])
    snapshot = {name for name, _ in candidate.source_sha256}
    assert "go-project/cmd/app/" + filename in snapshot
    receipt = inspect_d4_go_direct_import_sources(
        service.get("a"), candidate,
        staged_go_manifest=(("src/fmt/print.go", "a" * 64),))
    if active:
        assert receipt.selected_imports == ("fmt",)
        assert receipt.inactive_first_party_sources == ()
    else:
        assert receipt.selected_imports == ()
        assert receipt.inactive_first_party_sources == (
            "go-project/cmd/app/" + filename,)
    assert receipt.build_constraint_closure_proven is False
    assert receipt.actual_loaded_source_graph_proven is False
    assert receipt.native_launch_allowed is False


@pytest.mark.parametrize("source", [
    b'//go:build darwin && unreviewed_tool_tag\n\npackage main\n',
    b'//go:build (darwin\n\npackage main\n',
    b'//go:build darwin\n// +build linux\n\npackage main\n',
])
def test_d4_go_real_service_refuses_unqualified_build_tag_sources(
        product_service, source):
    from gateway.lbe_go_import_sources import (
        inspect_d4_go_direct_import_sources, D4GoImportSourceDenied,
    )
    service, workspace = product_service
    (workspace / "go-project/cmd/app/platform.go").write_bytes(source)
    candidate = service._prepare_d4_r003_fixture_candidate(
        "a", "go-project", ["go", "vet", "./..."])
    with pytest.raises(D4GoImportSourceDenied):
        inspect_d4_go_direct_import_sources(
            service.get("a"), candidate, staged_go_manifest=())


def test_d4_go_only_non_target_local_package_is_not_falsely_qualified(
        product_service):
    from gateway.lbe_go_import_sources import (
        inspect_d4_go_direct_import_sources, D4GoImportSourceDenied,
    )
    service, workspace = product_service
    go = workspace / "go-project"
    (go / "pkg/onlylinux").mkdir(parents=True)
    (go / "pkg/onlylinux/only_linux.go").write_bytes(
        b"package onlylinux\nconst Value=1\n")
    (go / "cmd/app/main.go").write_bytes(
        b'package main\nimport "firstparty.test/app/pkg/onlylinux"\n')
    candidate = service._prepare_d4_r003_fixture_candidate(
        "a", "go-project", ["go", "test", "./..."])
    with pytest.raises(D4GoImportSourceDenied):
        inspect_d4_go_direct_import_sources(
            service.get("a"), candidate, staged_go_manifest=())


def test_d4_go_inactive_platform_source_is_still_inode_and_hash_bound(
        product_service):
    from gateway.lbe_go_import_sources import (
        inspect_d4_go_direct_import_sources, D4GoImportSourceDenied,
    )
    service, workspace = product_service
    go = workspace / "go-project/cmd/app"
    file = go / "platform_linux.go"
    file.write_bytes(b'package main\nimport "external.example/ignore"\n')
    candidate = service._prepare_d4_r003_fixture_candidate(
        "a", "go-project", ["go", "test", "./..."])
    replacement = go / "replacement.go"
    replacement.write_bytes(file.read_bytes())
    os.replace(replacement, file)
    with pytest.raises(D4GoImportSourceDenied):
        inspect_d4_go_direct_import_sources(
            service.get("a"), candidate, staged_go_manifest=())


def test_d4_go_active_arch_and_unknown_suffix_imports_are_checked(
        product_service):
    from gateway.lbe_go_import_sources import (
        inspect_d4_go_direct_import_sources, D4GoImportSourceDenied,
    )
    service, workspace = product_service
    go = workspace / "go-project/cmd/app"
    (go / "valid_arm64.go").write_bytes(
        b'package main\nimport "fmt"\n')
    (go / "unknown_future.go").write_bytes(
        b'package main\nimport "external.example/ambiguous"\n')
    candidate = service._prepare_d4_r003_fixture_candidate(
        "a", "go-project", ["go", "vet", "./..."])
    with pytest.raises(D4GoImportSourceDenied):
        inspect_d4_go_direct_import_sources(
            service.get("a"), candidate,
            staged_go_manifest=(("src/fmt/print.go", "a" * 64),))



def test_d4_go_build_ignores_only_test_imports_and_selects_darwin_stdlib(
        product_service, monkeypatch):
    """Real WorkspaceService build source selection, never native go build."""
    from gateway.lbe_go_import_sources import inspect_d4_go_direct_import_sources

    service, workspace = product_service
    project = workspace / "go-project"
    (project / "cmd/app/main.go").write_bytes(
        b'package main\nimport "fmt"\nfunc main() {fmt.Println("ok")}\n')
    (project / "cmd/app/main_test.go").write_bytes(
        b'package main\nimport "unapproved.example/test-only"\n')
    stage = (
        ("src/fmt/print.go", "a" * 64),
        ("src/fmt/print_darwin_arm64.go", "b" * 64),
        ("src/fmt/print_linux.go", "c" * 64),
        ("src/fmt/print_windows_arm64.go", "d" * 64),
        ("src/fmt/print_test.go", "e" * 64),
    )
    with monkeypatch.context() as m:
        m.setattr(subprocess, "Popen", lambda *_a, **_k: (
            _ for _ in ()).throw(AssertionError("T0 cannot launch Go")))
        candidate, marker = service._prepare_d4_r003_attempt(
            "a", "go-project", ["go", "build", "-o", "bin/app", "./cmd/app"])
        actual = inspect_d4_go_direct_import_sources(
            service.get("a"), candidate, staged_go_manifest=stage)
        assert actual.selected_go_command == "build"
        assert actual.selected_imports == ("fmt",)
        assert actual.stdlib_stage_members == (
            ("fmt", ("src/fmt/print.go",
                     "src/fmt/print_darwin_arm64.go")),)
        assert actual.inactive_first_party_sources == (
            "go-project/cmd/app/main_test.go",)
        assert actual.stdlib_build_constraints_proven is False
        assert actual.transitive_import_closure_proven is False
        assert actual.native_launch_allowed is False
        assert "go-project/cmd/app/main_test.go" in dict(candidate.source_sha256)
        marker.consume_for(candidate.plan)
        with pytest.raises(GatewayError) as exc:
            service.invoke_exec(
                "a", "go-project",
                ["go", "build", "-o", "bin/app", "./cmd/app"],
                dry_run=False)
        assert exc.value.code == "exec_cleanup_proof_required"
    assert not (project / "bin/app").exists()


@pytest.mark.parametrize("argv", [
    ["go", "test", "./..."],
    ["go", "vet", "./..."],
])
def test_d4_go_test_and_vet_include_test_only_imports(
        product_service, argv):
    from gateway.lbe_go_import_sources import (
        D4GoImportSourceDenied, inspect_d4_go_direct_import_sources,
    )

    service, workspace = product_service
    (workspace / "go-project/cmd/app/main_test.go").write_bytes(
        b'package main\nimport "unapproved.example/test-only"\n')
    candidate = service._prepare_d4_r003_fixture_candidate(
        "a", "go-project", argv)
    with pytest.raises(D4GoImportSourceDenied):
        inspect_d4_go_direct_import_sources(
            service.get("a"), candidate, staged_go_manifest=())


def test_d4_go_build_first_party_package_excludes_test_files(
        product_service):
    from gateway.lbe_go_import_sources import inspect_d4_go_direct_import_sources

    service, workspace = product_service
    project = workspace / "go-project"
    (project / "pkg/util").mkdir(parents=True)
    (project / "pkg/util/value.go").write_bytes(
        b"package util\nconst Value = 2\n")
    (project / "pkg/util/value_test.go").write_bytes(
        b'package util\nimport "unapproved.example/test-only"\n')
    (project / "cmd/app/main.go").write_bytes(
        b'package main\nimport "firstparty.test/app/pkg/util"\n')
    candidate = service._prepare_d4_r003_fixture_candidate(
        "a", "go-project", ["go", "build", "-o", "bin/app", "./cmd/app"])
    record = inspect_d4_go_direct_import_sources(
        service.get("a"), candidate, staged_go_manifest=())
    assert record.selected_imports == ("firstparty.test/app/pkg/util",)
    assert record.first_party_members == (
        ("firstparty.test/app/pkg/util", ("go-project/pkg/util/value.go",)),)
    assert record.inactive_first_party_sources == (
        "go-project/pkg/util/value_test.go",)


def test_d4_go_testdata_go_source_is_pinned_but_not_built(product_service):
    from gateway.lbe_go_import_sources import inspect_d4_go_direct_import_sources

    service, workspace = product_service
    project = workspace / "go-project"
    (project / "pkg/util/testdata").mkdir(parents=True)
    (project / "pkg/util/testdata/shadow.go").write_bytes(
        b'package fixture\nimport "unknown.example/unbuilt"\n')
    (project / "pkg/util/value.go").write_bytes(
        b"package util\nconst Value=7\n")
    candidate = service._prepare_d4_r003_fixture_candidate(
        "a", "go-project", ["go", "test", "./..."])
    record = inspect_d4_go_direct_import_sources(
        service.get("a"), candidate, staged_go_manifest=())
    assert record.selected_imports == ()
    assert record.inactive_first_party_sources == (
        "go-project/pkg/util/testdata/shadow.go",)
    assert "go-project/pkg/util/testdata/shadow.go" in dict(candidate.source_sha256)


def test_d4_go_stdlib_manifest_cannot_claim_unpinned_candidate(
        product_service):
    from gateway.lbe_go_import_sources import (
        D4GoImportSourceDenied, inspect_d4_go_direct_import_sources,
    )

    service, workspace = product_service
    (workspace / "go-project/cmd/app/main.go").write_bytes(
        b'package main\nimport "fmt"\n')
    candidate = service._prepare_d4_r003_fixture_candidate(
        "a", "go-project", ["go", "build", "-o", "bin/app", "./cmd/app"])
    with pytest.raises(D4GoImportSourceDenied):
        inspect_d4_go_direct_import_sources(
            service.get("a"), candidate,
            staged_go_manifest=(("src/fmt/print.go", "invalid"),))



def test_d4_go_actual_service_build_header_with_license_block_is_accepted(
        product_service, monkeypatch):
    from gateway.lbe_go_import_sources import inspect_d4_go_direct_import_sources

    service, workspace = product_service
    (workspace / "go-project/cmd/app/main.go").write_bytes(
        b'/* Copyright approved fixture */\n'
        b'//go:build darwin && arm64\n\n'
        b'package main\nimport "fmt"\nfunc main(){fmt.Println("ok")}\n')
    with monkeypatch.context() as m:
        m.setattr(subprocess, "Popen", lambda *_a, **_k: (
            _ for _ in ()).throw(AssertionError("Go T1 is not authorized")))
        candidate = service._prepare_d4_r003_fixture_candidate(
            "a", "go-project", ["go", "build", "-o", "bin/app", "./cmd/app"])
        record = inspect_d4_go_direct_import_sources(
            service.get("a"), candidate,
            staged_go_manifest=(("src/fmt/print.go", "a" * 64),))
        assert record.selected_imports == ("fmt",)
        assert record.native_launch_allowed is False
        with pytest.raises(GatewayError) as exc:
            service.invoke_exec(
                "a", "go-project",
                ["go", "build", "-o", "bin/app", "./cmd/app"],
                dry_run=False)
        assert exc.value.code == "exec_cleanup_proof_required"


def test_d4_go_actual_service_missing_legacy_blank_cannot_exclude_source(
        product_service):
    from gateway.lbe_go_import_sources import (
        D4GoImportSourceDenied, inspect_d4_go_direct_import_sources,
    )

    service, workspace = product_service
    # Go ignores a +build selector without its required separating blank.
    # Do not claim this file is excluded from Darwin compile inputs.
    (workspace / "go-project/cmd/app/other.go").write_bytes(
        b'// +build linux\npackage main\n'
        b'import "unqualified.example/foreign"\n')
    candidate = service._prepare_d4_r003_fixture_candidate(
        "a", "go-project", ["go", "build", "-o", "bin/app", "./cmd/app"])
    with pytest.raises(D4GoImportSourceDenied):
        inspect_d4_go_direct_import_sources(
            service.get("a"), candidate, staged_go_manifest=())



@pytest.mark.parametrize("kind,cwd,argv", [
    ("python_direct", "py-direct", ["python", "-m", "pytest", "-q"]),
    ("python_direct", "py-direct",
     ["python", "-m", "compileall", "-q", "./src"]),
    ("pipenv", "py-pipenv", ["python", "-m", "pytest", "-q"]),
    ("go", "go-project", ["go", "test", "./..."]),
    ("go", "go-project", ["go", "vet", "./..."]),
    ("go", "go-project",
     ["go", "build", "-o", "bin/app", "./cmd/app"]),
])
def test_d4_service_macos_runner_launch_boundary_is_bound_but_native_denied(
        product_service, monkeypatch, kind, cwd, argv):
    """The actual service supplies the Worker launcher, never a client grant."""
    from gateway.lbe_macos_runner import D4MacOSRunnerLaunchBoundary
    from gateway.lbe_direct_owner import DirectChildOwner
    from gateway.lbe_worker import LbeWorker, LbeWorkerError

    service, workspace = product_service
    private, hashes = _stage_d4_native_bytes_in_private_runner(
        workspace, kind=kind)
    trees = _d4_staged_trees(workspace, kind)
    calls = []
    def illegal_native(*_args, **_kwargs):
        calls.append("native")
        raise AssertionError("SOURCE/T0 may not spawn any process")
    with monkeypatch.context() as m:
        m.setattr(os, "environ", {"PATH": "/usr/bin:/bin"})
        m.setattr(subprocess, "Popen", illegal_native)
        candidate, marker, _source, recipe, host = (
            service._prepare_d4_r003_runner_preflight(
                "a", cwd, argv, private_root=private,
                expected_hashes=hashes, expected_trees=trees))
        boundary = marker._macos_boundary
        assert type(boundary) is D4MacOSRunnerLaunchBoundary
        intent = boundary.intent
        assert intent.workspace == "a"
        assert intent.runner == candidate.plan.runner
        assert intent.resolved_executable == recipe.resolved_executable
        assert intent.requested_argv == tuple(argv)
        assert intent.resolved_spawn_argv == recipe.resolved_spawn_argv
        assert intent.closed_child_environment == recipe.closed_child_environment
        assert intent.original_timeout_seconds == candidate.plan.timeout_seconds
        assert intent.selected_source_fingerprint == host.source_fingerprint
        assert dict(intent.required_limits)["cpu_millicores_max"] == 2000
        assert dict(intent.required_limits)["memory_mib_max"] == 4096
        assert intent.real_macos_runner_attested is False
        assert intent.original_and_descendant_domain_enforced is False
        assert intent.owner_native_t1_approved is False
        assert intent.operative_f1_d0_exception_effective is False
        assert intent.native_launch_allowed is False
        owner = DirectChildOwner()
        status = LbeWorker(owner, launcher=boundary.launch).run(
            candidate.plan, product_attempt=marker)
        assert status["status"] == "launch_failed"
        assert status["executed"] is False
        assert status["process_may_be_running"] is False
        assert owner.snapshot()["reserved_slots"] == 0
        assert owner.snapshot()["unavailable"] is False
        with pytest.raises(LbeWorkerError) as replay:
            LbeWorker(owner, launcher=boundary.launch).run(
                candidate.plan, product_attempt=marker)
        assert replay.value.code == "attempt_replay_denied"
        with pytest.raises(GatewayError) as public:
            service.invoke_exec("a", cwd, argv, dry_run=False)
        assert public.value.code == "exec_cleanup_proof_required"
    assert calls == []


def test_d4_macos_runner_binding_rejects_forged_attestation_and_wrong_plan(
        product_service, monkeypatch):
    from gateway.lbe_macos_runner import (
        D4MacOSRunnerDenied, D4MacOSRunnerLaunchBoundary,
    )
    from gateway.lbe_worker import LbeNoChildStarted

    service, workspace = product_service
    private, hashes = _stage_d4_native_bytes_in_private_runner(
        workspace, kind="python_direct")
    trees = _d4_staged_trees(workspace, "python_direct")
    with monkeypatch.context() as m:
        m.setattr(os, "environ", {"PATH": "/usr/bin:/bin"})
        m.setattr(subprocess, "Popen", lambda *_a, **_k: (
            _ for _ in ()).throw(AssertionError("no native Popen permitted")))
        candidate, marker, _source, recipe, host = (
            service._prepare_d4_r003_runner_preflight(
                "a", "py-direct", ["python", "-m", "pytest", "-q"],
                private_root=private, expected_hashes=hashes,
                expected_trees=trees))
        boundary = marker._macos_boundary
        assert boundary is not None
        fake_host = replace(host,
            github_provider_attested=True,
            physical_whole_child_cpu_memory_attached=True,
            exact_owner_native_t1_authorized=True,
            native_launch_allowed=True, blockers=())
        with pytest.raises(D4MacOSRunnerDenied):
            D4MacOSRunnerLaunchBoundary(
                service.get("a"), candidate.plan, recipe, fake_host,
                private_root=private)
        with pytest.raises(LbeNoChildStarted):
            boundary.launch(replace(candidate.plan))
        with pytest.raises(D4MacOSRunnerDenied):
            boundary.check_binding(service.get("a"), replace(candidate.plan))
        assert service.info()["exec_policy"]["available"] is False


def test_d4_macos_runner_prelaunch_ambient_drift_refuses_before_worker_launch(
        product_service, monkeypatch):
    from gateway.lbe_macos_runner import D4MacOSRunnerDenied
    from gateway.lbe_direct_owner import DirectChildOwner
    from gateway.lbe_worker import LbeNoChildStarted, LbeWorker, LbeWorkerError

    service, workspace = product_service
    private, hashes = _stage_d4_native_bytes_in_private_runner(
        workspace, kind="go")
    trees = _d4_staged_trees(workspace, "go")
    with monkeypatch.context() as m:
        m.setattr(os, "environ", {"PATH": "/usr/bin:/bin"})
        m.setattr(subprocess, "Popen", lambda *_a, **_k: (
            _ for _ in ()).throw(AssertionError("no Go process permitted")))
        candidate, marker, _source, _recipe, _host = (
            service._prepare_d4_r003_runner_preflight(
                "a", "go-project", ["go", "test", "./..."],
                private_root=private, expected_hashes=hashes,
                expected_trees=trees))
        boundary = marker._macos_boundary
        m.setattr(os, "environ", {
            "PATH": "/usr/bin:/bin",
            "HTTPS_PROXY": "http://unqualified-proxy.invalid:8080",
        })
        with pytest.raises(D4MacOSRunnerDenied):
            boundary.recheck_for(service.get("a"), candidate.plan)
        with pytest.raises(LbeNoChildStarted):
            boundary.launch(candidate.plan)
        owner = DirectChildOwner()
        with pytest.raises(LbeWorkerError) as failed:
            LbeWorker(owner, launcher=boundary.launch).run(
                candidate.plan, product_attempt=marker)
        assert failed.value.code == "attempt_replay_denied"
        assert owner.snapshot()["reserved_slots"] == 0
        with pytest.raises(LbeWorkerError) as replay:
            LbeWorker(owner, launcher=boundary.launch).run(
                candidate.plan, product_attempt=marker)
        assert replay.value.code == "attempt_replay_denied"


def test_d4_macos_runner_rejects_generic_replacement_of_service_boundary(
        product_service):
    from gateway.lbe_product_fixture import D4FixtureDenied

    service, _workspace = product_service
    _candidate, marker = service._prepare_d4_r003_attempt(
        "a", "py-direct", ["python", "-m", "pytest", "-q"])
    with pytest.raises(D4FixtureDenied):
        marker.attach_macos_runner_boundary(lambda *_args: True)
    assert service.info()["exec_policy"]["available"] is False
