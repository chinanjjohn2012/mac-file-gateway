"""Consolidated LBE v2 PREVIEW-ONLY wiring and old-state fail-closed T0.

No native child, signal, real command, user Mac, Tunnel, or operative D0
exception is exercised. The F1 dry_run=False hard-denial remains in place.
"""
from __future__ import annotations

import copy
import os
from pathlib import Path
import subprocess

import pytest
from starlette.testclient import TestClient

from gateway.core import GatewayError
from gateway.exec_state import ExecStateStore
from gateway.http_multi import create_multi_app
from gateway.private_fs import PrivateFileError
from gateway.workspaces import ActiveRuntimeInventory, WorkspaceService
from gateway.workspaces_config import parse_workspace_config


@pytest.fixture
def scene(tmp_path: Path):
    projects = tmp_path / "projects"
    projects.mkdir()
    a, b = projects / "a", projects / "b"
    a.mkdir()
    b.mkdir()
    for name in ("python-project", "go-project", "default-project"):
        (a / name).mkdir()
    (a / "python-project" / "hello.py").write_text("print('hello')\n")
    (a / "python-project" / "Pipfile").write_text("[packages]\n")
    (a / "go-project" / "Pipfile").write_text("[packages]\n")
    (a / "default-project" / "Pipfile").write_text("[packages]\n")
    (b / "safe.txt").write_text("file independent\n")
    config = tmp_path / "private"
    config.mkdir(mode=0o700)
    config.chmod(0o700)
    runtime = tmp_path / "trusted-runtime"
    runtime.mkdir()
    return a, b, config, runtime


def v2_config(a: Path, b: Path, *, paths=None, runners=None):
    return {
        "schema_version": 2,
        "server": {"port": 8765, "transport": "http"},
        "workspaces": {
            "a": {
                "root": str(a),
                "exec": {
                    "paths": ["python-project", "go-project", "default-project"]
                    if paths is None else paths,
                    "runners": ["python-project=pipenv"] if runners is None else runners,
                },
            },
            "b": {"root": str(b)},
        },
    }


def service(scene, config):
    _a, _b, private, runtime = scene
    return WorkspaceService(
        parse_workspace_config(config), config_dir=private,
        inventory=ActiveRuntimeInventory(paths=(runtime,)))


def prime_existing_state(scene):
    a, b, private, _runtime = scene
    # Explicit offline bootstrap for the disposable fixture only.
    store = ExecStateStore(
        private / "exec-state", workspace_roots=(str(a), str(b)))
    assert store.durability_state == "healthy"
    store.close()
    return private / "exec-state"


def test_full_v2_config_parses_but_never_enables_positive_apply(scene):
    a, b, _private, _runtime = scene
    settings = parse_workspace_config(v2_config(a, b))
    assert settings.schema_version == 2
    assert settings.exec_enabled is True
    assert settings.workspaces[0].exec_enabled is True
    assert settings.workspaces[1].exec_enabled is False
    assert settings.workspaces[0].exec_paths == (
        "python-project", "go-project", "default-project")
    assert settings.workspaces[0].exec_runners == ("python-project=pipenv",)
    assert settings.git_enabled is False
    assert settings.workspaces[1].allow_write is False


@pytest.mark.parametrize("version", [True, False, 0, 3, 2.0, "2"])
def test_full_config_refuses_wrong_schema_versions(scene, version):
    a, b, _private, _runtime = scene
    src = v2_config(a, b)
    src["schema_version"] = version
    with pytest.raises(PrivateFileError, match="Unsupported workspace schema"):
        parse_workspace_config(src)


@pytest.mark.parametrize("bad", [
    lambda c: c["server"].update(exec={"enabled": False}),
    lambda c: c["server"].update(exec={"enabled": True}),
    lambda c: c["workspaces"]["a"]["exec"].update(enabled=False),
    lambda c: c["workspaces"]["a"]["exec"].update(enabled=True),
    lambda c: c["workspaces"]["a"]["exec"].update(paths=["../b"]),
    lambda c: c["workspaces"]["a"]["exec"].update(paths=["/tmp"]),
    lambda c: c["workspaces"]["a"]["exec"].update(paths=["project", "Project"]),
    lambda c: c["workspaces"]["a"]["exec"].update(runners=["b=pipenv"]),
    lambda c: c["workspaces"]["a"]["exec"].update(runners=["python-project=unsafe"]),
    lambda c: c["workspaces"]["a"].update(root="/"),
    lambda c: c["workspaces"]["a"]["read"].update(enabled=False),
    lambda c: c["server"].update(unknown=True),
])
def test_v2_cannot_bypass_other_full_config_grants(scene, bad):
    a, b, _private, _runtime = scene
    c = v2_config(a, b)
    c["workspaces"]["a"]["read"] = {"enabled": True}
    before = copy.deepcopy(c)
    bad(c)
    with pytest.raises(PrivateFileError):
        parse_workspace_config(c)
    assert before["schema_version"] == 2


def test_v2_missing_old_state_root_fails_without_auto_creation(scene):
    a, b, private, _runtime = scene
    svc = service(scene, v2_config(a, b))
    try:
        assert not (private / "exec-state").exists()
        policy = svc.info()["exec_policy"]
        assert policy["enabled"] is True
        assert policy["available"] is False
        assert policy["completion_capability"] == "none"
        assert policy["mode"] == "preview_only"
        assert policy["candidate_mode"] == "local_best_effort"
        assert policy["durability_state"] == "unavailable"
        for dry in (True, False):
            with pytest.raises(GatewayError) as exc:
                svc.invoke_exec("a", "python-project", ["python", "hello.py"],
                                dry_run=dry)
            assert exc.value.code == "exec_state_unavailable"
        assert svc.invoke("b", "read_file", "safe.txt", 1, 5)["workspace"] == "b"
        assert not (private / "exec-state").exists()
    finally:
        svc.close()


def test_v2_missing_old_owner_lock_never_recreates_lock(scene):
    a, b, private, _runtime = scene
    state = private / "exec-state"
    state.mkdir(mode=0o700)
    state.chmod(0o700)
    svc = service(scene, v2_config(a, b))
    try:
        with pytest.raises(GatewayError) as exc:
            svc.invoke_exec("a", "python-project", ["python", "hello.py"])
        assert exc.value.code == "exec_state_unavailable"
        assert list(state.iterdir()) == []
    finally:
        svc.close()


def test_v2_existing_healthy_state_previews_and_denies_apply(scene, monkeypatch):
    a, b, _private, _runtime = scene
    state = prime_existing_state(scene)
    before = sorted(p.name for p in state.iterdir())
    svc = service(scene, v2_config(a, b))
    try:
        policy = svc.info()["exec_policy"]
        assert policy["durability_state"] == "healthy"
        assert policy["available"] is False
        assert svc.any_exec is True
        assert svc.list_workspaces()["workspaces"][1]["exec"] is False
        preview = svc.invoke_exec("a", "python-project",
                                  ["python", "hello.py"])
        assert preview["executed"] is False
        assert preview["runner"] == "pipenv"
        assert preview["effective_argv"] == ["pipenv", "run", "python", "hello.py"]

        def deny(*args, **kwargs):
            raise AssertionError("live Exec must remain F1-denied")
        with monkeypatch.context() as m:
            m.setattr(subprocess, "Popen", deny)
            m.setattr(os, "killpg", deny, raising=False)
            with pytest.raises(GatewayError) as exc:
                svc.invoke_exec("a", "python-project", ["python", "hello.py"],
                                dry_run=False)
            assert exc.value.code == "exec_cleanup_proof_required"

        with TestClient(create_multi_app(svc, enable_mcp=False),
                        base_url="http://127.0.0.1:8765") as client:
            body = {"workspace": "a", "cwd": "go-project",
                    "argv": ["go", "test", "./..."]}
            res = client.post("/run", json=body)
            assert res.status_code == 200
            assert res.json()["runner"] == "direct"
            assert res.json()["executed"] is False
            failed = client.post("/run", json={**body, "dry_run": False})
            # Preserve the existing F1 REST error mapping: proof-denial
            # reports 503, not a newly invented v2-specific 403.
            assert failed.status_code == 503
            assert failed.json()["error"] == "exec_cleanup_proof_required"
            info = client.get("/health").json()["exec_policy"]
            assert info["mode"] == "preview_only"
            assert info["available"] is False
        assert sorted(p.name for p in state.iterdir()) == before
    finally:
        svc.close()


def test_v2_auto_pipenv_disabled_for_unconfigured_cwd_and_go(scene):
    a, b, _private, _runtime = scene
    prime_existing_state(scene)
    cfg = v2_config(a, b)
    cfg["workspaces"]["a"]["exec"]["runners"] = ["go-project=pipenv"]
    svc = service(scene, cfg)
    try:
        auto = svc.invoke_exec("a", "default-project", ["python", "-m", "pytest"])
        assert auto["runner"] == "direct"
        go = svc.invoke_exec("a", "go-project", ["go", "vet", "./..."])
        assert go["runner"] == "direct"
        with pytest.raises(GatewayError) as exc:
            svc.invoke_exec("b", ".", ["go", "vet", "./..."])
        assert exc.value.code == "exec_disabled"
    finally:
        svc.close()


def test_v2_empty_exec_paths_do_not_initialize_old_state(scene):
    a, b, private, _runtime = scene
    svc = service(scene, v2_config(a, b, paths=[], runners=[]))
    try:
        assert svc.any_exec is False
        assert svc.info()["exec_policy"]["durability_state"] == "disabled"
        assert not (private / "exec-state").exists()
        with pytest.raises(GatewayError) as exc:
            svc.invoke_exec("a", ".", ["go", "test", "./..."])
        assert exc.value.code == "exec_disabled"
    finally:
        svc.close()


@pytest.mark.parametrize("phase", ["PREPARED", "UNKNOWN", "RUNNING", "RETIRED"])
def test_v2_refuses_and_preserves_every_old_attempt_phase(scene, phase):
    a, b, private, _runtime = scene
    state = private / "exec-state"
    old = ExecStateStore(state, workspace_roots=(str(a), str(b)))
    try:
        dev, ino = a.stat().st_dev, a.stat().st_ino
        attempt = old.prepare("a", (dev, ino))
    finally:
        old.close()
    record = state / ("r-" + attempt + ".json")
    import json
    original = json.loads(record.read_text())
    original["phase"] = phase
    if phase == "RETIRED":
        original["cleanup_scope"] = "original_group_only"
    record.write_text(json.dumps(original, sort_keys=True) + "\n")
    before = record.read_bytes()
    svc = service(scene, v2_config(a, b))
    try:
        policy = svc.info()["exec_policy"]
        assert policy["quarantined"] is True
        assert policy["durability_state"] == "quarantined"
        for dry in (True, False):
            with pytest.raises(GatewayError) as exc:
                svc.invoke_exec("a", "python-project",
                                ["python", "hello.py"], dry_run=dry)
            assert exc.value.code == "exec_quarantined"
        assert record.read_bytes() == before
        assert svc.invoke("b", "read_file", "safe.txt", 1, 5)["workspace"] == "b"
    finally:
        svc.close()


def test_v2_locked_old_owner_denies_without_stealing_lock(scene):
    a, b, private, _runtime = scene
    holder = ExecStateStore(private / "exec-state",
                            workspace_roots=(str(a), str(b)))
    svc = service(scene, v2_config(a, b))
    try:
        assert svc.info()["exec_policy"]["durability_state"] == "unavailable"
        with pytest.raises(GatewayError) as exc:
            svc.invoke_exec("a", "go-project", ["go", "test", "./..."])
        assert exc.value.code == "exec_state_unavailable"
    finally:
        svc.close()
        holder.close()


def test_v1_parser_and_legacy_state_creation_remain_unchanged(scene):
    a, b, private, _runtime = scene
    cfg = v2_config(a, b)
    cfg["schema_version"] = 1
    cfg["server"]["exec"] = {"enabled": True}
    cfg["workspaces"]["a"]["exec"] = {
        "enabled": True, "paths": ["python-project"], "runners": []}
    settings = parse_workspace_config(cfg)
    assert settings.schema_version == 1
    svc = service(scene, cfg)
    try:
        assert (private / "exec-state" / "owner.lock").is_file()
        assert svc.info()["exec_policy"]["durability_state"] == "healthy"
        with pytest.raises(GatewayError) as exc:
            svc.invoke_exec("a", "python-project", ["python", "hello.py"],
                            dry_run=False)
        assert exc.value.code == "exec_cleanup_proof_required"
        # Historical v1 nearest-Pipfile default remains explicitly unchanged.
        preview = svc.invoke_exec("a", "python-project", ["python", "hello.py"])
        assert preview["runner"] == "pipenv"
    finally:
        svc.close()


@pytest.mark.parametrize("argv", [
    ["go", "build", "./..."],
    ["go", "build", "./cmd/server"],
    ["go", "build", "-v", "-trimpath", "./cmd/server"],
    ["go", "build", "-o", "bin/server", "./cmd/server"],
    ["go", "build", "-o=bin/server", "./cmd/server"],
])
def test_v2_go_build_preview_is_direct_and_never_spawns(scene, monkeypatch, argv):
    a, b, _private, _runtime = scene
    (a / "go-project" / "bin").mkdir()
    prime_existing_state(scene)
    svc = service(scene, v2_config(a, b))
    try:
        def refuse(*args, **kwargs):
            raise AssertionError("Go build preview must never spawn a process")
        with monkeypatch.context() as m:
            m.setattr(subprocess, "Popen", refuse)
            m.setattr(os, "killpg", refuse, raising=False)
            result = svc.invoke_exec("a", "go-project", argv)
        assert result["workspace"] == "a"
        assert result["requested_argv"] == argv
        assert result["effective_argv"] == argv
        assert result["runner"] == "direct"
        assert result["executed"] is False
        assert result["status"] == "preview"
        assert result["mode"] == "preview_only"
        assert result["process_may_be_running"] is False
        assert result["cleanup_proven"] is False
        assert result["output_complete"] is True
        with pytest.raises(GatewayError) as exc:
            svc.invoke_exec("a", "go-project", argv, dry_run=False)
        assert exc.value.code == "exec_cleanup_proof_required"
    finally:
        svc.close()


@pytest.mark.parametrize("argv", [
    ["go", "build", "-o", "/tmp/server", "./..."],
    ["go", "build", "-o", "../other", "./..."],
    ["go", "build", "-o=bin/missing/child", "./..."],
    ["go", "build", "-o=bin", "./..."],
    ["go", "build", "-toolexec=/bin/sh", "./..."],
    ["go", "build", "-exec=/bin/sh", "./..."],
    ["go", "build", "-ldflags=-extld=/bin/sh", "./..."],
    ["go", "build", "-o=bin/server", "-o=bin/server2", "./..."],
    ["go", "build", "./cmd/server", "-o=bin/server"],
    ["go", "build", "-o=bin/server"],
    ["go", "run", "./..."],
])
def test_v2_go_build_preview_rejects_unscoped_or_unsafe_args(scene, argv):
    a, b, _private, _runtime = scene
    (a / "go-project" / "bin").mkdir()
    prime_existing_state(scene)
    svc = service(scene, v2_config(a, b))
    try:
        with pytest.raises(GatewayError) as exc:
            svc.invoke_exec("a", "go-project", argv)
        assert exc.value.code in {"command_not_allowed", "invalid_argument"}
    finally:
        svc.close()


def test_v2_go_build_preview_rejects_linked_output(scene):
    a, b, _private, _runtime = scene
    go = a / "go-project"
    (go / "bin").mkdir()
    (go / "alias").symlink_to(go / "bin", target_is_directory=True)
    (go / "bin" / "linked").symlink_to("outside")
    prime_existing_state(scene)
    svc = service(scene, v2_config(a, b))
    try:
        for out in ("alias/child", "bin/linked"):
            with pytest.raises(GatewayError) as exc:
                svc.invoke_exec("a", "go-project",
                                ["go", "build", "-o", out, "./..."])
            assert exc.value.code == "command_not_allowed"
        with TestClient(create_multi_app(svc, enable_mcp=False),
                        base_url="http://127.0.0.1:8765") as client:
            result = client.post("/run", json={
                "workspace": "a", "cwd": "go-project",
                "argv": ["go", "build", "-o", "bin/server", "./cmd/server"]})
            assert result.status_code == 200
            assert result.json()["status"] == "preview"
            assert result.json()["runner"] == "direct"
            denied = client.post("/run", json={
                "workspace": "a", "cwd": "go-project",
                "argv": ["go", "build", "-o", "bin/server", "./cmd/server"],
                "dry_run": False})
            assert denied.status_code == 503
            assert denied.json()["error"] == "exec_cleanup_proof_required"
    finally:
        svc.close()


def test_v1_public_policy_has_no_v2_keys(scene):
    a, b, _private, _runtime = scene
    cfg = v2_config(a, b, paths=[], runners=[])
    cfg["schema_version"] = 1
    svc = service(scene, cfg)
    try:
        info = svc.info()
        assert "config_schema_version" not in info
        assert "mode" not in info["exec_policy"]
        assert "candidate_mode" not in info["exec_policy"]
    finally:
        svc.close()



def test_dormant_v2_owner_status_tracks_fake_child_but_exec_apply_stays_denied(scene):
    """Shared service/REST expose only direct-child counts, never grant apply.

    The child is a pure T0 Event waiter, NOT a real process or native cleanup.
    """
    import threading

    a, b, _private, _runtime = scene
    prime_existing_state(scene)
    svc = service(scene, v2_config(a, b))
    owner = svc._lbe_owner
    assert owner is not None
    ready = threading.Event()
    release = threading.Event()

    class FakeOnly:
        def wait(self):
            ready.set()
            if not release.wait(timeout=10):
                raise AssertionError("unreleased test fake child")
            return 7

    token = owner.reserve("a")
    owner.bind(token, FakeOnly())
    try:
        assert ready.wait(2)
        info = svc.info()
        policy = info["exec_policy"]
        assert policy["running_direct_children"] == 1
        assert policy["capacity_exhausted"] is False
        assert policy["owner_unavailable"] is False
        assert policy["available"] is False
        assert policy["completion_capability"] == "none"
        assert "pid" not in str(policy).lower()
        assert "pgid" not in str(policy).lower()

        with TestClient(create_multi_app(svc, enable_mcp=False),
                        base_url="http://127.0.0.1:8765") as client:
            other = client.get("/health").json()["exec_policy"]
            assert other == client.get("/info").json()["exec_policy"]
            assert other["running_direct_children"] == 1
            refused = client.post("/run", json={
                "workspace": "a", "cwd": "go-project",
                "argv": ["go", "build", "./..."], "dry_run": False})
            assert refused.status_code == 503
            assert refused.json()["error"] == "exec_cleanup_proof_required"
        assert svc.invoke("b", "read_file", "safe.txt", 1, 5)["workspace"] == "b"
    finally:
        # Graceful close must not wait for or signal the simulated child.
        svc.close()
        assert owner.snapshot()["closing"] is True
        assert owner.snapshot()["running_direct_children"] == 1
        release.set()
        token.waiter.join(timeout=2)
        assert not token.waiter.is_alive()
    assert owner.snapshot()["running_direct_children"] == 0


def test_v1_does_not_construct_or_expose_v2_owner(scene):
    a, b, _private, _runtime = scene
    cfg = v2_config(a, b, paths=[], runners=[])
    cfg["schema_version"] = 1
    svc = service(scene, cfg)
    try:
        assert svc._lbe_owner is None
        policy = svc.info()["exec_policy"]
        for key in ("running_direct_children", "capacity_exhausted",
                    "owner_unavailable", "candidate_mode"):
            assert key not in policy
    finally:
        svc.close()


def test_dormant_prepared_plans_use_real_v2_gateway_policies(scene, monkeypatch):
    """T0 source-only, no real process and no independent service apply route."""
    from gateway.lbe_plan import prepare_lbe_work_plan
    a, b, private, _runtime = scene
    (a / "go-project" / "bin").mkdir()
    prime_existing_state(scene)
    svc = service(scene, v2_config(a, b))

    def forbidden(*args, **kwargs):
        raise AssertionError("Planning must not spawn a native child")
    try:
        with monkeypatch.context() as m:
            m.setattr(subprocess, "Popen", forbidden)
            m.setattr(os, "kill", forbidden)
            m.setattr(os, "killpg", forbidden, raising=False)
            ctx = svc.require_exec("a")
            python_plan = prepare_lbe_work_plan(
                ctx, cwd="python-project", argv=["python", "hello.py"])
            assert python_plan.workspace == "a"
            assert python_plan.runner == "pipenv"
            assert python_plan.effective_argv == (
                "pipenv", "run", "python", "hello.py")
            assert python_plan.requested_argv == ("python", "hello.py")
            assert python_plan.cwd == "python-project"

            go_plan = prepare_lbe_work_plan(
                ctx, cwd="go-project",
                argv=["go", "build", "-o=bin/server", "./cmd/server"])
            assert go_plan.runner == "direct"
            assert go_plan.effective_argv == (
                "go", "build", "-o=bin/server", "./cmd/server")
            assert go_plan.runner_project == "go-project"
            assert not (a / "go-project" / "bin" / "server").exists()

            testing = prepare_lbe_work_plan(
                ctx, cwd="go-project",
                argv=["go", "test", "./..."])
            assert testing.runner == "direct"
            assert testing.requested_argv == ("go", "test", "./...")

            default_python = prepare_lbe_work_plan(
                ctx, cwd="default-project",
                argv=["python", "-m", "pytest"])
            assert default_python.runner == "direct"
            assert default_python.effective_argv == (
                "python", "-m", "pytest")

            with pytest.raises(GatewayError, match="cleanup proof"):
                svc.invoke_exec(
                    "a", "go-project", ["go", "build", "./..."],
                    dry_run=False)
        assert svc.info()["exec_policy"]["available"] is False
        assert svc._lbe_owner.snapshot()["reserved_slots"] == 0
    finally:
        svc.close()


@pytest.mark.parametrize("cwd,argv", [
    ("default-project", ["python", "missing.py"]),
    ("default-project", ["python", "-c", "print('unsafe')"]),
    ("default-project", ["go", "run", "./..."]),
    ("go-project", ["go", "build", "-o", "/tmp/executable", "./..."]),
    ("go-project", ["go", "build", "-o=../outside", "./..."]),
    ("go-project", ["go", "build", "-toolexec=/bin/sh", "./..."]),
    ("outside", ["python", "-m", "pytest"]),
])
def test_dormant_plan_rejects_invalid_real_gateway_cwd_command_and_output(
    scene, cwd, argv,
):
    from gateway.lbe_plan import prepare_lbe_work_plan
    a, b, _private, _runtime = scene
    prime_existing_state(scene)
    svc = service(scene, v2_config(a, b))
    try:
        with pytest.raises(GatewayError):
            prepare_lbe_work_plan(
                svc.require_exec("a"), cwd=cwd, argv=argv)
        assert svc._lbe_owner.snapshot()["reserved_slots"] == 0
    finally:
        svc.close()


def test_dormant_plan_does_not_upgrade_v1_or_ungranted_workspace(scene):
    from gateway.lbe_plan import prepare_lbe_work_plan
    a, b, private, _runtime = scene
    cfg = v2_config(a, b)
    svc = service(scene, cfg)
    try:
        # B has no Exec scopes; no plan or new capability can be constructed.
        with pytest.raises(GatewayError) as denied:
            prepare_lbe_work_plan(
                svc.get("b"), cwd=".", argv=["go", "test", "./..."])
        assert denied.value.code == "exec_disabled"
    finally:
        svc.close()

    cfg["schema_version"] = 1
    cfg["server"]["exec"] = {"enabled": True}
    cfg["workspaces"]["a"]["exec"] = {
        "enabled": True, "paths": ["go-project"], "runners": []}
    legacy = service(scene, cfg)
    try:
        with pytest.raises(GatewayError) as denied:
            prepare_lbe_work_plan(
                legacy.require_exec("a"),
                cwd="go-project", argv=["go", "test", "./..."])
        assert denied.value.code == "exec_disabled"
        with pytest.raises(GatewayError) as error:
            legacy.invoke_exec(
                "a", "go-project", ["go", "test", "./..."],
                dry_run=False)
        assert error.value.code == "exec_cleanup_proof_required"
    finally:
        legacy.close()

