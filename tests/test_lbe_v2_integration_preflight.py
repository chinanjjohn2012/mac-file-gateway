"""Schema-v2 preview / native-launch boundary T0 and old-state denial.

Only mocked/fake Popen callbacks are used in this module; no real native
child, OS signal, user Mac or Tunnel. Schema v1 retains F1 deny-only. The
separate authorized macOS T1 job proves limited real-process paths.
"""
from __future__ import annotations

import copy
import json
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


@pytest.mark.parametrize("fragment_json", [
    r'{"paths":["\ud800"]}',
    r'{"paths":["\udfff"]}',
    r'{"paths":["python-project"],"runners":["python-project/\ud800=pipenv"]}',
    r'{"paths":["python-project"],"runners":["python-project/\udfff=direct"]}',
])
def test_full_v2_json_config_normalizes_lone_surrogate_error(
    scene, fragment_json,
):
    a, b, _private, _runtime = scene
    config = v2_config(a, b)
    config["workspaces"]["a"]["exec"] = json.loads(fragment_json)
    with pytest.raises(PrivateFileError, match="Invalid v2 Exec fragment"):
        parse_workspace_config(config)
    # Pure validation: no Gateway/Worker, subprocess or state created.


def test_v2_missing_old_state_root_fails_without_auto_creation(scene):
    a, b, private, _runtime = scene
    svc = service(scene, v2_config(a, b))
    try:
        assert not (private / "exec-state").exists()
        policy = svc.info()["exec_policy"]
        assert policy["enabled"] is True
        assert policy["available"] is False
        assert policy["completion_capability"] == "none"
        assert policy["mode"] == "local_best_effort"
        assert "candidate_mode" not in policy
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


def test_v2_existing_healthy_state_previews_and_refuses_invalid_apply(scene, monkeypatch):
    a, b, _private, _runtime = scene
    state = prime_existing_state(scene)
    before = sorted(p.name for p in state.iterdir())
    svc = service(scene, v2_config(a, b))
    try:
        policy = svc.info()["exec_policy"]
        assert policy["durability_state"] == "healthy"
        assert policy["available"] is False
        assert policy["completion_capability"] == "none"
        assert svc.any_exec is True
        assert svc.list_workspaces()["workspaces"][1]["exec"] is False
        preview = svc.invoke_exec("a", "python-project",
                                  ["python", "hello.py"])
        assert preview["executed"] is False
        assert preview["runner"] == "pipenv"
        assert preview["effective_argv"] == ["pipenv", "run", "python", "hello.py"]

        def deny(*args, **kwargs):
            raise AssertionError("invalid request may not launch")
        with monkeypatch.context() as m:
            m.setattr(subprocess, "Popen", deny)
            m.setattr(os, "killpg", deny, raising=False)
            with pytest.raises(GatewayError) as exc:
                svc.invoke_exec("a", "python-project",
                                ["python", "-c", "print('blocked')"],
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
            failed = client.post("/run", json={
                **body, "argv": ["go", "run", "./..."], "dry_run": False})
            assert failed.status_code == 503
            assert failed.json()["error"] == "exec_cleanup_proof_required"
            info = client.get("/health").json()["exec_policy"]
            assert info["mode"] == "local_best_effort"
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


@pytest.mark.parametrize("cwd,argv,selected_runner", [
    ("python-project", ["python", "hello.py"], "pipenv"),
    ("default-project", ["python", "-m", "pytest"], "direct"),
    ("default-project", ["pytest", "-q"], "direct"),
    ("default-project", ["python", "-m", "compileall", "-q", "."], "direct"),
])
def test_v2_python_public_preview_uses_future_worker_plan(
    scene, monkeypatch, cwd, argv, selected_runner,
):
    """Exact Direct/Pipenv plan parity on public service + real REST ingress."""
    from gateway.lbe_plan import prepare_lbe_work_plan

    a, b, _private, _runtime = scene
    prime_existing_state(scene)
    svc = service(scene, v2_config(a, b))

    def no_native_child(*args, **kwargs):
        raise AssertionError("No positive Exec child or signal is authorized")
    try:
        with monkeypatch.context() as m:
            m.setattr(subprocess, "Popen", no_native_child)
            m.setattr(os, "killpg", no_native_child, raising=False)
            ctx = svc.require_exec("a")
            plan = prepare_lbe_work_plan(ctx, cwd=cwd, argv=argv)
            direct = svc.invoke_exec("a", cwd, argv)
            with TestClient(create_multi_app(svc, enable_mcp=False),
                            base_url="http://127.0.0.1:8765") as client:
                result = client.post("/run", json={
                    "workspace": "a", "cwd": cwd, "argv": argv})
                assert result.status_code == 200
                assert result.json() == direct
        assert plan.workspace == direct["workspace"] == "a"
        assert plan.cwd == direct["cwd"] == cwd
        assert list(plan.requested_argv) == direct["requested_argv"] == argv
        assert list(plan.effective_argv) == direct["effective_argv"]
        assert plan.runner == direct["runner"] == selected_runner
        assert plan.runner_project == direct["runner_project"]
        assert direct["mode"] == "local_best_effort"
        assert direct["status"] == "preview"
        assert direct["executed"] is False
        assert direct["cleanup_proven"] is False
        assert svc._lbe_owner.snapshot()["reserved_slots"] == 0
    finally:
        svc.close()


def test_v2_preview_mode_consistent_direct_rest_and_official_mcp(
    scene, monkeypatch,
):
    """No native child: v2 mode is its policy, not its preview status."""
    a, b, _private, _runtime = scene
    prime_existing_state(scene)
    svc = service(scene, v2_config(a, b, runners=[]))

    def no_process(*_args, **_kwargs):
        raise AssertionError("T0 preview must not launch/signal OS processes")

    try:
        with monkeypatch.context() as m:
            # Preserve the real Popen class for MCP SDK Popen[bytes] import
            # annotations while prohibiting every subprocess construction.
            m.setattr(subprocess.Popen, "__init__", no_process)
            m.setattr(os, "kill", no_process)
            m.setattr(os, "killpg", no_process, raising=False)
            args = {"workspace": "a", "cwd": "python-project",
                    "argv": ["python", "hello.py"],
                    "timeout_seconds": 5, "dry_run": True}
            direct = svc.invoke_exec(
                "a", "python-project", args["argv"],
                timeout_seconds=5, dry_run=True)
            assert svc.info()["exec_policy"]["mode"] == "local_best_effort"
            assert direct["mode"] == "local_best_effort"
            assert direct["status"] == "preview"
            assert direct["executed"] is False
            assert direct["cleanup_proven"] is False
            with TestClient(create_multi_app(svc),
                            base_url="http://127.0.0.1:8765") as client:
                rest = client.post("/run", json=args)
                assert rest.status_code == 200, rest.text
                assert rest.json() == direct
                hdr = {"Accept": "application/json, text/event-stream",
                       "Content-Type": "application/json"}
                init = client.post("/mcp", headers=hdr, json={
                    "jsonrpc": "2.0", "id": 1, "method": "initialize",
                    "params": {"protocolVersion": "2025-11-25",
                               "capabilities": {},
                               "clientInfo": {"name": "lbe-preview-mode-t0",
                                              "version": "1"}},
                })
                assert init.status_code == 200, init.text
                ready = client.post("/mcp", headers=hdr, json={
                    "jsonrpc": "2.0", "method": "notifications/initialized"})
                assert ready.status_code in (200, 202, 204)
                result = client.post("/mcp", headers=hdr, json={
                    "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                    "params": {"name": "run_command", "arguments": args},
                })
                assert result.status_code == 200, result.text
                tool = result.json()["result"]
                assert tool.get("isError") is not True
                assert tool["structuredContent"] == direct
        assert svc._lbe_owner.snapshot()["reserved_slots"] == 0
    finally:
        svc.close()


@pytest.mark.parametrize("argv", [
    ["pytest", "-k", "alpha\tbeta"],
    ["python", "-m", "pytest", "--maxfail=1\t--trace"],
])
def test_v2_python_invalid_worker_plan_is_sanitized_at_public_boundary(
    scene, argv,
):
    """Legacy argv parser permits tabs; future Worker rejects control chars."""
    a, b, _private, _runtime = scene
    prime_existing_state(scene)
    svc = service(scene, v2_config(a, b))
    try:
        with pytest.raises(GatewayError) as error:
            svc.invoke_exec("a", "default-project", argv)
        assert error.value.code == "invalid_argument"
        with TestClient(create_multi_app(svc, enable_mcp=False),
                        base_url="http://127.0.0.1:8765") as client:
            rejected = client.post("/run", json={
                "workspace": "a", "cwd": "default-project", "argv": argv})
            assert rejected.status_code == 400
            assert rejected.json()["error"] == "invalid_argument"
            denied = client.post("/run", json={
                "workspace": "a", "cwd": "default-project",
                "argv": argv, "dry_run": False})
            assert denied.status_code == 503
            assert denied.json()["error"] == "exec_cleanup_proof_required"
        assert svc._lbe_owner.snapshot()["reserved_slots"] == 0
    finally:
        svc.close()


@pytest.mark.parametrize("argv", [
    ["go", "test", "./..."],
    ["go", "test", "-v", "./..."],
    ["go", "vet", "./..."],
    ["go", "vet", "-trimpath", "./..."],
    ["go", "build", "./..."],
    ["go", "build", "./cmd/server"],
    ["go", "build", "-v", "-trimpath", "./cmd/server"],
    ["go", "build", "-o", "bin/server", "./cmd/server"],
    ["go", "build", "-o=bin/server", "./cmd/server"],
])
def test_v2_go_preview_is_direct_and_never_spawns(scene, monkeypatch, argv):
    a, b, _private, _runtime = scene
    (a / "go-project" / "bin").mkdir()
    prime_existing_state(scene)
    svc = service(scene, v2_config(a, b))
    try:
        def refuse(*args, **kwargs):
            raise AssertionError("Go preview must never spawn a process")
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
        assert result["mode"] == "local_best_effort"
        assert result["process_may_be_running"] is False
        assert result["cleanup_proven"] is False
        assert result["output_complete"] is True
        with pytest.raises(GatewayError) as exc:
            svc.invoke_exec("a", "go-project", ["go", "run", "./..."],
                            dry_run=False)
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
    ["go", "test", "-overlay=redirect.json", "./..."],
    ["go", "test", "-ldflags=-s", "./..."],
    ["go", "vet", "-modfile=alternate.mod", "./..."],
    ["go", "test", "-o=bin/tool", "./..."],
    ["go", "vet", "./...", "-v"],
    ["go", "test"],
    ["go", "vet"],
    ["go", "run", "./..."],
])
def test_v2_go_preview_rejects_unscoped_or_unsafe_args(scene, argv):
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


def test_v2_go_test_vet_rest_preview_refuses_old_flag_bypass(scene, monkeypatch):
    """Real HTTP -> shared service preview, no real Go child or F1 bypass."""
    a, b, _private, _runtime = scene
    prime_existing_state(scene)
    svc = service(scene, v2_config(a, b))

    def refuse(*args, **kwargs):
        raise AssertionError("No native process or signal is permitted")
    try:
        with monkeypatch.context() as m:
            m.setattr(subprocess, "Popen", refuse)
            m.setattr(os, "killpg", refuse, raising=False)
            with TestClient(create_multi_app(svc, enable_mcp=False),
                            base_url="http://127.0.0.1:8765") as client:
                for verb, forbidden in (
                    ("test", "-overlay=redirect.json"),
                    ("vet", "-modfile=alternate.mod"),
                ):
                    good = {"workspace": "a", "cwd": "go-project",
                            "argv": ["go", verb, "./..."]}
                    preview = client.post("/run", json=good)
                    assert preview.status_code == 200
                    assert preview.json()["requested_argv"] == good["argv"]
                    assert preview.json()["runner"] == "direct"
                    assert preview.json()["executed"] is False
                    bad = {**good, "argv": ["go", verb, forbidden, "./..."]}
                    refused = client.post("/run", json=bad)
                    assert refused.status_code != 200
                    assert refused.json()["error"] == "command_not_allowed"
                    still_denied = client.post(
                        "/run", json={**bad, "dry_run": False})
                    assert still_denied.status_code == 503
                    assert still_denied.json()["error"] == "exec_cleanup_proof_required"
        assert svc._lbe_owner.snapshot()["reserved_slots"] == 0
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
                "argv": ["go", "build", "-o", "alias/child", "./cmd/server"],
                "dry_run": False})
            assert denied.status_code == 503
            assert denied.json()["error"] == "exec_cleanup_proof_required"
    finally:
        svc.close()



@pytest.mark.parametrize("target,parent,excluded", [
    ("secrets/service", "secrets", False),
    ("credentials/service", "credentials", False),
    ("bin/review.key", "bin", False),
    ("bin/excluded-artifact", "bin", True),
])
def test_v2_go_build_output_denies_gateway_blocked_names_and_excludes(
    scene, monkeypatch, target, parent, excluded,
):
    """Go -o must obey original Gateway path exclusions on both paths.

    Deterministic T0-only counterexample: original policy did not compare
    Go output against configured File/path denylist. No Go compiler runs.
    """
    a, b, _private, _runtime = scene
    (a / "go-project" / parent).mkdir()
    prime_existing_state(scene)
    cfg = v2_config(a, b)
    if excluded:
        cfg["workspaces"]["a"]["read"] = {
            "excludes": ["go-project/bin/excluded*"]}
    svc = service(scene, cfg)

    def no_native(*args, **kwargs):
        raise AssertionError("T0 must not start any native command")

    try:
        with monkeypatch.context() as m:
            m.setattr(subprocess, "Popen", no_native)
            for dry in (True, False):
                with pytest.raises(GatewayError) as denied:
                    svc.invoke_exec(
                        "a", "go-project",
                        ["go", "build", "-o", target, "./cmd/server"],
                        timeout_seconds=5, dry_run=dry)
                assert denied.value.code == (
                    "command_not_allowed" if dry else "exec_cleanup_proof_required")
        assert svc._lbe_owner.snapshot()["reserved_slots"] == 0
        assert svc._lbe_owner.snapshot()["unavailable"] is False
        assert not (a / "go-project" / target).exists()
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
        assert "supported_preview_commands" not in info["exec_policy"]
    finally:
        svc.close()



def test_v2_owner_status_tracks_fake_child_and_refuses_busy_apply(scene):
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

            with pytest.raises(GatewayError) as denied:
                svc.invoke_exec(
                    "a", "go-project", ["go", "run", "./..."],
                    dry_run=False)
            assert denied.value.code == "exec_cleanup_proof_required"
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



@pytest.mark.parametrize("args", [
    ["go", "test", "-v", "./..."],
    ["go", "vet", "./..."],
    ["go", "build", "-o", "bin/tool", "./cmd/tool"],
])
def test_v2_go_preview_and_future_dormant_plan_share_exact_values(scene, args):
    """Plan parity is pure T0, NOT positive Exec permission or Mac acceptance."""
    from gateway.lbe_plan import prepare_lbe_work_plan
    a, b, private, _runtime = scene
    (a / "go-project" / "bin").mkdir()
    prime_existing_state(scene)
    svc = service(scene, v2_config(a, b))
    try:
        public_preview = svc.invoke_exec("a", "go-project", args)
        plan = prepare_lbe_work_plan(
            svc.require_exec("a"), cwd="go-project", argv=args)
        assert public_preview["dry_run"] is True
        assert public_preview["executed"] is False
        assert public_preview["cwd"] == plan.cwd
        assert public_preview["requested_argv"] == list(plan.requested_argv)
        assert public_preview["effective_argv"] == list(plan.effective_argv)
        assert public_preview["runner"] == plan.runner == "direct"
        assert public_preview["runner_project"] == plan.runner_project
        assert public_preview["mode"] == "local_best_effort"
        assert svc.info()["exec_policy"]["available"] is False
        with pytest.raises(GatewayError) as error:
            svc.invoke_exec("a", "go-project", ["go", "run", "./..."],
                            dry_run=False)
        assert error.value.code == "exec_cleanup_proof_required"
        assert not (a / "go-project" / "bin" / "tool").exists()
    finally:
        svc.close()



@pytest.mark.parametrize("cwd,argv,expected_effective,expected_runner", [
    ("python-project", ["python", "hello.py"],
     ("pipenv", "run", "python", "hello.py"), "pipenv"),
    ("go-project", ["go", "test", "./..."],
     ("go", "test", "./..."), "direct"),
    ("go-project", ["go", "vet", "-trimpath", "./..."],
     ("go", "vet", "-trimpath", "./..."), "direct"),
    ("go-project", ["go", "build", "./cmd/service"],
     ("go", "build", "./cmd/service"), "direct"),
    ("go-project", ["go", "build", "-o=bin/service", "./cmd/service"],
     ("go", "build", "-o=bin/service", "./cmd/service"), "direct"),
])
def test_v2_trusted_launcher_revalidates_go_and_pipenv_without_native_spawn(
    scene, monkeypatch, cwd, argv, expected_effective, expected_runner,
):
    """T0 spy inspects the exact pre-Popen contract, not a real Go/Pipenv run."""
    from gateway.lbe_native_launcher import make_trusted_lbe_launcher
    from gateway.lbe_plan import prepare_lbe_work_plan

    a, b, _private, _runtime = scene
    (a / "go-project" / "bin").mkdir()
    prime_existing_state(scene)
    # Go MUST remain Direct even with a Pipfile and configured Pipenv runner.
    cfg = v2_config(
        a, b, runners=["python-project=pipenv", "go-project=pipenv"])
    svc = service(scene, cfg)
    calls = []

    class SpawnIntercepted(Exception):
        pass

    def no_spawn(command, **kwargs):
        calls.append((tuple(command), kwargs))
        raise SpawnIntercepted

    def no_signal(*args, **kwargs):
        raise AssertionError("T0 may not signal an operating-system process")

    try:
        with monkeypatch.context() as m:
            m.setattr(subprocess, "Popen", no_spawn)
            m.setattr(os, "kill", no_signal)
            m.setattr(os, "killpg", no_signal, raising=False)
            m.setenv("OPENAI_API_KEY", "T0_FAKE_NOT_A_REAL_SECRET")
            ctx = svc.require_exec("a")
            plan = prepare_lbe_work_plan(
                ctx, cwd=cwd, argv=argv, timeout_seconds=5)
            assert plan.runner == expected_runner
            assert plan.effective_argv == expected_effective
            from gateway.lbe_worker import LbeNoChildStarted
            with pytest.raises(LbeNoChildStarted, match="Go/Pipenv"):
                make_trusted_lbe_launcher(ctx)(plan)
        # CI source bytes are not the running service's executable PATH.
        # Never consult even a fake Popen for unqualified Go/Pipenv.
        assert calls == []
        assert svc._lbe_owner.snapshot()["reserved_slots"] == 0
    finally:
        svc.close()



@pytest.mark.parametrize("excluded", [
    "python-project/Pipfile",
    "Pipfile",
    "python-project/Pip*",
])
def test_v2_pipenv_runner_respects_workspace_excluded_pipfile(
    scene, monkeypatch, excluded,
):
    """T0: explicit Pipenv runner must not consume an excluded Pipfile.

    This is a pre-Popen path authorization check, not a claim that trusted
    project Python code cannot read other files at its own OS privilege.
    Both preview and apply must deny a forbidden *runner input*.
    """
    a, b, _private, _runtime = scene
    prime_existing_state(scene)
    cfg = v2_config(a, b, runners=["python-project=pipenv"])
    cfg["workspaces"]["a"]["read"] = {
        "enabled": True, "excludes": [excluded],
    }
    svc = service(scene, cfg)

    def no_child(*_args, **_kwargs):
        raise AssertionError("Excluded runner input must never reach Popen")

    try:
        with monkeypatch.context() as m:
            m.setattr(subprocess, "Popen", no_child)
            for dry in (True, False):
                with pytest.raises(GatewayError) as err:
                    svc.invoke_exec(
                        "a", "python-project", ["python", "hello.py"],
                        timeout_seconds=5, dry_run=dry)
                assert err.value.code == (
                    "runner_unavailable" if dry else "exec_cleanup_proof_required")
        assert svc._lbe_owner.snapshot()["reserved_slots"] == 0
        assert svc._lbe_owner.snapshot()["unavailable"] is False
    finally:
        svc.close()


def test_v2_pipenv_hardlinked_pipfile_denied_in_preview_and_real_preflight(
    scene, monkeypatch,
):
    """No false-success preview for an untrusted two-link Pipfile."""
    a, b, _private, _runtime = scene
    prime_existing_state(scene)
    svc = service(scene, v2_config(a, b))
    pipfile = a / "python-project" / "Pipfile"
    spare = a / "python-project" / "Pipfile-copy"
    os.link(pipfile, spare)
    assert pipfile.stat().st_nlink == 2

    def no_spawn(*args, **kwargs):
        raise AssertionError("Hardlinked Pipfile must not reach Popen")

    try:
        with monkeypatch.context() as m:
            m.setattr(subprocess, "Popen", no_spawn)
            for dry in (True, False):
                with pytest.raises(GatewayError) as error:
                    svc.invoke_exec(
                        "a", "python-project", ["python", "hello.py"],
                        timeout_seconds=5, dry_run=dry)
                assert error.value.code == (
                    "runner_unavailable" if dry else "exec_cleanup_proof_required")
        assert svc._lbe_owner.snapshot()["reserved_slots"] == 0
        assert svc._lbe_owner.snapshot()["unavailable"] is False
    finally:
        svc.close()


def test_v2_go_output_symlink_inserted_after_preview_blocks_launcher(
    scene, monkeypatch,
):
    """A valid preview does not authorize a newly replaced Go output."""
    from gateway.lbe_native_launcher import make_trusted_lbe_launcher
    from gateway.lbe_plan import prepare_lbe_work_plan
    from gateway.lbe_worker import LbeNoChildStarted

    a, b, _private, _runtime = scene
    project = a / "go-project"
    (project / "bin").mkdir()
    prime_existing_state(scene)
    svc = service(scene, v2_config(a, b))

    def no_spawn(*args, **kwargs):
        raise AssertionError("Unsafe output leaf must not reach Popen")

    try:
        ctx = svc.require_exec("a")
        plan = prepare_lbe_work_plan(
            ctx, cwd="go-project",
            argv=["go", "build", "-o", "bin/service", "./cmd/service"],
            timeout_seconds=5)
        (project / "bin" / "service").symlink_to("../Pipfile")
        with monkeypatch.context() as m:
            m.setattr(subprocess, "Popen", no_spawn)
            with pytest.raises(LbeNoChildStarted):
                make_trusted_lbe_launcher(ctx)(plan)
        assert svc._lbe_owner.snapshot()["reserved_slots"] == 0
        assert svc._lbe_owner.snapshot()["unavailable"] is False
    finally:
        svc.close()


# D4: same live WorkspaceService, three entry surfaces, no actual Go/Pipenv
# or other Exec child. Exact public preview and positive-denial truth table.
@pytest.mark.parametrize("cwd,argv,selected_runner", [
    ("python-project", ["python", "hello.py"], "pipenv"),
    ("default-project", ["python", "-m", "pytest"], "direct"),
    ("go-project", ["go", "test", "./..."], "direct"),
    ("go-project", ["go", "vet", "./..."], "direct"),
    ("go-project", ["go", "build", "-o=bin/app", "./cmd/app"], "direct"),
])
def test_d4_all_three_ingresses_same_plan_and_f1_denial_no_native(
    scene, monkeypatch, cwd, argv, selected_runner,
):
    pytest.importorskip("mcp")
    a, b, _private, _runtime = scene
    (a / "go-project" / "bin").mkdir(exist_ok=True)
    state = prime_existing_state(scene)
    originals = sorted(p.name for p in state.iterdir())
    svc = service(scene, v2_config(a, b))
    def forbid(*_args, **_kwargs):
        raise AssertionError("D4 nonoperative preflight must not Popen/signal")
    args = {
        "workspace": "a", "cwd": cwd, "argv": argv,
        "timeout_seconds": 5, "dry_run": True,
    }
    hdr = {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
    }
    try:
        with monkeypatch.context() as m:
            m.setattr(subprocess.Popen, "__init__", forbid)
            m.setattr(os, "kill", forbid)
            m.setattr(os, "killpg", forbid, raising=False)
            direct = svc.invoke_exec("a", cwd, argv, timeout_seconds=5)
            assert direct["status"] == "preview"
            assert direct["executed"] is False
            assert direct["runner"] == selected_runner
            assert direct["planned_go_output"] == (
                "go-project/bin/app"
                if argv == ["go", "build", "-o=bin/app", "./cmd/app"]
                else None
            )
            if cwd == "python-project":
                import hashlib
                expected_script = (a / cwd / "hello.py").read_bytes()
                expected_pipfile = (a / cwd / "Pipfile").read_bytes()
                assert direct["planned_script_sha256"] == (
                    hashlib.sha256(expected_script).hexdigest())
                assert direct["planned_pipfile_sha256"] == (
                    hashlib.sha256(expected_pipfile).hexdigest())
            else:
                assert direct["planned_script_sha256"] is None
                assert direct["planned_pipfile_sha256"] is None
            assert direct["cleanup_proven"] is False
            assert direct["full_descendant_tree_clean"] == "not_proven"
            with TestClient(create_multi_app(svc),
                            base_url="http://127.0.0.1:8765") as client:
                rest = client.post("/run", json=args)
                assert rest.status_code == 200, rest.text
                assert rest.json() == direct
                init = client.post("/mcp", headers=hdr, json={
                    "jsonrpc": "2.0", "id": 1, "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-11-25",
                        "capabilities": {},
                        "clientInfo": {"name": "d4-lbe-t0", "version": "1"},
                    },
                })
                assert init.status_code == 200, init.text
                note = client.post("/mcp", headers=hdr, json={
                    "jsonrpc": "2.0", "method": "notifications/initialized",
                })
                assert note.status_code in (200, 202, 204)
                preview = client.post("/mcp", headers=hdr, json={
                    "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                    "params": {"name": "run_command", "arguments": args},
                })
                assert preview.status_code == 200, preview.text
                assert preview.json()["result"]["structuredContent"] == direct
                with pytest.raises(GatewayError) as error:
                    svc.invoke_exec("a", cwd, argv, timeout_seconds=5,
                                    dry_run=False)
                assert error.value.code == "exec_cleanup_proof_required"
                blocked = {**args, "dry_run": False}
                rest_block = client.post("/run", json=blocked)
                assert rest_block.status_code == 503
                assert rest_block.json()["error"] == "exec_cleanup_proof_required"
                mcp_block = client.post("/mcp", headers=hdr, json={
                    "jsonrpc": "2.0", "id": 3, "method": "tools/call",
                    "params": {"name": "run_command", "arguments": blocked},
                })
                assert mcp_block.status_code == 200, mcp_block.text
                failed = mcp_block.json()["result"]
                assert failed["isError"] is True
                assert (failed["structuredContent"]["error"] ==
                        "exec_cleanup_proof_required")
                policies = [
                    client.get("/info").json()["exec_policy"],
                    client.get("/health").json()["exec_policy"],
                ]
                assert policies[0] == policies[1]
                assert policies[0]["available"] is False
                assert policies[0]["completion_capability"] == "none"
                supported = policies[0]["supported_preview_commands"]
                assert "go build ./..." in supported
                assert "go build -o <relative-output> ./package" in supported
                assert "python -m pytest" in supported
                assert "python <relative-script.py>" in supported
                assert policies[0]["available"] is False
            assert svc._lbe_owner.snapshot()["reserved_slots"] == 0
        assert sorted(p.name for p in state.iterdir()) == originals
        assert not (a / "go-project" / "bin" / "app").exists()
    finally:
        svc.close()


# D6 test-first RED: reject a forged internal LbeWorkPlan before invoking
# caller-supplied equality hooks. Public F1 remains denied; no T1 is executed.
@pytest.mark.parametrize("poisoned_field", [
    "workspace", "cwd", "runner", "runner_project",
    "requested_argv", "effective_argv", "planned_go_output",
])
def test_d6_internal_launcher_rejects_nonprimitive_plan_without_hooks(
    scene, monkeypatch, poisoned_field,
):
    from dataclasses import replace
    from gateway.lbe_native_launcher import make_trusted_lbe_launcher
    from gateway.lbe_plan import prepare_lbe_work_plan
    from gateway.lbe_worker import LbeNoChildStarted

    a, b, _private, _runtime = scene
    prime_existing_state(scene)
    svc = service(scene, v2_config(a, b))
    hooks = []

    class MaliciousComparator:
        def __eq__(self, _other):
            hooks.append("eq")
            return True

        def __ne__(self, _other):
            hooks.append("ne")
            return False

    class MaliciousTuple(tuple):
        def __eq__(self, _other):
            hooks.append("tuple_eq")
            return True

        def __ne__(self, _other):
            hooks.append("tuple_ne")
            return False

    def no_spawn(*_args, **_kwargs):
        raise AssertionError("forged internal plan must never invoke Popen")

    try:
        ctx = svc.require_exec("a")
        plan = prepare_lbe_work_plan(
            ctx, cwd="default-project",
            argv=["python", "-m", "pytest"], timeout_seconds=5)
        forged = replace(
            plan, **{poisoned_field: (
                MaliciousTuple(plan.requested_argv)
                if poisoned_field.endswith("_argv")
                else MaliciousComparator())})
        with monkeypatch.context() as m:
            m.setattr(subprocess, "Popen", no_spawn)
            with pytest.raises(LbeNoChildStarted):
                make_trusted_lbe_launcher(ctx)(forged)
        assert hooks == [], "deny before user-defined hash/equality callbacks"
        assert svc._lbe_owner.snapshot()["reserved_slots"] == 0
    finally:
        svc.close()



# r006: actual product feature (PREVIEW ONLY) - normalized Go -o target.
# Output is an informational destination, not file creation / Exec grant.
@pytest.mark.parametrize("argv", [
    ["go", "build", "-o", "bin/app", "./cmd/app"],
    ["go", "build", "-o=bin/app", "./cmd/app"],
])
def test_r006_go_build_preview_returns_canonical_planned_output(
    scene, monkeypatch, argv,
):
    from gateway.lbe_plan import prepare_lbe_work_plan
    a, b, _private, _runtime = scene
    (a / "go-project" / "bin").mkdir(exist_ok=True)
    state = prime_existing_state(scene)
    before = sorted(p.name for p in state.iterdir())
    svc = service(scene, v2_config(a, b))

    def no_spawn(*_args, **_kwargs):
        raise AssertionError("Go preview or positive-denial must not launch")

    try:
        with monkeypatch.context() as m:
            m.setattr(subprocess, "Popen", no_spawn)
            m.setattr(os, "kill", no_spawn)
            m.setattr(os, "killpg", no_spawn, raising=False)
            ctx = svc.require_exec("a")
            plan = prepare_lbe_work_plan(
                ctx, cwd="go-project", argv=argv, timeout_seconds=5)
            assert plan.planned_go_output == "go-project/bin/app"
            preview = svc.invoke_exec(
                "a", "go-project", argv, timeout_seconds=5)
            assert preview["planned_go_output"] == plan.planned_go_output
            assert preview["status"] == "preview"
            assert preview["executed"] is False
            with pytest.raises(GatewayError) as denied:
                svc.invoke_exec(
                    "a", "go-project", argv, timeout_seconds=5,
                    dry_run=False)
            assert denied.value.code == "exec_cleanup_proof_required"
        assert not (a / "go-project" / "bin" / "app").exists()
        assert sorted(p.name for p in state.iterdir()) == before
        assert svc._lbe_owner.snapshot()["reserved_slots"] == 0
    finally:
        svc.close()


def test_r006_pipenv_writable_pipfile_denied_as_source(scene):
    a, b, _private, _runtime = scene
    prime_existing_state(scene)
    svc = service(scene, v2_config(a, b))
    try:
        (a / "python-project" / "Pipfile").chmod(0o666)
        with pytest.raises(GatewayError) as exc:
            svc.invoke_exec("a", "python-project", ["python", "hello.py"],
                            timeout_seconds=5, dry_run=True)
        assert exc.value.code == "runner_unavailable"
    finally:
        svc.close()


def test_r006_untrusted_pipfile_refused_by_rest_and_official_mcp(scene):
    pytest.importorskip("mcp")
    a, b, _private, _runtime = scene
    prime_existing_state(scene)
    svc = service(scene, v2_config(a, b))
    (a / "python-project" / "Pipfile").chmod(0o666)
    args = {"workspace": "a", "cwd": "python-project",
            "argv": ["python", "hello.py"], "timeout_seconds": 5,
            "dry_run": True}
    headers = {"Accept": "application/json, text/event-stream",
               "Content-Type": "application/json"}
    try:
        with TestClient(create_multi_app(svc),
                        base_url="http://127.0.0.1:8765") as client:
            rest = client.post("/run", json=args)
            assert rest.status_code != 200
            assert rest.json()["error"] == "runner_unavailable"
            init = client.post("/mcp", headers=headers, json={
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2025-11-25",
                           "capabilities": {},
                           "clientInfo": {"name": "r006-test", "version": "1"}},
            })
            assert init.status_code == 200
            client.post("/mcp", headers=headers, json={
                "jsonrpc": "2.0", "method": "notifications/initialized"})
            blocked = client.post("/mcp", headers=headers, json={
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "run_command", "arguments": args},
            })
            assert blocked.status_code == 200
            response = blocked.json()["result"]
            assert response["isError"] is True
            assert response["structuredContent"]["error"] == "runner_unavailable"
        assert svc._lbe_owner.snapshot()["reserved_slots"] == 0
    finally:
        svc.close()


@pytest.mark.parametrize("cwd,runner", [
    ("go-project", "direct"),
    ("python-project", "pipenv"),
])
def test_r006_python_script_plan_pins_source_bytes_in_shared_preview(
    scene, cwd, runner,
):
    import hashlib
    from gateway.lbe_plan import prepare_lbe_work_plan

    a, b, _private, _runtime = scene
    file = a / cwd / "hello.py"
    file.write_text("print('trusted candidate')\n")
    prime_existing_state(scene)
    svc = service(scene, v2_config(a, b))
    argv = ["python", "hello.py"]
    try:
        ctx = svc.require_exec("a")
        plan = prepare_lbe_work_plan(
            ctx, cwd=cwd, argv=argv, timeout_seconds=5)
        source_sha = hashlib.sha256(file.read_bytes()).hexdigest()
        assert plan.planned_script_sha256 == source_sha
        pipfile = a / cwd / "Pipfile"
        expected_pipfile = (hashlib.sha256(pipfile.read_bytes()).hexdigest()
                            if runner == "pipenv" else None)
        assert plan.planned_pipfile_sha256 == expected_pipfile
        preview = svc.invoke_exec("a", cwd, argv, timeout_seconds=5)
        assert preview["runner"] == runner
        assert preview["planned_script_sha256"] == source_sha
        assert preview["planned_pipfile_sha256"] == expected_pipfile
        assert preview["executed"] is False
        with TestClient(create_multi_app(svc, enable_mcp=False),
                        base_url="http://127.0.0.1:8765") as client:
            rest = client.post("/run", json={"workspace": "a",
                "cwd": cwd, "argv": argv, "timeout_seconds": 5})
            assert rest.status_code == 200
            assert rest.json() == preview
    finally:
        svc.close()


def test_r006_python_source_changed_after_plan_refused_before_spawn(
    scene, monkeypatch,
):
    from gateway.lbe_native_launcher import make_trusted_lbe_launcher
    from gateway.lbe_plan import prepare_lbe_work_plan
    from gateway.lbe_worker import LbeNoChildStarted

    a, b, _private, _runtime = scene
    file = a / "go-project" / "hello.py"
    file.write_text("print('old')\n")
    prime_existing_state(scene)
    svc = service(scene, v2_config(a, b))
    launches = []
    try:
        ctx = svc.require_exec("a")
        plan = prepare_lbe_work_plan(
            ctx, cwd="go-project",
            argv=["python", "hello.py"], timeout_seconds=5)
        file.write_text("print('new')\n")

        def forbidden(*_args, **_kwargs):
            launches.append(True)
            raise AssertionError("stale source must not launch")

        with monkeypatch.context() as m:
            m.setattr(subprocess, "Popen", forbidden)
            with pytest.raises(LbeNoChildStarted):
                make_trusted_lbe_launcher(ctx)(plan)
        assert launches == []
        assert svc._lbe_owner.snapshot()["reserved_slots"] == 0
    finally:
        svc.close()


def test_r006_pipfile_content_change_invalidates_earlier_plan(
    scene,
):
    from gateway.lbe_plan import prepare_lbe_work_plan

    a, b, _private, _runtime = scene
    prime_existing_state(scene)
    svc = service(scene, v2_config(a, b))
    try:
        ctx = svc.require_exec("a")
        argv = ["python", "hello.py"]
        first = prepare_lbe_work_plan(ctx, cwd="python-project",
                                      argv=argv, timeout_seconds=5)
        (a / "python-project" / "Pipfile").write_text(
            "[packages]\nnew_dependency='changed'\n")
        changed = prepare_lbe_work_plan(ctx, cwd="python-project",
                                        argv=argv, timeout_seconds=5)
        assert first.planned_pipfile_sha256 != changed.planned_pipfile_sha256
        assert first.planned_script_sha256 == changed.planned_script_sha256
        assert first != changed
    finally:
        svc.close()


# A stuck REST disconnect probe must not hold a completed response/error.
# Fake synchronous service only: never starts Python, Go or Pipenv.
@pytest.mark.parametrize("denied", [False, True])
def test_r006_stalled_disconnect_probe_cannot_block_finished_exec(denied):
    import anyio
    import threading
    from gateway.lbe_cancel_bridge import invoke_exec_with_cancel

    poll_started = threading.Event()

    async def poll():
        poll_started.set()
        await anyio.sleep_forever()

    class FastService:
        def invoke_exec(self, workspace, cwd, argv, timeout_seconds=60,
                        dry_run=True, *, cancelled=None):
            assert type(cancelled) is threading.Event
            assert poll_started.wait(2), "probe must start before Worker exits"
            if denied:
                raise GatewayError("exec_cleanup_proof_required",
                                   "Public positive Exec stays denied.")
            return {"status": "preview", "executed": False}

    async def scenario():
        with anyio.fail_after(2):
            if denied:
                with pytest.raises(GatewayError) as exc:
                    await invoke_exec_with_cancel(
                        FastService(), "a", "go-project",
                        ["go", "test", "./..."],
                        timeout_seconds=5, dry_run=False,
                        is_disconnected=poll,
                    )
                assert exc.value.code == "exec_cleanup_proof_required"
            else:
                result = await invoke_exec_with_cancel(
                    FastService(), "a", "go-project",
                    ["go", "test", "./..."],
                    timeout_seconds=5, dry_run=True,
                    is_disconnected=poll,
                )
                assert result == {"status": "preview", "executed": False}

    anyio.run(scenario)


# r006 cancellation is a waiter notification, never child termination.
def test_r006_transport_task_cancellation_reaches_worker():
    import anyio
    import threading
    from gateway.lbe_cancel_bridge import invoke_exec_with_cancel

    started = threading.Event()
    noticed = threading.Event()

    class FakeService:
        def invoke_exec(self, workspace, cwd, argv, timeout_seconds=60,
                        dry_run=True, *, cancelled=None):
            assert type(cancelled) is threading.Event
            started.set()
            assert cancelled.wait(3)
            noticed.set()
            return {"cleanup_proven": False}

    async def scenario():
        async def request():
            await invoke_exec_with_cancel(
                FakeService(), "a", "go-project", ["go", "test", "./..."],
                timeout_seconds=5, dry_run=False)

        async with anyio.create_task_group() as tasks:
            tasks.start_soon(request)
            with anyio.fail_after(3):
                assert await anyio.to_thread.run_sync(started.wait, 2)
            tasks.cancel_scope.cancel()

    anyio.run(scenario)
    assert noticed.wait(2)


def test_r006_rest_disconnect_notifies_sync_worker():
    import anyio
    import threading
    from gateway.lbe_cancel_bridge import invoke_exec_with_cancel

    started = threading.Event()
    seen = threading.Event()
    disconnected = [False]

    class FakeService:
        def invoke_exec(self, workspace, cwd, argv, timeout_seconds=60,
                        dry_run=True, *, cancelled=None):
            assert type(cancelled) is threading.Event
            started.set()
            assert cancelled.wait(3)
            seen.set()
            return {"cleanup_proven": False,
                    "process_may_be_running": True}

    async def poll():
        return disconnected[0]

    async def scenario():
        async def request():
            result = await invoke_exec_with_cancel(
                FakeService(), "a", "go-project", ["go", "test", "./..."],
                timeout_seconds=5, dry_run=False,
                is_disconnected=poll)
            assert result["cleanup_proven"] is False

        async with anyio.create_task_group() as tasks:
            tasks.start_soon(request)
            with anyio.fail_after(3):
                assert await anyio.to_thread.run_sync(started.wait, 2)
            disconnected[0] = True

    anyio.run(scenario)
    assert seen.is_set()


def test_r006_private_apply_passes_cancel_token_and_public_f1_stays_denied(
    scene, monkeypatch,
):
    import threading
    from gateway.lbe_worker import LbeWorker, LbeWorkerError

    a, b, _private, _runtime = scene
    prime_existing_state(scene)
    svc = service(scene, v2_config(a, b))
    token = threading.Event()
    token.set()
    observed = []

    def fake_run(_worker, plan, *, cancelled=None):
        observed.append((plan.workspace, cancelled))
        raise LbeWorkerError("waiter_disconnected")

    try:
        with monkeypatch.context() as m:
            m.setattr(LbeWorker, "run", fake_run)
            with pytest.raises(GatewayError) as err:
                svc._lbe_apply(
                    svc.require_exec("a"), svc._lbe_owner, "go-project",
                    ["go", "test", "./..."], 5, cancelled=token)
        assert err.value.code == "waiter_disconnected"
        assert observed == [("a", token)]
        with pytest.raises(GatewayError) as denied:
            svc.invoke_exec(
                "a", "go-project", ["go", "test", "./..."], 5,
                dry_run=False, cancelled=token)
        assert denied.value.code == "exec_cleanup_proof_required"
        assert svc._lbe_owner.snapshot()["reserved_slots"] == 0
    finally:
        svc.close()


def test_r006_rest_and_official_mcp_forward_internal_event_only(
    scene, monkeypatch,
):
    import threading

    pytest.importorskip("mcp")
    a, b, _private, _runtime = scene
    prime_existing_state(scene)
    svc = service(scene, v2_config(a, b))
    original = svc.invoke_exec
    seen = []

    def observed_invoke(*args, **kwargs):
        seen.append(kwargs.get("cancelled"))
        return original(*args, **kwargs)

    args = {"workspace": "a", "cwd": "go-project",
            "argv": ["go", "test", "./..."], "timeout_seconds": 5}
    headers = {"Accept": "application/json, text/event-stream",
               "Content-Type": "application/json"}
    try:
        with monkeypatch.context() as m:
            m.setattr(svc, "invoke_exec", observed_invoke)
            with TestClient(create_multi_app(svc),
                            base_url="http://127.0.0.1:8765") as client:
                rest = client.post("/run", json=args)
                assert rest.status_code == 200
                init = client.post("/mcp", headers=headers, json={
                    "jsonrpc": "2.0", "id": 1, "method": "initialize",
                    "params": {"protocolVersion": "2025-11-25",
                               "capabilities": {},
                               "clientInfo": {"name": "r006-cancel", "version": "1"}},
                })
                assert init.status_code == 200
                client.post("/mcp", headers=headers, json={
                    "jsonrpc": "2.0", "method": "notifications/initialized"})
                mcp = client.post("/mcp", headers=headers, json={
                    "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                    "params": {"name": "run_command", "arguments": args},
                })
                assert mcp.status_code == 200
                assert mcp.json()["result"]["structuredContent"] == rest.json()
        assert len(seen) == 2
        assert all(type(token) is threading.Event for token in seen)
        assert seen[0] is not seen[1]
        assert svc._lbe_owner.snapshot()["reserved_slots"] == 0
    finally:
        svc.close()


@pytest.mark.parametrize("poll_connection", [False, True])
def test_r006_cancel_bridge_preserves_gateway_error_from_sync_gate(
    poll_connection,
):
    import anyio
    from gateway.lbe_cancel_bridge import invoke_exec_with_cancel

    class DeniedService:
        def invoke_exec(self, workspace, cwd, argv, timeout_seconds=60,
                        dry_run=True, *, cancelled=None):
            raise GatewayError("exec_cleanup_proof_required",
                               "Public Exec apply is not qualified.")

    async def poll():
        return False

    async def scenario():
        with pytest.raises(GatewayError) as denied:
            await invoke_exec_with_cancel(
                DeniedService(), "a", "go-project",
                ["go", "test", "./..."], timeout_seconds=5, dry_run=False,
                is_disconnected=poll if poll_connection else None)
        assert denied.value.code == "exec_cleanup_proof_required"

    anyio.run(scenario)
