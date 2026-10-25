"""D/T11: actual REST Git adapter, strict POST envelope and status contract."""
from __future__ import annotations

import json
import os
import subprocess
import threading
import time

import pytest
from starlette.testclient import TestClient

from gateway.core import Gateway, GatewayError
from gateway.http import create_app, MAX_GIT_BODY
from gateway.http_multi import create_multi_app
from gateway.workspaces import WorkspaceService, ActiveRuntimeInventory
from gateway.workspaces_config import parse_workspace_config


def git_init(root):
    root.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)


def make_legacy(tmp_path, *, enabled=True, file_write=False):
    root = tmp_path / "project"
    git_init(root)
    state_home = tmp_path / "control"
    state_home.mkdir(mode=0o700)
    return Gateway(
        root, allow_git=enabled,
        git_allowed_commands=("status",) if enabled else (),
        git_state_dir=state_home / "git-state",
        allow_write=file_write, write_paths=(".",) if file_write else (),
    )


def make_multi(tmp_path, *, enabled=True, file_write=False):
    parent = tmp_path / "parent"
    git_init(parent)
    a, b = parent / "a", parent / "b"
    a.mkdir()
    b.mkdir()
    config = tmp_path / "control"
    config.mkdir(mode=0o700)
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    raw = {
        "schema_version": 1,
        "server": {"git": {"enabled": enabled}},
        "workspaces": {
            "a": {
                "root": str(a),
                "git": {"allowed_commands": ["status"] if enabled else []},
                "write": {"enabled": file_write,
                          "paths": ["."] if file_write else []},
            },
            "b": {"root": str(b),
                  "git": {"allowed_commands": ["diff"] if enabled else []}},
        },
    }
    return WorkspaceService(parse_workspace_config(raw), config_dir=config,
                            inventory=ActiveRuntimeInventory(paths=(runtime,)))


def request(client, args, *, status=200):
    response = client.post("/git/run", json=args)
    assert response.status_code == status, (args, response.text)
    return response.json()


def test_legacy_git_rest_is_independently_enabled_and_returns_native_schema(tmp_path):
    gateway = make_legacy(tmp_path)
    try:
        with TestClient(create_app(gateway, enable_mcp=False),
                        base_url="http://127.0.0.1:8765") as client:
            assert client.get("/info").json()["read_only"] is True
            preview = request(client, {"command": "status"})
            assert preview["execute_started"] is False
            assert preview["dry_run"] is True
            assert preview["repository_checked"] is False
            assert preview["remote_checked"] is False
            assert preview["branch_checked"] is False
            actual = request(client, {"command": "status", "dry_run": False})
            assert actual["execute_started"] is True
            assert actual["repository_checked"] is True
            assert actual["exit_code"] == 0
            assert actual["cleanup_status"] == "complete"
            assert actual["workspace"] == "legacy"  # Engine uses an implicit Legacy Workspace.
            assert request(client, {"command": "push", "options": {"remote": "origin", "branch": "main"}}, status=403)["error"] == "git_command_not_allowed"
            assert request(client, {"command": "checkout"}, status=403)["error"] == "git_command_not_allowed"
            assert request(client, {"command": "status", "workspace": "a"},
                           status=400)["error"] == "invalid_argument"
    finally:
        gateway.close()


def test_multi_git_rest_requires_workspace_and_enforces_exact_allowlist(tmp_path):
    svc = make_multi(tmp_path)
    try:
        with TestClient(create_multi_app(svc, enable_mcp=False),
                        base_url="http://127.0.0.1:8765") as client:
            assert request(client, {"command": "status"}, status=400)["error"] == "invalid_argument"
            assert request(client, {"workspace": "unknown", "command": "status"},
                           status=404)["error"] == "workspace_not_found"
            assert request(client, {"workspace": "b", "command": "status"},
                           status=403)["error"] == "git_command_not_allowed"
            assert request(client, {"workspace": "a", "command": "pull",
                                    "options": {"remote": "origin", "branch": "main"}},
                           status=403)["error"] == "git_command_not_allowed"
            prev = request(client, {"workspace": "a", "command": "status"})
            assert prev["workspace"] == "a"
            assert prev["execute_started"] is False
            assert prev["repository_checked"] is False
            result = request(client, {"workspace": "a", "command": "status", "dry_run": False})
            assert result["exit_code"] == 0
            assert result["workspace"] == "a"
            assert result["cleanup_status"] == "complete"
            assert svc.info()["read_only"] is False
            assert svc.info()["file_read_only"] is True
            assert client.get("/health").json()["read_only"] is False
            assert client.get("/health").json()["file_read_only"] is True
            assert client.get("/info").json()["git_policy"]["adapter_exposed"] is True
    finally:
        svc.close()


@pytest.mark.parametrize("mode", ["legacy", "multi"])
def test_rest_git_global_disable_is_403_even_when_file_routes_work(tmp_path, mode):
    instance = make_legacy(tmp_path, enabled=False) if mode == "legacy" else make_multi(
        tmp_path, enabled=False,
    )
    try:
        app = create_app(instance, enable_mcp=False) if mode == "legacy" else create_multi_app(
            instance, enable_mcp=False,
        )
        with TestClient(app, base_url="http://127.0.0.1:8765") as client:
            params = {"command": "status", **({"workspace": "a"} if mode == "multi" else {})}
            assert request(client, params, status=403)["error"] == "git_disabled"
            assert client.get("/info").status_code == 200
            assert client.get("/list", params={"path": ".", **({"workspace": "a"} if mode == "multi" else {})}).status_code == 200
    finally:
        instance.close()


@pytest.mark.parametrize("mode", ["legacy", "multi"])
def test_rest_git_rejects_nested_and_envelope_arguments_before_popen(
    tmp_path, monkeypatch, mode,
):
    instance = make_legacy(tmp_path) if mode == "legacy" else make_multi(tmp_path)
    assert instance._git_executor is not None
    original = instance._git_executor.runner.run
    started = []

    def spy(*args, **kwargs):
        started.append(args)
        return original(*args, **kwargs)

    monkeypatch.setattr(instance._git_executor.runner, "run", spy)
    try:
        app = create_app(instance, enable_mcp=False) if mode == "legacy" else create_multi_app(
            instance, enable_mcp=False,
        )
        with TestClient(app, base_url="http://127.0.0.1:8765") as client:
            ws = {"workspace": "a"} if mode == "multi" else {}
            cases = [
                ({"command": "status", "cwd": "../escape"}, 403, "git_path_blocked"),
                ({"command": "status", "paths": ["../escape"]}, 403, "git_path_blocked"),
                ({"command": "status", "options": {"unknown": 1}}, 400, "git_option_invalid"),
                ({"command": "status", "paths": "some-path"}, 400, "invalid_argument"),
                ({"command": "status", "options": ["not a dict"]}, 400, "invalid_argument"),
                ({"command": "status", "timeout_seconds": True}, 400, "invalid_argument"),
                ({"command": "status", "dry_run": 0}, 400, "invalid_argument"),
                ({"command": "status", "timeout_seconds": 9}, 400, "git_option_invalid"),
                ({"command": "status", "extra": "not allowed"}, 400, "invalid_argument"),
            ]
            for params, code, reason in cases:
                response = request(client, {**ws, **params}, status=code)
                assert response["error"] == reason, (params, response)
            assert started == []
            assert client.post("/git/run?unsafe=1", json={**ws, "command": "status"}).status_code == 400
            assert client.post("/git/run", content=b'{"command":"status","command":"push",'
                               + (b'"workspace":"a",' if mode == "multi" else b"")
                               + b'"dry_run":false}', headers={"Content-Type":"application/json"}).status_code == 400
            assert started == []
    finally:
        instance.close()


@pytest.mark.parametrize("mode", ["legacy", "multi"])
def test_rest_git_body_limit_applies_even_when_file_writer_has_large_budget(
    tmp_path, mode,
):
    instance = make_legacy(tmp_path, file_write=True) if mode == "legacy" else make_multi(
        tmp_path, file_write=True,
    )
    try:
        app = create_app(instance, enable_mcp=False) if mode == "legacy" else create_multi_app(
            instance, enable_mcp=False,
        )
        with TestClient(app, base_url="http://127.0.0.1:8765") as client:
            body = json.dumps({"command": "status",
                               **({"workspace": "a"} if mode == "multi" else {}),
                               "noise": "x" * MAX_GIT_BODY}).encode("utf-8")
            assert len(body) > MAX_GIT_BODY
            response = client.post("/git/run", content=body,
                                   headers={"Content-Type": "application/json"})
            assert response.status_code == 413
            assert response.json()["error"] in ("too_large", "request_body_too_large")
    finally:
        instance.close()


@pytest.mark.parametrize("mode", ["legacy", "multi"])
def test_rest_git_reuses_host_origin_and_bearer_security(tmp_path, mode):
    instance = make_legacy(tmp_path) if mode == "legacy" else make_multi(tmp_path)
    try:
        app = create_app(instance, enable_mcp=False, token="X" * 40) if mode == "legacy" else create_multi_app(
            instance, enable_mcp=False, token="X" * 40,
        )
        with TestClient(app, base_url="http://127.0.0.1:8765") as client:
            ws = {"workspace": "a"} if mode == "multi" else {}
            args = {**ws, "command": "status", "dry_run": False}
            assert client.post("/git/run", json=args).status_code == 401
            assert client.post("/git/run", json=args,
                               headers={"Host": "evil.test:8765",
                                        "Authorization": "Bearer " + "X"*40}).status_code == 421
            assert client.post("/git/run", json=args,
                               headers={"Origin": "https://evil.test",
                                        "Authorization": "Bearer " + "X"*40}).status_code == 403
            assert request_with_token(client, args)["exit_code"] == 0
    finally:
        instance.close()


def request_with_token(client, params):
    result = client.post("/git/run", json=params, headers={"Authorization": "Bearer " + "X"*40})
    assert result.status_code == 200, result.text
    return result.json()


@pytest.mark.parametrize("mode", ["legacy", "multi"])
def test_rest_git_failure_status_mapping_stays_sanitized(tmp_path, monkeypatch, mode):
    instance = make_legacy(tmp_path) if mode == "legacy" else make_multi(tmp_path)
    fn = instance.invoke_git
    codes = [
        ("git_busy", 409),
        ("git_repository_quarantined", 409),
        ("git_global_quarantined", 503),
        ("git_cleanup_incomplete", 503),
        ("git_state_unavailable", 503),
        ("git_timeout", 504),
    ]
    try:
        app = create_app(instance, enable_mcp=False) if mode == "legacy" else create_multi_app(
            instance, enable_mcp=False,
        )
        with TestClient(app, base_url="http://127.0.0.1:8765") as client:
            args = {"command": "status", **({"workspace": "a"} if mode == "multi" else {})}
            for code, status in codes:
                def raise_failure(*unused, **unused_kw):
                    raise GatewayError(code, "Git operation was not completed.")
                monkeypatch.setattr(instance, "invoke_git", raise_failure)
                answer = request(client, args, status=status)
                assert answer["error"] == code
                assert str(tmp_path) not in str(answer)
            monkeypatch.setattr(instance, "invoke_git", fn)
    finally:
        instance.close()


def test_multi_rest_git_actual_threadpool_worker_owns_root_fd_until_close(
    tmp_path, monkeypatch,
):
    svc = make_multi(tmp_path)
    entered, release = threading.Event(), threading.Event()
    response = []
    errors = []
    fd = svc.get("a").gateway._root_fd
    pinned_ino = os.fstat(fd).st_ino

    def blocked_run(**kwargs):
        assert kwargs["root_fd"] == fd
        entered.set()
        if not release.wait(timeout=10):
            raise AssertionError("worker timed out")
        assert os.fstat(fd).st_ino == pinned_ino
        return {"execute_started": True, "cleanup_status": "complete", "exit_code": 0}

    monkeypatch.setattr(svc._git_executor, "run", blocked_run)
    try:
        with TestClient(create_multi_app(svc, enable_mcp=False),
                        base_url="http://127.0.0.1:8765") as client:
            def do_request():
                try:
                    response.append(request(client, {"workspace": "a",
                                                     "command": "status",
                                                     "dry_run": False}))
                except BaseException as exc:
                    errors.append(exc)
            http_thread = threading.Thread(target=do_request)
            closed = threading.Event()
            def close_after_admission():
                try:
                    svc.close()
                finally:
                    closed.set()
            closer = threading.Thread(target=close_after_admission)
            try:
                http_thread.start()
                assert entered.wait(timeout=6)
                closer.start()
                limit = time.monotonic() + 5
                while not svc._closing and time.monotonic() < limit:
                    time.sleep(0.01)
                assert svc._closing
                assert not closed.is_set()
                assert os.fstat(fd)
            finally:
                release.set()
                http_thread.join(timeout=10)
                closer.join(timeout=10)
                assert not http_thread.is_alive() and not closer.is_alive()
            assert closed.is_set() and not errors, errors
            assert response and response[0]["exit_code"] == 0
    finally:
        svc.close()
