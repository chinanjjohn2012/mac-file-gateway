"""Multi-Workspace Exec candidate: opt-in grants and disposable Worker acceptance.

Only temporary test directories, never Candidate C or native group-signal
research. Exec scope controls cwd/script selection, NOT OS sandbox rights.
"""
from __future__ import annotations

import threading
from pathlib import Path
import pytest
from starlette.testclient import TestClient

from gateway.core import GatewayError
from gateway.private_fs import PrivateFileError
from gateway.workspaces_config import parse_workspace_config
from gateway.workspaces import WorkspaceService, ActiveRuntimeInventory
from gateway.http_multi import create_multi_app


def _settings(a: Path, b: Path, *, server: bool = True, grant: bool = True):
    return {
        "schema_version": 1,
        "server": {"exec": {"enabled": server}},
        "workspaces": {
            "a": {"root": str(a), "exec": {
                "enabled": grant,
                "paths": ["src"] if grant else [],
                "runners": ["src=direct"] if grant else [],
            }},
            "b": {"root": str(b)},
        },
    }


@pytest.fixture
def setup(tmp_path):
    projects = tmp_path / "projects"
    projects.mkdir()
    a, b = projects / "a", projects / "b"
    a.mkdir()
    b.mkdir()
    (a / "src").mkdir()
    (b / "src").mkdir()
    (a / "src" / "hello.py").write_text("print('from-workspace-a')\n")
    (b / "src" / "hello.py").write_text("print('from-workspace-b')\n")
    config = tmp_path / "config"
    config.mkdir(mode=0o700)
    config.chmod(0o700)
    runtime = tmp_path / "trusted-runtime"
    runtime.mkdir()
    return a, b, config, runtime


def _service(setup):
    a, b, config, runtime = setup
    settings = parse_workspace_config(_settings(a, b))
    return WorkspaceService(settings, config_dir=config,
                            inventory=ActiveRuntimeInventory(paths=(runtime,)))


@pytest.mark.parametrize("change", [
    lambda c: c["server"]["exec"].update(enabled=False),
    lambda c: c["workspaces"]["a"]["exec"].update(paths=[]),
    lambda c: c["workspaces"]["a"]["exec"].update(paths=["../other"]),
    lambda c: c["workspaces"]["a"]["exec"].update(paths=["/tmp"]),
    lambda c: c["workspaces"]["a"]["exec"].update(runners=["src=unknown"]),
    lambda c: c["workspaces"]["a"]["exec"].update(runners=["../other=direct"]),
    lambda c: c["workspaces"]["a"]["exec"].update(runners=["src=direct=extra"]),
    lambda c: c["workspaces"]["a"]["exec"].update(enabled=False),
    lambda c: c["server"]["exec"].update(enabled="true"),
])
def test_config_requires_two_gates_and_canonical_scopes(setup, change):
    a, b, _configdir, _runtime = setup
    value = _settings(a, b)
    change(value)
    with pytest.raises(PrivateFileError):
        parse_workspace_config(value)


def test_global_off_defaults_to_no_exec(setup):
    a, b, config, runtime = setup
    settings = parse_workspace_config({
        "schema_version": 1, "workspaces": {
            "a": {"root": str(a)}, "b": {"root": str(b)}}})
    svc = WorkspaceService(settings, config_dir=config,
                           inventory=ActiveRuntimeInventory(paths=(runtime,)))
    try:
        assert svc.any_exec is False
        assert svc.list_workspaces()["workspaces"][0]["exec"] is False
        assert svc.info()["exec_policy"]["enabled"] is False
        with pytest.raises(GatewayError) as exc:
            svc.invoke_exec("a", "src", ["python", "hello.py"])
        assert exc.value.code == "exec_disabled"
        with TestClient(create_multi_app(svc, enable_mcp=False),
                        base_url="http://127.0.0.1:8765") as client:
            assert client.post("/run", json={"workspace":"a","cwd":"src",
                                            "argv":["python","hello.py"]}).status_code == 404
    finally:
        svc.close()


def test_exec_preview_and_real_execution_are_workspace_scoped(setup):
    svc = _service(setup)
    try:
        assert svc.any_exec
        assert svc.info()["exec_policy"]["enabled"]
        assert svc.list_workspaces()["workspaces"][0]["exec"] is True
        assert svc.list_workspaces()["workspaces"][1]["exec"] is False
        preview = svc.invoke_exec("a", "src", ["python", "hello.py"])
        assert preview["dry_run"] is True and preview["executed"] is False
        assert preview["workspace"] == "a" and preview["runner"] == "direct"
        actual = svc.invoke_exec("a", "src", ["python", "hello.py"], dry_run=False)
        assert actual["executed"] is True
        assert actual["exit_code"] == 0 and actual["timed_out"] is False
        assert "from-workspace-a" in actual["stdout"]
        assert "from-workspace-b" not in actual["stdout"]
        with pytest.raises(GatewayError) as exc:
            svc.invoke_exec("b", "src", ["python", "hello.py"], dry_run=False)
        assert exc.value.code == "exec_disabled"
        with pytest.raises(GatewayError) as exc:
            svc.invoke_exec("a", ".", ["python", "src/hello.py"], dry_run=False)
        assert exc.value.code == "exec_scope"
        with pytest.raises(GatewayError) as exc:
            svc.invoke_exec("a", "src", ["python", "-c", "print(1)"], dry_run=False)
        assert exc.value.code == "command_not_allowed"
        with pytest.raises(GatewayError):
            svc.invoke("a", "run_command", "src", ["python", "hello.py"])
    finally:
        svc.close()


def test_rest_explicit_routing_and_types(setup):
    svc = _service(setup)
    try:
        with TestClient(create_multi_app(svc, enable_mcp=False),
                        base_url="http://127.0.0.1:8765") as client:
            base = {"workspace":"a","cwd":"src","argv":["python","hello.py"]}
            assert client.get("/info").json()["exec_policy"]["adapter_exposed"] is True
            preview = client.post("/run", json=base)
            assert preview.status_code == 200, preview.text
            assert preview.json()["executed"] is False
            denied = client.post("/run", json={**base,"workspace":"b","dry_run":False})
            assert denied.status_code == 403
            missing = client.post("/run", json={"cwd":"src","argv":["python","hello.py"]})
            assert missing.status_code == 400
            for value in ({"timeout_seconds":True}, {"timeout_seconds":301},
                          {"dry_run":"false"}, {"argv":["python",7]},
                          {"unexpected":1}):
                bad = client.post("/run", json={**base,**value})
                assert bad.status_code == 400, (value, bad.text)
            actual = client.post("/run", json={**base,"dry_run":False})
            assert actual.status_code == 200, actual.text
            assert "from-workspace-a" in actual.json()["stdout"]
    finally:
        svc.close()


def test_worker_lease_blocks_same_workspace_and_close_waits(setup, monkeypatch):
    svc = _service(setup)
    entered, release, closed = threading.Event(), threading.Event(), threading.Event()
    errors: list[Exception] = []
    gateway = svc.get("a").gateway
    real = gateway.run_command

    def blocked(cwd, argv, timeout_seconds=60, dry_run=True):
        entered.set()
        if not release.wait(5):
            raise AssertionError("test blocked worker was not released")
        return real(cwd, argv, timeout_seconds, True)

    monkeypatch.setattr(gateway, "run_command", blocked)
    def worker():
        try:
            svc.invoke_exec("a", "src", ["python", "hello.py"], dry_run=False)
        except Exception as exc:
            errors.append(exc)
    running = threading.Thread(target=worker, daemon=True)
    running.start()
    try:
        assert entered.wait(3)
        with pytest.raises(GatewayError) as exc:
            svc.invoke_exec("a", "src", ["python", "hello.py"], dry_run=False)
        assert exc.value.code == "busy"
        closer = threading.Thread(target=lambda: (svc.close(), closed.set()), daemon=True)
        closer.start()
        assert not closed.wait(0.12), "Service closed the root while Exec Worker held a lease"
    finally:
        release.set()
        running.join(5)
        if "closer" in locals():
            closer.join(5)
        svc.close()
    assert not errors and closed.is_set()


def test_mcp_registry_and_grants(setup):
    pytest.importorskip("mcp")
    svc = _service(setup)
    headers = {"Accept":"application/json, text/event-stream",
               "Content-Type":"application/json"}
    def rpc(client, method, params=None):
        response = client.post("/mcp", headers=headers, json={
            "jsonrpc":"2.0","id":2,"method":method,"params":params or {}})
        assert response.status_code == 200, response.text
        return response.json()
    try:
        with TestClient(create_multi_app(svc),
                        base_url="http://127.0.0.1:8765") as client:
            assert "result" in rpc(client,"initialize",{
                "protocolVersion":"2025-11-25","capabilities":{},
                "clientInfo":{"name":"exec-product-test","version":"1"}})
            client.post("/mcp",headers=headers,
                        json={"jsonrpc":"2.0","method":"notifications/initialized"})
            names = {tool["name"] for tool in rpc(client,"tools/list")["result"]["tools"]}
            assert "run_command" in names
            assert "run_skill_script" not in names
            base = {"workspace":"a","cwd":"src","argv":["python","hello.py"]}
            dry = rpc(client,"tools/call",{"name":"run_command","arguments":base})["result"]
            assert dry["structuredContent"]["executed"] is False
            denied = rpc(client,"tools/call",{"name":"run_command","arguments":{
                **base, "workspace":"b", "dry_run":False}})["result"]
            assert denied.get("isError") is True
            done = rpc(client,"tools/call",{"name":"run_command","arguments":{
                **base, "dry_run":False}})["result"]
            assert done["structuredContent"]["exit_code"] == 0
            assert "from-workspace-a" in done["structuredContent"]["stdout"]
    finally:
        svc.close()
