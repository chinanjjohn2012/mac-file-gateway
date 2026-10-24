"""Production-first F1 deny-only Multi-Workspace Exec regression.

Previously runnable real Exec subprocess cases remain inspectable verbatim at
Git HEAD 4110fac4edf2027703f4ce830a4d46718de4804d. The approved F0
traceability matrix maps historic positive-child requirements to future F3
native acceptance, not to silent skips or claimed F1 cleanup proof.
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



def test_exec_preview_and_proof_deny_are_workspace_scoped(setup, monkeypatch):
    svc = _service(setup)
    try:
        assert svc.any_exec
        policy = svc.info()["exec_policy"]
        assert policy["enabled"] and policy["available"] is False
        assert policy["completion_capability"] == "none"
        assert svc.list_workspaces()["workspaces"][0]["exec"] is True
        assert svc.list_workspaces()["workspaces"][1]["exec"] is False
        preview = svc.invoke_exec("a", "src", ["python", "hello.py"])
        assert preview["dry_run"] is True and preview["executed"] is False
        assert preview["workspace"] == "a" and preview["runner"] == "direct"
        calls = []
        monkeypatch.setattr(svc.get("a").gateway, "run_command",
                            lambda *args, **kwargs: calls.append((args, kwargs)))
        with pytest.raises(GatewayError) as exc:
            svc.invoke_exec("a", "src", ["python", "hello.py"], dry_run=False)
        assert exc.value.code == "exec_cleanup_proof_required"
        assert calls == []
        with pytest.raises(GatewayError) as exc:
            svc.invoke_exec("b", "src", ["python", "hello.py"], dry_run=False)
        assert exc.value.code == "exec_disabled"
        with pytest.raises(GatewayError) as exc:
            svc.invoke_exec("a", "src", ["python", "hello.py"], dry_run="false")
        assert exc.value.code == "invalid_argument"
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
            assert actual.status_code == 503, actual.text
            assert actual.json()["error"] == "exec_cleanup_proof_required"
            assert not (setup[0] / "src" / "started").exists()
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
            svc.invoke_exec("a", "src", ["python", "hello.py"], dry_run=True)
        except Exception as exc:
            errors.append(exc)
    running = threading.Thread(target=worker, daemon=True)
    running.start()
    try:
        assert entered.wait(3)
        with pytest.raises(GatewayError) as exc:
            svc.invoke_exec("a", "src", ["python", "hello.py"], dry_run=True)
        assert exc.value.code == "busy"
        with pytest.raises(GatewayError) as exc:
            svc.invoke_exec("a", "src", ["python", "hello.py"], dry_run=False)
        assert exc.value.code == "exec_cleanup_proof_required"
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
            assert done.get("isError") is True
            assert done["structuredContent"]["error"] == "exec_cleanup_proof_required"
    finally:
        svc.close()


def test_global_four_slots_reject_fifth_until_one_releases(tmp_path, monkeypatch):
    """Five distinct effective grants, four occupied Workers: reject, then reuse."""
    projects = tmp_path / "projects"
    projects.mkdir()
    config_dir = tmp_path / "config"
    config_dir.mkdir(mode=0o700)
    config_dir.chmod(0o700)
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    config = {"schema_version": 1, "server": {"exec": {"enabled": True}},
              "workspaces": {}}
    for name in "abcde":
        root = projects / name
        root.mkdir()
        (root / "src").mkdir()
        (root / "src" / "hello.py").write_text("print('disposable')\n")
        config["workspaces"][name] = {
            "root": str(root),
            "exec": {"enabled": True, "paths": ["src"],
                     "runners": ["src=direct"]},
        }
    svc = WorkspaceService(parse_workspace_config(config), config_dir=config_dir,
                           inventory=ActiveRuntimeInventory(paths=(runtime,)))
    entered = {name: threading.Event() for name in "abcd"}
    release = {name: threading.Event() for name in "abcd"}
    finished = {name: threading.Event() for name in "abcd"}
    errors = []

    def slow(name, original):
        def runner(cwd, argv, timeout_seconds=60, dry_run=True):
            entered[name].set()
            if not release[name].wait(8):
                raise AssertionError("test did not release the controlled Worker")
            return original(cwd, argv, timeout_seconds, True)
        return runner

    def worker(name):
        try:
            result = svc.invoke_exec(name, "src", ["python", "hello.py"],
                                     dry_run=True)
            assert result["workspace"] == name
        except BaseException as exc:
            errors.append(exc)
        finally:
            finished[name].set()

    threads = []
    try:
        for name in "abcd":
            gateway = svc.get(name).gateway
            monkeypatch.setattr(gateway, "run_command",
                                slow(name, gateway.run_command))
            thread = threading.Thread(target=worker, args=(name,), daemon=True)
            thread.start()
            threads.append(thread)
        for name in "abcd":
            assert entered[name].wait(4), f"Workspace {name} never occupied slot"
        with pytest.raises(GatewayError) as exc:
            svc.invoke_exec("e", "src", ["python", "hello.py"])
        assert exc.value.code == "busy"
        with pytest.raises(GatewayError) as exc:
            svc.invoke_exec("e", "src", ["python", "hello.py"], dry_run=False)
        assert exc.value.code == "exec_cleanup_proof_required"
        assert not any(finished[name].is_set() for name in "abcd")
        release["a"].set()
        assert finished["a"].wait(4), "one slot did not return"
        preview = svc.invoke_exec("e", "src", ["python", "hello.py"])
        assert preview["executed"] is False and preview["workspace"] == "e"
        assert not any(finished[name].is_set() for name in "bcd")
    finally:
        for event in release.values():
            event.set()
        for thread in threads:
            thread.join(timeout=5)
        svc.close()
    assert all(finished[name].is_set() for name in "abcd")
    assert not errors, errors


def test_cli_reports_actual_exec_state(setup, tmp_path, monkeypatch, capsys):
    """CLI status is truthful without starting a listener or executing commands."""
    import json
    from types import SimpleNamespace
    import uvicorn
    from gateway import multi_cli

    a, b, _private, _runtime = setup
    actual_run = []
    monkeypatch.setattr(uvicorn, "run",
                        lambda *args, **kwargs: actual_run.append(kwargs))
    for enabled in (False, True):
        control = tmp_path / ("config-disabled" if not enabled else "config-enabled")
        control.mkdir(mode=0o700)
        control.chmod(0o700)
        filename = control / "gateway.json"
        filename.write_text(json.dumps(_settings(a, b, server=enabled,
                                                  grant=enabled)))
        filename.chmod(0o600)
        assert multi_cli.run_multi(SimpleNamespace(config=str(filename),
                                                   check=False, http_only=True)) == 0
        output = capsys.readouterr().err
        if enabled:
            assert "Controlled Exec API registered" in output
            assert "Controlled Exec disabled" not in output
        else:
            assert "Controlled Exec disabled by policy" in output
        assert "Local Skills disabled" in output
        assert "General Exec and Local Skills disabled" not in output
    assert len(actual_run) == 2



def test_asgi_rest_disconnect_keeps_sync_preview_worker_until_exit(setup, monkeypatch):
    """F1 deterministic cancellation/drain regression; NO real Exec child.

    The frozen F3 positive-child evidence belongs to the earlier source SHA.
    The real Starlette/ASGI waiter may be cancelled while its synchronous
    preview Worker still leases the Workspace root.
    """
    import asyncio
    import json

    svc = _service(setup)
    app = create_multi_app(svc, enable_mcp=False)
    entered, release, finished, closed = (threading.Event(), threading.Event(),
                                          threading.Event(), threading.Event())
    errors = []
    gateway = svc.get("a").gateway
    real = gateway.run_command

    def blocked(cwd, argv, timeout_seconds=60, dry_run=True):
        assert dry_run is True
        entered.set()
        try:
            if not release.wait(8):
                raise AssertionError("preview Worker was not released")
            return real(cwd, argv, timeout_seconds, True)
        finally:
            finished.set()

    monkeypatch.setattr(gateway, "run_command", blocked)

    def close():
        try:
            svc.close()
        except BaseException as exc:
            errors.append(exc)
        finally:
            closed.set()

    async def scenario():
        body = json.dumps({"workspace": "a", "cwd": "src",
                           "argv": ["python", "hello.py"],
                           "dry_run": True}).encode()
        incoming = asyncio.Queue()
        await incoming.put({"type": "http.request", "body": body,
                            "more_body": False})
        async def receive():
            return await incoming.get()
        responses = []
        async def send(message):
            responses.append(message)
        scope = {
            "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
            "scheme": "http", "method": "POST", "path": "/run",
            "raw_path": b"/run", "root_path": "", "query_string": b"",
            "headers": [(b"host", b"127.0.0.1:8765"),
                        (b"content-type", b"application/json")],
            "client": ("127.0.0.1", 44000), "server": ("127.0.0.1", 8765),
        }
        request = asyncio.create_task(app(scope, receive, send))
        closer = None
        try:
            assert await asyncio.to_thread(entered.wait, 4)
            await incoming.put({"type": "http.disconnect"})
            request.cancel()
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(request, 2)
            assert not finished.is_set()
            with pytest.raises(GatewayError) as exc:
                svc.invoke_exec("a", "src", ["python", "hello.py"], dry_run=True)
            assert exc.value.code == "busy"
            with pytest.raises(GatewayError) as exc:
                svc.invoke_exec("a", "src", ["python", "hello.py"], dry_run=False)
            assert exc.value.code == "exec_cleanup_proof_required"
            assert svc.invoke("b", "list_files", ".")["workspace"] == "b"
            closer = threading.Thread(target=close, daemon=True)
            closer.start()
            assert not await asyncio.to_thread(closed.wait, 0.15)
            release.set()
            assert await asyncio.to_thread(closed.wait, 5)
            assert finished.is_set() and not errors
            assert not any(m.get("type") == "http.response.start"
                           for m in responses)
        finally:
            release.set()
            if not request.done():
                request.cancel()
                await asyncio.gather(request, return_exceptions=True)
            if closer is not None:
                await asyncio.to_thread(closer.join, 6)

    try:
        asyncio.run(scenario())
    finally:
        release.set()
        svc.close()
    assert closed.is_set() and not errors

def test_cancelled_mcp_tool_waiter_does_not_release_sync_worker(setup, monkeypatch):
    """Real SDK tool dispatch, cancelled request waiter, still-owned Worker.

    This validates MCP tool cancellation rather than a real MCP HTTP/Tunnel
    socket disconnect; that later native/listener acceptance remains NOT_RUN.
    """
    import asyncio

    pytest.importorskip("mcp")
    from gateway.mcp_multi import build_multi_mcp

    svc = _service(setup)
    gateway = svc.get("a").gateway
    entered, release, finished = (threading.Event(), threading.Event(),
                                  threading.Event())
    original = gateway.run_command

    def blocked(cwd, argv, timeout_seconds=60, dry_run=True):
        entered.set()
        try:
            if not release.wait(8):
                raise AssertionError("test did not release MCP Worker")
            return original(cwd, argv, timeout_seconds, True)
        finally:
            finished.set()

    monkeypatch.setattr(gateway, "run_command", blocked)
    mcp = build_multi_mcp(svc)

    async def scenario():
        request = asyncio.create_task(mcp.call_tool("run_command", {
            "workspace": "a", "cwd": "src", "argv": ["python", "hello.py"],
            "dry_run": True,
        }))
        try:
            assert await asyncio.to_thread(entered.wait, 4)
            request.cancel()
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(request, 2)
            assert not finished.is_set()
            with pytest.raises(GatewayError) as exc:
                svc.invoke_exec("a", "src", ["python", "hello.py"])
            assert exc.value.code == "busy"
            with pytest.raises(GatewayError) as exc:
                svc.invoke_exec("a", "src", ["python", "hello.py"], dry_run=False)
            assert exc.value.code == "exec_cleanup_proof_required"
        finally:
            release.set()
            assert await asyncio.to_thread(finished.wait, 5)
            if not request.done():
                request.cancel()
                await asyncio.gather(request, return_exceptions=True)

    try:
        asyncio.run(scenario())
    finally:
        release.set()
        svc.close()
