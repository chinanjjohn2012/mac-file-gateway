"""R2-T02-B1-B0: actual disposable loopback *transport* provenance.

The tests use only internally minted temporary roots and genuine HTTP/MCP
requests over an ephemeral listening TCP socket. No subprocess is launched,
no host PID or process group is signaled, and **no non-preview Exec apply**
is attempted here. Worker proof-gate and terminal cleanup are future gates.
"""
from __future__ import annotations

import importlib
import json
import os
import socket
import subprocess
import time
import urllib.error
import urllib.request
from types import SimpleNamespace

import pytest

from gateway._exec_test_grant import create_private_disposable_acceptance

_HEADERS = {"Content-Type": "application/json",
            "Accept": "application/json, text/event-stream"}


def _new():
    try:
        module = importlib.import_module("gateway._exec_test_transport")
        factory = getattr(module, "create_private_bound_transport")
    except (ModuleNotFoundError, AttributeError) as exc:
        pytest.fail("B1B0_RED_NO_BOUND_PRIVATE_TRANSPORT: " +
                    type(exc).__name__, pytrace=False)
    return factory()


def _request(port: int, path: str, body: dict | None = None, *,
             headers: dict | None = None):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    data = None if body is None else json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=data, headers={**_HEADERS, **(headers or {})})
    try:
        with opener.open(req, timeout=3) as response:
            payload = response.read()
            return response.status, json.loads(payload) if payload else None
    except urllib.error.HTTPError as exc:
        payload = exc.read()
        return exc.code, json.loads(payload) if payload else None


def _qualified(env, *, service=None, workspace="a", listener=None):
    return env.grant.qualifies_transport(
        env.service if service is None else service, workspace,
        transport=env.listener if listener is None else listener)


def test_b1b0_real_listener_is_bound_to_loopback_and_serves_actual_gateway():
    with _new() as env:
        assert env.port > 0
        assert env.host == "127.0.0.1"
        assert env.listener._socket.fileno() >= 0
        assert env.listener._socket.getsockname() == ("127.0.0.1", env.port)
        assert env.listener._socket.getsockopt(
            socket.SOL_SOCKET, socket.SO_ACCEPTCONN) == 1
        assert env.listener._thread.is_alive()
        assert env.listener._server.started is True
        status, health = _request(env.port, "/health")
        assert status == 200 and health["status"] == "ok"
        assert health["mode"] == "multi" and health["mcp_enabled"] is True
        status, info = _request(env.port, "/info")
        assert status == 200 and info["exec_policy"]["enabled"] is True
        assert info["workspace_count"] == 2
        assert _qualified(env) is True
        assert env.grant.qualifies(
            env.service, "a", listener_host="127.0.0.1") is True


def test_b1b0_real_rest_preview_no_subprocess_or_writable_exec():
    with _new() as env:
        status, value = _request(env.port, "/run", {
            "workspace": "a", "cwd": "src", "argv": ["python", "hello.py"]})
        assert status == 200 and value["executed"] is False
        assert value["dry_run"] is True and value["workspace"] == "a"
        assert _qualified(env) is True
        assert (env.fixture.workspace_root("a") / "src" / "hello.py").is_file()


def test_b1b0_real_mcp_listener_exposes_read_only_preview_over_actual_wire():
    pytest.importorskip("mcp")
    with _new() as env:
        status, result = _request(env.port, "/mcp", {
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-11-25",
                       "capabilities": {},
                       "clientInfo": {"name": "b1b0-test", "version": "1"}}})
        assert status == 200 and "result" in result
        status, _ = _request(env.port, "/mcp", {
            "jsonrpc": "2.0", "method": "notifications/initialized"})
        assert status in (200, 202)
        status, result = _request(env.port, "/mcp", {
            "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        assert status == 200 and "result" in result
        names = {tool["name"] for tool in result["result"]["tools"]}
        assert "run_command" in names
        status, result = _request(env.port, "/mcp", {
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": "run_command", "arguments": {
                "workspace": "a", "cwd": "src", "argv": ["python", "hello.py"]}}})
        assert status == 200 and result["result"]["structuredContent"]["executed"] is False
        assert _qualified(env)


def test_b1b0_unbound_legacy_string_and_fake_transport_never_qualify():
    with create_private_disposable_acceptance() as fx:
        grant = fx.grant
        assert grant.qualifies(fx.service, "a", listener_host="127.0.0.1")
        assert grant.qualifies_transport(
            fx.service, "a", transport="127.0.0.1") is False
        fake = SimpleNamespace(host="127.0.0.1", port=8765,
                               started=True, _wire_ready=True)
        assert grant.qualifies_transport(
            fx.service, "a", transport=fake) is False
        assert grant.qualifies(fx.service, "a", listener_host="127.0.0.1")


def test_b1b0_foreign_live_socket_cannot_borrow_exact_fixture_grant():
    with _new() as a, _new() as b:
        assert a.port != b.port
        assert _qualified(a) and _qualified(b)
        assert _qualified(a, listener=b.listener) is False
        assert _qualified(b, listener=a.listener) is False
        assert _qualified(a, service=b.service) is False
        assert _qualified(b, service=a.service) is False
        assert _qualified(a) and _qualified(b)


def test_b1b0_wrong_workspace_and_raw_metadata_cannot_mint_listener_authority():
    with _new() as env:
        assert _qualified(env, workspace="a")
        for workspace in ("b", "missing", "../a", "", 0):
            assert _qualified(env, workspace=workspace) is False
        for fake in (
                "127.0.0.1", "localhost", "0.0.0.0", 8765,
                {"host": "127.0.0.1", "port": env.port},
                SimpleNamespace(_socket=env.listener._socket,
                                _server=env.listener._server,
                                _thread=env.listener._thread)):
            assert env.grant.qualifies_transport(
                env.service, "a", transport=fake) is False
        assert _qualified(env)


def test_b1b0_real_http_parameters_cannot_set_private_transport_grant():
    with _new() as env:
        status, before = _request(env.port, "/info")
        assert status == 200
        for injected in (
                {"test_grant": True},
                {"listener_host": "127.0.0.1"},
                {"transport": {"port": env.port}},
                {"full_descendant_tree_clean": True}):
            status, answer = _request(env.port, "/run", {
                "workspace": "a", "cwd": "src",
                "argv": ["python", "hello.py"], **injected})
            assert status == 400, (injected, status, answer)
        status, after = _request(env.port, "/info")
        assert before["exec_policy"] == after["exec_policy"]
        assert "test_grant" not in json.dumps(after)
        assert _qualified(env)


def test_b1b0_close_revokes_transport_before_teardown_and_no_reuse():
    env = _new()
    try:
        listener = env.listener
        service = env.service
        grant = env.grant
        assert _qualified(env)
        env.close()
        assert grant.qualifies_transport(
            service, "a", transport=listener) is False
        assert listener._socket.fileno() == -1
        assert not listener._thread.is_alive()
    finally:
        env.close()


def test_b1b0_closed_socket_invalidates_even_with_live_old_service():
    with _new() as env:
        assert _qualified(env)
        env.listener.close()
        assert _qualified(env) is False
        assert env.grant.qualifies(
            env.service, "a", listener_host="127.0.0.1") is False


def test_b1b0_socket_descriptor_or_wire_readiness_loss_revokes_one_way(monkeypatch):
    with _new() as env:
        assert _qualified(env)
        with monkeypatch.context() as p:
            p.setattr(env.listener, "_wire_ready", False)
            assert _qualified(env) is False
        assert _qualified(env) is False


def test_b1b0_transport_factory_does_not_spawn_or_signal_os_process(monkeypatch):
    calls = []
    real_popen = subprocess.Popen

    class _BlockedPopen(real_popen):
        def __new__(cls, *args, **kwargs):
            calls.append("Popen")
            raise AssertionError("B1B0_UNAUTHORIZED_HOST_SPAWN")

    def forbidden(*args, **kwargs):
        calls.append("host process or signal")
        raise AssertionError("B1B0_UNAUTHORIZED_SIGNAL")

    with monkeypatch.context() as p:
        p.setattr(subprocess, "Popen", _BlockedPopen)
        for name in ("kill", "killpg", "posix_spawn", "posix_spawnp",
                     "fork", "forkpty"):
            if hasattr(os, name):
                p.setattr(os, name, forbidden)
        with _new() as env:
            status, health = _request(env.port, "/health")
            assert status == 200 and health["status"] == "ok"
            assert _qualified(env)
    assert calls == []


def test_b1b0_normal_product_cli_and_service_have_no_transport_factory_import():
    """Baseline guard: no new production factory import or hidden grant."""
    from gateway import multi_cli
    from gateway.workspaces import WorkspaceService
    from gateway.http_multi import create_multi_app
    assert "_exec_test_transport" not in multi_cli.run_multi.__code__.co_names
    assert "_exec_test_transport" not in WorkspaceService.__init__.__code__.co_names
    assert "_exec_test_transport" not in create_multi_app.__code__.co_names
