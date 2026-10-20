"""Inert admission drains with file workers; no live exec route is added."""
import asyncio
import os
import threading

import pytest
from starlette.testclient import TestClient
from mcp.server.mcpserver.exceptions import ToolError

from gateway.core import GatewayError
from gateway.exec_contracts import ExecutionOutcome
from gateway.http_multi import create_multi_app
from gateway.mcp_multi import build_multi_mcp
from exec_core_helpers import core_service


REQUEST = {"workspace": "a", "cwd": "service", "argv": ["pytest"], "dry_run": False}
ABANDONED = ExecutionOutcome(None, False, "abandoned")


def test_service_close_waits_for_owner_and_file_worker(tmp_path, monkeypatch):
    with core_service(tmp_path) as service:
        registry = service._exec_registry
        lease = service._reserve_execution(REQUEST)
        ctx = service.get("a")
        fd = ctx.gateway._root_fd
        file_started, file_finish = threading.Event(), threading.Event()
        closing, waiting_owner = threading.Event(), threading.Event()
        errors = []
        original_read = ctx.gateway.read_file
        def blocked_read(*args, **kwargs):
            file_started.set()
            assert file_finish.wait(timeout=5)
            return original_read(*args, **kwargs)
        original_close, original_wait = registry.begin_close, registry.wait_idle
        def begin_close():
            original_close()
            closing.set()
        def wait_idle():
            waiting_owner.set()
            original_wait()
        monkeypatch.setattr(ctx.gateway, "read_file", blocked_read)
        monkeypatch.setattr(registry, "begin_close", begin_close)
        monkeypatch.setattr(registry, "wait_idle", wait_idle)
        def read():
            try:
                service.invoke("a", "read_file", "service/test.txt")
            except BaseException as exc:
                errors.append(exc)
        file_thread = threading.Thread(target=read)
        close_thread = threading.Thread(target=service.close)
        file_thread.start()
        try:
            assert file_started.wait(timeout=3)
            close_thread.start()
            assert closing.wait(timeout=3)
            assert os.fstat(fd).st_ino > 0
            file_finish.set()
            file_thread.join(timeout=3)
            assert not file_thread.is_alive()
            assert waiting_owner.wait(timeout=3)
            assert os.fstat(fd).st_ino > 0
            assert close_thread.is_alive() and registry.snapshot().active_total == 1
        finally:
            file_finish.set()
            registry.finish(lease, ABANDONED)
            file_thread.join(timeout=3)
            if close_thread.ident is not None:
                close_thread.join(timeout=3)
        assert not errors and not close_thread.is_alive()
        with pytest.raises(OSError):
            os.fstat(fd)


def test_busy_exec_does_not_block_other_workspace_file_read(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("core path started a subprocess")
    monkeypatch.setattr("subprocess.Popen", forbidden)
    with core_service(tmp_path) as service:
        lease = service._reserve_execution(REQUEST)
        try:
            with pytest.raises(GatewayError) as e:
                service._reserve_execution(REQUEST)
            assert e.value.code == "exec_busy"
            value = service.invoke("b", "read_file", "service/test.txt")
            assert value["workspace"] == "b" and "fixture" in str(value)
        finally:
            service._exec_registry.finish(lease, ABANDONED)


def test_reserve_reauthorizes_payload_and_rejects_borrowed_intent(tmp_path):
    with core_service(tmp_path) as service:
        intent = service.prepare_execution(REQUEST)
        with pytest.raises(GatewayError):
            service._reserve_execution(intent)
        with pytest.raises(GatewayError) as e:
            service._reserve_execution({**REQUEST, "workspace": "b"})
        assert e.value.code == "exec_disabled"
        assert service._exec_registry.snapshot().active_total == 0


def test_close_never_admits_after_closing(tmp_path, monkeypatch):
    with core_service(tmp_path) as service:
        registry = service._exec_registry
        lease = service._reserve_execution(REQUEST)
        closing = threading.Event()
        original = registry.begin_close
        def observed():
            original()
            closing.set()
        monkeypatch.setattr(registry, "begin_close", observed)
        thread = threading.Thread(target=service.close)
        thread.start()
        try:
            assert closing.wait(timeout=3)
            for call in (lambda: service.prepare_execution(REQUEST),
                         lambda: service._reserve_execution(REQUEST),
                         lambda: service.invoke("a", "list_files")):
                with pytest.raises(GatewayError) as e:
                    call()
                assert e.value.code == "service_closing"
        finally:
            registry.finish(lease, ABANDONED)
            thread.join(timeout=3)
        assert not thread.is_alive()
        service.close()


def test_all_multi_gateways_stay_disabled(tmp_path, monkeypatch):
    calls = []
    def forbidden(*args, **kwargs):
        calls.append(1)
        raise AssertionError("Multi Popen")
    monkeypatch.setattr("subprocess.Popen", forbidden)
    with core_service(tmp_path) as service:
        service.prepare_execution(REQUEST)
        for name in ("a", "b"):
            ctx = service.get(name)
            assert ctx.gateway._executor.enabled is False
            with pytest.raises(GatewayError):
                ctx.gateway.run_command("service", ["pytest"], dry_run=False)
            for op in ("run_command", "prepare_execution", "_reserve_execution"):
                with pytest.raises(GatewayError):
                    service.invoke(name, op, REQUEST)
    assert calls == []


def test_file_only_factories_do_not_register_execution(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Multi task spawned")
    monkeypatch.setattr("subprocess.Popen", forbidden)
    with core_service(tmp_path, {"a": {"enabled": False}, "b": {"enabled": False}}) as service:
        app = create_multi_app(service, enable_mcp=False)
        with TestClient(app, base_url="http://127.0.0.1:8765") as client:
            assert client.get("/health").status_code == 200
            assert client.post("/run", json=REQUEST).status_code in (400, 404, 405)
        mcp = build_multi_mcp(service)
        names = {tool.name for tool in asyncio.run(mcp.list_tools())}
        assert "run_command" not in names and "prepare_execution" not in names
        with pytest.raises(ToolError, match="invalid_argument"):
            asyncio.run(mcp.call_tool("run_command", REQUEST))
