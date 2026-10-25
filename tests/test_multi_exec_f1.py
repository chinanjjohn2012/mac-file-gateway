"""F1 production-first safety: real ingress + private-state witness + Git apply.

These checks never launch an Exec subprocess, signal a host PID/PGID, reset
quarantine, or mount an internal test-grant on public network adapters.
Authorized Git subprocesses run only in pytest disposable repositories.
"""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import threading
import time
from contextlib import contextmanager
from types import SimpleNamespace
import urllib.error
import urllib.request

import uvicorn

import pytest
from starlette.testclient import TestClient

from gateway.core import GatewayError
from gateway.http_multi import create_multi_app
from gateway.workspaces import ActiveRuntimeInventory, WorkspaceService
from gateway.workspaces_config import parse_workspace_config


_APPLY = {"workspace": "a", "cwd": "src",
          "argv": ["python", "hello.py"], "dry_run": False}
_HEADERS = {"Accept": "application/json, text/event-stream",
            "Content-Type": "application/json"}


def _previously_reviewed_physical_witness():
    """Reuse frozen B1-B1-A physical intent hooks; don't duplicate a weak oracle."""
    path = (Path(__file__).parent / "b1b1_contracts" /
            "contract_multi_exec_default_deny_b1b1.py")
    spec = importlib.util.spec_from_file_location("_f1_b1b1_frozen_witness", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module._IntentWitness, module._records, module._public_policy_is_sanitized


@pytest.fixture
def mixed(tmp_path):
    project = tmp_path / "projects"
    project.mkdir()
    a, b = project / "a", project / "b"
    a.mkdir()
    b.mkdir()
    (a / "src").mkdir()
    (b / "src").mkdir()
    (a / "src" / "hello.py").write_text("print('must-not-execute')\n")
    (b / "src" / "read.txt").write_text("file-read-only\n")
    subprocess.run(["git", "init", "-q"], cwd=project, check=True,
                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                   stderr=subprocess.PIPE)
    config = tmp_path / "config"
    config.mkdir(mode=0o700)
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    cfg = {"schema_version": 1,
           "server": {"exec": {"enabled": True}, "git": {"enabled": True}},
           "workspaces": {
               "a": {"root": str(a),
                     "exec": {"enabled": True, "paths": ["src"],
                              "runners": ["src=direct"]},
                     "write": {"enabled": True, "paths": ["src"]},
                     "git": {"allowed_commands": ["status"]}},
               "b": {"root": str(b)},
           }}
    svc = WorkspaceService(
        parse_workspace_config(cfg), config_dir=config,
        inventory=ActiveRuntimeInventory(paths=(runtime,)))
    try:
        yield svc, a, b, config
    finally:
        svc.close()


def _error_code(svc, workspace="a", dry_run=False):
    with pytest.raises(GatewayError) as exc:
        svc.invoke_exec(workspace, "src", ["python", "hello.py"],
                        dry_run=dry_run)
    return exc.value.code


def _mcp(client, method, params=None, identifier=2):
    response = client.post("/mcp", headers=_HEADERS,
                           json={"jsonrpc": "2.0", "id": identifier,
                                 "method": method, "params": params or {}})
    assert response.status_code == 200, response.text
    return response.json()


def test_f1_physical_no_prep_or_runner_and_proof_before_busy(mixed, monkeypatch):
    svc, a, _b, config = mixed
    assert svc._exec_state is not None
    assert svc._exec_state.durability_state == "healthy"
    assert svc.info()["exec_policy"]["completion_capability"] == "none"
    assert svc.info()["exec_policy"]["available"] is False
    assert svc.invoke_exec("a", "src", ["python", "hello.py"])["executed"] is False
    Witness, records, _ = _previously_reviewed_physical_witness()
    scene = SimpleNamespace(state=config / "exec-state")
    witness = Witness(scene.state)
    calls = []
    svc._exec_active.add("a")
    try:
        with monkeypatch.context() as patch:
            patch.setattr(svc.get("a").gateway, "run_command",
                          lambda *args, **kwargs: calls.append((args, kwargs)))
            witness.install(patch)
            before = records(scene)
            assert _error_code(svc) == "exec_cleanup_proof_required"
            assert calls == [] and witness.events == []
            assert records(scene) == before and witness._root_is_pinned()
    finally:
        svc._exec_active.discard("a")
    assert _error_code(svc, "b") == "exec_disabled"
    assert svc.invoke_exec("a", "src", ["python", "hello.py"])["dry_run"] is True


def test_f1_real_rest_sdk_mcp_and_status_policy(mixed, monkeypatch):
    pytest.importorskip("mcp")
    svc, a, _b, config = mixed
    app = create_multi_app(svc)
    Witness, records, public_policy = _previously_reviewed_physical_witness()
    scene = SimpleNamespace(state=config / "exec-state")
    with TestClient(app, base_url="http://127.0.0.1:8765") as client:
        info = client.get("/info").json()
        health = client.get("/health").json()
        assert info["exec_policy"] == health["exec_policy"]
        assert public_policy(info["exec_policy"])
        assert info["exec_policy"]["available"] is False
        assert info["exec_policy"]["completion_capability"] == "none"
        dry = client.post("/run", json={**_APPLY, "dry_run": True})
        assert dry.status_code == 200 and dry.json()["executed"] is False
        initialized = _mcp(client, "initialize", {
            "protocolVersion": "2025-11-25", "capabilities": {},
            "clientInfo": {"name": "f1-deny-only", "version": "1"}}, 1)
        assert "result" in initialized
        client.post("/mcp", headers=_HEADERS,
                    json={"jsonrpc": "2.0", "method": "notifications/initialized"})
        witness = Witness(scene.state)
        calls = []
        with monkeypatch.context() as patch:
            patch.setattr(svc.get("a").gateway, "run_command",
                          lambda *args, **kwargs: calls.append((args, kwargs)))
            witness.install(patch)
            before = records(scene)
            rest = client.post("/run", json=_APPLY)
            assert rest.status_code == 503, rest.text
            assert rest.json()["error"] == "exec_cleanup_proof_required"
            mcp = _mcp(client, "tools/call", {
                "name": "run_command", "arguments": _APPLY}, 3)
            tool_result = mcp["result"]
            assert tool_result.get("isError") is True, tool_result
            assert tool_result["structuredContent"]["error"] == "exec_cleanup_proof_required"
            for field in ("test_grant", "test_mode", "group_only_test_grant"):
                denied = client.post("/run", json={**_APPLY, field: True})
                assert denied.status_code == 400
                assert denied.json()["error"] == "invalid_argument"
            header = client.post("/run", json=_APPLY,
                                 headers={"X-Gateway-Test-Mode": "1"})
            assert header.status_code == 503
            assert calls == [] and witness.events == []
            assert records(scene) == before and witness._root_is_pinned()
    assert svc.info()["exec_policy"]["adapter_exposed"] is True


def test_f1_same_service_real_git_and_file_write_survive_exec_quarantine(mixed):
    svc, a, b, config = mixed
    assert svc.any_exec and svc.any_git and svc.any_write
    assert _error_code(svc) == "exec_cleanup_proof_required"
    # The same live service that will run Git must also reject the
    # production REST apply route, not just a separate test fixture.
    with TestClient(create_multi_app(svc, enable_mcp=False),
                    base_url="http://127.0.0.1:8765") as client:
        rest = client.post("/run", json=_APPLY)
        assert rest.status_code == 503
        assert rest.json()["error"] == "exec_cleanup_proof_required"
    first = svc.invoke_git("a", "status", dry_run=False)
    assert first["exit_code"] == 0 and first["execute_started"] is True
    write = svc.invoke("a", "create_file", "src/f1-legal.txt",
                       "legal\n", False)
    assert write["workspace"] == "a"
    assert (a / "src" / "f1-legal.txt").read_text() == "legal\n"
    with pytest.raises(GatewayError) as exc:
        svc.invoke_git("b", "status", dry_run=False)
    assert exc.value.code == "git_command_not_allowed"
    with pytest.raises(GatewayError) as exc:
        svc.invoke_git("a", "pull", dry_run=False)
    assert exc.value.code == "git_command_not_allowed"
    with pytest.raises(GatewayError) as exc:
        svc.invoke("b", "create_file", "src/illegal.txt", "bad", False)
    assert exc.value.code == "write_disabled"
    assert not (b / "src" / "illegal.txt").exists()

    store = svc._exec_state
    assert store is not None and store.durability_state == "healthy"
    st = a.stat()
    attempt = store.prepare("a", (st.st_dev, st.st_ino))
    store.mark_unknown(attempt)
    record = config / "exec-state" / ("r-" + attempt + ".json")
    original = record.read_bytes()
    assert _error_code(svc) == "exec_quarantined"
    assert svc.info()["exec_policy"]["durability_state"] == "quarantined"
    assert svc.info()["exec_policy"]["quarantined"] is True
    with TestClient(create_multi_app(svc, enable_mcp=False),
                    base_url="http://127.0.0.1:8765") as client:
        quarantined_rest = client.post("/run", json=_APPLY)
        assert quarantined_rest.status_code == 503
        assert quarantined_rest.json()["error"] == "exec_quarantined"
    second = svc.invoke_git("a", "status", dry_run=False)
    assert second["exit_code"] == 0 and second["execute_started"] is True
    assert svc.invoke("a", "create_file", "src/f1-quarantined.txt",
                      "still-legal\n", False)["workspace"] == "a"
    assert (a / "src" / "f1-quarantined.txt").read_text() == "still-legal\n"
    with pytest.raises(GatewayError) as exc:
        svc.invoke("b", "create_file", "src/illegal-after.txt", "bad", False)
    assert exc.value.code == "write_disabled"
    assert record.read_bytes() == original
    assert svc.info()["exec_policy"]["quarantined"] is True



def _f1_tcp_request(port, path, body=None, *, headers=None):
    """Genuine loopback HTTP; no TestClient, proxy or mock ASGI transport."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    payload = None if body is None else json.dumps(body).encode("utf-8")
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}", data=payload,
        headers={**_HEADERS, **(headers or {})},
    )
    try:
        with opener.open(request, timeout=5) as reply:
            data = reply.read()
            return reply.status, json.loads(data) if data else None
    except urllib.error.HTTPError as exc:
        data = exc.read()
        return exc.code, json.loads(data) if data else None


def _f1_tcp_rpc(port, method, params, ident):
    status, body = _f1_tcp_request(port, "/mcp", {
        "jsonrpc": "2.0", "id": ident, "method": method, "params": params})
    assert status == 200 and body["id"] == ident, (method, status, body)
    assert "result" in body, (method, body)
    return body["result"]


@contextmanager
def _f1_real_tcp_listener(service):
    """One ephemeral, prebound loopback socket served by real Uvicorn.

    No unbounded or public interface, no user configuration, no Tunnel, no
    real Exec subprocess. The listener is fully stopped before releasing
    any pinned Workspace root or Exec-state ownership.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server = None
    worker = None
    errors = []
    try:
        sock.bind(("127.0.0.1", 0))
        sock.listen(32)
        sock.setblocking(False)
        host, port = sock.getsockname()
        assert host == "127.0.0.1" and port > 0
        app = create_multi_app(service, port=port, enable_mcp=True)
        server = uvicorn.Server(uvicorn.Config(
            app, host="127.0.0.1", port=port, lifespan="on",
            log_level="error", access_log=False, proxy_headers=False,
            server_header=False, date_header=False,
        ))

        def serve():
            try:
                server.run(sockets=[sock])
            except BaseException as exc:
                errors.append(exc)

        worker = threading.Thread(
            target=serve, name="f1-ephemeral-tcp-deny-only", daemon=True)
        worker.start()
        ready = False
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if errors or not worker.is_alive():
                raise AssertionError("F1_REAL_TCP_LISTENER_EXITED: " + repr(errors))
            if server.started:
                try:
                    status, health = _f1_tcp_request(port, "/health")
                    if status == 200:
                        assert health["mode"] == "multi"
                        assert health["mcp_enabled"] is True
                        ready = True
                        break
                except (OSError, urllib.error.URLError):
                    pass
            time.sleep(0.04)
        assert ready, "F1_REAL_TCP_LISTENER_NOT_READY"
        yield port
    finally:
        if server is not None:
            server.should_exit = True
        # Uvicorn's own asyncio shutdown must unregister the listening FD
        # BEFORE it is physically closed; otherwise selector._remove_reader
        # observes fileno() == -1 and raises despite correct test behavior.
        if worker is not None:
            worker.join(timeout=8)
            if worker.is_alive():
                # A failed graceful shutdown cannot keep accepting work.
                # Revoke socket admission and give the thread a final bound
                # opportunity to exit before the fixture releases state FDs.
                sock.close()
                worker.join(timeout=1)
            else:
                sock.close()
            assert not worker.is_alive(), "F1_REAL_TCP_LISTENER_DID_NOT_STOP"
        else:
            sock.close()
        assert not errors, "F1_REAL_TCP_LISTENER_FAILED: " + repr(errors)


def test_f1_real_tcp_rest_mcp_proof_and_unhealthy_states(mixed, monkeypatch):
    """P2-01/P2-02: real loopback TCP and official SDK tools/call.

    Real private-FS witness only covers the request portion, NOT the
    deliberate disposable PREPARED/UNKNOWN setup. Exec spawning is blocked
    inside the request witness; independent Git uses its own real subprocess.
    """
    svc, a, b, config = mixed
    assert svc._exec_state is not None
    assert svc._exec_state.durability_state == "healthy"
    state_root = config / "exec-state"
    Witness, records, public_policy = _previously_reviewed_physical_witness()
    scene = SimpleNamespace(state=state_root)

    with _f1_real_tcp_listener(svc) as port:
        # Both opt-ins are active, but no full-descendant cleanup proof
        # exists. Real TCP must reach this exact instance and no other.
        status, info = _f1_tcp_request(port, "/info")
        assert status == 200
        status, health = _f1_tcp_request(port, "/health")
        assert status == 200
        assert info["exec_policy"] == health["exec_policy"]
        assert public_policy(info["exec_policy"])
        assert info["exec_policy"]["enabled"] is True
        assert info["exec_policy"]["adapter_exposed"] is True
        assert info["exec_policy"]["available"] is False
        assert info["exec_policy"]["completion_capability"] == "none"
        public_json = json.dumps(info) + json.dumps(health)
        assert str(a) not in public_json and str(config) not in public_json
        status, preview = _f1_tcp_request(
            port, "/run", {**_APPLY, "dry_run": True})
        assert status == 200 and preview["dry_run"] is True
        assert preview["executed"] is False and preview["workspace"] == "a"
        init = _f1_tcp_rpc(port, "initialize", {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "f1-real-tcp-test", "version": "1"},
        }, 1)
        assert init["protocolVersion"] == "2025-11-25"
        status, _ = _f1_tcp_request(port, "/mcp", {
            "jsonrpc": "2.0", "method": "notifications/initialized"})
        assert status in (200, 202)
        listed = _f1_tcp_rpc(port, "tools/list", {}, 2)
        assert "run_command" in {item["name"] for item in listed["tools"]}
        mcp_preview = _f1_tcp_rpc(port, "tools/call", {
            "name": "run_command",
            "arguments": {**_APPLY, "dry_run": True}}, 3)
        assert mcp_preview["structuredContent"]["executed"] is False

        # Guard the network-only denial window with the frozen physical
        # intent oracle, plus an explicit OS child-spawn trap.
        witness = Witness(state_root)
        runner_calls = []
        popen_calls = []
        with monkeypatch.context() as patch:
            original_popen = subprocess.Popen

            class _NoHostPopen(original_popen):
                def __new__(cls, *args, **kwargs):
                    popen_calls.append("Popen")
                    raise AssertionError("F1_TCP_UNAUTHORIZED_EXEC_SPAWN")

            def impossible_runner(*args, **kwargs):
                runner_calls.append("run_command")
                raise AssertionError("F1_TCP_UNAUTHORIZED_RUNNER")

            patch.setattr(subprocess, "Popen", _NoHostPopen)
            patch.setattr(svc.get("a").gateway, "run_command", impossible_runner)
            witness.install(patch)
            before = records(scene)
            status, rest = _f1_tcp_request(port, "/run", _APPLY)
            assert status == 503 and rest["error"] == "exec_cleanup_proof_required"
            proof = _f1_tcp_rpc(port, "tools/call", {
                "name": "run_command", "arguments": _APPLY}, 4)
            assert proof.get("isError") is True
            assert proof["structuredContent"]["error"] == "exec_cleanup_proof_required"
            disabled = _f1_tcp_rpc(port, "tools/call", {
                "name": "run_command", "arguments": {**_APPLY, "workspace": "b"}}, 5)
            assert disabled.get("isError") is True
            assert disabled["structuredContent"]["error"] == "exec_disabled"
            status, rest_disabled = _f1_tcp_request(
                port, "/run", {**_APPLY, "workspace": "b"})
            assert status == 403 and rest_disabled["error"] == "exec_disabled"
            invalid = _f1_tcp_rpc(port, "tools/call", {
                "name": "run_command", "arguments": {**_APPLY, "dry_run": "false"}}, 6)
            assert invalid.get("isError") is True
            assert invalid["structuredContent"]["error"] == "invalid_argument"
            status, spoof = _f1_tcp_request(
                port, "/run", _APPLY, headers={"X-Gateway-Test-Mode": "1"})
            assert status == 503 and spoof["error"] == "exec_cleanup_proof_required"
            assert runner_calls == [] and popen_calls == []
            assert witness.events == [] and witness._root_is_pinned()
            assert records(scene) == before

        # A real, independent Git subprocess is legal in this SAME service.
        git_healthy = svc.invoke_git("a", "status", dry_run=False)
        assert git_healthy["exit_code"] == 0
        assert git_healthy["execute_started"] is True

        # Seed UNKNOWN only inside disposable private state; never through
        # a client request, never clear or remove this unresolved record.
        store = svc._exec_state
        st = a.stat()
        attempt = store.prepare("a", (st.st_dev, st.st_ino))
        store.mark_unknown(attempt)
        record = state_root / ("r-" + attempt + ".json")
        original_unknown = record.read_bytes()
        assert svc.info()["exec_policy"]["quarantined"] is True
        quarantine_witness = Witness(state_root)
        with monkeypatch.context() as patch:
            patch.setattr(svc.get("a").gateway, "run_command", impossible_runner)
            quarantine_witness.install(patch)
            before = records(scene)
            status, quarantined = _f1_tcp_request(port, "/run", _APPLY)
            assert status == 503 and quarantined["error"] == "exec_quarantined"
            result = _f1_tcp_rpc(port, "tools/call", {
                "name": "run_command", "arguments": _APPLY}, 7)
            assert result.get("isError") is True
            assert result["structuredContent"]["error"] == "exec_quarantined"
            status, status_info = _f1_tcp_request(port, "/health")
            assert status == 200 and status_info["exec_policy"]["quarantined"] is True
            assert quarantine_witness.events == []
            assert quarantine_witness._root_is_pinned()
            assert records(scene) == before
        assert record.read_bytes() == original_unknown
        git_quarantined = svc.invoke_git("a", "status", dry_run=False)
        assert git_quarantined["exit_code"] == 0
        assert git_quarantined["execute_started"] is True

        # Deliberately lose the disposable state owner FD; no automatic
        # quarantine reset and no misleading proof-required status.
        store.close()
        assert store.durability_state == "unavailable"
        status, unavailable = _f1_tcp_request(port, "/run", _APPLY)
        assert status == 503 and unavailable["error"] == "exec_state_unavailable"
        result = _f1_tcp_rpc(port, "tools/call", {
            "name": "run_command", "arguments": _APPLY}, 8)
        assert result.get("isError") is True
        assert result["structuredContent"]["error"] == "exec_state_unavailable"
        priority = _f1_tcp_rpc(port, "tools/call", {
            "name": "run_command", "arguments": {**_APPLY, "workspace": "b"}}, 9)
        assert priority.get("isError") is True
        assert priority["structuredContent"]["error"] == "exec_disabled"
        assert record.read_bytes() == original_unknown
