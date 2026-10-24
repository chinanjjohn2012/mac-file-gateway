"""B1-B1-B/R0 expected-RED bridge contract. NO subprocesses or group signals.

Existing genuine subprocess/REST/MCP/slot/cancel tests are untouched.
The private test-only qualification is not an ordinary network credential.
"""
from __future__ import annotations

import ast
import copy
import importlib
import importlib.util
import inspect
import json
import os
from pathlib import Path
import pickle
import signal
import subprocess
import threading
from types import ModuleType, SimpleNamespace
import urllib.error
import urllib.request

import pytest
from starlette.testclient import TestClient
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Mount

from gateway.core import GatewayError
from gateway._exec_test_transport import create_private_bound_transport
from gateway.http_multi import create_multi_app
from gateway.multi_cli import run_multi
from gateway.workspaces import WorkspaceService

HEADERS = {"Content-Type": "application/json",
           "Accept": "application/json, text/event-stream"}
APPLY = {"workspace": "a", "cwd": "src",
         "argv": ["python", "hello.py"], "dry_run": False}


class _NoHostActions:
    def __init__(self):
        self.calls = []

    def deny(self, action):
        def denied(*args, **kwargs):
            self.calls.append(action)
            raise AssertionError("B1B1B_FORBIDDEN_HOST_ACTION:" + action)
        return denied

    def install(self, patch):
        original_popen = subprocess.Popen
        guard = self

        class _NeverPopen(original_popen):
            def __new__(cls, *args, **kwargs):
                return guard.deny("Popen")(*args, **kwargs)

        patch.setattr(subprocess, "Popen", _NeverPopen)
        for attr in ("kill", "killpg", "fork", "forkpty", "posix_spawn",
                     "posix_spawnp", "system", "execv", "execve",
                     "spawnv", "spawnve"):
            if hasattr(os, attr):
                patch.setattr(os, attr, self.deny("os." + attr))
        for attr in ("pthread_kill", "raise_signal"):
            if hasattr(signal, attr):
                patch.setattr(signal, attr, self.deny("signal." + attr))


@pytest.fixture(autouse=True)
def _no_host_process_or_signal(monkeypatch):
    guard = _NoHostActions()
    guard.install(monkeypatch)
    yield
    assert not guard.calls, guard.calls


def _wire(port, path, payload=None, headers=None):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=None if payload is None else json.dumps(payload).encode("utf-8"),
        headers={**HEADERS, **(headers or {})})
    try:
        with opener.open(request, timeout=4) as response:
            raw = response.read()
            return response.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        return exc.code, json.loads(raw) if raw else None


def _records(env):
    return tuple(sorted(
        (p.name, p.lstat().st_mode, p.lstat().st_nlink,
         p.read_bytes() if p.is_file() and not p.is_symlink() else None)
        for p in env.fixture.state_path.iterdir()))


def _physical_oracle(env):
    """Reuse exactly the fixed, separately reviewed B1-B1-A physical witness.

    The original source, SHA and 31 GREEN oracle selfchecks are frozen by CI.
    New bridge tests must not fall back to a snapshot-only no-intent claim.
    """
    fixed = (Path(__file__).resolve().parents[1] / "b1b1_contracts"
             / "contract_multi_exec_default_deny_b1b1.py")
    spec = importlib.util.spec_from_file_location(
        "_b1b1a_reviewed_oracle", fixed)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    scene = SimpleNamespace(state=env.fixture.state_path)
    return scene, module._IntentWitness(scene.state), (
        module._records), module._never_started


def _runner_spy(env, monkeypatch):
    calls = []

    def fake(*args, **kwargs):
        calls.append((args, kwargs))
        return {"executed": True, "exit_code": 0, "timed_out": False,
                "stdout": "UNAUTHORIZED", "stderr": "", "dry_run": False}

    monkeypatch.setattr(env.service.get("a").gateway, "run_command", fake)
    return calls


def _require(ok, marker, facts):
    if not ok:
        pytest.fail("B1B1B_RED_" + marker + ": " + repr(facts)[:420],
                    pytrace=False)


_BRIDGE_MODULE = "gateway._exec_test_bridge"
_FACTORY_NAME = "create_private_exec_acceptance_bridge"
_MISSING = object()


def _parameter_free(factory):
    """No caller root/state/grant/listener or **kwargs, even optional ones."""
    try:
        return callable(factory) and not inspect.signature(factory).parameters
    except (TypeError, ValueError):
        return False


def _load_factory(marker):
    try:
        module = importlib.import_module(_BRIDGE_MODULE)
    except ModuleNotFoundError as exc:
        # Never disguise a broken nested dependency as an expected RED.
        if exc.name != _BRIDGE_MODULE:
            raise
        _require(False, marker, {"missing_module": exc.name})
        raise AssertionError("unreachable")
    # vars avoids module.__getattr__ converting an initialization failure
    # to an expected missing attribute. Only an actually ABSENT member is RED.
    factory = vars(module).get(_FACTORY_NAME, _MISSING)
    if factory is _MISSING:
        _require(False, marker, {"missing_factory": _FACTORY_NAME})
        raise AssertionError("unreachable")
    return factory


def _bridge(marker):
    factory = _load_factory(marker)
    _require(_parameter_free(factory), marker,
             {"factory_signature": str(inspect.signature(factory))})
    return factory()


def _public_app_graph_contains(root, target):
    """Detect direct/mounted and common wrapped ASGI routing to trusted app.

    Runtime path canaries and private nonpreview denials are ALSO necessary;
    object inequality alone is never a proof of network isolation.
    """
    queue = [root]
    visited = set()
    while queue:
        current = queue.pop()
        if current is target:
            return True
        if id(current) in visited:
            continue
        visited.add(id(current))
        if isinstance(current, (tuple, list, set)):
            queue.extend(current)
            continue
        for field in ("app", "_app", "application", "router", "routes",
                      "_routes", "endpoint"):
            try:
                next_item = getattr(current, field, None)
            except (AttributeError, RuntimeError):
                continue
            if next_item is not None and next_item is not current:
                queue.append(next_item)
    return False


def _assert_bridge_resources_pinned(env):
    service, store = env.service, env.service._exec_state
    assert store is not None
    assert not service._closing and not service._closed
    assert store.durability_state == "healthy"
    os.fstat(store._fd)
    os.fstat(store._lock_fd)
    os.fstat(service.get("a").pinned_root.fd)


def _held_real_preview(env, monkeypatch):
    """Hold an actual loopback TCP request in the real sync preview Worker."""
    gateway = env.service.get("a").gateway
    real = gateway.run_command
    entered, release = threading.Event(), threading.Event()
    results = []
    def held(cwd, argv, timeout_seconds=60, dry_run=True):
        if not dry_run:
            raise AssertionError("B1B1B_HOLD_PREVIEW_CANNOT_EXECUTE")
        entered.set()
        if not release.wait(7):
            raise AssertionError("B1B1B_HELD_HTTP_NOT_RELEASED")
        return real(cwd, argv, timeout_seconds, dry_run)
    monkeypatch.setattr(gateway, "run_command", held)
    def caller():
        try:
            results.append(_wire(env.port, "/run", {
                **APPLY, "dry_run": True}))
        except BaseException as exc:
            results.append(exc)
    thread = threading.Thread(target=caller, daemon=True)
    thread.start()
    if not entered.wait(3):
        release.set()
        thread.join(timeout=5)
        raise AssertionError("B1B1B_REAL_HTTP_PREVIEW_NOT_ENTERED")
    assert env.listener._thread.is_alive()
    return release, thread, results


def test_b1b1b_private_direct_untrusted_apply_denied_before_runner(monkeypatch):
    with create_private_bound_transport() as env:
        calls = _runner_spy(env, monkeypatch)
        scene, witness, snapshot, no_intent = _physical_oracle(env)
        with monkeypatch.context() as patch:
            witness.install(patch)
            before = snapshot(scene)
            try:
                env.service.invoke_exec(
                    "a", "src", ["python", "hello.py"], dry_run=False)
                code = "returned"
            except GatewayError as exc:
                code = exc.code
            clean = no_intent(scene, witness, before, calls)
        _require(code == "exec_cleanup_proof_required" and clean,
                 "PRIVATE_DIRECT_DENY",
                 {"code": code, "runner_calls": len(calls),
                  "physical_events": witness.events})


@pytest.mark.parametrize("metadata", ["plain", "forged"])
def test_b1b1b_private_wire_rest_apply_requires_nonclient_proof(
        monkeypatch, metadata):
    with create_private_bound_transport() as env:
        calls = _runner_spy(env, monkeypatch)
        scene, witness, snapshot, no_intent = _physical_oracle(env)
        headers = ({"x-gateway-test-mode": "true"}
                   if metadata == "forged" else {})
        with monkeypatch.context() as patch:
            witness.install(patch)
            before = snapshot(scene)
            status, data = _wire(env.port, "/run", APPLY, headers)
            clean = no_intent(scene, witness, before, calls)
        _require(status == 503
                 and data == {"error": "exec_cleanup_proof_required"}
                 and clean, "PRIVATE_WIRE_REST_DENY",
                 {"metadata": metadata, "status": status,
                  "response": repr(data)[:130],
                  "calls": len(calls), "events": witness.events})


@pytest.mark.parametrize("metadata", ["plain", "forged"])
def test_b1b1b_private_wire_mcp_apply_requires_nonclient_proof(
        monkeypatch, metadata):
    with create_private_bound_transport() as env:
        calls = _runner_spy(env, monkeypatch)
        scene, witness, snapshot, no_intent = _physical_oracle(env)
        headers = ({"x-internal-group-retirement-grant": "true"}
                   if metadata == "forged" else {})
        with monkeypatch.context() as patch:
            witness.install(patch)
            before = snapshot(scene)
            status, init = _wire(env.port, "/mcp", {
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2025-11-25",
                           "capabilities": {},
                           "clientInfo": {"name": "b1b1b-red",
                                          "version": "1"}}}, headers)
            assert status == 200 and "result" in init
            _wire(env.port, "/mcp", {
                "jsonrpc": "2.0", "method": "notifications/initialized"},
                headers)
            status, data = _wire(env.port, "/mcp", {
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "run_command", "arguments": APPLY}},
                headers)
            clean = no_intent(scene, witness, before, calls)
        result = data.get("result", {}) if isinstance(data, dict) else {}
        _require(status == 200 and result.get("isError") is True
                 and (result.get("structuredContent") or {}).get("error")
                 == "exec_cleanup_proof_required" and clean,
                 "PRIVATE_WIRE_MCP_DENY",
                 {"metadata": metadata, "status": status,
                  "result": repr(result)[:160], "calls": len(calls),
                  "events": witness.events})


def test_b1b1b_bridge_factory_rejects_caller_selected_scope():
    """Enforce Python zero-argument signature AND actual argument rejection."""
    factory = _load_factory("BRIDGE_FACTORY_NO_ARGS")
    _require(_parameter_free(factory), "BRIDGE_FACTORY_NO_ARGS",
             {"signature": repr(inspect.signature(factory))})
    sentinel = object()  # never a real user root, token, or file path
    unexpected = []
    for args, kwargs in (
            ((sentinel,), {}),
            ((), {"root": sentinel}),
            ((), {"workspace": "foreign"}),
            ((), {"state_root": sentinel}),
            ((), {"grant": sentinel}),
            ((), {"transport": sentinel}),
            ((), {"test_mode": True})):
        try:
            factory(*args, **kwargs)
        except TypeError:
            continue
        unexpected.append((args, kwargs))
    _require(not unexpected, "BRIDGE_FACTORY_NO_ARGS",
             {"accepted_args": repr(unexpected)[:140]})


def test_b1b1b_trusted_bridge_factory_is_live_and_instance_bound():
    with _bridge("TRUSTED_BRIDGE_FACTORY") as env:
        allowed = env.grant.qualifies_transport(
            env.service, "a", transport=env.listener)
        denied = env.grant.qualifies_transport(
            env.service, "b", transport=env.listener)
        _require(allowed and not denied and env.host == "127.0.0.1"
                 and env.listener._proves_live(), "TRUSTED_BRIDGE_FACTORY",
                 {"allowed": allowed, "denied": denied})


def test_b1b1b_bridge_wire_apply_denies_every_untrusted_client(monkeypatch):
    """A new bridge itself must not mount its trusted ASGI on raw TCP."""
    with _bridge("BRIDGE_WIRE_DENY") as env:
        calls = _runner_spy(env, monkeypatch)
        scene, witness, snapshot, no_intent = _physical_oracle(env)
        for headers in ({}, {"x-gateway-test-mode": "true"}):
            with monkeypatch.context() as patch:
                witness.install(patch)
                before = snapshot(scene)
                status, body = _wire(env.port, "/run", APPLY, headers)
                clean = no_intent(scene, witness, before, calls)
            _require(status == 503
                     and body == {"error": "exec_cleanup_proof_required"}
                     and clean, "BRIDGE_WIRE_DENY",
                     {"headers": tuple(headers), "status": status,
                      "calls": len(calls), "events": witness.events})


@pytest.mark.parametrize("metadata", ["plain", "forged"])
def test_b1b1b_bridge_real_wire_mcp_nonpreview_denied(monkeypatch, metadata):
    """New bridge's own REAL SDK MCP listener, never only the B1-B0 one."""
    with _bridge("BRIDGE_WIRE_MCP_DENY") as env:
        calls = _runner_spy(env, monkeypatch)
        scene, witness, snapshot, no_intent = _physical_oracle(env)
        headers = ({"x-internal-group-retirement-grant": "true"}
                   if metadata == "forged" else {})
        with monkeypatch.context() as patch:
            witness.install(patch)
            before = snapshot(scene)
            status, init = _wire(env.port, "/mcp", {
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2025-11-25",
                           "capabilities": {},
                           "clientInfo": {"name": "bridge-own-wire",
                                          "version": "1"}}}, headers)
            assert status == 200 and "result" in init
            _wire(env.port, "/mcp", {
                "jsonrpc": "2.0",
                "method": "notifications/initialized"}, headers)
            status, result_body = _wire(env.port, "/mcp", {
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "run_command",
                           "arguments": APPLY}}, headers)
            clean = no_intent(scene, witness, before, calls)
        reply = (result_body.get("result", {})
                 if isinstance(result_body, dict) else {})
        _require(status == 200 and reply.get("isError") is True
                 and (reply.get("structuredContent") or {}).get("error")
                 == "exec_cleanup_proof_required" and clean,
                 "BRIDGE_WIRE_MCP_DENY",
                 {"metadata": metadata, "status": status,
                  "reply": repr(reply)[:160],
                  "calls": len(calls), "events": witness.events})


def test_b1b1b_bridge_foreign_instance_never_borrows_grant():
    with _bridge("BRIDGE_FOREIGN_INSTANCE") as owner:
        with _bridge("BRIDGE_FOREIGN_INSTANCE") as other:
            assert owner.grant.qualifies_transport(
                owner.service, "a", transport=owner.listener)
            wrong_service = owner.grant.qualifies_transport(
                other.service, "a", transport=owner.listener)
            wrong_listener = owner.grant.qualifies_transport(
                owner.service, "a", transport=other.listener)
            _require(not wrong_service and not wrong_listener,
                     "BRIDGE_FOREIGN_INSTANCE",
                     {"wrong_service": wrong_service,
                      "wrong_listener": wrong_listener})


def test_b1b1b_trusted_inprocess_asgi_preview_is_not_network_auth():
    with _bridge("TRUSTED_ASGI_PREVIEW") as env:
        trusted = env.trusted_asgi_app
        _require(trusted is not None and
                 not _public_app_graph_contains(
                     env.listener._server.config.app, trusted),
                 "TRUSTED_ASGI_PREVIEW",
                 {"trusted_present": trusted is not None,
                  "trusted_in_public_routing": (
                      _public_app_graph_contains(
                          env.listener._server.config.app, trusted)
                      if trusted is not None else None)})
        with TestClient(trusted,
                        base_url="http://127.0.0.1:8765") as client:
            response = client.post("/run", json={
                **APPLY, "dry_run": True})
        status, wire = _wire(env.port, "/run", {
            **APPLY, "dry_run": True})
        _require(response.status_code == 200
                 and response.json().get("executed") is False
                 and status == 200 and wire.get("executed") is False,
                 "TRUSTED_ASGI_PREVIEW",
                 {"internal": response.status_code, "wire": status})


def test_b1b1b_trusted_inprocess_route_canary_is_not_network_reachable(
        monkeypatch):
    """Dynamic canary observes mounts/wrappers, not just different app IDs."""
    with _bridge("BRIDGE_TRUSTED_ROUTE_CANARY") as env:
        trusted = env.trusted_asgi_app
        _require(trusted is not None and
                 not _public_app_graph_contains(
                     env.listener._server.config.app, trusted),
                 "BRIDGE_TRUSTED_ROUTE_CANARY",
                 {"trusted_in_public_routing": True})
        router = getattr(trusted, "router", None)
        _require(router is not None and
                 callable(getattr(router, "add_route", None)),
                 "BRIDGE_TRUSTED_ROUTE_CANARY",
                 {"trusted_router_missing": router is None})
        calls = []
        canary = "/__b1b1b_private_canary_8fc3bd__"
        async def handle(request):
            calls.append("private")
            return JSONResponse({"b1b1b": "TRUSTED_ONLY"})
        router.add_route(canary, handle, methods=["GET"])
        with TestClient(trusted,
                        base_url="http://127.0.0.1:8765") as client:
            local = client.get(canary)
        _require(local.status_code == 200
                 and local.json() == {"b1b1b": "TRUSTED_ONLY"}
                 and calls == ["private"],
                 "BRIDGE_TRUSTED_ROUTE_CANARY",
                 {"local": local.status_code, "calls": calls})
        calls.clear()
        for path in (canary, "/internal" + canary,
                     "/trusted" + canary, "/__test__" + canary):
            status, data = _wire(env.port, path)
            _require(status in (404, 405) and not calls,
                     "BRIDGE_TRUSTED_ROUTE_CANARY",
                     {"network_path": path, "status": status,
                      "canary_calls": calls})
        runner = _runner_spy(env, monkeypatch)
        scene, witness, snapshot, no_intent = _physical_oracle(env)
        for path in ("/internal/run", "/trusted/run",
                     "/__test__/run", "/private/run"):
            with monkeypatch.context() as patch:
                witness.install(patch)
                before = snapshot(scene)
                status, _ = _wire(env.port, path, APPLY,
                                  {"x-gateway-test-mode": "true"})
                clean = no_intent(scene, witness, before, runner)
            _require(status in (404, 405) and clean and not calls,
                     "BRIDGE_TRUSTED_ROUTE_CANARY",
                     {"network_path": path, "status": status,
                      "events": witness.events, "runner": len(runner)})
        _require(not _public_app_graph_contains(
                     env.listener._server.config.app, trusted),
                 "BRIDGE_TRUSTED_ROUTE_CANARY",
                 {"graph_mount_detected": True})


def test_b1b1b_bridge_close_revokes_one_way():
    env = _bridge("BRIDGE_CLOSE_REVOKE")
    grant, service, listener = env.grant, env.service, env.listener
    try:
        assert grant.qualifies_transport(service, "a", transport=listener)
    finally:
        env.close()
    _require(not grant.qualifies_transport(
                 service, "a", transport=listener)
             and not listener._proves_live(), "BRIDGE_CLOSE_REVOKE",
             {"listener_live": listener._proves_live()})


@pytest.mark.parametrize("fault", ["join_exception", "join_returns_alive"])
def test_b1b1b_bridge_close_preserves_real_inflight_ownership_on_fault(
        monkeypatch, fault):
    """Live HTTP Worker, real Uvicorn thread, injected join ONLY (no fake is_alive)."""
    env = _bridge("BRIDGE_CLOSE_OWNER_RETAIN")
    release = caller = closer = None
    close_done = threading.Event()
    close_errors = []
    try:
        grant = env.grant
        service = env.service
        assert grant.qualifies_transport(service, "a", transport=env.listener)
        release, caller, _ = _held_real_preview(env, monkeypatch)
        assert env.listener._thread.is_alive()

        def join_fault(timeout):
            assert isinstance(timeout, (int, float)) and 0 < timeout <= 7
            assert env.listener._thread.is_alive()
            if fault == "join_exception":
                raise TimeoutError("B1B1B_INJECTED_JOIN_EXCEPTION")
            return None  # no-op join while the REAL listener remains live

        def attempt_close():
            try:
                env.close()
            except BaseException as exc:
                close_errors.append(exc)
            finally:
                close_done.set()

        with monkeypatch.context() as patch:
            patch.setattr(env.listener._thread, "join", join_fault)
            closer = threading.Thread(target=attempt_close, daemon=True)
            closer.start()
            assert close_done.wait(3), (
                "Bridge attempted to close pinned service under an inflight "
                "TCP Listener instead of returning bounded close failure")
            assert len(close_errors) == 1
            if fault == "join_exception":
                assert isinstance(close_errors[0], TimeoutError)
                assert "B1B1B_INJECTED_JOIN_EXCEPTION" in str(close_errors[0])
            else:
                assert isinstance(close_errors[0], RuntimeError)
                assert "did not shut down" in str(close_errors[0])
            assert env.listener._thread.is_alive()
            assert env.listener._socket.fileno() == -1
            assert not grant.qualifies_transport(
                service, "a", transport=env.listener)
            _assert_bridge_resources_pinned(env)
    finally:
        if release is not None:
            release.set()
        if caller is not None:
            caller.join(timeout=5)
        if closer is not None:
            closer.join(timeout=5)
        env.close()  # bounded retry only after real request/drain completed
    assert not env.listener._thread.is_alive()
    assert service._closed


def test_b1b1b_guard_real_listener_loopback_preview_without_execution():
    with create_private_bound_transport() as env:
        before = _records(env)
        assert env.listener._proves_live()
        assert env.listener._socket.getsockname() == ("127.0.0.1", env.port)
        status, data = _wire(env.port, "/run", {
            "workspace": "a", "cwd": "src", "argv": ["python", "hello.py"]})
        assert status == 200 and data["dry_run"] is True
        assert data["executed"] is False and data["workspace"] == "a"
        assert _records(env) == before


def test_b1b1b_guard_foreign_listener_cannot_transfer_qualification():
    with create_private_bound_transport() as left:
        with create_private_bound_transport() as right:
            assert left.grant.qualifies_transport(
                left.service, "a", transport=left.listener)
            assert not left.grant.qualifies_transport(
                left.service, "a", transport=right.listener)
            assert not right.grant.qualifies_transport(
                right.service, "a", transport=left.listener)


@pytest.mark.parametrize("field", ["test_mode", "group_only_test_grant"])
def test_b1b1b_guard_request_fields_cannot_set_internal_proof(
        monkeypatch, field):
    with create_private_bound_transport() as env:
        calls = _runner_spy(env, monkeypatch)
        before = _records(env)
        status, data = _wire(env.port, "/run", {**APPLY, field: True})
        assert status == 400 and data.get("error") == "invalid_argument"
        assert not calls and _records(env) == before


def test_b1b1b_guard_nested_import_or_initialization_error_is_not_expected_red(
        monkeypatch):
    """A missing *dependency* is NEVER legitimate missing-bridge RED."""
    for failure in (
            ModuleNotFoundError(
                "synthetic missing internal dependency",
                name="gateway._missing_internal_dependency"),
            AttributeError("synthetic initializer failure")):
        with monkeypatch.context() as patch:
            def fail_import(name):
                assert name == _BRIDGE_MODULE
                raise failure
            patch.setattr(importlib, "import_module", fail_import)
            with pytest.raises(type(failure)) as info:
                _bridge("TRUSTED_BRIDGE_FACTORY")
            assert str(info.value) == str(failure)
            assert "B1B1B_RED_" not in str(info.value)
    # A present module that simply lacks its factory is different.
    module = ModuleType(_BRIDGE_MODULE)
    with monkeypatch.context() as patch:
        patch.setattr(importlib, "import_module", lambda n: module)
        with pytest.raises(BaseException) as failure:
            _bridge("TRUSTED_BRIDGE_FACTORY")
        assert "B1B1B_RED_TRUSTED_BRIDGE_FACTORY" in str(failure.value)
        assert "missing_factory" in str(failure.value)


def test_b1b1b_guard_factory_signature_rejects_optional_untrusted_scope():
    """Synthetic unsafe callable signatures must never qualify."""
    def safe():
        return None
    def optional(*, root_override=None):
        return None
    def variadic(*args, **kwargs):
        return None
    def positional(root):
        return None
    assert _parameter_free(safe)
    for candidate in (optional, variadic, positional):
        assert not _parameter_free(candidate)


def test_b1b1b_guard_network_mount_or_wrapper_graph_is_detectable():
    """Mutation selfcheck: known Starlette Mount + outer wrapper is detected."""
    trusted = Starlette()
    nested = Starlette(routes=[
        Mount("/private", app=trusted)])
    class Wrapped:
        def __init__(self, app):
            self.app = app
    assert _public_app_graph_contains(trusted, trusted)
    assert _public_app_graph_contains(Wrapped(nested), trusted)
    assert not _public_app_graph_contains(Starlette(), trusted)


def test_b1b1b_guard_historical_real_subprocess_tests_are_present():
    source = (Path(__file__).resolve().parents[1]
              / "test_multi_exec_product.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    names = {x.name for x in tree.body
             if isinstance(x, (ast.FunctionDef, ast.AsyncFunctionDef))}
    required = {
        "test_exec_preview_and_real_execution_are_workspace_scoped",
        "test_rest_explicit_routing_and_types",
        "test_worker_lease_blocks_same_workspace_and_close_waits",
        "test_mcp_registry_and_grants",
        "test_global_four_slots_reject_fifth_until_one_releases",
        "test_asgi_rest_disconnect_keeps_real_worker_until_exit",
        "test_cancelled_mcp_tool_waiter_does_not_release_sync_worker",
    }
    assert required <= names
    assert source.count("dry_run=False") >= 5
    assert "hold.py" in source
    assert "pytest.mark.skip" not in source


def test_b1b1b_guard_normal_product_has_no_private_bridge_factory_import():
    assert "_exec_test_bridge" not in WorkspaceService.__init__.__code__.co_names
    assert "_exec_test_bridge" not in run_multi.__code__.co_names
    assert "_exec_test_bridge" not in create_multi_app.__code__.co_names


def test_b1b1b_guard_existing_test_grant_not_serializable_or_reusable():
    with create_private_bound_transport() as env:
        grant, service, listener = env.grant, env.service, env.listener
        assert grant.qualifies_transport(service, "a", transport=listener)
        with pytest.raises(TypeError):
            pickle.dumps(grant)
        with pytest.raises(TypeError):
            copy.copy(grant)
        assert "TestOnlyGroupRetirementGrant" not in json.dumps(
            env.service.info())
    assert not grant.qualifies_transport(
        service, "a", transport=listener)
