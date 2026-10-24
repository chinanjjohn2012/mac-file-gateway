"""B1-B1-B/R0 expected-RED bridge contract. NO subprocesses or group signals.

Existing genuine subprocess/REST/MCP/slot/cancel tests are untouched.
The private test-only qualification is not an ordinary network credential.
"""
from __future__ import annotations

import ast
import copy
import importlib
import importlib.util
import json
import os
from pathlib import Path
import pickle
import signal
import subprocess
from types import SimpleNamespace
import urllib.error
import urllib.request

import pytest
from starlette.testclient import TestClient

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


def _bridge(marker):
    try:
        module = importlib.import_module("gateway._exec_test_bridge")
        factory = getattr(module, "create_private_exec_acceptance_bridge")
    except (ModuleNotFoundError, AttributeError) as exc:
        _require(False, marker, {"factory": type(exc).__name__})
        raise AssertionError("unreachable")
    return factory()


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
        assert env.trusted_asgi_app is not None
        assert env.listener._server.config.app is not env.trusted_asgi_app
        with TestClient(env.trusted_asgi_app,
                        base_url="http://127.0.0.1:8765") as client:
            response = client.post("/run", json={**APPLY, "dry_run": True})
        status, wire = _wire(env.port, "/run",
                             {**APPLY, "dry_run": True})
        _require(response.status_code == 200
                 and response.json().get("executed") is False
                 and status == 200 and wire.get("executed") is False,
                 "TRUSTED_ASGI_PREVIEW",
                 {"internal": response.status_code, "wire": status})


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
