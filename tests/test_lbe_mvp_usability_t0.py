"""Official MCP SDK ClientSession and read-only diagnostics, SAFE T0 only.

No real Python/Pipenv/Go process, private Mac/Tunnel, or network listener.
Reuses the isolated synthetic fixture from the existing six-command tests.
"""
from __future__ import annotations

import asyncio
import subprocess

import pytest

pytest.importorskip("mcp", reason="official SDK v2 required")
from mcp.client import Client
from mcp.client.session import ClientSession

from gateway.lbe_mvp_readiness import summarize_mvp_readiness
from gateway.lbe_six_fixed_commands import SIX_FIXED_COMMANDS
from gateway.lbe_worker import LbeWorker
from gateway.mcp_multi import build_multi_mcp
from gateway.http_multi import create_multi_app
from test_lbe_mvp_apply_t0 import mvp  # existing disposable fake-tool fixture


def test_diagnostic_pure_failure_and_success_oracles():
    p = dict(enabled=False, apply_configured=False, tools_ready=False,
             durability="disabled", owner_unavailable=False,
             capacity_exhausted=False, closing=False, apply_eligible=False,
             preview_eligible=False)
    denied = summarize_mvp_readiness(**p)
    assert denied["blocking_codes"] == [
        "exec_paths_disabled", "dual_opt_in_or_scope_missing"]
    assert denied["six_command_apply"] == "blocked"
    assert denied["evidence_grade"] == "runtime_status_only_not_native_test"
    ok = summarize_mvp_readiness(**{
        **p, "enabled": True, "apply_configured": True,
        "tools_ready": True, "durability": "healthy",
        "apply_eligible": True, "preview_eligible": True})
    assert ok["blocking_codes"] == []
    assert ok["six_command_apply"] == "eligible"
    assert ok["evidence_grade"] == "runtime_status_only_not_native_test"


@pytest.mark.parametrize("durability,owner,busy,closing,code", [
    ("unavailable", False, False, False, "historical_state_unavailable"),
    ("quarantined", False, False, False, "historical_state_quarantined"),
    ("healthy", True, False, False, "original_child_owner_unavailable"),
    ("healthy", False, True, False, "original_child_capacity_exhausted"),
    ("healthy", False, False, True, "service_closing"),
])
def test_each_safety_status_has_fixed_fail_closed_code(
        durability, owner, busy, closing, code):
    state = summarize_mvp_readiness(
        enabled=True, apply_configured=True, tools_ready=True,
        durability=durability, owner_unavailable=owner,
        capacity_exhausted=busy, closing=closing,
        apply_eligible=False, preview_eligible=True)
    assert code in state["blocking_codes"]
    assert state["six_command_apply"] == "blocked"


@pytest.mark.parametrize("server_enabled,workspace_enabled", [
    (False, False), (False, True), (True, False), (True, True),
])
def test_current_service_status_is_read_only(
        mvp, monkeypatch, server_enabled, workspace_enabled):
    make, *_ = mvp
    service = make(server_enabled=server_enabled,
                   workspace_enabled=workspace_enabled)
    monkeypatch.setattr(subprocess, "Popen",
                        lambda *_a, **_kw: pytest.fail("SAFE T0 spawned"))
    try:
        info = service.info()
        diagnosis = info["exec_policy"]["mvp_readiness"]
        allowed = server_enabled and workspace_enabled
        assert diagnosis["six_command_apply"] == (
            "eligible" if allowed else "blocked")
        assert diagnosis["evidence_grade"] == "runtime_status_only_not_native_test"
        if not allowed:
            assert "dual_opt_in_or_scope_missing" in diagnosis["blocking_codes"]
        assert service.info() == info
        assert info["exec_policy"]["supported_apply_commands"] == [
            row.command_id for row in SIX_FIXED_COMMANDS]
    finally:
        service.close()


def test_rest_and_sdk_server_gateway_info_have_identical_readiness(
        mvp, monkeypatch):
    from starlette.testclient import TestClient
    make, *_ = mvp
    service = make(server_enabled=False, workspace_enabled=True)
    monkeypatch.setattr(subprocess, "Popen",
                        lambda *_a, **_kw: pytest.fail("native spawn"))
    headers = {"Accept": "application/json, text/event-stream",
               "Content-Type": "application/json"}
    try:
        with TestClient(create_multi_app(service),
                        base_url="http://127.0.0.1:8765") as client:
            info = client.get("/info").json()
            assert client.get("/health").json()["exec_policy"] == info["exec_policy"]
            r = client.post("/mcp", headers=headers, json={
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2025-11-25",
                           "capabilities": {},
                           "clientInfo": {"name": "safe-t0", "version": "1"}}})
            assert r.status_code == 200
            client.post("/mcp", headers=headers, json={
                "jsonrpc": "2.0", "method": "notifications/initialized"})
            r = client.post("/mcp", headers=headers, json={
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "gateway_info", "arguments": {}}})
            assert r.status_code == 200
            assert r.json()["result"]["structuredContent"]["exec_policy"][
                "mvp_readiness"] == info["exec_policy"]["mvp_readiness"]
    finally:
        service.close()


@pytest.mark.parametrize("protocol_mode", ["legacy", "auto"])
def test_official_client_session_six_previews_and_denied_apply(
        mvp, monkeypatch, protocol_mode):
    """Official SDK Client.session is a ClientSession; no handcrafted RPC."""
    make, *_ = mvp
    service = make(server_enabled=False, workspace_enabled=True)
    monkeypatch.setattr(subprocess, "Popen",
                        lambda *_a, **_kw: pytest.fail("native spawn"))

    async def run():
        async with Client(build_multi_mcp(service), mode=protocol_mode) as client:
            session = client.session
            assert isinstance(session, ClientSession)
            names = {tool.name for tool in (await session.list_tools()).tools}
            assert {"gateway_info", "list_workspaces", "run_command"} <= names
            info = (await session.call_tool(
                "gateway_info", {})).structured_content
            assert info["exec_policy"]["mvp_readiness"]["six_command_apply"] == "blocked"
            for row in SIX_FIXED_COMMANDS:
                result = await session.call_tool("run_command", {
                    "workspace": "a", "cwd": row.cwd,
                    "argv": list(row.requested_argv), "dry_run": True})
                assert result.is_error is not True
                assert result.structured_content["status"] == "preview"
                assert result.structured_content["executed"] is False
            denied = await session.call_tool("run_command", {
                "workspace": "a", "cwd": "py-direct",
                "argv": ["python", "-m", "pytest", "-q"],
                "dry_run": False})
            assert denied.is_error is True
            assert denied.structured_content["error"] == "exec_disabled"
    try:
        asyncio.run(run())
    finally:
        service.close()


def test_official_client_session_six_fake_worker_applies_and_negatives(
        mvp, monkeypatch):
    make, *_ = mvp
    service = make()
    visited = []
    monkeypatch.setattr(subprocess, "Popen",
                        lambda *_a, **_kw: pytest.fail("native spawn"))

    def fake_worker(self, plan, *, cancelled=None, **kwargs):
        visited.append((plan.workspace, plan.cwd, tuple(plan.effective_argv)))
        return {"status": "exited", "executed": True, "exit_code": 0,
                "stdout": "SAFE-T0-FAKE", "stderr": "",
                "timed_out": False, "process_may_be_running": True,
                "cleanup_proven": False, "output_complete": True}

    monkeypatch.setattr(LbeWorker, "run", fake_worker)

    async def run():
        async with Client(build_multi_mcp(service), mode="legacy") as client:
            session = client.session
            assert isinstance(session, ClientSession)
            for row in SIX_FIXED_COMMANDS:
                observed = await session.call_tool("run_command", {
                    "workspace": "a", "cwd": row.cwd,
                    "argv": list(row.requested_argv), "dry_run": False})
                assert observed.is_error is not True
                assert observed.structured_content["status"] == "exited"
                assert observed.structured_content["stdout"] == "SAFE-T0-FAKE"
                assert observed.structured_content["cleanup_proven"] is False
            for cwd, argv in (
                ("go-project", ["go", "run", "."]),
                ("py-direct", ["python", "-c", "print(1)"]),
                ("py-pipenv", ["pipenv", "run", "python", "-m", "pytest", "-q"]),
            ):
                illegal = await session.call_tool("run_command", {
                    "workspace": "a", "cwd": cwd, "argv": argv,
                    "dry_run": False})
                assert illegal.is_error is True
            wrong = await session.call_tool("run_command", {
                "workspace": "wrong-workspace", "cwd": "py-direct",
                "argv": ["python", "-m", "pytest", "-q"], "dry_run": False})
            assert wrong.is_error is True
    try:
        asyncio.run(run())
        assert visited == [
            ("a", row.cwd, tuple(row.effective_argv))
            for row in SIX_FIXED_COMMANDS]
    finally:
        service.close()
