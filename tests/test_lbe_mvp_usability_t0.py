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
    p = dict(enabled=False, apply_configured=False, scope_ready=False,
             tools_ready=False,
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
        "scope_ready": True, "tools_ready": True,
        "durability": "healthy",
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
        enabled=True, apply_configured=True, scope_ready=True,
        tools_ready=True,
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

def test_official_streamable_http_client_session_over_inprocess_asgi(
        mvp, monkeypatch):
    """Official client + SDK HTTP route, no TCP socket/host Tunnel or native child.

    httpx2.ASGITransport keeps every client request in this Python process.
    Unlike direct Client(server), this exercises actual SDK HTTP request and
    protocol handling against the configured streamable_http_app().
    The separate Boundary/REST auth policies retain their existing tests.
    """
    import httpx2
    from mcp.client.streamable_http import streamable_http_client
    from gateway.mcp_transport import build_streamable_http_app
    from gateway.multi_admission import MAX_RAW_BODY

    make, *_ = mvp
    service = make(server_enabled=False, workspace_enabled=True)
    monkeypatch.setattr(subprocess, "Popen",
                        lambda *_a, **_kw: pytest.fail("ASGI T0 spawned child"))
    sdk = build_multi_mcp(service)
    app = build_streamable_http_app(sdk, port=8765,
                                   max_request_body_size=MAX_RAW_BODY)

    async def exercise():
        # Explicit SDK lifespan, not a real listener. Every HTTP request stays
        # in the ASGITransport; there is no Mac, tunnel or outbound network.
        async with sdk.session_manager.run():
            async with httpx2.AsyncClient(
                transport=httpx2.ASGITransport(app=app),
                base_url="http://127.0.0.1:8765",
                timeout=httpx2.Timeout(30.0, read=300.0),
            ) as http:
                async with streamable_http_client(
                    "http://127.0.0.1:8765/mcp",
                    http_client=http,
                ) as (reader, writer):
                    async with ClientSession(reader, writer) as session:
                        await session.initialize()
                        names = {tool.name for tool in (
                            await session.list_tools()).tools}
                        assert {"gateway_info", "run_command"} <= names
                        info = (await session.call_tool(
                            "gateway_info", {})).structured_content
                        diagnosis = info["exec_policy"]["mvp_readiness"]
                        assert diagnosis["six_command_apply"] == "blocked"
                        assert "dual_opt_in_or_scope_missing" in (
                            diagnosis["blocking_codes"])
                        for row in SIX_FIXED_COMMANDS:
                            response = await session.call_tool("run_command", {
                                "workspace": "a", "cwd": row.cwd,
                                "argv": list(row.requested_argv),
                                "dry_run": True})
                            assert response.is_error is not True
                            assert response.structured_content["status"] == "preview"
                        rejected = await session.call_tool("run_command", {
                            "workspace": "a", "cwd": "py-direct",
                            "argv": ["python", "-m", "pytest", "-q"],
                            "dry_run": False})
                        assert rejected.is_error is True
                        assert rejected.structured_content["error"] == "exec_disabled"

    try:
        asyncio.run(exercise())
    finally:
        service.close()


# Independent literal expected scopes: never manufacture expected S1..S6
# from the same production SIX_FIXED_COMMANDS tuple used by the oracle.
@pytest.mark.parametrize("paths,runners,expected", [
    (("notes",), (), False),
    (("py-direct/src",), (), False),
    (("py-pipenv",), (), False),  # S3 REQUIRES explicit Pipenv runner
    (("py-direct",), ("py-direct=pipenv",), False),
    (("py-direct",), (), True),  # S1/S2 Direct, root exactly matches cwd
    (("go-project",), (), True),  # S4/S5 (and supported S6)
    (("py-pipenv",), ("py-pipenv=pipenv",), True),
    ((".",), (), True),  # Go direct even when root is nearest scope
    ((".",), ("py-direct=direct",), True),
    ((".",), ("go-project=pipenv",), True),  # Go ignores Python runner
])
def test_independent_literal_six_command_scope_matrix(paths, runners, expected):
    from gateway.lbe_mvp_readiness import has_supported_six_command_scope
    assert has_supported_six_command_scope(paths, runners) is expected


def _make_scope_variant(mvp, *, paths, runners):
    """Real parser and same disposable historical private state/tools."""
    from gateway.workspaces import ActiveRuntimeInventory, WorkspaceService
    from gateway.workspaces_config import parse_workspace_config
    _make, root, private, *_ = mvp
    parsed = parse_workspace_config({
        "schema_version": 2,
        "server": {"port": 8765, "transport": "http",
                   "exec": {"enabled": True}},
        "workspaces": {
            "a": {"root": str(root),
                  "exec": {"enabled": True, "paths": list(paths),
                           "runners": list(runners)}},
        },
    })
    return WorkspaceService(parsed, config_dir=private,
                            inventory=ActiveRuntimeInventory(
                                paths=(private.parent / "runtime",)))


@pytest.mark.parametrize("paths,runners,eligible", [
    (("notes",), (), False),
    (("py-pipenv",), (), False),
    (("py-direct",), ("py-direct=pipenv",), False),
    (("py-direct",), (), True),
    (("go-project",), (), True),
    (("py-pipenv",), ("py-pipenv=pipenv",), True),
])
def test_real_service_scope_and_runner_readiness_not_false_eligible(
        mvp, monkeypatch, paths, runners, eligible):
    _make, root, *_ = mvp
    (root / "notes").mkdir(exist_ok=True)
    monkeypatch.setattr(subprocess, "Popen",
                        lambda *_a, **_k: pytest.fail("SAFE T0 started child"))
    service = _make_scope_variant(mvp, paths=paths, runners=runners)
    try:
        before = service.info()
        diag = before["exec_policy"]["mvp_readiness"]
        assert before["exec_policy"]["apply_configured"] is True
        assert before["exec_policy"]["tool_selection_ready"] is True
        assert diag["six_command_apply"] == ("eligible" if eligible else "blocked")
        assert before["exec_policy"]["available"] is eligible
        assert before["exec_policy"]["completion_capability"] == (
            "best_effort" if eligible else "none")
        assert before["read_only"] is not eligible
        assert before["workspaces"][0]["exec_apply_available"] is eligible
        if not eligible:
            assert "six_command_scope_unavailable" in diag["blocking_codes"]
            assert diag["preview"] == "eligible"
            # A legal unrelated-scope Python PREVIEW remains nonspawning.
            if paths == ("notes",):
                assert service.invoke_exec(
                    "a", "notes", ["python", "-m", "pytest", "-q"],
                    dry_run=True)["status"] == "preview"
            with pytest.raises(Exception):
                # No static diagnosis value is an execution authorization.
                service.invoke_exec("a", "py-direct",
                                    ["python", "-m", "pytest", "-q"],
                                    dry_run=False)
        else:
            assert diag["blocking_codes"] == []
        assert service.info() == before
    finally:
        service.close()


def test_missing_six_scope_is_consistent_across_rest_mcp_health_and_list(
        mvp, monkeypatch):
    from starlette.testclient import TestClient
    _make, root, *_ = mvp
    (root / "notes").mkdir(exist_ok=True)
    monkeypatch.setattr(subprocess, "Popen",
                        lambda *_a, **_k: pytest.fail("SAFE T0 spawned"))
    service = _make_scope_variant(mvp, paths=("notes",), runners=())
    headers = {"Accept": "application/json, text/event-stream",
               "Content-Type": "application/json"}
    try:
        with TestClient(create_multi_app(service),
                        base_url="http://127.0.0.1:8765") as http:
            info = http.get("/info").json()
            assert info["exec_policy"]["available"] is False
            assert info["workspaces"][0]["exec_apply_configured"] is True
            assert info["workspaces"][0]["exec_apply_available"] is False
            assert http.get("/health").json()["exec_policy"] == info["exec_policy"]
            assert http.get("/workspaces").json() == service.list_workspaces()
            r = http.post("/mcp", headers=headers, json={
                "jsonrpc": "2.0", "id": 17, "method": "initialize",
                "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                           "clientInfo": {"name": "safe-t0-scope", "version": "1"}}})
            assert r.status_code == 200
            http.post("/mcp", headers=headers, json={
                "jsonrpc": "2.0", "method": "notifications/initialized"})
            r = http.post("/mcp", headers=headers, json={
                "jsonrpc": "2.0", "id": 18, "method": "tools/call",
                "params": {"name": "gateway_info", "arguments": {}}})
            assert r.status_code == 200
            assert r.json()["result"]["structuredContent"]["exec_policy"][
                "mvp_readiness"] == info["exec_policy"]["mvp_readiness"]
    finally:
        service.close()


def test_schema_v1_info_and_workspaces_shape_unmodified_by_v2_readiness(
        mvp, monkeypatch):
    from gateway.workspaces import ActiveRuntimeInventory, WorkspaceService
    from gateway.workspaces_config import parse_workspace_config
    _make, root, private, *_ = mvp
    monkeypatch.setattr(subprocess, "Popen",
                        lambda *_a, **_k: pytest.fail("T0 native child"))
    config = parse_workspace_config({
        "schema_version": 1,
        "workspaces": {"a": {"root": str(root), "write": {"enabled": False}}},
    })
    service = WorkspaceService(
        config, config_dir=private,
        inventory=ActiveRuntimeInventory(
            paths=(private.parent / "runtime",)))
    try:
        info = service.info()
        assert "mvp_readiness" not in info["exec_policy"]
        assert "supported_apply_commands" not in info["exec_policy"]
        assert "exec_apply_available" not in info["workspaces"][0]
        assert info["exec_policy"]["available"] is False
    finally:
        service.close()
