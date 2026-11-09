"""RED contracts: per-workspace audit visibility and exact UTC expiry semantics."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json

import pytest
from starlette.testclient import TestClient

from gateway.core import GatewayError
from gateway.http_multi import create_multi_app
from gateway.sensitive_audit import SensitiveAudit
from gateway.workspaces import ActiveRuntimeInventory, WorkspaceService
from gateway.workspaces_config import parse_workspace_config


def _service(tmp_path, scope="src"):
    parent = tmp_path / "projects"
    parent.mkdir()
    a, b = parent / "a", parent / "b"
    a.mkdir()
    b.mkdir()
    (a / "src").mkdir()
    config_dir = tmp_path / "private-config"
    config_dir.mkdir(mode=0o700)
    config_dir.chmod(0o700)
    runtime = tmp_path / "trusted-runtime"
    runtime.mkdir()
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat(timespec="seconds")
    settings = parse_workspace_config({
        "schema_version": 1,
        "workspaces": {
            "a": {
                "root": str(a),
                "write": {
                    "enabled": True,
                    "paths": [scope],
                    "sensitive_content": {
                        "mode": "audit",
                        "paths": [scope],
                        "expires_at": expires_at,
                    },
                },
            },
            "b": {"root": str(b), "write": {"enabled": False}},
        },
    })
    return (WorkspaceService(
        settings, config_dir=config_dir,
        inventory=ActiveRuntimeInventory(paths=(runtime,)),
    ), a, b, expires_at)


def _by_id(result):
    return {item["id"]: item for item in result["workspaces"]}


def _assert_effective_status(workspaces, expires_at):
    a, b = _by_id(workspaces)["a"], _by_id(workspaces)["b"]
    assert a["sensitive_content"] == {
        "write_mode": "audit",
        "read_redaction_enabled": True,
        "expires_at": expires_at,
        "audit_scope_count": 1,
    }
    assert b["sensitive_content"] == {
        "write_mode": "enforce",
        "read_redaction_enabled": True,
        "expires_at": None,
        "audit_scope_count": 0,
    }


def test_multi_status_service_and_real_rest_share_effective_policy(tmp_path):
    service, a, b, expires_at = _service(tmp_path)
    try:
        _assert_effective_status(service.list_workspaces(), expires_at)
        _assert_effective_status(service.info(), expires_at)
        # No absolute root or private configuration directory is disclosed.
        assert str(tmp_path) not in json.dumps(service.info())
        with TestClient(create_multi_app(service, enable_mcp=False),
                        base_url="http://127.0.0.1:8765") as client:
            listed = client.get("/workspaces")
            info = client.get("/info")
            assert listed.status_code == info.status_code == 200
            _assert_effective_status(listed.json(), expires_at)
            _assert_effective_status(info.json(), expires_at)
            assert listed.json()["workspaces"] == info.json()["workspaces"]

            # A live Workspace expires without restart; B never gains audit.
            service.get("a").gateway.sensitive_audit.deadline = 0.0
            after = _by_id(client.get("/workspaces").json())
            assert after["a"]["sensitive_content"] == {
                "write_mode": "enforce",
                "read_redaction_enabled": True,
                "expires_at": None,
                "audit_scope_count": 0,
            }
            assert after["b"]["sensitive_content"]["write_mode"] == "enforce"
            assert client.get("/info").json()["workspaces"] == client.get("/workspaces").json()["workspaces"]
    finally:
        service.close()


def test_multi_real_mcp_status_matches_service_and_rest(tmp_path):
    pytest.importorskip("mcp", reason="Official SDK required for real MCP transport")
    service, a, b, expires_at = _service(tmp_path)
    headers = {"Accept": "application/json, text/event-stream",
               "Content-Type": "application/json"}

    def rpc(client, method, params=None):
        response = client.post("/mcp", headers=headers, json={
            "jsonrpc": "2.0", "id": 7, "method": method, "params": params or {},
        })
        assert response.status_code == 200, response.text
        return response.json()

    try:
        with TestClient(create_multi_app(service),
                        base_url="http://127.0.0.1:8765") as client:
            response = rpc(client, "initialize", {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "sensitive-status", "version": "1"},
            })
            assert "result" in response
            client.post("/mcp", headers=headers,
                        json={"jsonrpc": "2.0", "method": "notifications/initialized"})
            for name in ("list_workspaces", "gateway_info"):
                tool = rpc(client, "tools/call", {
                    "name": name, "arguments": {},
                })["result"]
                assert tool.get("isError") is not True
                _assert_effective_status(tool["structuredContent"], expires_at)
                assert tool["structuredContent"]["workspaces"] == client.get("/workspaces").json()["workspaces"]
    finally:
        service.close()


@pytest.mark.parametrize("hours", [9, -4])
def test_non_utc_timezone_offsets_are_rejected(hours):
    expiry = (datetime.now(timezone.utc) + timedelta(minutes=10)).astimezone(
        timezone(timedelta(hours=hours)),
    ).isoformat()
    with pytest.raises(GatewayError, match="UTC") as error:
        SensitiveAudit(paths=("src",), expires_at=expiry, write_paths=("src",))
    assert error.value.code == "invalid_argument"


def test_naive_expiry_is_rejected():
    expiry = (datetime.now(timezone.utc) + timedelta(minutes=10)).replace(tzinfo=None).isoformat()
    with pytest.raises(GatewayError, match="UTC"):
        SensitiveAudit(paths=("src",), expires_at=expiry, write_paths=("src",))


@pytest.mark.parametrize("hours", [24, 25, 168, 87600])
def test_root_audit_expires_at_requested_deadline(tmp_path, monkeypatch, hours):
    import gateway.sensitive_audit as module
    from gateway.core import Gateway
    now = datetime(2026, 10, 26, 12, tzinfo=timezone.utc)

    class FrozenUtcClock(datetime):
        @classmethod
        def now(cls, tz=None):
            return now

    monkeypatch.setattr(module, "datetime", FrozenUtcClock)
    monkeypatch.setattr(module.time, "monotonic", lambda: 100.0)
    gateway = Gateway(tmp_path, allow_write=True, sensitive_content_audit_paths=(".",),
                      sensitive_content_audit_until=(now + timedelta(hours=hours)).isoformat())
    try:
        assert gateway.info()["write_policy"]["sensitive_content"]["write_mode"] == "audit"
        assert gateway.create_file("DEV_CHECKPOINT.md", "token = runtime_value\n", dry_run=False)["applied"]
        shown = gateway.read_file("DEV_CHECKPOINT.md")
        assert shown["redacted_lines"] == 0
        assert "token = runtime_value" in shown["content"]
        assert gateway.create_file("hard.md", "password = 'hardcoded'\n", dry_run=False)["applied"]
        assert "password = 'hardcoded'" in gateway.read_file("hard.md")["content"]
        duration = timedelta(hours=hours).total_seconds()
        monkeypatch.setattr(module.time, "monotonic", lambda: 100.0 + duration - 1)
        assert gateway.info()["write_policy"]["sensitive_content"]["write_mode"] == "audit"
        monkeypatch.setattr(module.time, "monotonic", lambda: 100.0 + duration)
        assert gateway.info()["write_policy"]["sensitive_content"]["write_mode"] == "enforce"
        with pytest.raises(GatewayError) as exc:
            gateway.create_file("SPRINT_STATUS.md", "token = runtime_value\n", dry_run=False)
        assert exc.value.details["rule_id"] == "CREDENTIAL_ASSIGNMENT"
        assert not (tmp_path / "SPRINT_STATUS.md").exists()
    finally:
        gateway.close()


@pytest.mark.parametrize("seconds", [0, -1])
def test_audit_rejects_expired_deadline(seconds):
    expiry = (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat()
    with pytest.raises(GatewayError):
        SensitiveAudit(paths=(".",), expires_at=expiry)


def test_root_audit_cannot_exceed_narrow_write_grants():
    expiry = (datetime.now(timezone.utc) + timedelta(hours=23)).isoformat()
    with pytest.raises(GatewayError):
        SensitiveAudit(paths=(".",), expires_at=expiry, write_paths=("src",))


def test_multi_workspace_root_audit_remains_workspace_scoped(tmp_path):
    service, a, b, expiry = _service(tmp_path, scope=".")
    try:
        active = service.get("a").gateway
        assert active.sensitive_audit.allows("DEV_CHECKPOINT.md")
        assert active.sensitive_audit.allows(".scratch/review-handoff/T06/DEV_CHECKPOINT.md")
        assert not service.get("b").gateway.sensitive_audit.allows("DEV_CHECKPOINT.md")
        assert service.list_workspaces()["workspaces"][0]["sensitive_content"]["write_mode"] == "audit"
    finally:
        service.close()


@pytest.mark.parametrize("suffix", ["Z", "+00:00"])
def test_explicit_utc_expiry_formats_are_accepted(suffix):
    expiry = (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat(timespec="seconds")
    expiry = expiry.replace("+00:00", suffix)
    policy = SensitiveAudit(paths=("src",), expires_at=expiry, write_paths=("src",))
    assert policy.status()["write_mode"] == "audit"
    assert policy.allows("src/a.py") is True
    assert policy.allows("other/a.py") is False


def test_utc_clock_advance_expires_even_if_monotonic_deadline_not_reached(monkeypatch):
    import gateway.sensitive_audit as module
    # The endpoint deliberately has no fractional seconds. Comparing ISO
    # strings fails when the clock moves to the first microsecond after it.
    expiry = (datetime.now(timezone.utc) + timedelta(minutes=10)).replace(microsecond=0)
    policy = SensitiveAudit(paths=("src",), expires_at=expiry.isoformat(), write_paths=("src",))
    assert policy.status()["write_mode"] == "audit"

    class AdvancedUtcClock:
        @staticmethod
        def now(tz=None):
            return expiry + timedelta(microseconds=1)

    monkeypatch.setattr(module, "datetime", AdvancedUtcClock)
    assert policy.status()["write_mode"] == "enforce"
    assert policy.allows("src/a.py") is False
