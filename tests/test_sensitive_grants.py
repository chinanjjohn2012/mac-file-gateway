"""Exact-line grants let an operator allow reviewed Hard lines and nothing else."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import inspect
import json
from pathlib import Path
import stat
import tempfile
import time

import pytest
from starlette.testclient import TestClient

from gateway.core import Gateway, GatewayError
from gateway.http import create_app
from gateway.sensitive_grants import ApprovalListener, ApprovalService, approval_request, approve_cli


HARD_LINES = (
    '    return {"Authorization": "Bearer " + sample_value()}',
    '    {"Authorization": "Bearer no-match"},',
    '    {"Authorization": "Basic value"},',
    '    {"Authorization": "Bearer"},',
    '    {"Authorization": "Bearer "},',
    '    {"Authorization": "bearer wrong"},',
    '    {"Authorization": "incorrect"},',
)
SOURCE = """\
def sample_value():
    return "runtime"

def bearer_headers():
%s

HEADERS = [
%s
]

def test_visible():
    assert bearer_headers()
""" % (HARD_LINES[0], "\n".join(HARD_LINES[1:]))
SECRET_TEXT = "Bearer no-match"
UNGRANTED = 'password = "ungranted-secret"\n'


def _hashes(lines: tuple[str, ...] | list[str]) -> set[str]:
    return {hashlib.sha256(line.encode("utf-8")).hexdigest() for line in lines}


def _future(hours: int = 1) -> str:
    return (datetime.now(timezone.utc) + timedelta(hours=hours)).isoformat()


def _gateway(tmp_path: Path, name: str = "handoff") -> tuple[Gateway, Path, Path]:
    root = tmp_path / name
    root.mkdir()
    grants = tmp_path / f"{name}-grants.json"
    gateway = Gateway(root, allow_write=True, workspace_name=name, sensitive_grants_path=grants)
    return gateway, root, grants


def _blob(exc: GatewayError) -> str:
    return json.dumps({"message": str(exc), "details": exc.details}, ensure_ascii=True)


def _pending(gateway: Gateway, fn) -> tuple[GatewayError, str]:
    import io
    from contextlib import redirect_stderr

    buffer = io.StringIO()
    with redirect_stderr(buffer):
        with pytest.raises(GatewayError) as caught:
            fn()
    error = caught.value
    return error, _operator_token(buffer.getvalue(), error.details["pending_id"])


def test_ungranted_bearer_fixture_is_credential_hard_without_leaking_text(tmp_path):
    gateway, root, _grants = _gateway(tmp_path)
    try:
        for dry_run in (True, False):
            with pytest.raises(GatewayError) as caught:
                gateway.create_file("auth.py", SOURCE, dry_run=dry_run)
            error = caught.value
            assert error.code == "sensitive_content"
            assert error.details["rule_id"] == "CREDENTIAL_HARD"
            assert error.details["severity"] == "hard"
            assert set(error.details) == {"rule_id", "line", "severity", "pending_id", "lines"}
            assert _hashes(HARD_LINES) == {item["line_sha256"] for item in error.details["lines"]}
            assert all(set(item) == {"line", "line_sha256"} for item in error.details["lines"])
            blob = _blob(error)
            for line in HARD_LINES:
                assert line.strip() not in blob
            assert SECRET_TEXT not in blob
            assert not (root / "auth.py").exists()
    finally:
        gateway.close()


def test_granted_lines_can_be_written_and_assertion_edits_stay_allowed(tmp_path):
    gateway, root, grants = _gateway(tmp_path)
    service = ApprovalService()
    service.register(gateway)
    try:
        error, token = _pending(gateway, lambda: gateway.create_file("auth.py", SOURCE, dry_run=False))
        pending_id = error.details["pending_id"]
        with pytest.raises(GatewayError):
            service.approve(pending_id, _future(), None, False, token)
        assert not grants.exists()
        status = service.approve(pending_id, _future(), None, True, token)
        assert status["grant_count"] == len(HARD_LINES)
        assert stat.S_IMODE(grants.stat().st_mode) == 0o600
        flags, findings = gateway._visibility.classify("auth.py", SOURCE.encode())
        assert any(kind == "hard" for _number, kind in findings)
        assert any(flags)
        preview = gateway.create_file("auth.py", SOURCE)
        assert preview["applied"] is False
        assert SECRET_TEXT in preview["diff"]
        applied = gateway.create_file("auth.py", SOURCE, dry_run=False)
        assert applied["applied"] is True
        read = gateway.read_file("auth.py")
        assert SECRET_TEXT in read["content"]
        assert read["redacted_lines"] == 0
        info = json.dumps(gateway.info(), ensure_ascii=True)
        assert SECRET_TEXT not in info
        assert "line_sha256" not in info
        assert gateway.info()["write_policy"]["sensitive_grants"]["grant_count"] == len(HARD_LINES)
        edited = gateway.replace_text(
            "auth.py", "assert bearer_headers()", "assert bearer_headers() is not None",
            read["file_sha256"], dry_run=False,
        )
        assert edited["applied"] is True
        assert "is not None" in (root / "auth.py").read_text()
    finally:
        gateway.close()


def test_changed_literal_other_prefix_and_expiry_are_rejected_again(tmp_path, monkeypatch):
    gateway, root, grants = _gateway(tmp_path)
    service = ApprovalService()
    service.register(gateway)
    try:
        error, token = _pending(gateway, lambda: gateway.create_file("auth.py", SOURCE, dry_run=False))
        service.approve(error.details["pending_id"], _future(), "auth.py", True, token)
        gateway.create_file("auth.py", SOURCE, dry_run=False)
        read = gateway.read_file("auth.py")
        with pytest.raises(GatewayError) as changed:
            gateway.replace_text(
                "auth.py", SECRET_TEXT, "Bearer other-token", read["file_sha256"], dry_run=False,
            )
        assert changed.value.details["rule_id"] == "CREDENTIAL_HARD"
        assert "Bearer other-token" not in _blob(changed.value)
        assert SECRET_TEXT in (root / "auth.py").read_text()
        with pytest.raises(GatewayError) as other_path:
            gateway.create_file("other.py", SOURCE, dry_run=False)
        assert other_path.value.details["rule_id"] == "CREDENTIAL_HARD"
        assert not (root / "other.py").exists()

        original = time.monotonic
        monkeypatch.setattr(
            "gateway.sensitive_grants.time.monotonic", lambda: original() + 10_000_000,
        )
        with pytest.raises(GatewayError) as expired:
            gateway.create_file("fresh.py", SOURCE, dry_run=False)
        assert expired.value.details["rule_id"] == "CREDENTIAL_HARD"
        hidden = gateway.read_file("auth.py")
        assert SECRET_TEXT not in hidden["content"]
        assert "[REDACTED]" in hidden["content"]
        assert hidden["redacted_lines"] == len(HARD_LINES)
        assert grants.exists()
    finally:
        gateway.close()


def test_granted_line_stays_visible_beside_an_ungranted_secret(tmp_path):
    gateway, root, _grants = _gateway(tmp_path)
    service = ApprovalService()
    service.register(gateway)
    try:
        error, token = _pending(gateway, lambda: gateway.create_file("auth.py", SOURCE, dry_run=False))
        service.approve(error.details["pending_id"], _future(), None, True, token)
        gateway.create_file("auth.py", SOURCE, dry_run=False)
        mixed = SOURCE + UNGRANTED
        (root / "auth.py").write_text(mixed)
        read = gateway.read_file("auth.py")
        assert SECRET_TEXT in read["content"]
        assert "ungranted-secret" not in read["content"]
        assert "[REDACTED]" in read["content"]
        found = gateway.search_files(SECRET_TEXT, file_glob="auth.py")
        assert found["matches"]
        missed = gateway.search_files("ungranted-secret", file_glob="auth.py")
        assert missed["matches"] == []
        with pytest.raises(GatewayError) as added:
            gateway.replace_text(
                "auth.py", "assert bearer_headers()", "assert bearer_headers()\n" + UNGRANTED.strip(),
                hashlib.sha256((root / "auth.py").read_bytes()).hexdigest(), dry_run=False,
            )
        assert added.value.details["rule_id"] == "CREDENTIAL_HARD"
        assert "ungranted-secret" not in _blob(added.value)
        assert (root / "auth.py").read_text() == mixed
    finally:
        gateway.close()


def test_scan_unavailable_cannot_be_granted(tmp_path, monkeypatch):
    from gateway import python_values

    gateway, root, _grants = _gateway(tmp_path)
    service = ApprovalService()
    service.register(gateway)
    try:
        error, token = _pending(gateway, lambda: gateway.create_file("auth.py", SOURCE, dry_run=False))
        service.approve(error.details["pending_id"], _future(), ".", True, token)
        monkeypatch.setattr(python_values, "MAX_TOKENS", 3)
        with pytest.raises(GatewayError) as blocked:
            gateway.create_file("auth.py", "x = 1\ny = 2\n", dry_run=False)
        assert blocked.value.details == {"rule_id": "SCAN_UNAVAILABLE", "severity": "scan_unavailable"}
        assert not (root / "auth.py").exists()
    finally:
        gateway.close()


def test_local_cli_prints_lines_and_records_a_grant_only_after_confirmation(tmp_path):
    gateway, root, grants = _gateway(tmp_path)
    service = ApprovalService()
    service.register(gateway)
    directory = Path(tempfile.mkdtemp(prefix="mgw", dir="/tmp"))
    socket_path = directory / "a.sock"
    listener = ApprovalListener(service, socket_path)
    listener.start()
    try:
        error, token = _pending(gateway, lambda: gateway.create_file("auth.py", SOURCE, dry_run=True))
        pending_id = error.details["pending_id"]
        shown = approval_request(
            {"op": "show", "pending_id": pending_id, "token": token}, socket_path,
        )
        assert shown["ok"] is True
        assert SECRET_TEXT in "\n".join(line["text"] for line in shown["lines"])
        refused = approval_request({
            "op": "approve", "pending_id": pending_id, "expires_at": _future(), "confirm": False,
        }, socket_path)
        assert refused["ok"] is False
        assert not grants.exists()
        printed: list[str] = []
        declined = approve_cli(
            ["--pending-id", pending_id, "--token", token, "--expires-at", _future(), "--socket", str(socket_path)],
            input_fn=lambda _prompt: "no", output_fn=printed.append,
        )
        assert declined == 2
        assert any(SECRET_TEXT in line for line in printed)
        assert not grants.exists()
        confirmed = approve_cli(
            ["--pending-id", pending_id, "--token", token, "--expires-at", _future(),
             "--socket", str(socket_path), "--yes"],
            output_fn=printed.append,
        )
        assert confirmed == 0
        assert gateway.create_file("auth.py", SOURCE, dry_run=False)["applied"] is True
        assert (root / "auth.py").read_text() == SOURCE
    finally:
        listener.close()
        gateway.close()
        directory.rmdir()


def test_approval_is_not_an_agent_tool(tmp_path):
    gateway, _root, _grants = _gateway(tmp_path)
    try:
        app = create_app(gateway, enable_mcp=False)
        paths = {getattr(route, "path", "") for route in app.app.routes}
        assert paths
        assert all("approve" not in path for path in paths)
        from gateway import mcp_adapter, mcp_multi
        assert "approve-sensitive" not in inspect.getsource(mcp_adapter.build_mcp)
        assert "approve-sensitive" not in inspect.getsource(mcp_multi.build_multi_mcp)
        pytest.importorskip("mcp")
        from gateway.mcp_adapter import build_mcp
        names = {tool.name for tool in __import__("asyncio").run(build_mcp(gateway).list_tools())}
        assert "approve_sensitive" not in names
        assert "approve-sensitive" not in names
        with TestClient(create_app(gateway, enable_mcp=False), base_url="http://127.0.0.1:8765") as client:
            denied = client.post("/approve-sensitive", json={})
            assert denied.status_code == 404
    finally:
        gateway.close()


def test_error_pending_id_cannot_read_or_grant_the_line(tmp_path):
    gateway, _root, grants = _gateway(tmp_path)
    service = ApprovalService()
    service.register(gateway)
    directory = Path(tempfile.mkdtemp(prefix="mgw", dir="/tmp"))
    socket_path = directory / "a.sock"
    listener = ApprovalListener(service, socket_path)
    listener.start()
    try:
        with pytest.raises(GatewayError) as caught:
            gateway.create_file("auth.py", SOURCE, dry_run=True)
        pending_id = caught.value.details["pending_id"]
        blob = _blob(caught.value)
        assert SECRET_TEXT not in blob
        shown = approval_request({"op": "show", "pending_id": pending_id}, socket_path)
        assert shown["ok"] is False
        assert SECRET_TEXT not in json.dumps(shown)
        approved = approval_request({
            "op": "approve",
            "pending_id": pending_id,
            "expires_at": _future(),
            "confirm": True,
        }, socket_path)
        assert approved["ok"] is False
        assert SECRET_TEXT not in json.dumps(approved)
        assert not grants.exists()
    finally:
        listener.close()
        gateway.close()
        directory.rmdir()


def test_operator_token_approves_once_and_a_repeat_does_not_extend_it(tmp_path, capsys):
    gateway, _root, grants = _gateway(tmp_path)
    service = ApprovalService()
    service.register(gateway)
    directory = Path(tempfile.mkdtemp(prefix="mgw", dir="/tmp"))
    socket_path = directory / "a.sock"
    listener = ApprovalListener(service, socket_path)
    listener.start()
    try:
        with pytest.raises(GatewayError) as caught:
            gateway.create_file("auth.py", SOURCE, dry_run=True)
        pending_id = caught.value.details["pending_id"]
        announced = capsys.readouterr().err
        assert SECRET_TEXT not in announced
        token = _operator_token(announced, pending_id)
        assert token not in _blob(caught.value)
        shown = approval_request(
            {"op": "show", "pending_id": pending_id, "token": token}, socket_path,
        )
        assert shown["ok"] is True
        assert SECRET_TEXT in "\n".join(line["text"] for line in shown["lines"])
        assert "token" not in shown
        first_expiry = _future(1)
        recorded = approval_request({
            "op": "approve",
            "pending_id": pending_id,
            "expires_at": first_expiry,
            "confirm": True,
            "token": token,
        }, socket_path)
        assert recorded["ok"] is True
        stored = json.loads(grants.read_text())
        assert len(stored["grants"]) == len(HARD_LINES)
        repeated = approval_request({
            "op": "approve",
            "pending_id": pending_id,
            "expires_at": _future(5),
            "confirm": True,
            "token": token,
        }, socket_path)
        assert repeated["ok"] is False
        again = json.loads(grants.read_text())
        assert [item["expires_at"] for item in again["grants"]] == [
            item["expires_at"] for item in stored["grants"]
        ]
        assert len(again["grants"]) == len(HARD_LINES)
    finally:
        listener.close()
        gateway.close()
        directory.rmdir()


def test_add_waits_for_the_grant_file_and_keeps_the_other_workspace(tmp_path):
    import fcntl
    import threading

    from gateway.sensitive_grants import SensitiveGrantTable

    path = tmp_path / "sensitive-grants.json"
    lock_path = path.with_name(path.name + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    handle = lock_path.open("a+")
    fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
    other_hash = "ab" * 32
    table = SensitiveGrantTable(path, "one")
    outcome: dict[str, object] = {}

    def add_one() -> None:
        try:
            outcome["status"] = table.add(
                path_prefix="auth.py", line_hashes=["cd" * 32], expires_at=_future(),
            )
        except Exception as exc:  # noqa: BLE001 - the assertion reports the thread failure
            outcome["error"] = exc

    thread = threading.Thread(target=add_one)
    thread.start()
    thread.join(0.4)
    try:
        assert thread.is_alive()
        path.write_text(json.dumps({
            "schema_version": 1,
            "grants": [{
                "workspace": "two",
                "path_prefix": "auth.py",
                "line_sha256": other_hash,
                "expires_at": _future(),
            }],
        }))
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        thread.join(2)
        assert "error" not in outcome
        payload = json.loads(path.read_text())
        found = {(item["workspace"], item["line_sha256"]) for item in payload["grants"]}
        assert ("two", other_hash) in found
        assert ("one", "cd" * 32) in found
        assert outcome["status"]["grant_count"] == 1
    finally:
        if thread.is_alive():
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            thread.join(2)
        handle.close()


def _operator_token(stderr: str, pending_id: str) -> str:
    prefix = f"sensitive approval pending_id={pending_id} token="
    for line in stderr.splitlines():
        if line.startswith(prefix):
            token = line.removeprefix(prefix).strip()
            assert token
            return token
    raise AssertionError("operator token was not announced")


def test_grant_does_not_cross_workspaces(tmp_path):
    first, _root, grants = _gateway(tmp_path, "one")
    (tmp_path / "two").mkdir()
    second = Gateway(tmp_path / "two", allow_write=True, workspace_name="two", sensitive_grants_path=grants)
    service = ApprovalService()
    service.register(first)
    try:
        error, token = _pending(first, lambda: first.create_file("auth.py", SOURCE, dry_run=False))
        service.approve(error.details["pending_id"], _future(), "auth.py", True, token)
        first.create_file("auth.py", SOURCE, dry_run=False)
        with pytest.raises(GatewayError) as blocked:
            second.create_file("auth.py", SOURCE, dry_run=False)
        assert blocked.value.details["rule_id"] == "CREDENTIAL_HARD"
    finally:
        second.close()
        first.close()
