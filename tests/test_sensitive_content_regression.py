"""RED contract for path-aware sensitive detection and bounded, scoped audit."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import pytest

from gateway.core import Gateway, GatewayError


def _contextvar_source(newline="\n", bom=""):
    source = (
        "from contextvars import ContextVar\n"
        "active = ContextVar('active')\n"
        "\n"
        "def scope(value):\n"
        "    token = active.set(value)\n"
        "    try:\n"
        "        yield\n"
        "    finally:\n"
        "        active.reset(token)\n"
    )
    return bom + source.replace("\n", newline)


@pytest.mark.parametrize("newline", ["\n", "\r\n"])
@pytest.mark.parametrize("bom", ["", "\ufeff"])
def test_contextvar_create_read_replace_assignment_and_whole_write(tmp_path, newline, bom):
    root = tmp_path / "project"
    (root / "src").mkdir(parents=True)
    source = _contextvar_source(newline, bom)
    gateway = Gateway(root, allow_write=True, write_paths=("src",))
    try:
        preview = gateway.create_file("src/confirmation.py", source)
        assert preview["applied"] is False
        gateway.create_file("src/confirmation.py", source, dry_run=False)
        read = gateway.read_file("src/confirmation.py")
        assert read["redacted_lines"] == 0
        assert "token = active.set(value)" in read["content"]
        sha = read["file_sha256"]
        old = "token = active.set(value)"
        new = "token = active.set(value + 1)"
        gateway.replace_text("src/confirmation.py", old, new, sha, dry_run=False)
        read = gateway.read_file("src/confirmation.py")
        assert read["redacted_lines"] == 0
        updated = source.replace(old, new)
        assert (root / "src" / "confirmation.py").read_bytes() == updated.encode("utf-8")
        final = updated + "# updated" + newline
        gateway.write_file("src/confirmation.py", final, read["file_sha256"], dry_run=False)
        assert (root / "src" / "confirmation.py").read_bytes() == final.encode("utf-8")
    finally:
        gateway.close()


def test_unproven_set_reset_pair_not_exempt(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    gateway = Gateway(root, allow_write=True)
    try:
        content = (
            "def scope(vault, authority):\n"
            "    token = vault.set(authority)\n"
            "    try:\n"
            "        yield\n"
            "    finally:\n"
            "        vault.reset(token)\n"
        )
        with pytest.raises(GatewayError) as exc:
            gateway.create_file("bad.py", content)
        assert exc.value.code == "sensitive_content"
    finally:
        gateway.close()


def test_rebound_contextvar_not_exempt(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    gateway = Gateway(root, allow_write=True)
    try:
        content = _contextvar_source() + "\nactive = make_unknown()\n"
        with pytest.raises(GatewayError) as exc:
            gateway.create_file("bad.py", content)
        assert exc.value.code == "sensitive_content"
    finally:
        gateway.close()


def test_audit_heuristic_only_scoped_and_hard_secrets_rejected(tmp_path):
    root = tmp_path / "project"
    (root / "src").mkdir(parents=True)
    (root / "other").mkdir()
    until = (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()
    gateway = Gateway(
        root, allow_write=True, write_paths=("src", "other"),
        sensitive_content_audit_paths=("src",),
        sensitive_content_audit_until=until,
    )
    try:
        candidate = "def f(vault):\n    token = vault.set(thing)\n"
        preview = gateway.create_file("src/a.py", candidate)
        assert preview["applied"] is False
        gateway.create_file("src/a.py", candidate, dry_run=False)
        with pytest.raises(GatewayError) as exc:
            gateway.create_file("other/b.py", candidate, dry_run=False)
        assert exc.value.code == "sensitive_content"
        with pytest.raises(GatewayError) as exc:
            gateway.create_file("src/ordinary.py", "password = 'hardcoded-secret'\n", dry_run=False)
        assert exc.value.code == "sensitive_content"
        assert gateway.info()["write_policy"]["sensitive_content"]["write_mode"] == "audit"
    finally:
        gateway.close()


def test_audit_expired_before_apply_rejects(tmp_path):
    root = tmp_path / "project"
    (root / "src").mkdir(parents=True)
    until = (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()
    gateway = Gateway(root, allow_write=True, write_paths=("src",),
                      sensitive_content_audit_paths=("src",),
                      sensitive_content_audit_until=until)
    try:
        payload = "def f(vault):\n    token = vault.set(value)\n"
        assert gateway.create_file("src/a.py", payload)["applied"] is False
        gateway.sensitive_audit.deadline = 0.0
        with pytest.raises(GatewayError) as exc:
            gateway.create_file("src/a.py", payload, dry_run=False)
        assert exc.value.code == "sensitive_content"
        assert not (root / "src" / "a.py").exists()
    finally:
        gateway.close()


def test_audit_expiry_during_install_prevents_commit(tmp_path, monkeypatch):
    from gateway import write_storage
    root = tmp_path / "project"
    (root / "src").mkdir(parents=True)
    until = (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()
    gateway = Gateway(root, allow_write=True, write_paths=("src",),
                      sensitive_content_audit_paths=("src",),
                      sensitive_content_audit_until=until)
    original_install = write_storage.install_file

    def expire_before_install(parent, name, raw, mode, verify, *, create):
        gateway.sensitive_audit.deadline = 0.0
        return original_install(parent, name, raw, mode, verify, create=create)

    try:
        monkeypatch.setattr(write_storage, "install_file", expire_before_install)
        with pytest.raises(GatewayError) as exc:
            gateway.create_file("src/a.py", "token = vault.set(value)\n", dry_run=False)
        assert exc.value.code == "sensitive_content"
        assert not (root / "src" / "a.py").exists()
    finally:
        gateway.close()


def test_hard_literal_on_same_line_as_contextvar_never_exempt(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    gateway = Gateway(root, allow_write=True)
    try:
        # A proven handle does not neutralize a distinct literal on its line.
        content = _contextvar_source().replace(
            "token = active.set(value)",
            "token = active.set(value); password = 'hardcoded'",
        )
        with pytest.raises(GatewayError) as exc:
            gateway.create_file("mixed.py", content)
        assert exc.value.code == "sensitive_content"
    finally:
        gateway.close()


def test_contextvar_reflective_rebinding_fails_closed(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    gateway = Gateway(root, allow_write=True)
    try:
        payload = _contextvar_source() + "\nglobals()['active'] = vault\n"
        with pytest.raises(GatewayError) as exc:
            gateway.create_file("dynamic.py", payload)
        assert exc.value.code == "sensitive_content"
    finally:
        gateway.close()


def test_contextvar_worker_parse_budget_falls_back_to_heuristic(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    gateway = Gateway(root, allow_write=True)
    try:
        content = _contextvar_source() + "# " + ("x" * 32768) + "\n"
        with pytest.raises(GatewayError) as exc:
            gateway.create_file("large.py", content)
        assert exc.value.code == "sensitive_content"
    finally:
        gateway.close()


def test_http_contextvar_cycle_and_temporary_audit(tmp_path):
    from starlette.testclient import TestClient
    from gateway.http import create_app
    root = tmp_path / "project"
    (root / "src").mkdir(parents=True)
    until = (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()
    gateway = Gateway(root, allow_write=True, write_paths=("src",),
                      sensitive_content_audit_paths=("src",),
                      sensitive_content_audit_until=until)
    try:
        with TestClient(create_app(gateway, enable_mcp=False),
                        base_url="http://127.0.0.1:8765") as client:
            src = _contextvar_source()
            preview = client.post("/create", json={"path": "src/a.py", "content": src})
            assert preview.status_code == 200, preview.text
            apply = client.post("/create", json={"path": "src/a.py", "content": src, "dry_run": False})
            assert apply.status_code == 200, apply.text
            read = client.get("/read", params={"path": "src/a.py"})
            assert read.status_code == 200
            assert "token = active.set(value)" in read.json()["content"]
            assert client.get("/info").json()["write_policy"]["sensitive_content"]["write_mode"] == "audit"
            hard = client.post("/create", json={"path": "src/hard.py",
                                                "content": "password = 'hardcoded'\n",
                                                "dry_run": False})
            assert hard.status_code == 403 and hard.json()["error"] == "sensitive_content"
    finally:
        gateway.close()


@pytest.mark.parametrize("payload", [
    "token: opaque-bearer-value\n",
    "password: opaque-password-value\n",
    "client-key-data: BASE64PRIVATEKEY\n",
    "client-certificate-data: BASE64CERTIFICATE\n",
])
def test_audit_does_not_allow_structured_kubernetes_credentials(tmp_path, payload):
    root = tmp_path / "project"
    (root / "src").mkdir(parents=True)
    until = (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()
    gateway = Gateway(root, allow_write=True, write_paths=("src",),
                      sensitive_content_audit_paths=("src",),
                      sensitive_content_audit_until=until)
    try:
        with pytest.raises(GatewayError) as exc:
            gateway.create_file("src/cluster.yaml", payload, dry_run=False)
        assert exc.value.code == "sensitive_content"
        assert not (root / "src" / "cluster.yaml").exists()
    finally:
        gateway.close()


def test_audit_expires_during_temporary_file_fsync(tmp_path, monkeypatch):
    from gateway import write_storage
    root = tmp_path / "project"
    (root / "src").mkdir(parents=True)
    until = (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()
    gateway = Gateway(root, allow_write=True, write_paths=("src",),
                      sensitive_content_audit_paths=("src",),
                      sensitive_content_audit_until=until)
    original_fsync = write_storage.os.fsync
    calls = []

    def expire_on_fsync(fd):
        result = original_fsync(fd)
        calls.append(fd)
        gateway.sensitive_audit.deadline = 0.0
        return result

    try:
        monkeypatch.setattr(write_storage.os, "fsync", expire_on_fsync)
        with pytest.raises(GatewayError) as exc:
            gateway.create_file("src/a.py", "token = vault.set(value)\n", dry_run=False)
        assert exc.value.code == "sensitive_content"
        assert calls
        assert not (root / "src" / "a.py").exists()
    finally:
        gateway.close()


@pytest.mark.parametrize("mutation", [
    "vars()['active'] = unknown_runtime_object()",
    "import builtins\nbuiltins.vars()['active'] = unknown_runtime_object()",
    "import sys\nsys.modules[__name__].__dict__['active'] = unknown_runtime_object()",
    "reflect = globals\nreflect()['active'] = unknown_runtime_object()",
])
def test_contextvar_dynamic_module_rebinding_must_not_receive_exemption(tmp_path, mutation):
    """Only source-level proven stable ContextVar instances can be exempted.

    No source code in this payload is executed by the gateway. A computed
    namespace rewrite should conservatively preserve the original heuristic.
    """
    root = tmp_path / "project"
    root.mkdir()
    gateway = Gateway(root, allow_write=True)
    try:
        source = _contextvar_source() + "\n" + mutation + "\n"
        with pytest.raises(GatewayError) as exc:
            gateway.create_file("dynamic_binding.py", source, dry_run=False)
        assert exc.value.code == "sensitive_content"
        assert not (root / "dynamic_binding.py").exists()
    finally:
        gateway.close()
