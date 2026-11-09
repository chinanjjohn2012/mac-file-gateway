"""V3 source credential values and scoped Audit — preserved Gateway regressions."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import pytest

from gateway.core import Gateway, GatewayError


@pytest.mark.parametrize("fence", ["```python", "~~~py", "```python3"])
@pytest.mark.parametrize("assignment", ["token = get_token()", "token = active.set(value)"])
@pytest.mark.parametrize("bom,newline", [("", "\n"), ("\ufeff", "\r\n")])
def test_markdown_python_dynamic_assignment_roundtrip(tmp_path, fence, assignment, bom, newline):
    content = bom + f"# Checkpoint\n\n{fence}\n{assignment}\n{fence[:3]}\n".replace("\n", newline)
    gateway = Gateway(tmp_path, allow_write=True)
    try:
        assert not gateway.create_file("DEV_CHECKPOINT.md", content)["applied"]
        assert not (tmp_path / "DEV_CHECKPOINT.md").exists()
        assert gateway.create_file("DEV_CHECKPOINT.md", content, dry_run=False)["applied"]
        read = gateway.read_file("DEV_CHECKPOINT.md")
        assert read["redacted_lines"] == 0
        assert f"4: {assignment}" in read["content"]
        assert gateway.search_files(assignment)["matches"][0]["line"] == 4
        updated = gateway.replace_text(
            "DEV_CHECKPOINT.md", assignment, "token = read_handle()",
            read["file_sha256"], dry_run=False,
        )
        assert updated["applied"]
        assert assignment in updated["diff"]
        assert (tmp_path / "DEV_CHECKPOINT.md").read_bytes() == content.replace(assignment, "token = read_handle()").encode()
    finally:
        gateway.close()


def test_markdown_checkpoint_evidence_authorization_reference(tmp_path):
    old = "Next role: DEVELOPER A, provided current r0012 is not frozen, gateway remains readable and applicable risk-specific authorizations are verified."
    evidence = (
        "Detailed TEST_RISK_MATRIX with original direct evidence and separate NOT_RUN impact/authorization: "
        "logs/cp3-g41-shared-asgi-local-developer-20261026.md. "
        "G41 earlier missing real SQL-backed shared ASGI route test is now directly covered on R9 local scope, "
        "but legal DM model itself remains stubbed; actual external UI/TCP and real IM/S3/IAM/old Worker/real egress "
        "remain R3 PRODUCTION_NOT_RUN. G20-G22 real isolated worker process termination and G29 currently running "
        "Redis old-AOF rollback/process restart remain NOT_RUN pending complete current operation-specific "
        "process/backup/consumer impact, before-state and recovery plan; historical fault injection/isolated Redis "
        "cannot substitute. No FULL_LOCAL_DB_REDIS_INTEGRATION_PASS or independent FULL_CODE_REVIEW_PASS. "
        "CP0 DONE; CP1/CP2 PARTIAL, with G41 local ASGI strengthened; CP3 PARTIAL_NATIVE_TESTED; CP4 NOT_READY."
    )
    original = "# Checkpoint\n" + "\n" * 643 + old + "\n"
    (tmp_path / "DEV_CHECKPOINT.md").write_text(original)
    new = old + "\n" * 10 + evidence
    gateway = Gateway(tmp_path, allow_write=True)
    try:
        sha = gateway.read_file("DEV_CHECKPOINT.md")["file_sha256"]
        preview = gateway.replace_text("DEV_CHECKPOINT.md", old, new, sha)
        assert not preview["applied"]
        assert (tmp_path / "DEV_CHECKPOINT.md").read_text() == original
        applied = gateway.replace_text("DEV_CHECKPOINT.md", old, new, sha, dry_run=False)
        assert applied["applied"]
        assert (tmp_path / "DEV_CHECKPOINT.md").read_text().splitlines()[654] == evidence
        read = gateway.read_file("DEV_CHECKPOINT.md", start_line=655)
        assert read["redacted_lines"] == 0
        assert f"655: {evidence}" in read["content"]
    finally:
        gateway.close()


@pytest.mark.parametrize("content", [
    "```python\ntoken = get_token(); password = 'hardcoded'\n```\n",
    "```python\ntoken = (\n    'hardcoded'\n)\n```\n",
    "```python\nvalue = 'ghp_' + 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'\n```\n",
    "```python\n-----BEGIN PRIVATE KEY-----\nprivate-key-body\n```\n",
    "impact/authorization: logs/evidence.md. password = 'hardcoded'\n",
    "impact/authorization: Bearer actual-credential-value\n",
    "impact/authorization: logs/evidence.md. authorization: Bearer actual-credential-value\n",
    "```python\ntoken = get_token(); payload = {'password': 'hardcoded'}\n```\n",
])
def test_markdown_exemptions_do_not_allow_credentials(tmp_path, content):
    gateway = Gateway(tmp_path, allow_write=True)
    try:
        with pytest.raises(GatewayError) as exc:
            gateway.create_file("DEV_CHECKPOINT.md", content, dry_run=False)
        assert exc.value.code == "sensitive_content"
        assert not (tmp_path / "DEV_CHECKPOINT.md").exists()
        (tmp_path / "DEV_CHECKPOINT.md").write_text(content)
        assert gateway.read_file("DEV_CHECKPOINT.md")["redacted_lines"] > 0
    finally:
        gateway.close()


@pytest.mark.parametrize("content", [
    "```text\ntoken = get_token()\n```\n",
    "```\ntoken = get_token()\n```\n",
    "```python\ntoken = get_token()\n",
    "````text\n```python\ntoken = get_token()\n```\n````\n",
])
def test_markdown_requires_closed_explicit_python_fence(tmp_path, content):
    gateway = Gateway(tmp_path, allow_write=True)
    try:
        with pytest.raises(GatewayError) as exc:
            gateway.create_file("DEV_CHECKPOINT.md", content)
        assert exc.value.code == "sensitive_content"
    finally:
        gateway.close()


def test_markdown_python_scan_failure_never_grants_an_exemption(tmp_path, monkeypatch):
    from gateway import python_values
    monkeypatch.setattr(python_values, "MAX_TOKENS", 1)
    content = "```python\ntoken = get_token()\n```\n"
    gateway = Gateway(tmp_path, allow_write=True)
    try:
        with pytest.raises(GatewayError) as exc:
            gateway.create_file("DEV_CHECKPOINT.md", content, dry_run=False)
        assert exc.value.details["rule_id"] == "SCAN_UNAVAILABLE"
        assert not (tmp_path / "DEV_CHECKPOINT.md").exists()
    finally:
        gateway.close()


def test_markdown_fence_edit_cannot_expose_multiline_credential(tmp_path):
    content = "```python\ntoken = (\n    'hardcoded'\n)\n```\n"
    (tmp_path / "DEV_CHECKPOINT.md").write_text(content)
    gateway = Gateway(tmp_path, allow_write=True)
    try:
        source = gateway.read_file("DEV_CHECKPOINT.md")
        assert "hardcoded" not in source["content"]
        with pytest.raises(GatewayError) as exc:
            gateway.replace_text("DEV_CHECKPOINT.md", "```python", "```text", source["file_sha256"], dry_run=False)
        assert exc.value.code == "sensitive_content"
        assert (tmp_path / "DEV_CHECKPOINT.md").read_text() == content
    finally:
        gateway.close()


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
        new = "token = active.set(42)"  # statically inert new value (no overloaded __add__)
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


def test_runtime_vault_set_reset_pair_is_not_name_only_sensitive(tmp_path):
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
        assert gateway.create_file("bad.py", content, dry_run=False)["applied"]
        read = gateway.read_file("bad.py")
        assert read["redacted_lines"] == 0
        assert "token = " in read["content"]
    finally:
        gateway.close()


def test_contextvar_identity_changes_do_not_create_source_credentials(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    gateway = Gateway(root, allow_write=True)
    try:
        content = _contextvar_source() + "\nactive = make_unknown()\n"
        assert gateway.create_file("bad.py", content, dry_run=False)["applied"]
        read = gateway.read_file("bad.py")
        assert read["redacted_lines"] == 0
        assert "token = " in read["content"]
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
        candidate = 'token = f"{runtime}" +\n'
        preview = gateway.create_file("src/a.py", candidate)
        assert preview["applied"] is False
        gateway.create_file("src/a.py", candidate, dry_run=False)
        with pytest.raises(GatewayError) as exc:
            gateway.create_file("other/b.py", candidate, dry_run=False)
        assert exc.value.code == "sensitive_content"
        gateway.create_file("src/ordinary.py", "password = 'hardcoded-secret'\n", dry_run=False)
        assert "hardcoded-secret" in gateway.read_file("src/ordinary.py")["content"]
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
        payload = 'token = f"{runtime}" +\n'
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
            gateway.create_file("src/a.py", 'token = f"{runtime}" +\n', dry_run=False)
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


def test_reflective_rebinding_without_literals_remains_visible(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    gateway = Gateway(root, allow_write=True)
    try:
        payload = _contextvar_source() + "\nglobals()['active'] = vault\n"
        assert gateway.create_file("dynamic.py", payload, dry_run=False)["applied"]
        assert gateway.read_file("dynamic.py")["redacted_lines"] == 0
    finally:
        gateway.close()


def test_large_python_source_above_removed_worker_limit_is_allowed(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    gateway = Gateway(root, allow_write=True)
    try:
        content = _contextvar_source() + "# " + ("x" * 32768) + "\n"
        assert gateway.create_file("large.py", content, dry_run=False)["applied"]
        read = gateway.read_file("large.py")
        assert read["redacted_lines"] == 0
        assert "token = active.set(value)" in read["content"]
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
            assert hard.status_code == 200
            read_hard = client.get("/read", params={"path": "src/hard.py"})
            assert "password = 'hardcoded'" in read_hard.json()["content"]
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
        applied = gateway.create_file("src/cluster.yaml", payload, dry_run=False)
        assert applied["applied"] is True
        assert payload.strip() in gateway.read_file("src/cluster.yaml")["content"]
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
            gateway.create_file("src/a.py", 'token = f"{runtime}" +\n', dry_run=False)
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
def test_dynamic_module_rebinding_does_not_imply_hardcoded_value(tmp_path, mutation):
    """Only source-level proven stable ContextVar instances can be exempted.

    No source code in this payload is executed by the gateway. A computed
    namespace rewrite should conservatively preserve the original heuristic.
    """
    root = tmp_path / "project"
    root.mkdir()
    gateway = Gateway(root, allow_write=True)
    try:
        source = _contextvar_source() + "\n" + mutation + "\n"
        assert gateway.create_file("dynamic_binding.py", source, dry_run=False)["applied"]
        read = gateway.read_file("dynamic_binding.py")
        assert read["redacted_lines"] == 0
        assert "token = active.set(value)" in read["content"]
    finally:
        gateway.close()


@pytest.mark.parametrize("source", [
    "token, attempt = attempts[0]['claim_token'], attempts[0]['id']\n",
    "token = attempts[0]['claim_token']\n",
    "password = records['password']\n",
    "token = records['claim_token'][0]\n",
    "[token, attempt] = [attempts[0]['claim_token'], attempts[0]['id']]\n",
])
def test_dynamic_lookup_keys_remain_visible_and_writable(tmp_path, source):
    gateway = Gateway(tmp_path, allow_write=True)
    try:
        preview = gateway.create_file('sample.py', source)
        assert preview['applied'] is False
        assert not (tmp_path / 'sample.py').exists()
        gateway.create_file('sample.py', source, dry_run=False)
        read = gateway.read_file('sample.py')
        assert read['redacted_lines'] == 0
        assert source.strip() in read['content']
        assert gateway.search_files('claim_token' if 'claim_token' in source else 'password',
                                    file_glob='sample.py')['matches']
    finally:
        gateway.close()


@pytest.mark.parametrize("source", [
    "token = ['synthetic-secret'][0]\n",
    "token = {'value': 'synthetic-secret'}['value']\n",
    "token = 'synthetic-secret'[:]\n",
    "token = records['claim_token'] or 'synthetic-secret'\n",
    "token = os.getenv('TOKEN', 'synthetic-secret')\n",
    "token = records['sk-1234567890abcdefghijklmnopqrstuvwxyz']\n",
])
def test_lookup_change_preserves_hard_literal_protection(tmp_path, source):
    gateway = Gateway(tmp_path, allow_write=True)
    try:
        with pytest.raises(GatewayError) as error:
            gateway.create_file('sample.py', source)
        assert error.value.details['rule_id'] == 'CREDENTIAL_HARD'
        (tmp_path / 'sample.py').write_text(source)
        assert gateway.read_file('sample.py')['redacted_lines'] > 0
    finally:
        gateway.close()


def test_active_audit_shows_hard_and_heuristic_lines_until_expiry(tmp_path):
    root = tmp_path / "project"
    (root / "src").mkdir(parents=True)
    (root / "other").mkdir()
    until = (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()
    gateway = Gateway(
        root, allow_write=True, write_paths=("src", "other"),
        sensitive_content_audit_paths=("src",),
        sensitive_content_audit_until=until,
    )
    hard = "password = 'hardcoded-secret'\n"
    heuristic = 'token = f"{runtime}" +\n'
    (root / "src" / "hard.py").write_text(hard)
    (root / "src" / "soft.py").write_text(heuristic)
    (root / "other" / "hard.py").write_text(hard)
    try:
        assert gateway.info()["write_policy"]["sensitive_content"]["read_redaction_enabled"] is True
        shown = gateway.read_file("src/hard.py")
        assert shown["redacted_lines"] == 0
        assert "hardcoded-secret" in shown["content"]
        _flags, findings = gateway._visibility.classify("src/hard.py", hard.encode())
        assert any(kind == "hard" for _number, kind in findings)
        assert "runtime" in gateway.read_file("src/soft.py")["content"]
        assert gateway.search_files("hardcoded-secret", file_glob="hard.py")["matches"]
        hidden = gateway.read_file("other/hard.py")
        assert "hardcoded-secret" not in hidden["content"]
        assert hidden["redacted_lines"] == 1
        gateway.sensitive_audit.deadline = 0.0
        expired = gateway.read_file("src/hard.py")
        assert "hardcoded-secret" not in expired["content"]
        assert expired["redacted_lines"] == 1
    finally:
        gateway.close()


def test_active_audit_writes_hard_lines_without_a_pending_grant(tmp_path, capsys):
    root = tmp_path / "project"
    (root / "src").mkdir(parents=True)
    (root / "other").mkdir()
    until = (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()
    gateway = Gateway(
        root, allow_write=True, write_paths=("src", "other"),
        sensitive_content_audit_paths=("src",),
        sensitive_content_audit_until=until,
    )
    hard = "password = 'hardcoded-secret'\n"
    try:
        preview = gateway.create_file("src/hard.py", hard)
        assert preview["applied"] is False
        assert "hardcoded-secret" in preview["diff"]
        assert preview["warnings"] == ["Temporary heuristic write audit active; inspect content locally."]
        applied = gateway.create_file("src/hard.py", hard, dry_run=False)
        assert applied["applied"] is True
        assert "sensitive approval" not in capsys.readouterr().err
        read = gateway.read_file("src/hard.py")
        replaced = gateway.replace_text(
            "src/hard.py", "hardcoded-secret", "other-secret",
            read["file_sha256"], dry_run=False,
        )
        assert replaced["applied"] is True
        assert "other-secret" in gateway.read_file("src/hard.py")["content"]
        current = gateway.read_file("src/hard.py")
        overwritten = gateway.write_file(
            "src/hard.py", "password = 'third-secret'\n", current["file_sha256"], dry_run=False,
        )
        assert overwritten["applied"] is True
        with pytest.raises(GatewayError) as outside:
            gateway.create_file("other/hard.py", hard, dry_run=False)
        assert outside.value.details["rule_id"] == "CREDENTIAL_HARD"
        assert not (root / "other" / "hard.py").exists()
        gateway.sensitive_audit.deadline = 0.0
        with pytest.raises(GatewayError) as expired:
            gateway.create_file("src/next.py", hard, dry_run=False)
        assert expired.value.details["rule_id"] == "CREDENTIAL_HARD"
        assert not (root / "src" / "next.py").exists()
    finally:
        gateway.close()


def test_hard_literal_without_audit_stays_rejected_and_redacted(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    gateway = Gateway(root, allow_write=True)
    hard = "password = 'hardcoded-secret'\n"
    try:
        with pytest.raises(GatewayError) as blocked:
            gateway.create_file("sample.py", hard, dry_run=False)
        assert blocked.value.details["rule_id"] == "CREDENTIAL_HARD"
        assert not (root / "sample.py").exists()
        (root / "sample.py").write_text(hard)
        assert "hardcoded-secret" not in gateway.read_file("sample.py")["content"]
    finally:
        gateway.close()


def test_hard_write_is_rejected_when_audit_expires_before_install(tmp_path, monkeypatch):
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
            gateway.create_file("src/hard.py", "password = 'hardcoded-secret'\n", dry_run=False)
        assert exc.value.code == "sensitive_content"
        assert "before install" in str(exc.value)
        assert not (root / "src" / "hard.py").exists()
    finally:
        gateway.close()
