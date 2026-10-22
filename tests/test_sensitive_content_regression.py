"""RED contract for path-aware sensitive detection and bounded, scoped audit."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib

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
            gateway.create_file("src/password.py", "password = 'hardcoded-secret'\n", dry_run=False)
        # A protected filename or hard credential must still be denied.
        assert exc.value.code in ("blocked_path", "sensitive_content")
        assert gateway.info()["write_policy"]["sensitive_content"]["write_mode"] == "audit"
    finally:
        gateway.close()
