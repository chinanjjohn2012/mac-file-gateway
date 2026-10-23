"""PR #52 V3 fixed-Head CODE_FIX_REQUIRED: P1 and P2 real Gateway RED/GREEN.

Source fixtures are never imported or executed. These tests intentionally
exercise the public Gateway read/search/preview/apply boundary and preserve
original raw file bytes, hidden-line provenance, hash and line numbering.
"""
from __future__ import annotations

import hashlib

import pytest

from gateway.core import Gateway, GatewayError
from gateway.visibility import SensitiveContentPolicy


_UNICODE_SEPARATORS = ["\u2028", "\u2029", "\u0085", "\x0b", "\x0c", "\x1c", "\x1d", "\x1e"]


@pytest.mark.parametrize("separator", _UNICODE_SEPARATORS)
@pytest.mark.parametrize("newline", ["\n", "\r\n", "\r"])
def test_p1_ast_physical_lines_never_expose_password_through_read_or_search(
    tmp_path, separator, newline,
):
    root = tmp_path / "project"
    root.mkdir()
    source = "# header" + separator + newline + 'password = "abc"' + newline
    raw = source.encode("utf-8")
    (root / "sample.py").write_bytes(raw)
    gateway = Gateway(root, allow_write=True)
    try:
        flags, findings = gateway._visibility.classify("sample.py", raw)
        assert flags == [False, True], (separator.encode("unicode_escape"), flags, findings)
        assert (2, "hard") in findings
        read = gateway.read_file("sample.py")
        assert read["total_lines"] == 2
        assert read["redacted_lines"] == 1
        assert 'password = "abc"' not in read["content"]
        assert "abc" not in read["content"]
        assert "[REDACTED]" in read["content"]
        assert read["file_sha256"] == hashlib.sha256(raw).hexdigest()
        found = gateway.search_files("abc", file_glob="sample.py")
        assert found["matches"] == []
        assert (root / "sample.py").read_bytes() == raw
    finally:
        gateway.close()


@pytest.mark.parametrize("separator", _UNICODE_SEPARATORS)
@pytest.mark.parametrize("bom", ["", "\ufeff"])
@pytest.mark.parametrize("newline", ["\n", "\r\n"])
def test_p1_hidden_original_bytes_cannot_be_replaced_or_shown_in_preview(
    tmp_path, separator, bom, newline,
):
    root = tmp_path / "project"
    root.mkdir()
    source = bom + "# header" + separator + newline + 'password = "abc"' + newline + "tail = 1" + newline
    raw = source.encode("utf-8")
    target = root / "sample.py"
    target.write_bytes(raw)
    gateway = Gateway(root, allow_write=True)
    try:
        read = gateway.read_file("sample.py")
        assert read["redacted_lines"] == 1
        assert "abc" not in read["content"]
        sha = read["file_sha256"]
        for dry_run in (True, False):
            with pytest.raises(GatewayError) as exc:
                gateway.replace_text(
                    "sample.py", 'password = "abc"', 'password = "def"',
                    sha, dry_run=dry_run,
                )
            assert exc.value.code in {"match_count", "sensitive_content"}
            assert target.read_bytes() == raw
            with pytest.raises(GatewayError) as exc:
                gateway.write_file(
                    "sample.py", source.replace("abc", "def"),
                    sha, dry_run=dry_run,
                )
            assert exc.value.code == "sensitive_content"
        preview = gateway.replace_text(
            "sample.py", "tail = 1", "tail = 2", sha, dry_run=True,
        )
        assert "abc" not in preview["diff"]
        assert "[REDACTED]" not in preview["diff"] or "abc" not in preview["diff"]
        applied = gateway.replace_text(
            "sample.py", "tail = 1", "tail = 2", sha, dry_run=False,
        )
        assert applied["applied"] is True
        assert "abc" not in applied["diff"]
        assert target.read_bytes() == source.replace("tail = 1", "tail = 2").encode("utf-8")
        assert gateway.read_file("sample.py")["redacted_lines"] == 1
    finally:
        gateway.close()


@pytest.mark.parametrize("newline", ["\n", "\r\n", "\r"])
@pytest.mark.parametrize("bom", ["", "\ufeff"])
def test_p1_preserved_physical_line_model_under_crlf_cr_bom(tmp_path, newline, bom):
    root = tmp_path / "project"
    root.mkdir()
    source = bom + "# benign" + newline + 'api_key = "literal"' + newline + "ordinary = 1" + newline
    raw = source.encode("utf-8")
    (root / "sample.pyi").write_bytes(raw)
    gateway = Gateway(root, allow_write=True)
    try:
        read = gateway.read_file("sample.pyi")
        assert read["total_lines"] == 3
        assert read["redacted_lines"] == 1
        assert 'api_key = "literal"' not in read["content"]
        assert read["file_sha256"] == hashlib.sha256(raw).hexdigest()
        assert gateway.search_files("literal", file_glob="sample.pyi")["matches"] == []
    finally:
        gateway.close()


_BROKEN_SOURCE = (
    'token = (\n'
    '    "abc"\n'
    ')\n'
    'if True print("broken")\n'
)


@pytest.mark.parametrize("newline", ["\n", "\r\n"])
def test_p2_syntaxerror_keeps_multiline_hard_value_visible_only_as_redaction(
    tmp_path, newline,
):
    root = tmp_path / "project"
    root.mkdir()
    source = _BROKEN_SOURCE.replace("\n", newline)
    raw = source.encode("utf-8")
    target = root / "sample.py"
    target.write_bytes(raw)
    gateway = Gateway(root, allow_write=True)
    try:
        flags, findings = gateway._visibility.classify("sample.py", raw)
        assert any(kind == "hard" for _, kind in findings), findings
        assert any(flags[:3])
        read = gateway.read_file("sample.py")
        assert "abc" not in read["content"]
        assert read["redacted_lines"] >= 1
        assert read["file_sha256"] == hashlib.sha256(raw).hexdigest()
        assert gateway.search_files("abc", file_glob="sample.py")["matches"] == []
        for dry_run in (True, False):
            with pytest.raises(GatewayError) as error:
                gateway.create_file("new.py", source, dry_run=dry_run)
            assert error.value.code == "sensitive_content"
            with pytest.raises(GatewayError) as error:
                gateway.replace_text(
                    "sample.py", '"abc"', '"def"',
                    read["file_sha256"], dry_run=dry_run,
                )
            assert error.value.code in {"match_count", "sensitive_content"}
        assert target.read_bytes() == raw
        assert not (root / "new.py").exists()
    finally:
        gateway.close()


@pytest.mark.parametrize("source", [
    'token = get_token()\nif True print("broken")\n',
    'password = config.password\nif True print("broken")\n',
    'api_key = os.environ["API_KEY"]\nif True print("broken")\n',
    'token = (\n    get_token()\n)\nif True print("broken")\n',
])
def test_p2_broken_python_dynamic_references_not_name_only_blocked(tmp_path, source):
    root = tmp_path / "project"
    root.mkdir()
    gateway = Gateway(root, allow_write=True)
    try:
        flags, findings = SensitiveContentPolicy().classify("sample.py", source.encode())
        assert not any(flags), findings
        assert gateway.create_file("sample.py", source, dry_run=False)["applied"]
        read = gateway.read_file("sample.py")
        assert read["redacted_lines"] == 0
        assert "broken" in read["content"]
    finally:
        gateway.close()


@pytest.mark.parametrize("source", [
    'token, label = get_token(), "ok"\n',
    'token, label = [get_token(), "ok"]\n',
    'label, token = "ok", get_token()\n',
    'token, (label, mode) = get_token(), ("ok", "ready")\n',
    'token, label = (\n    get_token(),\n    "ok",\n)\n',
])
def test_p2_unpacking_does_not_attribute_unrelated_literal_to_token(tmp_path, source):
    root = tmp_path / "project"
    root.mkdir()
    gateway = Gateway(root, allow_write=True)
    try:
        flags, findings = gateway._visibility.classify("sample.py", source.encode())
        assert not any(flags), findings
        assert gateway.create_file("sample.py", source, dry_run=True)["applied"] is False
        assert gateway.create_file("sample.py", source, dry_run=False)["applied"] is True
        read = gateway.read_file("sample.py")
        assert read["redacted_lines"] == 0
        assert gateway.search_files("ok", file_glob="sample.py")["matches"]
        preview = gateway.replace_text(
            "sample.py", "get_token()", "load_token()",
            read["file_sha256"], dry_run=True,
        )
        assert "ok" in preview["diff"]
        gateway.replace_text(
            "sample.py", "get_token()", "load_token()",
            read["file_sha256"], dry_run=False,
        )
        assert "load_token()" in gateway.read_file("sample.py")["content"]
    finally:
        gateway.close()


@pytest.mark.parametrize("source", [
    'token, label = "secret", "ok"\n',
    'label, token = "ok", "secret"\n',
    '(token, label) = ("secret", "ok")\n',
    'token, (label, mode) = "secret", ("ok", "ready")\n',
])
def test_p2_unpacking_still_protects_literal_assigned_to_credential(tmp_path, source):
    root = tmp_path / "project"
    root.mkdir()
    gateway = Gateway(root, allow_write=True)
    try:
        flags, findings = gateway._visibility.classify("sample.py", source.encode())
        assert any(flags) and any(kind == "hard" for _, kind in findings), findings
        with pytest.raises(GatewayError) as error:
            gateway.create_file("sample.py", source, dry_run=False)
        assert error.value.code == "sensitive_content"
        (root / "sample.py").write_text(source, encoding="utf-8")
        read = gateway.read_file("sample.py")
        assert read["redacted_lines"] >= 1
        assert "secret" not in read["content"]
        assert gateway.search_files("secret", file_glob="sample.py")["matches"] == []
    finally:
        gateway.close()
