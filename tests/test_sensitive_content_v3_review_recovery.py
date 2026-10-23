"""Regression contract for V3 malformed-source statement recovery.

Fixtures are data files, never imported or executed as Python source.
These tests exercise public Gateway read, search, and write boundaries.
"""
from __future__ import annotations

import hashlib

import pytest

from gateway.core import Gateway, GatewayError


@pytest.mark.parametrize("newline", ["\n", "\r\n", "\r"])
def test_invalid_module_keyword_secret_marked_at_absolute_line(tmp_path, newline):
    root = tmp_path / "project"
    root.mkdir()
    source = newline.join((
        "header = 0",
        'consume(password="abc")',
        'if True print("broken")',
        "",
    ))
    raw = source.encode("utf-8")
    target = root / "sample.py"
    target.write_bytes(raw)
    gateway = Gateway(root, allow_write=True)
    try:
        flags, findings = gateway._visibility.classify("sample.py", raw)
        assert flags == [False, True, False], (flags, findings)
        assert (2, "hard") in findings

        read = gateway.read_file("sample.py")
        assert read["file_sha256"] == hashlib.sha256(raw).hexdigest()
        assert "abc" not in read["content"]
        assert gateway.search_files("abc", file_glob="sample.py")["matches"] == []

        for dry_run in (True, False):
            with pytest.raises(GatewayError) as failure:
                gateway.replace_text(
                    "sample.py", 'password="abc"', 'password="def"',
                    read["file_sha256"], dry_run=dry_run,
                )
            assert failure.value.code in ("match_count", "sensitive_content")
            with pytest.raises(GatewayError) as failure:
                gateway.create_file("new.py", source, dry_run=dry_run)
            assert failure.value.code == "sensitive_content"
        assert target.read_bytes() == raw
        assert not (root / "new.py").exists()
    finally:
        gateway.close()


@pytest.mark.parametrize("newline", ["\n", "\r\n"])
def test_invalid_module_recovered_docstring_still_protects_literal(tmp_path, newline):
    root = tmp_path / "project"
    root.mkdir()
    source = newline.join((
        '"""password = "abc" """',
        'if True print("broken")',
        "",
    ))
    raw = source.encode("utf-8")
    target = root / "sample.py"
    target.write_bytes(raw)
    gateway = Gateway(root, allow_write=True)
    try:
        flags, findings = gateway._visibility.classify("sample.py", raw)
        assert flags[0] and (1, "hard") in findings, findings
        read = gateway.read_file("sample.py")
        assert read["file_sha256"] == hashlib.sha256(raw).hexdigest()
        assert "abc" not in read["content"]
        assert gateway.search_files("abc", file_glob="sample.py")["matches"] == []
        with pytest.raises(GatewayError) as failure:
            gateway.create_file("new.py", source, dry_run=False)
        assert failure.value.code == "sensitive_content"
        assert target.read_bytes() == raw
        assert not (root / "new.py").exists()
    finally:
        gateway.close()
