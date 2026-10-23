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
@pytest.mark.parametrize("suffix", [".py", ".pyi"])
@pytest.mark.parametrize("bom", ["", "\ufeff"])
@pytest.mark.parametrize("newline", ["\n", "\r\n", "\r"])
def test_unrecoverable_multiline_decorator_literal_has_actual_hard_line(
    tmp_path, newline, bom, suffix,
):
    """Malformed module + unparseable decorator statement cannot expose RHS."""
    root = tmp_path / "project"
    root.mkdir()
    source = bom + newline.join((
        "@wrapper(",
        '    password="abc"',
        ")",
        "def work():",
        "    pass",
        'if True print("broken")',
        "",
    ))
    raw = source.encode("utf-8")
    path = "sample" + suffix
    target = root / path
    target.write_bytes(raw)
    gateway = Gateway(root, allow_write=True)
    try:
        flags, findings = gateway._visibility.classify(path, raw)
        assert (2, "hard") in findings, (flags, findings)
        assert flags[1] is True, (flags, findings)
        read = gateway.read_file(path)
        assert read["total_lines"] == 6
        assert read["file_sha256"] == hashlib.sha256(raw).hexdigest()
        assert 'password="abc"' not in read["content"]
        assert "abc" not in read["content"]
        assert gateway.search_files("abc", file_glob=path)["matches"] == []
        for dry_run in (True, False):
            with pytest.raises(GatewayError) as failure:
                gateway.replace_text(
                    path, 'password="abc"', 'password="def"',
                    read["file_sha256"], dry_run=dry_run,
                )
            assert failure.value.code in ("match_count", "sensitive_content")
            with pytest.raises(GatewayError) as failure:
                gateway.write_file(
                    path, source.replace("abc", "def"),
                    read["file_sha256"], dry_run=dry_run,
                )
            assert failure.value.code == "sensitive_content"
            with pytest.raises(GatewayError) as failure:
                gateway.create_file("new" + suffix, source, dry_run=dry_run)
            assert failure.value.code == "sensitive_content"
        assert target.read_bytes() == raw
        assert not (root / ("new" + suffix)).exists()

        preview = gateway.replace_text(
            path, "    pass", "    return None", read["file_sha256"], dry_run=True,
        )
        assert "abc" not in preview["diff"]
        assert target.read_bytes() == raw
        applied = gateway.replace_text(
            path, "    pass", "    return None", read["file_sha256"], dry_run=False,
        )
        assert applied["applied"] is True
        assert "abc" not in applied["diff"]
        assert target.read_bytes() == source.replace(
            "    pass", "    return None",
        ).encode("utf-8")
        assert gateway.read_file(path)["file_sha256"] == hashlib.sha256(
            target.read_bytes()
        ).hexdigest()
    finally:
        gateway.close()


@pytest.mark.parametrize("newline", ["\n", "\r\n", "\r"])
def test_unrecoverable_fragment_split_field_literal_never_exposes_value(
    tmp_path, newline,
):
    """Even if a lexical field/value crosses physical lines, hide the evidence."""
    root = tmp_path / "project"
    root.mkdir()
    source = newline.join((
        "@wrapper(",
        "    password=",
        '    "abc"',
        ")",
        "def work():",
        "    pass",
        'if True print("broken")',
        "",
    ))
    raw = source.encode("utf-8")
    (root / "sample.py").write_bytes(raw)
    gateway = Gateway(root, allow_write=True)
    try:
        flags, findings = gateway._visibility.classify("sample.py", raw)
        assert flags[2], (flags, findings)
        assert any(kind == "hard" for _, kind in findings), findings
        read = gateway.read_file("sample.py")
        assert "abc" not in read["content"]
        assert gateway.search_files("abc", file_glob="sample.py")["matches"] == []
        with pytest.raises(GatewayError) as error:
            gateway.create_file("new.py", source, dry_run=False)
        assert error.value.code == "sensitive_content"
    finally:
        gateway.close()


@pytest.mark.parametrize("newline", ["\n", "\r\n", "\r"])
@pytest.mark.parametrize("dynamic", ["get_token()", "config.password"])
def test_unrecoverable_decorator_dynamic_source_is_not_name_only_secret(
    tmp_path, newline, dynamic,
):
    root = tmp_path / "project"
    root.mkdir()
    source = newline.join((
        "@wrapper(",
        "    password=" + dynamic,
        ")",
        "def work():",
        "    pass",
        'if True print("broken")',
        "",
    ))
    raw = source.encode("utf-8")
    gateway = Gateway(root, allow_write=True)
    try:
        flags, findings = gateway._visibility.classify("sample.py", raw)
        assert not any(flags) and not findings, (flags, findings)
        assert gateway.create_file("sample.py", source, dry_run=False)["applied"]
        read = gateway.read_file("sample.py")
        assert read["redacted_lines"] == 0
        assert dynamic in read["content"]
        assert gateway.search_files(dynamic, file_glob="sample.py")["matches"]
        assert (root / "sample.py").read_bytes() == raw
    finally:
        gateway.close()
