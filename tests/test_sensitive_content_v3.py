"""V3 value-based credential classification — real Gateway RED/GREEN contract.

This suite is written against the design-approved product behavior. During RED
the old V2 name-based classifier is expected to fail the ordinary-reference
and split-key tests. None of the scanned snippets is imported or executed.
"""
from __future__ import annotations

import hashlib

import pytest

from gateway.core import Gateway, GatewayError, _sensitive_line_flags
from gateway.visibility import SensitiveContentPolicy


@pytest.mark.parametrize("line", [
    "token = active.set(value)",
    "token = vault.set(authority)",
    "token = get_token()",
    "password = config.password",
    'api_key = os.getenv("API_KEY")',
    'api_key = os.environ.get("API_KEY")',
    'api_key = os.environ["API_KEY"]',
    "token = None",
    'token = f"{runtime}"',
    "# token = get_token()",
])
@pytest.mark.parametrize("newline", ["\n", "\r\n"])
def test_v3_runtime_references_are_visible_writable_and_searchable(tmp_path, line, newline):
    root = tmp_path / "workspace"
    root.mkdir()
    source = ("def probe(value):" + newline + "    " + line + newline
              if not line.startswith("#") else line + newline)
    gateway = Gateway(root, allow_write=True)
    try:
        preview = gateway.create_file("ordinary.py", source, dry_run=True)
        assert preview["applied"] is False
        applied = gateway.create_file("ordinary.py", source, dry_run=False)
        assert applied["applied"] is True
        read = gateway.read_file("ordinary.py")
        assert read["redacted_lines"] == 0
        assert line in read["content"]
        matches = gateway.search_files(line, file_glob="ordinary.py")
        assert matches["matches"], line
        assert (root / "ordinary.py").read_bytes() == source.encode("utf-8")
    finally:
        gateway.close()


@pytest.mark.parametrize("source", [
    'def connect(api_key="abc"): pass\n',
    'async def send(*, password="secret"): pass\n',
    'identity = lambda token="abc": token\n',
    'def connect(base, api_key="literal"): pass\n',
    'def f(*, unused=None, password=b"literal"): pass\n',
    '# password = "abc"\n',
    '# api_key: "actual-key"\n',
    '"""Credentials:\napi_key = "literal"\n"""\n',
    'def f():\n    """password = "abc" """\n    pass\n',
    'token = "prefix-" + part\n',
    'token = f"prefix-{runtime}"\n',
    'token = wrapper("literal")\n',
    'api_key = os.getenv("API_KEY", "fallback-secret")\n',
    'api_key = os.environ.get("API_KEY", "fallback-secret")\n',
    'request(token="literal")\n',
    'payload = {"password": "literal"}\n',
    'token = ("ab" "cd")\n',
])
def test_v3_source_credential_literals_are_hard(tmp_path, source):
    root = tmp_path / "workspace"
    root.mkdir()
    policy = SensitiveContentPolicy()
    flags, findings = policy.classify("credentials.py", source.encode("utf-8"))
    assert any(flags)
    assert "hard" in [kind for _, kind in findings]
    gateway = Gateway(root, allow_write=True)
    try:
        with pytest.raises(GatewayError) as exc:
            gateway.create_file("credentials.py", source, dry_run=False)
        assert exc.value.code == "sensitive_content"
        assert not (root / "credentials.py").exists()
        (root / "credentials.py").write_text(source, encoding="utf-8")
        seen = gateway.read_file("credentials.py")
        assert seen["redacted_lines"] >= 1
        assert "[REDACTED]" in seen["content"]
        assert gateway.search_files('literal', file_glob="credentials.py")["matches"] == []
    finally:
        gateway.close()


@pytest.mark.parametrize("source", [
    'marker = ("ghp_" "ABCDEFGHIJKLMNOPQRSTUVWX")\n',
    'marker = "ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWX"\n',
    'marker = ("ghp_"\n          "ABCDEFGHIJKLMNOPQRSTUVWX")\n',
])
def test_v3_known_secret_formats_split_across_literals_are_hard(source):
    flags, findings = SensitiveContentPolicy().classify("module.py", source.encode("utf-8"))
    assert any(flags), "Known key assembled statically must be Hard"
    assert "hard" in [kind for _, kind in findings]


@pytest.mark.parametrize("source", [
    'api_key = os.environ["API_KEY"]\n',
    'def connect(api_key=os.environ["API_KEY"]): pass\n',
    'request(token=os.environ.get("API_KEY"))\n',
    'lambda_fn = lambda token=get_token(): token\n',
    'def connect(api_key=None): pass\n',
    '"""This documents the password variable, not a literal credential."""\n',
    '# password may be loaded from the environment\n',
    'help_text = "the password variable is documented here"\n',
])
def test_v3_no_credential_value_evidence_is_not_redacted(source):
    flags, findings = SensitiveContentPolicy().classify("ordinary.py", source.encode("utf-8"))
    assert not any(flags), (source, findings)
    assert not findings


@pytest.mark.parametrize("ext", ["json", "yaml", "yml", "js", "txt"])
@pytest.mark.parametrize("source", [
    'token = get_token()\n',
    'password: $PASSWORD\n',
    'api_key: "hardcoded"\n',
    'password = "literal"\n',
])
def test_v3_nonpython_visibility_stays_identical_to_v2(ext, source):
    flags, _ = SensitiveContentPolicy().classify("sample." + ext, source.encode())
    assert flags == _sensitive_line_flags(source), (ext, source)


@pytest.mark.parametrize("newline", ["\n", "\r\n"])
@pytest.mark.parametrize("bom", ["", "\ufeff"])
def test_v3_normal_python_bom_crlf_create_edit_whole_write(tmp_path, newline, bom):
    root = tmp_path / "workspace"
    root.mkdir()
    initial = bom + ('token = get_token()\n' + 'status = 1\n').replace('\n', newline)
    gateway = Gateway(root, allow_write=True)
    try:
        gateway.create_file("mod.py", initial, dry_run=False)
        first = gateway.read_file("mod.py")
        assert first["redacted_lines"] == 0
        updated = initial.replace("status = 1", "status = 2")
        gateway.replace_text("mod.py", "status = 1", "status = 2",
                             first["file_sha256"], dry_run=False)
        assert (root / "mod.py").read_bytes() == updated.encode("utf-8")
        sha = hashlib.sha256(updated.encode()).hexdigest()
        final = updated + "# benign" + newline
        gateway.write_file("mod.py", final, sha, dry_run=False)
        assert (root / "mod.py").read_bytes() == final.encode()
    finally:
        gateway.close()
