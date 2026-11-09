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


@pytest.mark.parametrize("line", [
    "headers['Authorization'] = 'Bearer ' + access_value",
    "headers['Authorization'] = f'Bearer {access_value}'",
    "headers = {'Authorization': 'Bearer ' + access_value}",
    "headers = {'Authorization': f'Bearer {access_value}'}",
    "send(Authorization='Bearer ' + access_value)",
    "authorization = 'Bearer ' + access_value",
    "self.authorization = f'Bearer {access_value}'",
    "authorization, other = 'Bearer ' + access_value, 'ordinary'",
    "headers['Authorization'] = 'Bearer ' + os.environ['ACCESS_TOKEN']",
])
@pytest.mark.parametrize("ext", ["py", "pyi"])
def test_dynamic_bearer_authorization_is_writable_visible_and_searchable(tmp_path, line, ext):
    root = tmp_path / "workspace"
    root.mkdir()
    path = 'source.' + ext
    source = line + "\n# marker = 1\n"
    gateway = Gateway(root, allow_write=True)
    try:
        assert not gateway.create_file(path, source)["applied"]
        assert gateway.create_file(path, source, dry_run=False)["applied"]
        read = gateway.read_file(path)
        assert read["redacted_lines"] == 0
        assert line in read["content"]
        assert gateway.search_files("Bearer ", file_glob=path)["matches"]
        gateway.replace_text(path, "# marker = 1", "# marker = 2", read["file_sha256"], dry_run=False)
        updated = source.replace("# marker = 1", "# marker = 2")
        assert (root / path).read_bytes() == updated.encode()
        sha = gateway.read_file(path)["file_sha256"]
        gateway.write_file(path, updated + "# done\n", sha, dry_run=False)
        assert (root / path).read_bytes() == (updated + "# done\n").encode()
    finally:
        gateway.close()


@pytest.mark.parametrize("source", [
    "headers['Authorization'] = 'Bearer actual-literal-secret'\n",
    "headers['Authorization'] = 'Bearer ' + 'literal-secret'\n",
    "headers['Authorization'] = f\"Bearer {'literal-secret'}\"\n",
    "headers['Authorization'] = f'Bearer {access_value}literal-secret'\n",
    "headers['Authorization'] = 'Bearer ' + (access_value + 'literal-secret')\n",
    "headers = {'Authorization': 'Bearer ' + 'literal-secret'}\n",
    "send(Authorization='Bearer ' + 'literal-secret')\n",
    "token = 'Bearer ' + access_value\n",
    "headers['Authorization'] = 'Basic ' + access_value\n",
    "headers['Authorization'] = b'Bearer ' + access_value\n",
    "headers['Authorization'] = 'Bearer ' + os.getenv('ACCESS_TOKEN', 'literal-secret')\n",
    "headers['Authorization'] = 'Bearer ' + access_value; password = 'literal-secret'\n",
    "headers['Authorization'] = 'Bearer ' + str(123456789)\n",
    "headers['Authorization'] = f'Bearer {str(123456789)}'\n",
    "access_value = 'literal-secret'\nheaders['Authorization'] = 'Bearer ' + access_value\n",
    "first = 'literal-secret'\naccess_value = first\nheaders['Authorization'] = f'Bearer {access_value}'\n",
    "access_value = 'literal' + '-secret'\nheaders['Authorization'] = 'Bearer ' + access_value\n",
    "access_value = 'literal-secret' * 2\nheaders['Authorization'] = 'Bearer ' + access_value\n",
    "access_value = str(123456789)\nheaders['Authorization'] = 'Bearer ' + access_value\n",
    "access_value, other = 'literal-secret', None\nheaders['Authorization'] = 'Bearer ' + access_value\n",
    "def f(access_value='literal-secret'):\n    return {'Authorization': 'Bearer ' + access_value}\n",
    "os.environ['AUTH_VALUE'] = 'literal-secret'\nheaders['Authorization'] = 'Bearer ' + os.environ['AUTH_VALUE']\n",
    "os.environ['AUTH_VALUE'] = 'literal-secret'\naccess_value = os.getenv('AUTH_VALUE')\nheaders['Authorization'] = 'Bearer ' + access_value\n",
    "headers['Authorization'] = 'Bearer ' + get_token()\n",
    "for access_value in ['literal-secret']:\n    headers['Authorization'] = 'Bearer ' + access_value\n",
    "access_value = 'literal-secret'\ndef f():\n    global access_value\n    headers['Authorization'] = 'Bearer ' + access_value\n",
    "def outer():\n    access_value = get_value()\n    def inner():\n        nonlocal access_value\n        access_value = 'literal-secret'\n    inner()\n    headers['Authorization'] = 'Bearer ' + access_value\n",
    "values = {'AUTH_VALUE': 'literal-secret'}\nos.environ.update(values)\nheaders['Authorization'] = 'Bearer ' + os.environ['AUTH_VALUE']\n",
    "env = os.environ\nenv['AUTH_VALUE'] = 'literal-secret'\nheaders['Authorization'] = 'Bearer ' + os.environ['AUTH_VALUE']\n",
    "os.environ.setdefault('AUTH_VALUE', 'literal-secret')\nheaders['Authorization'] = 'Bearer ' + os.environ['AUTH_VALUE']\n",
    "class Vault:\n    def get(self):\n        return 'literal-secret'\naccess_value = Vault().get()\nheaders['Authorization'] = 'Bearer ' + access_value\n",
    "def build(access_value):\n    return {'Authorization': 'Bearer ' + access_value}\nbuild('literal-secret')\n",
    "def build(access_value):\n    return {'Authorization': 'Bearer ' + access_value}\nbuild(access_value='literal-secret')\n",
    "class Settings:\n    value = 'literal-secret'\naccess_value = Settings.value\nheaders['Authorization'] = 'Bearer ' + access_value\n",
    "env = os.environ\nenv.update({'AUTH_VALUE': 'literal-secret'})\nheaders['Authorization'] = 'Bearer ' + os.environ['AUTH_VALUE']\n",
    "env = os.environ\ne = env\ne['AUTH_VALUE'] = 'literal-secret'\nheaders['Authorization'] = 'Bearer ' + os.environ['AUTH_VALUE']\n",
    "def build(access_value):\n    return {'Authorization': 'Bearer ' + access_value}\nbuild(**{'access_value': 'literal-secret'})\n",
    "def build(*args):\n    access_value = args[0]\n    return {'Authorization': 'Bearer ' + access_value}\nbuild('literal-secret')\n",
    "key = 'AUTH_VALUE'\nos.environ[key] = 'literal-secret'\nheaders['Authorization'] = 'Bearer ' + os.environ['AUTH_VALUE']\n",
    "values = {}\nvalues['x'] = 'literal-secret'\naccess_value = values['x']\nheaders['Authorization'] = 'Bearer ' + access_value\n",
    "env: object = os.environ\nenv['AUTH_VALUE'] = 'literal-secret'\nheaders['Authorization'] = 'Bearer ' + os.environ['AUTH_VALUE']\n",
])
def test_bearer_exception_keeps_literal_and_other_credential_fields_hard(tmp_path, source):
    from datetime import datetime, timedelta, timezone
    root = tmp_path / "workspace"
    root.mkdir()
    expiry = (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()
    gateway = Gateway(root, allow_write=True, sensitive_content_audit_paths=(".",),
                      sensitive_content_audit_until=expiry)
    try:
        assert gateway.info()["write_policy"]["sensitive_content"]["write_mode"] == "audit"
        preview = gateway.create_file("candidate.py", source)
        assert preview["applied"] is False
        assert not (root / "candidate.py").exists()
        applied = gateway.create_file("candidate.py", source, dry_run=False)
        assert applied["applied"] is True
        read = gateway.read_file("candidate.py")
        assert read["redacted_lines"] == 0
        assert all(line in read["content"] for line in source.splitlines() if line.strip())
        _flags, findings = gateway._visibility.classify("candidate.py", source.encode())
        assert any(kind == "hard" for _number, kind in findings)
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
    r'"""api_key = \"abc\""""' + "\n",
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
    flags, findings = policy.classify("sample.py", source.encode("utf-8"))
    assert any(flags)
    assert "hard" in [kind for _, kind in findings]
    gateway = Gateway(root, allow_write=True)
    try:
        with pytest.raises(GatewayError) as exc:
            gateway.create_file("sample.py", source, dry_run=False)
        assert exc.value.code == "sensitive_content"
        assert not (root / "sample.py").exists()
        (root / "sample.py").write_text(source, encoding="utf-8")
        seen = gateway.read_file("sample.py")
        assert seen["redacted_lines"] >= 1
        assert "[REDACTED]" in seen["content"]
        assert gateway.search_files('literal', file_glob="sample.py")["matches"] == []
    finally:
        gateway.close()


@pytest.mark.parametrize("source", [
    'marker = ("ghp_" "ABCDEFGHIJKLMNOPQRSTUVWX")\n',
    'marker = "ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWX"\n',
    'marker = f"ghp_" f"ABCDEFGHIJKLMNOPQRSTUVWX"\n',
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


def test_v3_scan_integrity_failure_is_file_level_and_not_audit_bypass(tmp_path, monkeypatch):
    from datetime import datetime, timedelta, timezone
    from gateway import python_values

    root = tmp_path / "workspace"
    root.mkdir()
    (root / "src").mkdir()
    raw = b"visible = 123\nmarker = 456\n"
    (root / "src" / "existing.py").write_bytes(raw)
    until = (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()
    gateway = Gateway(
        root, allow_write=True,
        write_paths=("src",),
        sensitive_content_audit_paths=("src",),
        sensitive_content_audit_until=until,
    )
    monkeypatch.setattr(python_values, "MAX_TOKENS", 3)
    try:
        read = gateway.read_file("src/existing.py")
        assert read["file_sha256"] == hashlib.sha256(raw).hexdigest()
        assert read["redacted_lines"] == 2
        assert "visible = 123" not in read["content"]
        assert "marker = 456" not in read["content"]
        assert "[REDACTED]" in read["content"]

        search = gateway.search_files("visible", file_glob="existing.py")
        assert search["matches"] == []
        assert search["skipped_files_or_directories"] >= 1
        assert "scan_unavailable" in search["limit_reasons"]

        for dry_run in (True, False):
            with pytest.raises(GatewayError) as exc:
                gateway.create_file("src/candidate.py", "x = 1\ny = 2\n", dry_run=dry_run)
            assert exc.value.code == "sensitive_content"
            assert exc.value.details["rule_id"] == "SCAN_UNAVAILABLE"
            assert not (root / "src" / "candidate.py").exists()

            with pytest.raises(GatewayError) as exc:
                gateway.write_file(
                    "src/existing.py", "new = 1\n", read["file_sha256"], dry_run=dry_run,
                )
            assert exc.value.code == "sensitive_content"
            assert exc.value.details["rule_id"] == "SCAN_UNAVAILABLE"

            with pytest.raises(GatewayError) as exc:
                gateway.replace_text(
                    "src/existing.py", "visible", "new", read["file_sha256"],
                    dry_run=dry_run,
                )
            assert exc.value.code == "sensitive_content"
            assert exc.value.details["rule_id"] == "SCAN_UNAVAILABLE"

        assert (root / "src" / "existing.py").read_bytes() == raw
        assert not (root / "src" / "candidate.py").exists()
        assert not list(root.rglob("*.bak"))
    finally:
        gateway.close()


@pytest.mark.parametrize("target_size", [32769, 130000, 1048576])
def test_v3_python_scans_to_default_gateway_max_without_worker_limit(tmp_path, target_size):
    root = tmp_path / "workspace"
    root.mkdir()
    lead = "token = get_token()\n# "
    payload = lead + ("x" * (target_size - len(lead) - 1)) + "\n"
    assert len(payload.encode("utf-8")) == target_size
    gateway = Gateway(root, allow_write=True)
    try:
        preview = gateway.create_file("maxsize.py", payload)
        assert preview["applied"] is False
        result = gateway.create_file("maxsize.py", payload, dry_run=False)
        assert result["applied"]
        assert (root / "maxsize.py").stat().st_size == target_size
        response = gateway.read_file("maxsize.py")
        assert response["redacted_lines"] == 0
        assert response["file_sha256"] == hashlib.sha256(payload.encode()).hexdigest()
    finally:
        gateway.close()


def test_v3_pyi_is_classified_by_python_values_not_legacy_variable_names(tmp_path):
    root = tmp_path / "workspace"
    root.mkdir()
    payload = 'api_key = os.environ["API_KEY"]\n'
    gateway = Gateway(root, allow_write=True)
    try:
        assert gateway.create_file("types.pyi", payload, dry_run=False)["applied"]
        read = gateway.read_file("types.pyi")
        assert read["redacted_lines"] == 0
        assert "os.environ" in read["content"]
    finally:
        gateway.close()
