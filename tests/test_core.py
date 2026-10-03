"""Tests exercise real files, not mocked filesystem access."""
import hashlib
from dataclasses import replace
import json
import os
from pathlib import Path

import pytest
from gateway.core import Gateway, GatewayError, Limits

@pytest.fixture
def root(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "src").mkdir()
    (root / "src" / "bidder.py").write_text(
        "def record_click():\n    return 'click tracking'\n# NEXT\n", encoding="utf-8")
    (root / "README.md").write_text("# Project\nCLICK tracking\n", encoding="utf-8")
    return root

@pytest.fixture
def gateway(root):
    g = Gateway(root)
    yield g
    g.close()

def test_list_and_pagination(gateway):
    result = gateway.list_files(limit=1)
    assert len(result["entries"]) == 1
    assert result["next_offset"] == 1
    other = gateway.list_files(offset=1, limit=1)
    assert result["entries"][0]["path"] != other["entries"][0]["path"]
    assert other["next_offset"] is None

def test_read_preserves_line_numbers_and_next_page(gateway):
    result = gateway.read_file("src/bidder.py", start_line=2, max_lines=1)
    assert result["content"] == "2:     return 'click tracking'"
    assert result["next_start_line"] == 3
    assert result["total_lines"] == 3
    assert len(result["content_sha256"]) == 64

def test_empty_file_and_out_of_range(root, gateway):
    (root / "empty.txt").write_text("")
    assert gateway.read_file("empty.txt")["content"] == ""
    result = gateway.read_file("README.md", start_line=100)
    assert result["content"] == ""
    assert result["next_start_line"] is None

def test_unicode_and_spaces(root, gateway):
    (root / "file \u4e2d\u6587.py").write_text("# \u4f60\u597d\n", encoding="utf-8")
    assert "\u4f60\u597d" in gateway.read_file("file \u4e2d\u6587.py")["content"]

def test_bom_utf8(root, gateway):
    (root / "bom.txt").write_bytes(b"\xef\xbb\xbfhello\n")
    assert gateway.read_file("bom.txt")["content"] == "1: hello"

@pytest.mark.parametrize("path", ["../outside.py", "/etc/passwd", "src/../../x.py", "src\\x.py", "a\x00.py", "a\n.py", "~/.ssh/id_rsa", "C:/test.py"])
def test_bad_paths_blocked(gateway, path):
    with pytest.raises(GatewayError):
        gateway.read_file(path)

@pytest.mark.parametrize("name", [".env", ".ENV.production", "private.pem", "PRIVATE.KEY", "credentials.json", "service-account.json", "secrets.py", "id_rsa", "local.sqlite", "archive.zip", "photo.png", "production-us3-kubeconfig.yaml", "KUBECONFIG-prod.yml"])
def test_secret_or_unsupported_files_hidden(root, gateway, name):
    (root / name).write_text("supersecret")
    assert name not in [x["name"] for x in gateway.list_files()["entries"]]
    with pytest.raises(GatewayError):
        gateway.read_file(name)

@pytest.mark.parametrize("name", [".git", ".ssh", "node_modules", "__pycache__", ".venv", "Library"])
def test_blocked_directories(root, gateway, name):
    folder = root / name
    folder.mkdir()
    (folder / "public.py").write_text("click")
    with pytest.raises(GatewayError):
        gateway.read_file(f"{name}/public.py")
    assert not any(name in x["path"] for x in gateway.search_files("click")["matches"])

def test_symlink_file_and_directory_escape(root, gateway, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "visible.py").write_text("outside click")
    (root / "escape").symlink_to(outside, target_is_directory=True)
    (root / "linked.py").symlink_to(outside / "visible.py")
    for path in ("escape/visible.py", "linked.py"):
        with pytest.raises(GatewayError):
            gateway.read_file(path)
    names = {x["name"] for x in gateway.list_files()["entries"]}
    assert "escape" not in names and "linked.py" not in names
    assert all("outside" not in x["text"] for x in gateway.search_files("click")["matches"])

def test_symlinks_inside_root_also_rejected(root, gateway):
    (root / "alias.py").symlink_to(root / "src" / "bidder.py")
    with pytest.raises(GatewayError):
        gateway.read_file("alias.py")

def test_hardlinks_rejected(root, gateway, tmp_path):
    outside = tmp_path / "outside.py"
    outside.write_text("secret")
    os.link(outside, root / "hard.py")
    with pytest.raises(GatewayError):
        gateway.read_file("hard.py")
    assert "hard.py" not in {x["name"] for x in gateway.list_files()["entries"]}

def test_fifo_rejected_without_blocking(root, gateway):
    os.mkfifo(root / "pipe.py")
    with pytest.raises(GatewayError):
        gateway.read_file("pipe.py")

def test_binary_utf8_and_size_limits(root, gateway):
    for name, contents in [("binary.txt", b"hello\x00world"), ("bad.txt", b"\xff\xfe"), ("large.txt", b"x" * 1_048_577)]:
        (root / name).write_bytes(contents)
        with pytest.raises(GatewayError):
            gateway.read_file(name)

def test_long_line_bounded(root):
    (root / "long.txt").write_text("a" * 10_000 + "\nnext\n")
    g = Gateway(root, limits=replace(Limits(), max_line_chars=100))
    try:
        result = g.read_file("long.txt")
        assert result["line_truncated"] is True
        assert len(result["content"]) < 200
        assert "next" in result["content"]
    finally:
        g.close()

def test_literal_search_case_and_glob(gateway):
    result = gateway.search_files("CLICK", file_glob="*.py")
    assert len(result["matches"]) == 2
    assert all(x["path"].endswith(".py") for x in result["matches"])
    assert gateway.search_files("CLICK", file_glob="*.py", case_sensitive=True)["matches"] == []
    assert gateway.search_files(".*")["matches"] == []

def test_search_result_limit_reported(gateway):
    result = gateway.search_files("click", max_results=1)
    assert len(result["matches"]) == 1
    assert result["truncated"]
    assert "max_results" in result["limit_reasons"]

def test_search_file_budget_reported(root):
    g = Gateway(root, limits=replace(Limits(), max_files=1))
    try:
        result = g.search_files("not present")
        assert result["truncated"]
        assert "max_files" in result["limit_reasons"]
    finally:
        g.close()

def test_excludes_cannot_be_bypassed(root):
    (root / "internal.py").write_text("click")
    g = Gateway(root, excludes=("internal.py", "src/*"))
    try:
        with pytest.raises(GatewayError):
            g.read_file("internal.py")
        with pytest.raises(GatewayError):
            g.read_file("src/bidder.py")
        result = g.search_files("click")
        assert all(x["path"] == "README.md" for x in result["matches"])
    finally:
        g.close()

def test_secret_redaction_before_read_and_search(root, gateway):
    (root / "settings.py").write_text("api_key = 'sk-project-ABCDEFGHIJKLMNOPQRSTUV'\npassword = 'dont-leak-me'\nnormal = 'visible'\n")
    result = gateway.read_file("settings.py")
    assert "dont-leak-me" not in result["content"]
    assert "ABCDEFGHIJKLMNOP" not in result["content"]
    assert "[REDACTED]" in result["content"]
    assert "visible" in result["content"]
    assert gateway.search_files("dont-leak-me")["matches"] == []

def test_kubernetes_credential_fields_are_redacted(root, gateway):
    (root / "cluster.yaml").write_text(
        "token: opaque-bearer-value\n"
        "client-key-data: BASE64PRIVATEKEY\n"
        "client-certificate-data: BASE64CLIENTCERT\n"
        "certificate-authority-data: BASE64CACERT\n"
        "normal: visible\n",
        encoding="utf-8",
    )
    result = gateway.read_file("cluster.yaml")
    assert result["redacted_lines"] == 4
    for secret in ("opaque-bearer-value", "BASE64PRIVATEKEY", "BASE64CLIENTCERT", "BASE64CACERT"):
        assert secret not in result["content"]
    assert "normal: visible" in result["content"]


def test_pem_block_embedded_in_text(root, gateway):
    (root / "notes.txt").write_text("start\n-----BEGIN PRIVATE KEY-----\nabcdef\n-----END PRIVATE KEY-----\nend\n")
    result = gateway.read_file("notes.txt")
    assert "abcdef" not in result["content"]
    assert result["total_lines"] == 5

@pytest.mark.parametrize("kwargs", [{"start_line": 0}, {"max_lines": 0}, {"max_lines": 301}, {"start_line": True}])
def test_invalid_read_arguments(gateway, kwargs):
    with pytest.raises(GatewayError):
        gateway.read_file("README.md", **kwargs)

@pytest.mark.parametrize("kwargs", [{"query": ""}, {"query": "x" * 257}, {"query": "x", "max_results": 101}, {"query": "x", "file_glob": "../*"}])
def test_invalid_search_arguments(gateway, kwargs):
    with pytest.raises(GatewayError):
        gateway.search_files(**kwargs)

def test_refuse_home_and_filesystem_root():
    for root in (Path("/"), Path.home()):
        with pytest.raises(GatewayError):
            Gateway(root)

def test_missing_file_error_does_not_disclose_absolute_paths(gateway, root):
    with pytest.raises(GatewayError) as exc:
        gateway.read_file("missing.py")
    assert str(root) not in str(exc.value)

def test_json_serializable_no_absolute_root(gateway, root):
    text = json.dumps(gateway.list_files()) + json.dumps(gateway.read_file("README.md"))
    assert str(root) not in text

def test_explicit_root_may_have_non_sensitive_secret_named_ancestor(tmp_path):
    selected = tmp_path / "secret-project-tests" / "project"
    selected.mkdir(parents=True)
    g = Gateway(selected)
    try:
        assert g.list_files()["entries"] == []
    finally:
        g.close()

def test_large_non_secret_line_has_bounded_processing_time(root):
    # A timeout catches accidental quadratic credential-regex behavior.
    import subprocess
    import sys
    (root / "long.txt").write_text("a" * 300_000)
    script = "from gateway.core import Gateway; import sys; g=Gateway(sys.argv[1]); print(g.read_file('long.txt')['line_truncated']); g.close()"
    result = subprocess.run([sys.executable, "-c", script, str(root)], capture_output=True, text=True, timeout=3, check=True)
    assert result.stdout.strip() == "True"

def test_redacted_read_still_returns_raw_file_sha256(root, gateway):
    raw = b"password = 'dont-leak-me'\nnormal = 'visible'\n"
    (root / "settings.py").write_bytes(raw)
    result = gateway.read_file("settings.py")
    assert result["redacted_lines"] == 1
    assert result["file_sha256"] == hashlib.sha256(raw).hexdigest()
    assert "dont-leak-me" not in result["content"]


def test_credential_scanner_does_not_redact_go_field_references(root, gateway):
    source = (
        "cfg := RedisConfig{\n"
        "    Password: config.Redis.SampleCachePassword,\n"
        "    Token: cfg.Auth.Token,\n"
        "}\n"
    )
    (root / "main.go").write_text(source)
    result = gateway.read_file("main.go")
    assert result["redacted_lines"] == 0
    assert "Password: config.Redis.SampleCachePassword," in result["content"]
    assert "Token: cfg.Auth.Token," in result["content"]


@pytest.mark.parametrize(
    "line",
    [
        'Password: "actual-secret-value",',
        "password = 'actual-secret-value'",
        "password: actual-secret-value",
    ],
)
def test_credential_scanner_still_redacts_literal_values(root, gateway, line):
    (root / "settings.txt").write_text(line + "\n")
    result = gateway.read_file("settings.txt")
    assert result["redacted_lines"] == 1
    assert "actual-secret-value" not in result["content"]
    assert "[REDACTED]" in result["content"]

def test_colon_dotted_value_without_code_terminator_remains_redacted(root, gateway):
    (root / "settings.yaml").write_text("password: config.Redis.Password\n")
    result = gateway.read_file("settings.yaml")
    assert result["redacted_lines"] == 1
    assert "config.Redis.Password" not in result["content"]


def test_equals_dotted_code_reference_is_not_redacted(root, gateway):
    (root / "settings.py").write_text("password = config.redis.password\n")
    result = gateway.read_file("settings.py")
    assert result["redacted_lines"] == 0
    assert "config.redis.password" in result["content"]


def test_gateway_info_reports_current_version(root, gateway):
    assert gateway.info()["version"] == "2.4.0"
