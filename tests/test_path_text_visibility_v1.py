"""Path Text Visibility V1 — source strings are not file access grants.

These fixtures are not executed as Python. The suite verifies that path text
is ordinary content even when the target pathname is private/hidden or lies in
another Workspace; all actual file authorization and credentials remain safe.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from gateway.core import Gateway, GatewayError
from gateway.http_multi import create_multi_app
from gateway.visibility import SensitiveContentPolicy
from gateway.workspaces import ActiveRuntimeInventory, WorkspaceService
from gateway.workspaces_config import parse_workspace_config


@pytest.mark.parametrize("ext", ["py", "pyi", "json", "yaml", "txt"])
@pytest.mark.parametrize("newline", ["\n", "\r\n"])
def test_path_text_from_protected_root_is_visible_and_writable(tmp_path, ext, newline):
    root = tmp_path / "workspace"
    other = tmp_path / "other-workspace"
    root.mkdir()
    other.mkdir()
    absolute = str(other / "7_records" / ".env")
    if ext in ("py", "pyi"):
        source = "file_path = " + repr(absolute) + newline
    elif ext == "json":
        source = json.dumps({"file_path": absolute}) + newline
    elif ext == "yaml":
        source = "file_path: " + json.dumps(absolute) + newline
    else:
        source = "file at " + absolute + newline
    gateway = Gateway(root, allow_write=True, protected_content_paths=(
        str(other), str(Path.home()), str(tmp_path),
    ))
    file_path = "sample." + ext
    try:
        flags, findings = gateway._visibility.classify(file_path, source.encode())
        assert not any(flags) and not findings, (file_path, flags, findings)
        preview = gateway.create_file(file_path, source, dry_run=True)
        assert absolute in preview["diff"] and not preview["applied"]
        assert gateway.create_file(file_path, source, dry_run=False)["applied"]
        read = gateway.read_file(file_path)
        assert read["redacted_lines"] == 0 and absolute in read["content"]
        assert read["file_sha256"] == hashlib.sha256(source.encode()).hexdigest()
        result = gateway.search_files("7_records", file_glob=file_path)
        assert len(result["matches"]) == 1
        before = (root / file_path).read_bytes()
        args = dict(
            path=file_path, old_text="7_records", new_text="8_records",
            expected_sha256=read["file_sha256"],
        )
        change_preview = gateway.replace_text(**args, dry_run=True)
        assert "8_records" in change_preview["diff"] and "7_records" in change_preview["diff"]
        assert not change_preview["applied"] and (root / file_path).read_bytes() == before
        applied = gateway.replace_text(**args, dry_run=False)
        assert applied["applied"]
        assert (root / file_path).read_bytes() == source.replace(
            "7_records", "8_records"
        ).encode()
        assert (root / applied["backup_path"]).read_bytes() == before
        with pytest.raises(GatewayError) as old_hash:
            gateway.write_file(file_path, source, read["file_sha256"], dry_run=False)
        assert old_hash.value.code == "conflict"
        new_sha = applied["new_sha256"]
        assert gateway.write_file(file_path, source, new_sha, dry_run=False)["applied"]
        assert (root / file_path).read_bytes() == before
    finally:
        gateway.close()


@pytest.mark.parametrize("kind", ["path", "home", "private-config", "comment"])
def test_explicit_protected_path_regex_is_not_content_secret(tmp_path, kind):
    base = str(tmp_path / "other-workspace")
    path = {
        "path": base + "/7_data/config.json",
        "home": str(Path.home()) + "/7_data/report.csv",
        "private-config": base + "/.config/mac-file-gateway/gateway.json",
        "comment": base + "/.ssh/id_rsa",
    }[kind]
    source = (
        "# path: " + path + "\n" if kind == "comment"
        else "location = " + repr(path) + "\n"
    )
    policy = SensitiveContentPolicy(protected_paths=(
        base, str(Path.home()), str(tmp_path),
    ))
    flags, findings = policy.classify("path.py", source.encode())
    assert flags == [False] and findings == (), (flags, findings)
    assert path in "\n".join(policy.redact_lines(source, "path.py")[0])
    assert policy.visible_matches(source, path, "path.py")


@pytest.mark.parametrize("ext,source", [
    ("py", 'password = "abc"\n'),
    ("py", 'url = "https://user:pwd@example.net/resource"\n'),
    ("py", 'marker = "ghp_ABCDEFGHIJKLMNOPQRSTUVWX"\n'),
    ("pyi", 'api_key = "abc"\n'),
    ("json", '{"password": "abc"}\n'),
    ("yaml", 'password: "abc"\n'),
])
def test_real_credentials_still_hard_even_with_path_text_rule(tmp_path, ext, source):
    root = tmp_path / "workspace"
    root.mkdir()
    gateway = Gateway(root, allow_write=True, protected_content_paths=(str(tmp_path),))
    try:
        flags, findings = gateway._visibility.classify("sample." + ext, source.encode())
        assert any(flags) and any(kind == "hard" for _, kind in findings), findings
        with pytest.raises(GatewayError) as blocked:
            gateway.create_file("blocked." + ext, source, dry_run=False)
        assert blocked.value.code == "sensitive_content"
        assert not (root / ("blocked." + ext)).exists()
        (root / ("sample." + ext)).write_bytes(source.encode())
        read = gateway.read_file("sample." + ext)
        assert read["redacted_lines"] >= 1
        assert "abc" not in read["content"] or "abc" not in source
    finally:
        gateway.close()


@pytest.mark.parametrize("transport", ["rest", "mcp"])
def test_multi_workspace_path_text_visible_without_cross_root_access(tmp_path, transport):
    paths = {name: tmp_path / name for name in ("a", "b", "config", "runtime")}
    for path in paths.values():
        path.mkdir()
    text_path = str(paths["b"] / "7_data" / ".env")
    source = "file_path = " + repr(text_path) + "\n"
    (paths["a"] / "source.py").write_text(source, encoding="utf-8")
    (paths["b"] / "private.py").write_text("not authorized to a\n", encoding="utf-8")
    (paths["a"] / ".env").write_text("sensitive fixture\n", encoding="utf-8")
    settings = parse_workspace_config({
        "schema_version": 1,
        "workspaces": {
            "a": {"root": str(paths["a"]), "write": {"enabled": True, "paths": ["."]}},
            "b": {"root": str(paths["b"]), "write": {"enabled": False}},
        },
    })
    service = WorkspaceService(
        settings, config_dir=paths["config"],
        inventory=ActiveRuntimeInventory(paths=(paths["runtime"],)),
    )
    try:
        with TestClient(create_multi_app(service), base_url="http://127.0.0.1:8765") as client:
            if transport == "rest":
                response = client.get("/read", params={
                    "workspace": "a", "path": "source.py",
                })
                assert response.status_code == 200
                assert response.json()["redacted_lines"] == 0
                assert text_path in response.json()["content"]
                result = client.get("/search", params={
                    "workspace": "a", "q": "7_data", "file_glob": "source.py",
                })
                assert result.status_code == 200 and result.json()["matches"]
                blocked = client.get("/read", params={
                    "workspace": "a", "path": "../b/private.py",
                })
                assert blocked.status_code in (400, 403, 404)
                hidden = client.get("/read", params={
                    "workspace": "a", "path": ".env",
                })
                assert hidden.status_code in (400, 403, 404)
            else:
                headers = {"Accept": "application/json, text/event-stream"}
                initialized = client.post("/mcp", headers=headers, json={
                    "jsonrpc": "2.0", "id": 1, "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-11-25",
                        "capabilities": {},
                        "clientInfo": {"name": "path-text-v1", "version": "1"},
                    },
                })
                assert initialized.status_code == 200

                def invoke(name, args, ident):
                    response = client.post("/mcp", headers=headers, json={
                        "jsonrpc": "2.0", "id": ident, "method": "tools/call",
                        "params": {"name": name, "arguments": {
                            "workspace": "a", **args,
                        }},
                    })
                    assert response.status_code == 200
                    return response.json()["result"]

                read = invoke("read_file", {"path": "source.py"}, 2)
                assert not read.get("isError") and text_path in json.dumps(read)
                matches = invoke("search_files", {
                    "query": "7_data", "file_glob": "source.py",
                }, 3)
                assert not matches.get("isError") and text_path in json.dumps(matches)
                blocked = invoke("read_file", {"path": "../b/private.py"}, 4)
                assert blocked.get("isError") is True
    finally:
        service.close()


def test_unparseable_python_with_numeric_path_is_fail_closed(tmp_path):
    root = tmp_path / "workspace"
    root.mkdir()
    # This is *not* a valid Python quoted string or a comment. An invalid
    # numeric token must not be silently skipped to expose unscanned bytes.
    content = "x\n/private/var/7_tmp_abcd/secret.py\n"
    (root / "broken.py").write_text(content, encoding="utf-8")
    gateway = Gateway(root, allow_write=True)
    try:
        read = gateway.read_file("broken.py")
        assert read["redacted_lines"] == 2
        assert "/private/var/7_tmp_abcd" not in read["content"]
        assert gateway.search_files("7_tmp_abcd", file_glob="broken.py")["matches"] == []
        with pytest.raises(GatewayError) as failure:
            gateway.create_file("more.py", content, dry_run=False)
        assert failure.value.code == "sensitive_content"
    finally:
        gateway.close()
