"""Real official SDK integration; no mock or home-made protocol substitute."""
import pytest
pytest.importorskip("mcp", reason="Official MCP SDK unavailable in this environment")
from starlette.testclient import TestClient
from gateway.core import Gateway
from gateway.http import create_app

HEADERS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}


def rpc(client, method, params=None):
    r = client.post("/mcp", headers=HEADERS, json={"jsonrpc": "2.0", "id": 2, "method": method, "params": params or {}})
    assert r.status_code == 200, r.text
    return r.json()["result"]


@pytest.fixture
def root(tmp_path):
    p = tmp_path / "project"
    p.mkdir()
    (p / "app.py").write_bytes(b"count = 1\n")
    return p


@pytest.fixture
def client(root):
    g = Gateway(root, allow_write=True)
    with TestClient(create_app(g), base_url="http://127.0.0.1:8765") as c:
        r = c.post("/mcp", headers=HEADERS, json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "write-tests", "version": "2.0"}}})
        assert r.status_code == 200 and "result" in r.json(), r.text
        c.initialization_result = r.json()["result"]
        c.post("/mcp", headers=HEADERS, json={"jsonrpc": "2.0", "method": "notifications/initialized"})
        yield c
    g.close()


def test_sdk_write_tools_have_truthful_annotations(client):
    tools = {t["name"]: t for t in rpc(client, "tools/list")["tools"]}
    assert set(tools) == {"gateway_info", "list_files", "read_file", "search_files", "create_file", "write_file", "replace_text", "create_directory", "delete_file", "remove_file", "unlink", "rename", "move"}
    for name in ("create_file", "write_file", "replace_text", "create_directory"):
        t = tools[name]
        assert t["annotations"]["readOnlyHint"] is False
        assert t["annotations"]["openWorldHint"] is False
        assert t["inputSchema"]["properties"]["dry_run"]["default"] is True
    assert tools["write_file"]["annotations"]["destructiveHint"] is True
    assert tools["replace_text"]["annotations"]["destructiveHint"] is True
    assert tools["create_file"]["annotations"]["destructiveHint"] is False
    assert "expected_sha256" in tools["write_file"]["inputSchema"]["required"]


def test_sdk_create_preview_and_apply(client, root):
    args = {"path": "new.py", "content": "pass\n"}
    r = rpc(client, "tools/call", {"name": "create_file", "arguments": args})
    assert not r.get("isError", False), r
    assert not r["structuredContent"]["applied"] and not (root / "new.py").exists()
    args["dry_run"] = False
    r = rpc(client, "tools/call", {"name": "create_file", "arguments": args})
    assert r["structuredContent"]["applied"] is True
    assert (root / "new.py").read_bytes() == b"pass\n"


def test_sdk_write_and_stale_conflict(client, root):
    read = rpc(client, "tools/call", {"name": "read_file", "arguments": {"path": "app.py"}})["structuredContent"]
    args = {"path": "app.py", "content": "count = 2\n", "expected_sha256": read["file_sha256"], "dry_run": False}
    r = rpc(client, "tools/call", {"name": "write_file", "arguments": args})
    assert r["structuredContent"]["applied"] is True
    assert (root / r["structuredContent"]["backup_path"]).read_bytes() == b"count = 1\n"
    assert rpc(client, "tools/call", {"name": "write_file", "arguments": args})["isError"] is True


def test_sdk_exact_replace(client, root):
    sha = rpc(client, "tools/call", {"name": "read_file", "arguments": {"path": "app.py"}})["structuredContent"]["file_sha256"]
    r = rpc(client, "tools/call", {"name": "replace_text", "arguments": {"path": "app.py", "old_text": "1", "new_text": "3", "expected_sha256": sha, "dry_run": False}})
    assert not r.get("isError", False), r
    assert (root / "app.py").read_bytes() == b"count = 3\n"


def test_sdk_does_not_coerce_dry_run_string_into_false(client, root):
    r = rpc(client, "tools/call", {"name": "create_file", "arguments": {"path": "bad.py", "content": "pass", "dry_run": "false"}})
    assert r["isError"] is True
    assert not (root / "bad.py").exists()


def test_sdk_hidden_write_rejected(client):
    r = rpc(client, "tools/call", {"name": "create_file", "arguments": {"path": ".env", "content": "data", "dry_run": False}})
    assert r["isError"] is True


def test_sdk_instructions_do_not_claim_read_only(client):
    instructions = client.initialization_result["instructions"]
    assert "Read-only access" not in instructions
    assert "Write tools are exposed" in instructions


def test_sdk_directory_schema(client):
    tools = {t["name"]: t for t in rpc(client, "tools/list")["tools"]}
    tool = tools["create_directory"]
    assert tool["annotations"]["destructiveHint"] is False
    assert tool["annotations"]["idempotentHint"] is True
    properties = tool["inputSchema"]["properties"]
    assert properties["parents"]["default"] is False
    assert properties["exist_ok"]["default"] is True
    assert tool["inputSchema"]["required"] == ["path"]


def test_sdk_directory_preview_then_recursive_apply(client, root):
    args = {"path": "src/generated", "parents": True}
    r = rpc(client, "tools/call", {"name": "create_directory", "arguments": args})
    assert not r.get("isError", False), r
    assert r["structuredContent"]["planned_paths"] == ["src", "src/generated"]
    assert not (root / "src").exists()
    args["dry_run"] = False
    r = rpc(client, "tools/call", {"name": "create_directory", "arguments": args})
    assert not r.get("isError", False), r
    assert r["structuredContent"]["created_paths"] == ["src", "src/generated"]
    assert (root / "src/generated").is_dir()
    r = rpc(client, "tools/call", {"name": "create_directory", "arguments": args})
    assert r["structuredContent"]["already_exists"] is True


@pytest.mark.parametrize("flag", ["parents", "exist_ok", "dry_run"])
def test_sdk_directory_strict_boolean(client, root, flag):
    args = {"path": "new", flag: "false"}
    r = rpc(client, "tools/call", {"name": "create_directory", "arguments": args})
    assert r["isError"] is True
    assert not (root / "new").exists()


def test_sdk_directory_hidden_and_file_conflicts(client, root):
    for path in (".git/hooks", "app.py"):
        r = rpc(client, "tools/call", {"name": "create_directory", "arguments": {
            "path": path, "parents": True, "dry_run": False}})
        assert r["isError"] is True
    assert (root / "app.py").read_bytes() == b"count = 1\n"


def test_sdk_directory_errors_include_partial_result(client, root, monkeypatch):
    import errno
    import os
    original = os.mkdir
    def fail(name, *args, **kwargs):
        if name == "second":
            raise OSError(errno.ENOSPC, "disk full")
        return original(name, *args, **kwargs)
    monkeypatch.setattr(os, "mkdir", fail)
    r = rpc(client, "tools/call", {"name": "create_directory", "arguments": {
        "path": "first/second", "parents": True, "dry_run": False}})
    assert r["isError"] is True
    assert '"created_paths": ["first"]' in r["content"][0]["text"]
    assert (root / "first").is_dir()


def test_sdk_instructions_describe_explicit_mkdir(client):
    instructions = client.initialization_result["instructions"]
    assert "Use create_directory" in instructions
    assert "cannot delete files, create directories" not in instructions

def test_sdk_redacted_source_hash_supports_visible_replace(client, root):
    import hashlib
    raw = b"password = 'keep-me'\ncount = 1\n"
    (root / "settings.py").write_bytes(raw)
    read = rpc(client, "tools/call", {"name": "read_file", "arguments": {"path": "settings.py"}})["structuredContent"]
    assert read["redacted_lines"] == 1
    assert read["file_sha256"] == hashlib.sha256(raw).hexdigest()
    result = rpc(client, "tools/call", {"name": "replace_text", "arguments": {
        "path": "settings.py",
        "old_text": "count = 1",
        "new_text": "count = 2",
        "expected_sha256": read["file_sha256"],
        "dry_run": False,
    }})
    assert not result.get("isError", False), result
    assert (root / "settings.py").read_bytes() == b"password = 'keep-me'\ncount = 2\n"


def test_sdk_delete_and_move_alias_schemas(client):
    tools = {t["name"]: t for t in rpc(client, "tools/list")["tools"]}
    for name in ("delete_file", "remove_file", "unlink"):
        tool = tools[name]
        assert tool["annotations"]["readOnlyHint"] is False
        assert tool["annotations"]["destructiveHint"] is True
        assert tool["inputSchema"]["required"] == ["path", "expected_sha256"]
        assert tool["inputSchema"]["properties"]["dry_run"]["default"] is True
    for name in ("rename", "move"):
        tool = tools[name]
        assert tool["annotations"]["readOnlyHint"] is False
        assert tool["annotations"]["destructiveHint"] is True
        assert tool["inputSchema"]["required"] == ["source", "destination", "expected_sha256"]
        assert tool["inputSchema"]["properties"]["dry_run"]["default"] is True


def test_sdk_delete_and_move_aliases(client, root):
    for name in ("delete_file", "remove_file", "unlink"):
        path = root / f"{name}.py"
        path.write_bytes(b"pass\n")
        digest = __import__("hashlib").sha256(b"pass\n").hexdigest()
        r = rpc(client, "tools/call", {"name": name, "arguments": {"path": f"{name}.py", "expected_sha256": digest, "dry_run": False}})
        assert not r.get("isError", False), r
        assert not path.exists()
    for name in ("rename", "move"):
        source = root / f"{name}.py"
        source.write_bytes(b"pass\n")
        (root / "dst").mkdir(exist_ok=True)
        digest = __import__("hashlib").sha256(b"pass\n").hexdigest()
        r = rpc(client, "tools/call", {"name": name, "arguments": {"source": f"{name}.py", "destination": f"dst/{name}.py", "expected_sha256": digest, "dry_run": False}})
        assert not r.get("isError", False), r
        assert not source.exists()
        assert (root / "dst" / f"{name}.py").read_bytes() == b"pass\n"
