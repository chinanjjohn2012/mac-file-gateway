"""Real SDK integration tests; no fake MCP server or protocol shim.

Without the SDK installed this module is explicitly skipped. The supplied
setup.sh installs it; verify.sh --require-mcp fails rather than skipping it.
"""
import pytest
pytest.importorskip("mcp", reason="Official MCP SDK unavailable in this environment")
from starlette.testclient import TestClient
from gateway.core import Gateway
from gateway.http import create_app

HEADERS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}

@pytest.fixture
def client(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "sample.py").write_text("# click\n")
    (root / ".env").write_text("SECRET=hidden")
    g = Gateway(root)
    with TestClient(create_app(g), base_url="http://127.0.0.1:8765") as client:
        r = client.post("/mcp", headers=HEADERS, json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "gateway-tests", "version": "1.0"}}})
        assert r.status_code == 200, r.text
        assert "result" in r.json(), r.text
        client.post("/mcp", headers=HEADERS, json={"jsonrpc": "2.0", "method": "notifications/initialized"})
        yield client
    g.close()

def rpc(client, method, params=None):
    r = client.post("/mcp", headers=HEADERS, json={"jsonrpc": "2.0", "id": 2, "method": method, "params": params or {}})
    assert r.status_code == 200, r.text
    return r.json()

def test_sdk_lists_tools_and_valid_schemas(client):
    tools = rpc(client, "tools/list")["result"]["tools"]
    assert {x["name"] for x in tools} == {"gateway_info", "list_files", "read_file", "search_files"}
    for tool in tools:
        assert tool["inputSchema"]["type"] == "object"
        assert tool["annotations"]["readOnlyHint"] is True
        assert tool["annotations"]["destructiveHint"] is False

def test_sdk_read_file(client):
    r = rpc(client, "tools/call", {"name": "read_file", "arguments": {"path": "sample.py"}})["result"]
    assert r.get("isError", False) is False
    assert r["structuredContent"]["content"] == "1: # click"

def test_sdk_search(client):
    r = rpc(client, "tools/call", {"name": "search_files", "arguments": {"query": "click"}})["result"]
    assert r["structuredContent"]["matches"][0]["path"] == "sample.py"

def test_sdk_refuses_hidden_files(client):
    r = rpc(client, "tools/call", {"name": "read_file", "arguments": {"path": ".env"}})["result"]
    assert r.get("isError") is True
    assert "SECRET=hidden" not in str(r)
