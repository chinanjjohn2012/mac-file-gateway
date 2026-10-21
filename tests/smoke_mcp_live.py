"""Exercise both MCP protocol eras against a real loopback Uvicorn subprocess.

Unlike smoke_live.py (deliberately REST-only), this checks the SDK-backed /mcp
route over actual HTTP. The temporary project and unprivileged ephemeral port
cannot affect a user-managed Gateway or open a public tunnel.

Run: python tests/smoke_mcp_live.py
"""
from __future__ import annotations

import itertools
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

from mcp.types import (
    CLIENT_CAPABILITIES_META_KEY,
    CLIENT_INFO_META_KEY,
    PROTOCOL_VERSION_META_KEY,
)

from smoke_live import smoke_environment


MODERN_VERSION = "2026-07-28"
LEGACY_VERSION = "2025-11-25"
ACCEPT = "application/json, text/event-stream"


def main() -> None:
    package_root = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix="gateway-mcp-live-") as directory:
        root = Path(directory) / "project"
        root.mkdir()
        (root / "smoke.py").write_text("count = 1\n", encoding="utf-8")
        (root / ".env").write_text("password=never-expose-this", encoding="utf-8")
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        process = subprocess.Popen(
            [
                sys.executable, "-m", "gateway", "--root", str(root),
                "--port", str(port), "--allow-write",
            ],
            cwd=package_root,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=smoke_environment(),
        )
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        url = f"http://127.0.0.1:{port}"
        ids = itertools.count(1)

        def request(path: str, body: dict | None = None, *,
                    modern: bool = False, method: str | None = None,
                    name: str | None = None) -> tuple[int, dict | None]:
            headers = {"Accept": ACCEPT, "Content-Type": "application/json"}
            if modern:
                assert method is not None
                headers["MCP-Protocol-Version"] = MODERN_VERSION
                headers["Mcp-Method"] = method
                if name is not None:
                    headers["Mcp-Name"] = name
            payload = None if body is None else json.dumps(body).encode("utf-8")
            req = urllib.request.Request(url + path, data=payload, headers=headers)
            try:
                with opener.open(req, timeout=5) as response:
                    raw = response.read()
                    return response.status, json.loads(raw) if raw else None
            except urllib.error.HTTPError as exc:
                raw = exc.read()
                return exc.code, json.loads(raw) if raw else None

        def rpc(method: str, params: dict | None = None, *,
                modern: bool = False) -> dict:
            args = dict(params or {})
            if modern:
                args["_meta"] = {
                    PROTOCOL_VERSION_META_KEY: MODERN_VERSION,
                    CLIENT_INFO_META_KEY: {"name": "gateway-live-smoke", "version": "1"},
                    CLIENT_CAPABILITIES_META_KEY: {},
                }
            rid = next(ids)
            status, result = request(
                "/mcp", {"jsonrpc": "2.0", "id": rid, "method": method, "params": args},
                modern=modern, method=method,
                name=args.get("name") if method == "tools/call" else None,
            )
            assert status == 200, f"{method} returned HTTP {status}: {result}"
            assert isinstance(result, dict) and result.get("id") == rid, result
            assert "result" in result, f"{method} returned an MCP error: {result}"
            return result["result"]

        try:
            deadline = time.monotonic() + 10
            while True:
                if process.poll() is not None:
                    raise RuntimeError("MCP Gateway exited: " + process.communicate()[1])
                try:
                    status, health = request("/health")
                    if status == 200:
                        break
                    if status in {400, 401, 403, 421}:
                        raise RuntimeError(f"MCP Gateway /health rejected probe: HTTP {status}")
                except (OSError, urllib.error.URLError):
                    pass
                if time.monotonic() >= deadline:
                    raise RuntimeError("MCP Gateway did not become healthy")
                time.sleep(0.05)
            assert health is not None and health["mcp_enabled"] is True
            assert health["read_only"] is False

            # Modern clients do not initialize; one request is one exchange.
            discover = rpc("server/discover", modern=True)
            assert MODERN_VERSION in discover["supportedVersions"]
            modern_tools = {tool["name"] for tool in rpc("tools/list", modern=True)["tools"]}
            assert {"gateway_info", "read_file", "create_file"} <= modern_tools
            read = rpc("tools/call", {
                "name": "read_file", "arguments": {"path": "smoke.py"},
            }, modern=True)
            assert read["structuredContent"]["content"] == "1: count = 1"

            args = {"path": "created.py", "content": "created = True\n"}
            preview = rpc("tools/call", {"name": "create_file", "arguments": args}, modern=True)
            assert preview["structuredContent"]["applied"] is False
            assert not (root / "created.py").exists()
            rejected = rpc("tools/call", {
                "name": "create_file", "arguments": {**args, "dry_run": "false"},
            }, modern=True)
            assert rejected["isError"] is True
            assert not (root / "created.py").exists()
            applied = rpc("tools/call", {
                "name": "create_file", "arguments": {**args, "dry_run": False},
            }, modern=True)
            assert applied["structuredContent"]["applied"] is True
            assert (root / "created.py").read_text(encoding="utf-8") == "created = True\n"

            # A legacy client can initialize and call the same tools on this listener.
            init = rpc("initialize", {
                "protocolVersion": LEGACY_VERSION, "capabilities": {},
                "clientInfo": {"name": "gateway-live-smoke", "version": "1"},
            })
            assert init["protocolVersion"] == LEGACY_VERSION
            status, _ = request("/mcp", {
                "jsonrpc": "2.0", "method": "notifications/initialized",
            })
            assert status == 202, status
            legacy_tools = {tool["name"] for tool in rpc("tools/list")["tools"]}
            assert legacy_tools == modern_tools
            legacy_read = rpc("tools/call", {
                "name": "read_file", "arguments": {"path": "created.py"},
            })
            assert legacy_read["structuredContent"]["content"] == "1: created = True"
            hidden = rpc("tools/call", {
                "name": "read_file", "arguments": {"path": ".env"},
            })
            assert hidden["isError"] is True
            assert "never-expose-this" not in json.dumps(hidden)

            print(json.dumps({
                "real_mcp_listener": "PASS",
                "mcp_verified": True,
                "protocols": [LEGACY_VERSION, MODERN_VERSION],
                "checks": [
                    "mcp_enabled",
                    "modern_discover",
                    "modern_tools_list",
                    "modern_read_file",
                    "modern_write_preview",
                    "modern_strict_boolean_rejection",
                    "modern_create_file_apply",
                    "legacy_initialize",
                    "legacy_initialized_notification",
                    "legacy_tools_list",
                    "legacy_read_file",
                    "protected_file_rejected",
                ],
            }, indent=2))
        finally:
            if process.poll() is None:
                process.terminate()
            try:
                process.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate(timeout=5)


if __name__ == "__main__":
    main()
    # E/T14: independently start authorized Legacy and Multi Git listeners.
    # These are additional temporary processes, never a real Gateway/Tunnel.
    from smoke_git_cli import main as git_mcp_live_smoke
    git_mcp_live_smoke()
