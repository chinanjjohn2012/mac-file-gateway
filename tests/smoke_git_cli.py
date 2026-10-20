"""E/T13: real loopback Git MCP smoke for Legacy and Multi workspaces.

All repositories/remotes/control directories live under TemporaryDirectory.
The only allowed Git effects are unprivileged local test-file operations.
Run: python tests/smoke_git_cli.py
"""
from __future__ import annotations

import itertools
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

from mcp.types import (
    CLIENT_CAPABILITIES_META_KEY, CLIENT_INFO_META_KEY,
    PROTOCOL_VERSION_META_KEY,
)

from smoke_live import smoke_environment

MODERN = "2026-07-28"
LEGACY = "2025-11-25"
ACCEPT = "application/json, text/event-stream"


def git(where: Path, *args: str) -> str:
    result = subprocess.run(["git", *args], cwd=where, text=True,
                            capture_output=True, check=True)
    return result.stdout.strip()


def free_port() -> int:
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        return reservation.getsockname()[1]


def assert_http_git_mode(tmp: Path, *, multi: bool) -> None:
    repo = tmp / "project"
    repo.mkdir()
    git(repo, "init", "-q")
    git(repo, "config", "user.name", "E smoke")
    git(repo, "config", "user.email", "smoke@example.invalid")
    a, b = repo / "a", repo / "b"
    a.mkdir()
    b.mkdir()
    (a / "seed.txt").write_text("seed\n")
    git(repo, "add", "a/seed.txt")
    git(repo, "commit", "-qm", "initial")
    control = tmp / "control"
    control.mkdir(mode=0o700)
    config_path = control / "gateway.json"
    if multi:
        config_path.write_text(json.dumps({
            "schema_version": 1,
            "server": {"git": {"enabled": True}},
            "workspaces": {
                "a": {"root": str(a), "git": {"allowed_commands": ["status", "add"]}},
                "b": {"root": str(b), "git": {"allowed_commands": ["status"]}},
            },
        }))
        config_path.chmod(0o600)

    port = free_port()
    args = [sys.executable, "-m", "gateway"]
    if multi:
        args += ["--config", str(config_path)]
    else:
        args += ["--root", str(repo), "--allow-git", "--git-command", "status",
                 "--git-command", "add", "--port", str(port)]
    env = smoke_environment()
    env["HOME"] = str(tmp)
    # Multi port belongs to the strict private configuration, not argv.
    if multi:
        contents = json.loads(config_path.read_text())
        contents["server"]["port"] = port
        config_path.write_text(json.dumps(contents))
        config_path.chmod(0o600)

    server = subprocess.Popen(args, cwd=Path(__file__).resolve().parents[1],
                              env=env, stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              text=True)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    root_url = f"http://127.0.0.1:{port}"
    ids = itertools.count(1)

    def request(path: str, payload: dict | None = None, *,
                method: str | None = None, modern=False, name=None):
        headers = {"Accept": ACCEPT, "Content-Type": "application/json"}
        if modern:
            assert method is not None
            headers["MCP-Protocol-Version"] = MODERN
            headers["Mcp-Method"] = method
            if name is not None:
                headers["Mcp-Name"] = name
        body = None if payload is None else json.dumps(payload).encode()
        action = urllib.request.Request(root_url + path, data=body, headers=headers)
        try:
            with opener.open(action, timeout=9) as response:
                data = response.read()
                return response.status, json.loads(data) if data else None
        except urllib.error.HTTPError as exc:
            data = exc.read()
            return exc.code, json.loads(data) if data else None

    def rpc(method: str, params: dict | None = None, *, modern=False):
        args = dict(params or {})
        if modern:
            args["_meta"] = {
                PROTOCOL_VERSION_META_KEY: MODERN,
                CLIENT_INFO_META_KEY: {"name": "e-git-smoke", "version": "1"},
                CLIENT_CAPABILITIES_META_KEY: {},
            }
        ident = next(ids)
        status, payload = request(
            "/mcp", {"jsonrpc": "2.0", "id": ident,
                     "method": method, "params": args},
            method=method, modern=modern,
            name=args.get("name") if method == "tools/call" else None,
        )
        assert status == 200 and payload["id"] == ident, (status, payload)
        assert "result" in payload, (method, payload)
        return payload["result"]

    try:
        until = time.monotonic() + 10
        while True:
            if server.poll() is not None:
                raise RuntimeError("Git smoke child exited: " + server.communicate()[1])
            try:
                status, health = request("/health")
                if status == 200 and health["mcp_enabled"] is True:
                    break
            except (OSError, urllib.error.URLError):
                pass
            if time.monotonic() > until:
                raise RuntimeError("Temporary Git MCP listener failed health check")
            time.sleep(0.05)

        assert MODERN in rpc("server/discover", modern=True)["supportedVersions"]
        for modern in (True, False):
            if not modern:
                init = rpc("initialize", {
                    "protocolVersion": LEGACY, "capabilities": {},
                    "clientInfo": {"name": "e-git-smoke", "version": "1"},
                })
                assert init["protocolVersion"] == LEGACY
                notification = {"jsonrpc": "2.0", "method": "notifications/initialized"}
                status, _ = request("/mcp", notification)
                assert status == 202

            tools = {t["name"]: t for t in rpc("tools/list", modern=modern)["tools"]}
            assert "run_git" in tools and "run_command" not in tools
            schema = tools["run_git"]["inputSchema"]
            assert ("workspace" in schema["required"]) is multi
            for name, kind in (("options", "object"), ("paths", "array")):
                assert schema["properties"][name]["type"] == kind
            required = {"workspace": "a"} if multi else {}
            preview = rpc("tools/call", {
                "name": "run_git", "arguments": {**required, "command": "status"},
            }, modern=modern)
            assert preview.get("isError") is not True, preview
            assert preview["structuredContent"]["execute_started"] is False

            rejected = rpc("tools/call", {
                "name": "run_git",
                "arguments": {**required, "command": "status", "options": None},
            }, modern=modern)
            assert rejected.get("isError") is True
            denied = rpc("tools/call", {
                "name": "run_git",
                "arguments": {**required, "command": "push",
                              "options": {"remote": "origin", "branch": "main"}},
            }, modern=modern)
            assert denied.get("isError") is True

            result = rpc("tools/call", {
                "name": "run_git",
                "arguments": {**required, "command": "status", "dry_run": False},
            }, modern=modern)
            assert result.get("isError") is not True, result
            assert result["structuredContent"]["exit_code"] == 0
            assert result["structuredContent"]["cleanup_status"] == "complete"

            if multi:
                forbidden = rpc("tools/call", {
                    "name": "run_git",
                    "arguments": {"workspace": "b", "command": "add",
                                  "options": {"all": True}, "dry_run": False},
                }, modern=modern)
                assert forbidden.get("isError") is True

        target = a if multi else repo
        (target / "smoke-new.txt").write_text("smoke\n")
        staged = rpc("tools/call", {
            "name": "run_git",
            "arguments": {**({"workspace": "a"} if multi else {}),
                          "command": "add", "paths": ["smoke-new.txt"],
                          "dry_run": False},
        }, modern=True)
        assert staged.get("isError") is not True, staged
        assert staged["structuredContent"]["exit_code"] == 0
        tracked = git(repo, "diff", "--cached", "--name-only")
        assert tracked == ("a/smoke-new.txt" if multi else "smoke-new.txt"), tracked
        assert not any((control / "git-state").iterdir()) if multi else True
    finally:
        if server.poll() is None:
            server.terminate()
        try:
            server.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()
            server.communicate(timeout=5)


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="gateway-git-cli-e-") as name:
        base = Path(name)
        assert_http_git_mode(base / "legacy", multi=False) if False else None
        legacy, multi = base / "legacy", base / "multi"
        legacy.mkdir()
        multi.mkdir()
        assert_http_git_mode(legacy, multi=False)
        assert_http_git_mode(multi, multi=True)
    print(json.dumps({
        "real_git_mcp_listener": "PASS",
        "modes": ["legacy", "multi"],
        "protocols": [LEGACY, MODERN],
        "checks": [
            "loopback_process",
            "git_preview_without_subprocess",
            "strict_nullable_schema",
            "explicit_git_permission",
            "native_status_and_add_apply",
            "cross_workspace_denial",
            "state_records_cleaned",
        ],
    }, indent=2))


if __name__ == "__main__":
    main()
