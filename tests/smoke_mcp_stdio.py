"""Exercise actual MCP stdio subprocesses using the official SDK v2 client.

Runs both modern auto-discovery and the legacy initialize handshake.
No tunnel or user project is involved; child processes only receive a
temporary test project selected explicitly by --root.
"""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

import anyio
from mcp.client import Client
from mcp.client.stdio import StdioServerParameters

MODERN_VERSION = "2026-07-28"
LEGACY_VERSION = "2025-11-25"


async def exercise_stdio(root: Path, *, mode: str) -> None:
    server = StdioServerParameters(
        command=sys.executable,
        args=[
            "-m", "gateway", "--root", str(root), "--transport", "stdio", "--allow-write",
        ],
        cwd=str(Path(__file__).resolve().parents[1]),
    )
    # A hung or crashed server must fail the smoke rather than hang CI forever.
    with anyio.fail_after(30):
        async with Client(server, mode=mode) as client:
            assert client.protocol_version == (LEGACY_VERSION if mode == "legacy" else MODERN_VERSION)
            assert client.server_info is not None and client.server_info.name == "Mac File Gateway"
            tools = {item.name for item in (await client.list_tools()).tools}
            assert {"gateway_info", "read_file", "create_file"} <= tools
            assert "run_command" not in tools and "run_skill_script" not in tools

            read = await client.call_tool("read_file", {"path": "sample.py"})
            assert read.is_error is not True
            assert read.structured_content is not None
            assert read.structured_content["content"] == "1: state = 1"

            blocked = await client.call_tool("read_file", {"path": ".env"})
            assert blocked.is_error is True
            assert "private-value" not in str(blocked)

            if mode == "auto":
                args = {"path": "stdio-new.py", "content": "created = True\n"}
                preview = await client.call_tool("create_file", args)
                assert preview.is_error is not True
                assert preview.structured_content is not None
                assert preview.structured_content["applied"] is False
                assert not (root / "stdio-new.py").exists()

                wrong_type = await client.call_tool("create_file", {**args, "dry_run": "false"})
                assert wrong_type.is_error is True
                assert not (root / "stdio-new.py").exists()

                applied = await client.call_tool("create_file", {**args, "dry_run": False})
                assert applied.is_error is not True
                assert applied.structured_content is not None
                assert applied.structured_content["applied"] is True
                assert (root / "stdio-new.py").read_text(encoding="utf-8") == "created = True\n"
            else:
                from_modern = await client.call_tool("read_file", {"path": "stdio-new.py"})
                assert from_modern.is_error is not True
                assert from_modern.structured_content is not None
                assert from_modern.structured_content["content"] == "1: created = True"




async def exercise_git_stdio(root: Path, *, mode: str) -> None:
    """E/T14: actual independently opted-in Git CLI over real stdio MCP."""
    server = StdioServerParameters(
        command=sys.executable,
        args=[
            "-m", "gateway", "--root", str(root), "--transport", "stdio",
            "--allow-git", "--git-command", "status",
        ],
        cwd=str(Path(__file__).resolve().parents[1]),
        env={**os.environ, "HOME": str(root.parent)},
    )
    with anyio.fail_after(30):
        async with Client(server, mode=mode) as client:
            assert client.protocol_version == (
                LEGACY_VERSION if mode == "legacy" else MODERN_VERSION
            )
            tools = {tool.name for tool in (await client.list_tools()).tools}
            assert "run_git" in tools
            assert "run_command" not in tools
            preview = await client.call_tool("run_git", {"command": "status"})
            assert preview.is_error is not True, preview
            assert preview.structured_content is not None
            assert preview.structured_content["execute_started"] is False
            result = await client.call_tool(
                "run_git", {"command": "status", "dry_run": False},
            )
            assert result.is_error is not True, result
            assert result.structured_content["exit_code"] == 0
            assert result.structured_content["cleanup_status"] == "complete"
            for args in (
                {"command": "status", "options": None},
                {"command": "push",
                 "options": {"remote": "origin", "branch": "main"}},
            ):
                refused = await client.call_tool("run_git", args)
                assert refused.is_error is True, args


def assert_multi_stdio_still_refused(base: Path) -> None:
    """No hidden multi-Workspace stdio server may appear during Git opt-in."""
    completed = subprocess.run(
        [sys.executable, "-m", "gateway", "--config",
         str(base / "never-selected.json"), "--transport", "stdio", "--check"],
        cwd=Path(__file__).resolve().parents[1],
        text=True, capture_output=True, timeout=10,
    )
    assert completed.returncode == 2, completed
    assert not completed.stdout

def main() -> None:
    with tempfile.TemporaryDirectory(prefix="gateway-stdio-live-") as tmp:
        root = Path(tmp) / "project"
        root.mkdir()
        (root / "sample.py").write_text("state = 1\n", encoding="utf-8")
        (root / ".env").write_text("private-value", encoding="utf-8")
        asyncio.run(exercise_stdio(root, mode="auto"))
        asyncio.run(exercise_stdio(root, mode="legacy"))
        git_root = Path(tmp) / "git-project"
        git_root.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=git_root, check=True,
                       capture_output=True, text=True)
        asyncio.run(exercise_git_stdio(git_root, mode="auto"))
        asyncio.run(exercise_git_stdio(git_root, mode="legacy"))
        assert_multi_stdio_still_refused(Path(tmp))
    print(json.dumps({
        "real_mcp_stdio": "PASS",
        "stdio_verified": True,
        "protocols": [MODERN_VERSION, LEGACY_VERSION],
        "checks": [
            "sdk_client_auto_discovery",
            "sdk_client_legacy_initialize",
            "stdio_tool_list",
            "stdio_file_read",
            "stdio_create_preview_and_apply",
            "stdio_strict_boolean_rejection",
            "stdio_hidden_file_denied",
            "stdio_no_exec_or_skills",
            "stdio_process_cleanup",
            "git_modern_auto_preview_and_apply",
            "git_legacy_stdio_preview_and_apply",
            "git_rejected_null_and_unauthorized",
            "git_multi_stdio_denied",
        ],
    }, indent=2))


if __name__ == "__main__":
    main()
