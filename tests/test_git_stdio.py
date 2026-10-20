"""D/T10: actual Legacy MCP stdio client with both SDK v2 protocol modes.

Uses an independent disposable server process and temporary local Git repo.
"""
from __future__ import annotations

import asyncio
import os
from pathlib import Path
import subprocess
import sys

import pytest
pytest.importorskip("mcp", reason="Official MCP SDK required")

import anyio
from mcp.client import Client
from mcp.client.stdio import StdioServerParameters


@pytest.mark.parametrize("mode,version", [
    ("auto", "2026-07-28"),
    ("legacy", "2025-11-25"),
])
def test_actual_legacy_stdio_git_grants_preview_apply_and_rejection(
    tmp_path, mode, version,
):
    repo = tmp_path / "project"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    home = tmp_path / "home"
    home.mkdir()

    server = StdioServerParameters(
        command=sys.executable,
        args=[
            "-m", "gateway", "--root", str(repo),
            "--transport", "stdio", "--allow-git",
            "--git-command", "status",
        ],
        cwd=str(Path(__file__).resolve().parents[1]),
        env={**os.environ, "HOME": str(home)},
    )

    async def exercise():
        with anyio.fail_after(30):
            async with Client(server, mode=mode) as client:
                assert client.protocol_version == version
                tools = {tool.name for tool in (await client.list_tools()).tools}
                assert "run_git" in tools
                assert "run_command" not in tools

                preview = await client.call_tool("run_git", {"command": "status"})
                assert preview.is_error is not True, preview
                assert preview.structured_content is not None
                assert preview.structured_content["dry_run"] is True
                assert preview.structured_content["execute_started"] is False
                assert preview.structured_content["repository_checked"] is False

                applied = await client.call_tool(
                    "run_git", {"command": "status", "dry_run": False},
                )
                assert applied.is_error is not True, applied
                assert applied.structured_content["exit_code"] == 0
                assert applied.structured_content["cleanup_status"] == "complete"

                for arguments in (
                    {"command": "push", "options": {"remote": "origin", "branch": "main"}},
                    {"command": "status", "options": {"unknown": True}},
                    {"command": "status", "dry_run": "false"},
                    {"command": "status", "paths": ["../outside"]},
                ):
                    denied = await client.call_tool("run_git", arguments)
                    assert denied.is_error is True, arguments

    asyncio.run(exercise())
    records = home / ".config" / "mac-file-gateway" / "git-legacy-state"
    assert records.is_dir()
    assert not list(records.iterdir())


def test_legacy_stdio_default_git_off_even_when_transport_available(tmp_path):
    repo = tmp_path / "project"
    repo.mkdir()
    home = tmp_path / "home"
    home.mkdir()
    server = StdioServerParameters(
        command=sys.executable,
        args=["-m", "gateway", "--root", str(repo), "--transport", "stdio"],
        cwd=str(Path(__file__).resolve().parents[1]),
        env={**os.environ, "HOME": str(home)},
    )

    async def exercise():
        with anyio.fail_after(20):
            async with Client(server, mode="auto") as client:
                tools = {tool.name for tool in (await client.list_tools()).tools}
                assert "run_git" not in tools
                assert "run_command" not in tools

    asyncio.run(exercise())
