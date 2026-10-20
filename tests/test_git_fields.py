"""Strict run_git envelope checks, before MCP SDK can coerce JSON values."""
import pytest

from gateway.core import GatewayError
from gateway.multi_fields import validate_tool_arguments


def test_explicit_workspace_in_multi_and_no_workspace_in_legacy():
    assert validate_tool_arguments("run_git",
                                   {"workspace": "a", "command": "status"}, multi=True)
    assert validate_tool_arguments("run_git", {"command": "status"}, multi=False)
    with pytest.raises(GatewayError) as exc:
        validate_tool_arguments("run_git", {"command": "status"}, multi=True)
    assert exc.value.code == "workspace_required"
    with pytest.raises(GatewayError):
        validate_tool_arguments("run_git", {"workspace": "a", "command": "status"}, multi=False)


@pytest.mark.parametrize("name,value", [
    ("command", "checkout"), ("command", "clone"), ("command", None),
    ("cwd", "/etc"), ("cwd", "../outside"), ("cwd", None),
    ("options", None), ("options", []), ("options", {"unknown": True}),
    ("options", {"short": 1}), ("options", {"short": "yes"}),
    ("paths", None), ("paths", "x"), ("paths", ["../outside"]),
    ("paths", ["x"] * 65),
    ("timeout_seconds", 1), ("timeout_seconds", 901),
    ("timeout_seconds", True), ("timeout_seconds", "120"),
    ("dry_run", "false"), ("dry_run", 1),
    ("argv", ["git", "status"]), ("raw_argv", []), ("extra_args", ["-C", ".."]),
])
def test_malformed_run_git_rejected_legacy_and_multi(name, value):
    for multi in (False, True):
        payload = {"command": "status"}
        if multi:
            payload["workspace"] = "a"
        payload[name] = value
        with pytest.raises(GatewayError):
            validate_tool_arguments("run_git", payload, multi=multi)


def test_nested_command_specific_validation_and_paths():
    status = {"workspace": "a", "command": "status", "cwd": "src",
              "paths": ["x[2].py"], "options": {"short": True},
              "timeout_seconds": 900, "dry_run": True}
    assert validate_tool_arguments("run_git", status, multi=True) == status
    for command, options in (("commit", {"message": "m"}),
                             ("push", {"remote": "origin", "branch": "+main"}),
                             ("switch", {"name": "main"})):
        with pytest.raises(GatewayError) as exc:
            validate_tool_arguments("run_git", {"workspace": "a", "command": command,
                                                "options": options, "paths": ["x"]}, multi=True)
        assert exc.value.code == "git_option_invalid"


def test_phase_d_git_adapters_use_only_the_reviewed_sync_git_service():
    # A's pure compiler remains separate; D intentionally registers run_git.
    # Neither adapter may turn the structured schema into a raw command
    # execution fallback, and authorization is repeated by invoke_git.
    from pathlib import Path
    root = Path(__file__).resolve().parents[1] / "gateway"
    legacy = (root / "mcp_adapter.py").read_text(encoding="utf-8")
    multi = (root / "mcp_multi.py").read_text(encoding="utf-8")
    assert "async def run_git(" in legacy
    assert "async def run_git(" in multi
    assert "run_in_threadpool(\n                    gateway.invoke_git" in legacy
    assert "run_in_threadpool(\n                    service.invoke_git" in multi
    assert "run_in_threadpool(gateway.run_command" not in legacy
    assert "run_in_threadpool(service.invoke, workspace, 'run_git'" not in multi
