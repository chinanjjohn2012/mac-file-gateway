"""F/T15-T16: release documentation, example defaults and reviewed Git metadata.

The published 2.4.0 label must not imply Git is already released.
These tests are pure reads: no network, subprocesses, project writes or Git.
"""
from __future__ import annotations

import json
from pathlib import Path

from gateway.git_policy import GIT_V1_COMMANDS
from gateway.workspaces_config import parse_workspace_config


ROOT = Path(__file__).resolve().parents[1]


def test_build_info_records_candidate_without_premature_release_bump():
    metadata = json.loads((ROOT / "BUILD_INFO.json").read_text(encoding="utf-8"))
    assert metadata["bundle_release"] == "2.4.0"
    assert metadata["runtime_version"] == "2.4.0"
    assert metadata["source_baseline"] == "release/ms1"
    git = metadata["git_cli_v1"]
    assert git["release_status"] == "candidate_not_published_in_release_ms1"
    assert set(git["supported_commands"]) == GIT_V1_COMMANDS
    assert git["mcp_protocols"] == ["2025-11-25", "2026-07-28"]
    assert git["rest_endpoint"] == "POST /git/run"
    assert metadata["mcp_tools_when_git_authorized"] == ["run_git"]
    assert git["default_preview"] is True
    assert git["timeout_seconds"] == {"default": 120, "min": 10, "max": 900}
    assert git["max_git_request_bytes"] == 65536
    assert git["legacy_stdio"] is True and git["multi_stdio"] is False
    assert git["read_only_does_not_disable_git"] is True
    assert git["offline_only_quarantine_recovery"] is True
    assert git["git_is_not_a_sandbox"] is True


def test_public_multi_example_is_valid_and_git_fail_closed_by_default():
    raw = json.loads((ROOT / "samples" / "gateway.example.json").read_text())
    config = parse_workspace_config(raw)
    assert raw["server"]["git"]["enabled"] is False
    assert config.git_enabled is False
    assert len(config.workspaces) == 2
    for name, item in raw["workspaces"].items():
        assert item["git"] == {"allowed_commands": []}, name
    assert all(not item.git_allowed_commands for item in config.workspaces)
    # Enabling the server alone still grants no individual Git command.
    raw["server"]["git"]["enabled"] = True
    assert all(not item.git_allowed_commands
               for item in parse_workspace_config(raw).workspaces)


def test_main_and_chinese_compatibility_readmes_disclose_actual_git_boundaries():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    zh = (ROOT / "README.zh-CN.md").read_text(encoding="utf-8")
    for token in ("--allow-git", "--git-command", "server.git.enabled",
                  "git.allowed_commands", "run_git", "POST /git/run",
                  "dry_run", "read_only", "git_repository_quarantined",
                  "git_global_quarantined", "本地管理员", "2026-07-28"):
        assert token in readme, token
    assert "Multi stdio" in readme
    assert "default_preview" in json.dumps(json.loads(
        (ROOT / "BUILD_INFO.json").read_text(encoding="utf-8")))
    assert "README.md" in zh
    assert "未合并" in zh and "--allow-git" in zh
    for path in ("README.md", "README.zh-CN.md", "samples/gateway.example.json"):
        text = (ROOT / path).read_text(encoding="utf-8")
        assert "adx-opsagent" not in text
        assert "adx-codeagent" not in text
