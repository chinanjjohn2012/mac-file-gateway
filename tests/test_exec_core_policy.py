"""Configuration intent must never become a live execution capability."""
from dataclasses import FrozenInstanceError
from types import SimpleNamespace
import json

import pytest

from gateway.private_fs import PrivateFileError
from gateway.workspaces_config import parse_workspace_config, read_workspace_config


def config(policy=None):
    entry = {"root": "/tmp/core-fixture"}
    if policy is not None:
        entry["exec"] = policy
    return {"schema_version": 1, "workspaces": {"a": entry}}


def test_exec_defaults_disabled():
    policy = parse_workspace_config(config()).workspaces[0].execution
    assert (policy.enabled, policy.paths, policy.runners) == (False, (), ())
    with pytest.raises(FrozenInstanceError):
        policy.enabled = True


@pytest.mark.parametrize("policy", [{"enabled": True}, {"enabled": True, "paths": []}])
def test_enabled_requires_explicit_scope(policy):
    with pytest.raises(PrivateFileError):
        parse_workspace_config(config(policy))


def test_root_scope_requires_literal_dot():
    value = parse_workspace_config(config({"enabled": True, "paths": ["."]}))
    assert value.workspaces[0].execution.paths == (".",)


@pytest.mark.parametrize("policy", [
    None, [], True, {"enabled": 1}, {"enabled": "true"},
    {"paths": ["service"]}, {"runners": {"service": "direct"}},
    {"enabled": True, "paths": ["service"], "extra": 0},
    {"enabled": True, "paths": ["service", "service"]},
    *({"enabled": True, "paths": [p]} for p in ["", "../x", "/tmp", "~", "a//b", "a/./b", "a/../b", "a/", "a\\b", "a:b", "a*", "a\x00", "a\n", "a\ud800"]),
    {"enabled": True, "paths": ["a" * 2049]},
    {"enabled": True, "paths": [str(i) for i in range(129)]},
    {"enabled": True, "paths": ["."], "runners": []},
    {"enabled": True, "paths": ["."], "runners": {"a": "shell"}},
    {"enabled": True, "paths": ["."], "runners": {"a": True}},
    {"enabled": True, "paths": ["."], "runners": {"../a": "direct"}},
    {"enabled": True, "paths": ["."], "runners": {"a" * 2049: "direct"}},
    {"enabled": True, "paths": ["."], "runners": {str(i): "direct" for i in range(129)}},
])
def test_invalid_policy_fields(policy):
    from gateway.exec_policy import parse_exec_policy
    with pytest.raises(PrivateFileError):
        parse_exec_policy(policy)


def test_runner_map_cannot_escape_scope():
    from gateway.exec_policy import parse_exec_policy
    with pytest.raises(PrivateFileError):
        parse_exec_policy({"enabled": True, "paths": ["service"], "runners": {"service-extra": "direct"}})
    policy = parse_exec_policy({"enabled": True, "paths": ["service"],
                                "runners": {"service": "pipenv", "service/sub": "direct"}})
    assert dict(policy.runners) == {"service": "pipenv", "service/sub": "direct"}


@pytest.mark.parametrize("entrypoint", ["reader", "app", "mcp", "cli-check", "cli-http", "cli-mcp"])
def test_every_public_factory_rejects_enabled_policy(tmp_path, monkeypatch, entrypoint):
    from gateway import http_multi, mcp_multi, multi_cli
    from gateway import workspaces_config
    from gateway.exec_policy import assert_exec_runtime_unavailable
    policy = {"enabled": True, "paths": ["."]}
    settings = parse_workspace_config(config(policy))
    calls = []
    def forbidden(*args, **kwargs):
        calls.append(1)
        raise AssertionError("runtime constructed before activation guard")
    monkeypatch.setattr("subprocess.Popen", forbidden)
    monkeypatch.setattr(mcp_multi, "StrictWorkspaceMCP", forbidden)
    monkeypatch.setattr(http_multi, "Starlette", forbidden)
    monkeypatch.setattr(multi_cli, "WorkspaceService", forbidden)
    with pytest.raises(PrivateFileError):
        assert_exec_runtime_unavailable(settings)
    if entrypoint == "reader":
        monkeypatch.setattr(workspaces_config, "read_private_json", lambda path: config(policy))
        with pytest.raises(PrivateFileError) as exc:
            read_workspace_config(str(tmp_path / "config.json"))
        assert "/tmp/core-fixture" not in str(exc.value)
    elif entrypoint.startswith("cli"):
        monkeypatch.setattr(multi_cli, "read_workspace_config", lambda path: settings)
        args = SimpleNamespace(config=str(tmp_path / "config.json"), check=entrypoint == "cli-check", http_only=entrypoint == "cli-http")
        assert multi_cli.run_multi(args) == 2
    else:
        factory = http_multi.create_multi_app if entrypoint == "app" else mcp_multi.build_multi_mcp
        with pytest.raises(PrivateFileError):
            factory(SimpleNamespace(settings=settings))
    assert calls == []


def test_local_skills_still_cannot_enable():
    obj = config({"enabled": True, "paths": ["."]})
    obj["workspaces"]["a"]["local_skills"] = {"enabled": True}
    with pytest.raises(PrivateFileError):
        parse_workspace_config(obj)
