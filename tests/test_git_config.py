"""Git allowlists are independent from File API, command Exec, and Skills."""
import pytest

from gateway.private_fs import PrivateFileError
from gateway.workspaces_config import parse_workspace_config


def sample():
    return {"schema_version": 1, "workspaces": {
        "a": {"root": "/tmp/work-a", "read": {"enabled": True},
              "write": {"enabled": False}},
        "b": {"root": "/tmp/work-b", "write": {"enabled": False}},
    }}


def test_default_git_is_disabled_and_no_workspace_is_authorized():
    settings = parse_workspace_config(sample())
    assert not settings.git_enabled
    assert all(ws.git_allowed_commands == () for ws in settings.workspaces)


def test_global_gate_workspace_allowlist_and_file_permissions_are_independent():
    config = sample()
    config["server"] = {"git": {"enabled": True}}
    config["workspaces"]["a"]["git"] = {"allowed_commands": ["status", "log"]}
    config["workspaces"]["b"]["git"] = {"allowed_commands": ["pull", "push"]}
    settings = parse_workspace_config(config)
    assert settings.git_enabled
    assert settings.workspaces[0].git_allowed_commands == ("status", "log")
    assert settings.workspaces[1].git_allowed_commands == ("pull", "push")
    assert all(not ws.allow_write for ws in settings.workspaces)


@pytest.mark.parametrize("invalid", [
    None, False, [], {"enabled": 1}, {"enabled": "true"},
    {"enabled": True, "unknown": 1},
])
def test_server_git_strict_shape(invalid):
    config = sample()
    config["server"] = {"git": invalid}
    with pytest.raises(PrivateFileError):
        parse_workspace_config(config)


@pytest.mark.parametrize("invalid", [
    None, False, [], {"allowed_commands": None},
    {"allowed_commands": "status"},
    {"allowed_commands": ["status", "status"]},
    {"allowed_commands": ["checkout"]}, {"allowed_commands": ["clone"]},
    {"allowed_commands": ["run_command"]},
    {"allowed_commands": ["STATUS"]}, {"allowed_commands": [5]},
    {"allowed_commands": ["status"], "unrecognized": "x"},
])
def test_workspace_git_strict_shape(invalid):
    config = sample()
    config["server"] = {"git": {"enabled": True}}
    config["workspaces"]["a"]["git"] = invalid
    with pytest.raises(PrivateFileError):
        parse_workspace_config(config)


def test_disabled_global_gate_rejects_nonempty_grants():
    config = sample()
    config["workspaces"]["a"]["git"] = {"allowed_commands": ["status"]}
    with pytest.raises(PrivateFileError):
        parse_workspace_config(config)
    config["server"] = {"git": {"enabled": False}}
    with pytest.raises(PrivateFileError):
        parse_workspace_config(config)


def test_enabled_global_gate_without_workspace_grants_still_deny_all():
    config = sample()
    config["server"] = {"git": {"enabled": True}}
    result = parse_workspace_config(config)
    assert all(not ws.git_allowed_commands for ws in result.workspaces)
