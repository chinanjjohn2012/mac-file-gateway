"""Git policy stays entirely pure and compiles only frozen V1 command schemas."""
import subprocess
import pytest

from gateway.core import GatewayError
from gateway.git_policy import (
    GIT_V1_COMMANDS, compile_git_command, preview_git,
    validate_git_branch_name, validate_git_relative_path,
)


@pytest.mark.parametrize("command,options,paths,expected", [
    ("status", {}, [], ("status",)),
    ("status", {"short": True, "branch": True}, ["src/*[1].py"],
     ("status", "--short", "--branch", "--", ":(literal)src/*[1].py")),
    ("diff", {"cached": True, "stat": True}, ["-file"],
     ("diff", "--cached", "--stat", "--", ":(literal)-file")),
    ("log", {}, [], ("log", "--max-count=20")),
    ("log", {"limit": 5, "oneline": True}, [], ("log", "--max-count=5", "--oneline")),
    ("branch", {"action": "list"}, [], ("branch", "--list")),
    ("branch", {"action": "create", "name": "topic/+x"}, [],
     ("branch", "--", "topic/+x")),
    ("branch", {"action": "delete", "name": "topic"}, [],
     ("branch", "-d", "--", "topic")),
    ("switch", {"name": "main"}, [], ("switch", "--no-guess", "main")),
    ("switch", {"name": "x", "create": True}, [],
     ("switch", "--no-guess", "--no-track", "-c", "x", "HEAD")),
    ("add", {"all": True}, [], ("add", "-A")),
    ("add", {"update": True}, [], ("add", "-u")),
    ("add", {}, ["a[2].py"], ("add", "--", ":(literal)a[2].py")),
    ("commit", {"message": "hello"}, [], ("commit", "-m", "hello")),
    ("commit", {"message": "new", "amend": True}, [],
     ("commit", "--amend", "-m", "new")),
    ("fetch", {"remote": "origin"}, [], ("fetch", "origin")),
    ("fetch", {"remote": "origin", "prune": True}, [],
     ("fetch", "--prune", "origin")),
    ("pull", {"remote": "origin", "branch": "main"}, [],
     ("pull", "--ff-only", "origin", "refs/heads/main")),
    ("push", {"remote": "origin", "branch": "+main"}, [],
     ("push", "origin", "refs/heads/+main:refs/heads/+main")),
])
def test_exact_compiled_argv(command, options, paths, expected):
    item = compile_git_command(command, options=options, paths=paths)
    assert item.command == command
    assert item.argv == expected
    assert item.paths == tuple(paths)


def test_exact_command_set_and_lease():
    assert GIT_V1_COMMANDS == {"status", "diff", "log", "branch", "switch",
                               "add", "commit", "fetch", "pull", "push"}
    oid = "a" * 40
    item = compile_git_command("push", options={
        "remote": "origin", "branch": "+main",
        "force_with_lease": True, "expected_remote_oid": oid,
    })
    assert item.argv == (
        "push", "--force-with-lease=refs/heads/+main:" + oid,
        "origin", "refs/heads/+main:refs/heads/+main",
    )
    assert not any(s == "--force" or s.startswith("+") for s in item.argv)


@pytest.mark.parametrize("command", [
    "checkout", "clone", "restore", "reset", "clean", "rm",
    "config", "show", "remote", "rebase", None, "", 1,
])
def test_no_unimplemented_git_command(command):
    with pytest.raises(GatewayError) as exc:
        compile_git_command(command)
    assert exc.value.code == "git_command_not_allowed"


@pytest.mark.parametrize("command,opts,paths", [
    ("status", {"unknown": True}, []),
    ("status", {"short": 1}, []),
    ("diff", {"stat": "true"}, []),
    ("log", {"limit": 0}, []),
    ("log", {"limit": True}, []),
    ("log", {"limit": 51}, []),
    ("log", {"limit": 2.0}, []),
    ("branch", {}, []),
    ("branch", {"action": "list", "name": "x"}, []),
    ("branch", {"action": "create"}, []),
    ("branch", {"action": "force", "name": "x"}, []),
    ("switch", {}, []),
    ("switch", {"name": "main", "create": 1}, []),
    ("add", {}, []),
    ("add", {"all": True, "update": True}, []),
    ("add", {"all": 1}, []),
    ("commit", {}, []),
    ("commit", {"message": ""}, []),
    ("commit", {"message": "x", "amend": "yes"}, []),
    ("fetch", {}, []),
    ("fetch", {"remote": "https://host"}, []),
    ("pull", {"remote": "origin", "branch": "main", "ff_only": False}, []),
    ("push", {"remote": "origin", "branch": "main", "force_with_lease": True}, []),
    ("push", {"remote": "origin", "branch": "main", "expected_remote_oid": "f"*40}, []),
    ("push", {"remote": "origin", "branch": "main", "force_with_lease": True,
              "expected_remote_oid": "0"*40}, []),
    ("log", {}, ["x"]),
    ("commit", {"message": "x"}, ["x"]),
])
def test_invalid_options_rejected(command, opts, paths):
    with pytest.raises(GatewayError) as exc:
        compile_git_command(command, options=opts, paths=paths)
    assert exc.value.code == "git_option_invalid"


@pytest.mark.parametrize("options,paths", [
    (None, []), ([], []), ({}, None), ({}, "x"),
    ({}, ["x", "x"]), ({}, ["x"] * 65),
])
def test_invalid_option_container(options, paths):
    with pytest.raises(GatewayError):
        compile_git_command("status", options=options, paths=paths)


@pytest.mark.parametrize("name", [
    "-main", "../x", "x..y", "a@{b", "x.lock", "a/.hidden",
    "a//b", "a^b", "a:b", "a b", "@", ".", "a\nb", "a/",
])
def test_reject_bad_branch(name):
    with pytest.raises(GatewayError):
        validate_git_branch_name(name)


@pytest.mark.parametrize("path", [
    "", "../x", "/etc", "~/x", "./x", "x/../y", "x//y",
    "x/", "x\\y", "x:y", ":(top)x", "x\nb",
])
def test_reject_bad_path(path):
    with pytest.raises(GatewayError) as exc:
        validate_git_relative_path(path)
    assert exc.value.code == "git_path_blocked"


def test_preview_is_pure_and_clear_about_checks(monkeypatch):
    def no_process(*_a, **_kw):
        raise AssertionError("Git preview cannot start any child process")
    monkeypatch.setattr(subprocess, "Popen", no_process)
    result = preview_git("push", workspace="workspace-a", cwd="src",
                         options={"remote": "origin", "branch": "+main"})
    assert result["effective_argv"][-1] == "refs/heads/+main:refs/heads/+main"
    assert result["dry_run"] is True and result["execute_started"] is False
    assert result["repository_checked"] is False
    assert result["remote_checked"] is False
    assert result["branch_checked"] is False
    with pytest.raises(GatewayError):
        preview_git("status", timeout_seconds=True)
    with pytest.raises(GatewayError):
        preview_git("status", timeout_seconds=1)
