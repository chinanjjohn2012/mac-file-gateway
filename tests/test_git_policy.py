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
    ("diff", {"name_status": True}, [], ("diff", "--name-status")),
    ("diff", {"cached": True, "name_status": True, "stat": True}, ["-file"],
     ("diff", "--cached", "--name-status", "--stat", "--", ":(literal)-file")),
    ("diff", {"base": "a" * 40, "end": "b" * 40, "name_status": True, "stat": True}, [],
     ("--no-lazy-fetch", "diff", "--name-status", "--stat", "--end-of-options", "a" * 40, "b" * 40)),
    ("diff", {"base": "c" * 64, "end": "d" * 64}, [],
     ("--no-lazy-fetch", "diff", "--end-of-options", "c" * 64, "d" * 64)),
    ("diff", {"base": "266f0cc0", "end": "71cdcde8", "name_status": True}, [],
     ("--no-lazy-fetch", "diff", "--name-status", "--end-of-options", "266f0cc0", "71cdcde8")),
    ("diff", {"base": "266f0cc0", "end": "71cdcde8", "stat": True}, [],
     ("--no-lazy-fetch", "diff", "--stat", "--end-of-options", "266f0cc0", "71cdcde8")),
    ("diff", {"base": "266f0cc0", "end": "71cdcde8", "check": True}, [],
     ("--no-lazy-fetch", "diff", "--check", "--end-of-options", "266f0cc0", "71cdcde8")),
    ("diff", {"base": "266f0cc0", "end": "71cdcde8"}, [],
     ("--no-lazy-fetch", "diff", "--end-of-options", "266f0cc0", "71cdcde8")),
    ("diff", {"check": True}, [], ("diff", "--check")),
    ("diff", {"base": "a" * 40}, [],
     ("--no-lazy-fetch", "diff", "--end-of-options", "a" * 40)),
    ("diff", {"base": "266f0cc0", "end": "HEAD", "name_status": True}, [],
     ("--no-lazy-fetch", "diff", "--name-status", "--end-of-options", "266f0cc0", "HEAD")),
    ("diff", {"base": "HEAD~1", "end": "HEAD", "range": "..."}, ["src/a.py"],
     ("--no-lazy-fetch", "diff", "--end-of-options", "HEAD~1...HEAD", "--", ":(literal)src/a.py")),
    ("diff", {"base": "main", "cached": True, "numstat": True}, [],
     ("--no-lazy-fetch", "diff", "--cached", "--numstat", "--end-of-options", "main")),
    ("diff", {"base": "topic", "end": "HEAD", "range": "..", "stat": True,
              "unified": 3, "diff_filter": "AM"}, [],
     ("--no-lazy-fetch", "diff", "--stat", "-U3", "--diff-filter=AM",
      "--end-of-options", "topic..HEAD")),
    ("diff", {"base": "HEAD", "pickaxe": "token"}, [],
     ("--no-lazy-fetch", "diff", "-Stoken", "--end-of-options", "HEAD")),
    ("log", {}, [], ("log", "--max-count=20")),
    ("rev-parse", {}, [], ("--no-lazy-fetch", "rev-parse", "--verify", "HEAD^{tree}")),
    ("rev-parse", {"target": "tree"}, [], ("--no-lazy-fetch", "rev-parse", "--verify", "HEAD^{tree}")),
    ("rev-parse", {"target": "head"}, [], ("--no-lazy-fetch", "rev-parse", "--verify", "HEAD^{commit}")),
    ("rev-parse", {"target": "branch", "name": "topic/+x"}, [],
     ("--no-lazy-fetch", "rev-parse", "--verify", "--end-of-options", "refs/heads/topic/+x")),
    ("rev-list", {"commit": "a" * 40}, [],
     ("--no-lazy-fetch", "rev-list", "--parents", "--max-count=1", "--end-of-options", "a" * 40)),
    ("rev-list", {"commit": "a" * 8}, [],
     ("--no-lazy-fetch", "rev-list", "--parents", "--max-count=1", "--end-of-options", "a" * 8)),
    ("diff", {"base": "abc", "end": "def0"}, [],
     ("--no-lazy-fetch", "diff", "--end-of-options", "abc", "def0")),
    ("rev-list", {"commit": "e" * 64, "limit": 5}, [],
     ("--no-lazy-fetch", "rev-list", "--parents", "--max-count=5", "--end-of-options", "e" * 64)),
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
                               "add", "commit", "fetch", "pull", "push",
                               "rev-parse", "rev-list"}
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
    ("diff", {"end": "b" * 40}, []),
    ("diff", {"base": "a" * 40, "end": "b" * 40, "cached": True}, []),
    ("diff", {"base": "A" * 40, "end": "B" * 40}, []),
    ("diff", {"base": "0" * 40, "end": "0" * 40}, []),
    ("diff", {"check": "yes"}, []),
    ("diff", {"output": "/tmp/x"}, []),
    ("diff", {"ext_diff": True}, []),
    ("diff", {"textconv": True}, []),
    ("diff", {"no_index": True}, []),
    ("diff", {"base": "a..b", "end": "main"}, []),
    ("diff", {"base": "--output=x", "end": "main"}, []),
    ("diff", {"base": "HEAD", "end": "main", "range": "...."}, []),
    ("diff", {"base": "HEAD", "range": ".."}, []),
    ("diff", {"patch": True, "no_patch": True}, []),
    ("diff", {"merge_base": True}, []),
    ("diff", {"pickaxe": ""}, []),
    ("diff", {"diff_filter": "Q"}, []),
    ("diff", {"unified": -1}, []),
    ("rev-parse", {"target": "branch"}, []),
    ("rev-parse", {"target": "head", "name": "main"}, []),
    ("rev-parse", {"target": "tree", "name": "main"}, []),
    ("rev-parse", {"name": "main"}, []),
    ("rev-parse", {"target": "main"}, []),
    ("rev-list", {}, []),
    ("rev-list", {"commit": "HEAD"}, []),
    ("rev-list", {"commit": "a" * 40, "limit": 0}, []),
    ("rev-list", {"commit": "a" * 40, "limit": 51}, []),
    ("rev-list", {"commit": "a" * 40}, ["x"]),
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
    tree = preview_git("rev-parse")
    assert tree["effective_argv"] == ["--no-lazy-fetch", "rev-parse", "--verify", "HEAD^{tree}"]
    assert tree["options"] == {} and tree["paths"] == []
    assert tree["execute_started"] is False
    assert tree["repository_checked"] is False
    head = preview_git("rev-parse", options={"target": "head"})
    assert head["effective_argv"] == ["--no-lazy-fetch", "rev-parse", "--verify", "HEAD^{commit}"]
    assert head["options"] == {"target": "head"}
    assert head["execute_started"] is False and head["repository_checked"] is False
    base, end = "a" * 40, "b" * 40
    ranged = preview_git("diff", options={"base": base, "end": end, "name_status": True})
    assert ranged["effective_argv"] == ["--no-lazy-fetch", "diff", "--name-status",
                                        "--end-of-options", base, end]
    assert ranged["execute_started"] is False and ranged["branch_checked"] is False
    parents = preview_git("rev-list", options={"commit": end})
    assert parents["effective_argv"] == ["--no-lazy-fetch", "rev-list", "--parents",
                                         "--max-count=1", "--end-of-options", end]
    assert parents["execute_started"] is False and parents["repository_checked"] is False
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


@pytest.mark.parametrize("options,paths", [
    ({"revision": "HEAD"}, []),
    ({"revision": "HEAD~1^{tree}"}, []),
    ({"verify": True}, []),
    ({"args": ["--git-dir"]}, []),
    ({"output": "/tmp/tree"}, []),
    ({"end_of_options": True}, []),
    ({}, ["HEAD^{tree}"]),
    ({}, ["file.txt"]),
])
def test_head_tree_rejects_all_options_and_nonempty_paths(options, paths):
    with pytest.raises(GatewayError) as exc:
        compile_git_command("rev-parse", options=options, paths=paths)
    assert exc.value.code == "git_option_invalid"


@pytest.mark.parametrize("target", [None, True, 1, [], {}, "", "HEAD", "HEAD~1", "main", "--git-dir"])
def test_rev_parse_rejects_targets_outside_fixed_selector(target):
    with pytest.raises(GatewayError) as exc:
        compile_git_command("rev-parse", options={"target": target})
    assert exc.value.code == "git_option_invalid"
