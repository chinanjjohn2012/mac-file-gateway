"""E/T12: native Git semantics through the reviewed synchronous Workspace API.

Everything is created in pytest temporary directories. No network remotes,
SSH agents, user-managed repos, or real Gateway instances are involved.
"""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import threading
import time

import pytest

from gateway.core import GatewayError
from gateway.git_repository import RepositoryIdentity
from gateway.workspaces import ActiveRuntimeInventory, WorkspaceService
from gateway.workspaces_config import parse_workspace_config


DISCOVERY = (
    "rev-parse", "--path-format=absolute", "--show-toplevel",
    "--absolute-git-dir", "--git-common-dir",
)


def git(where: Path, *args: str, code: int = 0) -> str:
    p = subprocess.run(["git", *args], cwd=where, text=True, capture_output=True)
    assert p.returncode == code, (where, args, p.returncode, p.stderr)
    return p.stdout.strip()


def fixture(tmp_path: Path, *, grants=None):
    repo = tmp_path / "project"
    repo.mkdir()
    a, b = repo / "a", repo / "b"
    a.mkdir()
    b.mkdir()
    git(repo, "init", "-q")
    git(repo, "config", "user.name", "Git E Fixture")
    git(repo, "config", "user.email", "fixture@example.invalid")
    (a / "one.txt").write_text("one\n")
    (b / "two.txt").write_text("two\n")
    git(repo, "add", "a/one.txt", "b/two.txt")
    git(repo, "commit", "-qm", "initial")
    git(repo, "branch", "-M", "main")
    control = tmp_path / "control"
    control.mkdir(mode=0o700)
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    default = {
        "a": ["status", "diff", "add", "commit", "branch", "switch", "push", "fetch", "log"],
        "b": ["status", "diff", "add", "commit", "pull"],
    }
    grants = default if grants is None else grants
    raw = {"schema_version": 1, "server": {"git": {"enabled": True}},
           "workspaces": {
               name: {"root": str(repo / name),
                      "git": {"allowed_commands": commands}}
               for name, commands in grants.items()}}
    service = WorkspaceService(
        parse_workspace_config(raw), config_dir=control,
        inventory=ActiveRuntimeInventory(paths=(runtime,)),
    )
    return repo, a, b, control, service


def apply(service, workspace, command, *, options=None, paths=None, timeout=30):
    result = service.invoke_git(
        workspace, command, options=options, paths=paths,
        timeout_seconds=timeout, dry_run=False,
    )
    assert result["execute_started"] is True
    assert result["cleanup_status"] == "complete"
    assert result["repository_checked"] is True
    return result


def test_pull_from_sibling_updates_tracked_ignored_file_outside_workspace(tmp_path):
    repo, a, b, control, service = fixture(tmp_path)
    try:
        (repo / ".gitignore").write_text("*.secret\n")
        (b / ".gitignore").write_text("*.temp\n")
        (repo / ".git" / "info" / "exclude").write_text("*.excluded\n")
        (a / "keep.secret").write_text("old ignored but tracked\n")
        git(repo, "add", ".gitignore", "b/.gitignore")
        git(repo, "add", "-f", "a/keep.secret")
        git(repo, "commit", "-qm", "tracked ignored path")
        (a / "untracked.secret").write_text("never add\n")
        (b / "untracked.temp").write_text("never add\n")
        (b / "untracked.excluded").write_text("never add\n")

        remote = tmp_path / "bare.git"
        git(tmp_path, "init", "--bare", "-q", str(remote))
        git(repo, "remote", "add", "origin", str(remote))
        git(repo, "push", "-q", "origin", "main")
        git(remote, "symbolic-ref", "HEAD", "refs/heads/main")
        writer = tmp_path / "writer"
        git(tmp_path, "clone", "-q", str(remote), str(writer))
        git(writer, "config", "user.name", "Git E Fixture")
        git(writer, "config", "user.email", "fixture@example.invalid")
        (writer / "a" / "keep.secret").write_text("remote changed ignored tracked\n")
        git(writer, "commit", "-qam", "update tracked ignored")
        git(writer, "push", "-q", "origin", "main")

        with pytest.raises(GatewayError) as error:
            service.invoke_git("a", "pull", options={"remote": "origin", "branch": "main"},
                               dry_run=False)
        assert error.value.code == "git_command_not_allowed"
        result = apply(service, "b", "pull",
                       options={"remote": "origin", "branch": "main"})
        assert result["exit_code"] == 0, result["stderr"]
        assert (a / "keep.secret").read_text() == "remote changed ignored tracked\n"
        listed = git(repo, "status", "--porcelain=v1", "--untracked-files=all")
        assert "untracked.secret" not in listed
        assert "untracked.temp" not in listed
        assert "untracked.excluded" not in listed
        assert list((control / "git-state").iterdir()) == []
    finally:
        service.close()


def test_add_all_can_stage_entire_parent_but_literal_paths_stay_scoped(tmp_path):
    repo, a, b, control, service = fixture(tmp_path)
    try:
        (a / "sibling.txt").write_text("new\n")
        (b / "local.txt").write_text("new\n")
        first = apply(service, "b", "add", options={"all": True})
        assert first["exit_code"] == 0
        assert git(repo, "diff", "--cached", "--name-only").splitlines() == [
            "a/sibling.txt", "b/local.txt",
        ]
        git(repo, "reset", "-q")
        (b / "literal[1].txt").write_text("literal\n")
        (b / "literal1.txt").write_text("wildcard non-match\n")
        result = apply(service, "b", "add", paths=["literal[1].txt"])
        assert result["exit_code"] == 0
        assert git(repo, "diff", "--cached", "--name-only").splitlines() == [
            "b/literal[1].txt",
        ]
        (b / "alias").symlink_to(a, target_is_directory=True)
        for path in ("../a/sibling.txt", "/tmp/forbidden", "alias/sibling.txt",
                     ":(top)a/sibling.txt", "literal[1].txt:other"):
            with pytest.raises(GatewayError) as err:
                service.invoke_git("b", "add", paths=[path], dry_run=False)
            assert err.value.code == "git_path_blocked"
        assert git(repo, "diff", "--cached", "--name-only").splitlines() == [
            "b/literal[1].txt",
        ]
        assert list((control / "git-state").iterdir()) == []
    finally:
        service.close()


def test_native_hook_and_clean_filter_can_affect_parent_repository(tmp_path):
    repo, a, b, _, service = fixture(tmp_path)
    try:
        hook = repo / ".git" / "hooks" / "pre-commit"
        hook.write_text("#!/bin/sh\nprintf 'hook ran\\n' > a/hook-effect.txt\n")
        hook.chmod(0o755)
        (b / "change.txt").write_text("commit change\n")
        assert apply(service, "b", "add", paths=["change.txt"])["exit_code"] == 0
        committed = apply(service, "b", "commit", options={"message": "hook fixture"})
        assert committed["exit_code"] == 0, committed["stderr"]
        assert (a / "hook-effect.txt").read_text() == "hook ran\n"

        git(repo, "config", "filter.marker.clean",
            "sh -c 'cat; printf filtered > a/filter-effect.txt'")
        (b / ".gitattributes").write_text("filtered.txt filter=marker\n")
        (b / "filtered.txt").write_text("filtered input\n")
        filtered = apply(service, "b", "add",
                         paths=[".gitattributes", "filtered.txt"])
        assert filtered["exit_code"] == 0, filtered["stderr"]
        assert (a / "filter-effect.txt").read_text() == "filtered"
        assert "b/filtered.txt" in git(repo, "diff", "--cached", "--name-only")
    finally:
        service.close()


def test_switch_does_not_guess_remote_and_unknown_commands_are_forbidden(tmp_path):
    repo, a, _, _, service = fixture(tmp_path)
    try:
        remote = tmp_path / "bare.git"
        git(tmp_path, "init", "-q", "--bare", str(remote))
        git(repo, "remote", "add", "origin", str(remote))
        git(repo, "branch", "remoteonly")
        git(repo, "push", "-q", "origin", "remoteonly")
        git(repo, "branch", "-D", "remoteonly")
        git(repo, "fetch", "-q", "origin")
        assert git(repo, "branch", "--list", "remoteonly") == ""
        with pytest.raises(GatewayError) as e:
            service.invoke_git("a", "switch", options={"name": "remoteonly"},
                               dry_run=False)
        assert e.value.code == "git_branch_unknown"
        assert git(repo, "branch", "--list", "remoteonly") == ""

        branch = apply(service, "a", "branch",
                       options={"action": "create", "name": "localnew"})
        assert branch["exit_code"] == 0
        moved = apply(service, "a", "switch", options={"name": "localnew"})
        assert moved["exit_code"] == 0
        assert git(repo, "branch", "--show-current") == "localnew"
        for command in ("checkout", "clone"):
            with pytest.raises(GatewayError) as e2:
                service.invoke_git("a", command, dry_run=False)
            assert e2.value.code == "git_command_not_allowed"
    finally:
        service.close()


def test_non_fast_forward_and_invalid_lease_do_not_modify_remote(tmp_path):
    repo, a, _, _, service = fixture(tmp_path)
    try:
        remote = tmp_path / "bare.git"
        git(tmp_path, "init", "--bare", "-q", str(remote))
        git(repo, "remote", "add", "origin", str(remote))
        git(repo, "push", "-q", "origin", "main")
        old_oid = git(remote, "rev-parse", "refs/heads/main")

        created = apply(service, "a", "branch",
                        options={"action": "create", "name": "+main"})
        assert created["exit_code"] == 0
        pushed = apply(service, "a", "push",
                       options={"remote": "origin", "branch": "+main"})
        assert pushed["exit_code"] == 0, pushed["stderr"]
        assert git(remote, "rev-parse", "refs/heads/+main") == old_oid
        assert git(remote, "rev-parse", "refs/heads/main") == old_oid

        git(remote, "symbolic-ref", "HEAD", "refs/heads/main")
        writer = tmp_path / "writer"
        git(tmp_path, "clone", "-q", str(remote), str(writer))
        git(writer, "config", "user.name", "Git E Fixture")
        git(writer, "config", "user.email", "fixture@example.invalid")
        (writer / "a" / "one.txt").write_text("remote ahead\n")
        git(writer, "commit", "-qam", "remote moved")
        git(writer, "push", "-q", "origin", "main")
        newer_oid = git(remote, "rev-parse", "refs/heads/main")
        assert newer_oid != old_oid

        (a / "one.txt").write_text("local diverged\n")
        git(repo, "commit", "-qam", "local moved")
        normal = apply(service, "a", "push",
                       options={"remote": "origin", "branch": "main"})
        assert normal["exit_code"] != 0
        assert git(remote, "rev-parse", "refs/heads/main") == newer_oid
        lease = apply(service, "a", "push",
                      options={"remote": "origin", "branch": "main",
                               "force_with_lease": True,
                               "expected_remote_oid": old_oid})
        assert lease["exit_code"] != 0
        assert git(remote, "rev-parse", "refs/heads/main") == newer_oid
        assert apply(service, "a", "status")["exit_code"] == 0
    finally:
        service.close()


def test_git_environment_pollution_does_not_select_wrong_repo(tmp_path, monkeypatch):
    repo, a, _, _, previous = fixture(tmp_path)
    previous.close()
    impostor = tmp_path / "impostor"
    git(tmp_path, "init", "-q", str(impostor))
    monkeypatch.setenv("GIT_DIR", str(impostor / ".git"))
    monkeypatch.setenv("GIT_WORK_TREE", str(impostor))
    monkeypatch.setenv("GIT_INDEX_FILE", str(impostor / "index"))
    monkeypatch.setenv("GIT_COMMON_DIR", str(impostor / ".git"))
    # A new runner captures the polluted process environment before filtering.
    settings = parse_workspace_config({
        "schema_version": 1, "server": {"git": {"enabled": True}},
        "workspaces": {"a": {"root": str(a),
                            "git": {"allowed_commands": ["status"]}}},
    })
    control = tmp_path / "fresh-control"
    control.mkdir(mode=0o700)
    runtime = tmp_path / "fresh-runtime"
    runtime.mkdir()
    service = WorkspaceService(settings, config_dir=control,
                               inventory=ActiveRuntimeInventory(paths=(runtime,)))
    try:
        (a / "one.txt").write_text("changed\n")
        result = apply(service, "a", "status", options={"short": True})
        assert result["exit_code"] == 0
        assert "one.txt" in result["stdout"]
        assert "impostor" not in result["stdout"]
    finally:
        service.close()


def test_true_git_free_preview_even_outside_repository(tmp_path, monkeypatch):
    root = tmp_path / "plain"
    root.mkdir()
    control = tmp_path / "control"
    control.mkdir(mode=0o700)
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    settings = parse_workspace_config({
        "schema_version": 1, "server": {"git": {"enabled": True}},
        "workspaces": {"a": {"root": str(root),
                            "git": {"allowed_commands": ["status", "branch"]}}},
    })
    service = WorkspaceService(settings, config_dir=control,
                               inventory=ActiveRuntimeInventory(paths=(runtime,)))
    try:
        def forbidden(*args, **kwargs):
            pytest.fail("A Git-free preview must not start any subprocess")
        monkeypatch.setattr(service._git_executor.runner, "run", forbidden)
        for command, options in (("status", {}), ("branch", {"action": "list"})):
            preview = service.invoke_git("a", command, options=options)
            assert preview["dry_run"] is True
            assert preview["execute_started"] is False
            assert preview["repository_checked"] is False
        assert not list((control / "git-state").iterdir())
    finally:
        service.close()


def test_real_linked_worktree_and_independent_repo_lock_admission(tmp_path, monkeypatch):
    repo, a, _, control, original = fixture(tmp_path)
    original.close()
    linked = tmp_path / "linked"
    git(repo, "worktree", "add", "-q", "-b", "linked", str(linked))
    other = tmp_path / "other"
    git(tmp_path, "init", "-q", str(other))
    raw = {"schema_version": 1, "server": {"git": {"enabled": True}},
           "workspaces": {
               "a": {"root": str(a), "git": {"allowed_commands": ["status"]}},
               "linked": {"root": str(linked), "git": {"allowed_commands": ["status"]}},
               "other": {"root": str(other), "git": {"allowed_commands": ["status"]}},
           }}
    settings = parse_workspace_config(raw)
    runtime = tmp_path / "runtime-extra"
    runtime.mkdir()
    service = WorkspaceService(settings, config_dir=control,
                               inventory=ActiveRuntimeInventory(paths=(runtime,)))
    common = RepositoryIdentity.from_rev_parse(git(a, *DISCOVERY) + "\n")
    linked_identity = RepositoryIdentity.from_rev_parse(git(linked, *DISCOVERY) + "\n")
    assert linked_identity.common_key == common.common_key
    started = threading.Event()
    discovered = threading.Event()
    completed = threading.Event()
    result = []
    errors = []
    original_discovery = service._git_executor._run_discovery

    def observed_discovery(call_id, workspace, cwd, deadline):
        identity = original_discovery(call_id, workspace, cwd, deadline)
        if workspace == "linked":
            discovered.set()
        return identity

    monkeypatch.setattr(service._git_executor, "_run_discovery", observed_discovery)

    def worker():
        started.set()
        try:
            result.append(apply(service, "linked", "status", timeout=20))
        except BaseException as exc:
            errors.append(exc)
        finally:
            completed.set()

    thread = threading.Thread(target=worker, daemon=True)
    try:
        with service._git_executor.coordinator.hold(common.common_key,
                                                    time.monotonic() + 25):
            thread.start()
            assert started.wait(3)
            assert discovered.wait(5), "linked worktree must reach common-dir lock"
            assert not completed.wait(0.15), "linked worktree unexpectedly bypassed lock"
            assert apply(service, "other", "status", timeout=20)["exit_code"] == 0
        thread.join(timeout=12)
        assert not thread.is_alive()
        assert not errors, errors
        assert result[0]["exit_code"] == 0
    finally:
        if thread.is_alive():
            thread.join(timeout=12)
        service.close()
