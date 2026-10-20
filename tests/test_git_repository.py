"""T04 pinned Workspace local-path scope and physical Git common-dir keys."""
from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path
import subprocess
import threading
import time

import pytest

from gateway.core import GatewayError
from gateway.git_cli import GitCLIExecutor
from gateway.git_state import GitStateStore
from gateway.git_repository import (
    RepositoryIdentity, GitRepositoryCoordinator, check_git_paths,
)


def _fd(path: Path) -> int:
    return os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)


def _git(*args: str, cwd: Path) -> str:
    r = subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True)
    return r.stdout.strip()


def test_cwd_and_literal_paths_within_pinned_workspace(tmp_path):
    root = tmp_path / "repo" / "workspace"
    (root / "inner").mkdir(parents=True)
    (root / "inner" / "file[1].txt").write_text("hello")
    fd = _fd(root)
    try:
        assert check_git_paths(fd, str(root), "inner", ["file[1].txt"]) == str(root / "inner")
        assert check_git_paths(fd, str(root), ".", ["."]) == str(root)
        assert check_git_paths(fd, str(root), "inner", ["missing.txt"]) == str(root / "inner")
    finally:
        os.close(fd)


@pytest.mark.parametrize("cwd,path", [
    ("../other", "x"), ("", "x"), ("/tmp", "x"),
    (".", "../other"), (".", "/etc/passwd"), (".", ":(top)secret"),
])
def test_invalid_explicit_paths_are_denied(tmp_path, cwd, path):
    root = tmp_path / "workspace"
    root.mkdir()
    fd = _fd(root)
    try:
        with pytest.raises(GatewayError) as exc:
            check_git_paths(fd, str(root), cwd, [path])
        assert exc.value.code == "git_path_blocked"
    finally:
        os.close(fd)


def test_symlink_ancestors_and_leaf_are_blocked(tmp_path):
    root = tmp_path / "workspace"
    other = tmp_path / "private"
    root.mkdir()
    other.mkdir()
    (other / "secret.txt").write_text("private")
    (root / "out").symlink_to(other, target_is_directory=True)
    (root / "secret-link").symlink_to(other / "secret.txt")
    fd = _fd(root)
    try:
        for cwd, paths in [("out", []), (".", ["out/secret.txt"]),
                           (".", ["secret-link"])]:
            with pytest.raises(GatewayError) as exc:
                check_git_paths(fd, str(root), cwd, paths)
            assert exc.value.code == "git_path_blocked"
    finally:
        os.close(fd)


def test_cwd_root_replacement_detected(tmp_path):
    root = tmp_path / "workspace"
    root.mkdir()
    fd = _fd(root)
    try:
        root.rename(tmp_path / "original")
        root.mkdir()
        with pytest.raises(GatewayError) as exc:
            check_git_paths(fd, str(root), ".")
        assert exc.value.code == "git_path_blocked"
    finally:
        os.close(fd)


def test_parent_repo_and_real_common_dir_identity(tmp_path):
    root = tmp_path / "parent"
    root.mkdir()
    (root / "a").mkdir()
    (root / "b").mkdir()
    _git("init", "-q", cwd=root)
    argv = ("rev-parse", "--path-format=absolute", "--show-toplevel",
            "--absolute-git-dir", "--git-common-dir")
    a = RepositoryIdentity.from_rev_parse(_git(*argv, cwd=root / "a") + "\n")
    b = RepositoryIdentity.from_rev_parse(_git(*argv, cwd=root / "b") + "\n")
    assert a.common_key == b.common_key
    assert a.worktree == str(root)
    assert a.common_dir == str(root / ".git")


def test_linked_worktrees_share_one_common_dir(tmp_path):
    root = tmp_path / "parent"
    root.mkdir()
    _git("init", "-q", cwd=root)
    _git("config", "user.name", "Fixture", cwd=root)
    _git("config", "user.email", "fixture@example.invalid", cwd=root)
    (root / "a.txt").write_text("seed")
    _git("add", "a.txt", cwd=root)
    _git("commit", "-qm", "initial", cwd=root)
    second = tmp_path / "other-worktree"
    _git("worktree", "add", "-qb", "linked", str(second), cwd=root)
    argv = ("rev-parse", "--path-format=absolute", "--show-toplevel",
            "--absolute-git-dir", "--git-common-dir")
    a = RepositoryIdentity.from_rev_parse(_git(*argv, cwd=root) + "\n")
    b = RepositoryIdentity.from_rev_parse(_git(*argv, cwd=second) + "\n")
    assert a.common_key == b.common_key
    assert a.worktree_key != b.worktree_key


def test_same_repo_lock_serializes_but_another_repo_does_not_block():
    locks = GitRepositoryCoordinator()
    key = (1, 2)
    other = (3, 4)
    outcomes = []
    with locks.hold(key, time.monotonic() + 20):
        def worker():
            try:
                with locks.hold(key, time.monotonic() + 12):
                    outcomes.append("same-entered")
            except GatewayError as exc:
                outcomes.append(exc.code)
        thread = threading.Thread(target=worker)
        thread.start()
        time.sleep(0.1)
        assert outcomes == []
        with locks.hold(other, time.monotonic() + 20):
            outcomes.append("other-entered")
        assert outcomes == ["other-entered"]
    thread.join(timeout=5)
    assert outcomes == ["other-entered", "same-entered"]


def test_repo_lock_is_bounded():
    locks = GitRepositoryCoordinator()
    results = []
    with locks.hold((7, 8), time.monotonic() + 20):
        thread = threading.Thread(target=lambda: _try_busy(locks, results))
        thread.start()
        thread.join(timeout=2)
    assert results == ["git_busy"]


def _try_busy(locks, results):
    try:
        with locks.hold((7, 8), time.monotonic() + 5):
            results.append("unexpected")
    except GatewayError as exc:
        results.append(exc.code)



def test_queued_git_add_cannot_follow_branch_switched_cwd_symlink(tmp_path, monkeypatch):
    """A and B are real internal Git requests sharing one common-dir lock.

    B legitimately switches branches while A is waiting. The new branch
    replaces A's previously validated cwd directory with a symlink into a
    parent-repository sibling outside A's authorized Workspace. A MUST
    revalidate after acquiring the lock, before starting any lock-held Git.
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    _git("init", "-q", cwd=repo)
    _git("config", "user.name", "Fixture", cwd=repo)
    _git("config", "user.email", "fixture@example.invalid", cwd=repo)

    a_root = repo / "ws"
    (a_root / "sub").mkdir(parents=True)
    b_root = repo / "switch-workspace"
    b_root.mkdir()
    outside = repo / "outside"
    outside.mkdir()
    (a_root / "sub" / "target.txt").write_text("inside\n")
    _git("add", "ws/sub/target.txt", cwd=repo)
    _git("commit", "-qm", "directory cwd", cwd=repo)
    original_branch = _git("branch", "--show-current", cwd=repo)

    _git("switch", "-c", "symlink-branch", cwd=repo)
    _git("rm", "-qr", "ws/sub", cwd=repo)
    # git rm may prune the now-empty ws parent before the symlink is created.
    a_root.mkdir(exist_ok=True)
    (a_root / "sub").symlink_to("../outside", target_is_directory=True)
    _git("add", "ws/sub", cwd=repo)
    _git("commit", "-qm", "symlink cwd", cwd=repo)
    _git("switch", original_branch, cwd=repo)
    (outside / "target.txt").write_text("outside should remain untracked\n")
    assert (a_root / "sub").is_dir() and not (a_root / "sub").is_symlink()
    assert _git("diff", "--cached", "--name-only", cwd=repo) == ""

    state_path = tmp_path / "state"
    store = GitStateStore(state_path, workspace_roots=(str(a_root), str(b_root)))
    executor = GitCLIExecutor(store)
    actual_run = executor.runner.run
    actual_hold = executor.coordinator.hold
    b_inside_lock = threading.Event()
    allow_b_switch = threading.Event()
    a_waiting_on_lock = threading.Event()
    a_started_git: list[tuple[str, ...]] = []
    results: dict[str, object] = {}

    @contextmanager
    def watched_hold(key, deadline):
        if threading.current_thread().name == "request-A-add":
            # Reaching this point implies initial path check and actual
            # discovery have both completed, but lock acquisition has not.
            a_waiting_on_lock.set()
        with actual_hold(key, deadline):
            yield

    def watched_run(cwd, argv, *, spawn_admitted, execute_until, deadline):
        name = threading.current_thread().name
        if name == "request-B-switch" and argv[0] == "switch":
            # B is inside the repository lock, about to change branch.
            b_inside_lock.set()
            assert allow_b_switch.wait(timeout=10), "B switch not released"
        if name == "request-A-add":
            a_started_git.append(tuple(argv))
        return actual_run(
            cwd, argv, spawn_admitted=spawn_admitted,
            execute_until=execute_until, deadline=deadline,
        )

    monkeypatch.setattr(executor.coordinator, "hold", watched_hold)
    monkeypatch.setattr(executor.runner, "run", watched_run)

    def request_b():
        fd = _fd(b_root)
        try:
            results["B"] = executor.run(
                workspace="switch-workspace", root_fd=fd, root_path=str(b_root),
                command="switch", options={"name": "symlink-branch"},
                timeout_seconds=30, dry_run=False,
            )
        except BaseException as exc:
            results["B_error"] = exc
        finally:
            os.close(fd)

    def request_a():
        fd = _fd(a_root)
        try:
            results["A"] = executor.run(
                workspace="ws", root_fd=fd, root_path=str(a_root),
                cwd="sub", command="add", paths=["target.txt"],
                timeout_seconds=30, dry_run=False,
            )
        except BaseException as exc:
            results["A_error"] = exc
        finally:
            os.close(fd)

    thread_b = threading.Thread(target=request_b, name="request-B-switch", daemon=True)
    thread_a = threading.Thread(target=request_a, name="request-A-add", daemon=True)
    try:
        thread_b.start()
        assert b_inside_lock.wait(timeout=10), results
        thread_a.start()
        assert a_waiting_on_lock.wait(timeout=10), results
        assert (a_root / "sub").is_dir() and not (a_root / "sub").is_symlink()
    finally:
        allow_b_switch.set()
        if thread_b.ident is not None:
            thread_b.join(timeout=12)
        if thread_a.ident is not None:
            thread_a.join(timeout=12)
        assert not thread_b.is_alive() and not thread_a.is_alive(), results
        store.close()

    assert "B_error" not in results, results
    assert isinstance(results.get("B"), dict) and results["B"]["exit_code"] == 0
    assert (a_root / "sub").is_symlink()
    assert "A" not in results, results
    assert isinstance(results.get("A_error"), GatewayError), results
    assert results["A_error"].code == "git_path_blocked"
    # A's first Git process is discovery; no lock-held recheck or business
    # command was permitted to start with the displaced cwd.
    assert a_started_git and all(argv[0] == "rev-parse" for argv in a_started_git)
    assert _git("diff", "--cached", "--name-only", cwd=repo) == ""
    assert (outside / "target.txt").read_text() == "outside should remain untracked\n"
    assert not list(state_path.iterdir()), "Clean error must release state/lock"

    # A rejected request must not poison normal subsequent same-repo access.
    fd = _fd(b_root)
    store = GitStateStore(state_path, workspace_roots=(str(a_root), str(b_root)))
    try:
        response = GitCLIExecutor(store).run(
            workspace="switch-workspace", root_fd=fd, root_path=str(b_root),
            command="status", timeout_seconds=30, dry_run=False,
        )
        assert response["exit_code"] == 0
    finally:
        os.close(fd)
        store.close()
