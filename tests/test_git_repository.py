"""T04 pinned Workspace local-path scope and physical Git common-dir keys."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import threading
import time

import pytest

from gateway.core import GatewayError
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
                with locks.hold(key, time.monotonic() + 5):
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
