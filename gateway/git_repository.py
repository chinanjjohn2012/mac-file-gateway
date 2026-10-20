"""Git V1 pinned-path admission and parent-repository identity/coordination.

This module does not start Git or register a tool. Discovery must be invoked
only through the protected T05/T06 runner, never from an untracked Popen.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import os
import stat
import threading
import time
from typing import Iterator

from .core import GatewayError
from .git_policy import validate_git_relative_path
from .private_fs import PrivateFileError, open_pinned_directory

_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def _path_error() -> None:
    raise GatewayError("git_path_blocked", "Git local path is not Workspace-contained.")


def check_git_paths(root_fd: int, root_path: str, cwd: str,
                    paths: tuple[str, ...] | list[str] = ()) -> str:
    """Only *explicit* API paths are limited; parent-repository effects are not."""
    cwd = validate_git_relative_path(cwd)
    if type(root_path) is not str or not root_path.startswith("/"):
        _path_error()
    try:
        verified = open_pinned_directory(root_path)
        try:
            a = os.fstat(root_fd)
            b = os.fstat(verified.fd)
            if (a.st_dev, a.st_ino) != (b.st_dev, b.st_ino):
                _path_error()
        finally:
            verified.close()
    except (OSError, PrivateFileError):
        _path_error()
    fd = os.dup(root_fd)
    try:
        if cwd != ".":
            for part in cwd.split("/"):
                try:
                    nxt = os.open(part, _DIR, dir_fd=fd)
                except OSError:
                    _path_error()
                os.close(fd)
                fd = nxt
        for original in paths:
            path = validate_git_relative_path(original)
            components = () if path == "." else path.split("/")
            parent = os.dup(fd)
            try:
                missing_parent = False
                for part in components[:-1]:
                    try:
                        next_fd = os.open(part, _DIR, dir_fd=parent)
                    except FileNotFoundError:
                        missing_parent = True
                        break
                    except OSError:
                        _path_error()
                    os.close(parent)
                    parent = next_fd
                if not missing_parent and components:
                    try:
                        leaf = os.stat(components[-1], dir_fd=parent,
                                       follow_symlinks=False)
                    except FileNotFoundError:
                        leaf = None
                    except OSError:
                        _path_error()
                    if leaf is not None and stat.S_ISLNK(leaf.st_mode):
                        _path_error()
            finally:
                os.close(parent)
    finally:
        os.close(fd)
    return root_path if cwd == "." else os.path.join(root_path, cwd)


@dataclass(frozen=True)
class RepositoryIdentity:
    worktree: str
    git_dir: str
    common_dir: str
    common_key: tuple[int, int]
    worktree_key: tuple[int, int]
    git_dir_key: tuple[int, int]

    @classmethod
    def from_rev_parse(cls, output: str) -> "RepositoryIdentity":
        parts = output.rstrip("\n").split("\n")
        if len(parts) != 3 or any(not p.startswith("/") or "\x00" in p for p in parts):
            raise GatewayError("git_repository_invalid", "Git repository discovery returned invalid paths.")
        paths = tuple(os.path.realpath(p) for p in parts)
        keys = []
        for path in paths:
            try:
                fd = os.open(path, _DIR)
                try:
                    st = os.fstat(fd)
                    keys.append((st.st_dev, st.st_ino))
                finally:
                    os.close(fd)
            except OSError:
                raise GatewayError("git_repository_invalid", "Git repository identity is unavailable.") from None
        return cls(*paths, keys[2], keys[0], keys[1])


class GitRepositoryCoordinator:
    """All Gateway Git actions sharing a common Git dir use one execution lock."""

    def __init__(self) -> None:
        self._registry_guard = threading.Lock()
        self._locks: dict[tuple[int, int], threading.Lock] = {}

    @contextmanager
    def hold(self, key: tuple[int, int], deadline: float) -> Iterator[None]:
        with self._registry_guard:
            lock = self._locks.setdefault(key, threading.Lock())
        wait = min(10.0, max(0.0, deadline - time.monotonic() - 5.0))
        if not lock.acquire(timeout=wait):
            raise GatewayError("git_busy", "Another Git operation is using this repository.")
        try:
            yield
        finally:
            lock.release()
