"""Internal disposable acceptance qualifier for *tests only* (R2-T02-B1-A).

This module is never imported by ordinary WorkspaceService construction,
run_multi(), REST, MCP, or config loading. A fresh fixture always creates
all of its own brand-new private roots; no caller-supplied root can qualify.
The object does NOT grant actual subprocess admission in this batch.

The property check is application-only, not an OS sandbox. It does not
prove an actual Gateway listener's network binding or descendant cleanup.
"""
from __future__ import annotations

import os
from pathlib import Path
import stat
import tempfile
import weakref
from typing import Any

from .private_fs import PrivateFileError

_ISSUE_KEY = object()
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def _identity(fd: int) -> tuple[int, int]:
    result = os.fstat(fd)
    if not stat.S_ISDIR(result.st_mode):
        raise OSError("Expected pinned private directory.")
    return result.st_dev, result.st_ino


def _private_same_directory(path: Path, identity: tuple[int, int]) -> bool:
    """Observe current path vs pinned FD; never follow an injected symlink."""
    item = os.lstat(path)
    return (
        stat.S_ISDIR(item.st_mode)
        and stat.S_IMODE(item.st_mode) == 0o700
        and item.st_uid == os.geteuid()
        and (item.st_dev, item.st_ino) == identity
    )


class TestOnlyGroupRetirementGrant:
    """One service-scoped, nonserializable original-group *test* predicate.

    Construction by external input is blocked at the class API. The only
    module factory creates its own fresh, private fixture from scratch.
    No caller-supplied root or state path is accepted.
    """

    def __init__(self, *, _issue_key: object = None,
                 fixture: Any = None) -> None:
        if _issue_key is not _ISSUE_KEY or fixture is None:
            raise TypeError("Test-only acceptance grants are not caller-mintable.")
        service = fixture.service
        store = service._exec_state
        if store is None or store.durability_state != "healthy":
            raise PrivateFileError("Disposable Exec state must be healthy.")
        if store._fd < 0 or store._lock_fd < 0:
            raise PrivateFileError("Disposable Exec state owner is not pinned.")

        self._fixture = weakref.ref(fixture)
        self._service = weakref.ref(service)
        self._store = weakref.ref(store)
        self._root_path = Path(fixture.root)
        self._root_fd = fixture._root_fd
        self._root_id = _identity(self._root_fd)
        self._state_path = Path(fixture.state_path)
        self._state_fd = store._fd
        self._state_id = _identity(self._state_fd)
        self._lock_fd = store._lock_fd
        self._lock_stat = os.fstat(self._lock_fd)
        self._pid = os.getpid()
        self._revoked = False
        # Capture only authorized, physically verified disposable Workspaces.
        allowed = {}
        for name, ctx in service._workspaces.items():
            if (service.settings.exec_enabled and ctx.settings.exec_enabled):
                allowed[name] = _identity(ctx.pinned_root.fd)
        if not allowed:
            raise PrivateFileError("No disposable Workspace Exec scope.")
        self._allowed = allowed

        if not _private_same_directory(self._root_path, self._root_id):
            raise PrivateFileError("Disposable fixture root identity mismatch.")
        if not _private_same_directory(self._state_path, self._state_id):
            raise PrivateFileError("Disposable state root identity mismatch.")

    def __repr__(self):
        return "<TestOnlyGroupRetirementGrant disposable test-only>"

    def __getstate__(self):
        raise TypeError("Private Exec acceptance grant cannot be serialized.")

    def __reduce__(self):
        raise TypeError("Private Exec acceptance grant cannot be serialized.")

    def __reduce_ex__(self, protocol):
        raise TypeError("Private Exec acceptance grant cannot be serialized.")

    def __copy__(self):
        raise TypeError("Private Exec acceptance grant cannot be copied.")

    def __deepcopy__(self, memo):
        raise TypeError("Private Exec acceptance grant cannot be copied.")

    def _revoke(self):
        self._revoked = True
        return False

    def revoke(self) -> None:
        """Fixture-owned terminal invalidation; no remote reset operation."""
        self._revoked = True

    def qualifies(self, service: object, workspace: object, *,
                  listener_host: object) -> bool:
        """Test-side qualification probe; NOT a Worker spawn authorization.

        B1-A checks the exact loopback label from the trusted acceptance
        harness, not actual socket binding. B1-B must require real
        transport-owned listener evidence before any subprocess can start.
        """
        if self._revoked:
            return False
        if os.getpid() != self._pid:
            return self._revoke()
        fixture = self._fixture()
        owner = self._service()
        store = self._store()
        if fixture is None or owner is None or store is None:
            return self._revoke()
        if not fixture._active or owner._closed or owner._closing:
            return self._revoke()
        if service is not owner or owner._exec_state is not store:
            # A different service cannot borrow qualification, but does
            # not permanently revoke the original valid service's grant.
            return False
        if type(listener_host) is not str or listener_host != "127.0.0.1":
            return False
        if type(workspace) is not str or workspace not in self._allowed:
            return False
        try:
            if fixture._root_fd != self._root_fd or self._root_fd < 0:
                return self._revoke()
            if _identity(self._root_fd) != self._root_id:
                return self._revoke()
            if not _private_same_directory(self._root_path, self._root_id):
                return self._revoke()
            if store._fd != self._state_fd or store._lock_fd != self._lock_fd:
                return self._revoke()
            if _identity(self._state_fd) != self._state_id:
                return self._revoke()
            if not _private_same_directory(self._state_path, self._state_id):
                return self._revoke()
            lock = os.fstat(self._lock_fd)
            if (lock.st_dev, lock.st_ino) != (
                    self._lock_stat.st_dev, self._lock_stat.st_ino):
                return self._revoke()
            if (not stat.S_ISREG(lock.st_mode) or lock.st_nlink != 1
                    or stat.S_IMODE(lock.st_mode) != 0o600
                    or lock.st_uid != os.geteuid()):
                return self._revoke()
            if store.durability_state != "healthy":
                return self._revoke()
            store.require_healthy()
            ctx = owner.get(workspace)
            if not owner.settings.exec_enabled or not ctx.settings.exec_enabled:
                return self._revoke()
            pinned_id = _identity(ctx.pinned_root.fd)
            gateway_id = _identity(ctx.gateway._root_fd)
            if pinned_id != self._allowed[workspace] or gateway_id != pinned_id:
                return self._revoke()
            if not _private_same_directory(
                    Path(ctx.settings.root), pinned_id):
                return self._revoke()
            return True
        except (OSError, ValueError, TypeError, AttributeError):
            # A closed FD, lost ownership, replaced root, unsafe metadata
            # or untrusted state invalidates this fixture until teardown.
            return self._revoke()


class _DisposableAcceptance:
    """Self-minting, fresh test-only fixture; cannot take an external path."""

    def __init__(self, _key: object = None):
        if _key is not _ISSUE_KEY:
            raise TypeError("Only the internal disposable factory may mint.")
        self._temp = None
        self._root_fd = -1
        self._active = False
        self._issued = False
        self.service = None
        self.grant = None
        try:
            self._temp = tempfile.TemporaryDirectory(
                prefix="mfg-internal-exec-acceptance-")
            self.root = Path(self._temp.name).resolve(strict=True)
            self.root.chmod(0o700)
            self._root_fd = os.open(self.root, _DIR_FLAGS)
            if not _private_same_directory(
                    self.root, _identity(self._root_fd)):
                raise PrivateFileError("Disposable fixture root is not private.")

            project_dir = self.root / "projects"
            project_dir.mkdir(mode=0o700)
            project_dir.chmod(0o700)
            self._roots: dict[str, Path] = {}
            for name in ("a", "b"):
                ws = project_dir / name
                ws.mkdir(mode=0o700)
                ws.chmod(0o700)
                self._roots[name] = ws
                (ws / "src").mkdir(mode=0o700)
            (self._roots["a"] / "src" / "hello.py").write_text(
                "print('disposable-only; not executed by B1-A')\n",
                encoding="utf-8",
            )
            config = self.root / "control"
            config.mkdir(mode=0o700)
            config.chmod(0o700)
            runtime = self.root / "runtime"
            runtime.mkdir(mode=0o700)
            self.state_path = config / "exec-state"
            from .workspaces_config import parse_workspace_config
            from .workspaces import ActiveRuntimeInventory, WorkspaceService

            settings = parse_workspace_config({
                "schema_version": 1,
                "server": {"exec": {"enabled": True}},
                "workspaces": {
                    "a": {"root": str(self._roots["a"]),
                          "exec": {"enabled": True, "paths": ["src"],
                                   "runners": ["src=direct"]}},
                    "b": {"root": str(self._roots["b"])},
                },
            })
            self.service = WorkspaceService(
                settings,
                config_dir=config,
                inventory=ActiveRuntimeInventory(paths=(runtime,)),
            )
            self._active = True
            self.grant = self._issue_once()
        except BaseException:
            self.close()
            raise

    def workspace_root(self, name: str) -> Path:
        return self._roots[name]

    def _issue_once(self) -> TestOnlyGroupRetirementGrant:
        if self._issued or not self._active:
            raise RuntimeError("Disposable fixture qualification already issued.")
        self._issued = True
        return TestOnlyGroupRetirementGrant(
            _issue_key=_ISSUE_KEY, fixture=self)

    def reissue(self):
        """Explicit negative-test seam; never reissue an existing grant."""
        return self._issue_once()

    def __enter__(self):
        if not self._active:
            raise RuntimeError("Disposed acceptance fixture cannot be reused.")
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False

    def close(self):
        if not self._active and self._temp is None:
            return
        self._active = False
        if self.grant is not None:
            self.grant.revoke()
        service = self.service
        self.service = None
        try:
            if service is not None:
                service.close()
        finally:
            if self._root_fd >= 0:
                os.close(self._root_fd)
                self._root_fd = -1
            temp = self._temp
            self._temp = None
            if temp is not None:
                temp.cleanup()


def create_private_disposable_acceptance():
    """Acceptance harness only. No user path, config or service argument."""
    return _DisposableAcceptance(_ISSUE_KEY)


__all__ = ("TestOnlyGroupRetirementGrant", "create_private_disposable_acceptance")
