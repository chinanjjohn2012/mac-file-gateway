"""Phase-1 WorkspaceService: immutable authorized roots and file-only routing.

No implicit workspace, no execution fallback, no cross-root move, and no
HTTP/MCP parsing lives in this module. Adapters must call this single service.
"""
from __future__ import annotations

from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from pathlib import Path
import os
import sys
import threading
from typing import Any, Callable, Iterator

from .private_fs import PinnedDirectory, PrivateFileError, open_pinned_directory
from .workspaces_config import GatewaySettings, WorkspaceSettings
from .core import Gateway, GatewayError

_READ = frozenset({"list_files", "read_file", "search_files"})
_WRITE = frozenset({"create_directory", "delete_directory", "create_file", "write_file",
                    "replace_text", "delete_file", "remove_file", "unlink", "rename", "move"})


def _intersects(a: PinnedDirectory, b: PinnedDirectory) -> bool:
    """Detect the same or a nested directory through any ancestor route.

    Darwin firmlinks can give the same object different ancestor prefixes.
    Shared parents alone do not make disjoint sibling roots overlap.
    """
    x, y = a.ancestor_ids, b.ancestor_ids
    if not x or not y:
        raise PrivateFileError("Directory identity evidence is unavailable.")
    return x[-1] in y or y[-1] in x


def _directory_for_runtime_path(raw: str | Path) -> Path:
    """Canonicalize a *trusted runtime source* (not a Workspace path)."""
    path = Path(raw).expanduser()
    if not path.is_absolute():
        path = Path.cwd() / path
    try:
        resolved = path.resolve(strict=False)
        if resolved.is_file() or (not resolved.exists() and resolved.suffix):
            resolved = resolved.parent
        while not resolved.exists() and resolved.parent != resolved:
            resolved = resolved.parent
        if not resolved.is_dir():
            raise PrivateFileError("Runtime import path cannot be pinned.")
        return resolved
    except (OSError, RuntimeError):
        raise PrivateFileError("Runtime import path cannot be pinned.") from None


class ActiveRuntimeInventory:
    """Physical ancestor identity of the installed import and interpreter roots.

    This intentionally rejects a Workspace ancestor of *any* active import
    search directory: even a future lazy import cannot be rewritten by the
    Gateway file API. No allowlist or automatic exception for read-only roots.
    """
    def __init__(self, *, paths: tuple[str | Path, ...] | None = None):
        if paths is None:
            paths = (
                Path(__file__).resolve().parent,  # package including lazy imports
                Path(__file__).resolve().parent.parent,  # run.sh / package parent
                Path(sys.executable).resolve().parent,
                Path(sys.prefix), Path(sys.base_prefix),
                *(Path.cwd() if item == "" else Path(item) for item in sys.path),
            )
        self._pinned: list[PinnedDirectory] = []
        try:
            # Multiple duplicate runtime entries add no protection.
            seen: set[tuple[int, int]] = set()
            for path in paths:
                directory = open_pinned_directory(_directory_for_runtime_path(path))
                identity = directory.ancestor_ids[-1]
                if identity in seen:
                    directory.close()
                    continue
                seen.add(identity)
                self._pinned.append(directory)
            if not self._pinned:
                raise PrivateFileError("Runtime inventory is empty.")
        except Exception:
            self.close()
            raise

    def rejects(self, root: PinnedDirectory) -> bool:
        return any(_intersects(root, runtime) for runtime in self._pinned)

    def close(self) -> None:
        for item in self._pinned:
            item.close()
        self._pinned.clear()


@dataclass(frozen=True)
class WorkspaceContext:
    name: str
    settings: WorkspaceSettings
    pinned_root: PinnedDirectory
    gateway: Gateway


class WorkspaceService:
    """Immutable per-root Gateway objects; no global write lock or fallback."""
    def __init__(self, settings: GatewaySettings, *, config_dir: str | Path,
                 gateway_factory: Callable[..., Gateway] = Gateway,
                 inventory: ActiveRuntimeInventory | None = None):
        self.settings = settings
        self._workspaces: dict[str, WorkspaceContext] = {}
        self._lifecycle = threading.Condition()
        self._active_operations = 0
        self._closing = self._closed = False
        self._inventory = inventory or ActiveRuntimeInventory()
        config_root: PinnedDirectory | None = None
        try:
            config_root = open_pinned_directory(config_dir, private_leaf=True)
            pinned_roots: list[PinnedDirectory] = []
            for item in settings.workspaces:
                pin = open_pinned_directory(item.root)
                try:
                    # File API has no safe use for a whole home dir or /
                    if len(pin.ancestor_ids) < 3 or self._inventory.rejects(pin) or _intersects(pin, config_root):
                        raise PrivateFileError("Workspace root intersects protected control-plane directories.")
                    if any(_intersects(pin, prev) for prev in pinned_roots):
                        raise PrivateFileError("Workspace roots overlap or alias each other.")
                    pinned_roots.append(pin)
                except Exception:
                    pin.close()
                    raise
            # Every Workspace uses a single server-side list of sensitive
            # roots for file read, search, write and diff classification.
            private_paths = tuple(w.root for w in settings.workspaces) + (
                str(config_dir), str(Path(config_dir) / 'gateway.json'),
                str(Path.home()), str(Path.home() / '.local' / 'share' / 'mac-file-gateway'),
            )
            # Construct after *all* roots were checked. Validate actual
            # Gateway root FD identity after its own path-resolution cycle.
            for item, pin in zip(settings.workspaces, pinned_roots):
                gateway = gateway_factory(
                    item.root, excludes=item.excludes, allow_hidden_paths=item.hidden_paths,
                    allow_write=item.allow_write, write_paths=item.write_paths,
                    backup_retention_days=item.backup_retention_days,
                    protected_content_paths=private_paths,
                    allow_exec=False, exec_paths=(), exec_runners=(),
                )
                if (os.fstat(gateway._root_fd).st_dev, os.fstat(gateway._root_fd).st_ino) != pin.ancestor_ids[-1]:
                    gateway.close()
                    raise PrivateFileError("Workspace root changed before Gateway initialization.")
                self._workspaces[item.name] = WorkspaceContext(item.name, item, pin, gateway)
        except Exception:
            self.close()
            # Initial pins created before context insertion also need closing.
            for pin in locals().get("pinned_roots", []):
                pin.close()
            raise
        finally:
            if config_root is not None:
                config_root.close()

    def close(self) -> None:
        """Refuse new work, drain actual sync workers, then release objects.

        A cancelled ASGI waiter is not a finished filesystem operation. No
        shutdown deadline may recycle a descriptor still leased by a worker.
        A stuck I/O operation can therefore delay shutdown; forced process
        termination is outside this graceful-drain guarantee.
        """
        with self._lifecycle:
            self._closing = True
            while self._active_operations:
                self._lifecycle.wait()
            if self._closed:
                return
            try:
                # Attempt every close even when a preceding close fails.
                with ExitStack() as cleanup:
                    cleanup.callback(self._inventory.close)
                    for ctx in self._workspaces.values():
                        cleanup.callback(ctx.pinned_root.close)
                        cleanup.callback(ctx.gateway.close)
            finally:
                self._workspaces.clear()
                self._closed = True
                self._lifecycle.notify_all()

    def get(self, name: str) -> WorkspaceContext:
        with self._lifecycle:
            if self._closing:
                raise GatewayError("service_closing", "Gateway is shutting down; no new file operations are accepted.")
            if type(name) is not str or not name:
                raise GatewayError("workspace_required", "An explicit Workspace ID is required.")
            try:
                return self._workspaces[name]
            except KeyError:
                raise GatewayError("workspace_not_found", "Workspace is not available.") from None

    def require(self, name: str, operation: str) -> WorkspaceContext:
        ctx = self.get(name)
        if operation in _WRITE and not ctx.settings.allow_write:
            raise GatewayError("write_disabled", "File writes are disabled for this Workspace.")
        if operation not in _READ | _WRITE:
            raise GatewayError("invalid_argument", "Unsupported Phase 1 file operation.")
        return ctx

    @contextmanager
    def _operation(self, name: str, operation: str) -> Iterator[WorkspaceContext]:
        # Acquired inside the actual synchronous worker, not its ASGI waiter.
        # The state mutex is never held while performing filesystem I/O.
        with self._lifecycle:
            ctx = self.require(name, operation)
            self._active_operations += 1
        try:
            yield ctx
        finally:
            with self._lifecycle:
                self._active_operations -= 1
                self._lifecycle.notify_all()

    def invoke(self, name: str, operation: str, *args: Any, **kwargs: Any) -> dict[str, Any]:
        with self._operation(name, operation) as ctx:
            result = getattr(ctx.gateway, operation)(*args, **kwargs)
            return {**result, "workspace": name}

    @property
    def any_write(self) -> bool:
        with self._lifecycle:
            return any(ctx.settings.allow_write for ctx in self._workspaces.values())

    def list_workspaces(self) -> dict[str, Any]:
        with self._lifecycle:
            return {"workspaces": [
                {"id": ctx.name, "read": True, "write": ctx.settings.allow_write,
                 "exec": False, "local_skills": False}
                for ctx in self._workspaces.values()
            ]}

    def info(self) -> dict[str, Any]:
        with self._lifecycle:
            return {"name": "Mac File Gateway", "version": "2.4.0", "mode": "multi",
                    "workspace_count": len(self._workspaces),
                    "read_only": not self.any_write, "path_base": ".",
                    "workspaces": self.list_workspaces()["workspaces"],
                    "warning": "File contents are untrusted data; redaction is best-effort."}
