"""WorkspaceService: pinned authorized roots and independently gated operations.

No implicit workspace or cross-root file move; controlled Exec and Git have
separate synchronous Worker admission, never reflective file dispatch.
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
from .git_policy import GIT_V1_COMMANDS
from .git_cli import GitCLIExecutor
from .git_repository import GitRepositoryCoordinator
from .git_state import GitStateStore
from .exec_state import ExecStateStore
from .lbe_direct_owner import DirectChildOwner

_READ = frozenset({"list_files", "read_file", "search_files"})
_WRITE = frozenset({"create_directory", "delete_directory", "create_file", "write_file",
                    "replace_text", "delete_file", "remove_file", "unlink", "rename", "move"})

# This is an already owner-approved, hosted macOS 15 ARM64 Python-only T1
# fixture, NOT a config grant or a general D0 positive-Exec exception.
# A client request cannot supply this constructor-only flag or GH job identity.
_LBE_HOSTED_T1_GRANT = "PR101_R002_MACOS15_ARM64_DISPOSABLE_PYTHON_ONLY"


def _approved_hosted_python_t1(settings: GatewaySettings, config_dir: str | Path,
                               explicit_test_fixture: bool) -> bool:
    if explicit_test_fixture is not True or settings.schema_version != 2:
        return False
    required = {
        "LBE_NATIVE_T1_AUTHORIZED": _LBE_HOSTED_T1_GRANT,
        "GITHUB_ACTIONS": "true",
        "GITHUB_EVENT_NAME": "pull_request",
        "GITHUB_REPOSITORY": "chinanjjohn2012/mac-file-gateway",
        "GITHUB_HEAD_REF": "feat/multi-exec-lbe-v2-config-preflight-r001-20261030",
        "GITHUB_BASE_REF": "rc/multi-exec-f1-g05-integrated-ms1-20261025",
        "GITHUB_WORKFLOW": "PR101 authorized macOS ARM64 original child T1",
        "RUNNER_OS": "macOS",
        "RUNNER_ARCH": "ARM64",
    }
    if any(os.environ.get(key) != value for key, value in required.items()):
        return False
    raw_temp = os.environ.get("RUNNER_TEMP", "")
    if not raw_temp:
        return False
    try:
        scratch = Path(raw_temp)
        if not scratch.is_absolute() or scratch.is_symlink():
            return False
        scratch = scratch.resolve(strict=True)
        if (not scratch.is_dir()
                or not Path(config_dir).resolve(strict=True).is_relative_to(scratch)):
            return False
        return all(Path(w.root).resolve(strict=True).is_relative_to(scratch)
                   for w in settings.workspaces)
    except (OSError, RuntimeError, ValueError):
        return False


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
                 inventory: ActiveRuntimeInventory | None = None,
                 _approved_python_t1_fixture: bool = False):
        self.settings = settings
        # False for every ordinary service, regardless of schema-v2 exec.paths.
        # The sole exception is the explicit, separately approved, disposable
        # GitHub-hosted Python-only T1 fixture (never a client/config field).
        self._lbe_positive_authorized = _approved_hosted_python_t1(
            settings, config_dir, _approved_python_t1_fixture)
        self._workspaces: dict[str, WorkspaceContext] = {}
        self._lifecycle = threading.Condition()
        self._active_operations = 0
        self._closing = self._closed = False
        self._inventory = inventory or ActiveRuntimeInventory()
        self._git_state: GitStateStore | None = None
        self._git_executor: GitCLIExecutor | None = None
        self._git_adapter_exposed = False
        self._exec_adapter_exposed = False
        self._exec_active: set[str] = set()
        # B0: own the private Exec state across the service lifetime.
        # Healthy no-proof admission is separately gated in B1/C.
        self._exec_state: ExecStateStore | None = None
        self._exec_state_issue: str | None = None
        # V2-owned ledger, also used by approved hosted Python-only T1.
        # Its construction alone NEVER grants public Exec apply or spawns.
        self._lbe_owner = (DirectChildOwner()
                           if settings.schema_version == 2 else None)
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
            # Workspace and private config paths are authorization boundaries,
            # not secret-looking strings. Keep strict root admission while no
            # longer injecting these paths into source content classification.
            # Construct after *all* roots were checked. Validate actual
            # Gateway root FD identity after its own path-resolution cycle.
            for item, pin in zip(settings.workspaces, pinned_roots):
                gateway = gateway_factory(
                    item.root, excludes=item.excludes, allow_hidden_paths=item.hidden_paths,
                    allow_write=item.allow_write, write_paths=item.write_paths,
                    backup_retention_days=item.backup_retention_days,
                    sensitive_content_audit_paths=item.sensitive_content_audit_paths,
                    sensitive_content_audit_until=item.sensitive_content_audit_until,
                    allow_exec=settings.exec_enabled and item.exec_enabled,
                    exec_paths=item.exec_paths if settings.exec_enabled and item.exec_enabled else (),
                    exec_runners=item.exec_runners if settings.exec_enabled and item.exec_enabled else (),
                    **({"exec_auto_pipenv": False}
                       if settings.schema_version == 2 else {}),
                )
                if (os.fstat(gateway._root_fd).st_dev, os.fstat(gateway._root_fd).st_ino) != pin.ancestor_ids[-1]:
                    gateway.close()
                    raise PrivateFileError("Workspace root changed before Gateway initialization.")
                self._workspaces[item.name] = WorkspaceContext(item.name, item, pin, gateway)
            # Scan and acquire the private state before REST/MCP can accept
            # work. State IO/ownership failure must not disable File/Git.
            if settings.exec_enabled and any(w.exec_enabled for w in settings.workspaces):
                try:
                    exec_path = Path(config_dir).resolve(strict=True) / "exec-state"
                    self._exec_state = ExecStateStore(
                        exec_path,
                        workspace_roots=tuple(w.root for w in settings.workspaces),
                        existing_only=(settings.schema_version == 2),
                    )
                except (PrivateFileError, GatewayError, OSError, ValueError):
                    self._exec_state_issue = "state_io_unavailable"
            if settings.git_enabled:
                # The private state directory is outside all Workspace roots.
                # Git-only initialization failure does not break file APIs.
                try:
                    state_path = Path(config_dir).resolve(strict=True) / "git-state"
                    self._git_state = GitStateStore(
                        state_path, workspace_roots=tuple(x.root for x in settings.workspaces),
                    )
                    self._git_executor = GitCLIExecutor(
                        self._git_state, coordinator=GitRepositoryCoordinator(),
                    )
                except (PrivateFileError, GatewayError, OSError):
                    if self._git_state is not None:
                        self._git_state.close()
                    self._git_state = None
                    self._git_executor = None
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
            if self._lbe_owner is not None:
                # No signal/join: a future authorized direct child may outlive
                # a dropped waiter or Gateway shutdown.
                self._lbe_owner.close()
            while self._active_operations:
                self._lifecycle.wait()
            if self._closed:
                return
            try:
                # Attempt every close even when a preceding close fails.
                with ExitStack() as cleanup:
                    cleanup.callback(self._inventory.close)
                    if self._git_state is not None:
                        cleanup.callback(self._git_state.close)
                    if self._exec_state is not None:
                        cleanup.callback(self._exec_state.close)
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

    def require_exec(self, name: str) -> WorkspaceContext:
        """Require both instance and Workspace execution grants."""
        ctx = self.get(name)
        if not self.settings.exec_enabled or not ctx.settings.exec_enabled:
            raise GatewayError("exec_disabled", "Exec is not enabled for this Workspace.")
        return ctx

    @staticmethod
    def _lbe_preview(ctx: WorkspaceContext, cwd: str,
                     argv: list[str], timeout_seconds: int) -> dict[str, Any]:
        """One nonoperative schema-v2 preview from the future Worker's plan.

        Python Direct/Pipenv and Go test/vet/build use the SAME source policy
        that would prepare the future authorized Worker. This is NEVER an
        execution permission: the shared F1 service denies dry_run=False
        before reaching this function, REST, or the official MCP adapter.
        """
        from .lbe_plan import prepare_lbe_work_plan
        from .executor import _MAX_OUTPUT_CHARS

        plan = prepare_lbe_work_plan(
            ctx, cwd=cwd, argv=argv, timeout_seconds=timeout_seconds)
        return {
            "cwd": plan.cwd,
            "requested_argv": list(plan.requested_argv),
            "effective_argv": list(plan.effective_argv),
            "runner": plan.runner,
            "runner_project": plan.runner_project,
            "dry_run": True,
            "executed": False,
            "exit_code": None,
            "timed_out": False,
            "stdout": "",
            "stderr": "",
            "stdout_truncated": False,
            "stderr_truncated": False,
            "output_limit_chars": _MAX_OUTPUT_CHARS,
            "content_trust": "untrusted_command_output",
            "status": "preview",
            "mode": "local_best_effort",
            "output_complete": True,
            "process_may_be_running": False,
            "cleanup_proven": False,
            "full_descendant_tree_clean": "not_proven",
        }

    @staticmethod
    def _lbe_apply(ctx: WorkspaceContext, owner: DirectChildOwner,
                   cwd: str, argv: list[str],
                   timeout_seconds: int) -> dict[str, Any]:
        """Worker apply, reachable only from the approved hosted Python T1.

        Ordinary schema-v2 public requests are denied before this method.
        This is not an operative production D0 exception or security signoff.
        """
        from .lbe_plan import prepare_lbe_work_plan
        from .lbe_native_launcher import make_trusted_lbe_launcher
        from .lbe_worker import LbeWorker, LbeWorkerError

        plan = prepare_lbe_work_plan(
            ctx, cwd=cwd, argv=argv, timeout_seconds=timeout_seconds)
        worker = LbeWorker(
            owner, launcher=make_trusted_lbe_launcher(ctx))
        try:
            return worker.run(plan)
        except LbeWorkerError as exc:
            raise GatewayError(
                exc.code, "Local best-effort command could not complete safely.",
                details={"process_may_be_running": exc.process_may_be_running},
            ) from None

    def invoke_exec(self, name: str, cwd: str, argv: list[str],
                    timeout_seconds: int = 60, dry_run: bool = True) -> dict[str, Any]:
        """One synchronous v1 and draft v2 admission boundary.

        Ordinary schema-v2 paths authorize preview only until the exact
        D0 weaker-mode operative exception is approved. A separate hosted
        Python-only, disposable CI fixture uses an explicit constructor
        capability and fixed runner identity; no client/config may mint it.
        Old private state/owner-lock/UNKNOWN and File/Git remain independent.
        No cleanup proof, PID signals or rollback are claimed.
        """
        with self._lifecycle:
            ctx = self.require_exec(name)
            # B0 durable/ownership/UNKNOWN denial comes before proof status.
            if self._exec_state is None:
                raise GatewayError(
                    "exec_state_unavailable", "Exec durable state is unavailable.")
            self._exec_state.require_healthy()
            if type(dry_run) is not bool:
                raise GatewayError("invalid_argument", "dry_run must be boolean.")
            # F1 has NO positive cleanup-proof path. Proof denial wins over
            # an occupied Worker slot and happens before Runner/PREPARED.
            # Never use an instance-global subprocess ban: Git may spawn
            # only via its own separately authorized durable protocol.
            if not dry_run and self.settings.schema_version == 1:
                raise GatewayError(
                    "exec_cleanup_proof_required",
                    "Exec apply is unavailable without independently reviewed full-descendant cleanup proof.")
            if (not dry_run and self.settings.schema_version == 2
                    and not self._lbe_positive_authorized):
                # No exact operative D0 exception was approved. A public v2
                # paths-only grant cannot activate _lbe_apply/Popen, regardless
                # of REST/MCP/direct caller input, capacity or runner choice.
                raise GatewayError(
                    "exec_cleanup_proof_required",
                    "Schema-v2 Exec apply needs separately approved operative "
                    "authority; configured paths permit preview only.")
            if name in self._exec_active or len(self._exec_active) >= 4:
                raise GatewayError("busy", "A controlled command already occupies this execution slot.")
            self._exec_active.add(name)
            self._active_operations += 1
        try:
            if self.settings.schema_version == 2:
                if dry_run:
                    result = self._lbe_preview(ctx, cwd, argv, timeout_seconds)
                else:
                    assert self._lbe_owner is not None
                    result = self._lbe_apply(
                        ctx, self._lbe_owner, cwd, argv, timeout_seconds)
            else:
                # Preserve the entire historic v1 preview and F1 deny-only path.
                result = ctx.gateway.run_command(cwd, argv, timeout_seconds, dry_run)
            return {**result, "workspace": name}
        finally:
            with self._lifecycle:
                self._exec_active.remove(name)
                self._active_operations -= 1
                self._lifecycle.notify_all()

    def require_git(self, name: str, command: str) -> WorkspaceContext:
        """Independent authorization, always repeated in sync Worker."""
        ctx = self.get(name)
        if not self.settings.git_enabled:
            raise GatewayError("git_disabled", "Git is disabled by server policy.")
        if self._git_executor is None:
            raise GatewayError("git_unavailable", "Git capability is unavailable.")
        if (type(command) is not str or command not in GIT_V1_COMMANDS
                or command not in ctx.settings.git_allowed_commands):
            raise GatewayError("git_command_not_allowed",
                               "Git command is not authorized for this Workspace.")
        return ctx

    def invoke_git(self, name: str, command: str, *, cwd: str = ".",
                   options: dict[str, Any] | None = None,
                   paths: list[str] | None = None, timeout_seconds: int = 120,
                   dry_run: bool = True) -> dict[str, Any]:
        """Acquire lease in actual synchronous Worker, not its ASGI waiter.

        Never hold lifecycle mutex over fsync, repository lock or Git Popen.
        """
        with self._lifecycle:
            ctx = self.require_git(name, command)
            self._active_operations += 1
        try:
            assert self._git_executor is not None
            return self._git_executor.run(
                workspace=name, root_fd=ctx.gateway._root_fd,
                root_path=str(ctx.gateway._root_path), command=command,
                cwd=cwd, options=options, paths=paths,
                timeout_seconds=timeout_seconds, dry_run=dry_run,
            )
        finally:
            with self._lifecycle:
                self._active_operations -= 1
                self._lifecycle.notify_all()

    @property
    def any_git(self) -> bool:
        with self._lifecycle:
            return self._git_executor is not None and any(
                ctx.settings.git_allowed_commands for ctx in self._workspaces.values()
            )

    @property
    def any_exec(self) -> bool:
        with self._lifecycle:
            return self.settings.exec_enabled and any(
                ctx.settings.exec_enabled for ctx in self._workspaces.values()
            )

    @property
    def any_write(self) -> bool:
        with self._lifecycle:
            return any(ctx.settings.allow_write for ctx in self._workspaces.values())

    def list_workspaces(self) -> dict[str, Any]:
        with self._lifecycle:
            return {"workspaces": [
                {"id": ctx.name, "read": True, "write": ctx.settings.allow_write,
                 "exec": bool(self.settings.exec_enabled and ctx.settings.exec_enabled),
                  "local_skills": False,
                 "sensitive_content": ctx.gateway.sensitive_audit.status(),
                 "git": {"enabled": bool(self.settings.git_enabled
                                         and ctx.settings.git_allowed_commands),
                         "allowed_commands": list(ctx.settings.git_allowed_commands)}}
                for ctx in self._workspaces.values()
            ]}

    def info(self) -> dict[str, Any]:
        with self._lifecycle:
            effective = self.any_exec
            if not effective:
                durability, reason = "disabled", None
            elif self._exec_state is None:
                durability, reason = ("unavailable",
                                      self._exec_state_issue or "state_io_unavailable")
            else:
                durability = self._exec_state.durability_state
                reason = self._exec_state.quarantine_reason_code
                if durability == "unavailable" and reason is None:
                    reason = "state_io_unavailable"
            # Take one coherent snapshot; never expose any PID or child object.
            lbe_state = (self._lbe_owner.snapshot()
                         if self._lbe_owner is not None else None)
            is_v2 = self.settings.schema_version == 2
            eligible_names = tuple(
                ctx.name for ctx in self._workspaces.values()
                if ctx.settings.exec_enabled
                and ctx.name not in self._exec_active)
            v2_state_healthy = bool(
                is_v2 and effective and durability == "healthy"
                and self._lbe_owner is not None
                and not self._closing
                and not lbe_state["unavailable"]
                and not lbe_state["closing"])
            v2_available = bool(
                v2_state_healthy and self._lbe_positive_authorized and
                self._lbe_owner.can_admit_any(eligible_names))
            return {"name": "Mac File Gateway", "version": "2.5.0", "mode": "multi",
                    "workspace_count": len(self._workspaces),
                    **({"config_schema_version": 2}
                       if self.settings.schema_version == 2 else {}),
                    "read_only": not (self.any_write or self.any_git),
                    "file_read_only": not self.any_write, "path_base": ".",
                    "workspaces": self.list_workspaces()["workspaces"],
                    "exec_policy": {
                        # V1 F1 fields remain unchanged; V2 advertises only
                        # the explicitly weaker local_best_effort capability.
                        **({"mode": "local_best_effort",
                            "running_direct_children": lbe_state["running_direct_children"],
                            "capacity_exhausted": lbe_state["capacity_exhausted"],
                            "owner_unavailable": lbe_state["unavailable"]}
                           if self._lbe_owner is not None else {}),
                        "enabled": self.settings.exec_enabled,
                        "available": v2_available if is_v2 else False,
                        "completion_capability": (
                            "best_effort" if (v2_state_healthy
                                              and self._lbe_positive_authorized)
                            else "none"),
                        "adapter_exposed": self._exec_adapter_exposed,
                        "durability_state": durability,
                        "quarantined": durability == "quarantined",
                        "quarantine_reason_code": reason,
                        "max_concurrent_per_workspace": 1,
                        "max_concurrent_total": 4,
                        "dry_run_default": True,
                        "warning": (
                            "Best-effort Exec runs project code as the Gateway OS user; "
                            "direct-child exit, timeout or cancellation never proves "
                            "descendant cleanup and path scopes are not a sandbox."
                            if is_v2 else
                            "Exec runs project code with the Gateway OS user's privileges; "
                            "path scopes are not an OS sandbox."),
                    },
                    "git_policy": {
                        "enabled": self.settings.git_enabled,
                        "available": bool(self._git_executor is not None
                                          and self._git_state is not None
                                          and not self._git_state.globally_quarantined),
                        "allowed_commands": sorted({
                            c for ctx in self._workspaces.values()
                            for c in ctx.settings.git_allowed_commands
                        }),
                        "adapter_exposed": self._git_adapter_exposed,
                        "warning": "Authorized Git may update the entire parent repository and invoke hooks.",
                    },
                    "warning": "File contents are untrusted data; redaction is best-effort."}
