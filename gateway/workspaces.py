"""WorkspaceService: pinned authorized roots and independently gated operations.

No implicit workspace or cross-root file move; controlled Exec and Git have
separate synchronous Worker admission, never reflective file dispatch.
"""
from __future__ import annotations

from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, replace
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
                # No signal/join: a separately authorized direct child may
                # outlive a dropped waiter or Gateway shutdown.
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
        """Live schema-v2 preview of a Worker-compatible nonspawning plan.

        Python Direct/Pipenv and Go test/vet/build reuse source policy used
        for separately authorized Worker preparation. This preview NEVER
        grants positive Exec: shared F1 denies ordinary dry_run=False
        before this route, REST or the official MCP adapter can launch it.
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
            # Informational normalized Go build output; never a write claim.
            "planned_go_output": plan.planned_go_output,
            # Content snapshots only; no loaded source or native authority.
            "planned_script_sha256": plan.planned_script_sha256,
            "planned_pipfile_sha256": plan.planned_pipfile_sha256,
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
                   timeout_seconds: int, *,
                   cancelled: threading.Event | None = None) -> dict[str, Any]:
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
            return worker.run(plan, cancelled=cancelled)
        except LbeWorkerError as exc:
            raise GatewayError(
                exc.code, "Local best-effort command could not complete safely.",
                details={"process_may_be_running": exc.process_may_be_running},
            ) from None

    def invoke_exec(self, name: str, cwd: str, argv: list[str],
                    timeout_seconds: int = 60, dry_run: bool = True, *,
                    cancelled: threading.Event | None = None) -> dict[str, Any]:
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
            if cancelled is not None and type(cancelled) is not threading.Event:
                raise GatewayError("invalid_argument", "Invalid internal cancellation token.")
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
                        ctx, self._lbe_owner, cwd, argv, timeout_seconds,
                        cancelled=cancelled)
            else:
                # Preserve the entire historic v1 preview and F1 deny-only path.
                result = ctx.gateway.run_command(cwd, argv, timeout_seconds, dry_run)
            return {**result, "workspace": name}
        finally:
            with self._lifecycle:
                self._exec_active.remove(name)
                self._active_operations -= 1
                self._lifecycle.notify_all()

    def _prepare_d4_r003_fixture_candidate(
        self, name: str, cwd: str, argv: list[str],
        timeout_seconds: int = 60,
    ):
        """Service-origin selected first-party D4 input inspection, NO grant.

        This internal source-read function does not open positive Exec,
        bypass native Go/Pipenv denial, attest third-party loaded source or
        allow a REST/MCP caller to provide an authorization capability.
        A future independently approved product launch must recheck the
        *same* input, actual runner and all remaining guards pre-Popen.
        """
        with self._lifecycle:
            ctx = self.require_exec(name)
            if self.settings.schema_version != 2:
                raise GatewayError(
                    "exec_disabled", "D4 input qualification requires schema v2.")
            if self._exec_state is None:
                raise GatewayError(
                    "exec_state_unavailable", "Exec durable state is unavailable.")
            self._exec_state.require_healthy()
            # Keep pinned Workspace and old-state owner handles live while
            # inspecting first-party source bytes outside the lifecycle lock.
            self._active_operations += 1
        try:
            from .lbe_plan import prepare_lbe_work_plan
            from .lbe_product_fixture import (
                D4FixtureDenied, check_d4_r003_fixture,
            )

            plan = prepare_lbe_work_plan(
                ctx, cwd=cwd, argv=argv, timeout_seconds=timeout_seconds)
            from .lbe_python_import_sources import (
                D4PythonImportDenied, inspect_d4_python_first_party_import_sources,
            )
            try:
                candidate = check_d4_r003_fixture(ctx, plan)
                if candidate.plan.cwd in ("py-direct", "py-pipenv"):
                    # Actual pinned first-party import edges are a bounded,
                    # nonexecuting source observation. Third-party/sys.path
                    # and dynamic import identities remain unqualified.
                    imports = inspect_d4_python_first_party_import_sources(
                        ctx, candidate)
                    candidate = replace(candidate, python_import_sources=imports)
                return candidate
            except (D4FixtureDenied, D4PythonImportDenied):
                raise GatewayError(
                    "command_not_allowed",
                    "D4 first-party fixture is not qualified for this plan.",
                ) from None
        finally:
            with self._lifecycle:
                self._active_operations -= 1
                self._lifecycle.notify_all()

    def _prepare_d4_r003_attempt(
        self, name: str, cwd: str, argv: list[str],
        timeout_seconds: int = 60,
    ):
        """Source-only, one-use internal attempt; never an Exec grant.

        This returns the same live service's first-party candidate and a
        context-bound, atomic marker. The Worker verifies the marker again
        just before reservation/launch. Neither this private method nor a
        token can change the operative F1 or NativeLauncher Go/Pipenv DENY.
        """
        candidate = self._prepare_d4_r003_fixture_candidate(
            name, cwd, argv, timeout_seconds=timeout_seconds)
        from .lbe_product_fixture import D4OneUseAttemptMarker

        # get() rechecks service-closing state after source inspection.
        return candidate, D4OneUseAttemptMarker(candidate, self.get(name))

    def _inspect_d4_r003_staged_runtime(
        self, name: str, cwd: str, argv: list[str], *,
        private_root: str, expected_hashes: dict[str, str],
        expected_trees: dict[str, tuple[tuple[str, str | None], ...]] | None = None,
        timeout_seconds: int = 60,
    ):
        """Actual internal staged-source selection, NO Go/Pipenv execution.

        Build a strict first-party service plan, verify the existing v1
        ExecStateStore and Workspace gates, then read the staged native
        executable files and build a fresh, closed proposed environment.
        This is an internal *source* step for a future runner bootstrap,
        not a public REST/MCP API, owner test consent, full loaded-source
        attestation or a way to activate F1 or the NativeLauncher.
        """
        with self._lifecycle:
            ctx = self.require_exec(name)
            if self.settings.schema_version != 2:
                raise GatewayError(
                    "exec_disabled", "D4 stage requires schema v2.")
            if self._exec_state is None:
                raise GatewayError(
                    "exec_state_unavailable", "Exec durable state unavailable.")
            self._exec_state.require_healthy()
            self._active_operations += 1
        try:
            from .lbe_runtime_source import (
                D4RuntimeSourceDenied, inspect_d4_runtime_sources,
            )

            candidate = self._prepare_d4_r003_fixture_candidate(
                name, cwd, argv, timeout_seconds=timeout_seconds)
            try:
                return inspect_d4_runtime_sources(
                    ctx, candidate, private_root=private_root,
                    expected_hashes=expected_hashes,
                    expected_trees=expected_trees,
                )
            except D4RuntimeSourceDenied:
                raise GatewayError(
                    "runner_unavailable",
                    "D4 staged runtime source or environment unavailable.",
                ) from None
        finally:
            with self._lifecycle:
                self._active_operations -= 1
                self._lifecycle.notify_all()

    def _prepare_d4_r003_staged_attempt(
        self, name: str, cwd: str, argv: list[str], *,
        private_root: str, expected_hashes: dict[str, str],
        expected_trees: dict[str, tuple[tuple[str, str | None], ...]] | None = None,
        timeout_seconds: int = 60,
    ):
        """Bind actual staged source/env observations to a one-use Worker.

        The internal source-only attempt remains non-authorizing. It must
        recheck first-party and staged binaries, parent execution selectors,
        and the constructed closed child environment after atomic attempt
        consumption and before any possible child launch. Missing Runner
        image, loaded-source closure, resource witness, owner approval and
        operative F1 exception always leave Go/Pipenv native execution DENIED.
        """
        observed = self._inspect_d4_r003_staged_runtime(
            name, cwd, argv, private_root=private_root,
            expected_hashes=expected_hashes,
            expected_trees=expected_trees,
            timeout_seconds=timeout_seconds,
        )
        candidate = self._prepare_d4_r003_fixture_candidate(
            name, cwd, argv, timeout_seconds=timeout_seconds)
        ctx = self.get(name)
        from .lbe_product_fixture import D4OneUseAttemptMarker
        from .lbe_runtime_source import (
            D4RuntimeSourceDenied, D4StagedSourceRecheck,
        )

        try:
            binding = D4StagedSourceRecheck(
                ctx, candidate, private_root=private_root,
                expected_hashes=expected_hashes, observed=observed,
                expected_trees=expected_trees)
            marker = D4OneUseAttemptMarker(
                candidate, ctx, staged_source=binding)
        except D4RuntimeSourceDenied:
            raise GatewayError(
                "runner_unavailable",
                "D4 staged source recheck binding unavailable.",
            ) from None
        return candidate, marker, observed

    def _prepare_d4_r003_native_recipe(
        self, name: str, cwd: str, argv: list[str], *,
        private_root: str, expected_hashes: dict[str, str],
        expected_trees: dict[str, tuple[tuple[str, str | None], ...]],
        timeout_seconds: int = 60,
    ):
        """Real internal product command selection; no native execution.

        Binds an exact six-command fixture to a source-only absolute
        executable, working directory, canonical output and constructed
        private child environment. The returned recipe cannot be passed to
        a public API or be treated as a D0/F1/NativeLauncher grant.
        """
        candidate, marker, observed = self._prepare_d4_r003_staged_attempt(
            name, cwd, argv, private_root=private_root,
            expected_hashes=expected_hashes,
            expected_trees=expected_trees,
            timeout_seconds=timeout_seconds,
        )
        from .lbe_launch_recipe import (
            D4NativeRecipeDenied, prepare_d4_native_launch_recipe,
        )

        try:
            recipe = prepare_d4_native_launch_recipe(
                self.get(name), candidate, observed, private_root=private_root)
        except D4NativeRecipeDenied:
            raise GatewayError(
                "runner_unavailable",
                "D4 native source-only recipe is unavailable.",
            ) from None
        return candidate, marker, observed, recipe

    def _prepare_d4_r003_runner_preflight(
        self, name: str, cwd: str, argv: list[str], *,
        private_root: str, expected_hashes: dict[str, str],
        expected_trees: dict[str, tuple[tuple[str, str | None], ...]],
        timeout_seconds: int = 60,
    ):
        """Observe actual host source identity without native T1 qualification.

        This continues the real v2 WorkspaceService product path after old
        owner.lock/ExecStateStore checks, the six-command recipe and one-use
        Worker source binding. Real kernel/UID/root inode and per-process
        rlimits are inspected, but the *whole descendant* CPU/RAM domain,
        immutable GitHub runner image, owner T1 consent and loaded source
        are NOT proved; an ordinary public apply and NativeLauncher DENY.
        """
        candidate, marker, observed, recipe = (
            self._prepare_d4_r003_native_recipe(
                name, cwd, argv, private_root=private_root,
                expected_hashes=expected_hashes,
                expected_trees=expected_trees,
                timeout_seconds=timeout_seconds,
            ))
        from .lbe_runner_preflight import (
            D4RunnerProbeDenied, D4RunnerSourceRecheck,
            observe_d4_runner_preflight,
        )
        from .lbe_product_fixture import D4FixtureDenied
        from .lbe_macos_runner import (
            D4MacOSRunnerDenied, D4MacOSRunnerLaunchBoundary,
        )

        try:
            ctx = self.get(name)
            runner = observe_d4_runner_preflight(
                ctx, recipe, private_root=private_root)
            bound = D4RunnerSourceRecheck(
                ctx, candidate.plan, recipe, runner, private_root=private_root)
            marker.attach_runner_source(bound)
            # The real Worker-facing macOS Runner adapter is created from
            # the same service-owned ctx/plan/recipe/live host observation.
            # It remains a SOURCE/T0 launch-denial boundary until a separate
            # physical CPU/RAM domain, exact owner T1 grant and operative
            # F1/D0 exception are independently approved and implemented.
            launch_boundary = D4MacOSRunnerLaunchBoundary(
                ctx, candidate.plan, recipe, runner,
                private_root=private_root)
            marker.attach_macos_runner_boundary(launch_boundary)
        except (D4RunnerProbeDenied, D4FixtureDenied,
                D4MacOSRunnerDenied):
            raise GatewayError(
                "runner_unavailable",
                "D4 trusted host resource/source preflight unavailable.",
            ) from None
        return candidate, marker, observed, recipe, runner

    def _exercise_d4_r003_source_only_worker(
        self, name: str, cwd: str, argv: list[str], *,
        private_root: str, expected_hashes: dict[str, str],
        expected_trees: dict[str, tuple[tuple[str, str | None], ...]],
        timeout_seconds: int = 60,
        cancelled: threading.Event | None = None,
    ) -> dict[str, Any]:
        """Service-owned source -> Worker -> macOS Runner, always NO CHILD.

        This real internal product call chain is never registered as an
        HTTP/MCP adapter. It shares the synchronous Workspace request lease,
        historical owner.lock/ExecStateStore denial, one-use source marker and
        the service's actual DirectChildOwner. Unlike a fake test launcher,
        it invokes ONLY the already hard-denying bound macOS Runner method.
        Neither this internal entrypoint nor supplied SHA bytes can authorize
        PRODUCT_T1, lift public F1/D0 or prove a whole-descendant OS domain.
        """
        with self._lifecycle:
            ctx = self.require_exec(name)
            if self.settings.schema_version != 2:
                raise GatewayError(
                    "exec_disabled", "D4 source-only Worker requires schema v2.")
            if self._exec_state is None:
                raise GatewayError(
                    "exec_state_unavailable", "Exec durable state unavailable.")
            self._exec_state.require_healthy()
            if cancelled is not None and type(cancelled) is not threading.Event:
                raise GatewayError(
                    "invalid_argument", "Invalid internal cancellation token.")
            if cancelled is not None and cancelled.is_set():
                raise GatewayError(
                    "waiter_disconnected", "Request was cancelled before source preparation.")
            if name in self._exec_active or len(self._exec_active) >= 4:
                raise GatewayError(
                    "busy", "A controlled command already occupies this slot.")
            owner = self._lbe_owner
            if owner is None:
                raise GatewayError(
                    "exec_state_unavailable", "D4 original-child owner missing.")
            self._exec_active.add(name)
            self._active_operations += 1
        try:
            candidate, marker, _source, _recipe, _host = (
                self._prepare_d4_r003_runner_preflight(
                    name, cwd, argv, private_root=private_root,
                    expected_hashes=expected_hashes,
                    expected_trees=expected_trees,
                    timeout_seconds=timeout_seconds))
            from .lbe_product_fixture import D4OneUseAttemptMarker
            from .lbe_macos_runner import (
                D4MacOSRunnerDenied, D4MacOSRunnerLaunchBoundary,
            )
            from .lbe_worker import LbeWorker, LbeWorkerError

            # Product code, not a caller, chooses the exact service-bound
            # launch callback. No alternate launcher or temporary owner can
            # borrow this source and native-denial witness.
            if (type(marker) is not D4OneUseAttemptMarker
                    or marker._ctx is not ctx
                    or marker._candidate is not candidate):
                raise GatewayError(
                    "runner_unavailable", "Service Runner marker missing.")
            boundary = marker._macos_boundary
            if type(boundary) is not D4MacOSRunnerLaunchBoundary:
                raise GatewayError(
                    "runner_unavailable", "Service Runner binding missing.")
            try:
                boundary.check_binding(ctx, candidate.plan)
            except D4MacOSRunnerDenied:
                raise GatewayError(
                    "runner_unavailable", "Service Runner identity drift.") from None
            try:
                result = LbeWorker(
                    owner, launcher=boundary.launch,
                ).run(candidate.plan, cancelled=cancelled,
                      product_attempt=marker)
            except LbeWorkerError as exc:
                raise GatewayError(
                    exc.code, "D4 source-only Worker did not complete safely.",
                    details={
                        "process_may_be_running": exc.process_may_be_running,
                    },
                ) from None
            return {**result, "workspace": name}
        finally:
            with self._lifecycle:
                self._exec_active.remove(name)
                self._active_operations -= 1
                self._lifecycle.notify_all()

    def _stage_d4_r003_operator_source(
        self, name: str, cwd: str, argv: list[str], *,
        private_root: str, provisioner_root: str, kind: str,
        expected: tuple[tuple[str, str | None], ...],
        expected_source_identity_sha256: str | None = None,
        timeout_seconds: int = 60,
    ):
        """Materialize source from a separate owner-controlled provisioner.

        This is internal PRODUCT source preparation: the reviewed provisioner
        must supply exact staged source digests outside the private runner.
        It requires the existing v2 Workspace scope/owner.lock/ExecStateStore
        and canonical six-command fixture; it creates no native child and
        grants no public Exec capability, no matter what digest is supplied.
        """
        candidate = self._prepare_d4_r003_fixture_candidate(
            name, cwd, argv, timeout_seconds=timeout_seconds)
        allowed = (
            {"go"} if candidate.plan.cwd == "go-project" else {"bin", "lib"}
        )
        if type(kind) is not str or kind not in allowed:
            raise GatewayError(
                "runner_unavailable", "Selected runtime staging kind denied.")
        from .lbe_runtime_stage import (
            D4RuntimeStageDenied, stage_d4_operator_runtime_tree,
        )

        try:
            receipt = stage_d4_operator_runtime_tree(
                private_root=private_root, provisioner_root=provisioner_root,
                kind=kind, expected=expected,
                expected_source_identity_sha256=expected_source_identity_sha256)
        except D4RuntimeStageDenied:
            raise GatewayError(
                "runner_unavailable",
                "D4 private runtime staging unavailable.",
            ) from None
        # Staging has not promoted the original candidate to authority:
        # re-read the real Workspace before returning selected bytes.
        after = self._prepare_d4_r003_fixture_candidate(
            name, cwd, argv, timeout_seconds=timeout_seconds)
        if (after.plan != candidate.plan
                or after.source_sha256 != candidate.source_sha256
                or after.source_identity != candidate.source_identity
                or after.directory_identity != candidate.directory_identity):
            raise GatewayError(
                "runner_unavailable",
                "First-party runtime changed during source staging.",
            )
        return receipt

    def _observe_d4_r003_operator_provisioner(
        self, name: str, cwd: str, argv: list[str], *,
        provisioner_root: str,
        expected_venv_record_distributions: tuple[tuple[str, str], ...] | None = None,
        timeout_seconds: int = 60,
    ):
        """Observe complete operator source bytes for explicit later approval.

        This is the real WorkspaceService six-command SOURCE-only workflow.
        A generated manifest can be shown to an independent operator/reviewer,
        but MUST NOT be automatically promoted into the separately reviewed
        expected manifest accepted by _assemble_d4_r003_source_only_runner.
        In particular, bytes cannot self-attest their trusted provisioner,
        image, loaded-source closure, resources or owner T1 permission.
        """
        candidate = self._prepare_d4_r003_fixture_candidate(
            name, cwd, argv, timeout_seconds=timeout_seconds)
        from .lbe_runtime_tree import (
            D4RuntimeTreeDenied, observe_d4_operator_source_manifest,
            observe_d4_pipenv_venv_manifest,
        )
        from .lbe_runtime_source import _canonical, D4RuntimeSourceDenied
        from .lbe_pipenv_lock_sources import (
            D4PipenvLockDenied, inspect_d4_pipenv_lock_sources,
        )
        from .lbe_go_import_sources import (
            D4GoImportSourceDenied, inspect_d4_go_direct_import_sources,
        )
        from dataclasses import replace

        kinds = (("go",) if candidate.plan.cwd == "go-project"
                 else ("bin", "lib"))
        if (expected_venv_record_distributions is not None
                and candidate.plan.cwd != "py-pipenv"):
            raise GatewayError(
                "runner_unavailable",
                "D4 first-party Pipenv RECORD scope unavailable.")
        try:
            source = _canonical(provisioner_root, "operator provisioner")
            workspace = _canonical(
                str(self.get(name).gateway._root_path), "Workspace root")
            if (source == workspace
                    or source.startswith(workspace + "/")
                    or workspace.startswith(source + "/")):
                raise D4RuntimeSourceDenied(
                    "operator provisioner overlaps Workspace")
            observed = {
                kind: observe_d4_operator_source_manifest(
                    provisioner_root=source, kind=kind)
                for kind in kinds
            }
            if candidate.plan.cwd == "py-pipenv":
                # Unlike bin/lib, .venv belongs to the FIRST-PARTY
                # Workspace, not the operator. A whole imported-source
                # manifest is reviewable without import or execution.
                observed["venv"] = observe_d4_pipenv_venv_manifest(
                    project_root=workspace + "/py-pipenv",
                    expected_record_distributions=(
                        expected_venv_record_distributions))
                if expected_venv_record_distributions is not None:
                    # Lock default/develop requirements must agree with
                    # the separately selected RECORD-installed site.
                    lock_hash = dict(candidate.source_sha256)[
                        "py-pipenv/Pipfile.lock"]
                    matched_lock = inspect_d4_pipenv_lock_sources(
                        project_root=workspace + "/py-pipenv",
                        expected_lock_sha256=lock_hash,
                        expected_pipfile_sha256=dict(candidate.source_sha256)[
                            "py-pipenv/Pipfile"],
                        expected_distributions=(
                            expected_venv_record_distributions))
                    observed["venv"] = replace(
                        observed["venv"], pipenv_lock_sources=matched_lock)
            if (candidate.plan.cwd == "go-project"
                    and observed["go"].go_1_27_3_p007_stage_manifest_matched):
                # Direct import selection supplements the full P007 stage.
                # Neither source observation is a loaded/operating Go graph.
                direct = inspect_d4_go_direct_import_sources(
                    self.get(name), candidate,
                    staged_go_manifest=observed["go"].proposed_manifest)
                observed["go"] = replace(
                    observed["go"], go_direct_import_sources=direct)
        except (D4RuntimeTreeDenied, D4RuntimeSourceDenied,
                D4PipenvLockDenied, D4GoImportSourceDenied, OSError):
            raise GatewayError(
                "runner_unavailable", "D4 operator source selection unavailable."
            ) from None
        # Source inspection must not retain a first-party Workspace snapshot
        # across operator file reads without rechecking its live identity.
        after = self._prepare_d4_r003_fixture_candidate(
            name, cwd, argv, timeout_seconds=timeout_seconds)
        if (after.plan != candidate.plan
                or after.source_sha256 != candidate.source_sha256
                or after.source_identity != candidate.source_identity
                or after.directory_identity != candidate.directory_identity):
            raise GatewayError(
                "runner_unavailable",
                "D4 Workspace source changed during operator observation.",
            )
        return observed

    def _assemble_d4_r003_source_only_runner(
        self, name: str, cwd: str, argv: list[str], *,
        private_root: str, provisioner_root: str,
        staged_manifests: dict[str, tuple[tuple[str, str | None], ...]],
        venv_manifest: tuple[tuple[str, str | None], ...] | None = None,
        expected_source_identities: dict[str, str] | None = None,
        expected_venv_identity_sha256: str | None = None,
        require_go_p007_stage_source: bool = False,
        expected_venv_record_distributions: tuple[tuple[str, str], ...] | None = None,
        timeout_seconds: int = 60,
    ):
        """Assemble the real six-command private runtime, never launch it.

        The separate owner-controlled provisioner supplies exactly the Go
        toolchain or bin/lib source trees. This creates non-reusable private
        staged directories and fresh HOME/TMP/caches, derives selected
        executable hashes from the proven staged source set, then traverses
        the same service-owned D4 recipe/one-use/Runner and selected native
        Mach-O loader-set preflight. Non-Mach-O and wrong-architecture
        toolchain binaries fail before any possible native execution.
        Source manifests are NOT independent provider/image/owner attestation.
        Any failure leaves partial bytes in the disposable private runner;
        no rollback, unsafe path overwrite, native child or retry occurs.
        """
        candidate = self._prepare_d4_r003_fixture_candidate(
            name, cwd, argv, timeout_seconds=timeout_seconds)
        if candidate.plan.cwd == "go-project":
            flavor, kinds = "go", ("go",)
        elif candidate.plan.cwd == "py-pipenv":
            flavor, kinds = "pipenv", ("bin", "lib")
        else:
            flavor, kinds = "python_direct", ("bin", "lib")
        if (type(staged_manifests) is not dict
                or any(type(k) is not str or type(v) is not tuple
                       for k, v in staged_manifests.items())
                or set(staged_manifests) != set(kinds)
                or (flavor == "pipenv") != (type(venv_manifest) is tuple)
                or (venv_manifest is not None
                    and type(venv_manifest) is not tuple)):
            raise GatewayError(
                "runner_unavailable", "D4 source bundle selection is incomplete.")
        # These IDs are expected from a separately inspected/reviewed
        # operator-source snapshot. A caller-provided hash is NOT approval:
        # it only prevents staging an unobserved inode tree with matching
        # contents/modes. Validate complete kind set before creating files.
        if (expected_source_identities is not None
                and (type(expected_source_identities) is not dict
                     or set(expected_source_identities) != set(kinds)
                     or any(type(value) is not str or len(value) != 64
                            or value == "0" * 64
                            or any(ch not in "0123456789abcdef"
                                   for ch in value)
                            for value in expected_source_identities.values()))):
            raise GatewayError(
                "runner_unavailable",
                "D4 operator source identity selection is incomplete.")
        # When an owner explicitly requires the PR101 P007 complete Go
        # release SOURCE candidate, fail before copying anything unless the
        # FULL 15657-file sorted SHA-prefixed manifest matches the immutable
        # Go 1.27.3 stage pin. A hash of only go/compile/link is insufficient.
        # The additional caller-provided source-tree identity catches
        # subsequent drift but does NOT attest independent approval or origin.
        # This is a SOURCE-only opt-in, not a NativeLauncher/F1 exception.
        if type(require_go_p007_stage_source) is not bool:
            raise GatewayError(
                "runner_unavailable", "D4 Go source profile selection invalid.")
        if require_go_p007_stage_source:
            if flavor != "go" or expected_source_identities is None:
                raise GatewayError(
                    "runner_unavailable", "D4 complete Go source not selected.")
            from .lbe_runtime_tree import (
                _d4_p007_go_stage_matches, D4RuntimeTreeDenied,
            )
            try:
                matched = _d4_p007_go_stage_matches(staged_manifests["go"])
            except D4RuntimeTreeDenied:
                matched = False
            if not matched:
                raise GatewayError(
                    "runner_unavailable",
                    "D4 operator Go source does not match pinned full release.")
            from .lbe_go_import_sources import (
                D4GoImportSourceDenied, inspect_d4_go_direct_import_sources,
            )
            try:
                selected_go_imports = inspect_d4_go_direct_import_sources(
                    self.get(name), candidate,
                    staged_go_manifest=staged_manifests["go"])
            except (D4GoImportSourceDenied, OSError):
                raise GatewayError(
                    "runner_unavailable",
                    "D4 Go imported source set not qualified.") from None

        # The reviewed first-party Pipenv .venv tree is distinct from
        # operator-owned bin/lib. Its complete identity is checked before
        # materializing any source and again after materialization. Even a
        # matching identity is NOT imported-source attestation or T1 consent.
        if (expected_venv_identity_sha256 is not None
                and (flavor != "pipenv"
                     or type(expected_venv_identity_sha256) is not str
                     or len(expected_venv_identity_sha256) != 64
                     or expected_venv_identity_sha256 == "0" * 64
                     or any(ch not in "0123456789abcdef"
                            for ch in expected_venv_identity_sha256))):
            raise GatewayError(
                "runner_unavailable",
                "D4 first-party virtualenv identity selection is incomplete.")

        # RECORD checks are a SOURCE-only installed-file admission gate.
        # An independently selected exact distribution list is mandatory;
        # RECORD itself is not publisher/source authenticity or import closure.
        # Validate all shape/role prerequisites BEFORE any staging directories.
        if (expected_venv_record_distributions is not None
                and (flavor != "pipenv"
                     or expected_venv_identity_sha256 is None
                     or venv_manifest is None)):
            raise GatewayError(
                "runner_unavailable",
                "D4 installed virtualenv record selection incomplete.")

        def check_venv_identity() -> None:
            if expected_venv_identity_sha256 is None:
                return
            from .lbe_runtime_tree import (
                D4RuntimeTreeDenied, inspect_d4_closed_staged_tree,
            )
            try:
                project = str(self.get(name).gateway._root_path) + "/py-pipenv"
                seen = inspect_d4_closed_staged_tree(
                    private_root=private_root,
                    staged_root=project + "/.venv",
                    expected=venv_manifest,
                )
            except (D4RuntimeTreeDenied, OSError):
                raise GatewayError(
                    "runner_unavailable",
                    "D4 private virtualenv source not qualified.") from None
            if seen.observed_identity_sha256 != expected_venv_identity_sha256:
                raise GatewayError(
                    "runner_unavailable",
                    "D4 private virtualenv source identity changed.")

        def check_venv_records() -> None:
            if expected_venv_record_distributions is None:
                return
            from .lbe_runtime_tree import (
                D4RuntimeTreeDenied, inspect_d4_pipenv_installed_record_sources,
            )
            from .lbe_pipenv_lock_sources import (
                D4PipenvLockDenied, inspect_d4_pipenv_lock_sources,
            )
            try:
                project = str(self.get(name).gateway._root_path) + "/py-pipenv"
                observed = inspect_d4_pipenv_installed_record_sources(
                    project_root=project,
                    expected_venv_manifest=venv_manifest,
                    expected_distributions=expected_venv_record_distributions,
                )
                lock_hash = dict(candidate.source_sha256)[
                    "py-pipenv/Pipfile.lock"]
                locked = inspect_d4_pipenv_lock_sources(
                    project_root=project,
                    expected_lock_sha256=lock_hash,
                    expected_pipfile_sha256=dict(candidate.source_sha256)[
                        "py-pipenv/Pipfile"],
                    expected_distributions=expected_venv_record_distributions,
                )
                if locked.selected_installed_distributions != observed.distributions:
                    raise D4PipenvLockDenied("Pipenv lock and site selection diverged")
            except (D4RuntimeTreeDenied, D4PipenvLockDenied, OSError):
                raise GatewayError(
                    "runner_unavailable",
                    "D4 first-party Pipenv installed source RECORD incomplete."
                ) from None
            if (observed.venv_identity_sha256
                    != expected_venv_identity_sha256):
                raise GatewayError(
                    "runner_unavailable",
                    "D4 first-party Pipenv installed source tree changed.")

        check_venv_identity()
        check_venv_records()
        from .lbe_runtime_stage import (
            D4RuntimeStageDenied, create_d4_fresh_runner_scratch,
        )

        stage_receipts = []
        for kind in kinds:
            stage_receipts.append(self._stage_d4_r003_operator_source(
                name, cwd, argv,
                private_root=private_root,
                provisioner_root=provisioner_root,
                kind=kind, expected=staged_manifests[kind],
                expected_source_identity_sha256=(
                    expected_source_identities[kind]
                    if expected_source_identities is not None else None),
                timeout_seconds=timeout_seconds))
        # Bin/lib or Go staging may take time. The pinned first-party venv
        # identity MUST still match before preparing any child environment.
        check_venv_identity()
        check_venv_records()
        try:
            scratch = create_d4_fresh_runner_scratch(
                private_root=private_root, kind=flavor)
        except D4RuntimeStageDenied:
            raise GatewayError(
                "runner_unavailable", "D4 fresh runtime scratch unavailable."
            ) from None
        chosen = {}
        for kind in kinds:
            # Stage has already validated the exact source manifest. A
            # separate caller-provided digest cannot silently replace the
            # source result or create a trusted execution grant.
            chosen[kind] = dict(staged_manifests[kind])
        selected = dict(candidate.source_sha256)
        if flavor == "go":
            expected_hashes = {
                "go": chosen["go"].get("bin/go"),
                "compile": chosen["go"].get("pkg/tool/darwin_arm64/compile"),
                "link": chosen["go"].get("pkg/tool/darwin_arm64/link"),
            }
        elif flavor == "pipenv":
            expected_hashes = {
                "Pipfile": selected.get("py-pipenv/Pipfile"),
                "Pipfile.lock": selected.get("py-pipenv/Pipfile.lock"),
                "pyvenv.cfg": selected.get("py-pipenv/.venv/pyvenv.cfg"),
                "python": selected.get("py-pipenv/.venv/bin/python"),
                "pipenv": chosen["bin"].get("pipenv"),
            }
        else:
            expected_hashes = {"python": chosen["bin"].get("python")}
        if any(type(v) is not str or len(v) != 64
               for v in expected_hashes.values()):
            raise GatewayError(
                "runner_unavailable", "D4 staged executable selection incomplete.")
        expected_trees = dict(staged_manifests)
        expected_trees.update({name: (("", None),) for name in scratch})
        if flavor == "pipenv":
            expected_trees["venv"] = venv_manifest
        # The primary product source preparation NOW requires the same
        # actual pinned ARM64 image/header and one-use loader-set recheck as
        # the separate source inspector, for every selected Go compiler/linker
        # and the exact selected Python interpreter. Static declarations do
        # not establish dyld resolution or native execution authorization.
        prepared = self._prepare_d4_r003_selected_loader_set(
            name, cwd, argv, private_root=private_root,
            expected_hashes=expected_hashes,
            expected_trees=expected_trees,
            timeout_seconds=timeout_seconds,
        )
        current = prepared[0]
        if (current.plan != candidate.plan
                or current.source_sha256 != candidate.source_sha256
                or current.source_identity != candidate.source_identity
                or current.directory_identity != candidate.directory_identity):
            raise GatewayError(
                "runner_unavailable", "D4 fixture drifted during assembly.")
        # Runtime source trees are already closed against these exact bytes.
        # Resolve only PRIVATE Mach-O library references actually present in
        # the operator-staged Go/lib directories; a synthetic @rpath or
        # unpinned host/system library is an explicit unqualified gap, NOT
        # independent dyld loading proof or execution permission.
        private_dylibs = tuple(sorted(
            (kind + "/" + leaf, digest)
            for kind, rows in staged_manifests.items()
            for leaf, digest in rows
            if type(leaf) is str and leaf.endswith(".dylib")
            and type(digest) is str
        ))
        from .lbe_dylib_sources import (
            D4PrivateDylibDenied, D4PrivateDylibSourceRecheck,
            inspect_d4_private_dylib_candidates,
        )
        from .lbe_product_fixture import D4FixtureDenied

        try:
            graph = inspect_d4_private_dylib_candidates(
                prepared[5], private_root=private_root,
                expected_private_dylibs=private_dylibs)
            ctx = self.get(name)
            binding = D4PrivateDylibSourceRecheck(
                ctx, current.plan, prepared[5], graph,
                private_root=private_root,
                expected_private_dylibs=private_dylibs)
            prepared[1].attach_private_dylib_sources(binding)
        except (D4PrivateDylibDenied, D4FixtureDenied):
            raise GatewayError(
                "runner_unavailable", "D4 private native dylib source unqualified."
            ) from None
        check_venv_identity()
        check_venv_records()
        if require_go_p007_stage_source:
            try:
                rechecked_go_imports = inspect_d4_go_direct_import_sources(
                    self.get(name), candidate,
                    staged_go_manifest=staged_manifests["go"])
            except (D4GoImportSourceDenied, OSError):
                raise GatewayError(
                    "runner_unavailable",
                    "D4 Go imported source changed during assembly.") from None
            if rechecked_go_imports != selected_go_imports:
                raise GatewayError(
                    "runner_unavailable",
                    "D4 Go imported source selection drifted.")
        return (*prepared, graph, tuple(stage_receipts))

    def _prepare_d4_r003_selected_macho_source(
        self, name: str, cwd: str, argv: list[str], *,
        private_root: str, expected_hashes: dict[str, str],
        expected_trees: dict[str, tuple[tuple[str, str | None], ...]],
        timeout_seconds: int = 60,
    ):
        """Inspect actual Darwin ARM64 selected loader, without native T1.

        This extends the service-owned six-command source -> runner inspection
        with bounded Mach-O LC_LOAD_DYLIB/LC_RPATH evidence, and chooses the
        pinned Pipenv shebang interpreter rather than mistaking the script
        for the loaded Python image. The physical OS child resource domain,
        actual dyld closure, GitHub image and owner grant remain NOT PROVEN.
        The ordinary public Exec apply gate is untouched and denies.
        """
        prepared = self._prepare_d4_r003_runner_preflight(
            name, cwd, argv, private_root=private_root,
            expected_hashes=expected_hashes,
            expected_trees=expected_trees,
            timeout_seconds=timeout_seconds,
        )
        from .lbe_macho_loader import (
            D4MachOLoaderDenied, select_d4_macho_loader_source,
        )

        try:
            loader = select_d4_macho_loader_source(
                prepared[2], prepared[3], private_root=private_root)
        except D4MachOLoaderDenied:
            raise GatewayError(
                "runner_unavailable",
                "D4 ARM64 native loader declarations are not qualified.",
            ) from None
        return (*prepared, loader)

    def _prepare_d4_r003_selected_loader_set(
        self, name: str, cwd: str, argv: list[str], *,
        private_root: str, expected_hashes: dict[str, str],
        expected_trees: dict[str, tuple[tuple[str, str | None], ...]],
        timeout_seconds: int = 60,
    ):
        """Service-owned native binary set inspection and one-use recheck.

        Go selects actual go + compile + link, Python Direct selects its
        private interpreter, and Pipenv selects the private interpreter
        targeted by the verified #! script. No imports/commands are run:
        direct dyld declarations still cannot prove the real loaded graph.
        The snapshot recheck is attached only to the internal one-use
        Worker source marker and adds no positive Exec authority.
        """
        candidate, marker, observed, recipe, runner = (
            self._prepare_d4_r003_runner_preflight(
                name, cwd, argv, private_root=private_root,
                expected_hashes=expected_hashes,
                expected_trees=expected_trees,
                timeout_seconds=timeout_seconds,
            ))
        from .lbe_native_loader_set import (
            D4NativeLoaderSetDenied, D4NativeLoaderSetRecheck,
            inspect_d4_native_loader_set,
        )
        from .lbe_product_fixture import D4FixtureDenied

        try:
            loader_set = inspect_d4_native_loader_set(
                observed, recipe, private_root=private_root)
            bound = D4NativeLoaderSetRecheck(
                self.get(name), candidate.plan, observed, recipe,
                loader_set, private_root=private_root)
            marker.attach_macho_loader_set(bound)
        except (D4NativeLoaderSetDenied, D4FixtureDenied):
            raise GatewayError(
                "runner_unavailable",
                "D4 selected ARM64 native binary source set unavailable.",
            ) from None
        return candidate, marker, observed, recipe, runner, loader_set

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
        """Configured grants and actual v2 preview/apply availability differ.

        An exec.paths grant permits preview, not positive F1 launch. Keep
        the old configured exec field but expose each v2 Workspace's
        nonspawning preview and actual positive admission status separately.
        The result is status, never an execution token or new authority.
        """
        with self._lifecycle:
            v2 = self.settings.schema_version == 2
            old_state_healthy = bool(
                v2 and self._exec_state is not None
                and self._exec_state.durability_state == "healthy")
            preview_capacity = bool(
                old_state_healthy and not self._closing
                and len(self._exec_active) < 4)
            result = []
            for ctx in self._workspaces.values():
                granted = bool(self.settings.exec_enabled
                               and ctx.settings.exec_enabled)
                preview = bool(
                    granted and preview_capacity
                    and ctx.name not in self._exec_active)
                apply = bool(
                    preview and self._lbe_positive_authorized
                    and self._lbe_owner is not None
                    and self._lbe_owner.can_admit_any((ctx.name,)))
                result.append({
                    "id": ctx.name, "read": True,
                    "write": ctx.settings.allow_write,
                    "exec": granted,
                    # Never reinterpret existing v1 grants or response shape.
                    **({"exec_preview_available": preview,
                        "exec_apply_available": apply} if v2 else {}),
                    "local_skills": False,
                    "sensitive_content": ctx.gateway.sensitive_audit.status(),
                    "git": {
                        "enabled": bool(self.settings.git_enabled
                                        and ctx.settings.git_allowed_commands),
                        "allowed_commands": list(ctx.settings.git_allowed_commands),
                    },
                })
            return {"workspaces": result}

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
            # A healthy schema-v2 service may support an entirely
            # nonspawning plan even though positive Exec remains F1-denied.
            # Preview requests share the synchronous request slot gate, not
            # the original-child lease; never imply native launch authority.
            # Preview has no original-child lease and can remain usable
            # after the native owner latches unavailable. Only healthy old
            # durable state and free synchronous request slots are needed.
            v2_preview_available = bool(
                is_v2 and effective and durability == "healthy"
                and not self._closing and eligible_names
                and len(self._exec_active) < 4)
            return {"name": "Mac File Gateway", "version": "2.5.0", "mode": "multi",
                    "workspace_count": len(self._workspaces),
                    **({"config_schema_version": 2}
                       if self.settings.schema_version == 2 else {}),
                    # A paths-only v2 preview is read-only. A separately
                    # qualified internal positive Exec capability is not:
                    # its trusted child may mutate host state, even if its
                    # capacity is temporarily occupied or its waiter lost.
                    # This is STATUS reporting only, never an Exec grant.
                    "read_only": not (
                        self.any_write or self.any_git or
                        (is_v2 and self._lbe_positive_authorized)),
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
                        **({"preview_available": v2_preview_available}
                           if is_v2 else {}),
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
                        # Discovery is for NONSPAWNING validated commands only.
                        # It is not an operative Exec grant and does not mean
                        # the current owner/source/native gates have passed.
                        **({"supported_preview_commands": [
                            "pytest",
                            "python -m pytest",
                            "python -m compileall",
                            "python <relative-script.py>",
                            "go test ./...",
                            "go vet ./...",
                            "go build ./...",
                            "go build -o <relative-output> ./package",
                        ]} if is_v2 else {}),
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
