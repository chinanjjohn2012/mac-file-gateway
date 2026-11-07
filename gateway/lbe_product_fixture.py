"""D4 R003 first-party product fixture prelaunch checks; no execution grant.

This is real shared-Workspace source preflight, not the declaration-only T0
packet. It inspects *selected* disposable first-party input bytes using
nofollow descriptors, but cannot certify third-party loaded Go/Pipenv/Python
source, runner identity, OS CPU/RAM enforcement, owner consent or a future
pathname Popen. It NEVER imports or launches project/toolchain code and cannot
turn the current public F1 denial into a positive Exec permission.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass
import hashlib
import os
import re
import stat
from typing import TYPE_CHECKING

from .lbe_worker import LbeWorkPlan, LbeWorker, LbeWorkerError

if TYPE_CHECKING:
    from .workspaces import WorkspaceContext


class D4FixtureDenied(ValueError):
    """Proposed D4 product fixture is absent, mutable or out of scope."""


PROFILE_ID = "MWE-LBE-TRUSTED-PRODUCT-T1-PROFILE-R003"
PROFILE_GIT_BLOB = "f8556b48ab5f4af7390fb015092862a8a87768fb"
_STATUS = "SELECTED_FIRST_PARTY_SOURCE_ONLY_NO_NATIVE_AUTHORITY"
_MAX_SOURCE_BYTES = 1024 * 1024
_MAX_PYTHON_EXECUTABLE_BYTES = 128 * 1024 * 1024
_MAX_SRC_ENTRIES = 128
_MAX_TOTAL_FILES = 128
_MAX_TOTAL_BYTES = 160 * 1024 * 1024
_MAX_TREE_DEPTH = 5
_PY_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\.py\Z")
_GO_NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_-]*\.go\Z")
_DIR_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*\Z")

# Exact requested argv and effective argv must BOTH be checked: user-supplied
# `pipenv run` is not equivalent to an internal selected Pipenv runner.
_MATRIX = (
    ("py-direct", "direct",
     ("python", "-m", "pytest", "-q"),
     ("python", "-m", "pytest", "-q")),
    ("py-direct", "direct",
     ("python", "-m", "compileall", "-q", "./src"),
     ("python", "-m", "compileall", "-q", "./src")),
    ("py-pipenv", "pipenv",
     ("python", "-m", "pytest", "-q"),
     ("pipenv", "run", "python", "-m", "pytest", "-q")),
    ("go-project", "direct",
     ("go", "test", "./..."), ("go", "test", "./...")),
    ("go-project", "direct",
     ("go", "vet", "./..."), ("go", "vet", "./...")),
    ("go-project", "direct",
     ("go", "build", "-o", "bin/app", "./cmd/app"),
     ("go", "build", "-o", "bin/app", "./cmd/app")),
)


@dataclass(frozen=True, slots=True)
class D4FixtureCandidate:
    """One checked first-party fixture selection; deliberately NOT a grant."""

    plan: LbeWorkPlan
    source_sha256: tuple[tuple[str, str], ...]
    source_identity: tuple[tuple[str, tuple[int, ...]], ...] = ()
    directory_identity: tuple[tuple[str, tuple[int, ...]], ...] = ()
    profile_id: str = PROFILE_ID
    profile_git_blob: str = PROFILE_GIT_BLOB
    status: str = _STATUS
    native_launch_allowed: bool = False
    actual_loaded_sources_proven: bool = False
    runner_qualified: bool = False
    resource_enforcement_proven: bool = False
    owner_approval_attested: bool = False



class D4OneUseAttemptMarker:
    """One-use, live-Workspace-bound source-check marker, NOT Exec authority.

    The real service alone prepares the candidate+context pair. On the first
    consumption we atomically burn the marker, then re-plan and re-read every
    selected first-party source from the pinned Workspace before any Worker
    reservation or possible launcher. A changed byte/inode/mode/owner or
    runner/argv selection fails closed; no retry on failure. This is NOT
    third-party loaded-source, OS resource, credential, owner-consent or
    post-check pathname-race qualification. Crash/restart replay protection
    is outside this in-memory primitive.
    """
    __slots__ = ("_candidate", "_ctx", "_pid", "_lock",
                 "_consumed", "_staged", "_runner", "_macho_set")

    def __init__(self, candidate: D4FixtureCandidate,
                 ctx: "WorkspaceContext", *,
                 staged_source: object = None) -> None:
        from .workspaces import WorkspaceContext

        if (type(candidate) is not D4FixtureCandidate
                or type(ctx) is not WorkspaceContext
                or type(candidate.plan) is not LbeWorkPlan
                or candidate.plan.workspace != ctx.name
                or candidate.profile_id != PROFILE_ID
                or candidate.profile_git_blob != PROFILE_GIT_BLOB
                or candidate.status != _STATUS
                or candidate.native_launch_allowed is not False
                or candidate.actual_loaded_sources_proven is not False
                or candidate.runner_qualified is not False
                or candidate.resource_enforcement_proven is not False
                or candidate.owner_approval_attested is not False):
            raise D4FixtureDenied("only exact no-authority service source candidate allowed")
        try:
            LbeWorker._check_plan(candidate.plan)
        except LbeWorkerError:
            raise D4FixtureDenied("candidate plan is invalid") from None
        if (type(candidate.source_sha256) is not tuple
                or type(candidate.source_identity) is not tuple
                or len(candidate.source_sha256) == 0
                or len(candidate.source_sha256) != len(candidate.source_identity)
                or type(candidate.directory_identity) is not tuple
                or not 0 < len(candidate.directory_identity) <= 128):
            raise D4FixtureDenied("candidate source inventory is not qualified")
        for item, recorded in zip(candidate.source_sha256,
                                  candidate.source_identity):
            if (type(item) is not tuple or len(item) != 2
                    or type(item[0]) is not str
                    or type(item[1]) is not str
                    or len(item[1]) != 64
                    or any(ch not in "0123456789abcdef" for ch in item[1])
                    or type(recorded) is not tuple or len(recorded) != 2
                    or recorded[0] != item[0]
                    or type(recorded[1]) is not tuple
                    or len(recorded[1]) != 8
                    or any(type(v) is not int for v in recorded[1])):
                raise D4FixtureDenied("candidate source identity is malformed")
        seen_directories: set[str] = set()
        for entry in candidate.directory_identity:
            if (type(entry) is not tuple or len(entry) != 2
                    or type(entry[0]) is not str or not entry[0]
                    or entry[0] in seen_directories
                    or type(entry[1]) is not tuple or len(entry[1]) != 8
                    or any(type(v) is not int for v in entry[1])):
                raise D4FixtureDenied("candidate directory identity malformed")
            seen_directories.add(entry[0])
        if candidate.plan.cwd not in seen_directories:
            raise D4FixtureDenied("candidate project directory is unqualified")
        if staged_source is not None:
            # No generic callback or client-crafted predicate may stand in
            # for this exact internally inspected source recheck.
            from .lbe_runtime_source import D4StagedSourceRecheck
            if type(staged_source) is not D4StagedSourceRecheck:
                raise D4FixtureDenied("staged-source recheck must be internal")
            staged_source.check_binding(ctx, candidate)
        self._candidate = candidate
        self._ctx = ctx
        self._staged = staged_source
        self._runner = None
        self._macho_set = None
        self._pid = os.getpid()
        self._lock = threading.Lock()
        self._consumed = False

    def attach_runner_source(self, runner_recheck: object) -> None:
        """Attach one service-owned live Runner source recheck before use."""
        from .lbe_runner_preflight import D4RunnerSourceRecheck

        if type(runner_recheck) is not D4RunnerSourceRecheck:
            raise D4FixtureDenied("Runner recheck must be a real service binding")
        with self._lock:
            if self._consumed or self._runner is not None:
                raise D4FixtureDenied("Runner recheck already attached or consumed")
            try:
                runner_recheck.check_binding(self._ctx, self._candidate.plan)
            except Exception:
                raise D4FixtureDenied("Runner recheck binding drift") from None
            self._runner = runner_recheck

    def attach_macho_loader_set(self, binding: object) -> None:
        """Attach one live service-selected native binary loader-set recheck.

        This static source recheck is NOT a trust grant. It is only called
        once by the internal v2 WorkspaceService, and cannot be supplied
        as a generic callback from REST/MCP or a forged record.
        """
        from .lbe_native_loader_set import D4NativeLoaderSetRecheck

        if type(binding) is not D4NativeLoaderSetRecheck:
            raise D4FixtureDenied("Mach-O loader-set binding must be internal")
        with self._lock:
            if self._consumed or self._macho_set is not None:
                raise D4FixtureDenied("Mach-O loader-set already bound or consumed")
            try:
                binding.check_binding(self._ctx, self._candidate.plan)
            except Exception:
                raise D4FixtureDenied("loader-set prelaunch binding drift") from None
            self._macho_set = binding

    def consume_for(self, plan: LbeWorkPlan) -> None:
        """Burn once, then recheck source and plan BEFORE possible spawn."""
        with self._lock:
            if self._consumed:
                raise D4FixtureDenied("product attempt already consumed")
            self._consumed = True
        if os.getpid() != self._pid or plan is not self._candidate.plan:
            raise D4FixtureDenied("product attempt plan identity changed")
        try:
            from .lbe_plan import prepare_lbe_work_plan

            fresh_plan = prepare_lbe_work_plan(
                self._ctx, cwd=plan.cwd, argv=list(plan.requested_argv),
                timeout_seconds=plan.timeout_seconds,
            )
            # Recomputed plan values are all exact primitives validated by
            # the shared LbeWorker and lbe_plan; no untrusted comparator.
            if fresh_plan != plan:
                raise D4FixtureDenied("product plan changed before launch")
            current = check_d4_r003_fixture(self._ctx, fresh_plan)
            if (current.source_sha256 != self._candidate.source_sha256
                    or current.source_identity != self._candidate.source_identity
                    or current.directory_identity != self._candidate.directory_identity):
                raise D4FixtureDenied("selected first-party source changed before launch")
            if self._staged is not None:
                self._staged.recheck_for(self._ctx, self._candidate)
            if self._runner is not None:
                self._runner.recheck_for(self._ctx, self._candidate.plan)
            if self._macho_set is not None:
                self._macho_set.recheck_for(self._ctx, self._candidate.plan)
        except D4FixtureDenied:
            raise
        except Exception:
            # All these checks are source-only and pre-Popen; normalize
            # errors without leaking paths or assuming a child existed.
            raise D4FixtureDenied("product prelaunch source recheck unavailable") from None


def _require_controlled(fd: int, *, directory: bool) -> os.stat_result:
    metadata = os.fstat(fd)
    if (metadata.st_uid != os.getuid() or metadata.st_mode & 0o022
            or not (stat.S_ISDIR(metadata.st_mode) if directory
                    else stat.S_ISREG(metadata.st_mode))):
        raise D4FixtureDenied("fixture ownership, mode or type is unsafe")
    if not directory and metadata.st_nlink != 1:
        raise D4FixtureDenied("linked fixture source is not allowed")
    return metadata


def _open_dir(parent_fd: int, name: str) -> int:
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                 | os.O_CLOEXEC, dir_fd=parent_fd)
    try:
        _require_controlled(fd, directory=True)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _file_digest(
    parent_fd: int, name: str, *,
    max_bytes: int = _MAX_SOURCE_BYTES,
    executable: bool = False,
) -> tuple[str, tuple[int, ...]]:
    """Read selected bytes by nofollow FD, including a bounded Python binary."""
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
                 | os.O_NONBLOCK, dir_fd=parent_fd)
    try:
        metadata = _require_controlled(fd, directory=False)
        if not 0 < metadata.st_size <= max_bytes:
            raise D4FixtureDenied("fixture input exceeds source-size bound")
        if executable and not metadata.st_mode & stat.S_IXUSR:
            raise D4FixtureDenied("selected interpreter is not owner executable")
        digest = hashlib.sha256()
        read_bytes = 0
        while read_bytes < metadata.st_size:
            data = os.read(fd, min(65536, metadata.st_size - read_bytes))
            if not data:
                raise D4FixtureDenied("fixture source changed while reading")
            read_bytes += len(data)
            digest.update(data)
        after = _require_controlled(fd, directory=False)
        fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns",
                  "st_ctime_ns", "st_mode", "st_uid", "st_nlink")
        before_identity = tuple(getattr(metadata, key) for key in fields)
        after_identity = tuple(getattr(after, key) for key in fields)
        if before_identity != after_identity:
            raise D4FixtureDenied("fixture inode or permissions changed during read")
        return digest.hexdigest(), before_identity
    finally:
        os.close(fd)


def _directory_identity(fd: int) -> tuple[int, ...]:
    metadata = _require_controlled(fd, directory=True)
    fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns",
              "st_ctime_ns", "st_mode", "st_uid", "st_nlink")
    return tuple(getattr(metadata, key) for key in fields)


def _inventory_begin(fd: int) -> tuple[tuple[int, ...], tuple[str, ...]]:
    identity = _directory_identity(fd)
    names = tuple(sorted(os.listdir(fd)))
    if len(names) > _MAX_SRC_ENTRIES:
        raise D4FixtureDenied("source directory has too many entries")
    if any(type(n) is not str or n in ("", ".", "..") or "/" in n
           or any(ord(c) < 33 or ord(c) >= 127 for c in n)
           for n in names):
        raise D4FixtureDenied("source directory contains an unsafe entry")
    return identity, names


def _inventory_end(fd: int, identity: tuple[int, ...],
                   names: tuple[str, ...]) -> None:
    if (_directory_identity(fd) != identity
            or tuple(sorted(os.listdir(fd))) != names):
        raise D4FixtureDenied("source directory changed while inspecting")


def _budget_add(row: tuple, budget: list[int]) -> None:
    budget[0] += 1
    budget[1] += row[2][2]
    if budget[0] > _MAX_TOTAL_FILES or budget[1] > _MAX_TOTAL_BYTES:
        raise D4FixtureDenied("selected source inventory exceeds bounded budget")


def _inspect_empty_dir(
    parent_fd: int, name: str, *, path: str,
    directories: list[tuple[str, tuple[int, ...]]],
) -> None:
    fd = _open_dir(parent_fd, name)
    try:
        identity, names = _inventory_begin(fd)
        if names:
            raise D4FixtureDenied("unapproved cached or output files in fixture")
        _inventory_end(fd, identity, names)
        directories.append((path, identity))
    finally:
        os.close(fd)


def _walk_code_dir(parent_fd: int, name: str, *,
                   prefix: str, kind: str, depth: int,
                   budget: list[int],
                   directories: list[tuple[str, tuple[int, ...]]]) -> tuple[tuple, ...]:
    """Enumerate selected project package files, not only the entrypoint.

    Never follow a linked directory/file, accept an unlisted source kind or
    trust bytes that moved while the directory walk was active. This proves
    only a bounded first-party source snapshot, NOT imported toolchain/site
    source identity, nor protection against a later Popen pathname race.
    """
    if depth > _MAX_TREE_DEPTH:
        raise D4FixtureDenied("source tree is deeper than approved fixture")
    fd = _open_dir(parent_fd, name)
    try:
        identity, names = _inventory_begin(fd)
        directories.append((prefix, identity))
        selected: list[tuple] = []
        for entry in names:
            if kind == "py" and entry == "__pycache__":
                _inspect_empty_dir(
                    fd, entry, path=prefix + "/" + entry,
                    directories=directories)
                continue
            if (kind == "py" and _PY_NAME.fullmatch(entry)
                    or kind == "go" and _GO_NAME.fullmatch(entry)):
                row = (prefix + "/" + entry, *_file_digest(fd, entry))
                _budget_add(row, budget)
                selected.append(row)
                continue
            if _DIR_NAME.fullmatch(entry) is None or depth == _MAX_TREE_DEPTH:
                raise D4FixtureDenied("unexpected file or import source in fixture")
            metadata = os.stat(entry, dir_fd=fd, follow_symlinks=False)
            if not stat.S_ISDIR(metadata.st_mode):
                raise D4FixtureDenied("unlisted source, symlink or nonregular entry")
            selected.extend(_walk_code_dir(
                fd, entry, prefix=prefix + "/" + entry, kind=kind,
                depth=depth + 1, budget=budget,
                directories=directories,
            ))
        _inventory_end(fd, identity, names)
        if not selected:
            raise D4FixtureDenied("empty package directory is not qualified")
        return tuple(selected)
    finally:
        os.close(fd)


def _python_selected_sources(
    project_fd: int, directories: list[tuple[str, tuple[int, ...]]],
) -> tuple[tuple, ...]:
    identity, names = _inventory_begin(project_fd)
    directories.append(("", identity))
    if "src" not in names:
        raise D4FixtureDenied("Python src input missing")
    budget = [0, 0]
    selected: list[tuple] = []
    for name in names:
        if name == "src" or name == "tests":
            selected.extend(_walk_code_dir(
                project_fd, name, prefix=name, kind="py", depth=1,
                budget=budget, directories=directories,
            ))
        elif name in ("conftest.py", "pytest.ini", "pyproject.toml",
                      "setup.cfg"):
            row = (name, *_file_digest(project_fd, name))
            _budget_add(row, budget)
            selected.append(row)
        else:
            raise D4FixtureDenied("unlisted Python fixture input or import hook")
    _inventory_end(project_fd, identity, names)
    return tuple(sorted(selected, key=lambda row: row[0]))


def _pipenv_selected_sources(
    project_fd: int, directories: list[tuple[str, tuple[int, ...]]],
) -> tuple[tuple, ...]:
    identity, names = _inventory_begin(project_fd)
    directories.append(("", identity))
    if not {"Pipfile", "Pipfile.lock", ".venv"}.issubset(names):
        raise D4FixtureDenied("Pipenv fixture inputs missing")
    budget = [0, 0]
    selected: list[tuple] = []
    for name in names:
        if name in ("Pipfile", "Pipfile.lock", "conftest.py",
                    "pytest.ini", "pyproject.toml", "setup.cfg"):
            row = (name, *_file_digest(project_fd, name))
            _budget_add(row, budget)
            selected.append(row)
        elif name == "tests":
            selected.extend(_walk_code_dir(
                project_fd, name, prefix=name, kind="py", depth=1,
                budget=budget, directories=directories,
            ))
        elif name != ".venv":
            raise D4FixtureDenied("unlisted Pipenv first-party input")
    venv_fd = _open_dir(project_fd, ".venv")
    try:
        directories.append((".venv", _directory_identity(venv_fd)))
        row = (".venv/pyvenv.cfg", *_file_digest(venv_fd, "pyvenv.cfg"))
        _budget_add(row, budget)
        selected.append(row)
        bin_fd = _open_dir(venv_fd, "bin")
        try:
            directories.append((".venv/bin", _directory_identity(bin_fd)))
            # A real interpreter may exceed the ordinary 1 MiB metadata cap.
            # Use a bounded 64 KiB streaming reader; never load/execute it.
            row = (".venv/bin/python", *_file_digest(
                bin_fd, "python", max_bytes=_MAX_PYTHON_EXECUTABLE_BYTES,
                executable=True,
            ))
            _budget_add(row, budget)
            selected.append(row)
        finally:
            os.close(bin_fd)
    finally:
        os.close(venv_fd)
    _inventory_end(project_fd, identity, names)
    # .venv/site, .pth, stdlib and actual Pipenv loader are NOT proven by
    # these selected first-party inputs; the F1/NativeLauncher deny remains.
    return tuple(sorted(selected, key=lambda row: row[0]))


def _qualify_go_module_snapshot(
    project_fd: int, pinned: tuple,
) -> None:
    """Reject unresolved Go module or toolchain selectors before any launch.

    This check is deliberately limited to a private, no-external-module
    first-party fixture. Unknown `require`, `replace`, `toolchain` and
    workspace directives must STOP until actual module graph/loader source
    provenance is independently reviewed. It is NOT a Go parser, actual
    GOROOT/stdlib proof, Go execution eligibility, or an OS egress control.
    """
    fd = os.open("go.mod", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
                 | os.O_NONBLOCK, dir_fd=project_fd)
    try:
        before = _require_controlled(fd, directory=False)
        if not 0 < before.st_size <= 64 * 1024:
            raise D4FixtureDenied("Go module declaration exceeds fixed fixture")
        raw = bytearray()
        while len(raw) < before.st_size:
            chunk = os.read(fd, min(65536, before.st_size - len(raw)))
            if not chunk:
                raise D4FixtureDenied("Go module changed during validation")
            raw.extend(chunk)
        after = _require_controlled(fd, directory=False)
        fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns",
                  "st_ctime_ns", "st_mode", "st_uid", "st_nlink")
        identity = tuple(getattr(before, key) for key in fields)
        if (identity != tuple(getattr(after, key) for key in fields)
                or identity != pinned[2]
                or hashlib.sha256(raw).hexdigest() != pinned[1]):
            raise D4FixtureDenied("Go module identity changed after inventory")
    finally:
        os.close(fd)
    try:
        source = bytes(raw).decode("ascii")
    except UnicodeDecodeError:
        raise D4FixtureDenied("Go module has non-ASCII unsupported directives") from None
    if any(c in source for c in ("\x00", "\r", "\\", "\t")):
        raise D4FixtureDenied("Go module is not an exact simple fixture")
    module_count, go_count = 0, 0
    for line in source.split("\n"):
        if not line:
            continue
        if line.startswith("module "):
            path = line[len("module "):]
            # Local replace, relative imports and quote/space escaped paths
            # cannot be qualified through this one-module fixture parser.
            if (re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]*", path) is None
                    or any(part in ("", ".", "..") for part in path.split("/"))
                    or "." not in path.split("/")[0]):
                raise D4FixtureDenied("Go module path is not first-party scoped")
            module_count += 1
        elif line.startswith("go "):
            if re.fullmatch(r"1\.[0-9]+(?:\.[0-9]+)?",
                            line[len("go "):]) is None:
                raise D4FixtureDenied("Go version directive is invalid")
            go_count += 1
        else:
            raise D4FixtureDenied(
                "unqualified Go dependency, workspace or toolchain directive")
    if module_count != 1 or go_count != 1:
        raise D4FixtureDenied("Go module must contain one module and go version")


def _go_selected_sources(
    project_fd: int, directories: list[tuple[str, tuple[int, ...]]],
) -> tuple[tuple, ...]:
    identity, names = _inventory_begin(project_fd)
    directories.append(("", identity))
    if not {"go.mod", "cmd", "bin"}.issubset(names):
        raise D4FixtureDenied("Go module/package/output root missing")
    budget = [0, 0]
    selected: list[tuple] = []
    for name in names:
        if name in ("go.mod", "go.sum") or _GO_NAME.fullmatch(name):
            row = (name, *_file_digest(project_fd, name))
            _budget_add(row, budget)
            selected.append(row)
        elif name in ("cmd", "internal", "pkg"):
            selected.extend(_walk_code_dir(
                project_fd, name, prefix=name, kind="go", depth=1,
                budget=budget, directories=directories,
            ))
        elif name == "bin":
            # Go build -o bin/app must start with a fresh private output dir.
            _inspect_empty_dir(
                project_fd, name, path=name, directories=directories)
        else:
            # Do not silently omit extra Go packages, go.work, go:embed data,
            # tool hooks, hidden module/replace sources or output shadows.
            raise D4FixtureDenied("unlisted Go module or build input")
    _qualify_go_module_snapshot(
        project_fd, next(row for row in selected if row[0] == "go.mod"))
    _inventory_end(project_fd, identity, names)
    if "cmd/app/main.go" not in {row[0] for row in selected}:
        raise D4FixtureDenied("fixed Go app entrypoint is missing")
    return tuple(sorted(selected, key=lambda row: row[0]))


def check_d4_r003_fixture(ctx: "WorkspaceContext",
                         plan: LbeWorkPlan) -> D4FixtureCandidate:
    """Inspect a fixed candidate selected by the real WorkspaceService.

    This is called only from trusted internal source and returns NO
    permission to run. It never receives a client-supplied approval token.
    The full loaded-source/runner/credential/resource Gate B remains absent.
    """
    from .workspaces import WorkspaceContext

    if type(ctx) is not WorkspaceContext or type(plan) is not LbeWorkPlan:
        raise D4FixtureDenied("trusted WorkspaceContext and plan required")
    try:
        LbeWorker._check_plan(plan)
    except LbeWorkerError:
        raise D4FixtureDenied("invalid selected product plan") from None
    if (plan.workspace != ctx.name or not ctx.settings.exec_enabled
            or plan.timeout_seconds > 120 or plan.runner_project != plan.cwd
            or plan.cwd not in ctx.settings.exec_paths):
        raise D4FixtureDenied("selected fixture scope or timeout is invalid")
    key = (plan.cwd, plan.runner, plan.requested_argv, plan.effective_argv)
    if key not in _MATRIX:
        raise D4FixtureDenied("command is not an exact D4 product fixture")
    expected_go_output = ("go-project/bin/app" if
                          plan.requested_argv == (
                              "go", "build", "-o", "bin/app", "./cmd/app")
                          else None)
    if plan.planned_go_output != expected_go_output:
        raise D4FixtureDenied("Go output does not match fixture scope")
    if plan.cwd == "py-pipenv" and plan.planned_pipfile_sha256 is None:
        raise D4FixtureDenied("missing selected Pipenv input")
    if (plan.cwd != "py-pipenv"
            and plan.planned_pipfile_sha256 is not None):
        raise D4FixtureDenied("unexpected Pipenv selection")

    # Repeat a nofollow walk from the actual currently pinned Workspace FD,
    # not from an untrusted cwd string or stat(path). No third-party import,
    # project command, network or filesystem write occurs here.
    root_fd = os.dup(ctx.gateway._root_fd)
    try:
        _require_controlled(root_fd, directory=True)
        project_fd = _open_dir(root_fd, plan.cwd)
        try:
            directories: list[tuple[str, tuple[int, ...]]] = []
            if plan.cwd == "py-direct":
                selected = _python_selected_sources(project_fd, directories)
            elif plan.cwd == "py-pipenv":
                selected = _pipenv_selected_sources(project_fd, directories)
            else:
                selected = _go_selected_sources(project_fd, directories)
        finally:
            os.close(project_fd)
    except (OSError, OverflowError, ValueError) as exc:
        raise D4FixtureDenied("first-party D4 source identity unavailable") from None
    finally:
        os.close(root_fd)
    # This is a trusted internal source inventory, not the public file API.
    # However, explicit Workspace exclusions and disallowed path names still
    # apply to every selected first-party source. Use is_file=False because
    # go.mod and Pipfile.lock are valid internal fixture inputs even if not
    # exposed by the public text-file extension policy. The fixed private
    # .venv binary/interpreter tree is deliberately inspected with nofollow
    # FDs despite being protected from public File API browsing.
    for source_name, _digest, _identity in selected:
        if source_name.startswith(".venv/"):
            continue
        parts = (plan.cwd, *source_name.split("/"))
        try:
            allowed = ctx.gateway._allowed(parts, is_file=False)
        except Exception:
            raise D4FixtureDenied("source Workspace path policy unavailable") from None
        if allowed is not True:
            raise D4FixtureDenied("selected fixture source is excluded")
    return D4FixtureCandidate(
        plan=plan,
        source_sha256=tuple((plan.cwd + "/" + name, digest)
                            for name, digest, _identity in selected),
        source_identity=tuple((plan.cwd + "/" + name, identity)
                              for name, _digest, identity in selected),
        directory_identity=tuple(sorted(
            ((plan.cwd + ("/" + name if name else ""), identity)
             for name, identity in directories),
            key=lambda entry: entry[0],
        )),
    )
