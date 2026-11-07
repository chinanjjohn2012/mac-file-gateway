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
_MAX_SRC_ENTRIES = 128
_PY_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\.py\Z")

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
    __slots__ = ("_candidate", "_ctx", "_pid", "_lock", "_consumed")

    def __init__(self, candidate: D4FixtureCandidate,
                 ctx: "WorkspaceContext") -> None:
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
                or len(candidate.source_sha256) != len(candidate.source_identity)):
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
        self._candidate = candidate
        self._ctx = ctx
        self._pid = os.getpid()
        self._lock = threading.Lock()
        self._consumed = False

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
                    or current.source_identity != self._candidate.source_identity):
                raise D4FixtureDenied("selected first-party source changed before launch")
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


def _file_digest(parent_fd: int, name: str) -> tuple[str, tuple[int, ...]]:
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
                 | os.O_NONBLOCK, dir_fd=parent_fd)
    try:
        metadata = _require_controlled(fd, directory=False)
        if not 0 < metadata.st_size <= _MAX_SOURCE_BYTES:
            raise D4FixtureDenied("fixture input exceeds source-size bound")
        digest = hashlib.sha256()
        read_bytes = 0
        while True:
            data = os.read(fd, min(65536, _MAX_SOURCE_BYTES + 1 - read_bytes))
            if not data:
                break
            read_bytes += len(data)
            if read_bytes > _MAX_SOURCE_BYTES:
                raise D4FixtureDenied("fixture input changed or grew beyond bound")
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


def _python_selected_sources(project_fd: int) -> tuple[tuple[str, str, tuple[int, ...]], ...]:
    src_fd = _open_dir(project_fd, "src")
    try:
        names = os.listdir(src_fd)
        if not names or len(names) > _MAX_SRC_ENTRIES:
            raise D4FixtureDenied("first-party Python fixture inventory invalid")
        selected: list[tuple[str, str]] = []
        for name in sorted(names):
            if name == "__pycache__":
                cache_fd = _open_dir(src_fd, name)
                try:
                    # A fresh fixture must not import pre-existing bytecode.
                    if os.listdir(cache_fd):
                        raise D4FixtureDenied("unqualified cached Python bytecode")
                finally:
                    os.close(cache_fd)
            elif _PY_NAME.fullmatch(name):
                selected.append(("src/" + name, *_file_digest(src_fd, name)))
            else:
                # No unreviewed subdirectories, symlink traversal, .pth, or
                # generated import inputs in this fixed compileall fixture.
                raise D4FixtureDenied("unlisted Python fixture source")
        if not selected:
            raise D4FixtureDenied("no first-party Python sources selected")
        return tuple(selected)
    finally:
        os.close(src_fd)


def _pipenv_selected_sources(project_fd: int) -> tuple[tuple[str, str, tuple[int, ...]], ...]:
    selected = [
        ("Pipfile", *_file_digest(project_fd, "Pipfile")),
        ("Pipfile.lock", *_file_digest(project_fd, "Pipfile.lock")),
    ]
    venv_fd = _open_dir(project_fd, ".venv")
    try:
        selected.append((".venv/pyvenv.cfg", *_file_digest(venv_fd, "pyvenv.cfg")))
        bin_fd = _open_dir(venv_fd, "bin")
        try:
            selected.append((".venv/bin/python", *_file_digest(bin_fd, "python")))
        finally:
            os.close(bin_fd)
    finally:
        os.close(venv_fd)
    return tuple(selected)


def _go_selected_sources(project_fd: int) -> tuple[tuple[str, str, tuple[int, ...]], ...]:
    selected = [("go.mod", *_file_digest(project_fd, "go.mod"))]
    cmd_fd = _open_dir(project_fd, "cmd")
    try:
        app_fd = _open_dir(cmd_fd, "app")
        try:
            selected.append(("cmd/app/main.go", *_file_digest(app_fd, "main.go")))
        finally:
            os.close(app_fd)
    finally:
        os.close(cmd_fd)
    # Actual go build -o validation separately requires a pre-existing
    # nofollow bin parent; this also refuses a linked output directory.
    bin_fd = _open_dir(project_fd, "bin")
    os.close(bin_fd)
    return tuple(selected)


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
            if plan.cwd == "py-direct":
                selected = _python_selected_sources(project_fd)
            elif plan.cwd == "py-pipenv":
                selected = _pipenv_selected_sources(project_fd)
            else:
                selected = _go_selected_sources(project_fd)
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
    )
