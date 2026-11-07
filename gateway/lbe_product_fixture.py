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
    profile_id: str = PROFILE_ID
    profile_git_blob: str = PROFILE_GIT_BLOB
    status: str = _STATUS
    native_launch_allowed: bool = False
    actual_loaded_sources_proven: bool = False
    runner_qualified: bool = False
    resource_enforcement_proven: bool = False
    owner_approval_attested: bool = False



class D4OneUseAttemptMarker:
    """Atomic deny-replay primitive for a checked first-party source candidate.

    NOT a grant/owner consent or verification of actual loaded source,
    macOS runner, credentials or resource enforcement. Public Direct/REST/MCP
    cannot supply this local object, and the current service never mints one
    as execution authority. One use is burned before possible reservation/
    Popen, including invalid plan, cancellation and busy. Does not survive
    Gateway crash or remove the operator's duplicate-effects risk.
    """
    __slots__ = ("_candidate", "_pid", "_lock", "_consumed")

    def __init__(self, candidate: D4FixtureCandidate) -> None:
        if type(candidate) is not D4FixtureCandidate:
            raise D4FixtureDenied("only checked candidate is eligible")
        self._candidate = candidate
        self._pid = os.getpid()
        self._lock = threading.Lock()
        self._consumed = False

    def consume_for(self, plan: LbeWorkPlan) -> None:
        """Burn before any possible native spawn, even on mismatched input."""
        with self._lock:
            if self._consumed:
                raise D4FixtureDenied("product attempt already consumed")
            self._consumed = True
            if os.getpid() != self._pid or plan is not self._candidate.plan:
                raise D4FixtureDenied("product attempt plan identity changed")


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


def _file_digest(parent_fd: int, name: str) -> str:
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
                 | os.O_NONBLOCK, dir_fd=parent_fd)
    try:
        metadata = _require_controlled(fd, directory=False)
        if not 0 <= metadata.st_size <= _MAX_SOURCE_BYTES:
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
        if ((metadata.st_dev, metadata.st_ino, metadata.st_size,
             metadata.st_mtime_ns, metadata.st_ctime_ns)
                != (after.st_dev, after.st_ino, after.st_size,
                    after.st_mtime_ns, after.st_ctime_ns)):
            raise D4FixtureDenied("fixture source changed during read")
        return digest.hexdigest()
    finally:
        os.close(fd)


def _python_selected_sources(project_fd: int) -> tuple[tuple[str, str], ...]:
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
                selected.append(("src/" + name, _file_digest(src_fd, name)))
            else:
                # No unreviewed subdirectories, symlink traversal, .pth, or
                # generated import inputs in this fixed compileall fixture.
                raise D4FixtureDenied("unlisted Python fixture source")
        if not selected:
            raise D4FixtureDenied("no first-party Python sources selected")
        return tuple(selected)
    finally:
        os.close(src_fd)


def _pipenv_selected_sources(project_fd: int) -> tuple[tuple[str, str], ...]:
    selected = [
        ("Pipfile", _file_digest(project_fd, "Pipfile")),
        ("Pipfile.lock", _file_digest(project_fd, "Pipfile.lock")),
    ]
    venv_fd = _open_dir(project_fd, ".venv")
    try:
        selected.append((".venv/pyvenv.cfg", _file_digest(venv_fd, "pyvenv.cfg")))
        bin_fd = _open_dir(venv_fd, "bin")
        try:
            selected.append((".venv/bin/python", _file_digest(bin_fd, "python")))
        finally:
            os.close(bin_fd)
    finally:
        os.close(venv_fd)
    return tuple(selected)


def _go_selected_sources(project_fd: int) -> tuple[tuple[str, str], ...]:
    selected = [("go.mod", _file_digest(project_fd, "go.mod"))]
    cmd_fd = _open_dir(project_fd, "cmd")
    try:
        app_fd = _open_dir(cmd_fd, "app")
        try:
            selected.append(("cmd/app/main.go", _file_digest(app_fd, "main.go")))
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
    return D4FixtureCandidate(
        plan=plan,
        source_sha256=tuple((plan.cwd + "/" + name, digest)
                            for name, digest in selected),
    )
