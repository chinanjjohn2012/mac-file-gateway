"""Git CLI V1 synchronous internal runner.

No Web/MCP/REST adapter calls this until the later, reviewed service phases.
Every Popen goes through a durable DISCOVERING or RUNNING admission record.
Never use the ordinary run_command or arbitrary shell execution interface.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
import selectors
import shutil
import signal
import stat
import subprocess
import time
from typing import Any, Callable

from .core import GatewayError
from .git_policy import compile_git_command, preview_git
from .git_repository import (
    GitRepositoryCoordinator, RepositoryIdentity, check_git_paths,
)
from .git_state import GitStateStore

_GIT_PATH = "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin"
_REV_PARSE = (
    "rev-parse", "--path-format=absolute", "--show-toplevel",
    "--absolute-git-dir", "--git-common-dir",
)
_OUTPUT_LIMIT = 131072
_CLEANUP_RESERVE = 5.0


@dataclass(frozen=True)
class GitProcessResult:
    exit_code: int | None
    stdout: str
    stderr: str
    timed_out: bool
    output_truncated: bool
    cleanup_complete: bool


def git_environment(source: dict[str, str] | None = None) -> dict[str, str]:
    """Do not inherit caller-injected GIT_* or Gateway/private credentials."""
    values = os.environ if source is None else source
    env = {"PATH": _GIT_PATH, "GIT_TERMINAL_PROMPT": "0"}
    keep = {"HOME", "USER", "LOGNAME", "TMPDIR", "LANG", "SSH_AUTH_SOCK"}
    for name in keep:
        value = values.get(name)
        if isinstance(value, str) and "\x00" not in value and len(value) <= 4096:
            env[name] = value
    for name, value in values.items():
        if (name.startswith("LC_") and name not in env and isinstance(value, str)
                and "\x00" not in value and len(value) <= 200):
            env[name] = value
    return env


def trusted_git_binary() -> str:
    binary = shutil.which("git", path=_GIT_PATH)
    if binary is None:
        raise GatewayError("git_unavailable", "A trusted Git executable is unavailable.")
    real = os.path.realpath(binary)
    try:
        st = os.stat(real)
    except OSError:
        raise GatewayError("git_unavailable", "Trusted Git executable is missing.") from None
    if not os.path.isabs(real) or not stat.S_ISREG(st.st_mode) or not os.access(real, os.X_OK):
        raise GatewayError("git_unavailable", "Trusted Git executable is invalid.")
    return real


def _signal_group(pid: int, sig: int) -> None:
    try:
        os.killpg(pid, sig)
    except ProcessLookupError:
        pass  # Already reaped/exited.
    except PermissionError:
        pass  # Cleanup is not confirmed; subsequent admission will fail closed.


class GitProcessRunner:
    """Bounded drain/reap with cleanup evidence and no subprocess retries."""

    def __init__(self, *, binary: str | None = None,
                 environment: dict[str, str] | None = None) -> None:
        self.binary = trusted_git_binary() if binary is None else binary
        if not os.path.isabs(self.binary):
            raise GatewayError("git_unavailable", "Git executable must be absolute.")
        self.environment = git_environment() if environment is None else git_environment(environment)

    def run(self, cwd: str, argv: tuple[str, ...] | list[str], *,
            spawn_admitted: Callable[[Callable[[], subprocess.Popen[bytes]]],
                                     subprocess.Popen[bytes]],
            execute_until: float, deadline: float) -> GitProcessResult:
        """Must be called only inside T05's discover/repo intent protocol."""
        if time.monotonic() >= min(execute_until, deadline - _CLEANUP_RESERVE):
            raise GatewayError("git_timeout", "Not enough time to start Git safely.")
        def spawn() -> subprocess.Popen[bytes]:
            return subprocess.Popen(
                [self.binary, *argv], cwd=cwd, env=self.environment,
                shell=False, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, start_new_session=True, close_fds=True,
            )
        child = spawn_admitted(spawn)
        streams: dict[int, bytearray] = {1: bytearray(), 2: bytearray()}
        truncated = False
        timed_out = False
        clean = False
        selector = selectors.DefaultSelector()
        try:
            for num, pipe in ((1, child.stdout), (2, child.stderr)):
                if pipe is None:
                    raise OSError("Git output pipe unavailable.")
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ, num)

            def group_gone() -> bool:
                # A hook/filter child can close both pipes while staying in
                # Git's process group. EOF + reaped leader is NOT enough.
                try:
                    os.killpg(child.pid, 0)
                except ProcessLookupError:
                    return True
                except PermissionError:
                    return False
                return False

            def pump(until: float) -> bool:
                nonlocal truncated
                while True:
                    if (not selector.get_map() and child.poll() is not None
                            and group_gone()):
                        return True
                    remaining = until - time.monotonic()
                    if remaining <= 0:
                        return False
                    for key, _mask in selector.select(min(0.1, remaining)):
                        pipe = key.fileobj
                        try:
                            data = os.read(pipe.fileno(), 65536)
                        except BlockingIOError:
                            continue
                        if not data:
                            selector.unregister(pipe)
                            pipe.close()
                            continue
                        buffer = streams[key.data]
                        budget = max(0, _OUTPUT_LIMIT - sum(len(v) for v in streams.values()))
                        if len(data) > budget:
                            truncated = True
                        if budget:
                            buffer.extend(data[:budget])

            finish = min(execute_until, deadline - _CLEANUP_RESERVE)
            clean = pump(finish)
            if not clean:
                timed_out = True
                _signal_group(child.pid, signal.SIGTERM)
                clean = pump(min(deadline, time.monotonic() + 2.0))
                if not clean:
                    _signal_group(child.pid, signal.SIGKILL)
                    clean = pump(deadline)
            if clean:
                child.wait(timeout=max(0.0, deadline - time.monotonic()))
            else:
                # A process with open inherited pipes can survive the whole
                # deadline even when the original Git leader has exited.
                if child.poll() is None:
                    _signal_group(child.pid, signal.SIGKILL)
                    try:
                        child.wait(timeout=max(0.0, deadline - time.monotonic()))
                    except subprocess.TimeoutExpired:
                        pass
                clean = (child.poll() is not None and not selector.get_map()
                         and group_gone())
        except BaseException:
            _signal_group(child.pid, signal.SIGTERM)
            _signal_group(child.pid, signal.SIGKILL)
            try:
                child.wait(timeout=max(0.0, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                pass
            clean = False  # Unexpected drain failure must quarantine.
        finally:
            selector.close()
            for pipe in (child.stdout, child.stderr):
                if pipe is not None and not pipe.closed:
                    pipe.close()
        return GitProcessResult(
            child.poll(),
            streams[1].decode("utf-8", "replace"),
            streams[2].decode("utf-8", "replace"),
            timed_out, truncated, clean,
        )


class GitCLIExecutor:
    """Internal engine; Workspace/Legacy authorization is added in batch C."""

    def __init__(self, state: GitStateStore, *,
                 coordinator: GitRepositoryCoordinator | None = None,
                 runner: GitProcessRunner | None = None) -> None:
        self.state = state
        self.coordinator = coordinator or GitRepositoryCoordinator()
        self.runner = runner or GitProcessRunner()

    def _run_discovery(self, call_id: str, workspace: str, cwd: str,
                       deadline: float) -> RepositoryIdentity:
        until = min(deadline - _CLEANUP_RESERVE, time.monotonic() + 5.0)
        launched = False
        def spawn(callback: Callable[[], subprocess.Popen[bytes]]) -> subprocess.Popen[bytes]:
            nonlocal launched
            child = self.state.start_discovery(call_id, workspace, callback)
            launched = True
            return child
        result: GitProcessResult | None = None
        try:
            result = self.runner.run(cwd, _REV_PARSE, spawn_admitted=spawn,
                                     execute_until=until, deadline=deadline)
        finally:
            if launched:
                self.state.finish_discovery(
                    call_id, clean=result is not None and result.cleanup_complete,
                )
        if result is None:
            raise GatewayError("git_cleanup_incomplete", "Git discovery is incomplete.")
        if result.timed_out:
            raise GatewayError("git_timeout", "Git repository discovery timed out.")
        if result.exit_code != 0 or result.output_truncated:
            raise GatewayError("git_not_repository", "No usable Git repository was discovered.")
        return RepositoryIdentity.from_rev_parse(result.stdout)

    def _repo_command(self, key: tuple[int, int], call_id: str, cwd: str,
                      argv: tuple[str, ...] | list[str], deadline: float,
                      *, maximum_seconds: float | None = None) -> GitProcessResult:
        until = deadline - _CLEANUP_RESERVE
        if maximum_seconds is not None:
            until = min(until, time.monotonic() + maximum_seconds)
        admitted = lambda spawn: self.state.start_repo_process(key, call_id, spawn)
        return self.runner.run(cwd, argv, spawn_admitted=admitted,
                               execute_until=until, deadline=deadline)

    def _checked_git(self, key: tuple[int, int], call_id: str, cwd: str,
                     argv: tuple[str, ...] | list[str], deadline: float,
                     *, allow_failure: bool = False) -> GitProcessResult:
        result = self._repo_command(key, call_id, cwd, argv, deadline, maximum_seconds=5)
        if not result.cleanup_complete:
            raise _CleanupIncomplete()
        if result.timed_out:
            raise GatewayError("git_timeout", "Git repository check timed out.")
        if result.output_truncated or (not allow_failure and result.exit_code != 0):
            raise GatewayError("git_repository_invalid", "Git repository check failed.")
        return result

    def _check_prerequisites(self, key: tuple[int, int], call_id: str, cwd: str,
                             command: str, values: dict[str, Any],
                             deadline: float) -> None:
        if command in {"fetch", "pull", "push"}:
            remote = values["remote"]
            r = self._checked_git(key, call_id, cwd, ["remote"], deadline)
            if remote not in r.stdout.splitlines():
                raise GatewayError("git_remote_unknown", "Requested Git remote is not configured.")
        if command == "switch":
            ref = "refs/heads/" + values["name"]
            found = self._checked_git(key, call_id, cwd,
                                      ["show-ref", "--verify", "--quiet", ref],
                                      deadline, allow_failure=True)
            if values["create"] and found.exit_code == 0:
                raise GatewayError("git_branch_exists", "Local Git branch already exists.")
            if not values["create"] and found.exit_code != 0:
                raise GatewayError("git_branch_unknown", "Local Git branch does not exist.")
            if values["create"]:
                self._checked_git(key, call_id, cwd,
                                  ["rev-parse", "--verify", "HEAD"], deadline)
        if command == "push":
            ref = "refs/heads/" + values["branch"]
            present = self._checked_git(key, call_id, cwd,
                                        ["show-ref", "--verify", "--quiet", ref],
                                        deadline, allow_failure=True)
            if present.exit_code != 0:
                raise GatewayError("git_branch_unknown", "Local Git branch does not exist.")
            if values["force_with_lease"]:
                obj = self._checked_git(key, call_id, cwd,
                                        ["rev-parse", "--show-object-format"], deadline)
                expected = {"sha1": 40, "sha256": 64}.get(obj.stdout.strip())
                if expected is None or len(values["expected_remote_oid"]) != expected:
                    raise GatewayError("git_option_invalid", "Git object ID has wrong format.")

    def run(self, *, workspace: str, root_fd: int, root_path: str,
            cwd: str = ".", command: str, options: dict[str, Any] | None = None,
            paths: list[str] | None = None, timeout_seconds: int = 120,
            dry_run: bool = True) -> dict[str, Any]:
        """Caller must already hold its actual synchronous Workspace worker lease.

        This is NOT an authorization source: batch C applies both global Git
        enable and Workspace command allowlist in that worker before calling.
        """
        opts = {} if options is None else options
        path_args = [] if paths is None else paths
        preview = preview_git(command, cwd=cwd, options=opts, paths=path_args,
                              timeout_seconds=timeout_seconds, workspace=workspace)
        if type(dry_run) is not bool:
            raise GatewayError("git_option_invalid", "dry_run must be boolean.")
        if dry_run:
            return preview  # Zero Git children, including rev-parse.
        compiled = compile_git_command(command, options=opts, paths=path_args)
        started_at = time.monotonic()
        deadline = started_at + timeout_seconds
        physical_cwd = check_git_paths(root_fd, root_path, cwd, compiled.paths)
        call_id = self.state.new_call_id()
        identity = self._run_discovery(call_id, workspace, physical_cwd, deadline)
        with self.coordinator.hold(identity.common_key, deadline):
            key = identity.common_key
            self.state.begin_repo(key, call_id)
            complete = True
            result: GitProcessResult | None = None
            try:
                # This second rev-parse is itself protected by RUNNING.
                checked = self._checked_git(key, call_id, physical_cwd,
                                            _REV_PARSE, deadline)
                current = RepositoryIdentity.from_rev_parse(checked.stdout)
                if current != identity:
                    raise GatewayError("git_repository_changed",
                                       "Git repository identity changed during admission.")
                self._check_prerequisites(key, call_id, physical_cwd, command,
                                          dict(compiled.options), deadline)
                result = self._repo_command(key, call_id, physical_cwd,
                                            compiled.argv, deadline)
                if not result.cleanup_complete:
                    complete = False
            except _CleanupIncomplete:
                complete = False
            except BaseException:
                # An interrupted runner may still have an uncontrolled child.
                # Only ordinary preflight GatewayError paths are known clean.
                raise
            finally:
                self.state.finish_repo(key, call_id, clean=complete)
            if not complete or result is None:
                raise GatewayError("git_cleanup_incomplete", "Git process cleanup was not confirmed.")
            return {
                **preview, "dry_run": False, "repository_checked": True,
                "execute_started": True, "remote_checked": command in {"fetch", "pull", "push"},
                "branch_checked": command in {"switch", "push"},
                "exit_code": result.exit_code, "stdout": result.stdout,
                "stderr": result.stderr, "timed_out": result.timed_out,
                "output_truncated": result.output_truncated,
                "cleanup_status": "complete",
            }


class _CleanupIncomplete(Exception):
    """Private signal: a Git child was not fully reaped/drained."""
