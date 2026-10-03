"""Controlled project command execution with no shell parsing.

This is intentionally not a general-purpose terminal. Enabling it permits project code
execution, so it must remain opt-in and narrowly scoped.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import threading
from typing import Any, TYPE_CHECKING

from .core import GatewayError, _parts, _redact

if TYPE_CHECKING:
    from .core import Gateway

_ALLOWED_COMMANDS = (
    "pytest",
    "python -m pytest",
    "python -m compileall",
    "python <relative-script.py>",
    "go test",
    "go vet",
)
_PYTHON = re.compile(r"^python(?:3(?:\.[0-9]+)?)?$")
_SAFE_ENV_KEYS = ("PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "LC_CTYPE")
_MAX_ARGV = 64
_MAX_ARG_CHARS = 1_024
_MAX_ARGV_CHARS = 8_192
_MAX_OUTPUT_CHARS = 48_000


def _parse_scope(value: str) -> tuple[str, ...]:
    parts = _parts(value)
    return parts


def _canonical(parts: tuple[str, ...]) -> str:
    return "/".join(parts) or "."


def _inside(parts: tuple[str, ...], scope: tuple[str, ...]) -> bool:
    return len(parts) >= len(scope) and parts[:len(scope)] == scope


def _clean_argv(argv: list[str]) -> list[str]:
    if type(argv) is not list or not 1 <= len(argv) <= _MAX_ARGV:
        raise GatewayError("invalid_argument", f"argv must be a list of 1-{_MAX_ARGV} strings.")
    total = 0
    result: list[str] = []
    for item in argv:
        if type(item) is not str or not item or len(item) > _MAX_ARG_CHARS:
            raise GatewayError("invalid_argument", "Each argv item must be a non-empty bounded string.")
        if "\x00" in item or any(ord(ch) < 32 and ch not in "\t" for ch in item):
            raise GatewayError("invalid_argument", "argv contains a control character.")
        total += len(item)
        result.append(item)
    if total > _MAX_ARGV_CHARS:
        raise GatewayError("invalid_argument", "argv is too large.")
    return result


def _reject_external_path_args(argv: list[str]) -> None:
    for arg in argv[1:]:
        if arg.startswith(("/", "~")) or "\\" in arg or "=/" in arg or "=~" in arg:
            raise GatewayError("command_not_allowed", "Command arguments must not explicitly reference paths outside the project.")
        if any(part == ".." for part in arg.split("/")):
            raise GatewayError("command_not_allowed", "Parent traversal in command arguments is not allowed.")


def _relative_script(argv: list[str]) -> str | None:
    if not _PYTHON.fullmatch(argv[0]) or len(argv) < 2:
        return None
    if argv[1] == "-m":
        return None
    if argv[1].startswith("-"):
        raise GatewayError("command_not_allowed", "Python flags such as -c and stdin execution are not allowed.")
    script = argv[1]
    parts = _parts(script)
    if not parts or not script.casefold().endswith(".py"):
        raise GatewayError("command_not_allowed", "Direct Python execution requires a project-relative .py script.")
    return "/".join(parts)


def _validate_command(argv: list[str]) -> str | None:
    _reject_external_path_args(argv)
    program = argv[0]
    if program == "pytest":
        if any(arg in {"--pdb", "--trace"} for arg in argv[1:]):
            raise GatewayError("command_not_allowed", "Interactive pytest modes are not allowed.")
        return None
    if _PYTHON.fullmatch(program):
        if len(argv) >= 3 and argv[1:3] == ["-m", "pytest"]:
            if any(arg in {"--pdb", "--trace"} for arg in argv[3:]):
                raise GatewayError("command_not_allowed", "Interactive pytest modes are not allowed.")
            return None
        if len(argv) >= 3 and argv[1:3] == ["-m", "compileall"]:
            return None
        script = _relative_script(argv)
        if script is not None:
            return script
        raise GatewayError("command_not_allowed", "Allowed Python forms are -m pytest, -m compileall, or a relative .py script.")
    if program == "go" and len(argv) >= 2 and argv[1] in {"test", "vet"}:
        denied = ("-exec", "-toolexec", "-vettool")
        if any(arg == flag or arg.startswith(flag + "=") for arg in argv[2:] for flag in denied):
            raise GatewayError("command_not_allowed", "External Go tool hooks are not allowed.")
        return None
    raise GatewayError("command_not_allowed", "Command is outside the configured execution allowlist.")


def _drain(stream: Any, limit: int, result: dict[str, Any], key: str) -> None:
    chunks: list[bytes] = []
    kept = 0
    truncated = False
    while True:
        chunk = stream.read(8_192)
        if not chunk:
            break
        remaining = limit - kept
        if remaining > 0:
            part = chunk[:remaining]
            chunks.append(part)
            kept += len(part)
        if len(chunk) > max(remaining, 0):
            truncated = True
    result[key] = b"".join(chunks)
    result[key + "_truncated"] = truncated


def _bounded_text(data: bytes) -> tuple[str, bool]:
    text = data.decode("utf-8", errors="replace")
    lines, _ = _redact(text)
    redacted = "\n".join(lines)
    if len(redacted) <= _MAX_OUTPUT_CHARS:
        return redacted, False
    marker = "\n[...output truncated...]"
    keep = max(0, _MAX_OUTPUT_CHARS - len(marker))
    return redacted[:keep] + marker, True


class CommandRunner:
    def __init__(self, gateway: "Gateway", *, enabled: bool = False,
                 exec_paths: tuple[str, ...] = (), exec_runners: tuple[str, ...] = ()):
        if type(enabled) is not bool:
            raise GatewayError("invalid_argument", "allow_exec must be a boolean.")
        self.gateway = gateway
        self.enabled = enabled
        if (exec_paths or exec_runners) and not enabled:
            raise GatewayError("invalid_argument", "Execution scope/runner configuration requires allow_exec.")
        if enabled and not exec_paths:
            raise GatewayError("invalid_argument", "allow_exec requires at least one exec_path.")
        self.scopes = tuple(_parse_scope(path) for path in exec_paths)
        for scope in self.scopes:
            if not gateway._allowed(scope, is_file=False):
                raise GatewayError("blocked_path", "An execution scope is blocked by the project policy.")
        runners: dict[tuple[str, ...], str] = {}
        for item in exec_runners:
            if type(item) is not str or "=" not in item:
                raise GatewayError("invalid_argument", "exec_runner must use PATH=direct or PATH=pipenv.")
            path, runner = item.rsplit("=", 1)
            parts = _parse_scope(path)
            if runner not in {"direct", "pipenv"}:
                raise GatewayError("invalid_argument", "exec_runner must be direct or pipenv.")
            if not any(_inside(parts, scope) for scope in self.scopes):
                raise GatewayError("exec_scope", "Configured runner path must be inside an execution scope.")
            runners[parts] = runner
        self.runners = runners

    def policy(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "shell": False,
            "paths": [_canonical(scope) for scope in self.scopes],
            "configured_runners": {_canonical(path): runner for path, runner in self.runners.items()},
            "runner_fallback": "nearest Pipfile => pipenv; otherwise direct",
            "allowed_commands": list(_ALLOWED_COMMANDS),
            "timeout_seconds_default": 60,
            "timeout_seconds_max": 300,
            "output_limit_chars": _MAX_OUTPUT_CHARS,
            "stdin": "disabled",
            "environment": "minimal allowlist; common secret variables and VIRTUAL_ENV are not inherited",
        }

    def _cwd(self, cwd: str) -> tuple[tuple[str, ...], Path]:
        parts = _parts(cwd)
        if not any(_inside(parts, scope) for scope in self.scopes):
            raise GatewayError("exec_scope", "Working directory is outside the configured execution scope.")
        if not self.gateway._allowed(parts, is_file=False):
            raise GatewayError("blocked_path", "Working directory is blocked by project policy.")
        # Pin/open every component without following symlinks before deriving the cwd path.
        with self.gateway._directory(parts):
            pass
        path = self.gateway._root_path.joinpath(*parts)
        return parts, path

    def _configured_runner(self, cwd_parts: tuple[str, ...]) -> tuple[str | None, tuple[str, ...] | None]:
        matches = [(path, runner) for path, runner in self.runners.items() if _inside(cwd_parts, path)]
        if not matches:
            return None, None
        path, runner = max(matches, key=lambda pair: len(pair[0]))
        return runner, path

    def _runner(self, cwd_parts: tuple[str, ...], cwd_path: Path) -> tuple[str, Path | None, str]:
        configured, configured_path = self._configured_runner(cwd_parts)
        if configured is not None:
            if configured == "direct":
                return "direct", None, _canonical(configured_path or ())
            project = self.gateway._root_path.joinpath(*(configured_path or ()))
            pipfile = project / "Pipfile"
            try:
                metadata = pipfile.stat(follow_symlinks=False)
            except OSError:
                raise GatewayError("runner_unavailable", "Configured pipenv runner requires a regular Pipfile.") from None
            if not stat.S_ISREG(metadata.st_mode):
                raise GatewayError("runner_unavailable", "Configured Pipfile is not a regular file.")
            return "pipenv", pipfile, _canonical(configured_path or ())

        containing_scope = max((scope for scope in self.scopes if _inside(cwd_parts, scope)), key=len)
        current_parts = cwd_parts
        while True:
            candidate = self.gateway._root_path.joinpath(*current_parts, "Pipfile")
            try:
                metadata = candidate.stat(follow_symlinks=False)
                if stat.S_ISREG(metadata.st_mode):
                    return "pipenv", candidate, _canonical(current_parts)
            except FileNotFoundError:
                pass
            except OSError:
                pass
            if current_parts == containing_scope:
                break
            current_parts = current_parts[:-1]
        return "direct", None, _canonical(containing_scope)

    def _verify_script(self, cwd_parts: tuple[str, ...], script: str | None) -> None:
        if script is None:
            return
        script_parts = (*cwd_parts, *_parts(script))
        if not self.gateway._allowed(script_parts, is_file=True):
            raise GatewayError("blocked_path", "Python script is blocked by the project policy.")
        self.gateway._snapshot(script_parts)

    def run(self, cwd: str, argv: list[str], timeout_seconds: int = 60,
            dry_run: bool = True) -> dict[str, Any]:
        if not self.enabled:
            raise GatewayError("exec_disabled", "Command execution is disabled. Restart locally with --allow-exec.")
        if type(dry_run) is not bool:
            raise GatewayError("invalid_argument", "dry_run must be a boolean.")
        if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 300:
            raise GatewayError("invalid_argument", "timeout_seconds must be an integer from 1 to 300.")
        requested = _clean_argv(argv)
        script = _validate_command(requested)
        cwd_parts, cwd_path = self._cwd(cwd)
        self._verify_script(cwd_parts, script)
        runner, pipfile, runner_project = self._runner(cwd_parts, cwd_path)
        effective = list(requested)
        if runner == "pipenv":
            effective = ["pipenv", "run", *requested]

        result: dict[str, Any] = {
            "cwd": _canonical(cwd_parts),
            "requested_argv": requested,
            "effective_argv": effective,
            "runner": runner,
            "runner_project": runner_project,
            "dry_run": dry_run,
            "executed": False,
            "exit_code": None,
            "timed_out": False,
            "stdout": "",
            "stderr": "",
            "stdout_truncated": False,
            "stderr_truncated": False,
            "output_limit_chars": _MAX_OUTPUT_CHARS,
            "content_trust": "untrusted_command_output",
        }
        if dry_run:
            return result

        env = {key: value for key in _SAFE_ENV_KEYS if (value := os.environ.get(key))}
        env["PATH"] = os.environ.get("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        env["PYTHONUNBUFFERED"] = "1"
        if pipfile is not None:
            env["PIPENV_PIPFILE"] = str(pipfile)
            env["PIPENV_NOSPIN"] = "1"

        try:
            process = subprocess.Popen(
                effective,
                cwd=str(cwd_path),
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
        except FileNotFoundError:
            raise GatewayError("runner_unavailable", "Required executable is not installed or not on PATH.") from None
        except OSError:
            raise GatewayError("exec_failed", "Command could not be started.") from None

        captured: dict[str, Any] = {}
        byte_limit = _MAX_OUTPUT_CHARS * 4
        assert process.stdout is not None and process.stderr is not None
        readers = [
            threading.Thread(target=_drain, args=(process.stdout, byte_limit, captured, "stdout"), daemon=True),
            threading.Thread(target=_drain, args=(process.stderr, byte_limit, captured, "stderr"), daemon=True),
        ]
        for reader in readers:
            reader.start()
        try:
            process.wait(timeout=timeout_seconds)
            exit_code: int | None = process.returncode
            timed_out = False
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except OSError:
                process.kill()
            process.wait()
            exit_code = None
        for reader in readers:
            reader.join(timeout=5)
        stdout = captured.get("stdout", b"")
        stderr = captured.get("stderr", b"")
        stdout_text, text_stdout_truncated = _bounded_text(stdout)
        stderr_text, text_stderr_truncated = _bounded_text(stderr)
        stdout_truncated = bool(captured.get("stdout_truncated")) or text_stdout_truncated
        stderr_truncated = bool(captured.get("stderr_truncated")) or text_stderr_truncated
        result.update(
            executed=True,
            exit_code=exit_code,
            timed_out=timed_out,
            stdout=stdout_text,
            stderr=stderr_text,
            stdout_truncated=stdout_truncated,
            stderr_truncated=stderr_truncated,
        )
        return result
