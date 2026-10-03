"""Bounded executor for audited Local Skill shell scripts."""
from __future__ import annotations

import os
from pathlib import Path
import signal
import stat
import subprocess
import threading
from typing import Any

from gateway.core import Gateway, GatewayError
from .args import SkillArgValidator
from .config import AuditValidator
from .hooks import ExistingHookRunner, build_hook_command
from .registry import SkillRegistry
from .runs import SkillRunStore
from .sql_policy import SqlPolicyGate
from .sanitize import LocalSkillSanitizer

_MAX_OUTPUT_CHARS = 48_000
_BYTE_LIMIT = _MAX_OUTPUT_CHARS * 4


def _drain(stream: Any, result: dict[str, Any], key: str) -> None:
    chunks: list[bytes] = []
    kept = 0
    truncated = False
    while True:
        chunk = stream.read(8192)
        if not chunk:
            break
        remaining = _BYTE_LIMIT - kept
        if remaining > 0:
            part = chunk[:remaining]
            chunks.append(part)
            kept += len(part)
        if len(chunk) > max(remaining, 0):
            truncated = True
    result[key] = b"".join(chunks)
    result[key + "_truncated"] = truncated


class SkillScriptExecutor:
    def __init__(
        self,
        gateway: Gateway,
        validator: AuditValidator,
        registry: SkillRegistry,
        runs: SkillRunStore,
        args: SkillArgValidator,
        sql: SqlPolicyGate,
        hooks: ExistingHookRunner,
        *,
        artifact_root: Path | None = None,
        sanitizer: LocalSkillSanitizer | None = None,
    ):
        self.gateway = gateway
        self.validator = validator
        self.registry = registry
        self.runs = runs
        self.args = args
        self.sql = sql
        self.hooks = hooks
        self.skills_parts = (*validator.root_parts, "skills")
        self.codeagent_path = gateway._root_path.joinpath(*validator.root_parts)
        self.artifact_root = artifact_root or Path.home() / ".local" / "share" / "mac-file-gateway" / "artifacts"
        self.sanitizer = sanitizer or LocalSkillSanitizer(gateway._root_path, self.codeagent_path)

    @staticmethod
    def _ensure_directory(path: Path) -> None:
        if path.exists():
            if path.is_symlink() or not path.is_dir():
                raise GatewayError("skill_execution_failed", "Artifact path is not a safe directory.")
        else:
            path.mkdir(parents=True, mode=0o700)
        try:
            os.chmod(path, 0o700)
        except OSError:
            raise GatewayError("skill_execution_failed", "Artifact directory permissions could not be set.") from None

    def _artifact_dir(self, skill_run_id: str) -> Path:
        self._ensure_directory(self.artifact_root)
        path = self.artifact_root / skill_run_id
        self._ensure_directory(path)
        return path

    def _script_path(self, skill: str, script: str) -> Path:
        parts = (*self.skills_parts, skill, *script.split("/"))
        if not self.gateway._allowed(parts, is_file=True):
            raise GatewayError("skill_script_not_allowed", "Skill script is blocked.")
        snapshot = self.gateway._snapshot(parts)
        if not stat.S_ISREG(snapshot.metadata.st_mode):
            raise GatewayError("skill_script_not_allowed", "Skill script must be a regular file.")
        return self.gateway._root_path.joinpath(*parts)

    def _environment(self) -> dict[str, str]:
        keep = {"HOME", "PATH", "USER", "LANG", "TMPDIR", "SSH_AUTH_SOCK"}
        env = {key: value for key, value in os.environ.items() if key in keep or key.startswith("LC_")}
        env["PATH"] = os.environ.get("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        agent_env = self.validator.policy.compatibility.get("agent_dir_env", "LOCAL_SKILL_AGENT_DIR")
        env[agent_env] = str(self.codeagent_path)
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        env["PYTHONUNBUFFERED"] = "1"
        return env

    def run(
        self,
        skill_run_id: str,
        skill: str,
        script: str,
        argv: list[str],
        timeout_seconds: int = 60,
    ) -> dict[str, Any]:
        if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 300:
            raise GatewayError("skill_arg_not_allowed", "timeout_seconds must be from 1 to 300.")

        run = self.runs.get_active(skill_run_id, self.registry)
        mode = run.access_mode(skill)
        if mode not in {"entry", "execute_allowed_script"}:
            raise GatewayError("skill_script_not_allowed", "This dependency is read-only.")
        if script not in run.scripts_for(skill):
            raise GatewayError("skill_script_not_allowed", "Script is outside the active run allowlist.")
        if not self.validator.validate_skill(skill).available:
            raise GatewayError("skill_audit_stale", "Audited Skill source changed after startup.")

        clean_argv = self.args.validate(skill, script, argv)
        kind = self.registry.get(skill).kind
        if kind == "clickhouse":
            self.sql.validate(skill, clean_argv[0], instance=clean_argv[1])
        elif kind == "mysql":
            self.sql.validate(skill, clean_argv[0])

        script_path = self._script_path(skill, script)
        hook_command = build_hook_command(str(script_path), clean_argv)
        self.hooks.run_all_for_command(hook_command)
        cwd = self._artifact_dir(skill_run_id)

        try:
            process = subprocess.Popen(
                ["bash", str(script_path), *clean_argv],
                cwd=str(cwd),
                env=self._environment(),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
        except OSError:
            raise GatewayError("skill_execution_failed", "Skill script could not be started.") from None

        captured: dict[str, Any] = {}
        assert process.stdout is not None and process.stderr is not None
        readers = [
            threading.Thread(target=_drain, args=(process.stdout, captured, "stdout"), daemon=True),
            threading.Thread(target=_drain, args=(process.stderr, captured, "stderr"), daemon=True),
        ]
        for reader in readers:
            reader.start()

        timed_out = False
        try:
            process.wait(timeout=timeout_seconds)
            exit_code: int | None = process.returncode
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

        stdout, _stdout_redacted, stdout_text_truncated = self.sanitizer.bytes(captured.get("stdout", b""), limit=_MAX_OUTPUT_CHARS)
        stderr, _stderr_redacted, stderr_text_truncated = self.sanitizer.bytes(captured.get("stderr", b""), limit=_MAX_OUTPUT_CHARS)
        return {
            "skill": skill,
            "script": script,
            "argv": clean_argv,
            "executed": True,
            "exit_code": exit_code,
            "timed_out": timed_out,
            "stdout": stdout,
            "stderr": stderr,
            "stdout_truncated": bool(captured.get("stdout_truncated")) or stdout_text_truncated,
            "stderr_truncated": bool(captured.get("stderr_truncated")) or stderr_text_truncated,
            "output_limit_chars": _MAX_OUTPUT_CHARS,
            "content_trust": "untrusted_skill_output",
        }


__all__ = ["SkillScriptExecutor"]
