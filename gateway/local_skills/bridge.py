"""Compose audited Local Skill Bridge components behind one internal API."""
from __future__ import annotations

from pathlib import Path
import re
import threading
from typing import Any

from gateway.core import Gateway, GatewayError
from .args import SkillArgValidator
from .config import AuditValidator, default_policy_dir, load_audit_policy
from .executor import SkillScriptExecutor
from .hooks import ExistingHookRunner
from .reader import SkillReader
from .registry import SkillRegistry
from .runs import SkillRunStore
from .sanitize import LocalSkillSanitizer
from .sql_policy import SqlPolicyGate

_ALLOWED_DISPOSITIONS = {"PASS", "PASS_WITH_CONSTRAINTS"}


def _frontmatter_description(text: str) -> str:
    """Extract only the description field from simple Skill YAML frontmatter."""
    if not text.startswith("---\n"):
        return ""
    end = text.find("\n---", 4)
    if end < 0:
        return ""
    lines = text[4:end].splitlines()
    for index, line in enumerate(lines):
        match = re.match(r"^description:\s*(.*)$", line)
        if match is None:
            continue
        value = match.group(1).strip()
        if value in {">", ">-", "|", "|-"}:
            parts: list[str] = []
            for following in lines[index + 1:]:
                if following and not following[0].isspace():
                    break
                stripped = following.strip()
                if stripped:
                    parts.append(stripped)
            return " ".join(parts)
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        return value
    return ""


class LocalSkillBridge:
    """Web-mode Local Skill Bridge. Construction fails closed without stopping Gateway."""

    def __init__(
        self,
        gateway: Gateway,
        local_skill_root: str,
        *,
        policy_dir: Path | None = None,
        artifact_root: Path | None = None,
    ):
        self.gateway = gateway
        self.local_skill_root = local_skill_root
        self.policy_dir = policy_dir
        self.artifact_root = artifact_root
        self._lock = threading.RLock()
        self._status = "disabled"
        self._reason: str | None = "skill_bridge_unavailable"
        self._policy = None
        self._validator = None
        self._hooks = None
        self._runs = SkillRunStore()
        self._sanitizer = None
        self._registry = None
        self._reader = None
        self._args = None
        self._sql = None
        self._executor = None

    @classmethod
    def create(
        cls,
        gateway: Gateway,
        local_skill_root: str,
        *,
        policy_dir: Path | None = None,
        artifact_root: Path | None = None,
    ) -> "LocalSkillBridge":
        bridge = cls(
            gateway,
            local_skill_root,
            policy_dir=policy_dir,
            artifact_root=artifact_root,
        )
        bridge._initialize()
        return bridge

    def _disable(self, reason: str) -> None:
        self._status = "disabled"
        self._reason = reason

    def _initialize(self) -> None:
        with self._lock:
            try:
                policy_dir = Path(self.policy_dir).expanduser() if self.policy_dir is not None else default_policy_dir()
                if policy_dir.resolve().is_relative_to(self.gateway._root_path.resolve()):
                    raise GatewayError("skill_bridge_unavailable", "Audit policy must be outside the Gateway project scope.")
                policy = load_audit_policy(policy_dir)
                validator = AuditValidator(self.gateway, self.local_skill_root, policy)
                codeagent_path = self.gateway._root_path.joinpath(*validator.root_parts)
                sanitizer = LocalSkillSanitizer(self.gateway._root_path, codeagent_path)
                hooks = ExistingHookRunner(self.gateway, validator, policy)
                hooks.self_test()
                self._policy = policy
                self._validator = validator
                self._sanitizer = sanitizer
                self._hooks = hooks
                self._sql = SqlPolicyGate(policy)
                self._status = "enabled"
                self._reason = None
                self._refresh_registry_locked()
            except GatewayError as exc:
                reason = "skill_hook_selftest_failed" if exc.code == "skill_hook_error" else exc.code
                self._disable(reason)
            except (OSError, RuntimeError):
                self._disable("skill_bridge_unavailable")

    def _require_enabled(self) -> None:
        if self._status != "enabled":
            raise GatewayError("skill_bridge_unavailable", "Local Skill Bridge is unavailable.")

    def _refresh_common_locked(self) -> None:
        self._require_enabled()
        assert self._hooks is not None
        try:
            self._hooks.validate_common_freshness()
        except GatewayError as exc:
            if exc.code == "skill_bridge_unavailable":
                self._disable("skill_bridge_unavailable")
            raise

    def _refresh_registry_locked(self) -> None:
        self._require_enabled()
        assert self._policy is not None
        assert self._validator is not None
        assert self._hooks is not None
        assert self._sanitizer is not None
        assert self._sql is not None
        freshness = self._validator.validate_all_skills()
        registry = SkillRegistry(self._policy, freshness)
        args = SkillArgValidator(registry)
        reader = SkillReader(
            self.gateway,
            self._validator,
            registry,
            self._runs,
            sanitizer=self._sanitizer,
        )
        executor = SkillScriptExecutor(
            self.gateway,
            self._validator,
            registry,
            self._runs,
            args,
            self._sql,
            self._hooks,
            artifact_root=self.artifact_root,
            sanitizer=self._sanitizer,
        )
        self._registry = registry
        self._args = args
        self._reader = reader
        self._executor = executor

    def _refresh_locked(self) -> None:
        self._refresh_common_locked()
        self._refresh_registry_locked()

    def status_info(self) -> dict[str, Any]:
        with self._lock:
            result: dict[str, Any] = {"configured": True, "status": self._status}
            if self._reason is not None:
                result["reason"] = self._reason
            return result

    def _description_locked(self, skill: str) -> str:
        assert self._validator is not None
        assert self._sanitizer is not None
        path = f"{self.local_skill_root}/skills/{skill}/SKILL.md"
        try:
            snapshot = self._validator.snapshot(path)
        except GatewayError:
            return ""
        description = _frontmatter_description(snapshot.text)
        return self._sanitizer.text(description, limit=1000)[0]

    def info(self) -> dict[str, Any]:
        with self._lock:
            if self._status != "enabled":
                return {**self.status_info(), "entries": []}
            try:
                self._refresh_locked()
            except GatewayError:
                if self._status != "enabled":
                    return {**self.status_info(), "entries": []}
                raise
            assert self._registry is not None
            entries = []
            for name in self._registry.entry_names():
                record = self._registry.get(name)
                if record.disposition not in _ALLOWED_DISPOSITIONS:
                    continue
                status = self._registry.availability(name)
                item: dict[str, Any] = {
                    "name": name,
                    "description": self._description_locked(name) if status.available else "",
                    "available": status.available,
                }
                if status.reason is not None:
                    item["reason"] = status.reason
                if status.dependency is not None:
                    item["dependency"] = status.dependency
                entries.append(item)
            return {**self.status_info(), "entries": entries}

    def begin(self, skill: str, request: str) -> dict[str, Any]:
        with self._lock:
            self._refresh_locked()
            assert self._reader is not None
            return self._sanitizer.structure(self._reader.begin(skill, request))

    def read(self, skill_run_id: str, skill: str, path: str) -> dict[str, Any]:
        with self._lock:
            self._refresh_locked()
            assert self._reader is not None
            return self._sanitizer.structure(self._reader.read(skill_run_id, skill, path))

    def run(
        self,
        skill_run_id: str,
        skill: str,
        script: str,
        argv: list[str],
        timeout_seconds: int = 60,
    ) -> dict[str, Any]:
        with self._lock:
            self._refresh_locked()
            assert self._executor is not None
            try:
                result = self._executor.run(
                    skill_run_id,
                    skill,
                    script,
                    argv,
                    timeout_seconds,
                )
            except GatewayError as exc:
                if exc.code == "skill_bridge_unavailable":
                    self._disable("skill_bridge_unavailable")
                raise
            return self._sanitizer.structure(result)


__all__ = ["LocalSkillBridge"]
