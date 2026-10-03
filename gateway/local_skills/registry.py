"""Audited Local Skill registry."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from gateway.core import GatewayError
from .config import AuditPolicy, SkillFreshness

_ALLOWED = {"PASS", "PASS_WITH_CONSTRAINTS"}


@dataclass(frozen=True)
class SkillDependency:
    skill: str
    access: str


@dataclass(frozen=True)
class SkillRecord:
    name: str
    kind: str
    role: str
    disposition: str
    allowed_scripts: tuple[str, ...]
    disabled_workflows: tuple[str, ...]
    dependencies: tuple[SkillDependency, ...]
    argv_policy: dict[str, Any]
    command_script_sections: dict[str, str]
    instruction_overlay: tuple[str, ...]


@dataclass(frozen=True)
class SkillAvailability:
    available: bool
    reason: str | None = None
    dependency: str | None = None


class SkillRegistry:
    def __init__(self, policy: AuditPolicy, freshness: dict[str, SkillFreshness]):
        self._records = {
            name: self._parse(name, raw)
            for name, raw in policy.compatibility["skills"].items()
        }
        self._availability = self._resolve(freshness)

    @staticmethod
    def _string_list(value: Any, field: str) -> tuple[str, ...]:
        if value is None:
            return ()
        if not isinstance(value, list) or any(not isinstance(x, str) or not x for x in value):
            raise GatewayError("skill_bridge_unavailable", f"{field} must be a string array.")
        return tuple(value)

    def _parse(self, name: str, raw: Any) -> SkillRecord:
        if not isinstance(raw, dict):
            raise GatewayError("skill_bridge_unavailable", "Invalid Skill config.")
        role = raw.get("role")
        disposition = raw.get("disposition")
        if not isinstance(role, str) or not isinstance(disposition, str):
            raise GatewayError("skill_bridge_unavailable", "Invalid Skill role/disposition.")

        deps_raw = raw.get("dependencies", [])
        if not isinstance(deps_raw, list):
            raise GatewayError("skill_bridge_unavailable", "Invalid Skill dependencies.")
        deps: list[SkillDependency] = []
        seen: set[str] = set()
        for item in deps_raw:
            if not isinstance(item, dict):
                raise GatewayError("skill_bridge_unavailable", "Invalid Skill dependency.")
            target = item.get("skill")
            access = item.get("access")
            if not isinstance(target, str) or not target or not isinstance(access, str) or not access:
                raise GatewayError("skill_bridge_unavailable", "Invalid Skill dependency.")
            if target == name or target in seen:
                raise GatewayError("skill_bridge_unavailable", "Duplicate or self dependency.")
            seen.add(target)
            deps.append(SkillDependency(target, access))

        argv_policy = raw.get("argv", raw.get("arg_policy", {}))
        if not isinstance(argv_policy, dict):
            raise GatewayError("skill_bridge_unavailable", "Invalid Skill argv policy.")

        return SkillRecord(
            name=name,
            kind=raw.get("kind", "instructions"),
            role=role,
            disposition=disposition,
            allowed_scripts=self._string_list(raw.get("allowed_scripts", []), f"{name}.allowed_scripts"),
            disabled_workflows=self._string_list(raw.get("disabled_workflows", []), f"{name}.disabled_workflows"),
            dependencies=tuple(deps),
            argv_policy=argv_policy,
            command_script_sections=raw.get("command_script_sections", {}),
            instruction_overlay=self._string_list(raw.get("instruction_overlay", []), f"{name}.instruction_overlay"),
        )

    def _resolve(self, freshness: dict[str, SkillFreshness]) -> dict[str, SkillAvailability]:
        result: dict[str, SkillAvailability] = {}
        for name, record in self._records.items():
            fresh = freshness.get(name)
            if record.disposition not in _ALLOWED:
                result[name] = SkillAvailability(False, "skill_not_available")
            elif fresh is None or not fresh.available:
                result[name] = SkillAvailability(False, fresh.reason if fresh else "skill_audit_stale")
            else:
                result[name] = SkillAvailability(True)

        for record in self._records.values():
            for dep in record.dependencies:
                if dep.skill not in self._records:
                    result[record.name] = SkillAvailability(False, "skill_dependency_unavailable", dep.skill)

        changed = True
        while changed:
            changed = False
            for name, record in self._records.items():
                if not result[name].available:
                    continue
                for dep in record.dependencies:
                    status = result.get(dep.skill)
                    if status is None or not status.available:
                        result[name] = SkillAvailability(False, "skill_dependency_unavailable", dep.skill)
                        changed = True
                        break
        return result

    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._records))

    def entry_names(self) -> tuple[str, ...]:
        return tuple(sorted(
            r.name for r in self._records.values()
            if r.role == "entry" and r.disposition in _ALLOWED
        ))

    def get(self, name: str) -> SkillRecord:
        record = self._records.get(name)
        if record is None:
            raise GatewayError("skill_not_available", "Unknown Local Skill.")
        return record

    def availability(self, name: str) -> SkillAvailability:
        self.get(name)
        return self._availability[name]

    def require_startable(self, name: str) -> SkillRecord:
        record = self.get(name)
        status = self._availability[name]
        if record.role != "entry" or record.disposition not in _ALLOWED or not status.available:
            raise GatewayError("skill_not_available", "Local Skill is not startable.")
        return record

    def dependencies_for(self, entry_name: str) -> tuple[SkillDependency, ...]:
        return self.require_startable(entry_name).dependencies

    def dependency_access(self, entry_name: str, target_skill: str) -> str:
        for dep in self.require_startable(entry_name).dependencies:
            if dep.skill == target_skill:
                return dep.access
        raise GatewayError("skill_dependency_not_allowed", "Dependency is not allowed.")


__all__ = ["SkillAvailability", "SkillDependency", "SkillRecord", "SkillRegistry"]
