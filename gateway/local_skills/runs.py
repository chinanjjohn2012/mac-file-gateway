"""Bounded in-memory SkillRun state."""
from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
import secrets
import threading
import time

from gateway.core import GatewayError
from .registry import SkillRegistry


@dataclass(frozen=True)
class SkillRun:
    skill_run_id: str
    entry_skill: str
    accessible_skills: tuple[tuple[str, str], ...]
    allowed_scripts: tuple[tuple[str, tuple[str, ...]], ...]
    created_at: float

    def access_mode(self, skill: str) -> str:
        for name, mode in self.accessible_skills:
            if name == skill:
                return mode
        raise GatewayError("skill_dependency_not_allowed", "Skill is outside this run's dependency scope.")

    def scripts_for(self, skill: str) -> tuple[str, ...]:
        for name, scripts in self.allowed_scripts:
            if name == skill:
                return scripts
        raise GatewayError("skill_dependency_not_allowed", "Skill is outside this run's dependency scope.")


class SkillRunStore:
    def __init__(self, *, max_runs: int = 256):
        if type(max_runs) is not int or not 1 <= max_runs <= 4096:
            raise GatewayError("skill_bridge_unavailable", "max_runs is invalid.")
        self.max_runs = max_runs
        self._runs: OrderedDict[str, SkillRun] = OrderedDict()
        self._lock = threading.Lock()

    def create(self, registry: SkillRegistry, entry_skill: str) -> SkillRun:
        entry = registry.require_startable(entry_skill)
        access: list[tuple[str, str]] = [(entry.name, "entry")]
        scripts: list[tuple[str, tuple[str, ...]]] = [(entry.name, entry.allowed_scripts)]
        for dep in entry.dependencies:
            status = registry.availability(dep.skill)
            if not status.available:
                raise GatewayError("skill_not_available", "A required Skill dependency is unavailable.")
            record = registry.get(dep.skill)
            access.append((dep.skill, dep.access))
            scripts.append((dep.skill, record.allowed_scripts))

        run = SkillRun(
            skill_run_id=secrets.token_urlsafe(24),
            entry_skill=entry.name,
            accessible_skills=tuple(access),
            allowed_scripts=tuple(scripts),
            created_at=time.time(),
        )
        with self._lock:
            while run.skill_run_id in self._runs:
                run = SkillRun(
                    skill_run_id=secrets.token_urlsafe(24),
                    entry_skill=run.entry_skill,
                    accessible_skills=run.accessible_skills,
                    allowed_scripts=run.allowed_scripts,
                    created_at=run.created_at,
                )
            self._runs[run.skill_run_id] = run
            while len(self._runs) > self.max_runs:
                self._runs.popitem(last=False)
        return run

    def get(self, skill_run_id: str) -> SkillRun:
        if not isinstance(skill_run_id, str) or not skill_run_id:
            raise GatewayError("skill_run_not_found", "Skill run was not found.")
        with self._lock:
            run = self._runs.get(skill_run_id)
        if run is None:
            raise GatewayError("skill_run_not_found", "Skill run was not found.")
        return run

    def get_active(self, skill_run_id: str, registry: SkillRegistry) -> SkillRun:
        run = self.get(skill_run_id)
        registry.require_startable(run.entry_skill)
        for skill, _mode in run.accessible_skills:
            if skill == run.entry_skill:
                continue
            if not registry.availability(skill).available:
                raise GatewayError("skill_not_available", "A Skill used by this run is no longer available.")
        return run

    def __len__(self) -> int:
        with self._lock:
            return len(self._runs)


__all__ = ["SkillRun", "SkillRunStore"]
