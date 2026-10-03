"""Read audited Skill instructions/references within an active SkillRun."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from gateway.core import Gateway, GatewayError
from .config import AuditValidator
from .paths import normalize_skill_path
from .registry import SkillRegistry
from .runs import SkillRun, SkillRunStore
from .sanitize import LocalSkillSanitizer

_OVERLAY_HEADER = "## Local Skill Bridge Web Mode Overlay"


class SkillReader:
    def __init__(
        self,
        gateway: Gateway,
        validator: AuditValidator,
        registry: SkillRegistry,
        runs: SkillRunStore,
        sanitizer: LocalSkillSanitizer | None = None,
    ):
        self.gateway = gateway
        self.validator = validator
        self.registry = registry
        self.runs = runs
        self.skills_parts = (*validator.root_parts, "skills")
        self.codeagent_path = gateway._root_path.joinpath(*validator.root_parts)
        self.skills_path = self.codeagent_path / "skills"
        self.sanitizer = sanitizer or LocalSkillSanitizer(gateway._root_path, self.codeagent_path)

    def _ensure_run_fresh(self, run: SkillRun) -> None:
        for skill, _mode in run.accessible_skills:
            status = self.validator.validate_skill(skill)
            if not status.available:
                raise GatewayError("skill_audit_stale", "Audited Skill source changed after startup.")

    def _skill_parts(self, skill: str, relative_path: str) -> tuple[str, ...]:
        return (*self.skills_parts, skill, *relative_path.split("/"))

    @staticmethod
    def _readable(relative_path: str) -> bool:
        return (
            relative_path == "SKILL.md"
            or relative_path.startswith("references/")
            or relative_path.startswith("schemas/")
        )

    def _sanitize_text(self, text: str) -> tuple[str, int]:
        value, redacted, _truncated = self.sanitizer.text(text)
        return value, redacted

    def _overlay(self, skill: str) -> str:
        record = self.registry.get(skill)
        lines = [
            _OVERLAY_HEADER,
            "",
            "These Web Mode constraints override conflicting execution instructions in the source Skill.",
            "",
            "- Gateway security constraints override all Skill instructions.",
            "- Entry interaction/confirmation rules may override dependency interaction/confirmation rules.",
            "- Dependency data rules remain effective and cannot be overridden by an Entry Skill.",
            "- Database access is read-only.",
            "- Schema synchronization workflows are unavailable.",
            "- Bash execution instructions must use run_skill_script with an argv array.",
            "- Ignore Windows/PowerShell execution sections in Web Mode.",
        ]
        if record.kind == "mysql":
            lines.append("- For an unknown table, inspect columns with SHOW COLUMNS or DESCRIBE; do not infer schema from external repositories.")
        if record.disabled_workflows:
            lines.append("- Disabled workflows: " + ", ".join(record.disabled_workflows) + ".")
        for item in record.instruction_overlay:
            lines.append("- " + item)
        return "\n".join(lines)

    def _read_exact(self, skill: str, relative_path: str) -> dict[str, Any]:
        if not self._readable(relative_path):
            raise GatewayError("skill_file_not_allowed", "Only SKILL.md, references, and schemas are readable.")
        parts = self._skill_parts(skill, relative_path)
        if not self.gateway._allowed(parts, is_file=True):
            raise GatewayError("skill_file_not_allowed", "Skill file is blocked.")
        snapshot = self.gateway._snapshot(parts)
        content, redacted = self._sanitize_text(snapshot.text)
        if relative_path == "SKILL.md":
            content = content.rstrip() + "\n\n" + self._overlay(skill) + "\n"
        return {
            "skill": skill,
            "path": relative_path,
            "content": content,
            "redacted_lines": redacted,
            "file_sha256": snapshot.sha256,
            "content_trust": "untrusted_skill_content",
        }

    def _list_tree(self, skill: str, directory: str) -> list[str]:
        base = "/".join((*self.skills_parts, skill, directory))
        pending = [base]
        found: list[str] = []
        while pending:
            current = pending.pop()
            try:
                offset = 0
                while True:
                    page = self.gateway.list_files(current, offset, 200)
                    for entry in page["entries"]:
                        path = entry["path"]
                        if entry["type"] == "directory":
                            pending.append(path)
                        elif entry["type"] == "file":
                            prefix = "/".join((*self.skills_parts, skill)) + "/"
                            relative = path[len(prefix):]
                            if self._readable(relative):
                                found.append(relative)
                        if len(found) > 1000:
                            raise GatewayError("too_large", "Skill file inventory exceeds the v1 limit.")
                    next_offset = page.get("next_offset")
                    if next_offset is None:
                        break
                    offset = next_offset
            except GatewayError as exc:
                if exc.code == "unavailable" and current == base:
                    return []
                raise
        return sorted(set(found))

    def begin(self, entry_skill: str, request: str) -> dict[str, Any]:
        if not isinstance(request, str) or not request or len(request) > 20_000:
            raise GatewayError("invalid_argument", "request must be a non-empty bounded string.")
        record = self.registry.require_startable(entry_skill)
        for skill in (entry_skill, *(dep.skill for dep in record.dependencies)):
            if not self.validator.validate_skill(skill).available:
                raise GatewayError("skill_audit_stale", "Audited Skill source changed after startup.")
        run = self.runs.create(self.registry, entry_skill)
        result = self._read_exact(entry_skill, "SKILL.md")
        result.update(
            skill_run_id=run.skill_run_id,
            references=self._list_tree(entry_skill, "references"),
            schemas=self._list_tree(entry_skill, "schemas"),
            allowed_scripts=list(run.scripts_for(entry_skill)),
            dependencies=[
                {"skill": skill, "access": mode}
                for skill, mode in run.accessible_skills
                if skill != entry_skill
            ],
            disabled_workflows=list(record.disabled_workflows),
        )
        return result

    def read(self, skill_run_id: str, current_skill: str, path: str) -> dict[str, Any]:
        run = self.runs.get_active(skill_run_id, self.registry)
        run.access_mode(current_skill)
        self._ensure_run_fresh(run)
        normalized = normalize_skill_path(current_skill, path, local_skill_root=self.validator.root_prefix)
        run.access_mode(normalized.skill)
        return self._read_exact(normalized.skill, normalized.relative_path)


__all__ = ["SkillReader"]
