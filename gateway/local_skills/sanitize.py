"""Shared output sanitizer for Local Skill Bridge."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from gateway.core import _redact


class LocalSkillSanitizer:
    def __init__(self, project_root: Path, codeagent_root: Path):
        self.project_root = str(project_root)
        self.codeagent_root = str(codeagent_root)
        self.skills_root = str(codeagent_root / "skills")
        self.home = str(Path.home())

    def text(self, value: str, *, limit: int | None = None) -> tuple[str, int, bool]:
        lines, redacted = _redact(value)
        result = "\n".join(lines)
        replacements = [
            (self.skills_root, "$SKILL_ROOT"),
            (self.codeagent_root, "$CODEAGENT_ROOT"),
            (self.project_root, "$PROJECT_ROOT"),
            (self.home + "/.agent-config", "$AGENT_CONFIG"),
            (self.home + "/.ssh/", "$SSH_DIR/"),
            (self.home, "$HOME"),
            ("$HOME/.agent-config", "$AGENT_CONFIG"),
            ("~/.agent-config", "$AGENT_CONFIG"),
            ("$HOME/.ssh/", "$SSH_DIR/"),
            ("~/.ssh/", "$SSH_DIR/"),
        ]
        for source, target in sorted(replacements, key=lambda item: len(item[0]), reverse=True):
            if source:
                result = result.replace(source, target)
        truncated = False
        if limit is not None and len(result) > limit:
            marker = "\n[...output truncated...]"
            result = result[:max(0, limit - len(marker))] + marker
            truncated = True
        return result, redacted, truncated

    def bytes(self, raw: bytes, *, limit: int | None = None) -> tuple[str, int, bool]:
        return self.text(raw.decode("utf-8", errors="replace"), limit=limit)

    def structure(self, value: Any) -> Any:
        if isinstance(value, str):
            return self.text(value)[0]
        if isinstance(value, list):
            return [self.structure(item) for item in value]
        if isinstance(value, tuple):
            return tuple(self.structure(item) for item in value)
        if isinstance(value, dict):
            return {key: self.structure(item) for key, item in value.items()}
        return value


__all__ = ["LocalSkillSanitizer"]
