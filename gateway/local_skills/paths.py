"""Normalize legacy Skill-authored path forms without granting access."""
from __future__ import annotations

from dataclasses import dataclass
import re

from gateway.core import GatewayError


@dataclass(frozen=True)
class NormalizedSkillPath:
    skill: str
    relative_path: str


def _clean_parts(value: str) -> tuple[str, ...]:
    if not isinstance(value, str) or not value or len(value) > 4096:
        raise GatewayError("skill_file_not_allowed", "Skill path is invalid.")
    if "\x00" in value or "\\" in value or any(ord(ch) < 32 for ch in value):
        raise GatewayError("skill_file_not_allowed", "Skill path is invalid.")
    parts = tuple(part for part in value.split("/") if part not in ("", "."))
    if not parts or any(part == ".." for part in parts):
        raise GatewayError("skill_file_not_allowed", "Skill path traversal is not allowed.")
    if any(part.startswith(".") or part == "__pycache__" for part in parts):
        raise GatewayError("skill_file_not_allowed", "Hidden or bytecode-cache Skill paths are not allowed.")
    return parts


def _result(skill: str, relative_parts: tuple[str, ...]) -> NormalizedSkillPath:
    if not skill or skill.startswith(".") or "/" in skill:
        raise GatewayError("skill_file_not_allowed", "Skill name is invalid.")
    if not relative_parts:
        raise GatewayError("skill_file_not_allowed", "Skill relative path is required.")
    if any(part == ".." or part.startswith(".") or part == "__pycache__" for part in relative_parts):
        raise GatewayError("skill_file_not_allowed", "Skill path is not allowed.")
    return NormalizedSkillPath(skill, "/".join(relative_parts))


def normalize_skill_path(current_skill: str, path: str, *, local_skill_root: str = "agent-runtime") -> NormalizedSkillPath:
    """Normalize known legacy source forms to (skill, relative_path)."""
    if not isinstance(current_skill, str) or not current_skill:
        raise GatewayError("skill_file_not_allowed", "Current Skill is invalid.")
    if not isinstance(path, str) or not path or len(path) > 4096:
        raise GatewayError("skill_file_not_allowed", "Skill path is invalid.")
    if "\x00" in path or "\\" in path or any(ord(ch) < 32 for ch in path):
        raise GatewayError("skill_file_not_allowed", "Skill path is invalid.")

    if path.startswith("../"):
        raw = path[3:]
        parts = _clean_parts(raw)
        if len(parts) < 2:
            raise GatewayError("skill_file_not_allowed", "Dependency Skill path is incomplete.")
        return _result(parts[0], parts[1:])

    env_form = re.match(r"^\$\{[A-Z][A-Z0-9_]*\}/skills/", path)
    prefixes = ("$SKILL_ROOT/",) + ((env_form.group(),) if env_form else ())
    for prefix in prefixes:
        if path.startswith(prefix):
            parts = _clean_parts(path[len(prefix):])
            if len(parts) < 2:
                raise GatewayError("skill_file_not_allowed", "Skill-root path is incomplete.")
            return _result(parts[0], parts[1:])

    cursor_marker = "/.cursor/skills/"
    if cursor_marker in path and not path.startswith(("/", "~")):
        prefix, suffix = path.split(cursor_marker, 1)
        _clean_parts(prefix)
        parts = _clean_parts(suffix)
        if len(parts) < 2:
            raise GatewayError("skill_file_not_allowed", "Cursor Skill path is incomplete.")
        return _result(parts[0], parts[1:])

    marker = "/" + local_skill_root.strip("/") + "/skills/"
    if path.startswith(("/", "~")) and marker not in path:
        raise GatewayError("skill_file_not_allowed", "Absolute Skill paths are not allowed.")
    if marker in path:
        _prefix, suffix = path.rsplit(marker, 1)
        parts = _clean_parts(suffix)
        if len(parts) < 2:
            raise GatewayError("skill_file_not_allowed", "Repository Skill path is incomplete.")
        return _result(parts[0], parts[1:])

    relative = _clean_parts(path)
    return _result(current_skill, relative)


__all__ = ["NormalizedSkillPath", "normalize_skill_path"]
