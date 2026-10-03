"""Phase 1 configuration and audit-freshness validation for Local Skill Bridge."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
from typing import Any

from gateway.core import Gateway, GatewayError, _parts

_SCHEMA_VERSION = 1
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _config_error(message: str) -> GatewayError:
    return GatewayError("skill_bridge_unavailable", message)


def _strict_json_text(text: str, *, source: str) -> dict[str, Any]:
    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    try:
        data = json.loads(
            text,
            object_pairs_hook=unique_object,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"non-standard JSON constant: {value}")
            ),
        )
    except (json.JSONDecodeError, UnicodeError, ValueError, RecursionError):
        raise _config_error(f"{source} must be valid UTF-8 JSON with unique keys.") from None
    if not isinstance(data, dict):
        raise _config_error(f"{source} must contain a JSON object.")
    return data


def _strict_json_file(path: Path, *, source: str) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
    except OSError:
        raise _config_error(f"{source} is unavailable.") from None
    if len(raw) > 2_000_000:
        raise _config_error(f"{source} exceeds the policy size limit.")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise _config_error(f"{source} must be UTF-8.") from None
    return _strict_json_text(text, source=source)


def _require_sha256(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise _config_error(f"{field} must be a lowercase SHA-256 hex digest.")
    return value


def _require_nonempty_str(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise _config_error(f"{field} must be a non-empty string.")
    return value


def _require_string_argv(value: Any, *, field: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise _config_error(f"{field} must be an array of strings.")
    result: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item or "\x00" in item:
            raise _config_error(f"{field} contains an invalid argv item.")
        result.append(item)
    return tuple(result)


@dataclass(frozen=True)
class HookCase:
    id: str
    script: str
    argv: tuple[str, ...]


@dataclass(frozen=True)
class HookSelfTest:
    name: str
    script: str
    sha256: str
    must_allow: tuple[HookCase, ...]
    must_deny: tuple[HookCase, ...]


@dataclass(frozen=True)
class AuditPolicy:
    compatibility: dict[str, Any]
    hooks_manifest_path: str
    hooks_manifest_sha256: str
    hook_tests: tuple[HookSelfTest, ...]


@dataclass(frozen=True)
class SkillFreshness:
    available: bool
    reason: str | None = None


@dataclass(frozen=True)
class LocalSkillSafetyState:
    configured: bool
    status: str
    reason: str | None
    skill_freshness: dict[str, SkillFreshness]

    def public_status(self) -> dict[str, Any]:
        result: dict[str, Any] = {"configured": self.configured, "status": self.status}
        if self.reason is not None:
            result["reason"] = self.reason
        if self.skill_freshness:
            result["skills"] = {
                name: {"available": value.available, **({"reason": value.reason} if value.reason else {})}
                for name, value in sorted(self.skill_freshness.items())
            }
        return result


def default_policy_dir() -> Path:
    """Private local configuration; public samples are never a runtime fallback."""
    return Path.home() / ".config" / "mac-file-gateway" / "local-skill-policy"


def load_audit_policy(policy_dir: Path | None = None) -> AuditPolicy:
    base = Path(policy_dir).expanduser() if policy_dir is not None else default_policy_dir()
    compatibility = _strict_json_file(base / "skill-compatibility.json", source="skill compatibility policy")
    hook_data = _strict_json_file(base / "hook-selftests.json", source="hook self-test policy")

    if compatibility.get("schema_version") != _SCHEMA_VERSION:
        raise _config_error("Unsupported skill compatibility policy schema_version.")
    if compatibility.get("review_status", "approved") != "approved":
        raise _config_error("Draft audit policies cannot be used at runtime.")
    agent_env = compatibility.get("agent_dir_env", "LOCAL_SKILL_AGENT_DIR")
    if not isinstance(agent_env, str) or re.fullmatch(r"(?:LOCAL_SKILL_AGENT_DIR|[A-Z][A-Z0-9_]*_PROJECT_AGENT_DIR)", agent_env) is None:
        raise _config_error("Agent directory environment key is invalid.")
    skills = compatibility.get("skills")
    if not isinstance(skills, dict) or not skills:
        raise _config_error("skill compatibility policy must define skills.")

    for skill_name, skill in skills.items():
        if not isinstance(skill_name, str) or not skill_name or not isinstance(skill, dict):
            raise _config_error("skill compatibility policy contains an invalid skill entry.")
        allowed_scripts = skill.get("allowed_scripts", [])
        if not isinstance(allowed_scripts, list) or any(not isinstance(script, str) or not script for script in allowed_scripts):
            raise _config_error("allowed_scripts must be an array.")
        kind = skill.get("kind", "instructions")
        if not isinstance(kind, str) or kind not in {"instructions", "shell", "clickhouse", "mysql", "prometheus", "cloud-api", "trace"}:
            raise _config_error("Unsupported Skill kind.")
        if allowed_scripts and kind == "instructions":
            raise _config_error("Executable Skills require a supported explicit kind.")
        if kind == "cloud-api":
            sections = skill.get("command_script_sections")
            argv_policy = skill.get("argv", skill.get("arg_policy", {}))
            if not isinstance(sections, dict) or not isinstance(argv_policy, dict):
                raise _config_error("Cloud scripts require explicit command policy sections.")
            for script in allowed_scripts:
                section = sections.get(script)
                if not isinstance(section, str) or not isinstance(argv_policy.get(section), dict):
                    raise _config_error("Cloud scripts require explicit command policy sections.")
        if kind in {"mysql", "clickhouse"}:
            argv_policy = skill.get("argv", {})
            if not isinstance(argv_policy, dict):
                raise _config_error("SQL scripts require explicit argv rules.")
            for script in allowed_scripts:
                rules = argv_policy.get(script)
                if not isinstance(rules, list) or any(not isinstance(rule, dict) for rule in rules):
                    raise _config_error("SQL scripts require explicit argv rules.")
                sql_rules = [rule for rule in rules if rule.get("index") == 0]
                if len(sql_rules) != 1 or not sql_rules[0].get("required") or not sql_rules[0].get("non_empty"):
                    raise _config_error("SQL must be a required non-empty first argument.")
                if kind == "clickhouse":
                    instance_rules = [rule for rule in rules if rule.get("index") == 1 and rule.get("name") == "instance"]
                    if len(instance_rules) != 1 or not (instance_rules[0].get("required") or isinstance(instance_rules[0].get("default"), str) and instance_rules[0]["default"]):
                        raise _config_error("ClickHouse requires an audited instance argument.")
            if kind == "clickhouse" and (not isinstance(skill.get("realtime_time_columns", {}), dict) or type(skill.get("small_schema_count", 0)) is not int):
                raise _config_error("ClickHouse scope policy is invalid.")
        evidence = skill.get("evidence", [])
        if not isinstance(evidence, list):
            raise _config_error(f"Skill {skill_name} evidence must be an array.")
        for index, item in enumerate(evidence):
            if not isinstance(item, dict):
                raise _config_error(f"Skill {skill_name} evidence[{index}] must be an object.")
            if item.get("kind") == "code_fact":
                _require_nonempty_str(item.get("path"), field=f"{skill_name}.evidence[{index}].path")
                _require_sha256(item.get("sha256"), field=f"{skill_name}.evidence[{index}].sha256")

    if hook_data.get("schema_version") != _SCHEMA_VERSION:
        raise _config_error("Unsupported hook self-test policy schema_version.")
    if hook_data.get("review_status", "approved") != "approved":
        raise _config_error("Draft hook policies cannot be used at runtime.")
    manifest = hook_data.get("hooks_manifest")
    if not isinstance(manifest, dict):
        raise _config_error("hook self-test policy must define hooks_manifest.")
    manifest_path = _require_nonempty_str(manifest.get("path"), field="hooks_manifest.path")
    manifest_sha256 = _require_sha256(manifest.get("sha256"), field="hooks_manifest.sha256")

    hooks_raw = hook_data.get("hooks")
    if not isinstance(hooks_raw, list) or not hooks_raw:
        raise _config_error("hook self-test policy must define hooks.")
    hook_tests: list[HookSelfTest] = []
    seen_names: set[str] = set()
    for hook_index, hook in enumerate(hooks_raw):
        if not isinstance(hook, dict):
            raise _config_error(f"hooks[{hook_index}] must be an object.")
        name = _require_nonempty_str(hook.get("name"), field=f"hooks[{hook_index}].name")
        if name in seen_names:
            raise _config_error("hook self-test names must be unique.")
        seen_names.add(name)
        script = _require_nonempty_str(hook.get("script"), field=f"hooks[{hook_index}].script")
        sha256 = _require_sha256(hook.get("sha256"), field=f"hooks[{hook_index}].sha256")

        def parse_cases(key: str) -> tuple[HookCase, ...]:
            raw_cases = hook.get(key)
            if not isinstance(raw_cases, list) or not raw_cases:
                raise _config_error(f"Hook {name} must define at least one {key} case.")
            parsed: list[HookCase] = []
            for case_index, case in enumerate(raw_cases):
                if not isinstance(case, dict) or "command" in case:
                    raise _config_error(f"Hook {name} {key}[{case_index}] must use script + argv, not command.")
                case_id = _require_nonempty_str(case.get("id"), field=f"{name}.{key}[{case_index}].id")
                case_script = _require_nonempty_str(case.get("script"), field=f"{name}.{key}[{case_index}].script")
                argv = _require_string_argv(case.get("argv"), field=f"{name}.{key}[{case_index}].argv")
                parsed.append(HookCase(case_id, case_script, argv))
            return tuple(parsed)

        hook_tests.append(HookSelfTest(
            name=name,
            script=script,
            sha256=sha256,
            must_allow=parse_cases("must_allow"),
            must_deny=parse_cases("must_deny"),
        ))

    return AuditPolicy(
        compatibility=compatibility,
        hooks_manifest_path=manifest_path,
        hooks_manifest_sha256=manifest_sha256,
        hook_tests=tuple(hook_tests),
    )


class AuditValidator:
    """Validate audited source hashes through the Gateway's no-symlink file reader."""

    def __init__(self, gateway: Gateway, local_skill_root: str, policy: AuditPolicy):
        self.gateway = gateway
        self.policy = policy
        self.root_parts = gateway._checked(local_skill_root, is_file=False)
        if not self.root_parts:
            raise _config_error("local_skill_root must name a project-relative directory.")
        self.root_prefix = "/".join(self.root_parts)

    def _checked_root_relative(self, path: str) -> tuple[str, ...]:
        parts = _parts(path)
        if len(parts) <= len(self.root_parts) or parts[:len(self.root_parts)] != self.root_parts:
            raise _config_error("Audited evidence path is outside the configured local Skill root.")
        canonical = "/".join(parts)
        return self.gateway._checked(canonical, is_file=True)

    def snapshot(self, path: str):
        parts = self._checked_root_relative(path)
        return self.gateway._snapshot(parts)

    def sha256(self, path: str) -> str:
        return self.snapshot(path).sha256

    def validate_skill(self, skill_name: str) -> SkillFreshness:
        skills = self.policy.compatibility["skills"]
        skill = skills.get(skill_name)
        if not isinstance(skill, dict):
            return SkillFreshness(False, "skill_not_available")
        evidence = skill.get("evidence", [])
        try:
            for item in evidence:
                if item.get("kind") != "code_fact":
                    continue
                path = item["path"]
                expected = item["sha256"]
                if self.sha256(path) != expected:
                    return SkillFreshness(False, "skill_audit_stale")
        except GatewayError:
            return SkillFreshness(False, "skill_audit_stale")
        return SkillFreshness(True)

    def validate_all_skills(self) -> dict[str, SkillFreshness]:
        return {
            skill_name: self.validate_skill(skill_name)
            for skill_name in self.policy.compatibility["skills"]
        }

    def verify_exact_hash(self, path: str, expected_sha256: str) -> bool:
        _require_sha256(expected_sha256, field="expected_sha256")
        try:
            return self.sha256(path) == expected_sha256
        except GatewayError:
            return False


def digest_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


__all__ = [
    "AuditPolicy",
    "AuditValidator",
    "HookCase",
    "HookSelfTest",
    "LocalSkillSafetyState",
    "SkillFreshness",
    "_strict_json_text",
    "load_audit_policy",
]
