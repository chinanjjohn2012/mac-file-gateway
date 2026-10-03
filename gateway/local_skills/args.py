"""Deterministic argv validation for audited Local Skill scripts."""
from __future__ import annotations

import re
from typing import Any

from gateway.core import GatewayError
from .registry import SkillRegistry

_MAX_ARG_CHARS = 32_768
_MAX_ARGV_CHARS = 65_536
_UUID = re.compile(r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$")


class SkillArgValidator:
    def __init__(self, registry: SkillRegistry):
        self.registry = registry

    @staticmethod
    def _base(argv: Any) -> list[str]:
        if not isinstance(argv, list) or len(argv) > 64:
            raise GatewayError("skill_arg_not_allowed", "argv must be a bounded string array.")
        result: list[str] = []
        total = 0
        for item in argv:
            if not isinstance(item, str) or len(item) > _MAX_ARG_CHARS or "\x00" in item:
                raise GatewayError("skill_arg_not_allowed", "argv contains an invalid item.")
            total += len(item)
            if total > _MAX_ARGV_CHARS:
                raise GatewayError("skill_arg_not_allowed", "argv is too large.")
            result.append(item)
        return result

    @staticmethod
    def _value(rule: dict[str, Any], value: str) -> str:
        if rule.get("non_empty") and value == "":
            raise GatewayError("skill_arg_not_allowed", "Argument must not be empty.")
        if rule.get("explicit_empty") == "reject" and value == "":
            raise GatewayError("skill_arg_not_allowed", "Explicit empty argument is not allowed.")
        if rule.get("max_length") is not None and len(value) > int(rule["max_length"]):
            raise GatewayError("skill_arg_not_allowed", "Argument exceeds its length limit.")
        enum = rule.get("enum")
        if enum is not None and value not in enum:
            raise GatewayError("skill_arg_not_allowed", "Argument is outside the allowed enum.")
        pattern = rule.get("pattern")
        if pattern is not None and re.fullmatch(pattern, value) is None:
            raise GatewayError("skill_arg_not_allowed", "Argument does not match the required format.")
        if rule.get("format") == "uuid" and _UUID.fullmatch(value) is None:
            raise GatewayError("skill_arg_not_allowed", "Argument must be a UUID.")

        value_type = rule.get("type")
        if value_type in {"integer", "positive_integer"}:
            try:
                number = int(value, 10)
            except ValueError:
                raise GatewayError("skill_arg_not_allowed", "Argument must be an integer.") from None
            if value_type == "positive_integer" and number <= 0:
                raise GatewayError("skill_arg_not_allowed", "Argument must be positive.")
            if "min" in rule and number < int(rule["min"]):
                raise GatewayError("skill_arg_not_allowed", "Argument is below its minimum.")
            if "max" in rule and number > int(rule["max"]):
                raise GatewayError("skill_arg_not_allowed", "Argument exceeds its maximum.")
            return str(number)
        return value

    def _standard(self, rules: list[dict[str, Any]], argv: list[str]) -> list[str]:
        positional = sorted((r for r in rules if "index" in r), key=lambda r: int(r["index"]))
        flags = {r["flag"]: r for r in rules if "flag" in r}
        constraints = [r for r in rules if "constraint" in r]

        pos_count = len(positional)
        provided_pos = argv[:pos_count]
        remainder = argv[pos_count:]
        output: list[str] = []
        values: dict[str, int] = {}

        for rule in positional:
            index = int(rule["index"])
            if index < len(provided_pos):
                raw = provided_pos[index]
            elif "default" in rule:
                raw = str(rule["default"])
            elif rule.get("required"):
                raise GatewayError("skill_arg_not_allowed", "A required argument is missing.")
            else:
                continue
            clean = self._value(rule, raw)
            output.append(clean)
            if rule.get("type") in {"integer", "positive_integer"}:
                values[str(rule.get("name", index))] = int(clean)

        if flags:
            seen: set[str] = set()
            parsed: dict[str, str] = {}
            i = 0
            while i < len(remainder):
                flag = remainder[i]
                if flag not in flags or flag in seen or i + 1 >= len(remainder):
                    raise GatewayError("skill_arg_not_allowed", "Unknown, duplicate, or incomplete flag argument.")
                parsed[flag] = remainder[i + 1]
                seen.add(flag)
                i += 2
            for flag, rule in flags.items():
                raw = parsed.get(flag, str(rule["default"]) if "default" in rule else None)
                if raw is None:
                    continue
                clean = self._value(rule, raw)
                output.extend([flag, clean])
                if rule.get("type") in {"integer", "positive_integer"}:
                    values[flag.lstrip("-").replace("-", "_")] = int(clean)
        elif remainder:
            raise GatewayError("skill_arg_not_allowed", "Extra arguments are not allowed.")

        for rule in constraints:
            if rule["constraint"] == "offset_minutes * 60 / step_seconds <= 11000":
                offset = values.get("offset_minutes")
                step = values.get("step_seconds")
                if offset is None or step is None or offset * 60 > step * 11_000:
                    raise GatewayError("skill_arg_not_allowed", "Prometheus query exceeds the point limit.")
            else:
                raise GatewayError("skill_bridge_unavailable", "Unsupported argv constraint in fixture.")
        return output

    def _infra(self, policy: dict[str, Any], sections: dict[str, str], script: str, argv: list[str]) -> list[str]:
        if any(item == "" for item in argv):
            raise GatewayError("skill_arg_not_allowed", "Explicit empty argument is not allowed.")
        if any(any(ord(ch) < 32 or ord(ch) == 127 for ch in item) for item in argv):
            raise GatewayError("skill_arg_not_allowed", "Control characters are not allowed.")

        key = sections.get(script)
        if key is None or key not in policy:
            raise GatewayError("skill_script_not_allowed", "Skill script is not allowed.")
        section = policy[key]
        if not argv:
            raise GatewayError("skill_arg_not_allowed", "cloud API command is required.")
        command = argv[0]
        if command not in section.get("command_enum", []):
            raise GatewayError("skill_arg_not_allowed", "Unknown cloud API command.")
        command_rule = section.get("commands", {}).get(command)
        if not isinstance(command_rule, dict):
            raise GatewayError("skill_bridge_unavailable", "Missing cloud API command policy.")

        args = argv[1:]
        rules = command_rule.get("args", [])
        if not isinstance(rules, list):
            raise GatewayError("skill_bridge_unavailable", "Invalid cloud API command policy.")
        output = [command]
        cursor = 0
        for index, rule in enumerate(rules):
            if not isinstance(rule, dict):
                raise GatewayError("skill_bridge_unavailable", "Invalid cloud API argument policy.")
            if rule.get("repeatable"):
                remaining = args[cursor:]
                if len(remaining) > int(rule.get("max_items", 64)):
                    raise GatewayError("skill_arg_not_allowed", "Too many repeated arguments.")
                output.extend(self._value(rule, item) for item in remaining)
                cursor = len(args)
                break
            if cursor < len(args):
                raw = args[cursor]
                cursor += 1
            elif "default" in rule:
                raw = str(rule["default"])
            elif rule.get("required"):
                raise GatewayError("skill_arg_not_allowed", "A required cloud API argument is missing.")
            else:
                continue
            output.append(self._value(rule, raw))
        if cursor != len(args):
            raise GatewayError("skill_arg_not_allowed", "Extra cloud API arguments are not allowed.")
        return output

    def validate(self, skill: str, script: str, argv: Any) -> list[str]:
        record = self.registry.get(skill)
        if script not in record.allowed_scripts:
            raise GatewayError("skill_script_not_allowed", "Skill script is not allowed.")
        clean = self._base(argv)
        if record.kind == "cloud-api":
            return self._infra(record.argv_policy, record.command_script_sections, script, clean)

        rules = record.argv_policy.get(script)
        if not isinstance(rules, list):
            if clean:
                raise GatewayError("skill_arg_not_allowed", "Arguments are not configured for this script.")
            return []
        return self._standard(rules, clean)


__all__ = ["SkillArgValidator"]
