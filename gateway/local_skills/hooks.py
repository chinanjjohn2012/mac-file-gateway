"""Existing hook manifest parsing and deterministic startup self-tests."""
from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import shlex
import signal
import subprocess
from typing import Any

from gateway.core import Gateway, GatewayError, _parts
from .config import AuditPolicy, AuditValidator, HookCase, _strict_json_text

_HOOK_PATH = re.compile(r"/hooks/([A-Za-z0-9._-]+\.sh)")
_SAFE_ENV_KEYS = ("PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "LC_CTYPE")


@dataclass(frozen=True)
class HookSpec:
    name: str
    script_name: str
    timeout_seconds: int


@dataclass(frozen=True)
class HookResult:
    decision: str
    reason: str | None = None


def build_hook_command(script: str, argv: list[str] | tuple[str, ...]) -> str:
    """Build the exact command text hooks inspect. Shared by self-test and runtime."""
    if not isinstance(script, str) or not script:
        raise GatewayError("skill_hook_error", "Hook command script is invalid.")
    items = [script]
    for item in argv:
        if not isinstance(item, str) or not item or "\x00" in item:
            raise GatewayError("skill_hook_error", "Hook command argv is invalid.")
        items.append(item)
    return shlex.join(items)


def _parse_hook_manifest(text: str) -> tuple[HookSpec, ...]:
    data = _strict_json_text(text, source="hooks.json")
    if data.get("version") != 1:
        raise GatewayError("skill_bridge_unavailable", "Unsupported hooks.json version.")
    hooks = data.get("hooks")
    if not isinstance(hooks, dict) or set(hooks) != {"preToolUse"}:
        raise GatewayError("skill_bridge_unavailable", "hooks.json must define only preToolUse hooks in v1.")
    entries = hooks.get("preToolUse")
    if not isinstance(entries, list) or not entries:
        raise GatewayError("skill_bridge_unavailable", "hooks.json preToolUse must be a non-empty array.")

    result: list[HookSpec] = []
    seen: set[str] = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict) or set(entry) != {"command", "matcher", "timeout"}:
            raise GatewayError("skill_bridge_unavailable", f"hooks.json preToolUse[{index}] has unsupported fields.")
        command = entry.get("command")
        matcher = entry.get("matcher")
        timeout = entry.get("timeout")
        if not isinstance(command, str) or matcher != "Shell" or type(timeout) is not int or not 1 <= timeout <= 30:
            raise GatewayError("skill_bridge_unavailable", f"hooks.json preToolUse[{index}] has unsupported fields.")
        matches = _HOOK_PATH.findall(command)
        if len(matches) != 1:
            raise GatewayError("skill_bridge_unavailable", f"hooks.json preToolUse[{index}] does not map to one hook script.")
        script_name = matches[0]
        name = script_name[:-3]
        if name in seen:
            raise GatewayError("skill_bridge_unavailable", "hooks.json contains duplicate hook names.")
        seen.add(name)
        result.append(HookSpec(name, script_name, timeout))
    return tuple(result)


class ExistingHookRunner:
    """Run audited existing hooks as defense-in-depth. No manifest shell command is executed."""

    def __init__(self, gateway: Gateway, validator: AuditValidator, policy: AuditPolicy):
        self.gateway = gateway
        self.validator = validator
        self.policy = policy
        self.codeagent_path = gateway._root_path.joinpath(*validator.root_parts)
        self.skills_path = self.codeagent_path / "skills"
        self.hooks_path = self.codeagent_path / "hooks"
        self.specs = self._load_and_validate_manifest()
        self.tests = {item.name: item for item in policy.hook_tests}
        manifest_names = {item.name for item in self.specs}
        policy_names = set(self.tests)
        if manifest_names != policy_names:
            raise GatewayError("skill_bridge_unavailable", "Hook self-test coverage does not match hooks.json.")

    def _load_and_validate_manifest(self) -> tuple[HookSpec, ...]:
        if not self.validator.verify_exact_hash(
            self.policy.hooks_manifest_path,
            self.policy.hooks_manifest_sha256,
        ):
            raise GatewayError("skill_bridge_unavailable", "hooks.json audit hash mismatch.")
        snapshot = self.validator.snapshot(self.policy.hooks_manifest_path)
        return _parse_hook_manifest(snapshot.text)

    def _hook_snapshot(self, relative_script: str):
        rel_parts = _parts(relative_script)
        if len(rel_parts) != 2 or rel_parts[0] != "hooks":
            raise GatewayError("skill_bridge_unavailable", "Hook policy script path is invalid.")
        canonical = "/".join((*self.validator.root_parts, *rel_parts))
        parts = self.gateway._checked(canonical, is_file=True)
        return self.gateway._snapshot(parts)

    def validate_hook_hashes(self) -> None:
        for spec in self.specs:
            policy = self.tests[spec.name]
            if policy.script != f"hooks/{spec.script_name}":
                raise GatewayError("skill_bridge_unavailable", "Hook policy path does not match hooks.json.")
            snapshot = self._hook_snapshot(policy.script)
            if snapshot.sha256 != policy.sha256:
                raise GatewayError("skill_bridge_unavailable", "Hook script audit hash mismatch.")

    def _expand_value(self, value: str) -> str:
        marker = "$SKILL_ROOT"
        if value == marker:
            return str(self.skills_path)
        if value.startswith(marker + "/"):
            suffix = value[len(marker) + 1 :]
            parts = _parts(suffix)
            return str(self.skills_path.joinpath(*parts))
        return value

    def command_for_case(self, case: HookCase) -> str:
        script = self._expand_value(case.script)
        argv = [self._expand_value(item) for item in case.argv]
        return build_hook_command(script, argv)

    @staticmethod
    def _parse_result(exit_code: int, stdout: str) -> HookResult:
        if exit_code == 0 and stdout == "":
            return HookResult("allow")
        if exit_code == 2:
            try:
                data = json.loads(stdout)
            except (json.JSONDecodeError, UnicodeError, TypeError):
                raise GatewayError("skill_hook_error", "Hook deny output is malformed.") from None
            try:
                decision = data["hookSpecificOutput"]["permissionDecision"]
            except (KeyError, TypeError):
                raise GatewayError("skill_hook_error", "Hook deny output is malformed.") from None
            if decision == "deny":
                return HookResult("deny")
        raise GatewayError("skill_hook_error", "Hook returned an invalid exit/stdout combination.")

    def _run_one(self, spec: HookSpec, command: str) -> HookResult:
        hook_path = self.hooks_path / spec.script_name
        payload = json.dumps({"tool_input": {"command": command}}, separators=(",", ":"))
        env = {key: value for key in _SAFE_ENV_KEYS if (value := os.environ.get(key))}
        env["PATH"] = os.environ.get("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        try:
            process = subprocess.Popen(
                ["bash", str(hook_path)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=str(self.codeagent_path),
                env=env,
                start_new_session=True,
            )
        except OSError:
            raise GatewayError("skill_hook_error", "Hook could not be started.") from None
        try:
            stdout, _stderr = process.communicate(payload, timeout=spec.timeout_seconds)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except OSError:
                process.kill()
            process.wait()
            raise GatewayError("skill_hook_error", "Hook timed out.") from None
        return self._parse_result(process.returncode, stdout)

    def validate_common_freshness(self) -> None:
        current_specs = self._load_and_validate_manifest()
        if current_specs != self.specs:
            raise GatewayError("skill_bridge_unavailable", "Hook manifest changed after startup.")
        self.validate_hook_hashes()

    def run_all_for_command(self, command: str) -> None:
        """Runtime defense-in-depth entrypoint. Any deny/error rejects the command."""
        self.validate_common_freshness()
        for spec in self.specs:
            result = self._run_one(spec, command)
            if result.decision == "deny":
                raise GatewayError("skill_hook_denied", "Existing safety hook denied the Skill command.")

    def self_test(self) -> None:
        self.validate_hook_hashes()
        try:
            for spec in self.specs:
                policy = self.tests[spec.name]
                for case in policy.must_allow:
                    result = self._run_one(spec, self.command_for_case(case))
                    if result.decision != "allow":
                        raise GatewayError("skill_hook_selftest_failed", "Hook must-allow self-test failed.")
                for case in policy.must_deny:
                    result = self._run_one(spec, self.command_for_case(case))
                    if result.decision != "deny":
                        raise GatewayError("skill_hook_selftest_failed", "Hook must-deny self-test failed.")
        except GatewayError as exc:
            if exc.code in {"skill_bridge_unavailable", "skill_hook_selftest_failed"}:
                raise
            raise GatewayError("skill_hook_selftest_failed", "Hook startup self-test failed.") from None


__all__ = ["ExistingHookRunner", "HookResult", "HookSpec", "build_hook_command"]
