import hashlib
import json
from pathlib import Path
import shlex

import pytest

from gateway.core import Gateway, GatewayError
from gateway.local_skills.config import AuditValidator, load_audit_policy
from gateway.local_skills.hooks import ExistingHookRunner, build_hook_command


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _policy_dir(tmp_path: Path, project: Path, *, hook_body: str, allow_script: str = "echo", allow_argv=None,
                 deny_script: str = "echo", deny_argv=None, timeout: int = 2) -> Path:
    allow_argv = ["ALLOW"] if allow_argv is None else allow_argv
    deny_argv = ["DENY"] if deny_argv is None else deny_argv
    codeagent = project / "agent-runtime"
    hooks = codeagent / "hooks"
    skill = codeagent / "skills" / "demo"
    hooks.mkdir(parents=True)
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text("# demo\n", encoding="utf-8")
    (hooks / "guard.sh").write_text(hook_body, encoding="utf-8")
    (codeagent / "hooks.json").write_text(json.dumps({
        "version": 1,
        "hooks": {"preToolUse": [{
            "command": "bash \"$(git rev-parse --show-toplevel)/hooks/guard.sh\"",
            "matcher": "Shell",
            "timeout": timeout,
        }]},
    }), encoding="utf-8")

    policy = tmp_path / "policy"
    policy.mkdir()
    (policy / "skill-compatibility.json").write_text(json.dumps({
        "schema_version": 1,
        "skills": {
            "demo": {
                "role": "entry",
                "disposition": "PASS_WITH_CONSTRAINTS",
                "evidence": [{
                    "id": "demo",
                    "kind": "code_fact",
                    "path": "agent-runtime/skills/demo/SKILL.md",
                    "sha256": _sha(skill / "SKILL.md"),
                }],
            }
        },
    }), encoding="utf-8")
    (policy / "hook-selftests.json").write_text(json.dumps({
        "schema_version": 1,
        "hooks_manifest": {
            "path": "agent-runtime/hooks.json",
            "sha256": _sha(codeagent / "hooks.json"),
        },
        "hooks": [{
            "name": "guard",
            "script": "hooks/guard.sh",
            "sha256": _sha(hooks / "guard.sh"),
            "must_allow": [{"id": "allow", "script": allow_script, "argv": allow_argv}],
            "must_deny": [{"id": "deny", "script": deny_script, "argv": deny_argv}],
        }],
    }), encoding="utf-8")
    return policy


GOOD_HOOK = (
    "#!/bin/bash\n"
    "INPUT=$(cat)\n"
    "if echo \"$INPUT\" | grep -q DENY; then\n"
    "  echo '{\"hookSpecificOutput\":{\"permissionDecision\":\"deny\"}}'\n"
    "  exit 2\n"
    "fi\n"
    "exit 0\n"
)


def _runner(tmp_path: Path, project: Path, **kwargs):
    policy_dir = _policy_dir(tmp_path, project, hook_body=kwargs.pop("hook_body", GOOD_HOOK), **kwargs)
    gateway = Gateway(project)
    policy = load_audit_policy(policy_dir)
    validator = AuditValidator(gateway, "agent-runtime", policy)
    return gateway, ExistingHookRunner(gateway, validator, policy)


def test_command_builder_matches_shlex_join():
    script = "bash"
    argv = ["/tmp/a b/script.sh", "SELECT 'quoted'"]
    assert build_hook_command(script, argv) == shlex.join([script, *argv])


def test_hook_selftest_is_bidirectional(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    gateway, runner = _runner(tmp_path, project)
    try:
        runner.self_test()
    finally:
        gateway.close()


def test_hook_manifest_hash_mismatch_fails_closed(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    policy_dir = _policy_dir(tmp_path, project, hook_body=GOOD_HOOK)
    policy = load_audit_policy(policy_dir)
    (project / "agent-runtime" / "hooks.json").write_text('{"version":1,"hooks":{"preToolUse":[]}}', encoding="utf-8")
    gateway = Gateway(project)
    try:
        validator = AuditValidator(gateway, "agent-runtime", policy)
        with pytest.raises(GatewayError) as exc:
            ExistingHookRunner(gateway, validator, policy)
        assert exc.value.code == "skill_bridge_unavailable"
    finally:
        gateway.close()


def test_hook_script_hash_mismatch_fails_closed(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    policy_dir = _policy_dir(tmp_path, project, hook_body=GOOD_HOOK)
    policy = load_audit_policy(policy_dir)
    (project / "agent-runtime" / "hooks" / "guard.sh").write_text("#!/bin/bash\nexit 0\n", encoding="utf-8")
    gateway = Gateway(project)
    try:
        validator = AuditValidator(gateway, "agent-runtime", policy)
        runner = ExistingHookRunner(gateway, validator, policy)
        with pytest.raises(GatewayError) as exc:
            runner.self_test()
        assert exc.value.code == "skill_bridge_unavailable"
    finally:
        gateway.close()


def test_new_manifest_hook_without_policy_vector_fails_closed(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    policy_dir = _policy_dir(tmp_path, project, hook_body=GOOD_HOOK)
    hook2 = project / "agent-runtime" / "hooks" / "second.sh"
    hook2.write_text(GOOD_HOOK, encoding="utf-8")
    hooks_json = project / "agent-runtime" / "hooks.json"
    data = json.loads(hooks_json.read_text())
    data["hooks"]["preToolUse"].append({
        "command": "bash \"$(git rev-parse --show-toplevel)/hooks/second.sh\"",
        "matcher": "Shell",
        "timeout": 2,
    })
    hooks_json.write_text(json.dumps(data), encoding="utf-8")
    hook_policy_path = policy_dir / "hook-selftests.json"
    hook_policy = json.loads(hook_policy_path.read_text())
    hook_policy["hooks_manifest"]["sha256"] = _sha(hooks_json)
    hook_policy_path.write_text(json.dumps(hook_policy), encoding="utf-8")

    gateway = Gateway(project)
    try:
        policy = load_audit_policy(policy_dir)
        validator = AuditValidator(gateway, "agent-runtime", policy)
        with pytest.raises(GatewayError) as exc:
            ExistingHookRunner(gateway, validator, policy)
        assert exc.value.code == "skill_bridge_unavailable"
    finally:
        gateway.close()


def test_hook_malformed_deny_json_is_error(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    bad = (
        "#!/bin/bash\n"
        "cat >/dev/null\n"
        "echo not-json\n"
        "exit 2\n"
    )
    gateway, runner = _runner(tmp_path, project, hook_body=bad)
    try:
        with pytest.raises(GatewayError) as exc:
            runner.self_test()
        assert exc.value.code == "skill_hook_selftest_failed"
    finally:
        gateway.close()


def test_hook_timeout_is_error(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    slow = (
        "#!/bin/bash\n"
        "cat >/dev/null\n"
        "sleep 2\n"
        "exit 0\n"
    )
    gateway, runner = _runner(tmp_path, project, hook_body=slow, timeout=1)
    try:
        with pytest.raises(GatewayError) as exc:
            runner.self_test()
        assert exc.value.code == "skill_hook_selftest_failed"
    finally:
        gateway.close()


def test_allow_requires_truly_empty_stdout(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    noisy = (
        "#!/bin/bash\n"
        "cat >/dev/null\n"
        "echo unexpected\n"
        "exit 0\n"
    )
    gateway, runner = _runner(tmp_path, project, hook_body=noisy)
    try:
        with pytest.raises(GatewayError) as exc:
            runner.self_test()
        assert exc.value.code == "skill_hook_selftest_failed"
    finally:
        gateway.close()


def test_runtime_rechecks_hook_hashes(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    gateway, runner = _runner(tmp_path, project)
    try:
        runner.self_test()
        (project / "agent-runtime" / "hooks" / "guard.sh").write_text("#!/bin/bash\nexit 0\n", encoding="utf-8")
        with pytest.raises(GatewayError) as exc:
            runner.run_all_for_command("echo ALLOW")
        assert exc.value.code == "skill_bridge_unavailable"
    finally:
        gateway.close()


def test_runtime_hook_deny_blocks_command(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    gateway, runner = _runner(tmp_path, project)
    try:
        runner.self_test()
        with pytest.raises(GatewayError) as exc:
            runner.run_all_for_command("echo DENY")
        assert exc.value.code == "skill_hook_denied"
    finally:
        gateway.close()


def test_hook_manifest_rejects_unknown_fields(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    policy_dir = _policy_dir(tmp_path, project, hook_body=GOOD_HOOK)
    hooks_json = project / "agent-runtime" / "hooks.json"
    data = json.loads(hooks_json.read_text())
    data["hooks"]["preToolUse"][0]["unexpected"] = True
    hooks_json.write_text(json.dumps(data), encoding="utf-8")
    hook_policy_path = policy_dir / "hook-selftests.json"
    hook_policy = json.loads(hook_policy_path.read_text())
    hook_policy["hooks_manifest"]["sha256"] = _sha(hooks_json)
    hook_policy_path.write_text(json.dumps(hook_policy), encoding="utf-8")

    gateway = Gateway(project)
    try:
        policy = load_audit_policy(policy_dir)
        validator = AuditValidator(gateway, "agent-runtime", policy)
        with pytest.raises(GatewayError) as exc:
            ExistingHookRunner(gateway, validator, policy)
        assert exc.value.code == "skill_bridge_unavailable"
    finally:
        gateway.close()
