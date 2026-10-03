import hashlib
import json
from pathlib import Path

import pytest

from gateway.core import Gateway, GatewayError
from gateway.local_skills.config import AuditValidator, default_policy_dir, load_audit_policy


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_minimal_policy(base: Path, project: Path) -> None:
    policy = base / "policy"
    policy.mkdir(parents=True)
    skill_file = project / "agent-runtime" / "skills" / "demo" / "SKILL.md"
    compatibility = {
        "schema_version": 1,
        "skills": {
            "demo": {
                "role": "entry",
                "disposition": "PASS_WITH_CONSTRAINTS",
                "evidence": [{
                    "id": "demo",
                    "kind": "code_fact",
                    "path": "agent-runtime/skills/demo/SKILL.md",
                    "sha256": _sha(skill_file),
                }],
            }
        },
    }
    hook_script = project / "agent-runtime" / "hooks" / "guard.sh"
    hooks_json = project / "agent-runtime" / "hooks.json"
    hook_policy = {
        "schema_version": 1,
        "hooks_manifest": {
            "path": "agent-runtime/hooks.json",
            "sha256": _sha(hooks_json),
        },
        "hooks": [{
            "name": "guard",
            "script": "hooks/guard.sh",
            "sha256": _sha(hook_script),
            "must_allow": [{"id": "allow", "script": "echo", "argv": ["ALLOW"]}],
            "must_deny": [{"id": "deny", "script": "echo", "argv": ["DENY"]}],
        }],
    }
    (policy / "skill-compatibility.json").write_text(json.dumps(compatibility), encoding="utf-8")
    (policy / "hook-selftests.json").write_text(json.dumps(hook_policy), encoding="utf-8")


@pytest.fixture
def project(tmp_path):
    root = tmp_path / "project"
    skill = root / "agent-runtime" / "skills" / "demo"
    hooks = root / "agent-runtime" / "hooks"
    skill.mkdir(parents=True)
    hooks.mkdir(parents=True)
    (skill / "SKILL.md").write_text("# demo\n", encoding="utf-8")
    (hooks / "guard.sh").write_text(
        "#!/bin/bash\n"
        "INPUT=$(cat)\n"
        "if echo \"$INPUT\" | grep -q DENY; then\n"
        "  echo '{\"hookSpecificOutput\":{\"permissionDecision\":\"deny\"}}'\n"
        "  exit 2\n"
        "fi\n"
        "exit 0\n",
        encoding="utf-8",
    )
    (root / "agent-runtime" / "hooks.json").write_text(json.dumps({
        "version": 1,
        "hooks": {"preToolUse": [{
            "command": "bash \"$(git rev-parse --show-toplevel)/hooks/guard.sh\"",
            "matcher": "Shell",
            "timeout": 2,
        }]},
    }), encoding="utf-8")
    return root


def test_default_policy_dir_is_private_local_config(monkeypatch, tmp_path):
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    assert default_policy_dir() == tmp_path / ".config" / "mac-file-gateway" / "local-skill-policy"
    with pytest.raises(GatewayError) as exc:
        load_audit_policy()
    assert exc.value.code == "skill_bridge_unavailable"


def test_load_and_validate_current_skill_hash(tmp_path, project):
    _write_minimal_policy(tmp_path, project)
    policy = load_audit_policy(tmp_path / "policy")
    gateway = Gateway(project)
    try:
        validator = AuditValidator(gateway, "agent-runtime", policy)
        status = validator.validate_skill("demo")
        assert status.available is True
        assert status.reason is None
    finally:
        gateway.close()


def test_stale_skill_hash_marks_only_skill_unavailable(tmp_path, project):
    _write_minimal_policy(tmp_path, project)
    policy = load_audit_policy(tmp_path / "policy")
    (project / "agent-runtime" / "skills" / "demo" / "SKILL.md").write_text("# changed\n", encoding="utf-8")
    gateway = Gateway(project)
    try:
        status = AuditValidator(gateway, "agent-runtime", policy).validate_skill("demo")
        assert status.available is False
        assert status.reason == "skill_audit_stale"
    finally:
        gateway.close()


def test_policy_duplicate_json_key_rejected(tmp_path, project):
    _write_minimal_policy(tmp_path, project)
    path = tmp_path / "policy" / "skill-compatibility.json"
    path.write_text('{"schema_version":1,"schema_version":1,"skills":{}}', encoding="utf-8")
    with pytest.raises(GatewayError) as exc:
        load_audit_policy(tmp_path / "policy")
    assert exc.value.code == "skill_bridge_unavailable"


def test_policy_unsupported_schema_version_rejected(tmp_path, project):
    _write_minimal_policy(tmp_path, project)
    path = tmp_path / "policy" / "skill-compatibility.json"
    data = json.loads(path.read_text())
    data["schema_version"] = 2
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(GatewayError) as exc:
        load_audit_policy(tmp_path / "policy")
    assert exc.value.code == "skill_bridge_unavailable"


def test_hook_policy_requires_script_plus_argv(tmp_path, project):
    _write_minimal_policy(tmp_path, project)
    path = tmp_path / "policy" / "hook-selftests.json"
    data = json.loads(path.read_text())
    case = data["hooks"][0]["must_allow"][0]
    case["command"] = "echo ALLOW"
    del case["script"]
    with pytest.raises(GatewayError) as exc:
        path.write_text(json.dumps(data), encoding="utf-8")
        load_audit_policy(tmp_path / "policy")
    assert exc.value.code == "skill_bridge_unavailable"


def test_audited_path_must_stay_under_configured_root(tmp_path, project):
    _write_minimal_policy(tmp_path, project)
    path = tmp_path / "policy" / "skill-compatibility.json"
    data = json.loads(path.read_text())
    data["skills"]["demo"]["evidence"][0]["path"] = "other/SKILL.md"
    path.write_text(json.dumps(data), encoding="utf-8")
    policy = load_audit_policy(tmp_path / "policy")
    gateway = Gateway(project)
    try:
        status = AuditValidator(gateway, "agent-runtime", policy).validate_skill("demo")
        assert status.available is False
        assert status.reason == "skill_audit_stale"
    finally:
        gateway.close()


def test_policy_rejects_nonstandard_json_constants(tmp_path, project):
    _write_minimal_policy(tmp_path, project)
    path = tmp_path / "policy" / "skill-compatibility.json"
    path.write_text('{"schema_version":1,"skills":{"demo":{"role":"entry","disposition":"PASS_WITH_CONSTRAINTS","evidence":[]}},"bad":NaN}', encoding="utf-8")
    with pytest.raises(GatewayError) as exc:
        load_audit_policy(tmp_path / "policy")
    assert exc.value.code == "skill_bridge_unavailable"


def test_policy_nonstandard_json_constant_rejected(tmp_path, project):
    _write_minimal_policy(tmp_path, project)
    path = tmp_path / "policy" / "skill-compatibility.json"
    path.write_text('{"schema_version":1,"skills":{},"bad":NaN}', encoding="utf-8")
    with pytest.raises(GatewayError) as exc:
        load_audit_policy(tmp_path / "policy")
    assert exc.value.code == "skill_bridge_unavailable"
