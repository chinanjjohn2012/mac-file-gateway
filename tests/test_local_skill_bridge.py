import hashlib
import json
from pathlib import Path

import pytest

from gateway.core import Gateway, GatewayError
from gateway.local_skills.bridge import LocalSkillBridge


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _setup(tmp_path, *, break_hook=False):
    project = tmp_path / "project"
    codeagent = project / "agent-runtime"
    entry = codeagent / "skills" / "demo"
    dep = codeagent / "skills" / "dep"
    hooks = codeagent / "hooks"
    for root in (entry, dep):
        (root / "references").mkdir(parents=True)
        (root / "schemas").mkdir()
        (root / "scripts").mkdir()
    hooks.mkdir(parents=True)

    (entry / "SKILL.md").write_text(
        "---\nname: demo\ndescription: Demo local query skill\n---\n# Demo\n",
        encoding="utf-8",
    )
    (entry / "references" / "guide.md").write_text("guide\n", encoding="utf-8")
    (entry / "scripts" / "run.sh").write_text("#!/bin/bash\necho \"ok:$1\"\n", encoding="utf-8")
    (dep / "SKILL.md").write_text(
        "---\nname: dep\ndescription: Dependency docs\n---\n# Dep\n",
        encoding="utf-8",
    )

    hook = hooks / "guard.sh"
    hook.write_text(
        "#!/bin/bash\n"
        "INPUT=$(cat)\n"
        "if echo \"$INPUT\" | grep -q BLOCK; then\n"
        "  echo '{\"hookSpecificOutput\":{\"permissionDecision\":\"deny\"}}'\n"
        "  exit 2\n"
        "fi\n"
        "exit 0\n",
        encoding="utf-8",
    )
    hooks_json = codeagent / "hooks.json"
    hooks_json.write_text(json.dumps({
        "version": 1,
        "hooks": {"preToolUse": [{
            "command": "bash \"$(git rev-parse --show-toplevel)/hooks/guard.sh\"",
            "matcher": "Shell",
            "timeout": 2,
        }]},
    }), encoding="utf-8")

    policy = tmp_path / "policy"
    policy.mkdir()
    compatibility = {
        "schema_version": 1,
        "skills": {
            "demo": {
                "kind": "shell",
                "role": "entry",
                "disposition": "PASS_WITH_CONSTRAINTS",
                "allowed_scripts": ["scripts/run.sh"],
                "disabled_workflows": [],
                "dependencies": [{"skill": "dep", "access": "read_only"}],
                "argv": {
                    "scripts/run.sh": [
                        {"index": 0, "name": "value", "required": False, "default": "hello"}
                    ]
                },
                "evidence": [
                    {"id": "demo-skill", "kind": "code_fact", "path": "agent-runtime/skills/demo/SKILL.md", "sha256": _sha(entry / "SKILL.md")},
                    {"id": "demo-run", "kind": "code_fact", "path": "agent-runtime/skills/demo/scripts/run.sh", "sha256": _sha(entry / "scripts" / "run.sh")},
                ],
            },
            "dep": {
                "role": "dependency_only",
                "disposition": "PASS_WITH_CONSTRAINTS",
                "allowed_scripts": [],
                "disabled_workflows": [],
                "dependencies": [],
                "evidence": [
                    {"id": "dep-skill", "kind": "code_fact", "path": "agent-runtime/skills/dep/SKILL.md", "sha256": _sha(dep / "SKILL.md")}
                ],
            },
            "sample-deferred": {
                "role": "deferred",
                "disposition": "DEFER",
                "allowed_scripts": [],
                "disabled_workflows": [],
                "dependencies": [],
                "evidence": [],
            },
            "sample-clickhouse": {
                "role": "deferred",
                "disposition": "DEFER",
                "allowed_scripts": [],
                "disabled_workflows": [],
                "dependencies": [],
                "realtime_time_columns": {},
                "small_schema_count": 0,
                "evidence": [],
            },
        },
    }
    (policy / "skill-compatibility.json").write_text(json.dumps(compatibility), encoding="utf-8")
    hook_hash = "0" * 64 if break_hook else _sha(hook)
    (policy / "hook-selftests.json").write_text(json.dumps({
        "schema_version": 1,
        "hooks_manifest": {"path": "agent-runtime/hooks.json", "sha256": _sha(hooks_json)},
        "hooks": [{
            "name": "guard",
            "script": "hooks/guard.sh",
            "sha256": hook_hash,
            "must_allow": [{"id": "allow", "script": "echo", "argv": ["ALLOW"]}],
            "must_deny": [{"id": "deny", "script": "echo", "argv": ["BLOCK"]}],
        }],
    }), encoding="utf-8")

    gateway = Gateway(project)
    bridge = LocalSkillBridge.create(
        gateway,
        "agent-runtime",
        policy_dir=policy,
        artifact_root=tmp_path / "artifacts",
    )
    return project, gateway, bridge


def test_bridge_info_begin_read_and_run(tmp_path):
    _project, gateway, bridge = _setup(tmp_path)
    try:
        info = bridge.info()
        assert info["status"] == "enabled"
        assert info["entries"] == [{
            "name": "demo",
            "description": "Demo local query skill",
            "available": True,
        }]
        begin = bridge.begin("demo", "run demo")
        assert "Local Skill Bridge Web Mode Overlay" in begin["content"]
        assert begin["dependencies"] == [{"skill": "dep", "access": "read_only"}]
        ref = bridge.read(begin["skill_run_id"], "demo", "references/guide.md")
        assert ref["content"] == "guide"
        result = bridge.run(begin["skill_run_id"], "demo", "scripts/run.sh", ["value"])
        assert result["exit_code"] == 0
        assert "ok:value" in result["stdout"]
    finally:
        gateway.close()


def test_dependency_only_and_deferred_cannot_begin(tmp_path):
    _project, gateway, bridge = _setup(tmp_path)
    try:
        for name in ("dep", "sample-deferred"):
            with pytest.raises(GatewayError) as exc:
                bridge.begin(name, "try")
            assert exc.value.code == "skill_not_available"
    finally:
        gateway.close()


def test_common_hook_failure_keeps_info_but_blocks_operations(tmp_path):
    _project, gateway, bridge = _setup(tmp_path, break_hook=True)
    try:
        info = bridge.info()
        assert info["status"] == "disabled"
        assert info["entries"] == []
        with pytest.raises(GatewayError) as exc:
            bridge.begin("demo", "run")
        assert exc.value.code == "skill_bridge_unavailable"
    finally:
        gateway.close()


def test_runtime_common_hash_change_disables_bridge(tmp_path):
    project, gateway, bridge = _setup(tmp_path)
    try:
        assert bridge.info()["status"] == "enabled"
        hook = project / "agent-runtime" / "hooks" / "guard.sh"
        hook.write_text("#!/bin/bash\nexit 0\n", encoding="utf-8")
        info = bridge.info()
        assert info["status"] == "disabled"
        with pytest.raises(GatewayError) as exc:
            bridge.begin("demo", "run")
        assert exc.value.code == "skill_bridge_unavailable"
    finally:
        gateway.close()
