import hashlib
import json
from pathlib import Path

import pytest

from gateway.core import Gateway, GatewayError
from gateway.local_skills.config import AuditValidator, SkillFreshness, load_audit_policy
from gateway.local_skills.reader import SkillReader
from gateway.local_skills.registry import SkillRegistry
from gateway.local_skills.runs import SkillRunStore


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _setup(tmp_path):
    project = tmp_path / "project"
    codeagent = project / "agent-runtime"
    entry = codeagent / "skills" / "entry"
    dep = codeagent / "skills" / "dep"
    for root in (entry, dep):
        (root / "references").mkdir(parents=True)
        (root / "schemas").mkdir()
        (root / "scripts").mkdir()
    (entry / "SKILL.md").write_text(
        "# Entry\nAbsolute: " + str(project) + "/agent-runtime/skills/entry\npassword: hidden-value\n",
        encoding="utf-8",
    )
    (entry / "references" / "guide.md").write_text("guide\n", encoding="utf-8")
    (entry / "schemas" / "table.md").write_text("schema\n", encoding="utf-8")
    (entry / "scripts" / "run.sh").write_text("#!/bin/bash\n", encoding="utf-8")
    (dep / "SKILL.md").write_text("# Dependency\n", encoding="utf-8")
    (dep / "references" / "dep.md").write_text("dep ref\n", encoding="utf-8")

    hooks = codeagent / "hooks"
    hooks.mkdir()
    hook = hooks / "guard.sh"
    hook.write_text("#!/bin/bash\nexit 0\n", encoding="utf-8")
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
            "entry": {
                "kind": "shell",
                "role": "entry",
                "disposition": "PASS_WITH_CONSTRAINTS",
                "allowed_scripts": ["scripts/run.sh"],
                "disabled_workflows": ["sync"],
                "dependencies": [{"skill": "dep", "access": "read_only"}],
                "evidence": [{
                    "id": "entry-skill",
                    "kind": "code_fact",
                    "path": "agent-runtime/skills/entry/SKILL.md",
                    "sha256": _sha(entry / "SKILL.md"),
                }],
            },
            "dep": {
                "role": "dependency_only",
                "disposition": "PASS_WITH_CONSTRAINTS",
                "allowed_scripts": [],
                "disabled_workflows": [],
                "dependencies": [],
                "evidence": [{
                    "id": "dep-skill",
                    "kind": "code_fact",
                    "path": "agent-runtime/skills/dep/SKILL.md",
                    "sha256": _sha(dep / "SKILL.md"),
                }],
            },
        },
    }
    (policy / "skill-compatibility.json").write_text(json.dumps(compatibility), encoding="utf-8")
    (policy / "hook-selftests.json").write_text(json.dumps({
        "schema_version": 1,
        "hooks_manifest": {"path": "agent-runtime/hooks.json", "sha256": _sha(hooks_json)},
        "hooks": [{
            "name": "guard",
            "script": "hooks/guard.sh",
            "sha256": _sha(hook),
            "must_allow": [{"id": "a", "script": "echo", "argv": ["ALLOW"]}],
            "must_deny": [{"id": "d", "script": "echo", "argv": ["DENY"]}],
        }],
    }), encoding="utf-8")

    gateway = Gateway(project)
    loaded = load_audit_policy(policy)
    validator = AuditValidator(gateway, "agent-runtime", loaded)
    freshness = {name: SkillFreshness(True) for name in loaded.compatibility["skills"]}
    registry = SkillRegistry(loaded, freshness)
    reader = SkillReader(gateway, validator, registry, SkillRunStore())
    return project, gateway, reader


def test_begin_returns_overlay_inventory_and_no_absolute_root(tmp_path):
    project, gateway, reader = _setup(tmp_path)
    try:
        result = reader.begin("entry", "inspect")
        assert "Local Skill Bridge Web Mode Overlay" in result["content"]
        assert str(project) not in result["content"]
        assert "hidden-value" not in result["content"]
        assert "references/guide.md" in result["references"]
        assert "schemas/table.md" in result["schemas"]
        assert result["allowed_scripts"] == ["scripts/run.sh"]
        assert result["dependencies"] == [{"skill": "dep", "access": "read_only"}]
    finally:
        gateway.close()


def test_dependency_skill_md_also_gets_overlay(tmp_path):
    _project, gateway, reader = _setup(tmp_path)
    try:
        begin = reader.begin("entry", "inspect")
        result = reader.read(begin["skill_run_id"], "entry", "../dep/SKILL.md")
        assert result["skill"] == "dep"
        assert "Local Skill Bridge Web Mode Overlay" in result["content"]
    finally:
        gateway.close()


def test_script_source_is_not_readable(tmp_path):
    _project, gateway, reader = _setup(tmp_path)
    try:
        begin = reader.begin("entry", "inspect")
        with pytest.raises(GatewayError) as exc:
            reader.read(begin["skill_run_id"], "entry", "scripts/run.sh")
        assert exc.value.code == "skill_file_not_allowed"
    finally:
        gateway.close()


def test_unlisted_cross_skill_read_rejected(tmp_path):
    _project, gateway, reader = _setup(tmp_path)
    try:
        begin = reader.begin("entry", "inspect")
        with pytest.raises(GatewayError) as exc:
            reader.read(begin["skill_run_id"], "entry", "../other/SKILL.md")
        assert exc.value.code == "skill_dependency_not_allowed"
    finally:
        gateway.close()


def test_source_change_after_begin_fails_closed(tmp_path):
    project, gateway, reader = _setup(tmp_path)
    try:
        begin = reader.begin("entry", "inspect")
        (project / "agent-runtime" / "skills" / "entry" / "SKILL.md").write_text("# changed\n", encoding="utf-8")
        with pytest.raises(GatewayError) as exc:
            reader.read(begin["skill_run_id"], "entry", "references/guide.md")
        assert exc.value.code == "skill_audit_stale"
    finally:
        gateway.close()


def test_sanitizer_hides_home_agent_config_and_ssh_paths(tmp_path, monkeypatch):
    _project, gateway, reader = _setup(tmp_path)
    try:
        home = str(Path.home())
        value, _redacted = reader._sanitize_text(
            home + "/.agent-config/local-settings.sh\n" + home + "/.ssh/id_ed25519\n"
        )
        assert home not in value
        assert "$AGENT_CONFIG/local-settings.sh" in value
        assert "$SSH_DIR/id_ed25519" in value
    finally:
        gateway.close()
