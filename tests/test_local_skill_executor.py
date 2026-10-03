import hashlib
import os
from pathlib import Path

import pytest

from gateway.core import Gateway, GatewayError
from gateway.local_skills.args import SkillArgValidator
from gateway.local_skills.config import AuditPolicy, AuditValidator, SkillFreshness
from gateway.local_skills.executor import SkillScriptExecutor
from gateway.local_skills.registry import SkillRegistry
from gateway.local_skills.runs import SkillRunStore


class FakeHooks:
    def __init__(self):
        self.commands = []

    def run_all_for_command(self, command):
        self.commands.append(command)


class FakeSql:
    def validate(self, *args, **kwargs):
        raise AssertionError("SQL gate should not run for demo Skill")


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _tree_hash(path: Path) -> str:
    digest = hashlib.sha256()
    for item in sorted(p for p in path.rglob("*") if p.is_file()):
        digest.update(item.relative_to(path).as_posix().encode())
        digest.update(item.read_bytes())
    return digest.hexdigest()


def _setup(tmp_path):
    project = tmp_path / "project"
    skill = project / "agent-runtime" / "skills" / "demo"
    scripts = skill / "scripts"
    scripts.mkdir(parents=True)
    (skill / "SKILL.md").write_text("# demo\n", encoding="utf-8")
    (scripts / "helper.py").write_text("VALUE = 'helper-ok'\n", encoding="utf-8")
    (scripts / "run.sh").write_text(
        "#!/bin/bash\n"
        "set -e\n"
        "SCRIPT_DIR=$(cd \"$(dirname \"$0\")\" && pwd)\n"
        "echo \"cwd=$PWD\"\n"
        "echo \"dontwrite=$PYTHONDONTWRITEBYTECODE\"\n"
        "PYTHONPATH=\"$SCRIPT_DIR\" python3 -c 'import helper; print(helper.VALUE)'\n"
        "if read value; then echo \"stdin=$value\"; else echo \"stdin=closed\"; fi\n"
        "echo \"password=topsecret\"\n"
        "echo \"arg=$1\"\n",
        encoding="utf-8",
    )
    (scripts / "slow.sh").write_text("#!/bin/bash\nsleep 3\n", encoding="utf-8")
    (scripts / "big.sh").write_text("#!/bin/bash\npython3 -c \"print('x' * 60000)\"\n", encoding="utf-8")

    evidence = []
    for name in ("SKILL.md", "scripts/run.sh", "scripts/slow.sh", "scripts/big.sh", "scripts/helper.py"):
        path = skill / name
        evidence.append({
            "id": name,
            "kind": "code_fact",
            "path": "agent-runtime/skills/demo/" + name,
            "sha256": _sha(path),
        })
    compatibility = {
        "schema_version": 1,
        "skills": {
            "demo": {
                "kind": "shell",
                "role": "entry",
                "disposition": "PASS_WITH_CONSTRAINTS",
                "allowed_scripts": ["scripts/run.sh", "scripts/slow.sh", "scripts/big.sh"],
                "disabled_workflows": [],
                "dependencies": [],
                "argv": {
                    "scripts/run.sh": [{"index": 0, "name": "value", "required": False, "default": "ok"}],
                    "scripts/slow.sh": [],
                    "scripts/big.sh": [],
                },
                "evidence": evidence,
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
    policy = AuditPolicy(
        compatibility=compatibility,
        hooks_manifest_path="agent-runtime/hooks.json",
        hooks_manifest_sha256="0" * 64,
        hook_tests=(),
    )
    gateway = Gateway(project)
    validator = AuditValidator(gateway, "agent-runtime", policy)
    freshness = {name: SkillFreshness(True) for name in compatibility["skills"]}
    registry = SkillRegistry(policy, freshness)
    runs = SkillRunStore()
    run = runs.create(registry, "demo")
    hooks = FakeHooks()
    executor = SkillScriptExecutor(
        gateway,
        validator,
        registry,
        runs,
        SkillArgValidator(registry),
        FakeSql(),
        hooks,
        artifact_root=tmp_path / "artifacts",
    )
    return gateway, skill, run, hooks, executor, tmp_path / "artifacts"


def test_executor_uses_artifact_cwd_closed_stdin_and_no_bytecode(tmp_path):
    gateway, skill, run, hooks, executor, artifacts = _setup(tmp_path)
    before = _tree_hash(skill)
    try:
        result = executor.run(run.skill_run_id, "demo", "scripts/run.sh", ["hello"])
        assert result["exit_code"] == 0
        assert result["timed_out"] is False
        assert "helper-ok" in result["stdout"]
        assert "dontwrite=1" in result["stdout"]
        assert "stdin=closed" in result["stdout"]
        assert "topsecret" not in result["stdout"]
        assert "[REDACTED]" in result["stdout"]
        assert "arg=hello" in result["stdout"]
        assert hooks.commands and "scripts/run.sh" in hooks.commands[0]
        assert not hooks.commands[0].startswith("bash ")
        run_dir = artifacts / run.skill_run_id
        assert run_dir.is_dir()
        assert os.stat(run_dir).st_mode & 0o777 == 0o700
        assert not any(p.name == "__pycache__" for p in skill.rglob("__pycache__"))
        assert _tree_hash(skill) == before
    finally:
        gateway.close()


def test_executor_rejects_nonallowlisted_script(tmp_path):
    gateway, _skill, run, _hooks, executor, _artifacts = _setup(tmp_path)
    try:
        with pytest.raises(GatewayError) as exc:
            executor.run(run.skill_run_id, "demo", "scripts/not-allowed.sh", [])
        assert exc.value.code == "skill_script_not_allowed"
    finally:
        gateway.close()


def test_executor_timeout_kills_process(tmp_path):
    gateway, _skill, run, _hooks, executor, _artifacts = _setup(tmp_path)
    try:
        result = executor.run(run.skill_run_id, "demo", "scripts/slow.sh", [], timeout_seconds=1)
        assert result["timed_out"] is True
        assert result["exit_code"] is None
    finally:
        gateway.close()


def test_executor_bounds_large_output(tmp_path):
    gateway, _skill, run, _hooks, executor, _artifacts = _setup(tmp_path)
    try:
        result = executor.run(run.skill_run_id, "demo", "scripts/big.sh", [])
        assert result["stdout_truncated"] is True
        assert len(result["stdout"]) <= 48000
    finally:
        gateway.close()
