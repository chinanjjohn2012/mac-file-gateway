import copy
import json
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from gateway.core import Gateway, GatewayError
from gateway.local_skills.bridge import LocalSkillBridge
from gateway.local_skills.config import load_audit_policy
from gateway.local_skills.sql_policy import SqlPolicyGate
from tools.collect_local_skill_policy import collect
from test_local_skill_bridge import _setup


def test_external_policy_cli_and_checker_use_same_directory(tmp_path):
    project, gateway, _bridge = _setup(tmp_path)
    gateway.close()
    args = [str(project), "--local-skill-root", "agent-runtime", "--local-skill-policy-dir", str(tmp_path / "policy")]
    check = subprocess.run([sys.executable, "tools/check_local_skill_bridge.py", *args], capture_output=True, text=True)
    assert check.returncode == 0, check.stdout
    assert json.loads(check.stdout)["status"] == "PASS"
    cli = subprocess.run([sys.executable, "-m", "gateway", "--root", *args, "--check"], capture_output=True, text=True)
    assert cli.returncode == 0, cli.stderr
    assert json.loads(cli.stdout)["local_skill_bridge"]["status"] == "enabled"
    assert str(tmp_path / "policy") not in cli.stdout


def test_policy_inside_project_is_disabled(tmp_path):
    project, gateway, _bridge = _setup(tmp_path)
    try:
        shutil.copytree(tmp_path / "policy", project / "untrusted-policy")
        bridge = LocalSkillBridge.create(gateway, "agent-runtime", policy_dir=project / "untrusted-policy")
        assert bridge.info()["status"] == "disabled"
        with pytest.raises(GatewayError):
            bridge.begin("demo", "run")
    finally:
        gateway.close()


def test_collector_preserves_permissions_and_creates_blocked_draft(tmp_path, monkeypatch):
    project, gateway, _bridge = _setup(tmp_path)
    gateway.close()
    policy_dir = tmp_path / "policy"
    before_bytes = (policy_dir / "skill-compatibility.json").read_bytes()
    before = json.loads(before_bytes)
    source = project / "agent-runtime" / "skills" / "demo" / "scripts" / "run.sh"
    source.write_text("#!/bin/bash\necho changed\n", encoding="utf-8")
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: pytest.fail("collector must not execute scripts"))
    draft_dir = tmp_path / "draft"
    report = collect(project, "agent-runtime", policy_dir, draft_dir)
    draft = json.loads((draft_dir / "skill-compatibility.json").read_text())
    assert (policy_dir / "skill-compatibility.json").read_bytes() == before_bytes
    assert report["scripts_executed"] is False
    assert report["permissions_updated"] is False
    assert any(change["status"] == "changed" for change in report["changes"])
    for name, record in before["skills"].items():
        expected = copy.deepcopy(record)
        actual = copy.deepcopy(draft["skills"][name])
        expected.pop("evidence", None)
        actual.pop("evidence", None)
        assert expected == actual
    assert draft_dir.stat().st_mode & 0o777 == 0o700
    for path in draft_dir.iterdir():
        assert path.stat().st_mode & 0o777 == 0o600
    with pytest.raises(GatewayError):
        load_audit_policy(draft_dir)
    with pytest.raises(GatewayError) as exc:
        collect(project, "agent-runtime", policy_dir, draft_dir)
    assert exc.value.code == "conflict"


def test_collector_reports_new_hook_without_granting_it(tmp_path):
    project, gateway, _bridge = _setup(tmp_path)
    gateway.close()
    path = project / "agent-runtime" / "hooks.json"
    manifest = json.loads(path.read_text())
    manifest["hooks"]["preToolUse"].append({"command": 'bash "$(git rev-parse --show-toplevel)/hooks/new-guard.sh"', "matcher": "Shell", "timeout": 2})
    path.write_text(json.dumps(manifest))
    output = tmp_path / "draft"
    report = collect(project, "agent-runtime", tmp_path / "policy", output)
    assert any(x["status"] == "requires_manual_audit" for x in report["changes"])
    assert len(json.loads((output / "hook-selftests.json").read_text())["hooks"]) == 1


def test_executable_policy_requires_explicit_kind(tmp_path):
    _project, gateway, _bridge = _setup(tmp_path)
    gateway.close()
    path = tmp_path / "policy" / "skill-compatibility.json"
    policy = json.loads(path.read_text())
    policy["skills"]["demo"].pop("kind")
    path.write_text(json.dumps(policy))
    with pytest.raises(GatewayError):
        load_audit_policy(path.parent)


def test_sql_policy_follows_kind_for_renamed_skill():
    root = Path(__file__).resolve().parents[1]
    policy = load_audit_policy(root / "samples" / "local-skill-policy")
    record = policy.compatibility["skills"].pop("sample-mysql")
    policy.compatibility["skills"]["arbitrary-private-name"] = record
    gate = SqlPolicyGate(policy)
    gate.validate("arbitrary-private-name", "SELECT 1")
    with pytest.raises(GatewayError):
        gate.validate("arbitrary-private-name", "DELETE FROM sample_table")
    with pytest.raises(GatewayError):
        gate.validate("arbitrary-private-name", "SELECT * FROM mysql.user")


def test_sql_rejection_happens_before_hook_for_renamed_script(tmp_path, monkeypatch):
    _project, gateway, bridge = _setup(tmp_path)
    try:
        path = tmp_path / "policy" / "skill-compatibility.json"
        policy = json.loads(path.read_text())
        policy["skills"]["demo"]["kind"] = "mysql"
        policy["skills"]["demo"]["argv"]["scripts/run.sh"] = [{"index": 0, "name": "sql", "required": True, "non_empty": True}]
        path.write_text(json.dumps(policy))
        bridge = LocalSkillBridge.create(gateway, "agent-runtime", policy_dir=path.parent)
        run = bridge.begin("demo", "query")
        monkeypatch.setattr(bridge._hooks, "run_all_for_command", lambda *a: pytest.fail("SQL rejection must precede hooks"))
        with pytest.raises(GatewayError) as exc:
            bridge.run(run["skill_run_id"], "demo", "scripts/run.sh", ["DELETE FROM sample_table"])
        assert exc.value.code == "skill_sql_not_readonly"
    finally:
        gateway.close()


@pytest.mark.parametrize("failure", ["draft-compatibility", "draft-hooks", "bad-kind", "missing-cloud-sections", "symlink-loop"])
def test_bad_external_policy_disables_bridge_without_stopping_gateway(tmp_path, failure):
    _project, gateway, _bridge = _setup(tmp_path)
    try:
        policy_dir = tmp_path / "policy"
        if failure == "symlink-loop":
            policy_dir = tmp_path / "loop"
            policy_dir.symlink_to(policy_dir)
        else:
            name = "hook-selftests.json" if failure == "draft-hooks" else "skill-compatibility.json"
            path = policy_dir / name
            data = json.loads(path.read_text())
            if failure.startswith("draft-"):
                data["review_status"] = "draft"
            elif failure == "bad-kind":
                data["skills"]["demo"]["kind"] = {"unexpected": "value"}
            else:
                data["skills"]["demo"]["kind"] = "cloud-api"
            path.write_text(json.dumps(data))
        bridge = LocalSkillBridge.create(gateway, "agent-runtime", policy_dir=policy_dir)
        assert bridge.info()["status"] == "disabled"
        assert gateway.info()["name"] == "Mac File Gateway"
        with pytest.raises(GatewayError):
            bridge.begin("demo", "run")
    finally:
        gateway.close()
