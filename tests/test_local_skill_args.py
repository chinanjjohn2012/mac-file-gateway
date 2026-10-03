import json
from pathlib import Path

import pytest

from gateway.core import GatewayError
from gateway.local_skills.args import SkillArgValidator
from gateway.local_skills.config import SkillFreshness, load_audit_policy
from gateway.local_skills.registry import SkillRegistry


def _validator():
    policy = load_audit_policy(Path(__file__).resolve().parents[1] / "samples" / "local-skill-policy")
    freshness = {name: SkillFreshness(True) for name in policy.compatibility["skills"]}
    return SkillArgValidator(SkillRegistry(policy, freshness))


def test_standard_defaults_are_materialized():
    validator = _validator()
    assert validator.validate("sample-clickhouse", "scripts/ck_query.sh", ["SELECT 1"]) == ["SELECT 1", "sample-primary"]
    assert validator.validate("sample-mysql", "scripts/mysql_query.sh", ["SELECT 1"]) == ["SELECT 1", "pretty"]
    assert validator.validate("sample-metrics", "scripts/collect_prom.sh", ["up"]) == ["up", "30", "60"]


def test_trace_flags_are_canonicalized_with_defaults():
    result = _validator().validate("sample-trace", "scripts/query_trace.sh", ["trace-1"])
    assert result == ["trace-1", "--limit", "100", "--max-field-chars", "12000"]


def test_prometheus_point_limit_is_enforced():
    with pytest.raises(GatewayError) as exc:
        _validator().validate("sample-metrics", "scripts/collect_prom.sh", ["up", "1440", "1"])
    assert exc.value.code == "skill_arg_not_allowed"


def test_nonallowlisted_script_rejected():
    with pytest.raises(GatewayError) as exc:
        _validator().validate("sample-clickhouse", "scripts/ck_sync_schemas.sh", [])
    assert exc.value.code == "skill_script_not_allowed"


def test_fixture_argument_vectors():
    fixture_path = Path(__file__).parent / "fixtures" / "skill-rejections.json"
    data = json.loads(fixture_path.read_text(encoding="utf-8"))
    validator = _validator()
    cases = [case for case in data["cases"] if case.get("enforced_by") == "skill_arg_validator"]
    assert cases
    for case in cases:
        skill = case["skill"]
        script = case["input"]["script"]
        argv = case["input"]["argv"]
        if case["kind"] == "must_allow":
            validator.validate(skill, script, argv)
        else:
            with pytest.raises(GatewayError) as exc:
                validator.validate(skill, script, argv)
            assert exc.value.code == case["expected_error"], case["id"]


@pytest.mark.parametrize(
    "argv",
    [
        ["search", "x" * 129],
        ["monitoring", "123", "cpu", "0"],
        ["monitoring", "123", "cpu", "169"],
        ["lb-detail", "not-a-uuid"],
        ["k8s-pools", "../cluster"],
    ],
)
def test_do_api_invalid_arguments(argv):
    with pytest.raises(GatewayError) as exc:
        _validator().validate("sample-cloud", "scripts/do_api.sh", argv)
    assert exc.value.code == "skill_arg_not_allowed"


def test_infra_defaults_and_numeric_ids():
    validator = _validator()
    assert validator.validate("sample-cloud", "scripts/linode_api.sh", ["instance", "123"]) == ["instance", "123"]
    assert validator.validate("sample-cloud", "scripts/do_api.sh", ["monitoring", "123", "cpu"]) == [
        "monitoring", "123", "cpu", "1"
    ]
