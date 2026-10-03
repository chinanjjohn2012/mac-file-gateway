import json
from pathlib import Path

import pytest

from gateway.core import GatewayError
from gateway.local_skills.config import load_audit_policy
from gateway.local_skills.sql_policy import SqlPolicyGate


def _gate():
    return SqlPolicyGate(load_audit_policy(Path(__file__).resolve().parents[1] / "samples" / "local-skill-policy"))


def test_fixture_sql_policy_vectors():
    path = Path(__file__).parent / "fixtures" / "skill-rejections.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    cases = [case for case in data["cases"] if str(case.get("enforced_by", "")).startswith("sql_policy")]
    assert cases
    gate = _gate()
    for case in cases:
        sql = case["input"]["sql"]
        if case["kind"] == "must_allow":
            gate.validate(case["skill"], sql)
        else:
            with pytest.raises(GatewayError) as exc:
                gate.validate(case["skill"], sql)
            assert exc.value.code == case["expected_error"], case["id"]


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT REPLACE(name, 'a', 'b') FROM t",
        "SELECT replaceAll(name, 'a', 'b') FROM t",
        "SELECT replaceRegexpAll(name, 'a', 'b') FROM t",
        "SELECT load, system FROM metrics",
        "SELECT 'DELETE UPDATE SET' AS sample",
        "SELECT 1 /* DELETE FROM t */",
    ],
)
def test_token_scan_does_not_reject_normal_read_expressions(sql):
    _gate().validate("sample-mysql", sql)


@pytest.mark.parametrize(
    ("sql", "code"),
    [
        ("SHOW PROCESSLIST", "skill_show_not_allowed"),
        ("SHOW ENGINE INNODB STATUS", "skill_show_not_allowed"),
        ("SHOW VARIABLES", "skill_show_not_allowed"),
        ("SHOW GRANTS", "skill_show_not_allowed"),
        ("SELECT * FROM mysql.user", "skill_system_schema_not_allowed"),
        ("SELECT * FROM sys.schema_table_statistics", "skill_system_schema_not_allowed"),
        ("SELECT * FROM t FOR UPDATE", "skill_sql_not_readonly"),
        ("SELECT 1; SELECT 2", "skill_sql_not_readonly"),
    ],
)
def test_mysql_rejections(sql, code):
    with pytest.raises(GatewayError) as exc:
        _gate().validate("sample-mysql", sql)
    assert exc.value.code == code


def test_explain_inner_select_is_checked_normally():
    _gate().validate("sample-mysql", "EXPLAIN SELECT * FROM t")
    with pytest.raises(GatewayError) as exc:
        _gate().validate("sample-mysql", "EXPLAIN SELECT * FROM information_schema.tables")
    assert exc.value.code == "skill_system_schema_not_allowed"


def test_realtime_instance_mapping_is_respected():
    gate = _gate()
    gate.validate(
        "sample-clickhouse",
        "SELECT count() FROM sample_rollup_realtime WHERE date_hour >= now() - INTERVAL 2 HOUR",
        instance="sample-secondary",
    )
    with pytest.raises(GatewayError) as exc:
        gate.validate(
            "sample-clickhouse",
            "SELECT count() FROM sample_rollup_realtime WHERE date_hour >= now() - INTERVAL 2 HOUR",
            instance="sample-primary",
        )
    assert exc.value.code == "skill_query_scope_unknown"


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT count() FROM sample_events_realtime, other_table WHERE time >= now() - INTERVAL 1 HOUR",
        "SELECT count() FROM sample_events_realtime WHERE time >= now() - INTERVAL 2 HOUR - INTERVAL 1 DAY",
        "SELECT count() FROM sample_events_realtime WHERE time >= '2026-10-01 10:00:00' - INTERVAL 1 DAY AND time < '2026-10-01 12:00:00'",
        "SELECT count() FROM sample_events_realtime WHERE time BETWEEN '2026-10-01 10:00:00' AND '2026-10-01 12:00:00' - INTERVAL 1 DAY",
    ],
)
def test_realtime_scope_rejects_comma_join_and_extended_time_expressions(sql):
    with pytest.raises(GatewayError) as exc:
        _gate().validate("sample-clickhouse", sql)
    assert exc.value.code == "skill_query_scope_unknown"


@pytest.mark.parametrize(
    "sql",
    [
        'SELECT * FROM "mysql".user',
        "SHOW TABLES FROM mysql",
        "SHOW TABLES IN information_schema",
    ],
)
def test_system_schema_rejects_quoted_and_show_forms(sql):
    with pytest.raises(GatewayError) as exc:
        _gate().validate("sample-mysql", sql)
    assert exc.value.code == "skill_system_schema_not_allowed"
