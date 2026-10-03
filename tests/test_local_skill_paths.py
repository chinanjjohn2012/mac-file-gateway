import json
from pathlib import Path

import pytest

from gateway.core import GatewayError
from gateway.local_skills.paths import normalize_skill_path


@pytest.mark.parametrize(
    ("current", "source", "skill", "relative"),
    [
        ("sample-clickhouse", "references/sql-patterns.md", "sample-clickhouse", "references/sql-patterns.md"),
        ("sample-diagnosis", "../sample-source/references/flow-tracing.md", "sample-source", "references/flow-tracing.md"),
        ("sample-clickhouse", "${LOCAL_SKILL_AGENT_DIR}/skills/sample-clickhouse/schemas/sample-primary/table.md", "sample-clickhouse", "schemas/sample-primary/table.md"),
        ("sample-clickhouse", "$SKILL_ROOT/sample-clickhouse/SKILL.md", "sample-clickhouse", "SKILL.md"),
        ("sample-source", "service-a/.cursor/skills/sample-source/references/flow-tracing.md", "sample-source", "references/flow-tracing.md"),
        ("sample-clickhouse", "/repo/project/agent-runtime/skills/sample-clickhouse/SKILL.md", "sample-clickhouse", "SKILL.md"),
    ],
)
def test_normalize_supported_legacy_forms(current, source, skill, relative):
    result = normalize_skill_path(current, source)
    assert result.skill == skill
    assert result.relative_path == relative


@pytest.mark.parametrize(
    "source",
    [
        "../../sample-mysql/SKILL.md",
        "../sample-mysql",
        "references/../scripts/x.sh",
        ".hidden/file.md",
        "references/.secret.md",
        "a\\b.md",
        "a\x00b.md",
    ],
)
def test_normalize_rejects_unsafe_forms(source):
    with pytest.raises(GatewayError) as exc:
        normalize_skill_path("sample-clickhouse", source)
    assert exc.value.code == "skill_file_not_allowed"


def test_fixture_path_rejection_vectors():
    fixture = Path(__file__).parent / "fixtures" / "skill-rejections.json"
    data = json.loads(fixture.read_text(encoding="utf-8"))
    cases = [case for case in data["cases"] if case.get("enforced_by") == "path_normalizer"]
    assert cases
    for case in cases:
        with pytest.raises(GatewayError) as exc:
            normalize_skill_path(case["skill"], case["input"]["path"])
        assert exc.value.code == case["expected_error"], case["id"]
