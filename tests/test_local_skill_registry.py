from pathlib import Path
import pytest

from gateway.core import GatewayError
from gateway.local_skills.config import SkillFreshness, load_audit_policy
from gateway.local_skills.registry import SkillRegistry
from gateway.local_skills.runs import SkillRunStore


def _registry(stale=()):
    policy = load_audit_policy(Path(__file__).resolve().parents[1] / "samples" / "local-skill-policy")
    freshness = {
        name: SkillFreshness(name not in stale, "skill_audit_stale" if name in stale else None)
        for name in policy.compatibility["skills"]
    }
    return SkillRegistry(policy, freshness)


def test_registry_entry_scope_matches_frozen_v1():
    registry = _registry()
    assert registry.entry_names() == tuple(sorted((
        "sample-clickhouse", "sample-compare", "sample-cloud", "sample-trace",
        "sample-mysql", "sample-diagnosis", "sample-metrics",
    )))


def test_dependency_only_and_deferred_skills_cannot_start():
    registry = _registry()
    for name in ("sample-source", "sample-deferred"):
        with pytest.raises(GatewayError) as exc:
            registry.require_startable(name)
        assert exc.value.code == "skill_not_available"


def test_unknown_skill_rejected():
    with pytest.raises(GatewayError) as exc:
        _registry().require_startable("does-not-exist")
    assert exc.value.code == "skill_not_available"


def test_explicit_dependency_access_is_preserved():
    registry = _registry()
    assert registry.dependency_access("sample-diagnosis", "sample-source") == "read_only"
    assert registry.dependency_access("sample-diagnosis", "sample-mysql") == "execute_allowed_script"
    assert registry.dependency_access("sample-diagnosis", "sample-clickhouse") == "execute_allowed_script"
    with pytest.raises(GatewayError) as exc:
        registry.dependency_access("sample-diagnosis", "sample-metrics")
    assert exc.value.code == "skill_dependency_not_allowed"


def test_stale_mysql_propagates_only_to_mysql_dependents():
    registry = _registry({"sample-mysql"})
    assert registry.availability("sample-mysql").available is False
    status = registry.availability("sample-diagnosis")
    assert status.available is False
    assert status.reason == "skill_dependency_unavailable"
    assert status.dependency == "sample-mysql"
    assert registry.availability("sample-compare").available is True
    assert registry.availability("sample-metrics").available is True


def test_stale_ch_query_propagates_to_both_dependents():
    registry = _registry({"sample-clickhouse"})
    assert registry.availability("sample-clickhouse").available is False
    assert registry.availability("sample-compare").available is False
    assert registry.availability("sample-diagnosis").available is False
    assert registry.availability("sample-mysql").available is True


def test_unrelated_stale_skill_does_not_disable_others():
    registry = _registry({"sample-trace"})
    assert registry.availability("sample-trace").available is False
    assert registry.availability("sample-clickhouse").available is True
    assert registry.availability("sample-mysql").available is True


def test_run_store_freezes_scope_and_evicts_oldest():
    registry = _registry()
    store = SkillRunStore(max_runs=2)
    first = store.create(registry, "sample-diagnosis")
    assert dict(first.accessible_skills) == {
        "sample-diagnosis": "entry",
        "sample-source": "read_only",
        "sample-mysql": "execute_allowed_script",
        "sample-clickhouse": "execute_allowed_script",
    }
    store.create(registry, "sample-mysql")
    store.create(registry, "sample-metrics")
    with pytest.raises(GatewayError) as exc:
        store.get(first.skill_run_id)
    assert exc.value.code == "skill_run_not_found"


def test_existing_run_is_rechecked_against_refreshed_registry():
    store = SkillRunStore()
    run = store.create(_registry(), "sample-diagnosis")
    with pytest.raises(GatewayError) as exc:
        store.get_active(run.skill_run_id, _registry({"sample-mysql"}))
    assert exc.value.code == "skill_not_available"
