"""R1 RED-only deterministic contracts for D0 durable Exec lifecycle.

NOT discovered by plain pytest: filename intentionally does not start test_.
Invoke explicitly with the dedicated R1 workflow. No Popen, real signals,
private Tunnel, Native C, or external Workspace is used. Real product
entrypoints are probed with a fake runner; deeper failure windows use the
explicit *internal-only* test probe required of future R2 implementation.

A failing assertion is not proof of a working state machine. It shows the
reviewed D0 outcome is not yet enforced. See R1 acceptance evidence document.
"""
from __future__ import annotations

import asyncio
import os
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from gateway.core import GatewayError
from gateway.private_fs import PrivateFileError
from gateway.workspaces import ActiveRuntimeInventory, WorkspaceService
from gateway.workspaces_config import parse_workspace_config
from gateway.http_multi import create_multi_app


@pytest.fixture
def disposable(tmp_path):
    """Fully disposable two-Workspace service; never launches a real process."""
    roots = tmp_path / "projects"
    roots.mkdir()
    for name in ("a", "b"):
        src = roots / name / "src"
        src.mkdir(parents=True)
        (src / "ok.py").write_text("print('disposable-only')\n")
    config_dir = tmp_path / "control"
    config_dir.mkdir(mode=0o700)
    config_dir.chmod(0o700)
    runtime = tmp_path / "trusted-runtime"
    runtime.mkdir()
    services = []

    class Scene:
        state_root = config_dir / "exec-state"
        config = config_dir
        roots = roots if False else None

        def settings(self, *, server=True, workspace=True):
            return parse_workspace_config({
                "schema_version": 1,
                "server": {"exec": {"enabled": server}},
                "workspaces": {
                    "a": {"root": str(roots / "a"), "exec": {
                        "enabled": workspace,
                        "paths": ["src"] if workspace else [],
                        "runners": ["src=direct"] if workspace else [],
                    }},
                    "b": {"root": str(roots / "b")},
                },
            })

        def service(self, *, server=True, workspace=True):
            service = WorkspaceService(
                self.settings(server=server, workspace=workspace),
                config_dir=config_dir,
                inventory=ActiveRuntimeInventory(paths=(runtime,)),
            )
            services.append(service)
            return service

        @staticmethod
        def fake_runner(service, monkeypatch):
            """Patch the last Python runner boundary: zero actual Popen."""
            calls = []

            def fake(cwd, argv, timeout_seconds=60, dry_run=True):
                calls.append((cwd, tuple(argv), timeout_seconds, dry_run))
                return {"cwd": cwd, "dry_run": dry_run,
                        "executed": not dry_run, "exit_code": 0,
                        "stdout": "stubbed; no child", "stderr": ""}
            monkeypatch.setattr(service.get("a").gateway, "run_command", fake)
            return calls

        def add_state_entry(self, filename, contents=b'{"unexpected":true}\n'):
            self.state_root.mkdir(mode=0o700, exist_ok=True)
            candidate = self.state_root / filename
            candidate.write_bytes(contents)
            candidate.chmod(0o600)
            return candidate

    scene = Scene()
    scene.roots = roots
    try:
        yield scene
    finally:
        for svc in reversed(services):
            svc.close()


def _must_deny(func, code, red):
    try:
        result = func()
    except GatewayError as exc:
        if exc.code != code:
            raise AssertionError("R1_TEST_INFRA_WRONG_DENIAL_CODE: expected "
                                 + code + ", received " + exc.code)
    else:
        pytest.fail("R1_RED_" + red + ": unauthorized result " + repr(result),
                    pytrace=False)


def _must_status(policy, field, expected, red):
    if field not in policy or policy[field] != expected:
        pytest.fail("R1_RED_" + red + ": expected " + field + "="
                    + repr(expected) + ", observed "
                    + repr(policy.get(field, "<missing>")), pytrace=False)


# H: Test-only proof must be independent of ordinary global/Workspace Exec grants.

def test_normal_two_grants_do_not_authorize_apply(disposable, monkeypatch):
    svc = disposable.service()
    calls = disposable.fake_runner(svc, monkeypatch)
    _must_deny(lambda: svc.invoke_exec("a", "src", ["python", "ok.py"],
                                       dry_run=False),
               "exec_cleanup_proof_required", "NORMAL_PROOF_GATE")
    assert calls == [], "R1_RED_NORMAL_PROOF_GATE: Python runner was invoked"


def test_normal_rest_apply_is_503_before_runner(disposable, monkeypatch):
    svc = disposable.service()
    calls = disposable.fake_runner(svc, monkeypatch)
    with TestClient(create_multi_app(svc, enable_mcp=False),
                    base_url="http://127.0.0.1:8765") as client:
        response = client.post("/run", json={
            "workspace": "a", "cwd": "src", "argv": ["python", "ok.py"],
            "dry_run": False,
        })
        if response.status_code == 200:
            pytest.fail("R1_RED_REST_PROOF_GATE: normal apply was accepted",
                        pytrace=False)
        if (response.status_code != 503 or
                response.json().get("error") != "exec_cleanup_proof_required"):
            raise AssertionError("R1_TEST_INFRA_UNEXPECTED_HTTP: "
                                 + str(response.status_code) + " "
                                 + response.text[:160])
    assert not calls, "R1_RED_REST_PROOF_GATE: execution reached runner"


def test_normal_mcp_apply_rejects_cleanup_proof(disposable, monkeypatch):
    from gateway.mcp_multi import build_multi_mcp
    from mcp.server.mcpserver.exceptions import ToolError

    svc = disposable.service()
    calls = disposable.fake_runner(svc, monkeypatch)
    mcp = build_multi_mcp(svc)
    arguments = {"workspace": "a", "cwd": "src",
                 "argv": ["python", "ok.py"], "dry_run": False}
    try:
        response = asyncio.run(mcp.call_tool("run_command", arguments))
    except ToolError as exc:
        if "exec_cleanup_proof_required" not in str(exc):
            raise AssertionError("R1_TEST_INFRA_WRONG_MCP_ERROR: " + str(exc))
    else:
        pytest.fail("R1_RED_MCP_PROOF_GATE: returned " + repr(response)[:180],
                    pytrace=False)
    assert not calls, "R1_RED_MCP_PROOF_GATE: execution reached runner"


@pytest.mark.parametrize("env_name", [
    "GATEWAY_EXEC_TEST_GRANT",
    "GATEWAY_R1_TEST_ONLY",
    "PYTEST_CURRENT_TEST",
])
def test_environment_cannot_grant_test_only_retirement(
        disposable, monkeypatch, env_name):
    monkeypatch.setenv(env_name, "trusted:yes")
    svc = disposable.service()
    calls = disposable.fake_runner(svc, monkeypatch)
    _must_deny(lambda: svc.invoke_exec("a", "src", ["python", "ok.py"],
                                       dry_run=False),
               "exec_cleanup_proof_required", "ENV_PROOF_BYPASS")
    assert not calls, "R1_RED_ENV_PROOF_BYPASS: runner invoked"


def test_config_test_only_grant_is_not_a_public_option(disposable):
    settings = {
        "schema_version": 1,
        "server": {"exec": {"enabled": True, "test_only": True}},
        "workspaces": {"a": {"root": str(disposable.roots / "a"),
                             "exec": {"enabled": True, "paths": ["src"]}}},
    }
    with pytest.raises(PrivateFileError):
        parse_workspace_config(settings)


def test_rest_test_grant_request_field_is_rejected(disposable):
    svc = disposable.service()
    with TestClient(create_multi_app(svc, enable_mcp=False),
                    base_url="http://127.0.0.1:8765") as client:
        response = client.post("/run", json={
            "workspace": "a", "cwd": "src", "argv": ["python", "ok.py"],
            "test_only_grant": True, "dry_run": False,
        })
        assert response.status_code == 400, response.text


# L: registered capability, grant and proof-available are separate states.

def test_info_false_available_when_proof_missing(disposable):
    svc = disposable.service()
    policy = svc.info()["exec_policy"]
    _must_status(policy, "available", False, "AVAILABLE_WITHOUT_PROOF")
    _must_status(policy, "completion_capability", "none", "CAPABILITY_DEFAULT")


def test_info_health_same_exec_policy(disposable):
    svc = disposable.service()
    with TestClient(create_multi_app(svc, enable_mcp=False),
                    base_url="http://127.0.0.1:8765") as client:
        info = client.get("/info").json()
        health = client.get("/health").json()
    if "exec_policy" not in health or health["exec_policy"] != info["exec_policy"]:
        pytest.fail("R1_RED_HEALTH_STATUS_PARITY: missing/different exec_policy",
                    pytrace=False)
    _must_status(info["exec_policy"], "adapter_exposed", True,
                 "REGISTERED_ROUTE_STILL_VISIBLE")


def test_nonqualified_status_never_exposes_full_tree_capability(disposable):
    svc = disposable.service()
    policy = svc.info()["exec_policy"]
    _must_status(policy, "completion_capability", "none",
                 "NO_FULL_TREE_PROOF_BY_DEFAULT")
    _must_status(policy, "durability_state", "healthy",
                 "HEALTHY_STATE_REPORTED")


# A/C: boot scan must latch global quarantine before exposing Exec API.

@pytest.mark.parametrize("filename", [
    "unexpected-control.json",
    "temp-crash-after-write.tmp",
    "r-stale-running.json",
    "unknown-unretired.json",
])
def test_boot_untrusted_state_entry_quarantines(disposable, filename):
    entry = disposable.add_state_entry(filename)
    svc = disposable.service()
    policy = svc.info()["exec_policy"]
    _must_status(policy, "quarantined", True, "BOOT_SCAN_QUARANTINE")
    _must_status(policy, "available", False, "BOOT_SCAN_AVAILABLE")
    assert entry.exists(), "R1_RED_BOOT_SCAN_QUARANTINE: evidence was erased"


def test_quarantined_dry_run_is_not_misleading_preview(disposable):
    disposable.add_state_entry("foreign-entry.json")
    svc = disposable.service()
    _must_deny(lambda: svc.invoke_exec("a", "src", ["python", "ok.py"],
                                       dry_run=True),
               "exec_quarantined", "QUARANTINED_PREVIEW")


def test_quarantined_other_workspace_read_still_works(disposable):
    disposable.add_state_entry("stale-record.json")
    svc = disposable.service()
    result = svc.invoke("b", "list_files", ".")
    assert result["workspace"] == "b"
    _must_status(svc.info()["exec_policy"], "quarantined", True,
                 "FILE_READ_INDEPENDENT_OF_EXEC")


def test_state_root_is_not_allowed_to_be_a_symlink(disposable):
    target = disposable.config / "other-private"
    target.mkdir(mode=0o700)
    disposable.state_root.symlink_to(target, target_is_directory=True)
    svc = disposable.service()
    policy = svc.info()["exec_policy"]
    _must_status(policy, "available", False, "SYMLINK_STATE_UNAVAILABLE")
    if policy.get("durability_state") not in ("unavailable", "quarantined"):
        pytest.fail("R1_RED_SYMLINK_STATE_UNAVAILABLE: unsafe state accepted",
                    pytrace=False)


def test_foreign_hardlinked_record_fails_closed(disposable):
    disposable.state_root.mkdir(mode=0o700)
    outside = disposable.config / "linked-record"
    outside.write_text('{"kind":"RUNNING"}')
    os.link(outside, disposable.state_root / "foreign.json")
    svc = disposable.service()
    _must_status(svc.info()["exec_policy"], "available", False,
                 "HARDLINK_STATE_UNAVAILABLE")


def test_conflicting_second_owner_cannot_admit_exec(disposable):
    first = disposable.service()
    second = disposable.service()
    first_policy = first.info()["exec_policy"]
    second_policy = second.info()["exec_policy"]
    if second_policy.get("durability_state") not in ("unavailable", "quarantined"):
        pytest.fail("R1_RED_OWNER_LOCK: second state owner was admitted "
                    + repr((first_policy, second_policy)), pytrace=False)


def test_unreadable_state_root_cannot_fall_back_to_inmemory(disposable, monkeypatch):
    real_open = os.open

    def deny_exec_state(path, *args, **kwargs):
        if str(path) == "exec-state" or str(path).endswith("/exec-state"):
            raise PermissionError("R1 injected Exec state directory permission error")
        return real_open(path, *args, **kwargs)

    with monkeypatch.context() as m:
        m.setattr(os, "open", deny_exec_state)
        svc = disposable.service()
    policy = svc.info()["exec_policy"]
    _must_status(policy, "available", False, "STATE_IO_FAIL_CLOSED")
    _must_status(policy, "durability_state", "unavailable",
                 "STATE_IO_DIAGNOSTIC")


# B/C: ambiguous post-run work must not be treated as a clean lease release.

def test_ambiguous_sync_worker_failure_latches_quarantine(
        disposable, monkeypatch):
    svc = disposable.service()
    calls = []

    def ambiguous(*args, **kwargs):
        calls.append("possibly_spawned")
        raise OSError("R1 injected post-spawn-observation ambiguity")

    monkeypatch.setattr(svc.get("a").gateway, "run_command", ambiguous)
    try:
        svc.invoke_exec("a", "src", ["python", "ok.py"], dry_run=False)
    except (OSError, GatewayError):
        pass
    else:
        pytest.fail("R1_RED_AMBIGUOUS_LIFECYCLE: failed runner reported success",
                    pytrace=False)
    _must_status(svc.info()["exec_policy"], "quarantined", True,
                 "AMBIGUOUS_LIFECYCLE")
    assert calls == [] or calls == ["possibly_spawned"]


def test_ambiguous_state_survives_service_restart(disposable, monkeypatch):
    first = disposable.service()
    def ambiguous(*args, **kwargs):
        raise OSError("R1 synthetic launch uncertainty")

    monkeypatch.setattr(first.get("a").gateway, "run_command", ambiguous)
    try:
        first.invoke_exec("a", "src", ["python", "ok.py"], dry_run=False)
    except (OSError, GatewayError):
        pass
    first.close()
    again = disposable.service()
    _must_status(again.info()["exec_policy"], "quarantined", True,
                 "RESTART_UNKNOWN_STICKY")


def test_quarantine_never_triggers_stale_pid_signal(disposable, monkeypatch):
    disposable.add_state_entry("unknown-process-record.json",
                               b'{"phase":"UNKNOWN","pid":123456}\n')
    signals = []
    with monkeypatch.context() as m:
        m.setattr(os, "killpg", lambda *a: signals.append(("killpg", a)))
        m.setattr(os, "kill", lambda *a: signals.append(("kill", a)))
        svc = disposable.service()
    _must_status(svc.info()["exec_policy"], "quarantined", True,
                 "UNKNOWN_NO_STALE_PID_SIGNAL")
    assert signals == [], "R1_RED_UNKNOWN_NO_STALE_PID_SIGNAL: unsafe signal"


# K: quota, retired-only pruning, fsync windows, internal-grant proof and
# precise crash windows need a *private* R2 test probe. Ordinary REST/MCP
# must never expose this seam. R1 documents the exact inputs and outcomes
# and deliberately RED-fails on its absence; it never simulates a fake GREEN.

_SCENARIOS = [
    # A/B durable intent must be present before any possibly-started process.
    ("intent_file_fsync_failure", "exec_state_unavailable", 0, True),
    ("intent_directory_fsync_failure", "exec_state_unavailable", 0, True),
    ("intent_atomic_rename_failure", "exec_state_unavailable", 0, True),
    ("deadline_before_popen", "exec_timeout", 0, False),
    ("ambiguous_popen_failure", "exec_cleanup_incomplete", 1, True),
    ("stream_drain_failure", "exec_cleanup_incomplete", 1, True),
    ("leader_wait_failure", "exec_cleanup_incomplete", 1, True),
    ("post_spawn_finalization_fsync_failure", "exec_state_unavailable", 1, True),
    # C: no restarted process may re-admit unresolved or replay RETIRED.
    ("restart_after_prepared_before_popen", "exec_quarantined", 0, True),
    ("restart_after_popen_before_identity", "exec_quarantined", 1, True),
    ("restart_after_leader_reap", "exec_quarantined", 1, True),
    ("restart_after_retire_before_response", "no_replay", 1, False),
    # I/J: only trusted, same-instance disposable grant can retire group-only.
    ("valid_internal_test_grant_group_retirement", "retired_original_group_only", 1, False),
    ("forged_or_client_supplied_grant", "exec_cleanup_proof_required", 0, False),
    ("grant_bound_to_other_service", "exec_cleanup_proof_required", 0, False),
    ("grant_bound_to_other_workspace_inode", "exec_cleanup_proof_required", 0, False),
    ("grant_invalidated_by_restart", "exec_cleanup_proof_required", 0, False),
    ("grant_invalidated_during_finalization", "exec_cleanup_incomplete", 1, True),
    ("detached_descendant_observed", "exec_cleanup_incomplete", 1, True),
    # K: no eviction of UNKNOWN; only durable RETIRED under bounded capacity.
    ("quota_full_without_retired", "exec_state_unavailable", 0, True),
    ("retired_only_prune_and_dir_fsync", "retired_only_pruned", 0, False),
    ("retired_prune_directory_fsync_failure", "exec_state_unavailable", 0, True),
    ("quota_exact_4096_records_16mib", "quota_enforced", 0, False),
    # D: worker slot held until durable retirement / UNKNOWN finalized.
    ("cancellation_during_final_state_fsync", "busy_until_finalization", 1, False),
]


@pytest.mark.parametrize("case,expected_code,spawn_count,quarantined", _SCENARIOS,
                         ids=[item[0] for item in _SCENARIOS])
def test_internal_state_fault_injection_contract(
        disposable, case, expected_code, spawn_count, quarantined):
    """R2-owned internal test probe, not a product API/production grant.

    Required narrow seam: private WorkspaceService._r1_contract_probe(
        *, case, fixture_root, state_root, workspace) -> dict with
    outcome_code, spawn_attempts, quarantined, and, for retired group-only,
    cleanup_scope + full_descendant_tree_clean. R2 may implement a test-only
    adapter in this file, but must keep the seam unreachable via server args.
    """
    svc = disposable.service()
    probe = getattr(svc, "_r1_contract_probe", None)
    if not callable(probe):
        pytest.fail("R1_RED_INTERNAL_PROBE_MISSING: " + case, pytrace=False)
    observed = probe(
        case=case,
        fixture_root=disposable.roots,
        state_root=disposable.state_root,
        workspace="a",
    )
    if (type(observed) is not dict or
            observed.get("outcome_code") != expected_code or
            observed.get("spawn_attempts") != spawn_count or
            observed.get("quarantined") is not quarantined):
        pytest.fail("R1_RED_INTERNAL_SCENARIO_OUTCOME: " + case + " "
                    + repr(observed)[:240], pytrace=False)
    if case == "valid_internal_test_grant_group_retirement":
        if (observed.get("cleanup_scope") != "original_group_only" or
                observed.get("full_descendant_tree_clean") != "not_proven"):
            pytest.fail("R1_RED_TEST_ONLY_PROOF_MISREPORTED", pytrace=False)
    if case == "restart_after_retire_before_response":
        if observed.get("retry_count", -1) != 0:
            pytest.fail("R1_RED_RETIRED_MUST_NOT_REPLAY", pytrace=False)
    if case.startswith("retired_") or case.startswith("quota_"):
        if observed.get("removed_unresolved_markers", 0) != 0:
            pytest.fail("R1_RED_UNRESOLVED_MUST_NOT_EVICT", pytrace=False)


def test_unrelated_git_authority_not_inferred(disposable):
    svc = disposable.service()
    assert svc.info()["git_policy"]["enabled"] is False
    assert svc.info()["exec_policy"]["enabled"] is True
    with pytest.raises(GatewayError) as exc:
        svc.invoke_git("a", "status")
    assert exc.value.code == "git_disabled"


def test_no_remote_unquarantine_route(disposable):
    svc = disposable.service()
    with TestClient(create_multi_app(svc, enable_mcp=False),
                    base_url="http://127.0.0.1:8765") as client:
        for route in ("/exec/reset", "/exec/unquarantine"):
            assert client.post(route, json={}).status_code == 404
