"""R1 T0 evidence: protocol data and an inert deny-only coordinator.

These are pure Python/static tests, not a native process lifecycle proof.
The separately maintained F1 real REST/MCP/Write/Git tests remain mandatory.
"""
from __future__ import annotations

import ast
from dataclasses import FrozenInstanceError
import inspect

import pytest

from gateway.runner_seam import (
    AdmissionDecision,
    AttemptIdentity,
    BackendQualification,
    BoundReference,
    CleanupEvidence,
    CommandOutcome,
    DeliveryOutcome,
    ProposedCommand,
    RunnerCoordinator,
)
import gateway.runner_seam as seam
from gateway.workspaces import WorkspaceService
from gateway.exec_state import _PHASES


def key(generation: str = "b" * 32) -> AttemptIdentity:
    return AttemptIdentity(
        workspace="a", workspace_dev=101, workspace_ino=202,
        attempt_id="a" * 32, owner_generation=generation,
    )


def test_r1_never_calls_a_claimed_full_cleanup_backend():
    class Trap:
        def __getattribute__(self, name):
            raise AssertionError("R1 touched the injected backend: " + name)

    coordinator = RunnerCoordinator()
    for _ in range(3):
        result = coordinator.evaluate(key(), backend=Trap())
        assert result == AdmissionDecision()
        assert result.allowed is False
        assert result.error_code == "exec_cleanup_proof_required"
        assert result.completion_capability == "none"


def test_r1_cannot_promote_admission_or_qualification():
    with pytest.raises(ValueError, match="positive execution"):
        AdmissionDecision(allowed=True)
    with pytest.raises(ValueError, match="positive execution"):
        AdmissionDecision(completion_capability="full_tree_qualified")
    with pytest.raises(ValueError, match="positive execution"):
        AdmissionDecision(error_code="ok")
    with pytest.raises(ValueError, match="positive backend"):
        BackendQualification(completion_capability="full_bound_domain")
    assert BackendQualification().completion_capability == "none"


def test_r1_rejects_untrusted_inputs_and_has_no_remote_profile_selector():
    coordinator = RunnerCoordinator()
    with pytest.raises(TypeError):
        coordinator.evaluate({"workspace": "a"})
    with pytest.raises(TypeError):
        coordinator.evaluate(key(), profile="native_limited")
    with pytest.raises(TypeError):
        coordinator.evaluate(key(), proof="test_original_group_only")
    with pytest.raises(TypeError):
        coordinator.evaluate(key(), reset_unknown=True)
    assert coordinator.evaluate(key()) == AdmissionDecision()


@pytest.mark.parametrize("change", [
    {"workspace": "A"},
    {"workspace": "../a"},
    {"workspace": ""},
    {"workspace": "a" * 33},
    {"workspace_dev": -1},
    {"workspace_dev": True},
    {"workspace_ino": -1},
    {"workspace_ino": 1.0},
    {"attempt_id": "1234"},
    {"attempt_id": "A" * 32},
    {"owner_generation": "x" * 32},
    {"owner_generation": ""},
])
def test_attempt_identity_rejects_invalid_data(change):
    values = dict(
        workspace="a", workspace_dev=101, workspace_ino=202,
        attempt_id="a" * 32, owner_generation="b" * 32,
    )
    values.update(change)
    with pytest.raises(ValueError):
        AttemptIdentity(**values)


def test_attempt_identity_and_command_are_immutable_and_no_argv_repr():
    intent = key()
    with pytest.raises(FrozenInstanceError):
        intent.workspace = "b"
    command = ProposedCommand(
        cwd="src", argv=("python", "secret_argument"), timeout_seconds=60
    )
    assert "secret_argument" not in repr(command)
    with pytest.raises(FrozenInstanceError):
        command.cwd = "other"
    assert ProposedCommand(cwd=".", argv=("go", "test")).timeout_seconds == 60


@pytest.mark.parametrize("case_kwargs", [
    dict(cwd="", argv=("pytest",)),
    dict(cwd=".", argv=[]),
    dict(cwd=".", argv=("python", "")),
    dict(cwd=".", argv=("pytest",), timeout_seconds=0),
    dict(cwd=".", argv=("pytest",), timeout_seconds=301),
    dict(cwd=".", argv=("pytest",), timeout_seconds=True),
])
def test_command_data_rejects_malformed_fields_without_executing(case_kwargs):
    with pytest.raises(ValueError):
        ProposedCommand(**case_kwargs)


def test_bound_reference_is_opaque_and_not_a_numeric_pid_authority():
    ref = BoundReference(attempt=key(), backend_id="fake", opaque_ref="opaque-secret")
    assert "opaque-secret" not in repr(ref)
    with pytest.raises(ValueError):
        BoundReference(attempt="a" * 32, backend_id="fake", opaque_ref="x")
    with pytest.raises(ValueError):
        BoundReference(attempt=key(), backend_id="fake", opaque_ref="")


def test_command_exit_zero_is_not_descendant_cleanup_proof():
    command = CommandOutcome(executed=True, exit_code=0)
    group = CleanupEvidence(
        scope="original_group_only", full_descendant_tree_clean="not_proven"
    )
    delivery = DeliveryOutcome(response_attempted=True, acknowledged=None)
    assert command.exit_code == 0
    assert group.full_descendant_tree_clean == "not_proven"
    assert delivery.acknowledged is None
    assert RunnerCoordinator().evaluate(key()).allowed is False


@pytest.mark.parametrize("kwargs", [
    dict(scope="original_group_only", full_descendant_tree_clean="proven"),
    dict(scope="none", full_descendant_tree_clean="proven"),
    dict(scope="original_group_only", observed_detached_survivor=True),
    dict(scope="full_bound_domain", observed_detached_survivor=True),
    dict(scope="invalid"),
    dict(full_descendant_tree_clean="invalid"),
    dict(observed_detached_survivor=1),
])
def test_cleanup_claims_fail_closed_without_qualified_backend(kwargs):
    with pytest.raises(ValueError):
        CleanupEvidence(**kwargs)


def test_descriptive_strict_evidence_cannot_bypass_inert_coordinator():
    forged = CleanupEvidence(
        scope="full_bound_domain", full_descendant_tree_clean="proven"
    )
    assert forged.full_descendant_tree_clean == "proven"
    # The data type is deliberately not a capability or trusted certificate.
    assert RunnerCoordinator().evaluate(key()).completion_capability == "none"


def test_positive_detached_observation_is_unknown_even_if_group_was_absent():
    observed = CleanupEvidence(observed_detached_survivor=True)
    assert observed.scope == "none"
    assert observed.full_descendant_tree_clean == "not_proven"
    with pytest.raises(ValueError):
        CleanupEvidence(
            scope="original_group_only",
            observed_detached_survivor=True,
        )


def test_missing_response_ack_does_not_imply_replay_authorization():
    assert DeliveryOutcome(response_attempted=True).acknowledged is None
    with pytest.raises(ValueError):
        DeliveryOutcome(response_attempted=False, acknowledged=True)
    with pytest.raises(ValueError):
        DeliveryOutcome(response_attempted=True, acknowledged="yes")
    assert RunnerCoordinator().evaluate(key()).allowed is False


def test_nonexecuted_command_cannot_have_exit_or_timeout():
    with pytest.raises(ValueError):
        CommandOutcome(executed=False, exit_code=0)
    with pytest.raises(ValueError):
        CommandOutcome(executed=False, timed_out=True)
    with pytest.raises(ValueError):
        CommandOutcome(executed=True, exit_code=True)


def test_r1_protocol_source_has_no_process_or_network_implementations():
    module = ast.parse(inspect.getsource(seam))
    forbidden_modules = {
        "os", "subprocess", "signal", "socket", "multiprocessing",
        "asyncio", "ctypes", "threading",
    }
    for node in ast.walk(module):
        if isinstance(node, ast.Import):
            assert not (set(alias.name.split(".")[0] for alias in node.names)
                        & forbidden_modules)
        if isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] not in forbidden_modules
    assert not hasattr(RunnerCoordinator(), "start_once")
    assert not hasattr(RunnerCoordinator(), "terminate_and_prove")


def test_f1_only_wires_inert_denial_and_durable_schema_v1_is_unchanged():
    source = inspect.getsource(WorkspaceService.invoke_exec)
    assert "RunnerCoordinator()" in inspect.getsource(WorkspaceService.__init__)
    assert "deny_unqualified_apply()" in source
    assert "exec_cleanup_proof_required" in source
    assert source.index("if not dry_run:") < source.index("if name in self._exec_active")
    assert "runner_seam" in inspect.getsource(seam)
    assert _PHASES == {"PREPARED", "RUNNING", "UNKNOWN", "RETIRED"}


def test_production_decision_is_always_denied_even_after_forged_full_evidence():
    coordinator = RunnerCoordinator()
    assert coordinator.deny_unqualified_apply() == AdmissionDecision()
    fake = CleanupEvidence(scope="full_bound_domain", full_descendant_tree_clean="proven")
    assert fake.full_descendant_tree_clean == "proven"
    assert coordinator.deny_unqualified_apply().allowed is False
