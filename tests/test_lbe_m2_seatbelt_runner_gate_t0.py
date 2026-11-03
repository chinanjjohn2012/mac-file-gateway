"""T0-only Seatbelt Runner safety proposal: pure, no real native child."""
from dataclasses import fields, replace
from pathlib import Path
import socket
import subprocess

import pytest

from gateway.lbe_m2_seatbelt_runner_gate_t0 import (
    LbeM2RunnerGateT0Denied,
    MacOSRunnerIdentityProposalT0,
    MacOSRunnerResourceBudgetT0,
    advance_child_survivor_latch_t0,
    execute_macos_seatbelt_runner_canary,
    prepare_seatbelt_runner_gate_t0,
)

_ROOT = Path(__file__).resolve().parents[1]
_HEAD = "a" * 40
_TREE = "b" * 40
_DIGESTS = ("1" * 64, "2" * 64, "3" * 64, "4" * 64, "5" * 64)


def _input():
    return {
        "proposed_head_sha": _HEAD,
        "proposed_tree_sha": _TREE,
        "native_helper_bytes": (
            _ROOT / "tools/lbe_m2_seatbelt_canary_only.c").read_bytes(),
        "fd_scrub_header_bytes": (
            _ROOT / "tools/lbe_m2_fd_scrub_t0.h").read_bytes(),
        "bounded_wait_header_bytes": (
            _ROOT / "tools/lbe_m2_canary_bounded_wait_t0.h").read_bytes(),
        "runner_identity": MacOSRunnerIdentityProposalT0(
            _HEAD, _TREE, "macOS", "macos-15", "arm64", *_DIGESTS),
        "budget": MacOSRunnerResourceBudgetT0(),
    }


def _make(**overrides):
    kw = _input()
    kw.update(overrides)
    return prepare_seatbelt_runner_gate_t0(**kw)


def test_valid_proposed_runner_stays_nonoperative_with_zero_spawn(monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("native process or network started in T0")
    with monkeypatch.context() as m:
        m.setattr(subprocess, "Popen", forbidden)
        m.setattr(subprocess, "run", forbidden)
        m.setattr(socket, "socket", forbidden)
        p = _make()
    assert p.status == "NONOPERATIVE_RUNNER_SECURITY_GATE_T0"
    assert p.proposed_head_sha == _HEAD and p.proposed_tree_sha == _TREE
    assert len(p.source_sha256) == 3
    assert all(len(s) == 64 for s in p.source_sha256)
    assert p.proposed_runner_label == "macos-15"
    assert p.identity_structure_only == "MATCHED_UNTRUSTED_INPUTS"
    assert p.budget_structure_only == "WITHIN_PROPOSED_CEILINGS"
    assert p.precontact_structure_only == "ORDERED_NOT_EXECUTED"
    assert p.proposed_precontact_sequence.index(
        "SEATBELT_POLICY_ATTACHED_BEFORE_EXTERNAL_CODE"
    ) < p.proposed_precontact_sequence.index(
        "PRECONTACT_DENIAL_PROBES_IN_SAME_DOMAIN"
    )
    for name in (
        "actual_runner_verified", "actual_os_limits_enforced",
        "actual_precontact_isolation_attached", "descendant_retirement_proven",
        "native_canary_launch_allowed", "source_t1_launch_allowed",
        "product_t1_launch_allowed",
    ):
        assert getattr(p, name) is False, name
    assert "MACOS_KERNEL_RESOURCE_LIMITS_NOT_ENFORCED_OR_OBSERVED" in p.blockers


@pytest.mark.parametrize("field,value", [
    ("runner_os", "Linux"), ("runner_os", True),
    ("runner_label", "macos-latest"), ("runner_arch", "x86_64"),
    ("proposed_head_sha", "c" * 40),
    ("proposed_tree_sha", "d" * 40),
    ("runner_image_sha256", ""),
    ("runner_image_sha256", "A" * 64),
    ("runner_image_sha256", "0" * 64),
    ("workflow_sha256", "g" * 64),
    ("compiler_sha256", None),
    ("sdk_sha256", True),
    ("compiled_macho_sha256", "9" * 63),
])
def test_forged_wrong_or_incomplete_runner_claim_refused(field, value):
    identity = replace(_input()["runner_identity"], **{field: value})
    with pytest.raises(LbeM2RunnerGateT0Denied):
        _make(runner_identity=identity)


def test_repeated_unrelated_origin_digests_cannot_qualify():
    x = replace(_input()["runner_identity"],
                compiled_macho_sha256=_DIGESTS[0])
    with pytest.raises(LbeM2RunnerGateT0Denied):
        _make(runner_identity=x)


@pytest.mark.parametrize("path", [
    "native_helper_bytes", "fd_scrub_header_bytes",
    "bounded_wait_header_bytes",
])
def test_any_current_pinned_source_mutation_is_denied(path):
    with pytest.raises(LbeM2RunnerGateT0Denied):
        _make(**{path: _input()[path] + b"\n"})


@pytest.mark.parametrize("field,value", [
    ("job_wall_seconds", 1201),
    ("job_wall_seconds", 9),
    ("canary_wall_seconds", 11),
    ("canary_wall_seconds", 0),
    ("canary_cpu_seconds", 11),
    ("canary_cpu_seconds", 0),
    ("canary_memory_mib", 129),
    ("canary_memory_mib", 15),
    ("selected_child_wait_ms", 2001),
    ("selected_child_wait_ms", 0),
    ("stdout_raw_bytes", 4097),
    ("stderr_raw_bytes", 4097),
    ("nofile_soft", 65),
    ("nofile_soft", 15),
    ("max_canary_children", 2),
    ("max_parallel_canaries", 0),
    ("max_parallel_canaries", 2),
    ("canary_cpu_seconds", True),
    ("canary_memory_mib", 128.0),
    ("stdout_raw_bytes", "4096"),
])
def test_resource_ceiling_or_invalid_type_denied_before_execution(field, value):
    budget = replace(MacOSRunnerResourceBudgetT0(), **{field: value})
    with pytest.raises(LbeM2RunnerGateT0Denied):
        _make(budget=budget)


def test_cross_limit_wait_and_wall_inconsistency_refused():
    with pytest.raises(LbeM2RunnerGateT0Denied):
        _make(budget=replace(MacOSRunnerResourceBudgetT0(),
                             canary_wall_seconds=2))
    with pytest.raises(LbeM2RunnerGateT0Denied):
        _make(budget=replace(MacOSRunnerResourceBudgetT0(),
                             canary_wall_seconds=5, canary_cpu_seconds=10))


def test_safe_lowered_limits_are_only_descriptive_not_os_proof():
    p = _make(budget=replace(
        MacOSRunnerResourceBudgetT0(),
        canary_wall_seconds=5, canary_cpu_seconds=4,
        canary_memory_mib=64, selected_child_wait_ms=1000,
        stdout_raw_bytes=2048, stderr_raw_bytes=2048,
        nofile_soft=32))
    assert p.actual_os_limits_enforced is False
    assert p.native_canary_launch_allowed is False


@pytest.mark.parametrize("mutator", [
    lambda s: s[:-1],
    lambda s: s[1:],
    lambda s: s + ("RUN_GO",),
    lambda s: s[:5] + (s[6], s[5]) + s[7:],
    lambda s: list(s),
    lambda s: tuple("RUN_GO" if x == "NO_NATIVE_EXECUTION_IN_T0" else x for x in s),
])
def test_omitted_reordered_or_injected_precontact_step_denied(mutator):
    order = _make().proposed_precontact_sequence
    with pytest.raises(LbeM2RunnerGateT0Denied):
        _make(proposed_precontact_sequence=mutator(order))


def test_finite_lifecycle_natural_exit_never_proves_descendant_retirement():
    state = advance_child_survivor_latch_t0("NOT_STARTED", "STARTED")
    assert state == "RUNNING"
    assert advance_child_survivor_latch_t0(state, "POLL") == "RUNNING"
    state = advance_child_survivor_latch_t0(state, "EXIT_ZERO")
    assert state == "EXIT_OBSERVED_DESCENDANTS_UNPROVEN"
    p = _make(simulated_child_state=state)
    assert p.descendant_retirement_proven is False
    assert "SIMULATED_CHILD_IS_NOT_NATIVE_OS_EVIDENCE" in p.blockers


@pytest.mark.parametrize("event", [
    "TIMEOUT", "UNKNOWN_CHILD", "ECHILD", "OWNER_LOST", "RETRY",
])
def test_unknown_survivor_event_irreversibly_latches(event):
    state = advance_child_survivor_latch_t0("NOT_STARTED", "STARTED")
    state = advance_child_survivor_latch_t0(state, event)
    assert state == "POSSIBLE_SURVIVOR"
    for later in ("EXIT_ZERO", "NO_SPAWN", "STARTED", "POLL", "RETRY"):
        assert advance_child_survivor_latch_t0(state, later) == state
    p = _make(simulated_child_state=state)
    assert "SURVIVOR_LATCHED_NO_RETRY_OR_NATIVE_LAUNCH" in p.blockers
    with pytest.raises(LbeM2RunnerGateT0Denied):
        execute_macos_seatbelt_runner_canary(p)


def test_timeout_even_after_observed_original_exit_latches():
    state = advance_child_survivor_latch_t0("RUNNING", "EXIT_ZERO")
    assert advance_child_survivor_latch_t0(state, "OWNER_LOST") == "POSSIBLE_SURVIVOR"


@pytest.mark.parametrize("state,event", [
    ("", "STARTED"), ("POSSIBLE_SURVIVOR", "MAGIC_CLEAR"),
    ("RUNNING", True), (False, "POLL"),
])
def test_invalid_lifecycle_inputs_refused(state, event):
    with pytest.raises(LbeM2RunnerGateT0Denied):
        advance_child_survivor_latch_t0(state, event)


@pytest.mark.parametrize("fake", [
    None, True, False, "PASS", "MACOS_OS_PROVEN",
    {"runner_attested": True, "os_limits": True, "safe_child": True},
])
def test_fake_receipts_never_grant_real_canary(fake):
    plan = _make()
    with pytest.raises(LbeM2RunnerGateT0Denied,
                       match="NATIVE_MACOS_CANARY=NOT_RUN"):
        execute_macos_seatbelt_runner_canary(plan, fake, fake, fake, fake)


def test_mutated_frozen_receipt_is_never_an_execution_capability():
    p = replace(
        _make(), native_canary_launch_allowed=True,
        source_t1_launch_allowed=True, product_t1_launch_allowed=True,
        actual_runner_verified=True, actual_os_limits_enforced=True,
        actual_precontact_isolation_attached=True,
        descendant_retirement_proven=True, blockers=(),
    )
    with pytest.raises(LbeM2RunnerGateT0Denied):
        execute_macos_seatbelt_runner_canary(p, p, p, p, p)


def test_runner_gate_never_imports_process_network_native_or_os_mutators():
    s = (_ROOT / "gateway/lbe_m2_seatbelt_runner_gate_t0.py").read_text(
        encoding="ascii")
    for forbidden in (
        "import subprocess", "import socket", "import ctypes",
        "import resource", "import os", "sandbox_init(", "setrlimit(",
        "kill(", "Popen(", "fork(", "execve(",
    ):
        assert forbidden not in s, forbidden
    assert "execute_macos_seatbelt_runner_canary(" in s


def test_four_part_gate_is_explicitly_nonoperative():
    p = _make()
    assert set(p.__dataclass_fields__) >= {
        "source_sha256", "proposed_runner_label", "budget",
        "proposed_precontact_sequence", "simulated_child_state",
        "native_canary_launch_allowed",
    }
    assert len(fields(type(p))) > 10
