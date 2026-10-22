"""R2b-R2b-R2 SOURCE-only request/binding contract. NO C load or call."""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tools/research/c3_candidate_b_t01_r2_source_only_adapter.py"
NATIVE_C = ROOT / "tools/research/c3_candidate_b_t01_no_signal_candidate.c"
HEADER = ROOT / "tests/native/c3_b03_t01_no_signal_contract.h"
DOC = ROOT / "docs/research/phase2-lite-c3/candidate-b-b03-t01-r2b-r2b-r2-source-only-adapter.md"
WORKFLOW = ROOT / ".github/workflows/c3-candidate-b-t01-r2b-r2b-r2-adapter-source.yml"
MANIFEST = ROOT / "MANIFEST.sha256"

# This source module contains NO loader and is import-safe. The original
# contract module is safe to import; individual native RED tests are NOT run.
sys.path.insert(0, str(ROOT / "tools/research"))
import c3_candidate_b_t01_r2_source_only_adapter as adapter  # noqa: E402

from test_c3_candidate_b_t01_r2b_contract_red import (  # noqa: E402
    FAULT_CATALOG, FAULT_IDS, POLICY_FIELDS, REQUEST_FIELDS, case, policy,
    steps_for,
)


def _plan(phase="KILL", fault="nominal-synthetic", *, instance=None, edit=None):
    request = case(phase, fault)
    if edit is not None:
        edit(request)
    adapter_instance = adapter.SourceOnlyAdapter() if instance is None else instance
    return request, adapter_instance.plan(request)


def test_adapter_reproduces_the_exact_frozen_67_catalog_and_12_key_request():
    assert adapter.FAULT_CATALOG == FAULT_CATALOG
    assert adapter.FAULT_IDS == FAULT_IDS
    assert adapter.REQUEST_FIELDS == REQUEST_FIELDS
    assert len(adapter.REQUEST_FIELDS) == 12
    assert set(adapter.POLICY_FIELD_ORDER) == POLICY_FIELDS
    assert len(adapter.POLICY_FIELD_ORDER) == 8
    assert len(adapter.FAULT_IDS) == 67
    assert adapter.FAULT_CATALOG[65] == ("MODE", "different-mode")
    assert adapter.FAULT_CATALOG[66] == ("KILL", "nominal-synthetic")


@pytest.mark.parametrize("phase,fault", FAULT_CATALOG, ids=[
    f"{n:02d}-{phase}-{fault}"
    for n, (phase, fault) in enumerate(FAULT_CATALOG, 1)
])
def test_each_finite_synthetic_case_creates_only_review_data(phase, fault):
    request, plan = _plan(phase, fault)
    if phase == "MODE":
        assert plan is None
        return
    assert type(plan) is adapter.SourceBindingPlan
    assert plan.scenario_id == FAULT_IDS[(phase, fault)]
    assert plan.nonce == request["nonce"]
    assert plan.attempt_steps == tuple(
        {"TERM": 1, "KILL": 2}[step] for step in steps_for(phase, fault)
    )
    expected_phase = (
        1 if (phase == "TERM" or
              (phase == "ERRNO" and fault.startswith("term-")) or
              (phase == "MUTATION" and (fault in adapter.TERM_MUTANTS or
                                        fault == "allow-second-term")))
        else 2 if phase in {"KILL", "ERRNO", "MUTATION"} else 3
    )
    assert plan.phase_enum == expected_phase
    assert plan.original_deadline == tuple(
        request["original_policy"][k] for k in adapter.POLICY_FIELD_ORDER
    )
    assert plan.attempt_deadline == tuple(
        request["attempt_policy"][k] for k in adapter.POLICY_FIELD_ORDER
    )
    assert plan.native_dispatches == 0
    assert plan.native_execution_allowed is False


@pytest.mark.parametrize("field", sorted(REQUEST_FIELDS))
def test_missing_every_request_field_is_blocked_and_nonce_consumed(field):
    request = case("KILL", "nominal-synthetic")
    instance = adapter.SourceOnlyAdapter()
    original_nonce = request["nonce"]
    broken = dict(request)
    broken.pop(field)
    assert instance.plan(broken) is None
    # If missing nonce, it wasn't a valid nonce to consume; otherwise it was.
    if field != "nonce":
        assert instance.plan(request) is None
    else:
        assert instance.plan(request) is not None
    assert original_nonce > 0


@pytest.mark.parametrize("field,value", (
    ("abi_version", True), ("abi_version", "1"),
    ("mode", "non-T01"), ("mode", 1),
    ("fixture_target", "fixture:synthetic-owned-anchor-group-T01_alias"),
    ("fixture_target", 12345),
    ("mock_only", 1), ("mock_only", False),
    ("now_ms", True), ("now_ms", -1), ("now_ms", float(108000)),
    ("term_sent_at_ms", "108000"), ("term_sent_at_ms", -1),
    ("phase", "WRONG"), ("phase", True),
    ("fault", "wrong-scenario"), ("fault", None),
    ("attempt_sequence", ["TERM", "KILL"]),
    ("attempt_sequence", ("KILL", "TERM")),
    ("attempt_sequence", ("TERM", "KILL", "KILL", "KILL")),
    ("nonce", 0), ("nonce", -1), ("nonce", True),
    ("nonce", 1 << 64),
))
def test_malformed_request_cannot_create_review_plan(field, value):
    request = case("KILL", "nominal-synthetic")
    request[field] = value
    assert adapter.SourceOnlyAdapter().plan(request) is None


@pytest.mark.parametrize("field,value", (
    ("t0_ms", True), ("t0_ms", "100000"),
    ("outer_budget_ms", 0), ("cleanup_reserve_ms", 0),
    ("term_grace_ms", 0), ("kill_entry_margin_ms", 0),
    ("outer_deadline_ms", 0), ("term_cutoff_ms", 10**20),
    ("kill_cutoff_ms", -2),
))
@pytest.mark.parametrize("which", ("original_policy", "attempt_policy"))
def test_bad_policy_always_blocks_before_any_native_bridge(which, field, value):
    request = case("KILL", "nominal-synthetic")
    request[which] = dict(request[which])
    request[which][field] = value
    assert adapter.SourceOnlyAdapter().plan(request) is None


@pytest.mark.parametrize("damage", ("extra", "missing", "wrong-key-type", "wrong-dict-type"))
@pytest.mark.parametrize("which", ("original_policy", "attempt_policy"))
def test_policy_schema_remains_exact(which, damage):
    request = case("KILL", "nominal-synthetic")
    if damage == "extra":
        request[which] = {**request[which], "other": 1}
    elif damage == "missing":
        request[which] = {k: v for k, v in request[which].items() if k != "t0_ms"}
    elif damage == "wrong-key-type":
        request[which] = {**request[which], 1: 1}
    else:
        request[which] = tuple(request[which].values())
    assert adapter.SourceOnlyAdapter().plan(request) is None


def test_valid_but_different_attempt_policy_is_type_checked_not_falsely_native_denied():
    p = policy(t0=107000)
    request = case("KILL", "rebase-original-policy", replacement=p)
    plan = adapter.SourceOnlyAdapter().plan(request)
    assert plan is not None
    assert plan.original_deadline != plan.attempt_deadline
    # Real C Gate must deny any rebase; source validation is not a fake C Gate.
    assert plan.native_dispatches == 0


def test_nonce_replay_and_repair_after_malformed_are_denied_on_same_instance():
    request = case("KILL", "nominal-synthetic")
    inst = adapter.SourceOnlyAdapter()
    assert inst.plan(request) is not None
    assert inst.plan(dict(request)) is None
    rebase = dict(request, phase="TERM", fault="root-unsafe",
                  attempt_sequence=("TERM",))
    assert inst.plan(rebase) is None
    next_request = case("KILL", "nominal-synthetic")
    broken = dict(next_request, mock_only=1)
    assert inst.plan(broken) is None
    assert inst.plan(next_request) is None


def test_adapter_does_not_accept_extra_field_or_nondict():
    req = case("KILL", "nominal-synthetic")
    req["run_native"] = True
    assert adapter.SourceOnlyAdapter().plan(req) is None
    for bad in (None, False, [], (), "C", 7):
        assert adapter.SourceOnlyAdapter().plan(bad) is None


def test_native_call_is_unconditionally_blocked():
    assert adapter.REVIEW_ONLY_NO_LOAD is True
    assert adapter.GROUP_SIGNAL_AUTHORIZED is False
    assert adapter.C_DISPATCH_IMPLEMENTED is False
    with pytest.raises(RuntimeError, match="SOURCE_ONLY_NO_C_LOAD"):
        adapter.native_call()
    with pytest.raises(RuntimeError, match="SOURCE_ONLY_NO_C_LOAD"):
        adapter.native_call("/any/file.so", approved=True)


def test_source_ast_contains_no_native_loader_or_os_process_escape():
    assert SOURCE.is_file()
    source = SOURCE.read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.extend(x.name.split(".")[0] for x in node.names)
        if isinstance(node, ast.ImportFrom):
            imported.append((node.module or "").split(".")[0])
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            assert node.func.attr not in {
                "CDLL", "PyDLL", "dlopen", "dlsym", "kill", "killpg",
                "system", "Popen", "spawn", "exec", "load_library",
            }, ast.dump(node)
    assert set(imported) == {"__future__", "dataclasses"}
    assert "libSystem" not in source
    assert "ctypes" not in source.split('from dataclasses import dataclass', 1)[1]
    assert "tools/research/c3_candidate_b_kill.c" not in source
    assert "c_adapter_dispatches=1" not in source
    assert "SOURCE_ONLY_NO_C_LOAD" in source


def test_frozen_source_header_and_platform_hashes_are_review_metadata_only():
    assert hashlib.sha256(NATIVE_C.read_bytes()).hexdigest() == adapter.REVIEWED_C_SHA256
    assert hashlib.sha256(HEADER.read_bytes()).hexdigest() == adapter.REVIEWED_HEADER_SHA256
    assert adapter.REVIEWED_R1_HEAD == "a39124235c89a92794eb973a0c718e766eb4f64d"
    assert dict(adapter.HISTORICAL_LINKED_SHA256) == {
        "Darwin-arm64": "87d87fd11bc2a38f066e41b1c51d8282eafe2d174f35a87354fdd728a01c5c9a",
        "Linux-x86_64": "9bbf2acd784cebb363fb9fb1bc6a2b71781b84d76c38262e44cc60bbe56d8918",
    }
    # Historical hash strings do not attest a FUTURE linked image byte buffer.
    assert all(len(v) == 64 for _, v in adapter.HISTORICAL_LINKED_SHA256)


def test_design_stage_manifest_and_no_load_actions_policy():
    assert DOC.is_file() and WORKFLOW.is_file()
    s = DOC.read_text(encoding="utf-8")
    y = WORKFLOW.read_text(encoding="utf-8")
    for token in ("P3-01", "P3-02", "P3-03", "NO_LOAD",
                  "SOURCE_ONLY_NO_C_LOAD", "172", "191",
                  "group_kill_authorized=false", "g2_qualified=false",
                  "PRE-COMPILE", "PRE-LOAD", "NOT_RUN/BLOCK"):
        assert token in s, token
    for token in ("persist-credentials: false", "contents: read",
                  "C3B03_T01_R2B_R2B_R2_NO_LOAD: \"true\"",
                  "test ! -e tools/research/c3_candidate_b_kill.c",
                  "test ! -e tools/research/c3_candidate_b_kill_t01_no_signal_probe.py",
                  "MANIFEST.sha256",
                  "tests/test_c3_candidate_b_t01_r2b_r2b_r2_source_only_adapter.py"):
        assert token in y, token
    for forbidden in ("workflow_dispatch", "continue-on-error:", "|| true",
                      "ctypes.CDLL(", "dlopen(", "os.kill("):
        assert forbidden not in y
    lines = MANIFEST.read_text(encoding="utf-8").splitlines()
    for path in (SOURCE, DOC, WORKFLOW):
        entry = "./" + path.relative_to(ROOT).as_posix()
        assert sum(line.endswith("  " + entry) for line in lines) == 1
