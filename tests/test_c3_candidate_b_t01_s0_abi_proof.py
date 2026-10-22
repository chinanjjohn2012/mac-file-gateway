"""B03-T01 R2b-R2b-R2-S0: REAL source/compile-only ABI proof; no load.

Positive assertions compile a single C11 layout TU to a private ephemeral .o.
Negative mutants of the test-owned HEADER must fail compile with ABI_* static
assert messages. No compiled function executes and no shared library is made.
"""
from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
import re

import pytest

ROOT = Path(__file__).resolve().parents[1]
PROOF_SOURCE = ROOT / "tools/research/c3_candidate_b_t01_s0_abi_proof.py"
ABI_C = ROOT / "tests/native/c3_b03_t01_abi_compile_only.c"
DOC = ROOT / "docs/research/phase2-lite-c3/candidate-b-b03-t01-r2b-r2b-r2-s0-abi-proof.md"
WORKFLOW = ROOT / ".github/workflows/c3-candidate-b-t01-r2b-r2b-r2-s0-abi-proof.yml"
MANIFEST = ROOT / "MANIFEST.sha256"

import sys
sys.path.insert(0, str(PROOF_SOURCE.parent))
import c3_candidate_b_t01_s0_abi_proof as proof  # noqa: E402


@pytest.fixture(scope="module")
def actual_proof():
    report = proof.collect_static_abi_evidence()
    print("C3B03_T01_S0_ACTUAL_SOURCE_PROOF=" + json.dumps(
        report, sort_keys=True, separators=(",", ":")
    ))
    return report


def test_actual_header_and_full_manifest_are_byte_locked(actual_proof):
    report = actual_proof
    assert report["manifest_entry_count"] >= 200
    assert report["reviewed_c_sha256"] == proof.REVIEWED_C_SHA256
    assert report["reviewed_c_header_sha256"] == proof.REVIEWED_HEADER_SHA256
    assert report["abi_assertions_sha256"] == hashlib.sha256(
        ABI_C.read_bytes()
    ).hexdigest()
    assert re.fullmatch(r"[a-f0-9]{40}", report["current_head"])
    assert re.fullmatch(r"[a-f0-9]{40}", report["current_tree"])
    assert re.fullmatch(r"[a-f0-9]{64}", report["manifest_sha256"])
    assert report["reviewed_parent_head"] == proof.PARENT_HEAD
    assert report["reviewed_parent_tree"] == proof.PARENT_TREE


def test_real_compiler_entry_hash_occurs_before_compile_and_is_not_full_s1(actual_proof):
    report = actual_proof
    assert report["compiler_returncode"] == 0, report["compiler_stderr"]
    assert report["entry_hashed_before_compiler_spawn"] is True
    assert report["compiler_entry_sha256_precompile"] == (
        report["compiler_entry_sha256_postcompile"]
    )
    assert re.fullmatch(r"[a-f0-9]{64}", report["compiler_entry_sha256_precompile"])
    assert re.fullmatch(r"[a-f0-9]{64}", report["compiler_argv_sha256"])
    assert re.fullmatch(r"[a-f0-9]{64}", report["abi_object_sha256"])
    assert report["compiler_sdk_linker_closure_complete"] is False
    assert report["admission"] == "REVIEW_REQUIRED_NO_LOAD"


def test_real_c11_abi_assertions_pin_each_frozen_structure(actual_proof):
    assert actual_proof["abi_struct_sizes"] == {
        "c3b03_t01_deadline_t": 64,
        "c3b03_t01_mock_input_t": 208,
        "c3b03_t01_mock_output_t": 48,
    }
    source = ABI_C.read_text(encoding="utf-8")
    assert source.count("CHECK_OFF(") >= 29
    assert source.count("CHECK_SIZE(") >= 6
    assert "CHECK_FIELD_SIZE(c3b03_t01_mock_input_t, attempt_sequence, 12)" in source
    for field in (
        "abi_version", "mode", "phase", "scenario_nonce", "scenario_fault_id",
        "attempt_sequence_len", "attempt_sequence", "term_fact_mask",
        "kill_fact_mask", "now_ms", "term_sent_at_ms",
        "original_policy", "attempt_policy",
    ):
        assert f"CHECK_OFF(c3b03_t01_mock_input_t, {field}," in source
    for field in (
        "abi_version", "decision", "scenario_nonce", "fake_term_transport_calls",
        "fake_kill_transport_calls", "real_group_signal_syscalls",
        "term_attempts", "kill_attempts", "signals_closed",
        "group_signals_after_close",
    ):
        assert f"CHECK_OFF(c3b03_t01_mock_output_t, {field}," in source
    assert "int c3b03_t01_no_signal_candidate(" not in source


@pytest.mark.parametrize("name,old,new", (
    ("wrong-steps", "c3b03_t01_phase_t attempt_sequence[3];",
     "c3b03_t01_phase_t attempt_sequence[2];"),
    ("wrong-nonce", "uint64_t scenario_nonce;",
     "uint32_t scenario_nonce;"),
    ("wrong-output", "uint32_t real_group_signal_syscalls;",
     "uint64_t real_group_signal_syscalls;"),
    ("wrong-count", "#define C3B03_T01_MAX_SCENARIO_ID UINT32_C(67)",
     "#define C3B03_T01_MAX_SCENARIO_ID UINT32_C(68)"),
    ("wrong-phase", "C3B03_T01_PHASE_KILL = 2",
     "C3B03_T01_PHASE_KILL = 4"),
    ("wrong-deadline", "int64_t cleanup_reserve_ms;",
     "uint32_t cleanup_reserve_ms;"),
))
def test_real_c11_compiler_rejects_mutated_layout_and_enum(name, old, new):
    original = proof.HEADER.read_text(encoding="utf-8")
    assert old in original
    mutant = original.replace(old, new, 1).encode("utf-8")
    assert mutant != proof.HEADER.read_bytes()
    result = proof._compile_abi_once(header=mutant, variant=name)
    assert result["compiler_returncode"] != 0, name
    assert result["abi_object_sha256"] is None
    assert "ABI_" in result["compiler_stderr"], result["compiler_stderr"]
    assert result["admission"] == "REJECT"
    assert result["native_loader_invoked"] is False
    assert result["candidate_c_executed"] is False
    print("C3B03_T01_S0_ABI_NEGATIVE=" + name + ":REJECT")


def test_no_native_load_even_on_success(actual_proof):
    for key in ("native_loader_invoked", "candidate_c_executed",
                "group_signal_authorized", "real_preload_chain_proven",
                "ffi_binding_proven", "first_c_load_authorized"):
        assert actual_proof[key] is False, key
    assert actual_proof["native_dispatches"] == 0
    assert actual_proof["admission"] == "REVIEW_REQUIRED_NO_LOAD"


def test_fixed_argv_has_only_c11_compile_object_and_no_runtime_linker():
    assert "-DC3B03_TEST_NO_SIGNAL_STUB=1" in proof._COMPILE_FLAGS
    assert "-std=c11" in proof._COMPILE_FLAGS
    assert proof._ALLOWED_PATH == "/usr/bin:/bin:/usr/sbin:/sbin"
    src = PROOF_SOURCE.read_text(encoding="utf-8")
    tree = ast.parse(src)
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(x.name.split(".")[0] for x in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add((node.module or "").split(".")[0])
    assert imported == {
        "__future__", "hashlib", "os", "pathlib", "re", "shutil",
        "stat", "subprocess", "tempfile", "time",
    }
    for forbidden in ("ctypes", "cffi", "dlopen(", "CDLL(",
                      "killpg(", "os.kill(", "os.getpgid(", "posix_spawn("):
        assert forbidden not in src
    assert '"-c", "-o"' in src
    assert 'str(source),' in src


@pytest.mark.parametrize("required", (
    "S0", "S1", "S2", "S3", "S4", "S5", "S6",
    "P3-01", "P3-02", "P3-03", "SOURCE_ONLY_NO_LOAD",
    "REVIEW_REQUIRED_NO_LOAD", "compiler", "SDK", "PRE-COMPILE",
    "before compiler", "sizeof", "offsetof", "alignof", "C11",
    "64", "208", "48", "scenario_nonce", "attempt_sequence",
    "source", "header", "Git Tree", "MANIFEST.sha256",
    "partial", "unknown", "191 expected RED", "NOT_RUN/BLOCK",
    "group_kill_authorized=false", "reuse_proven=false",
    "g2_qualified=false", "ExecSupervisor", "REST/MCP Multi Exec",
))
def test_design_documents_scope_and_pending_native_gates(required):
    s = DOC.read_text(encoding="utf-8")
    assert required.lower() in s.lower(), required


def test_workflow_remains_test_only_no_load_and_manifest_complete():
    y = WORKFLOW.read_text(encoding="utf-8")
    for phrase in (
        "persist-credentials: false", "permissions:", "contents: read",
        "macos-15", "ubuntu-latest", '"3.13"', '"3.14"',
        "MANIFEST.sha256", "SOURCE_ONLY_NO_LOAD",
        "C3B03_T01_S0_GROUP_SIGNAL_AUTHORIZED: \"false\"",
        "tests/test_c3_candidate_b_t01_s0_abi_proof.py",
        "test ! -e tools/research/c3_candidate_b_kill.c",
        "test ! -e tools/research/c3_candidate_b_kill_t01_no_signal_probe.py",
    ):
        assert phrase in y, phrase
    for forbidden in (
        "workflow_dispatch", "continue-on-error:", "|| true",
        "ctypes.CDLL(", "dlopen(", "cc -shared", "cc -dynamiclib",
        "os.kill(", "killpg(",
    ):
        assert forbidden not in y, forbidden
    lines = MANIFEST.read_text(encoding="utf-8").splitlines()
    for f in (PROOF_SOURCE, ABI_C, DOC, WORKFLOW, Path(__file__)):
        path = "./" + f.relative_to(ROOT).as_posix()
        assert sum(line.endswith("  " + path) for line in lines) == 1


def test_no_source_or_ci_can_produce_a_native_runtime_authorization():
    s = DOC.read_text(encoding="utf-8")
    assert "P3-01/P3-02 remain OPEN" in s
    assert "first C load remains BLOCK" in s
    assert "R2b-R2b-R3" in s
    assert not (ROOT / "tools/research/c3_candidate_b_kill.c").exists()
    assert not (ROOT / "tools/research/c3_candidate_b_kill_t01_no_signal_probe.py").exists()
    assert not (ROOT / "tools/research/run_c3_candidate_b_kill.py").exists()
