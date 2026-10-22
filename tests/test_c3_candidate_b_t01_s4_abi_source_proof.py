"""S4 ABI data-only / Source-only AST proof. No candidate link, load or C run."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import re
import sys
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools/research"))
import c3_candidate_b_t01_s4_abi_source_proof as s4  # noqa: E402

DOC = ROOT / "docs/research/phase2-lite-c3/candidate-b-b03-t01-r2b-r2b-r2-s4-abi-source-proof.md"
WF = ROOT / ".github/workflows/c3-candidate-b-t01-r2b-r2b-r2-s4-abi-source-proof.yml"

@pytest.fixture(scope="module")
def evidence():
    p = s4.collect_static_s4_evidence()
    print("C3B03_S4_STATIC_ABI_SOURCE_PROOF=" +
          json.dumps(p, sort_keys=True, separators=(",", ":")))
    return p

def test_actual_compiled_c11_asserts_and_python_layout(evidence):
    p = evidence
    assert p["head"] != p["reviewed_s3_parent_head"]
    assert p["reviewed_s3_parent_head"] == "9c0bb5b0e83a3d5e57bacd2d55eaff174cb9c8fc"
    assert p["reviewed_s3_parent_tree"] == "ad13b6a5a362874f50dc7ad70778b55c48f7f5c8"
    assert re.fullmatch(r"[a-f0-9]{40}", p["head"])
    assert re.fullmatch(r"[a-f0-9]{40}", p["tree"])
    assert p["real_compiler_entry_sha256_precompile"] == p[
        "real_compiler_entry_sha256_postcompile"]
    assert p["real_c11_abi_assertions_compiled_only"] is True
    assert p["python_ctypes_data_layout_only"] is True
    assert p["layout"]["sizes"]["c3b03_t01_deadline_t"] == 64
    assert p["layout"]["sizes"]["c3b03_t01_mock_input_t"] == 208
    assert p["layout"]["sizes"]["c3b03_t01_mock_output_t"] == 48
    assert p["layout"]["assertion_counts"] == {
        "SIZE": 9, "ALIGN": 6, "OFF": 31, "FIELD_SIZE": 31,
    }
    assert p["layout"]["field_count"] == 31
    assert p["layout"]["field_offsets"]["c3b03_t01_mock_input_t"][
        "attempt_policy"] == 144
    for digest in (
        p["layout_sha256"], p["adapter_source_graph_sha256"],
        p["abi_assertion_object_sha256"], p["manifest_sha256"],
        *p["reviewed_inputs"].values(),
    ):
        assert re.fullmatch(r"[a-f0-9]{64}", digest)

def test_source_only_adapter_ast_not_executed_or_promoted(evidence):
    x = evidence["adapter_source_graph"]
    assert x["direct_import_roots"] == ("__future__", "dataclasses")
    assert x["native_call_always_denies"] is True
    assert tuple(x["policy_fields"]) == s4.POLICY_FIELDS
    assert tuple(x["binding_fields"]) == s4.BINDING_FIELDS
    assert x["transitive_stdlib_import_closure_proven"] is False
    assert x["future_ffi_adapter_import_graph_proven"] is False

def test_s4_remains_partial_no_load_with_zero_dispatch(evidence):
    assert evidence["admission"] == "REVIEW_REQUIRED_NO_LOAD"
    assert evidence["native_dispatches"] == 0
    for key in (
        "candidate_c_compiled", "candidate_c_executed",
        "native_candidate_library_linked", "native_candidate_library_loaded",
        "native_adapter_imported", "complete_toolchain_sdk_closure_proven",
        "complete_python_ffi_import_graph_proven",
        "actual_python_to_c_call_binding_proven",
        "loader_inode_custody_proven", "first_c_load_authorized",
        "group_kill_authorized", "reuse_proven", "g2_qualified",
    ):
        assert evidence[key] is False, key

@pytest.mark.parametrize("mutation", (
    "new-import", "dynamic-import", "new-capability", "remove-deny",
    "alter-policy-order", "add-binding-field", "change-request-fields",
))
def test_unreviewed_source_adapter_mutants_fail_closed(mutation):
    source = s4.SOURCE_ONLY.read_text(encoding="utf-8")
    if mutation == "new-import":
        source += "\nimport ctypes\n"
    elif mutation == "dynamic-import":
        source += "\n__import__('os')\n"
    elif mutation == "new-capability":
        source = source.replace(
            "C_DISPATCH_IMPLEMENTED = False", "C_DISPATCH_IMPLEMENTED = True", 1)
    elif mutation == "remove-deny":
        source = source.replace(
            'raise RuntimeError("SOURCE_ONLY_NO_C_LOAD: independent PRE-LOAD review required")',
            'return None', 1)
    elif mutation == "alter-policy-order":
        source = source.replace(
            '"t0_ms", "outer_budget_ms",', '"outer_budget_ms", "t0_ms",', 1)
    elif mutation == "add-binding-field":
        source = source.replace(
            "    scenario_id: int\n",
            "    scenario_id: int\n    forbidden_extra: int\n", 1)
    elif mutation == "change-request-fields":
        source = source.replace(
            '"mock_only", "attempt_sequence",',
            '"mock_only", "attempt_sequence", "unreviewed",', 1)
    with pytest.raises((ValueError, SyntaxError)):
        s4._static_adapter_graph(source)

@pytest.mark.parametrize("mutation", (
    "type-change", "array-length", "field-reorder", "extra-field",
    "missing-field",
))
def test_frozen_c_header_mutants_fail_closed(mutation):
    text = s4.HEADER.read_text(encoding="utf-8")
    if mutation == "type-change":
        text = text.replace("    uint32_t abi_version;",
                            "    uint64_t abi_version;", 1)
    elif mutation == "array-length":
        text = text.replace("attempt_sequence[3]", "attempt_sequence[4]", 1)
    elif mutation == "field-reorder":
        text = text.replace(
            "    int64_t t0_ms;\n    int64_t outer_budget_ms;",
            "    int64_t outer_budget_ms;\n    int64_t t0_ms;", 1)
    elif mutation == "extra-field":
        text = text.replace(
            "    int64_t t0_ms;",
            "    int64_t unreviewed;\n    int64_t t0_ms;", 1)
    else:
        text = text.replace("    uint32_t scenario_fault_id;\n", "", 1)
    with pytest.raises(ValueError):
        s4._header_fields(text)

@pytest.mark.parametrize("mutation", (
    "offset-drift", "field-size-drift", "missing-offset",
    "missing-field-size", "duplicate-assert",
))
def test_c11_assertions_cover_entire_python_layout(mutation):
    source = s4.ABI_C.read_text(encoding="utf-8")
    off = "CHECK_OFF(c3b03_t01_mock_input_t, attempt_policy, 144);"
    field_size = "CHECK_FIELD_SIZE(c3b03_t01_mock_input_t, attempt_policy, 64);"
    if mutation == "offset-drift":
        source = source.replace(off, off.replace("144", "152"), 1)
    elif mutation == "field-size-drift":
        source = source.replace(field_size, field_size.replace("64", "56"), 1)
    elif mutation == "missing-offset":
        source = source.replace(off, "", 1)
    elif mutation == "missing-field-size":
        source = source.replace(field_size, "", 1)
    else:
        source += "\n" + off + "\n"
    with pytest.raises(ValueError):
        s4._verify_existing_c_assertions(source)

def test_research_only_ci_manifest_and_hard_boundaries():
    doc = DOC.read_text(encoding="utf-8")
    for phrase in (
        "S4", "PARTIAL", "NO LOAD", "NO C EXEC",
        "P3-01", "P3-02", "P3-03", "S5", "S6",
        "191 expected RED", "REVIEW_REQUIRED_NO_LOAD",
        "group_kill_authorized=false", "reuse_proven=false",
        "g2_qualified=false", "R2b-R2b-R3",
        "NOT_RUN/BLOCK", "SOURCE_ONLY_NO_C_LOAD",
    ):
        assert phrase.lower() in doc.lower(), phrase
    wf = WF.read_text(encoding="utf-8")
    for phrase in (
        "contents: read", "persist-credentials: false",
        "MANIFEST.sha256", "macos-15", "ubuntu-latest",
        'python-version: "3.13"', 'python-version: "3.14"',
        "tests/test_c3_candidate_b_t01_s4_abi_source_proof.py",
        "C3B03_S4_GROUP_SIGNAL_AUTHORIZED",
        "test ! -e tools/research/c3_candidate_b_kill.c",
    ):
        assert phrase in wf, phrase
    for forbidden in (
        "workflow_dispatch", "continue-on-error:", "|| true",
        "ctypes.CDLL(", "dlopen(", "cc -shared", "cc -dynamiclib",
        "killpg(", "os.kill(", "test_c3_candidate_b_t01_r2b_contract_red.py",
    ):
        assert forbidden not in wf, forbidden
    for p in (
        "tools/research/c3_candidate_b_kill.c",
        "tools/research/c3_candidate_b_kill_t01_no_signal_probe.py",
        "tools/research/run_c3_candidate_b_kill.py",
    ):
        assert not (ROOT / p).exists()
    manifest = s4.s0.checked_manifest()
    for path in (DOC, WF, Path(__file__), Path(s4.__file__)):
        key = "./" + path.relative_to(ROOT).as_posix()
        assert key in manifest
        assert manifest[key] == hashlib.sha256(path.read_bytes()).hexdigest()
