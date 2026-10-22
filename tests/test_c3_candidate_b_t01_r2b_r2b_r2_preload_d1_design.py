"""R2b-R2b-R2-D1 PRE-LOAD provenance DESIGN: text and synthetic fixtures ONLY.

The fixture linter in this test IS NOT a runtime security gate. Even a fully
well-formed *fabricated* evidence record can at most say REVIEW_REQUIRED_NO_LOAD.
No compiler/linker, subprocess, dynamic loader, C function or signal is run.
"""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path
import re

import pytest

ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs/research/phase2-lite-c3/candidate-b-b03-t01-r2b-r2b-r2-preload-provenance-d1-design.md"
WORKFLOW = ROOT / ".github/workflows/c3-candidate-b-t01-r2b-r2b-r2-preload-provenance-d1-design.yml"
SOURCE_ONLY = ROOT / "tools/research/c3_candidate_b_t01_r2_source_only_adapter.py"
C_SOURCE = ROOT / "tools/research/c3_candidate_b_t01_no_signal_candidate.c"
C_HEADER = ROOT / "tests/native/c3_b03_t01_no_signal_contract.h"
MANIFEST = ROOT / "MANIFEST.sha256"
PARENT_HEAD = "d8e011fb538d9638f67e5c0d928340d374677a1b"
PARENT_TREE = "cce4d65bdd64dac4d7fa6604abaca6925d04102c"
REVIEWED_C_SHA256 = "5a1292787584632fac20c86bbe62e50153e82b0ecb36ad190446bf4b7b714195"
REVIEWED_HEADER_SHA256 = "7c9bd037ecf65da8de91605846c4ac4fc7ceaebbd0ca2fe983ecfef630c9958e"

STAGES = (
    "S0_REVIEWED_SOURCE_LOCK",
    "S1_PRE_COMPILE_TOOLCHAIN_LOCK",
    "S2_COMPILED_OBJECT_LOCK",
    "S3_FINAL_LINKED_IMAGE_LOCK",
    "S4_ADAPTER_ABI_IMPORT_GRAPH_LOCK",
    "S5_PRE_LOAD_PATH_CUSTODY_LOCK",
    "S6_INDEPENDENT_PRELOAD_DECISION",
)
HEX_FIELDS = (
    "reviewed_head", "reviewed_tree", "manifest_sha256",
    "source_sha256", "header_sha256", "adapter_source_sha256",
    "transitive_import_graph_sha256", "compiler_binary_sha256",
    "linker_binary_sha256", "toolchain_resource_sha256",
    "sdk_sysroot_sha256", "environment_sha256",
    "ordered_argv_sha256", "object_sha256", "final_linked_sha256",
    "abi_layout_sha256", "exports_sha256", "imports_sha256",
    "relocations_sha256", "initializer_sha256",
    "complete_cfg_sha256", "loader_path_custody_sha256",
    "independent_review_digest",
)
GATE_FIELDS = (
    "source_inputs_verified_before_compile",
    "toolchain_locked_before_compile",
    "sdk_and_nested_tools_frozen",
    "object_bound_to_source_toolchain",
    "linked_bound_to_object_linker",
    "abi_and_import_graph_reviewed",
    "all_machine_code_edges_classified",
    "all_relocations_initializers_classified",
    "loader_opens_exact_verified_inode",
)
FALSE_FIELDS = (
    "native_loader_invoked", "candidate_c_executed",
    "group_signal_sent", "runtime_load_authorized",
)
ALL_FIELDS = frozenset((
    "fixture_kind", "build_session_sha256", "platform", "stages",
) + HEX_FIELDS + GATE_FIELDS + FALSE_FIELDS)
HEX_RE = re.compile(r"[0-9a-f]{64}")


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _synthetic_submission() -> dict:
    """The contents are FICTITIOUS; they do not attest real filesystem bytes."""
    data = {
        "fixture_kind": "SYNTHETIC_TEST_EVIDENCE_ONLY",
        "build_session_sha256": _digest("fake-session-not-a-build"),
        "platform": "Darwin-arm64",
    }
    for name in HEX_FIELDS:
        data[name] = _digest("not-observed-" + name)
    data["reviewed_head"] = PARENT_HEAD
    data["reviewed_tree"] = PARENT_TREE
    data["source_sha256"] = REVIEWED_C_SHA256
    data["header_sha256"] = REVIEWED_HEADER_SHA256
    for name in GATE_FIELDS:
        data[name] = True  # Only hypothetical for rejection tests.
    for name in FALSE_FIELDS:
        data[name] = False
    records = []
    previous = data["reviewed_tree"]
    for index, stage in enumerate(STAGES):
        evidence = _digest(f"fake-observation-{index}-{stage}")
        records.append({
            "step": stage,
            "sequence": index,
            "build_session_sha256": data["build_session_sha256"],
            "previous_evidence_sha256": previous,
            "evidence_sha256": evidence,
        })
        previous = evidence
    data["stages"] = tuple(records)
    return data


def _offline_design_lint(fixture: object) -> str:
    """Checks only mock record SHAPE. NEVER returns a permission or runtime PASS."""
    if type(fixture) is not dict or set(fixture) != ALL_FIELDS:
        return "REJECT"
    if fixture["fixture_kind"] != "SYNTHETIC_TEST_EVIDENCE_ONLY":
        return "REJECT"
    if fixture["platform"] not in ("Darwin-arm64", "Linux-x86_64"):
        return "REJECT"
    if (type(fixture["build_session_sha256"]) is not str or
            HEX_RE.fullmatch(fixture["build_session_sha256"]) is None):
        return "REJECT"
    if any(
        type(fixture[key]) is not str or HEX_RE.fullmatch(fixture[key]) is None
        for key in HEX_FIELDS
    ):
        return "REJECT"
    if fixture["reviewed_head"] != PARENT_HEAD:
        return "REJECT"
    if fixture["reviewed_tree"] != PARENT_TREE:
        return "REJECT"
    if fixture["source_sha256"] != REVIEWED_C_SHA256:
        return "REJECT"
    if fixture["header_sha256"] != REVIEWED_HEADER_SHA256:
        return "REJECT"
    if any(fixture[name] is not True for name in GATE_FIELDS):
        return "REJECT"
    if any(fixture[name] is not False for name in FALSE_FIELDS):
        return "REJECT"
    records = fixture["stages"]
    if type(records) is not tuple or len(records) != len(STAGES):
        return "REJECT"
    previous = fixture["reviewed_tree"]
    for index, expected in enumerate(STAGES):
        row = records[index]
        if type(row) is not dict or set(row) != {
            "step", "sequence", "build_session_sha256",
            "previous_evidence_sha256", "evidence_sha256",
        }:
            return "REJECT"
        if row["step"] != expected or type(row["sequence"]) is not int:
            return "REJECT"
        if row["sequence"] != index or row["build_session_sha256"] != fixture[
            "build_session_sha256"
        ]:
            return "REJECT"
        if row["previous_evidence_sha256"] != previous:
            return "REJECT"
        if type(row["evidence_sha256"]) is not str:
            return "REJECT"
        if HEX_RE.fullmatch(row["evidence_sha256"]) is None:
            return "REJECT"
        previous = row["evidence_sha256"]
    # No amount of self-reported "green" data can grant Native C authority.
    return "REVIEW_REQUIRED_NO_LOAD"


def test_formally_well_formed_synthetic_claim_is_never_a_native_load_permit():
    fixture = _synthetic_submission()
    assert _offline_design_lint(fixture) == "REVIEW_REQUIRED_NO_LOAD"
    assert "AUTHORIZED" not in _offline_design_lint(fixture)
    assert "ALLOW" not in _offline_design_lint(fixture)
    assert fixture["native_loader_invoked"] is False
    assert fixture["candidate_c_executed"] is False


@pytest.mark.parametrize("field", sorted(ALL_FIELDS))
def test_missing_any_provenance_claim_is_rejected(field):
    fixture = _synthetic_submission()
    fixture.pop(field)
    assert _offline_design_lint(fixture) == "REJECT"


@pytest.mark.parametrize("field", sorted(HEX_FIELDS))
@pytest.mark.parametrize("invalid", ("", "not-a-sha256", "0" * 63, "F" * 64, None))
def test_absent_malformed_or_case_changed_sha_is_rejected(field, invalid):
    fixture = _synthetic_submission()
    fixture[field] = invalid
    assert _offline_design_lint(fixture) == "REJECT"


@pytest.mark.parametrize("gate", GATE_FIELDS)
@pytest.mark.parametrize("bad", (False, None, 1, "true"))
def test_missing_stage_provenance_cannot_be_accepted_from_fixture(gate, bad):
    fixture = _synthetic_submission()
    fixture[gate] = bad
    assert _offline_design_lint(fixture) == "REJECT"


@pytest.mark.parametrize("gate", FALSE_FIELDS)
@pytest.mark.parametrize("bad", (True, 1, "false", None))
def test_runtime_call_or_load_claim_never_passes_no_load_fixture(gate, bad):
    fixture = _synthetic_submission()
    fixture[gate] = bad
    assert _offline_design_lint(fixture) == "REJECT"


@pytest.mark.parametrize("field,value", (
    ("build_session_sha256", None),
    ("build_session_sha256", 22),
    ("fixture_kind", "ACTUAL_APPROVED"),
    ("fixture_kind", True),
    ("platform", "Darwin-x86_64"),
    ("platform", "Linux-arm64"),
    ("platform", "unknown"),
    ("reviewed_head", "0" * 40),
    ("reviewed_tree", "1" * 40),
    ("source_sha256", "a" * 64),
    ("header_sha256", "b" * 64),
    ("build_session_sha256", "not-a-digest"),
))
def test_wrong_parent_or_claimed_authority_is_rejected(field, value):
    fixture = _synthetic_submission()
    fixture[field] = value
    assert _offline_design_lint(fixture) == "REJECT"


@pytest.mark.parametrize("bad_kind", ("extra", "missing", "wrong-type", "reverse", "swap"))
def test_missing_added_or_reordered_evidence_stages_are_blocked(bad_kind):
    fixture = _synthetic_submission()
    records = list(fixture["stages"])
    if bad_kind == "extra":
        records.append(dict(records[-1]))
    elif bad_kind == "missing":
        records.pop(3)
    elif bad_kind == "wrong-type":
        records[1] = "fake-record"
    elif bad_kind == "reverse":
        records.reverse()
    else:
        records[1], records[2] = records[2], records[1]
    fixture["stages"] = tuple(records)
    assert _offline_design_lint(fixture) == "REJECT"


@pytest.mark.parametrize("position", range(len(STAGES)))
@pytest.mark.parametrize("mutation", (
    "wrong-session", "wrong-previous", "wrong-evidence", "bad-order",
    "extra-field", "missing-field",
))
def test_broken_one_session_digest_chain_is_rejected(position, mutation):
    fixture = _synthetic_submission()
    records = [dict(r) for r in fixture["stages"]]
    row = records[position]
    if mutation == "wrong-session":
        row["build_session_sha256"] = _digest("other-inert-session")
    elif mutation == "wrong-previous":
        row["previous_evidence_sha256"] = _digest("spliced-provenance")
    elif mutation == "wrong-evidence":
        row["evidence_sha256"] = "malformed"
    elif mutation == "bad-order":
        row["sequence"] = True
    elif mutation == "extra-field":
        row["approved"] = True
    else:
        row.pop("evidence_sha256")
    fixture["stages"] = tuple(records)
    assert _offline_design_lint(fixture) == "REJECT"


@pytest.mark.parametrize("tamper", (
    ("compiled-first", "S2_COMPILED_OBJECT_LOCK", 1),
    ("load-before-preload", "S5_PRE_LOAD_PATH_CUSTODY_LOCK", 0),
))
def test_out_of_order_stage_must_fail_closed(tamper):
    _label, stage, position = tamper
    fixture = _synthetic_submission()
    records = [dict(r) for r in fixture["stages"]]
    records[position]["step"] = stage
    fixture["stages"] = tuple(records)
    assert _offline_design_lint(fixture) == "REJECT"


def test_malformed_extra_authorization_key_is_rejected():
    fixture = _synthetic_submission()
    fixture["approved"] = True
    assert _offline_design_lint(fixture) == "REJECT"


@pytest.mark.parametrize("platform", ("Darwin-arm64", "Linux-x86_64"))
def test_even_complete_platform_specific_claim_requires_human_review(platform):
    fixture = _synthetic_submission()
    fixture["platform"] = platform
    assert _offline_design_lint(fixture) == "REVIEW_REQUIRED_NO_LOAD"


@pytest.mark.parametrize("required", (
    "P3-01", "P3-02", "P3-03", "Review #5610072946",
    PARENT_HEAD, PARENT_TREE, "Standards PASS / Spec PASS",
    "S0 REVIEWED_SOURCE_LOCK", "S1 PRE_COMPILE_TOOLCHAIN_LOCK",
    "S2 COMPILED_OBJECT_LOCK", "S3 FINAL_LINKED_IMAGE_LOCK",
    "S4 ADAPTER_ABI_IMPORT_GRAPH_LOCK", "S5 PRE_LOAD_PATH_CUSTODY_LOCK",
    "S6 INDEPENDENT_PRELOAD_DECISION", "PRE-COMPILE",
    "before launching compiler", "compiler", "linker", "sdk",
    "Git Tree", "MANIFEST.sha256", "build_session_sha",
    "transitive imports", "sizeof", "alignof", "offsetof",
    "ABI", "strong", "MH_DYLIB", "ET_DYN", "LC_ROUTINES_64",
    "__init_offsets", "DT_NEEDED", "CFG", "TOCTOU",
    "DYLD_INSERT_LIBRARIES", "LD_PRELOAD", "REVIEW_REQUIRED_NO_LOAD",
    "NO_LOAD=true", "SOURCE_ONLY_NO_C_LOAD", "191 expected RED",
    "no dynamic", "group_kill_authorized=false", "reuse_proven=false",
    "g2_qualified=false", "NOT_RUN/BLOCK", "R2b-R2b-R3",
    "ExecSupervisor", "REST/MCP Multi Exec",
))
def test_design_names_complete_obligations_and_blocked_stages(required):
    s = DOC.read_text(encoding="utf-8")
    assert required.lower() in s.lower(), required


def test_design_parent_source_and_manifest_are_byte_checked_not_historical_aliases():
    assert hashlib.sha256(C_SOURCE.read_bytes()).hexdigest() == REVIEWED_C_SHA256
    assert hashlib.sha256(C_HEADER.read_bytes()).hexdigest() == REVIEWED_HEADER_SHA256
    assert SOURCE_ONLY.is_file() and DOC.is_file() and WORKFLOW.is_file()
    entries = {}
    for row in MANIFEST.read_text(encoding="utf-8").splitlines():
        sha, path = row.split("  ", 1)
        assert path.startswith("./") and path not in entries
        entries[path] = sha
        assert hashlib.sha256((ROOT / path).read_bytes()).hexdigest() == sha, path
    for path in (SOURCE_ONLY, C_SOURCE, C_HEADER, DOC, WORKFLOW, Path(__file__)):
        assert "./" + path.relative_to(ROOT).as_posix() in entries


def test_d1_design_has_no_native_adapter_or_run_paths():
    for name in (
        "tools/research/c3_candidate_b_kill.c",
        "tools/research/c3_candidate_b_kill_t01_no_signal_probe.py",
        "tools/research/run_c3_candidate_b_kill.py",
    ):
        assert not (ROOT / name).exists()
    s = SOURCE_ONLY.read_text(encoding="utf-8")
    tree = ast.parse(s)
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(n.name.split(".")[0] for n in node.names)
        if isinstance(node, ast.ImportFrom):
            imports.add((node.module or "").split(".")[0])
    assert imports == {"__future__", "dataclasses"}
    assert 'raise RuntimeError("SOURCE_ONLY_NO_C_LOAD:' in s
    assert "C_DISPATCH_IMPLEMENTED = False" in s


def test_d1_workflow_cannot_compile_link_import_load_or_signal():
    y = WORKFLOW.read_text(encoding="utf-8")
    for required in (
        "contents: read", "persist-credentials: false", "macos-15",
        "ubuntu-latest", '"3.13"', '"3.14"', "MANIFEST.sha256",
        "test ! -e tools/research/c3_candidate_b_kill.c",
        "test ! -e tools/research/c3_candidate_b_kill_t01_no_signal_probe.py",
        "test ! -e tools/research/run_c3_candidate_b_kill.py",
        "C3B03_T01_R2B_R2B_D1_DESIGN_ONLY=true",
        "C3B03_T01_R2B_R2B_D1_NO_LOAD=true",
        "C3B03_T01_R2B_R2B_D1_GROUP_SIGNAL_AUTHORIZED=false",
        "tests/test_c3_candidate_b_t01_r2b_r2b_r2_preload_d1_design.py",
        "tests/test_c3_candidate_b_t01_r2b_r2b_r2_source_only_adapter.py",
    ):
        assert required in y, required
    for forbidden in (
        "workflow_dispatch", "continue-on-error:", "|| true",
        "ctypes.CDLL(", "dlopen(", "killpg(", "os.kill(",
        "cc -shared", "cc -dynamiclib", "cc -c", "pip install -e",
        "tests/test_c3_candidate_b_t01_r2b_contract_red.py",
    ):
        assert forbidden not in y, forbidden
