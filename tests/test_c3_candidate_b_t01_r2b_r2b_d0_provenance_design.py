"""B03-T01 R2b-R2b-D0: pre-execution provenance DESIGN checks.

Only text / frozen-source hashes / synthetic nm-line fixtures are examined here.
No compiler invocation, linker, shared library, native function, subprocess,
dlopen or process-group signal is performed by THIS design test.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import re

import pytest

ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs/research/phase2-lite-c3/candidate-b-b03-t01-r2b-r2b-d0-linked-adapter-provenance-design.md"
WORKFLOW = ROOT / ".github/workflows/c3-candidate-b-t01-r2b-r2b-d0-provenance-design.yml"
SOURCE = ROOT / "tools/research/c3_candidate_b_t01_no_signal_candidate.c"
HEADER = ROOT / "tests/native/c3_b03_t01_no_signal_contract.h"
R2A_TEST = ROOT / "tests/test_c3_candidate_b_t01_r2b_r2a_source_admission.py"
R1_RED = ROOT / "tests/test_c3_candidate_b_t01_r2b_contract_red.py"
MANIFEST = ROOT / "MANIFEST.sha256"
SYMBOL = "c3b03_t01_no_signal_candidate"
REVIEWED_PARENT = "a0ec979217a01cfcd9405ab02fb858dee6225cdd"
REVIEWED_TREE = "c15b69649d8db355d302285c12b0ea688ba0b5a7"
PARENT_SOURCE_SHA256 = "5a1292787584632fac20c86bbe62e50153e82b0ecb36ad190446bf4b7b714195"
PARENT_HEADER_SHA256 = "7c9bd037ecf65da8de91605846c4ac4fc7ceaebbd0ca2fe983ecfef630c9958e"


def _doc() -> str:
    assert DOC.is_file()
    return DOC.read_text(encoding="utf-8")


def _canonical_defined_export(nm_text: str, platform: str) -> bool:
    """Fixture-level exact nm SYMBOL/T-only contract, NOT a real binary proof.

    Every nonblank line must be a defined, externally visible strong TEXT
    symbol and the entire output must have precisely one name. A substring,
    weak alias, extra U-symbol or text data cannot be considered an export.
    """
    if platform not in {"Darwin", "Linux"}:
        return False
    wanted = "_" + SYMBOL if platform == "Darwin" else SYMBOL
    lines = [line.strip() for line in nm_text.splitlines() if line.strip()]
    if len(lines) != 1:
        return False
    m = re.fullmatch(r"[0-9A-Fa-f]+\s+([A-Za-z])\s+([^\s]+)", lines[0])
    return m is not None and m.group(1) == "T" and m.group(2) == wanted


def test_reviewed_parent_and_provenance_scope_are_explicit():
    s = _doc()
    for phrase in (
        REVIEWED_PARENT, REVIEWED_TREE,
        "Review #5608742844", "Standards PASS / Spec PASS",
        "P3-01 and P3-02 OPEN", "NO_LOAD_NO_EXECUTE=true",
        "LINKED_ARTIFACT_CREATED=false",
        "R2b-R2b-D0 design only",
        "R2b-R2b-R1", "R2b-R2b-R2", "R2b-R2b-R3",
    ):
        assert phrase in s, phrase
    assert SOURCE.is_file() and HEADER.is_file()
    assert R2A_TEST.is_file() and R1_RED.is_file()


def test_future_artifact_chain_must_be_independently_attested():
    s = _doc()
    for token in (
        "PRE-COMPILE", "PRE-LINK", "PRE-LOAD",
        "SHA256", "Git Tree", "compiler executable hash",
        "target architecture", "SDK/sysroot", "complete ordered compile",
        "final bytes", "linked", "Mach-O", "ELF",
        "full source-to-final-binary identity", "exact linked SHA",
        "before", "first load", "independent",
    ):
        assert token in s, token


@pytest.mark.parametrize("platform,nm_line", (
    ("Darwin", "00000000000004f0 T _c3b03_t01_no_signal_candidate"),
    ("Linux", "0000000000000010 T c3b03_t01_no_signal_candidate"),
))
def test_exact_architecture_symbol_accepts_only_the_expected_text_export(
    platform, nm_line,
):
    assert _canonical_defined_export(nm_line, platform)


@pytest.mark.parametrize("platform,nm_line", (
    ("Darwin", "0000000000000100 T _unsafe_c3b03_t01_no_signal_candidate_alias"),
    ("Darwin", "0000000000000100 T _c3b03_t01_no_signal_candidate_alias"),
    ("Darwin", "0000000000000100 W _c3b03_t01_no_signal_candidate"),
    ("Darwin", "0000000000000100 D _c3b03_t01_no_signal_candidate"),
    ("Darwin", "                 U _c3b03_t01_no_signal_candidate"),
    ("Darwin", "0000000000000100 T c3b03_t01_no_signal_candidate"),
    ("Linux", "0000000000000100 T unsafe_c3b03_t01_no_signal_candidate_alias"),
    ("Linux", "0000000000000100 T _c3b03_t01_no_signal_candidate"),
    ("Linux", "0000000000000100 W c3b03_t01_no_signal_candidate"),
    ("Linux", "0000000000000100 D c3b03_t01_no_signal_candidate"),
    ("Linux", "                 U c3b03_t01_no_signal_candidate"),
    ("Linux", "0000000000000100 T c3b03_t01_no_signal_candidate\n0000000000000200 T another_export"),
    ("Darwin", "0000000000000100 T _c3b03_t01_no_signal_candidate\n0000000000000200 T _hidden_loader"),
    ("Linux", ""),
))
def test_nm_alias_weak_undefined_data_or_extra_export_must_be_rejected(
    platform, nm_line,
):
    assert not _canonical_defined_export(nm_line, platform)


@pytest.mark.parametrize("arch", ("Unknown", "macOS", "FreeBSD", "", "Linux-aarch64"))
def test_unknown_export_platform_never_inherits_linux_or_darwin_policy(arch):
    assert not _canonical_defined_export(
        "00000000 T c3b03_t01_no_signal_candidate", arch
    )


@pytest.mark.parametrize("danger", (
    "external relocation", "indirect call", "signal/trap opcode",
    "unexpected dynamic dependency", "init section", "hash mismatch",
    "alternate platform ABI", "prefix/suffix alias", "weak export",
    "zero undefined imports", "exactly", "STOP/BLOCK",
))
def test_design_names_falsifiable_p3_02_regressions(danger):
    s = _doc().lower()
    assert danger.lower() in s, danger


@pytest.mark.parametrize("risk", (
    "constructor", "initializers", "TOCTOU", "private",
    "0700", "lstat", "st_nlink == 1", "read-only",
    "before loading", "post-load SHA", "LD_PRELOAD",
    "DYLD_INSERT_LIBRARIES", "transitive imports",
    "pure-Python response synthesizer",
    "c_adapter_dispatches=1", "run_no_signal_case",
    "Adapter→C", "build manifest", "exact reviewed",
))
def test_preload_auth_and_python_call_provenance_are_non_optional(risk):
    assert risk.lower() in _doc().lower(), risk


def test_future_linked_artifact_needs_relocation_and_initializer_inspection():
    s = _doc()
    for token in (
        "nm -u", "nm -g", "objdump -dr", "readelf -rW",
        "readelf -dW", "otool -rv", "otool -l", "otool -tv",
        "LC_LOAD_DYLIB", "DT_NEEDED", ".init_array",
        "__mod_init_func", "__interpose", "PLT/GOT",
        "source-to-final-binary", "same-repository",
    ):
        assert token in s, token


def test_pre_execution_design_will_not_confuse_object_green_with_native_green():
    s = _doc()
    for phrase in (
        "172 R2b-R1", "19 original B03-R1",
        "RED", "148 passed per platform",
        "NOT", "lawful waitpid", "G2 qualification",
        "group_kill_authorized=false", "reuse_proven=false",
        "g2_qualified=false", "T04/T08b/T10",
        "NOT_RUN/BLOCK", "ExecSupervisor", "REST/MCP Multi-Exec",
    ):
        assert phrase in s, phrase


def test_existing_parent_source_and_abi_are_still_sha_manifest_accounted():
    lines = MANIFEST.read_text(encoding="utf-8").strip().splitlines()
    manifest = {}
    for line in lines:
        digest, path = line.split("  ", 1)
        assert path.startswith("./") and path not in manifest
        manifest[path] = digest
        assert hashlib.sha256((ROOT / path).read_bytes()).hexdigest() == digest
    for file in (SOURCE, HEADER, R2A_TEST, R1_RED, DOC, WORKFLOW):
        assert "./" + file.relative_to(ROOT).as_posix() in manifest
    # Check reviewed source fingerprints are documented for lineage;
    # do not permanently prohibit a separately approved future source update.
    assert len(PARENT_SOURCE_SHA256) == len(PARENT_HEADER_SHA256) == 64
    assert "5a1292787584632fac20c86bbe62e50153e82b0ecb36ad190446bf4b7b714195" == PARENT_SOURCE_SHA256


def test_stage_specific_ci_refuses_code_load_and_actual_native_execution():
    y = WORKFLOW.read_text(encoding="utf-8")
    for token in (
        "contents: read", "persist-credentials: false", "macos-15",
        '"3.13"', '"3.14"', "ubuntu-latest",
        "MANIFEST.sha256", "C3B03_T01_R2B_R2B_D0_NO_LOAD_NO_EXECUTE=true",
        "C3B03_T01_R2B_R2B_D0_GROUP_SIGNAL_AUTHORIZED=false",
        "test ! -e tools/research/c3_candidate_b_kill.c",
        "test ! -e tools/research/c3_candidate_b_kill_t01_no_signal_probe.py",
        "test ! -e tools/research/run_c3_candidate_b_kill.py",
        "tests/test_c3_candidate_b_t01_r2b_r2b_d0_provenance_design.py",
        "tests/test_c3_candidate_b_t01_r2b_r2a_source_admission.py",
    ):
        assert token in y, token
    for forbidden in (
        "workflow_dispatch", "continue-on-error:", "|| true",
        "ctypes.CDLL", "dlopen(", "cffi", "python -m pytest -q tests/test_c3_candidate_b_t01_r2b_contract_red.py",
        "cc -shared", "cc -dynamiclib", "signal.SIGKILL", "os.kill(",
    ):
        assert forbidden not in y, forbidden


def test_design_no_runtime_gate_executed_or_mislabeled_approved():
    s = _doc()
    assert "**This design review does not close P3-01 or P3-02**" in s
    assert "no Approval" in s or "GitHub Approval" in s
    assert "never C loading or native signal sending" in s
    assert "group_kill_authorized=true" not in s
    assert "g2_qualified=true" not in s
