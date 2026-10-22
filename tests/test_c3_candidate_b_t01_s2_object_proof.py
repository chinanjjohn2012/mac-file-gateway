"""S2 candidate C .o evidence and negatives, NEVER link/load/run candidate C."""
from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
import re
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
PROOF = ROOT / "tools/research/c3_candidate_b_t01_s2_object_proof.py"
S0_PROOF = ROOT / "tools/research/c3_candidate_b_t01_s0_abi_proof.py"
DOC = ROOT / "docs/research/phase2-lite-c3/candidate-b-b03-t01-r2b-r2b-r2-s2-object-proof.md"
WORKFLOW = ROOT / ".github/workflows/c3-candidate-b-t01-r2b-r2b-r2-s2-object-proof.yml"
MANIFEST = ROOT / "MANIFEST.sha256"
C_SOURCE = ROOT / "tools/research/c3_candidate_b_t01_no_signal_candidate.c"
HEADER = ROOT / "tests/native/c3_b03_t01_no_signal_contract.h"

sys.path.insert(0, str(PROOF.parent))
import c3_candidate_b_t01_s2_object_proof as proof  # noqa: E402


@pytest.fixture(scope="module")
def actual_object():
    report = proof._compile_candidate()
    summary = {k: v for k, v in report.items() if k != "disassembly"}
    print("C3B03_T01_S2_ACTUAL_OBJECT_PROOF=" + json.dumps(
        summary, sort_keys=True, separators=(",", ":")
    ))
    print("C3B03_T01_S2_CANDIDATE_DISASM_BEGIN")
    print(report["disassembly"])
    print("C3B03_T01_S2_CANDIDATE_DISASM_END")
    return report


def test_actual_object_is_bound_to_frozen_source_and_current_git_tree(actual_object):
    report = actual_object
    assert report["source_sha256_precompile"] == (
        report["source_sha256_postcompile"] == proof.s0.REVIEWED_C_SHA256
    )
    assert report["header_sha256_precompile"] == (
        report["header_sha256_postcompile"] == proof.s0.REVIEWED_HEADER_SHA256
    )
    assert report["reviewed_parent_head"] == (
        "37bd517932b6b99952fa19e091b5b8d94d45939a"
    )
    assert report["reviewed_parent_tree"] == (
        "ed661fe5ea2297b89c9ba96bd312e01a5a4f8778"
    )
    assert re.fullmatch(r"[a-f0-9]{40}", report["current_head"])
    assert re.fullmatch(r"[a-f0-9]{40}", report["current_tree"])
    assert report["current_head"] != report["reviewed_parent_head"]
    assert re.fullmatch(r"[a-f0-9]{64}", report["manifest_sha256"])
    assert re.fullmatch(r"[a-f0-9]{64}", report["candidate_object_sha256"])


def test_real_object_witness_is_compile_only_and_no_preload_approval(actual_object):
    x = actual_object
    assert x["compiler_entry_hash_recorded_before_compile"] is True
    assert x["compiler_entry_sha256_precompile"] == (
        x["compiler_entry_sha256_postcompile"]
    )
    assert x["complete_toolchain_sdk_closure_proven"] is False
    assert x["complete_object_cfg_proven"] is False
    assert x["final_linked_image_proven"] is False
    assert x["python_ffi_binding_proven"] is False
    assert x["preload_custody_proven"] is False
    assert x["first_c_load_authorized"] is False
    assert x["candidate_c_executed"] is False
    assert x["native_loader_invoked"] is False
    assert x["group_signal_authorized"] is False
    assert x["native_dispatches"] == 0
    assert x["admission"] == "REVIEW_REQUIRED_NO_LOAD"
    assert x["undefined_symbols"] == 0
    assert "T" in x["defined_global_symbol"]
    assert proof.SYMBOL in x["defined_global_symbol"]
    assert re.fullmatch(r"[a-f0-9]{64}", x["disassembly_sha256"])
    assert hashlib.sha256(x["disassembly"].encode("utf-8")).hexdigest() == (
        x["disassembly_sha256"]
    )


@pytest.mark.parametrize("variant", ("missing", "zero", "two"))
def test_actual_compiler_rejects_missing_or_bad_no_signal_macro(variant):
    report = proof._compile_candidate(variant)
    assert report["admission"] == "REJECT"
    assert report["compiler_returncode"] != 0
    assert report["candidate_object_sha256"] is None
    assert report["native_loader_invoked"] is False
    assert report["candidate_c_executed"] is False
    print("C3B03_T01_S2_NEGATIVE_MACRO=" + variant + ":REJECT")


def test_compiler_source_include_closure_is_exactly_the_reviewed_subset():
    text = C_SOURCE.read_text(encoding="utf-8")
    proof._validated_source_includes(text)
    with pytest.raises(ValueError, match="UNREVIEWED_C_INCLUDE_CLOSURE"):
        proof._validated_source_includes(text + "\n#include <signal.h>\n")
    with pytest.raises(ValueError, match="UNREVIEWED_C_INCLUDE_CLOSURE"):
        proof._validated_source_includes(text.replace(
            '#include <stdint.h>', '#include <signal.h>', 1
        ))


@pytest.mark.parametrize("kind", (
    "wrong-platform", "wrong-architecture", "extra-global",
    "weak-global", "alternate-global", "missing-global",
    "undefined-import", "syscall-opcode", "svc-instruction",
    "trap-instruction", "missing-disassembly", "unknown-arch",
))
def test_object_metadata_negative_mutants_fail_before_any_future_load(
    actual_object, kind
):
    x = actual_object
    platform = x["platform"]
    desc = x["object_format"]
    defined = x["defined_global_symbol"]
    undefined = ""
    disassembly = x["disassembly"]
    if kind == "wrong-platform":
        platform = "Linux" if platform == "Darwin" else "Darwin"
    if kind == "wrong-architecture":
        desc = "PE32 Intel 80386 executable"
    if kind == "extra-global":
        defined += "\n0000000000000120 T injected_symbol"
    if kind == "weak-global":
        defined = defined.replace(" T ", " W ")
    if kind == "alternate-global":
        defined = defined.replace(proof.SYMBOL, "malicious_other")
    if kind == "missing-global":
        defined = ""
    if kind == "undefined-import":
        undefined = "U killpg"
    if kind == "syscall-opcode":
        disassembly += "\n\tsyscall\n"
    if kind == "svc-instruction":
        disassembly += "\n svc #0\n"
    if kind == "trap-instruction":
        disassembly += "\n\tud2\n"
    if kind == "missing-disassembly":
        disassembly = "tiny"
    if kind == "unknown-arch":
        platform = "Solaris"
    with pytest.raises(ValueError, match=(
        "UNKNOWN_OBJECT_PLATFORM|UNEXPECTED_OBJECT_ARCH_OR_FORMAT|"
        "UNEXPECTED_OBJECT_SYMBOLS|OBJECT_UNDEFINED_SYMBOLS|"
        "OBJECT_KNOWN_FORBIDDEN_INSTRUCTION|OBJECT_DISASSEMBLY_MISSING"
    )):
        proof._metadata_gate(platform, desc, defined, undefined, disassembly)


def test_object_metadata_is_not_complete_machine_code_cfg_evidence(actual_object):
    assert proof._metadata_gate(
        actual_object["platform"], actual_object["object_format"],
        actual_object["defined_global_symbol"], "",
        actual_object["disassembly"],
    ) == "OBJECT_INSPECTION_PARTIAL_NO_LOAD"
    # This narrower gate does NOT prove all branch targets / all relocations.
    assert actual_object["complete_object_cfg_proven"] is False
    assert actual_object["final_linked_image_proven"] is False


@pytest.mark.parametrize("variant", ("bad", "runtime", "", "reviewed-no-approval"))
def test_unknown_compile_requests_are_rejected(variant):
    if variant == "reviewed-no-approval":
        variant = "reviewed" + "-native"
    with pytest.raises(ValueError, match="UNKNOWN_TEST_VARIANT"):
        proof._compile_candidate(variant)


def test_only_fixed_argv_fixed_tools_and_inert_source_are_available():
    src = PROOF.read_text(encoding="utf-8")
    tree = ast.parse(src)
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(n.name.split(".")[0] for n in node.names)
        if isinstance(node, ast.ImportFrom):
            imports.add((node.module or "").split(".")[0])
    assert imports == {
        "__future__", "hashlib", "os", "pathlib", "re", "stat",
        "tempfile", "time", "c3_candidate_b_t01_s0_abi_proof",
    }
    assert "C3B03_TEST_NO_SIGNAL_STUB=1" in proof.FLAGS
    assert all(p.startswith("/usr/bin/") for v in proof.TOOLS.values() for p in v)
    for forbidden in ("ctypes.CDLL(", "cffi", "dlopen(", "killpg(",
                      "os.kill(", "os.getpgid(", "posix_spawn(",
                      "subprocess.Popen(", "subprocess.call("):
        assert forbidden not in src
    assert 'args.extend(("-I", str(HEADER.parent), "-c", "-o",' in src
    assert "compiler_entry_hash_recorded_before_compile" in src
    assert "complete_toolchain_sdk_closure_proven" in src


@pytest.mark.parametrize("token", (
    "P3-01", "P3-02", "P3-03", "S0", "S1", "S2", "S3", "S4",
    "S5", "S6", "REVIEW_REQUIRED_NO_LOAD",
    "SOURCE_ONLY_NO_LOAD", "191 expected RED", "NO_LOAD",
    "PRE-COMPILE", "candidate C", "cc -c", "COMPILER",
    "compiler", "SDK", "toolchain", "HEADER", "MANIFEST.sha256",
    "Git Tree", "SHA256", "T", "undefined", "symbol",
    "relocation", "CFG", "disassembly", "non-atomic",
    "group_kill_authorized=false", "reuse_proven=false",
    "g2_qualified=false", "NOT_RUN/BLOCK", "ExecSupervisor",
    "REST/MCP Multi Exec", "NO C EXEC",
))
def test_scope_doc_falsifiability_and_hard_block_boundaries(token):
    assert token.lower() in DOC.read_text(encoding="utf-8").lower(), token


def test_manifest_and_ci_are_strict_and_native_behavior_red_untouched():
    s = WORKFLOW.read_text(encoding="utf-8")
    for required in (
        "permissions:", "contents: read", "persist-credentials: false",
        "macos-15", "ubuntu-latest", '"3.13"', '"3.14"',
        "MANIFEST.sha256", "C3B03_T01_S2_SOURCE_ONLY_NO_LOAD",
        "C3B03_T01_S2_GROUP_SIGNAL_AUTHORIZED",
        "tests/test_c3_candidate_b_t01_s2_object_proof.py",
        "test ! -e tools/research/c3_candidate_b_kill.c",
        "test ! -e tools/research/c3_candidate_b_kill_t01_no_signal_probe.py",
    ):
        assert required in s, required
    for forbidden in (
        "workflow_dispatch", "continue-on-error:", "|| true",
        "ctypes.CDLL(", "dlopen(", "cc -shared", "cc -dynamiclib",
        "os.kill(", "killpg(",
    ):
        assert forbidden not in s
    lines = MANIFEST.read_text(encoding="utf-8").splitlines()
    for path in (PROOF, DOC, WORKFLOW, Path(__file__)):
        target = "./" + path.relative_to(ROOT).as_posix()
        assert sum(line.endswith("  " + target) for line in lines) == 1
    assert not (ROOT / "tools/research/c3_candidate_b_kill.c").exists()
    assert not (ROOT / "tools/research/c3_candidate_b_kill_t01_no_signal_probe.py").exists()
    assert not (ROOT / "tools/research/run_c3_candidate_b_kill.py").exists()
