"""S3 real inert linked object evidence: NO LOAD / NO C EXEC."""
from __future__ import annotations
import copy
import hashlib
import json
from pathlib import Path
import re
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools/research"))
import c3_candidate_b_t01_s3_linked_proof as s3  # noqa: E402

DOC = ROOT / "docs/research/phase2-lite-c3/candidate-b-b03-t01-r2b-r2b-r2-s3-linked-proof.md"
WORKFLOW = ROOT / ".github/workflows/c3-candidate-b-t01-r2b-r2b-r2-s3-linked-proof.yml"

@pytest.fixture(scope="module")
def evidence():
    x = s3._compile_link_observe()
    out = {k: v for k, v in x.items() if k not in ("inspection", "image_header_bytes")}
    print("C3B03_S3_ACTUAL_LINKED_PROOF=" + json.dumps(out, sort_keys=True, default=str))
    for key, body in x["inspection"].items():
        print("C3B03_S3_" + key.upper() + "_SHA256=" + hashlib.sha256(body.encode()).hexdigest())
        print("C3B03_S3_" + key.upper() + "_BEGIN")
        print(body)
        print("C3B03_S3_" + key.upper() + "_END")
    return x

def test_real_linked_bytes_are_bound_to_same_session_object(evidence):
    x = evidence
    assert x["source_sha256"] == s3.s0.REVIEWED_C_SHA256
    assert x["header_sha256"] == s3.s0.REVIEWED_HEADER_SHA256
    assert x["compiler_entry_sha256_precompile"] == x["compiler_entry_sha256_postlink"]
    assert x["reviewed_s2_parent_head"] == "21d0f6b00e21f154d41703d1f1910080b066c884"
    assert x["reviewed_s2_parent_tree"] == "8610fa21b8bd7470e8d3d155be5a2453c8d1d90b"
    for item in ("object_sha256", "linked_image_sha256"):
        assert re.fullmatch(r"[0-9a-f]{64}", x[item])
    assert x["image_owner_uid"] >= 0
    assert x["image_device"] > 0 and x["image_inode"] > 0
    assert all(re.fullmatch(r"[a-f0-9]{64}", v) for v in x["stage_digests"].values())
    assert x["linked_image_bytes_observed"] is True
    assert x["linked_header"].endswith("_PARTIAL")
    assert s3._metadata_gate(x["platform"], x["inspection"]) == "LINKED_METADATA_PARTIAL_NO_LOAD"

def test_s3_never_authorizes_load_execution_or_signals(evidence):
    x = evidence
    assert x["admission"] == "REVIEW_REQUIRED_NO_LOAD"
    for field in ("toolchain_sdk_closure_proven", "complete_final_binary_cfg_proven",
                  "final_linked_image_lock_proven", "adapter_ffi_proven",
                  "loader_inode_custody_proven", "first_c_load_authorized",
                  "candidate_c_executed", "native_loader_invoked",
                  "group_kill_authorized", "reuse_proven", "g2_qualified"):
        assert x[field] is False, field
    assert x["native_dispatches"] == 0
    assert not (ROOT / "tools/research/c3_candidate_b_kill.c").exists()

@pytest.mark.parametrize("mutation", (
    "export", "undefined", "format", "disassembly", "instruction",
    "constructor", "relocation", "dependency",
))
def test_synthetic_linked_metadata_mutants_rejected(evidence, mutation):
    p = evidence["platform"]
    x = copy.deepcopy(evidence["inspection"])
    if mutation == "export":
        x["exports"] += "\n0000000000000001 T extra"
    elif mutation == "undefined":
        x["undefined"] = "U killpg"
    elif mutation == "format":
        x["file"] = "PE32 executable"
    elif mutation == "disassembly":
        x["disasm"] = ""
    elif mutation == "instruction":
        x["disasm"] += "\n\tsyscall"
    elif mutation == "constructor":
        if p == "Darwin":
            x["loader"] += "\n__mod_init_func"
        else:
            x["loader"] += "\n(INIT_ARRAY)"
    elif mutation == "relocation":
        if p == "Darwin":
            x["reloc"] += "\n3 entries"
        else:
            x["reloc"] += "\nR_X86_64_64"
    elif mutation == "dependency":
        if p == "Darwin":
            x["dependencies"] += "\n/evil.dylib (compatibility version 1.0.0)"
        else:
            x["loader"] += "\n(NEEDED)"
    with pytest.raises(ValueError):
        s3._metadata_gate(p, x)

@pytest.mark.parametrize("kind", ("bad-platform", "bad-header", "bad-command"))
def test_byte_header_negatives_rejected_offline(evidence, kind):
    raw = bytearray(evidence["image_header_bytes"])
    platform = evidence["platform"]
    if kind == "bad-platform":
        with pytest.raises(ValueError):
            s3._linked_header_gate(bytes(raw), "Windows", "fake")
        return
    if kind == "bad-header":
        raw[0:4] = b"XXXX"
    elif kind == "bad-command":
        if platform == "Darwin":
            raw[32:36] = b"XXXX"
        else:
            raw[16:18] = b"XX"
    with pytest.raises(ValueError):
        s3._linked_header_gate(bytes(raw), platform,
                               s3.NAME + (".dylib" if platform == "Darwin" else ".so"))

def test_scope_is_strict_no_load():
    text = DOC.read_text()
    for phrase in ("P3-01", "P3-02", "S3", "NO LOAD", "NO C EXEC",
                   "group_kill_authorized=false", "reuse_proven=false",
                   "g2_qualified=false", "191 expected RED",
                   "REVIEW_REQUIRED_NO_LOAD"):
        assert phrase.lower() in text.lower()
    wf = WORKFLOW.read_text()
    for phrase in ("contents: read", "persist-credentials: false",
                   "MANIFEST.sha256", "macos-15", "ubuntu-latest",
                   "tests/test_c3_candidate_b_t01_s3_linked_proof.py"):
        assert phrase in wf
    for forbidden in ("workflow_dispatch", "continue-on-error", "|| true",
                      "ctypes.CDLL(", "dlopen(", "os.kill(", "killpg("):
        assert forbidden not in wf
