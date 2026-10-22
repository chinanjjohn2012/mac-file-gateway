"""S6 deny-only cross-stage S3/S4/S5 static evidence. NO Native load/call."""
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
import c3_candidate_b_t01_s6_offline_deny_proof as s6  # noqa: E402

DOC = ROOT / "docs/research/phase2-lite-c3/candidate-b-b03-t01-r2b-r2b-r2-s6-offline-deny.md"
WF = ROOT / ".github/workflows/c3-candidate-b-t01-r2b-r2b-r2-s6-offline-deny.yml"


@pytest.fixture(scope="module")
def actual():
    bundle, summary = s6.collect_real_partial_evidence()
    print("C3B03_S6_REAL_PARTIAL_CROSS_STAGE_NO_LOAD=" + json.dumps(
        summary, sort_keys=True, separators=(",", ":")
    ))
    return bundle, summary


def _verdict(bundle, summary):
    return s6.decide_offline_only(
        bundle, head=summary["head"], tree=summary["tree"],
        manifest_sha=summary["manifest_sha256"],
    )


def test_real_same_job_partial_s3_s4_s5_never_grants_load(actual):
    bundle, summary = actual
    assert summary["reviewed_s5_parent_head"] == (
        "499574be48ad14d2473f73342cc2c7708fb81b8f"
    )
    assert summary["reviewed_s5_parent_tree"] == (
        "7d7393ee645d9c9bcfbf54f755a03ccc4aee02af"
    )
    assert summary["head"] != summary["reviewed_s5_parent_head"]
    assert re.fullmatch(r"[a-f0-9]{40}", summary["head"])
    assert re.fullmatch(r"[a-f0-9]{40}", summary["tree"])
    assert re.fullmatch(r"[a-f0-9]{64}", summary["manifest_sha256"])
    assert tuple(bundle) == s6.STAGES
    assert _verdict(bundle, summary) == "REVIEW_REQUIRED_NO_LOAD"
    assert summary["admission"] == "REVIEW_REQUIRED_NO_LOAD"
    assert summary["missing_full_gates"] == s6.MISSING_FULL_GATES
    assert len(summary["missing_full_gates"]) == 6
    assert summary["collector_sessions_are_atomic"] is False
    assert summary["full_s6_independent_decision_made"] is False
    assert summary["s0_s3_stage_digest_consistency_recomputed"] is True
    assert summary["object_inspection_preimage_recorded"] is True
    assert summary["actual_static_object_bytes_sha_recomputed"] is True
    assert summary["actual_static_linked_bytes_sha_recomputed"] is True
    assert summary["actual_static_linked_header_prefix_checked"] is True
    assert 0 < summary["static_object_byte_count"] <= s6.s3._STATIC_ARTIFACT_LIMIT
    assert 0 < summary["static_linked_byte_count"] <= s6.s3._STATIC_ARTIFACT_LIMIT
    assert summary["author_or_synthetic_self_approval_accepted"] is False
    assert summary["first_c_load_authorized"] is False
    assert summary["native_dispatches"] == 0
    for key in ("native_loader_invoked", "candidate_c_executed",
                "actual_native_loader_custody_proven", "group_kill_authorized",
                "reuse_proven", "g2_qualified"):
        assert summary[key] is False


def test_fresh_actual_frozen_inputs_and_stage_artifacts(actual):
    bundle, summary = actual
    a, b, c = (bundle[name] for name in s6.STAGES)
    assert a["source_sha256"] == summary["sources"]["candidate_c_sha256"]
    assert b["reviewed_inputs"]["adapter"] == (
        summary["sources"]["adapter_source_sha256"]
    )
    assert a["source_sha256"] == c["reviewed_c_source_sha256"]
    assert a["header_sha256"] == c["reviewed_c_header_sha256"]
    assert b["layout"]["sizes"]["c3b03_t01_mock_input_t"] == 208
    assert b["layout"]["assertion_counts"] == {
        "SIZE": 9, "ALIGN": 6, "OFF": 31, "FIELD_SIZE": 31,
    }
    assert a["linked_image_bytes_observed"] is True
    assert type(a["object_bytes"]) is bytes
    assert type(a["linked_image_bytes"]) is bytes
    assert hashlib.sha256(a["object_bytes"]).hexdigest() == a["object_sha256"]
    assert hashlib.sha256(a["linked_image_bytes"]).hexdigest() == a["linked_image_sha256"]
    assert a["image_header_bytes"] == a["linked_image_bytes"][:4096]
    assert set(a["object_inspection"]) == {
        "object_format", "exports", "undefined",
    }
    assert a["object_inspection"]["object_format"]
    assert a["object_inspection"]["exports"]
    assert a["object_inspection"]["undefined"].strip() == ""
    assert type(a["manifest_entry_count"]) is int
    assert a["manifest_entry_count"] == len(s6.s0.checked_manifest())
    assert a["compile_environment"] == s6.s3.ENV
    assert s6._recomputed_s3_stages(
        a, head=summary["head"], tree=summary["tree"],
        manifest_sha=summary["manifest_sha256"],
    ) == a["stage_digests"]
    assert b["real_c11_abi_assertions_compiled_only"] is True
    assert c["inert_temporary_directory_discarded"] is True
    assert c["same_content_and_inode_observed_twice"] == (
        "UNCHANGED_STATIC_OBSERVATION_NOT_LOADER_CUSTODY"
    )
    for key, value in summary["observations"].items():
        if key != "s5_current_observation":
            assert re.fullmatch(r"[0-9a-f]{64}", value), key
    assert re.fullmatch(r"[0-9a-f]{64}",
                        summary["cross_stage_observation_digest"])


@pytest.mark.parametrize("mutation", (
    "missing-stage", "reverse-stage", "wrong-head", "wrong-tree",
    "wrong-manifest", "spliced-source", "s3-false-authority",
    "s3-loaded", "s3-linked-hash", "s3-corrupt-header",
    "s3-extra-export", "s4-authorized-call", "s4-layout-drift",
    "s4-ast-drift", "s5-inert-sha", "s5-inode-zero", "s5-hardlink",
    "s5-loader-proof-claim", "parent-tree-drift", "unexpected-field",
    "stage-null", "s3-status-authorized",
    # P2-01 regression: all hashes below remain VALID 64-character hex.
    # These used to be accepted as REVIEW_REQUIRED_NO_LOAD despite
    # contradicting the frozen S0->S1->S2->S3 stage computation.
    "valid-hex-object-sha", "valid-hex-linked-sha",
    "valid-hex-s0-digest", "valid-hex-s1-digest",
    "valid-hex-s2-digest", "valid-hex-s3-digest",
    "changed-object-file-preimage", "changed-object-exports-preimage",
    "changed-object-undefined-preimage",
    "missing-object-inspection", "missing-manifest-count",
    "changed-manifest-count", "changed-compile-environment",
    # S3/S6 byte-to-SHA binding: raw evidence must match both hashes.
    "missing-object-bytes", "missing-linked-bytes",
    "modified-object-bytes", "modified-linked-bytes",
    "linked-bytes-not-bytes", "object-bytes-too-large",
    "linked-header-contradicts-bytes", "valid-hex-object-rehash-only",
    "valid-hex-linked-rehash-only",
))
def test_missing_spliced_mutated_or_self_authorized_fails_closed(actual, mutation):
    real, summary = actual
    bundle = copy.deepcopy(real)
    a, b, c = (bundle[name] for name in s6.STAGES)
    if mutation == "missing-stage":
        del bundle[s6.STAGES[1]]
    elif mutation == "reverse-stage":
        bundle = dict(reversed(list(bundle.items())))
    elif mutation == "wrong-head":
        b["head"] = "0" * 40
    elif mutation == "wrong-tree":
        a["current_tree"] = "1" * 40
    elif mutation == "wrong-manifest":
        c["manifest_sha256"] = "f" * 64
    elif mutation == "spliced-source":
        a["source_sha256"] = "d" * 64
    elif mutation == "s3-false-authority":
        a["complete_final_binary_cfg_proven"] = True
    elif mutation == "s3-loaded":
        a["native_loader_invoked"] = True
    elif mutation == "s3-linked-hash":
        a["linked_image_sha256"] = "MALFORMED"
    elif mutation == "s3-corrupt-header":
        a["image_header_bytes"] = b"\x00\x01\x02\x03" + a[
            "image_header_bytes"][4:]
    elif mutation == "s3-extra-export":
        a["inspection"]["exports"] += "\n0000000000000001 T extra"
    elif mutation == "s4-authorized-call":
        b["actual_python_to_c_call_binding_proven"] = True
    elif mutation == "s4-layout-drift":
        b["layout"]["sizes"]["c3b03_t01_mock_input_t"] = 216
    elif mutation == "s4-ast-drift":
        b["adapter_source_graph"]["native_call_always_denies"] = False
    elif mutation == "s5-inert-sha":
        c["inert_file_sha256"] = "a" * 64
    elif mutation == "s5-inode-zero":
        c["inert_file_snapshot"]["leaf_ino"] = 0
    elif mutation == "s5-hardlink":
        c["inert_file_snapshot"]["leaf_nlink"] = 2
    elif mutation == "s5-loader-proof-claim":
        c["future_loader_same_inode_proven"] = True
    elif mutation == "parent-tree-drift":
        c["reviewed_s4_parent_tree"] = "e" * 40
    elif mutation == "unexpected-field":
        a["review_approved"] = True
    elif mutation == "stage-null":
        bundle[s6.STAGES[0]] = None
    elif mutation == "s3-status-authorized":
        a["admission"] = "AUTHORIZED"
    elif mutation == "valid-hex-object-sha":
        a["object_sha256"] = "0" * 64
    elif mutation == "valid-hex-linked-sha":
        a["linked_image_sha256"] = "0" * 64
    elif mutation == "valid-hex-s0-digest":
        a["stage_digests"]["S0_observation"] = "0" * 64
    elif mutation == "valid-hex-s1-digest":
        a["stage_digests"]["S1_partial"] = "0" * 64
    elif mutation == "valid-hex-s2-digest":
        a["stage_digests"]["S2_object"] = "0" * 64
    elif mutation == "valid-hex-s3-digest":
        a["stage_digests"]["S3_linked_partial"] = "0" * 64
    elif mutation == "changed-object-file-preimage":
        a["object_inspection"]["object_format"] += " changed"
    elif mutation == "changed-object-exports-preimage":
        a["object_inspection"]["exports"] += "\nextra exported symbol"
    elif mutation == "changed-object-undefined-preimage":
        a["object_inspection"]["undefined"] = " U unreviewed"
    elif mutation == "missing-object-inspection":
        del a["object_inspection"]
    elif mutation == "missing-manifest-count":
        del a["manifest_entry_count"]
    elif mutation == "changed-manifest-count":
        a["manifest_entry_count"] += 1
    elif mutation == "changed-compile-environment":
        a["compile_environment"]["LC_ALL"] = "C.UTF-8"
    elif mutation == "missing-object-bytes":
        del a["object_bytes"]
    elif mutation == "missing-linked-bytes":
        del a["linked_image_bytes"]
    elif mutation == "modified-object-bytes":
        a["object_bytes"] = b"X" + a["object_bytes"][1:]
    elif mutation == "modified-linked-bytes":
        a["linked_image_bytes"] = b"X" + a["linked_image_bytes"][1:]
    elif mutation == "linked-bytes-not-bytes":
        a["linked_image_bytes"] = "not raw bytes"
    elif mutation == "object-bytes-too-large":
        a["object_bytes"] = b"x" * (s6.s3._STATIC_ARTIFACT_LIMIT + 1)
    elif mutation == "linked-header-contradicts-bytes":
        a["image_header_bytes"] = (
            a["image_header_bytes"][:100] + b"Z" +
            a["image_header_bytes"][101:]
        )
    elif mutation == "valid-hex-object-rehash-only":
        a["object_sha256"] = hashlib.sha256(
            b"DIFFERENT UNOBSERVED ARTIFACT"
        ).hexdigest()
        a["stage_digests"] = s6._recomputed_s3_stages(
            a, head=summary["head"], tree=summary["tree"],
            manifest_sha=summary["manifest_sha256"],
        )
    elif mutation == "valid-hex-linked-rehash-only":
        a["linked_image_sha256"] = hashlib.sha256(
            b"DIFFERENT UNOBSERVED LINKED IMAGE"
        ).hexdigest()
        a["stage_digests"] = s6._recomputed_s3_stages(
            a, head=summary["head"], tree=summary["tree"],
            manifest_sha=summary["manifest_sha256"],
        )
    assert _verdict(bundle, summary) == "REJECT"


@pytest.mark.parametrize("candidate", (
    {}, None, [], "APPROVED", True, 1,
))
def test_non_observation_bundle_cannot_be_promoted(actual, candidate):
    _, summary = actual
    assert _verdict(candidate, summary) == "REJECT"


@pytest.mark.parametrize("input", (
    ("head", "A" * 40),
    ("head", "a" * 39),
    ("tree", "0" * 64),
    ("tree", None),
    ("manifest_sha", "f" * 40),
    ("manifest_sha", "Y" * 64),
))
def test_wrong_git_oid_vs_sha_digest_is_rejected(actual, input):
    bundle, summary = actual
    values = {
        "head": summary["head"],
        "tree": summary["tree"],
        "manifest_sha": summary["manifest_sha256"],
    }
    key, bad = input
    values[key] = bad
    assert s6.decide_offline_only(bundle, **values) == "REJECT"


def test_even_well_formed_copied_dictionary_is_not_permission(actual):
    """Data dictionaries are not independently authenticated artifacts."""
    real, summary = actual
    untrusted_copy = copy.deepcopy(real)
    assert _verdict(untrusted_copy, summary) == "REVIEW_REQUIRED_NO_LOAD"
    assert "ALLOW" not in _verdict(untrusted_copy, summary)
    assert "AUTHORIZED" not in _verdict(untrusted_copy, summary)
    assert not any(x in (s6.NO_LOAD, s6.REJECT)
                   for x in ("ALLOW_NATIVE", "FIRST_LOAD_AUTHORIZED"))


def test_p2_01_self_consistent_fake_sha_still_never_grants_load(actual):
    """Recomputed digests catch contradictions, not forged real-world bytes.

    An attacker can synthesize internally consistent digest records. Such a
    record must still NEVER produce a Native load permission or a PASS.
    """
    original, summary = actual
    fake = copy.deepcopy(original)
    entry = fake[s6.STAGES[0]]
    assert entry["object_sha256"] != "0" * 64
    entry["object_sha256"] = "0" * 64
    assert _verdict(fake, summary) == "REJECT"
    entry["stage_digests"] = s6._recomputed_s3_stages(
        entry, head=summary["head"], tree=summary["tree"],
        manifest_sha=summary["manifest_sha256"],
    )
    # Fully consistent hash chain but submitted bytes still disagree -> REJECT.
    assert _verdict(fake, summary) == "REJECT"
    # A fully forged dictionary CAN submit internally self-consistent raw
    # bytes, object SHA and all stage digests. That is not authentication.
    counterfeit = b"X" + entry["object_bytes"][1:]
    entry["object_bytes"] = counterfeit
    entry["object_sha256"] = hashlib.sha256(counterfeit).hexdigest()
    entry["stage_digests"] = s6._recomputed_s3_stages(
        entry, head=summary["head"], tree=summary["tree"],
        manifest_sha=summary["manifest_sha256"],
    )
    assert re.fullmatch(r"[0-9a-f]{64}", entry["stage_digests"]["S2_object"])
    assert _verdict(fake, summary) == "REVIEW_REQUIRED_NO_LOAD"
    assert _verdict(fake, summary) != "AUTHORIZED"


def test_review_scope_manifest_branch_guard_and_no_loader():
    source = (ROOT / "tools/research/c3_candidate_b_t01_s6_offline_deny_proof.py").read_text()
    doc = DOC.read_text(encoding="utf-8")
    workflow = WF.read_text(encoding="utf-8")
    for token in (
        "S6", "S0", "S1", "S2", "S3", "S4", "S5",
        "P3-01", "P3-02", "P3-03", "191 expected RED",
        "NO LOAD", "NO C EXEC", "REVIEW_REQUIRED_NO_LOAD",
        "group_kill_authorized=false", "reuse_proven=false",
        "g2_qualified=false", "NOT_RUN/BLOCK", "R2b-R2b-R3",
        "ExecSupervisor", "REST/MCP Multi-Workspace Exec",
        "independent", "TOCTOU", "same-UID",
    ):
        assert token.lower() in doc.lower(), token
    for token in (
        "contents: read", "persist-credentials: false",
        "macos-15", "ubuntu-latest", '"3.13"', '"3.14"',
        "MANIFEST.sha256", "C3B03_S6_NO_LOAD",
        "C3B03_S6_GROUP_SIGNAL_AUTHORIZED",
        "tests/test_c3_candidate_b_t01_s6_offline_deny.py",
        "test ! -e tools/research/c3_candidate_b_kill.c",
    ):
        assert token in workflow, token
    for token in (
        "workflow_dispatch", "continue-on-error:", "|| true",
        "ctypes.CDLL(", "dlopen(", "os.kill(", "killpg(",
        "test_c3_candidate_b_t01_r2b_contract_red.py",
    ):
        assert token not in workflow, token
    for token in (
        "ctypes.CDLL(", "ctypes.PyDLL(", "dlopen(", "os.kill(", "killpg(",
        "subprocess.Popen(", "posix_spawn(",
    ):
        assert token not in source, token
    for forbidden_path in (
        "tools/research/c3_candidate_b_kill.c",
        "tools/research/c3_candidate_b_kill_t01_no_signal_probe.py",
        "tools/research/run_c3_candidate_b_kill.py",
    ):
        assert not (ROOT / forbidden_path).exists()
    manifest = s6.s0.checked_manifest()
    for path in (DOC, WF, Path(__file__), Path(s6.__file__)):
        name = "./" + path.relative_to(ROOT).as_posix()
        assert manifest[name] == hashlib.sha256(path.read_bytes()).hexdigest()
