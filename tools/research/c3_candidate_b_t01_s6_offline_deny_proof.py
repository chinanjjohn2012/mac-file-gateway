"""B03-T01 S6 OFFLINE DENY-ONLY: check S3/S4/S5 partial static observations.

A valid partial evidence bundle can mean only REVIEW_REQUIRED_NO_LOAD.
A malformed, spliced, self-authorizing or missing bundle is REJECT.
No ALLOW branch or authorization token exists. This is NOT full D1 S6.

This authoring/test-only tool reuses independently reviewed static collectors:
S3 compiles + LINKS inert Candidate C, but NEVER loads or calls it.
S4 compiles only C11 ABI _Static_assert and inspects ctypes DATA layout.
S5 reads an inert DATA file and observes FD/inode only.
Each collector owns a DIFFERENT ephemeral session; ordered digests are NOT
atomic source/toolchain/loader custody or independent approval.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any

import c3_candidate_b_t01_s0_abi_proof as s0
import c3_candidate_b_t01_s3_linked_proof as s3
import c3_candidate_b_t01_s4_abi_source_proof as s4
import c3_candidate_b_t01_s5_inert_path_custody_proof as s5

PARENT_S5_HEAD = "499574be48ad14d2473f73342cc2c7708fb81b8f"
PARENT_S5_TREE = "7d7393ee645d9c9bcfbf54f755a03ccc4aee02af"
STAGES = ("S3_LINKED_STATIC_PARTIAL", "S4_SOURCE_ABI_STATIC_PARTIAL",
          "S5_INERT_DATA_PATH_STATIC_PARTIAL")
NO_LOAD = "REVIEW_REQUIRED_NO_LOAD"
REJECT = "REJECT"
_GIT = re.compile(r"[a-f0-9]{40}\Z")
_SHA = re.compile(r"[a-f0-9]{64}\Z")
S3_FIELDS = frozenset((
    "current_head current_tree reviewed_s2_parent_head reviewed_s2_parent_tree "
    "platform source_sha256 header_sha256 compiler_entry_sha256_precompile "
    "compiler_entry_sha256_postlink manifest_sha256 compile_argv link_argv "
    "object_sha256 linked_image_sha256 linked_header image_owner_uid "
    "image_device image_inode stage_digests inspection image_header_bytes "
    "linked_image_bytes_observed toolchain_sdk_closure_proven "
    "complete_final_binary_cfg_proven final_linked_image_lock_proven "
    "adapter_ffi_proven loader_inode_custody_proven first_c_load_authorized "
    "candidate_c_executed native_loader_invoked native_dispatches "
    "group_kill_authorized reuse_proven g2_qualified admission"
).split())
S4_FIELDS = frozenset((
    "head tree reviewed_s3_parent_head reviewed_s3_parent_tree manifest_sha256 "
    "reviewed_inputs real_compiler_entry_sha256_precompile "
    "real_compiler_entry_sha256_postcompile abi_assertion_object_sha256 "
    "header_struct_fields layout layout_sha256 adapter_source_graph "
    "adapter_source_graph_sha256 real_c11_abi_assertions_compiled_only "
    "python_ctypes_data_layout_only candidate_c_compiled candidate_c_executed "
    "native_candidate_library_linked native_candidate_library_loaded "
    "native_adapter_imported native_dispatches complete_toolchain_sdk_closure_proven "
    "complete_python_ffi_import_graph_proven actual_python_to_c_call_binding_proven "
    "loader_inode_custody_proven first_c_load_authorized group_kill_authorized "
    "reuse_proven g2_qualified admission"
).split())
S5_FIELDS = frozenset((
    "current_head current_tree reviewed_s4_parent_head reviewed_s4_parent_tree "
    "manifest_sha256 reviewed_c_source_sha256 reviewed_c_header_sha256 "
    "inert_file_snapshot inert_file_sha256 same_content_and_inode_observed_twice "
    "inert_temporary_directory_discarded candidate_c_compiled candidate_c_executed "
    "candidate_shared_library_linked candidate_shared_library_loaded "
    "native_loader_invoked native_dispatches future_loader_same_inode_proven "
    "atomic_loader_check_use_proven same_uid_writer_absence_proven "
    "loader_dependency_resolution_proven complete_toolchain_sdk_closure_proven "
    "complete_final_cfg_proven complete_python_ffi_import_graph_proven "
    "first_c_load_authorized group_kill_authorized reuse_proven g2_qualified "
    "admission"
).split())
S3_FALSE = (
    "toolchain_sdk_closure_proven", "complete_final_binary_cfg_proven",
    "final_linked_image_lock_proven", "adapter_ffi_proven",
    "loader_inode_custody_proven", "first_c_load_authorized",
    "candidate_c_executed", "native_loader_invoked",
    "group_kill_authorized", "reuse_proven", "g2_qualified",
)
S4_FALSE = (
    "candidate_c_compiled", "candidate_c_executed",
    "native_candidate_library_linked", "native_candidate_library_loaded",
    "native_adapter_imported", "complete_toolchain_sdk_closure_proven",
    "complete_python_ffi_import_graph_proven",
    "actual_python_to_c_call_binding_proven", "loader_inode_custody_proven",
    "first_c_load_authorized", "group_kill_authorized", "reuse_proven",
    "g2_qualified",
)
S5_FALSE = (
    "candidate_c_compiled", "candidate_c_executed",
    "candidate_shared_library_linked", "candidate_shared_library_loaded",
    "native_loader_invoked", "future_loader_same_inode_proven",
    "atomic_loader_check_use_proven", "same_uid_writer_absence_proven",
    "loader_dependency_resolution_proven", "complete_toolchain_sdk_closure_proven",
    "complete_final_cfg_proven", "complete_python_ffi_import_graph_proven",
    "first_c_load_authorized", "group_kill_authorized", "reuse_proven",
    "g2_qualified",
)
# An honest DENY-ONLY result lists every missing D1 full admission precondition.
MISSING_FULL_GATES = (
    "S1_NESTED_COMPILER_ASSEMBLER_LINKER_SDK_RESOURCE_CLOSURE",
    "S2_S3_ATOMIC_SOURCE_OBJECT_FINAL_IMAGE_PROVENANCE",
    "S3_ALL_MACHINE_CODE_CFG_IMPORT_RELOC_INITIALIZER_PROOF",
    "S4_ACTUAL_FFI_ADAPTER_TRANSITIVE_IMPORT_AND_CALL_BINDING",
    "S5_FINAL_IMAGE_EXACT_LOADER_INODE_CHECK_USE_CUSTODY",
    "S6_INDEPENDENT_EXPLICIT_FIRST_NO_SIGNAL_NATIVE_LOAD_PERMISSION",
)


def _digest(data: Any) -> str:
    return hashlib.sha256(json.dumps(
        data, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("ascii")).hexdigest()


def _hex(value: Any, pattern: re.Pattern[str]) -> bool:
    return type(value) is str and pattern.fullmatch(value) is not None


def _stage_flags(item: dict, fields: tuple[str, ...]) -> bool:
    return (item.get("admission") == NO_LOAD and
            type(item.get("native_dispatches")) is int and
            item["native_dispatches"] == 0 and
            all(item.get(field) is False for field in fields))


def _check_bundle(bundle: object, *, head: str, tree: str,
                  manifest_sha: str) -> bool:
    """Validate observation consistency, NEVER decide to load. No I/O.

    This is a semantic *partial-evidence* check, not authentication of the
    submitted Python dictionaries. A counterfeited structurally valid bundle
    remains REVIEW_REQUIRED_NO_LOAD and cannot become a permission.
    """
    if not (_hex(head, _GIT) and _hex(tree, _GIT) and
            _hex(manifest_sha, _SHA)):
        return False
    if type(bundle) is not dict or tuple(bundle) != STAGES:
        return False
    a, b, c = (bundle[key] for key in STAGES)
    if not all(type(x) is dict for x in (a, b, c)):
        return False
    if set(a) != S3_FIELDS or set(b) != S4_FIELDS or set(c) != S5_FIELDS:
        return False
    if not (_stage_flags(a, S3_FALSE) and _stage_flags(b, S4_FALSE)
            and _stage_flags(c, S5_FALSE)):
        return False
    if any(x is not True for x in (
        a["linked_image_bytes_observed"], b["real_c11_abi_assertions_compiled_only"],
        b["python_ctypes_data_layout_only"],
        c["inert_temporary_directory_discarded"],
    )):
        return False
    if not (a["current_head"] == b["head"] == c["current_head"] == head
            and a["current_tree"] == b["tree"] == c["current_tree"] == tree
            and a["manifest_sha256"] == b["manifest_sha256"]
            == c["manifest_sha256"] == manifest_sha):
        return False
    # These are known independently reviewed ancestry markers; do not
    # substitute a new child's self-reported Review for any ancestor.
    if not (a["reviewed_s2_parent_head"] ==
            "21d0f6b00e21f154d41703d1f1910080b066c884"
            and a["reviewed_s2_parent_tree"] ==
            "8610fa21b8bd7470e8d3d155be5a2453c8d1d90b"
            and b["reviewed_s3_parent_head"] ==
            "9c0bb5b0e83a3d5e57bacd2d55eaff174cb9c8fc"
            and b["reviewed_s3_parent_tree"] ==
            "ad13b6a5a362874f50dc7ad70778b55c48f7f5c8"
            and c["reviewed_s4_parent_head"] ==
            "4f388a0344fbd2326574ba7d82f9c1eb5d6cfd1c"
            and c["reviewed_s4_parent_tree"] ==
            "3af5720dd01553cc189174fbd0365cdff37e1fcc"):
        return False
    if not (a["source_sha256"] == b["reviewed_inputs"].get(
            "candidate_source") == c["reviewed_c_source_sha256"]
            == s0.REVIEWED_C_SHA256
            and a["header_sha256"] == b["reviewed_inputs"].get("header")
            == c["reviewed_c_header_sha256"] == s0.REVIEWED_HEADER_SHA256):
        return False
    if not all(_hex(x, _SHA) for x in (
        a["compiler_entry_sha256_precompile"],
        a["compiler_entry_sha256_postlink"], a["object_sha256"],
        a["linked_image_sha256"], b["abi_assertion_object_sha256"],
        b["layout_sha256"], b["adapter_source_graph_sha256"],
        b["real_compiler_entry_sha256_precompile"],
        b["real_compiler_entry_sha256_postcompile"],
        c["inert_file_sha256"],
    )):
        return False
    if not (a["compiler_entry_sha256_precompile"] ==
            a["compiler_entry_sha256_postlink"]
            and b["real_compiler_entry_sha256_precompile"] ==
            b["real_compiler_entry_sha256_postcompile"]):
        return False
    stages = a["stage_digests"]
    if (type(stages) is not dict or set(stages) != {
        "S0_observation", "S1_partial", "S2_object", "S3_linked_partial",
    } or not all(_hex(v, _SHA) for v in stages.values())):
        return False
    if not (type(a["compile_argv"]) is tuple and
            type(a["link_argv"]) is tuple and
            len(a["compile_argv"]) > 10 and len(a["link_argv"]) > 5
            and a["platform"] in ("Darwin", "Linux")):
        return False
    if not (type(a["image_header_bytes"]) is bytes and
            type(a["inspection"]) is dict and
            _hex(a["linked_image_sha256"], _SHA)):
        return False
    image_name = s3.NAME + (".dylib" if a["platform"] == "Darwin" else ".so")
    if (s3._linked_header_gate(
        a["image_header_bytes"], a["platform"], image_name,
    ) != a["linked_header"]):
        return False
    if s3._metadata_gate(a["platform"], a["inspection"]) != (
        "LINKED_METADATA_PARTIAL_NO_LOAD"
    ):
        return False
    if not (type(b["reviewed_inputs"]) is dict and
            set(b["reviewed_inputs"]) == {
                "adapter", "header", "abi", "candidate_source",
            } and all(_hex(x, _SHA) for x in b["reviewed_inputs"].values())):
        return False
    if not (type(b["layout"]) is dict and
            type(b["adapter_source_graph"]) is dict and
            _digest(b["layout"]) == b["layout_sha256"]
            and _digest(b["adapter_source_graph"]) ==
            b["adapter_source_graph_sha256"]):
        return False
    if not (b["layout"].get("assertion_counts") == {
        "SIZE": 9, "ALIGN": 6, "OFF": 31, "FIELD_SIZE": 31,
    } and b["layout"].get("field_count") == 31
            and b["layout"].get("sizes", {}).get(
                "c3b03_t01_mock_input_t") == 208
            and b["adapter_source_graph"].get(
                "native_call_always_denies") is True
            and b["adapter_source_graph"].get(
                "future_ffi_adapter_import_graph_proven") is False):
        return False
    snap = c["inert_file_snapshot"]
    if type(snap) is not dict or set(snap) != {
        "leaf_sha256", "leaf_dev", "leaf_ino", "leaf_uid", "leaf_nlink",
        "leaf_mode", "leaf_size", "leaf_mtime_ns", "leaf_ctime_ns",
        "root_dev", "root_ino", "root_uid", "root_mode",
        "observed_fd_path_identical_during_this_read",
    }:
        return False
    if not (
        all(type(snap[key]) is int and snap[key] > 0 for key in (
            "leaf_dev", "leaf_ino", "root_dev", "root_ino", "leaf_size",
            "leaf_mtime_ns", "leaf_ctime_ns",
        ))
        and type(snap["leaf_uid"]) is int
        and snap["leaf_uid"] >= 0 and snap["leaf_uid"] == snap["root_uid"]
        and snap["leaf_size"] == len(s5.FIXTURE)
    ):
        return False
    if (c["inert_file_sha256"] != s5.FIXTURE_SHA256 or
            c["same_content_and_inode_observed_twice"] != (
                "UNCHANGED_STATIC_OBSERVATION_NOT_LOADER_CUSTODY")
            or c["inert_file_snapshot"].get("leaf_sha256") != s5.FIXTURE_SHA256
            or c["inert_file_snapshot"].get("leaf_mode") != 0o400
            or c["inert_file_snapshot"].get("root_mode") != 0o700
            or c["inert_file_snapshot"].get("leaf_nlink") != 1
            or c["inert_file_snapshot"].get(
                "observed_fd_path_identical_during_this_read") is not True):
        return False
    return True


def decide_offline_only(bundle: object, *, head: str, tree: str,
                        manifest_sha: str) -> str:
    """Two non-authorizing return values: REJECT or REVIEW_REQUIRED_NO_LOAD."""
    try:
        if _check_bundle(bundle, head=head, tree=tree,
                         manifest_sha=manifest_sha):
            return NO_LOAD
    except (AssertionError, AttributeError, KeyError, TypeError, ValueError,
            IndexError):
        pass
    return REJECT


def collect_real_partial_evidence() -> tuple[dict[str, dict], dict[str, object]]:
    """Collect fresh real S3/S4/S5 observations, never load any C/library."""
    s0.checked_manifest()
    head, tree = s0.current_revision()
    manifest_sha = s0._sha_regular(s0.MANIFEST)[0]
    # This sequence has three independent, transient collectors, NOT a
    # single atomic build-to-loader lifetime. No S6 actual approval.
    s3_data = s3._compile_link_observe()
    s4_data = s4.collect_static_s4_evidence()
    s5_data = s5.collect_static_s5_evidence()
    bundle = dict(zip(STAGES, (s3_data, s4_data, s5_data)))
    verdict = decide_offline_only(bundle, head=head, tree=tree,
                                  manifest_sha=manifest_sha)
    if verdict != NO_LOAD:
        raise ValueError("FRESH_STATIC_EVIDENCE_INCONSISTENT")
    summary = {
        "head": head, "tree": tree,
        "reviewed_s5_parent_head": PARENT_S5_HEAD,
        "reviewed_s5_parent_tree": PARENT_S5_TREE,
        "manifest_sha256": manifest_sha,
        "sources": {
            "candidate_c_sha256": s3_data["source_sha256"],
            "candidate_header_sha256": s3_data["header_sha256"],
            "adapter_source_sha256": s4_data["reviewed_inputs"]["adapter"],
        },
        "observations": {
            "s3_object_sha256": s3_data["object_sha256"],
            "s3_linked_sha256": s3_data["linked_image_sha256"],
            "s3_partial_chain_sha256": s3_data[
                "stage_digests"]["S3_linked_partial"],
            "s4_abi_compile_only_object_sha256": s4_data[
                "abi_assertion_object_sha256"],
            "s4_layout_sha256": s4_data["layout_sha256"],
            "s4_source_ast_sha256": s4_data["adapter_source_graph_sha256"],
            "s5_inert_file_sha256": s5_data["inert_file_sha256"],
            "s5_current_observation": s5_data[
                "same_content_and_inode_observed_twice"],
        },
        "cross_stage_observation_digest": _digest({
            "head": head, "tree": tree, "manifest_sha256": manifest_sha,
            "s3_partial": s3_data["stage_digests"],
            "s4_layout": s4_data["layout_sha256"],
            "s4_adapter_ast": s4_data["adapter_source_graph_sha256"],
            "s5_inert_sha": s5_data["inert_file_sha256"],
            "s5_leaf_identity": s5_data["inert_file_snapshot"],
        }),
        "missing_full_gates": MISSING_FULL_GATES,
        "collector_sessions_are_atomic": False,
        "author_or_synthetic_self_approval_accepted": False,
        "full_s6_independent_decision_made": False,
        "actual_native_loader_custody_proven": False,
        "first_c_load_authorized": False,
        "native_loader_invoked": False,
        "candidate_c_executed": False,
        "native_dispatches": 0,
        "group_kill_authorized": False,
        "reuse_proven": False, "g2_qualified": False,
        "admission": verdict,
    }
    return bundle, summary
