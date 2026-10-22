"""S5 inert file descriptor/path observations only: NO C, NO LOAD."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools/research"))
import c3_candidate_b_t01_s5_inert_path_custody_proof as s5  # noqa: E402

DOC = ROOT / "docs/research/phase2-lite-c3/candidate-b-b03-t01-r2b-r2b-r2-s5-inert-path-custody.md"
WORKFLOW = ROOT / ".github/workflows/c3-candidate-b-t01-r2b-r2b-r2-s5-inert-path-custody.yml"


@pytest.fixture(scope="module")
def evidence():
    data = s5.collect_static_s5_evidence()
    print("C3B03_T01_S5_ACTUAL_INERT_CUSTODY=" + json.dumps(
        data, sort_keys=True, separators=(",", ":")
    ))
    return data


def _new_private_root(tmp_path: Path) -> Path:
    root = (tmp_path / "private-0700").resolve()
    root.mkdir(mode=0o700)
    assert root.stat().st_mode & 0o777 == 0o700
    return root


def test_real_nofollow_private_inert_data_and_parent_head(evidence):
    x = evidence
    assert x["reviewed_s4_parent_head"] == (
        "4f388a0344fbd2326574ba7d82f9c1eb5d6cfd1c"
    )
    assert x["reviewed_s4_parent_tree"] == (
        "3af5720dd01553cc189174fbd0365cdff37e1fcc"
    )
    assert x["current_head"] != x["reviewed_s4_parent_head"]
    assert re.fullmatch(r"[a-f0-9]{40}", x["current_head"])
    assert re.fullmatch(r"[a-f0-9]{40}", x["current_tree"])
    assert x["inert_file_sha256"] == s5.FIXTURE_SHA256
    assert x["inert_temporary_directory_discarded"] is True
    assert x["same_content_and_inode_observed_twice"] == (
        "UNCHANGED_STATIC_OBSERVATION_NOT_LOADER_CUSTODY"
    )
    a = x["inert_file_snapshot"]
    assert a["leaf_sha256"] == hashlib.sha256(s5.FIXTURE).hexdigest()
    assert a["root_mode"] == 0o700
    assert a["leaf_mode"] == 0o400
    assert a["leaf_nlink"] == 1
    assert a["leaf_size"] == len(s5.FIXTURE)
    assert a["leaf_ino"] > 0 and a["root_ino"] > 0
    assert a["observed_fd_path_identical_during_this_read"] is True


def test_never_authorizes_loader_native_execution_or_group_signal(evidence):
    x = evidence
    assert x["admission"] == "REVIEW_REQUIRED_NO_LOAD"
    assert x["native_dispatches"] == 0
    for key in (
        "candidate_c_compiled", "candidate_c_executed",
        "candidate_shared_library_linked", "candidate_shared_library_loaded",
        "native_loader_invoked", "future_loader_same_inode_proven",
        "atomic_loader_check_use_proven", "same_uid_writer_absence_proven",
        "loader_dependency_resolution_proven",
        "complete_toolchain_sdk_closure_proven", "complete_final_cfg_proven",
        "complete_python_ffi_import_graph_proven",
        "first_c_load_authorized", "group_kill_authorized",
        "reuse_proven", "g2_qualified",
    ):
        assert x[key] is False, key
    assert s5.FIXTURE[:4] != b"\x7fELF"
    assert s5.FIXTURE[:4] != b"\xcf\xfa\xed\xfe"


def test_identical_bytes_different_inode_is_detected(tmp_path):
    root = _new_private_root(tmp_path)
    s5._create_fixture(root)
    before = s5._observe_once(root)
    replacement = root / "same-bytes-different-inode.data"
    replacement.write_bytes(s5.FIXTURE)
    replacement.chmod(0o400)
    os.replace(replacement, root / s5.LEAF)
    after = s5._observe_once(root)
    assert before["leaf_sha256"] == after["leaf_sha256"]
    assert before["leaf_ino"] != after["leaf_ino"]
    with pytest.raises(ValueError, match="INERT_IDENTITY_CHANGED"):
        s5._compare_observations(before, after)


def test_leaf_hardlink_is_refused(tmp_path):
    root = _new_private_root(tmp_path)
    s5._create_fixture(root)
    alias = root / "hardlink"
    os.link(root / s5.LEAF, alias)
    assert os.stat(root / s5.LEAF).st_nlink == 2
    with pytest.raises(ValueError, match="INERT_FILE_OWNER_MODE_NLINK_OR_SIZE"):
        s5._observe_once(root)


def test_leaf_symlink_is_refused(tmp_path):
    root = _new_private_root(tmp_path)
    s5._create_fixture(root)
    original = root / s5.LEAF
    other = root / "other"
    original.rename(other)
    original.symlink_to(other)
    with pytest.raises(ValueError, match="INERT_NOT_REGULAR"):
        s5._observe_once(root)


@pytest.mark.parametrize("mutation", ("wrong-mode", "wrong-size", "wrong-sha"))
def test_inert_leaf_mode_size_and_sha_fail_closed(tmp_path, mutation):
    root = _new_private_root(tmp_path)
    s5._create_fixture(root)
    leaf = root / s5.LEAF
    if mutation == "wrong-mode":
        leaf.chmod(0o644)
    elif mutation == "wrong-size":
        leaf.chmod(0o600)
        leaf.write_bytes(b"x")
        leaf.chmod(0o400)
    else:
        leaf.chmod(0o600)
        leaf.write_bytes(b"Z" * len(s5.FIXTURE))
        leaf.chmod(0o400)
    with pytest.raises(ValueError, match="INERT_FILE_OWNER_MODE_NLINK_OR_SIZE|INERT_CONTENT_SHA_CHANGED"):
        s5._observe_once(root)


def test_missing_leaf_is_denied(tmp_path):
    root = _new_private_root(tmp_path)
    with pytest.raises(ValueError, match="INERT_FILE_MISSING"):
        s5._observe_once(root)


def test_root_symlink_alias_and_untrusted_parent_denied(tmp_path):
    root = _new_private_root(tmp_path)
    alias = tmp_path / "directory-alias"
    alias.symlink_to(root, target_is_directory=True)
    with pytest.raises(ValueError, match="UNCANONICAL_OR_LINKED_ROOT"):
        s5._private_directory_fd(alias)
    unsafe_parent = tmp_path / "unsafe-world-writable"
    unsafe_parent.mkdir()
    unsafe_parent.chmod(0o777)
    child = unsafe_parent / "private"
    child.mkdir(mode=0o700)
    try:
        with pytest.raises(ValueError, match="UNTRUSTED_WRITABLE_ANCESTOR"):
            s5._private_directory_fd(child)
    finally:
        unsafe_parent.chmod(0o700)


def test_root_mode_not_0700_denied(tmp_path):
    root = _new_private_root(tmp_path)
    root.chmod(0o755)
    with pytest.raises(ValueError, match="ROOT_NOT_PRIVATE_OWNED_0700"):
        s5._private_directory_fd(root)


def test_missing_or_spliced_custody_observation_denied(tmp_path):
    root = _new_private_root(tmp_path)
    s5._create_fixture(root)
    before = s5._observe_once(root)
    assert s5._compare_observations(before, dict(before)) == (
        "UNCHANGED_STATIC_OBSERVATION_NOT_LOADER_CUSTODY"
    )
    missing = dict(before)
    missing.pop("leaf_ino")
    with pytest.raises(ValueError, match="INCOMPLETE_CUSTODY_EVIDENCE"):
        s5._compare_observations(before, missing)
    changed = dict(before)
    changed["leaf_ino"] += 1
    with pytest.raises(ValueError, match="INERT_IDENTITY_CHANGED"):
        s5._compare_observations(before, changed)
    forged = dict(before)
    forged["observed_fd_path_identical_during_this_read"] = False
    with pytest.raises(ValueError, match="INERT_CURRENT_FD_PATH_UNBOUND"):
        s5._compare_observations(forged, dict(forged))


def test_manifest_doc_and_ci_enforce_no_load_and_no_native_run():
    doc = DOC.read_text(encoding="utf-8")
    for token in (
        "NO LOAD", "NO C EXEC", "PARTIAL", "P3-01", "P3-02",
        "P3-03", "S5", "S6", "TOCTOU", "same-UID", "191 expected RED",
        "REVIEW_REQUIRED_NO_LOAD", "group_kill_authorized=false",
        "reuse_proven=false", "g2_qualified=false", "NOT_RUN/BLOCK",
        "ExecSupervisor", "REST/MCP Multi-Workspace Exec",
    ):
        assert token.lower() in doc.lower(), token
    yml = WORKFLOW.read_text(encoding="utf-8")
    for token in (
        "contents: read", "persist-credentials: false",
        "macos-15", "ubuntu-latest", '"3.13"', '"3.14"',
        "MANIFEST.sha256", "C3B03_S5_NO_LOAD",
        "C3B03_S5_GROUP_SIGNAL_AUTHORIZED",
        "tests/test_c3_candidate_b_t01_s5_inert_path_custody.py",
        "test ! -e tools/research/c3_candidate_b_kill.c",
    ):
        assert token in yml, token
    for token in (
        "workflow_dispatch", "continue-on-error:", "|| true",
        "cc -shared", "cc -dynamiclib", "ctypes.CDLL(",
        "dlopen(", "os.kill(", "killpg(",
        "test_c3_candidate_b_t01_r2b_contract_red.py",
    ):
        assert token not in yml, token
    module = (ROOT / "tools/research/c3_candidate_b_t01_s5_inert_path_custody_proof.py").read_text(encoding="utf-8")
    for token in ("ctypes", "cffi", "dlopen(", "os.kill(", "killpg(",
                  "subprocess.Popen(", "posix_spawn("):
        assert token not in module, token
    manifest = s5.s0.checked_manifest()
    for path in (DOC, WORKFLOW, Path(__file__), Path(s5.__file__)):
        key = "./" + path.relative_to(ROOT).as_posix()
        assert key in manifest
        assert manifest[key] == hashlib.sha256(path.read_bytes()).hexdigest()
