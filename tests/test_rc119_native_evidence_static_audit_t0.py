"""Read-only static/SAFE T0 checks; never import native runner or spawn a child."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import zipfile

import pytest

SOURCE = Path(__file__).resolve().parents[1] / "tools" / "rc119_native_evidence_static_audit.py"
SPEC = importlib.util.spec_from_file_location("rc119_native_evidence_static_audit", SOURCE)
assert SPEC and SPEC.loader
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)


def _native_receipt() -> dict:
    return {
        "source_head": AUDIT.PR114_HEAD,
        "source_tree": AUDIT.PR114_TREE,
        "contract_blob": AUDIT.PRODUCT_CONTRACT,
        "review_target": "PR114 LBE-SIX-COMMAND-MVP PRODUCT_T1",
        "status": "PASS",
        "expected_positive_observations": 18,
        "actual_positive_observations": 18,
        "observations": [
            {"mode": mode, "command_id": command, "kind": "NATIVE_T1", "executed": True,
             "status": "exited", "exit_code": 0, "output_complete": True}
            for mode in sorted(AUDIT.ROUTES)
            for command in sorted(AUDIT.COMMAND_IDS)
        ],
        "tools": {key: "a" * 64 for key in (
            "python_sha256", "pipenv_sha256", "go_sha256", "source_pipenv_sha256", "source_python_sha256")},
    }


def _mixed_receipt() -> dict:
    return {
        "head": AUDIT.PR114_HEAD,
        "tree": AUDIT.PR114_TREE,
        "contract": AUDIT.PRODUCT_CONTRACT,
        "status": "PASS",
        "native_exit_code": 0,
        "native_original_children": 1,
        "original_child_overlapped_real_git_file": True,
        "real_git_file_independent_under_unknown": True,
        "full_descendant_tree_clean": "not_proven",
        "phases": [{"phase": x} for x in ("before", "during", "after", "under-UNKNOWN")],
    }


def test_historical_eighteen_rows_not_promoted_to_current_tree():
    assert len(AUDIT.validate_old_native(_native_receipt())) == 18
    assert AUDIT.PR114_TREE != AUDIT.PR119_TREE
    assert AUDIT.PR114_HEAD != AUDIT.PR119_HEAD


@pytest.mark.parametrize("field,bad", [
    ("source_head", "33c30b6c2710cac0f8533370c1ca42f31ef6747a"),
    ("source_tree", "27e26c423e700cdbad0aeca27efcdf82594507c1"),
    ("contract_blob", "0" * 40),
    ("status", "UNKNOWN"),
    ("expected_positive_observations", 17),
])
def test_wrong_historical_identity_and_outcome_denied(field, bad):
    x = _native_receipt()
    x[field] = bad
    with pytest.raises(ValueError):
        AUDIT.validate_old_native(x)


@pytest.mark.parametrize("mutation", ["duplicate", "nonzero_exit", "unobserved", "incomplete_output", "wrong_kind", "missing_row"])
def test_missing_or_invalid_route_observation_denied(mutation):
    x = _native_receipt()
    if mutation == "duplicate":
        x["observations"][1]["command_id"] = x["observations"][0]["command_id"]
    elif mutation == "nonzero_exit":
        x["observations"][0]["exit_code"] = 1
    elif mutation == "unobserved":
        x["observations"][0]["executed"] = False
    elif mutation == "incomplete_output":
        x["observations"][0]["output_complete"] = False
    elif mutation == "wrong_kind":
        x["observations"][0]["kind"] = "MOCK"
    else:
        x["observations"].pop()
    with pytest.raises(ValueError):
        AUDIT.validate_old_native(x)


def test_historical_tool_digest_not_floating_string():
    x = _native_receipt()
    x["tools"]["go_sha256"] = "unattested"
    with pytest.raises(ValueError, match="INVALID_HISTORICAL_TOOL_SHA"):
        AUDIT.validate_old_native(x)


def test_historical_mixed_success_without_full_cleanup_claim():
    assert AUDIT.validate_old_mixed(_mixed_receipt()) is None


@pytest.mark.parametrize("field,bad", [
    ("full_descendant_tree_clean", "yes"),
    ("native_exit_code", 5),
    ("original_child_overlapped_real_git_file", False),
    ("head", "33c30b6c2710cac0f8533370c1ca42f31ef6747a"),
])
def test_mixed_claims_must_not_be_upgraded(field,bad):
    x = _mixed_receipt()
    x[field] = bad
    with pytest.raises(ValueError):
        AUDIT.validate_old_mixed(x)


def test_zip_read_is_digest_checked_and_never_extracts(tmp_path,monkeypatch):
    member="evidence.json"
    name="fixture.zip"
    path=tmp_path / name
    with zipfile.ZipFile(path,"w",compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr(member,json.dumps({"hello": "read-only"}))
    before=sorted(p.name for p in tmp_path.iterdir())
    digest=hashlib.sha256(path.read_bytes()).hexdigest()
    monkeypatch.setattr(AUDIT,"ROOT",tmp_path)
    data,sz=AUDIT.load_original(name,member,digest)
    assert data=={"hello":"read-only"}
    assert sz==len(path.read_bytes())
    assert sorted(p.name for p in tmp_path.iterdir())==before
    with pytest.raises(ValueError,match="ZIP_DIGEST_MISMATCH"):
        AUDIT.load_original(name,member,"0"*64)
    with pytest.raises(ValueError,match="ZIP_MEMBER_MISMATCH"):
        AUDIT.load_original(name,"different.json",digest)


def test_json_grades_source_unattested_and_no_release():
    x = _native_receipt()
    y = _mixed_receipt()
    count=AUDIT.selftest(x,y)
    assert count==5
    assert AUDIT.PR119_HEAD != x["source_head"]
    assert AUDIT.PR119_TREE != x["source_tree"]


def test_no_product_launcher_or_network_imported_into_audit():
    source=SOURCE.read_text()
    assert "import subprocess" not in source
    assert "from gateway" not in source
    assert "import requests" not in source
    assert "import socket" not in source
    assert "native_execution_decision\": \"DENY_UNAUTHORIZED_AND_UNQUALIFIED" in source
