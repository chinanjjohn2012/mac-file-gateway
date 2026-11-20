"""T0 dummy fixture tests only: never interact with installed Go/Pipenv/Python."""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path

import pytest

from tools import rc119_t1_input_qualification as q


def sample_template() -> dict:
    rows = [{"id": x, "origin_uri": None, "source_version": None,
             "expected_size_bytes": None, "expected_sha256": None,
             "observed_sha256": None, "fetched_bytes_location": None,
             "verified_import_location": None, "independent_evidence_uri": None,
             "evidence_status": "NOT_ATTESTED"} for x in q.REQUIRED_IDS]
    return {"schema_version": 1, "kind": "RC119_T1_INPUT_IDENTITY_TEMPLATE_NONATTESTED",
            "target_repo": q.REPO, "target_pr": q.RC_PR, "target_head": q.RC_HEAD,
            "target_tree": q.RC_TREE, "control_commit": None, "control_tree": None,
            "source_provenance": "BASE_AND_TARGET_GIT_IDENTITIES_ONLY_NOT_NATIVE_SELECTED_INPUTS",
            "network_profile": "PENDING_B_C_AND_OWNER_DECISION",
            "owner_native_test_permission": "NOT_GRANTED",
            "replay_consumption": "NOT_IMPLEMENTED", "inputs": rows}


def test_exact_22_unattested_categories_are_not_source_pass():
    report = q.inspect_input_template(sample_template())
    assert report["valid_nonattested_template"] is True
    assert len(report["observed_categories"]) == 22
    assert report["selected_sources_attested"] is False
    assert report["native_execution_authorized"] is False


@pytest.mark.parametrize("mutator", [
    lambda x: x["inputs"].pop(),
    lambda x: x["inputs"].append(copy.deepcopy(x["inputs"][0])),
    lambda x: x["inputs"][0].update({"id": "out_of_scope"}),
    lambda x: x["inputs"][0].update({"evidence_status": "ATTESTED"}),
    lambda x: x["inputs"][0].update({"observed_sha256": "a" * 64}),
    lambda x: x.update({"target_head": "0" * 40}),
    lambda x: x.update({"target_pr": True}),
    lambda x: x.update({"owner_native_test_permission": "GRANTED"}),
    lambda x: x.update({"replay_consumption": "CONSUMED"}),
    lambda x: x.update({"native_execution_authorized": True}),
    lambda x: x["inputs"][0].update({"claimed_source_closed": True}),
    lambda x: x.update({"source_provenance": "ALL_SOURCE_CLOSED"}),
    lambda x: x.update({"control_commit": "0"*40}),
])
def test_bad_template_fails_closed(mutator):
    x = sample_template()
    mutator(x)
    assert q.inspect_input_template(x)["valid_nonattested_template"] is False


@pytest.mark.parametrize("claim", [None, 3, {}, [], "not a manifest"])
def test_wrong_manifest_shape_denied(claim):
    assert q.inspect_input_template(claim)["valid_nonattested_template"] is False


def test_dummy_regular_file_matches_but_no_external_provenance(tmp_path):
    (tmp_path / "nested").mkdir()
    data = b"dummy source bytes for nonexecuting T0, no external dependency"
    f = tmp_path / "nested" / "dummy.dat"
    f.write_bytes(data)
    result = q.read_disposable_fixture(tmp_path, "nested/dummy.dat",
                                       hashlib.sha256(data).hexdigest(), len(data))
    assert result["grade"] == "LOCAL_T0_DUMMY_BYTES_MATCHED_ONLY"
    assert result["selected_source_provenance"] == "NOT_ATTESTED"
    assert result["native_execution_authorized"] is False


@pytest.mark.parametrize("relative", [
    "../test", "nested/../test", "/etc/passwd", "nested//dummy.dat",
    "nested/./dummy.dat", "nested\\dummy.dat", "", "bad\x00file",
])
def test_noncanonical_or_escaping_paths_denied(tmp_path, relative):
    with pytest.raises(q.QualificationDenied):
        q.read_disposable_fixture(tmp_path, relative, "a" * 64, 1)


def test_symlink_to_outside_private_root_never_followed(tmp_path):
    external = tmp_path.parent / "external.dat"
    external.write_bytes(b"outside")
    (tmp_path / "link.dat").symlink_to(external)
    with pytest.raises(q.QualificationDenied):
        q.read_disposable_fixture(tmp_path, "link.dat", hashlib.sha256(b"outside").hexdigest(), 7)


def test_parent_directory_symlink_denied(tmp_path):
    (tmp_path / "real").mkdir()
    (tmp_path / "real" / "payload").write_bytes(b"abc")
    (tmp_path / "alias").symlink_to(tmp_path / "real", target_is_directory=True)
    with pytest.raises(q.QualificationDenied):
        q.read_disposable_fixture(tmp_path, "alias/payload", hashlib.sha256(b"abc").hexdigest(), 3)


def test_hardlink_denied(tmp_path):
    f = tmp_path / "f"
    f.write_bytes(b"data")
    os.link(f, tmp_path / "other")
    with pytest.raises(q.QualificationDenied, match="NOT_SINGLE_LINK_REGULAR_FILE"):
        q.read_disposable_fixture(tmp_path, "f", hashlib.sha256(b"data").hexdigest(), 4)


@pytest.mark.parametrize("expected_size,expected_digest", [
    (2, hashlib.sha256(b"ok").hexdigest()),
    (3, "0" * 64),
    (True, hashlib.sha256(b"ok").hexdigest()),
    (3, "not a SHA"),
])
def test_wrong_size_digest_or_type_denied(tmp_path, expected_size, expected_digest):
    (tmp_path / "f").write_bytes(b"ok!")
    with pytest.raises(q.QualificationDenied):
        q.read_disposable_fixture(tmp_path, "f", expected_digest, expected_size)


def test_unexpected_t0_budget_denied_before_open(tmp_path):
    with pytest.raises(q.QualificationDenied, match="BAD_BYTE_BUDGET"):
        q.read_disposable_fixture(tmp_path, "data", "a" * 64, 5, max_bytes="untrusted")


def test_fifo_is_not_read(tmp_path):
    os.mkfifo(tmp_path / "namedpipe")
    with pytest.raises(q.QualificationDenied, match="NOT_SINGLE_LINK_REGULAR_FILE"):
        q.read_disposable_fixture(tmp_path, "namedpipe", "a" * 64, 0)


@pytest.mark.parametrize("prelaunch_match,seen_helper,witness,expected", [
    (False,False,False,"PRELAUNCH_INPUTS_NOT_ATTESTED"),
    (True,False,False,"RUNTIME_DYNAMIC_EXECUTION_NOT_ATTESTED"),
    (True,False,True,"RUNTIME_DYNAMIC_EXECUTION_NOT_ATTESTED"),
    (True,True,False,"DYNAMIC_FOREIGN_SOURCE_OBSERVED_BLOCKED"),
    (False,True,True,"DYNAMIC_FOREIGN_SOURCE_OBSERVED_BLOCKED"),
])
def test_runtime_source_grade_never_claims_source_closed(prelaunch_match,seen_helper,witness,expected):
    assert q.classify_claimed_runtime_source(prelaunch_match,seen_helper,witness) == expected


def test_untrusted_runtime_grade_types_denied():
    with pytest.raises(q.QualificationDenied):
        q.classify_claimed_runtime_source(1,False,False)


def test_no_native_execution_entrypoint():
    with pytest.raises(q.QualificationDenied, match="NATIVE_T1_NOT_AUTHORIZED"):
        q.native_execution_decision()
    text = Path(q.__file__).read_text()
    for unsafe in ("import subprocess", "urllib.request", "requests.get", "os.system", "subprocess.Popen", "exec("):
        assert unsafe not in text
