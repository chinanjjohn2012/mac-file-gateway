"""R010 immutable Owner Choice and R014 targeted design Reviews: offline T0."""
from copy import deepcopy
from dataclasses import replace
import os
import socket
import subprocess

import pytest

from gateway.lbe_r010_owner_choice import (
    R010OwnerChoiceDenied, validate_r010_owner_design_choice_offline,
)

REPO = "chinanjjohn2012/mac-file-gateway"
HEAD = "0ef4671b63617c3a3519087f695cb335c67e9d9d"
BASE = "ca90cf30095695479615e475b8440e09f02f34d9"
TREE = "0b7f3585329b4c679ec2b200803cda762a94ec87"
DESIGN_ID = "MWE-LBE-R010-AUTHORITY-CHAIN-DESIGN-013-CANDIDATE"
DESIGN_BLOB = "f57e39543a6fe3d64fe99b8669fc7da854b93a64"
ROUND = "D4-R014-AUTHORITY-CHAIN-DESIGN-013"
B = "PRR_kwDOU5v3IM8AAAABWtAZjQ"
C = "PRR_kwDOU5v3IM8AAAABWtBPMQ"
FIELDS = [
    ("repo", REPO), ("pr", "114"),
    ("task_id", "MULTI-EXEC-LBE-FIVE-DAY-CANDIDATE-20261105"),
    ("review_round", ROUND),
    ("r010_design_id", DESIGN_ID), ("r010_design_blob", DESIGN_BLOB),
    ("design_base_sha", BASE), ("design_head_sha", HEAD),
    ("design_head_tree", TREE), ("b_r010_design_review_id", B),
    ("c_r010_design_review_id", C), ("host_option", "A1"),
    ("review_sequence_option", "B1"),
    ("state_domain", "R010_EPHEMERAL_JOB_STATE_V1"),
    ("risk_marker", "R010_REAFFIRM_R006_RISK1_9_PLUS_RISK10_11"),
]


@pytest.fixture(autouse=True)
def forbid_os_side_effects(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("source-only owner choice T0 forbids OS child/network")
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(os, "kill", forbidden)
    monkeypatch.setattr(os, "killpg", forbidden, raising=False)


def body():
    header = "\n".join(key + ": " + value + "  " for key, value in FIELDS)
    return (
        "R010_OWNER_DESIGN_CHOICE_V1\n\n" + header +
        "\n\n## 1. Owner design choice\n"
        "A1 + B1, RISK_10 and RISK_11 accepted.\n"
        "**PRODUCT_T1: NOT_AUTHORIZED.**\n"
        "**FULL_CODE_REVIEW_PASS: NOT_ISSUED.**\n"
        "**INTEGRATION_STATUS: NOT_TESTED.**\n"
        "**R10_STATUS: BLOCKED.**\n"
    )


def comment():
    return {
        "id": 6740275850,
        "user": {"login": "chinanjjohn2012", "id": 13314291, "type": "User"},
        "author_association": "OWNER",
        "issue_url": "https://api.github.com/repos/" + REPO + "/issues/114",
        "created_at": "2026-11-09T12:39:35Z",
        "updated_at": "2026-11-09T12:39:35Z", "body": body(),
    }


def review(role):
    name = "STANDARDS_REVIEW" if role == "STANDARDS_REVIEWER" else "SPEC_REVIEW"
    node = B if role == "STANDARDS_REVIEWER" else C
    values = {
        "ROLE": role, "REPO": REPO, "REVIEW_ROUND": ROUND,
        "REVIEWED_BASE_SHA": BASE, "REVIEWED_HEAD_SHA": HEAD,
        "REVIEWED_TREE_SHA": TREE, "REVIEW_SCOPE": "TARGETED",
        "REVIEW_PROGRESS": "REVIEW_COMPLETE",
        "REVIEW_LEVEL": "TARGETED_REVIEW_PASS",
        "VERDICT": "PASS", "EVIDENCE_STATUS": "SUFFICIENT",
        "CONTRACT_SCOPE": DESIGN_ID + " GitBlob " + DESIGN_BLOB,
    }
    text = "GH_HANDOFF_V2 " + name + "\n" + "\n".join(
        key + ": " + val for key, val in values.items()) + "\n"
    return {
        "node_id": node, "commit_id": HEAD, "state": "COMMENTED",
        "submitted_at": "2026-11-08T16:01:21Z",
        "body": text + "READ_ONLY: " + ("R010 source-" * 50),
    }


def check(**changes):
    data = {"comment": comment(),
            "standards_review": review("STANDARDS_REVIEWER"),
            "spec_review": review("SPEC_REVIEWER")}
    data.update(changes)
    return validate_r010_owner_design_choice_offline(**data)


def test_exact_design_choice_and_independent_role_nodes_are_nonoperative():
    observed = check()
    assert observed.comment_id == 6740275850
    assert observed.design_id == DESIGN_ID
    assert observed.design_blob == DESIGN_BLOB
    assert observed.b_review_node_id != observed.c_review_node_id
    assert observed.options == ("A1", "B1")
    assert observed.native_launch_allowed is False
    assert observed.product_t1_grant_verified is False
    assert observed.full_code_review_pass is False
    assert len(observed.body_sha256) == 64


@pytest.mark.parametrize("field,value", [
    ("id", 6740275851), ("author_association", "CONTRIBUTOR"),
    ("created_at", "2026-11-10T00:00:00Z"),
    ("updated_at", "2026-11-09T12:40:35Z"),
    ("issue_url", "https://api.github.com/repos/other/repo/issues/114"),
])
def test_untrusted_or_modified_owner_comment_denied(field, value):
    altered = comment()
    altered[field] = value
    with pytest.raises(R010OwnerChoiceDenied):
        check(comment=altered)


def test_author_login_user_id_and_type_must_be_original():
    for field, value in (("login", "not-owner"), ("id", 1), ("type", "Bot")):
        altered = comment()
        altered["user"][field] = value
        with pytest.raises(R010OwnerChoiceDenied):
            check(comment=altered)


@pytest.mark.parametrize("field,value", [
    ("r010_design_id", "MWE-LBE-R010-AUTHORITY-CHAIN-DESIGN-012-CANDIDATE"),
    ("r010_design_blob", "0" * 40), ("design_head_sha", "a" * 40),
    ("design_head_tree", "f" * 40), ("host_option", "A0"),
    ("review_sequence_option", "B0"), ("b_r010_design_review_id", C),
    ("risk_marker", "R010_REAFFIRM_R006_RISK1_9"),
])
def test_wrong_or_historical_choice_identity_is_denied(field, value):
    altered = comment()
    original = field + ": " + dict(FIELDS)[field]
    altered["body"] = altered["body"].replace(original, field + ": " + value)
    with pytest.raises(R010OwnerChoiceDenied):
        check(comment=altered)


def test_duplicate_or_unrecognized_machine_field_is_denied():
    for injected in ("\nrepo: " + REPO, "\nignored_key: yes"):
        altered = comment()
        altered["body"] = altered["body"].replace(
            "\n\n## 1.", injected + "\n\n## 1.")
        with pytest.raises(R010OwnerChoiceDenied):
            check(comment=altered)


def test_valid_choice_without_explicit_no_t1_or_risk_denied():
    for removed in ("RISK_10", "RISK_11", "PRODUCT_T1: NOT_AUTHORIZED",
                    "FULL_CODE_REVIEW_PASS: NOT_ISSUED"):
        altered = comment()
        altered["body"] = altered["body"].replace(removed, "NOT_PRESENT")
        with pytest.raises(R010OwnerChoiceDenied):
            check(comment=altered)


@pytest.mark.parametrize("field,value", [
    ("node_id", "PRR_stale"), ("commit_id", "f" * 40),
    ("state", "APPROVED"),
    ("submitted_at", "2026-11-09T12:39:35Z"),
])
def test_stale_wrong_state_or_late_review_denied(field, value):
    b = review("STANDARDS_REVIEWER")
    b[field] = value
    with pytest.raises(R010OwnerChoiceDenied):
        check(standards_review=b)


@pytest.mark.parametrize("field,value", [
    ("REVIEWED_BASE_SHA", "f" * 40),
    ("REVIEWED_TREE_SHA", "e" * 40),
    ("VERDICT", "FAIL"),
    ("REVIEW_LEVEL", "FIX_PASS"),
    ("REVIEW_SCOPE", "FULL"),
    ("EVIDENCE_STATUS", "INSUFFICIENT"),
    ("CONTRACT_SCOPE", "unrelated"),
])
def test_design_review_wrong_snapshot_scope_or_verdict_denied(field, value):
    c = review("SPEC_REVIEWER")
    prefix = field + ": "
    c["body"] = c["body"].replace(
        prefix + next(line[len(prefix):] for line in c["body"].splitlines()
                      if line.startswith(prefix)),
        prefix + value)
    with pytest.raises(R010OwnerChoiceDenied):
        check(spec_review=c)


def test_design_review_duplicate_field_denied():
    b = review("STANDARDS_REVIEWER")
    b["body"] += "\nVERDICT: PASS\n"
    with pytest.raises(R010OwnerChoiceDenied):
        check(standards_review=b)


def test_model_receipt_never_exposes_an_execution_method():
    observed = check()
    for method in ("launch", "popen", "grant", "start_row", "run"):
        assert not hasattr(observed, method)
