"""R010 R014 OWNER design-choice cross-check, offline and non-operative.

Consumes native GitHub API JSON *as data*. A caller-provided JSON object is
NOT independently authenticated GitHub evidence, and this module never queries
GitHub, obtains a PRODUCT_T1 Grant, calls a provider or enables Exec. It fixes
the expected immutable R014 identity, not expectations supplied by the Choice.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import re
from collections.abc import Mapping

_REPO = "chinanjjohn2012/mac-file-gateway"
_TASK_ID = "MULTI-EXEC-LBE-FIVE-DAY-CANDIDATE-20261105"
_ROUND = "D4-R014-AUTHORITY-CHAIN-DESIGN-013"
_ID = "MWE-LBE-R010-AUTHORITY-CHAIN-DESIGN-013-CANDIDATE"
_BLOB = "f57e39543a6fe3d64fe99b8669fc7da854b93a64"
_BASE = "ca90cf30095695479615e475b8440e09f02f34d9"
_HEAD = "0ef4671b63617c3a3519087f695cb335c67e9d9d"
_TREE = "0b7f3585329b4c679ec2b200803cda762a94ec87"
_REVIEW_IDS = {
    "STANDARDS_REVIEWER": "PRR_kwDOU5v3IM8AAAABWtAZjQ",
    "SPEC_REVIEWER": "PRR_kwDOU5v3IM8AAAABWtBPMQ",
}
_COMMENT_ID = 6740275850
_OWNER_ID = 13314291
_URL = "https://api.github.com/repos/" + _REPO
_REQUIRED_FIELDS = {
    "repo": _REPO,
    "pr": "114",
    "task_id": _TASK_ID,
    "review_round": _ROUND,
    "r010_design_id": _ID,
    "r010_design_blob": _BLOB,
    "design_base_sha": _BASE,
    "design_head_sha": _HEAD,
    "design_head_tree": _TREE,
    "b_r010_design_review_id": _REVIEW_IDS["STANDARDS_REVIEWER"],
    "c_r010_design_review_id": _REVIEW_IDS["SPEC_REVIEWER"],
    "host_option": "A1",
    "review_sequence_option": "B1",
    "state_domain": "R010_EPHEMERAL_JOB_STATE_V1",
    "risk_marker": "R010_REAFFIRM_R006_RISK1_9_PLUS_RISK10_11",
}
_TIMESTAMP = re.compile(r"20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z", re.ASCII)


class R010OwnerChoiceDenied(ValueError):
    """Current-version design-choice source does not satisfy R014 predicates."""


@dataclass(frozen=True, slots=True)
class R010OwnerDesignChoiceObservation:
    comment_id: int
    body_sha256: str
    design_id: str
    design_blob: str
    b_review_node_id: str
    c_review_node_id: str
    options: tuple[str, str]
    risk_marker: str
    status: str = "SOURCE_ONLY_R014_CHOICE_MATCH_NOT_PROVIDER_ATTESTED"
    native_launch_allowed: bool = False
    product_t1_grant_verified: bool = False
    full_code_review_pass: bool = False


def _single_field(body: str, field: str) -> str:
    # An original reviewed heading may occur once; a second conflicting
    # machine-readable field must never choose whichever value appears first.
    values = re.findall(r"^" + re.escape(field) + r":[ \t]*([^\r\n]+)",
                        body, flags=re.MULTILINE)
    if len(values) != 1:
        raise R010OwnerChoiceDenied("missing or duplicate review field: " + field)
    return values[0].strip()


def _choice_header(body: str) -> dict[str, str]:
    if (type(body) is not str or not 1 <= len(body) <= 8192
            or "\x00" in body or body.replace("\r\n", "\n").split("\n")[0]
            != "R010_OWNER_DESIGN_CHOICE_V1"):
        raise R010OwnerChoiceDenied("missing current owner-choice marker")
    lines = body.replace("\r\n", "\n").split("\n")
    fields: dict[str, str] = {}
    reached_section = False
    for line in lines[1:]:
        if line.startswith("## "):
            reached_section = True
            break
        if not line.strip():
            continue
        name, colon, value = line.partition(":")
        if (not colon or name not in _REQUIRED_FIELDS or name in fields
                or not value.strip()):
            raise R010OwnerChoiceDenied("unknown or duplicate owner-choice field")
        fields[name] = value.strip()
    if not reached_section or fields != _REQUIRED_FIELDS:
        raise R010OwnerChoiceDenied("wrong current design/review/Choice identity")
    # Risk statement is an explicit design-only choice, not a run authority.
    if (not all(token in body for token in (
            "RISK_10", "RISK_11", "A1 + B1", "PRODUCT_T1: NOT_AUTHORIZED",
            "FULL_CODE_REVIEW_PASS: NOT_ISSUED",
            "INTEGRATION_STATUS: NOT_TESTED", "R10_STATUS: BLOCKED"))):
        raise R010OwnerChoiceDenied("risk boundary or no-execution statement absent")
    return fields


def _validate_review(review: Mapping[str, object], role: str,
                     *, owner_created_at: str) -> str:
    if not isinstance(review, Mapping):
        raise R010OwnerChoiceDenied("missing native GitHub review data")
    node_id = _REVIEW_IDS[role]
    if (review.get("node_id") != node_id or
            review.get("commit_id") != _HEAD or
            review.get("state") != "COMMENTED"):
        raise R010OwnerChoiceDenied("review node, commit or state does not match")
    submitted = review.get("submitted_at")
    if (type(submitted) is not str or _TIMESTAMP.fullmatch(submitted) is None
            or submitted >= owner_created_at):
        raise R010OwnerChoiceDenied("design review not before owner choice")
    body = review.get("body")
    if type(body) is not str or not 500 <= len(body) <= 250000:
        raise R010OwnerChoiceDenied("native review body absent or unbounded")
    marker = "GH_HANDOFF_V2 " + (
        "STANDARDS_REVIEW" if role == "STANDARDS_REVIEWER" else "SPEC_REVIEW")
    if not body.startswith(marker + "\n"):
        raise R010OwnerChoiceDenied("wrong independent role Review marker")
    required = {
        "ROLE": role, "REPO": _REPO, "REVIEW_ROUND": _ROUND,
        "REVIEWED_BASE_SHA": _BASE, "REVIEWED_HEAD_SHA": _HEAD,
        "REVIEWED_TREE_SHA": _TREE, "REVIEW_SCOPE": "TARGETED",
        "REVIEW_PROGRESS": "REVIEW_COMPLETE",
        "REVIEW_LEVEL": "TARGETED_REVIEW_PASS",
    }
    for field, value in required.items():
        if _single_field(body, field) != value:
            raise R010OwnerChoiceDenied("review target drift: " + field)
    if (not _single_field(body, "VERDICT").startswith("PASS")
            or not _single_field(body, "EVIDENCE_STATUS").startswith("SUFFICIENT")
            or _ID not in _single_field(body, "CONTRACT_SCOPE")
            or _BLOB not in _single_field(body, "CONTRACT_SCOPE")):
        raise R010OwnerChoiceDenied("not a valid R014 targeted design PASS")
    return node_id


def validate_r010_owner_design_choice_offline(
    *, comment: Mapping[str, object],
    standards_review: Mapping[str, object],
    spec_review: Mapping[str, object],
) -> R010OwnerDesignChoiceObservation:
    """Check frozen R014 native-API object fields. Never asserts API authenticity."""
    if not isinstance(comment, Mapping):
        raise R010OwnerChoiceDenied("missing direct Owner comment")
    creator = comment.get("user")
    created = comment.get("created_at")
    if (type(comment.get("id")) is not int or
            comment["id"] != _COMMENT_ID or
            not isinstance(creator, Mapping) or
            creator.get("login") != "chinanjjohn2012" or
            type(creator.get("id")) is not int or
            creator.get("id") != _OWNER_ID or
            creator.get("type") != "User" or
            comment.get("author_association") != "OWNER" or
            comment.get("issue_url") != _URL + "/issues/114" or
            type(created) is not str or _TIMESTAMP.fullmatch(created) is None or
            comment.get("updated_at") != created):
        raise R010OwnerChoiceDenied("direct unchanged Owner identity not proven")
    body = comment.get("body")
    _choice_header(body)
    b_id = _validate_review(
        standards_review, "STANDARDS_REVIEWER", owner_created_at=created)
    c_id = _validate_review(
        spec_review, "SPEC_REVIEWER", owner_created_at=created)
    # Both reviews may have been published through one connected GitHub user.
    # This is logical role independence, NEVER two independent humans.
    return R010OwnerDesignChoiceObservation(
        comment_id=_COMMENT_ID,
        body_sha256=hashlib.sha256(body.encode("utf-8")).hexdigest(),
        design_id=_ID, design_blob=_BLOB,
        b_review_node_id=b_id, c_review_node_id=c_id,
        options=("A1", "B1"), risk_marker=_REQUIRED_FIELDS["risk_marker"],
    )
