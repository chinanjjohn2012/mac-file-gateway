"""R010 exact Owner PRODUCT_T1 Grant source predicate (no execution authority).

Checks a prospective GitHub Owner comment against one frozen implementation,
two distinct independent TARGETED qualification reviews, the R014 A1+B1
Choice and original OIDC signature transcript. The arguments are untrusted
native API-shaped data: this module DOES NOT fetch GitHub/TLS/JWKS or establish
provider provenance. Even a matching record cannot enable PRODUCT_T1, issue
a service grant, advance a row or authorize a launcher.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import re

from .lbe_r010_oidc_verify import (
    R010OIDCExpected, R010OIDCSignatureReceipt, R010OIDCDenied,
    require_r010_oidc_offline_fresh_at,
)
from .lbe_r010_owner_choice import R010OwnerDesignChoiceObservation

_REPO = "chinanjjohn2012/mac-file-gateway"
_DESIGN_BLOB = "f57e39543a6fe3d64fe99b8669fc7da854b93a64"
_TARGET = "R010_COMPLETE_PRE_T1_CRITICAL_PATH_V1"
_SCOPE = "R010_IMPLEMENTATION_CONTRACT_V1"
_PROVIDER = "R010_GITHUB_OIDC_CHECK_RUN_V1"
_SHA40 = re.compile(r"[0-9a-f]{40}\Z", re.ASCII)
_SHA64 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_TIMESTAMP = re.compile(r"20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z", re.ASCII)


class R010GrantSourceDenied(ValueError):
    """No source-qualified current implementation grant candidate."""


@dataclass(frozen=True, slots=True)
class R010GrantExpected:
    """Caller expectations, not authenticated GitHub or provider evidence."""

    base_sha: str
    head_sha: str
    tree_sha: str
    manifest_sha256: str
    state_provenance_sha256: str
    runner_image_sha256: str
    source_graph_sha256: str
    host_snapshot_sha256: str
    job_envelope_key_sha256: str
    job_envelope_root_sha256: str
    job_lease_sha256: str
    job_local_secret_sha256: str
    service_instance_nonce_sha256: str
    owner_lock_sha256: str
    exec_state_sha256: str
    command_journal_sha256: str
    config_sha256: str
    six_commands_sha256: str
    six_nonces_sha256: str

    def checked(self) -> "R010GrantExpected":
        for field in ("base_sha", "head_sha", "tree_sha"):
            value = getattr(self, field)
            if type(value) is not str or _SHA40.fullmatch(value) is None:
                raise R010GrantSourceDenied("missing fixed implementation SHA")
        for field in self.__dataclass_fields__:
            if field in ("base_sha", "head_sha", "tree_sha"):
                continue
            value = getattr(self, field)
            if type(value) is not str or _SHA64.fullmatch(value) is None:
                raise R010GrantSourceDenied("unqualified source/Job digest: " + field)
        return self


@dataclass(frozen=True, slots=True)
class R010GrantSourceObservation:
    """A matching proposal, NEVER a trusted Owner/Provider execution grant."""

    grant_comment_id: int
    body_sha256: str
    implementation_head_sha: str
    standards_review_node_id: str
    spec_review_node_id: str
    signed_jwt_sha256: str
    job_envelope_key_sha256: str
    grant_expires_unix: int
    status: str = "OWNER_GRANT_SOURCE_MATCH_EXTERNAL_TRUST_NOT_ATTESTED"
    owner_comment_authenticated: bool = False
    provider_job_authenticated: bool = False
    execution_qualification_attested: bool = False
    native_launch_allowed: bool = False
    row_positive_success: bool = False
    six_command_product_t1_pass: bool = False


def _timestamp(raw: object) -> int:
    if type(raw) is not str or _TIMESTAMP.fullmatch(raw) is None:
        raise R010GrantSourceDenied("invalid native GitHub timestamp")
    try:
        return int(datetime.strptime(raw, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc).timestamp())
    except ValueError:
        raise R010GrantSourceDenied("unrecognized native timestamp") from None


def _read_header(body: object) -> dict[str, str]:
    if (type(body) is not str or not 100 <= len(body) <= 16384
            or "\x00" in body):
        raise R010GrantSourceDenied("unavailable Owner grant body")
    lines = body.replace("\r\n", "\n").split("\n")
    if lines[0] != "R010_OWNER_PRODUCT_T1_GRANT_V1":
        raise R010GrantSourceDenied("wrong PRODUCT_T1 grant marker")
    fields: dict[str, str] = {}
    boundary = False
    for line in lines[1:]:
        if line.startswith("## "):
            boundary = True
            break
        if not line.strip():
            continue
        key, sep, value = line.partition(":")
        if (sep != ":" or key in fields or
                re.fullmatch(r"[a-z][a-z0-9_]{0,79}", key) is None or
                not value.strip() or len(value.strip()) > 1024):
            raise R010GrantSourceDenied("duplicate or invalid Grant field")
        fields[key] = value.strip()
    if not boundary:
        raise R010GrantSourceDenied("unbounded Grant field section")
    return fields


def _review_field(body: str, name: str) -> str:
    matches = re.findall(
        r"^" + re.escape(name) + r":[ \t]*([^\r\n]+)",
        body, flags=re.MULTILINE)
    if len(matches) != 1:
        raise R010GrantSourceDenied("missing or duplicate review field: " + name)
    return matches[0].strip()


def _review(review: Mapping[str, object], *, role: str,
            expected: R010GrantExpected, before_unix: int) -> str:
    if not isinstance(review, Mapping):
        raise R010GrantSourceDenied("missing independent qualification Review")
    node = review.get("node_id")
    if (type(node) is not str or not 8 <= len(node) <= 128
            or review.get("commit_id") != expected.head_sha
            or review.get("state") != "COMMENTED"
            or _timestamp(review.get("submitted_at")) >= before_unix):
        raise R010GrantSourceDenied("stale/missing SHA-bound qualification")
    body = review.get("body")
    marker = ("STANDARDS_REVIEW" if role == "STANDARDS_REVIEWER"
              else "SPEC_REVIEW")
    if (type(body) is not str or not 300 <= len(body) <= 250000
            or not body.startswith("GH_HANDOFF_V2 " + marker + "\n")):
        raise R010GrantSourceDenied("unqualified independent review body")
    required = {
        "ROLE": role, "REPO": _REPO,
        "REVIEWED_BASE_SHA": expected.base_sha,
        "REVIEWED_HEAD_SHA": expected.head_sha,
        "REVIEWED_TREE_SHA": expected.tree_sha,
        "REVIEW_SCOPE": "TARGETED",
        "REVIEW_PROGRESS": "REVIEW_COMPLETE",
        "EVIDENCE_STATUS": "SUFFICIENT",
        "REVIEW_LEVEL": "TARGETED_REVIEW_PASS",
    }
    for name, value in required.items():
        if _review_field(body, name) != value:
            raise R010GrantSourceDenied("qualification drift: " + name)
    if (not _review_field(body, "VERDICT").startswith("PASS")
            or _TARGET not in _review_field(body, "REVIEW_TARGET")
            or _SCOPE not in _review_field(body, "CONTRACT_SCOPE")):
        raise R010GrantSourceDenied("not complete PRE-T1 targeted qualification")
    return node


def validate_r010_product_grant_source_offline(
    *, comment: Mapping[str, object],
    standards_review: Mapping[str, object],
    spec_review: Mapping[str, object],
    choice: R010OwnerDesignChoiceObservation,
    expected: R010GrantExpected,
    oidc_expected: R010OIDCExpected,
    oidc_receipt: R010OIDCSignatureReceipt,
    now_unix: int,
) -> R010GrantSourceObservation:
    """Reject stale/mixed source tuples; always return NO execution authority.

    Even a successful synthetic fixture does not verify direct Owner authorship,
    GitHub API authenticity, TLS/JWKS provenance, a live provider Job, a real
    original child or the independent current executable source review.
    """
    if (type(choice) is not R010OwnerDesignChoiceObservation
            or choice.comment_id != 6740275850
            or choice.design_blob != _DESIGN_BLOB
            or choice.options != ("A1", "B1")
            or choice.status != "SOURCE_ONLY_R014_CHOICE_MATCH_NOT_PROVIDER_ATTESTED"
            or choice.native_launch_allowed is not False
            or choice.product_t1_grant_verified is not False
            or type(expected) is not R010GrantExpected
            or type(oidc_expected) is not R010OIDCExpected
            or type(oidc_receipt) is not R010OIDCSignatureReceipt
            or type(now_unix) is not int):
        raise R010GrantSourceDenied("current R014 Choice and candidate missing")
    expected.checked()
    try:
        oidc_expected.checked()
        require_r010_oidc_offline_fresh_at(
            oidc_receipt, grant_now_unix=now_unix)
    except R010OIDCDenied:
        raise R010GrantSourceDenied("OIDC source transcript unqualified") from None
    if (oidc_expected.implementation_head_sha != expected.head_sha
            or oidc_expected.signed_source_sha != expected.head_sha
            or oidc_expected.job_local_secret_sha256 !=
               expected.job_local_secret_sha256
            or oidc_receipt.checked_run_id != oidc_expected.run_id
            or oidc_receipt.checked_run_attempt != oidc_expected.run_attempt
            or oidc_receipt.checked_check_run_id != oidc_expected.check_run_id
            or oidc_receipt.signed_subject != oidc_expected.subject):
        raise R010GrantSourceDenied("current signed Job/source binding drift")
    if not isinstance(comment, Mapping):
        raise R010GrantSourceDenied("missing direct Owner source")
    author = comment.get("user")
    created = comment.get("created_at")
    if (type(comment.get("id")) is not int or comment["id"] <= 0
            or not isinstance(author, Mapping)
            or author.get("login") != "chinanjjohn2012"
            or type(author.get("id")) is not int
            or author["id"] != 13314291 or author.get("type") != "User"
            or comment.get("author_association") != "OWNER"
            or comment.get("issue_url") !=
               "https://api.github.com/repos/" + _REPO + "/issues/114"
            or comment.get("updated_at") != created):
        raise R010GrantSourceDenied("missing unchanged native Owner source")
    owner_unix = _timestamp(created)
    if owner_unix > now_unix or now_unix - owner_unix > 600:
        raise R010GrantSourceDenied("unqualified Owner publication time")
    b_id = _review(
        standards_review, role="STANDARDS_REVIEWER",
        expected=expected, before_unix=owner_unix)
    c_id = _review(
        spec_review, role="SPEC_REVIEWER",
        expected=expected, before_unix=owner_unix)
    if b_id == c_id:
        raise R010GrantSourceDenied("one review is not two role reviews")
    field_expected = {
        "repo": _REPO, "pr": "114",
        "r010_design_blob": _DESIGN_BLOB,
        "owner_design_choice_comment_id": str(choice.comment_id),
        "owner_design_choice_body_sha256": choice.body_sha256,
        "host_option": "A1", "review_sequence_option": "B1",
        "risk_marker": "R010_REAFFIRM_R006_RISK1_9_PLUS_RISK10_11",
        "b_r010_design_review_id": choice.b_review_node_id,
        "c_r010_design_review_id": choice.c_review_node_id,
        "implementation_base_sha": expected.base_sha,
        "implementation_head_sha": expected.head_sha,
        "implementation_head_tree": expected.tree_sha,
        "manifest_sha256": expected.manifest_sha256,
        "b_r010_t1_qualification_review_id": b_id,
        "c_r010_t1_qualification_review_id": c_id,
        "review_target_id": _TARGET,
        "contract_scope_id": _SCOPE,
        "provider_contract": _PROVIDER,
        "oidc_issuer": oidc_receipt.issuer,
        "oidc_audience": oidc_expected.audience,
        "oidc_token_sha256": oidc_receipt.jwt_sha256,
        "oidc_signing_input_sha256": oidc_receipt.signing_input_sha256,
        "oidc_payload_sha256": oidc_receipt.signed_payload_sha256,
        "oidc_issuer_metadata_sha256": oidc_receipt.issuer_metadata_sha256,
        "oidc_jwks_sha256": oidc_receipt.jwks_sha256,
        "oidc_algorithm": oidc_receipt.algorithm,
        "oidc_kid": oidc_receipt.key_id,
        "oidc_subject": oidc_receipt.signed_subject,
        "run_id": oidc_expected.run_id,
        "run_attempt": oidc_expected.run_attempt,
        "check_run_id": oidc_expected.check_run_id,
        "workflow_ref": oidc_expected.workflow_ref,
        "workflow_sha": oidc_expected.workflow_sha,
        "runner_image_sha256": expected.runner_image_sha256,
        "source_graph_sha256": expected.source_graph_sha256,
        "host_snapshot_sha256": expected.host_snapshot_sha256,
        "state_domain": "R010_EPHEMERAL_JOB_STATE_V1",
        "state_provenance_sha256": expected.state_provenance_sha256,
        "job_envelope_key_sha256": expected.job_envelope_key_sha256,
        "job_envelope_root_sha256": expected.job_envelope_root_sha256,
        "job_lease_sha256": expected.job_lease_sha256,
        "job_local_secret_sha256": expected.job_local_secret_sha256,
        "service_instance_nonce_sha256": expected.service_instance_nonce_sha256,
        "owner_lock_sha256": expected.owner_lock_sha256,
        "exec_state_sha256": expected.exec_state_sha256,
        "command_journal_sha256": expected.command_journal_sha256,
        "config_sha256": expected.config_sha256,
        "row_contract": "R010_SERIAL_EXIT0_FINITE_OBSERVED_DELTA_V1",
        "six_commands_sha256": expected.six_commands_sha256,
        "six_nonces_sha256": expected.six_nonces_sha256,
    }
    if (type(choice.body_sha256) is not str
            or _SHA64.fullmatch(choice.body_sha256) is None):
        raise R010GrantSourceDenied("missing immutable Choice body digest")
    fields = _read_header(comment.get("body"))
    if set(fields) != set(field_expected) | {"expires_unix"}:
        raise R010GrantSourceDenied("missing/unknown current Grant fields")
    if any(fields[key] != value for key, value in field_expected.items()):
        raise R010GrantSourceDenied("grant source tuple mismatch")
    try:
        expiry = int(fields["expires_unix"])
    except ValueError:
        raise R010GrantSourceDenied("invalid grant expiry") from None
    if (str(expiry) != fields["expires_unix"]
            or not owner_unix < expiry <= owner_unix + 600
            or now_unix >= expiry
            or expiry > oidc_receipt.expires_unix):
        raise R010GrantSourceDenied("stale or overbroad candidate Grant")
    return R010GrantSourceObservation(
        grant_comment_id=comment["id"],
        body_sha256=hashlib.sha256(
            comment["body"].encode("utf-8")).hexdigest(),
        implementation_head_sha=expected.head_sha,
        standards_review_node_id=b_id, spec_review_node_id=c_id,
        signed_jwt_sha256=oidc_receipt.jwt_sha256,
        job_envelope_key_sha256=expected.job_envelope_key_sha256,
        grant_expires_unix=expiry,
    )
