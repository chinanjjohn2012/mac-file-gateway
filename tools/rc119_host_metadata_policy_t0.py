"""Inert negative-only RC119 host safety policy; no host IO whatsoever.

Only evaluate caller-supplied SYNTHETIC SAFE T0 categorical fixtures. This is
NOT a host collector, not a run authorization and not a future N1-B admission.
The precise design Blob has independent B/C TARGETED DESIGN reviews only.
"""
from __future__ import annotations

import json

SCOPE_BLOB = "fed1cdae899d38fb300b860eb307c2d027ae8b39"
PRODUCT_HEAD = "33c30b6c2710cac0f8533370c1ca42f31ef6747a"
PRODUCT_TREE = "27e26c423e700cdbad0aeca27efcdf82594507c1"
OWNER_HOST_RUN_AUTHORIZED = False
N1B_QUALIFIED_PRE_FOREIGN = False
NATIVE_T1_AUTHORIZED = False
SCHEMA = frozenset({"kind", "scope_blob", "product_head", "product_tree", "host_identity", "categories"})
IDENTITY_FIELDS = frozenset({"runner_kind", "os", "arch", "image_identity", "uid_consistency", "run_attempt"})
CATEGORIES = frozenset({"bootstrap", "environment", "credential_paths", "fd_socket",
                        "mounts", "cloud_identity", "sentinel", "stability"})
STATES = frozenset({"CLEAR", "RISK", "UNKNOWN"})
MAX_JSON_BYTES = 2048
MAX_OUTPUT_BYTES = 1300


def _result(code: str, *reasons: str) -> dict[str, object]:
    # Fixed enumerated strings only. Never echo fixture values/paths/errors.
    return {"evidence_mode": "SAFE_T0_SYNTHETIC_ONLY",
            "synthetic_host_decision": code,
            "reason_codes": list(reasons[:8]),
            "actual_host_job": "NOT_RUN",
            "host_metadata_observed": False,
            "n1b_qualified_pre_foreign": False,
            "real_external_loaded_source": "NOT_ATTESTED",
            "native_execution_authorized": False}


def evaluate_synthetic_fixture(value: object) -> dict[str, object]:
    """Evaluate categorical FAKE input. Cannot sign a real host PASS."""
    if type(value) is not dict or set(value) != SCHEMA:
        return _result("HOST_UNKNOWN_SIMULATED", "SCHEMA_NOT_CLOSED")
    if any(type(value[k]) is not str for k in ("kind", "scope_blob", "product_head", "product_tree")):
        return _result("HOST_UNKNOWN_SIMULATED", "IDENTITY_SHAPE_INVALID")
    if (value["kind"] != "SAFE_T0_SYNTHETIC_HOST_METADATA" or
            value["scope_blob"] != SCOPE_BLOB or
            value["product_head"] != PRODUCT_HEAD or
            value["product_tree"] != PRODUCT_TREE):
        return _result("HOST_UNKNOWN_SIMULATED", "IDENTITY_MISMATCH")
    identity = value["host_identity"]
    statuses = value["categories"]
    if (type(identity) is not dict or set(identity) != IDENTITY_FIELDS or
            type(statuses) is not dict or set(statuses) != CATEGORIES or
            any(type(x) is not str or x not in STATES for x in statuses.values())):
        return _result("HOST_UNKNOWN_SIMULATED", "CATEGORIES_NOT_CLOSED")
    if (identity.get("runner_kind") != "DISPOSABLE_GITHUB_HOSTED" or
            identity.get("os") != "macos-15" or identity.get("arch") != "arm64" or
            identity.get("image_identity") != "SYNTHETIC_MATCH" or
            identity.get("uid_consistency") != "SYNTHETIC_MATCH" or
            type(identity.get("run_attempt")) is not int or identity["run_attempt"] != 1):
        return _result("HOST_DENIED_SIMULATED", "HOST_IDENTITY_MISMATCH")
    deny = sorted(k for k, v in statuses.items() if v == "RISK")
    if deny:
        # Bounded categorical labels only, not arbitrary strings.
        return _result("HOST_DENIED_SIMULATED", *tuple("RISK_" + k.upper() for k in deny))
    unknown = sorted(k for k, v in statuses.items() if v == "UNKNOWN")
    if unknown:
        return _result("HOST_UNKNOWN_SIMULATED", *tuple("UNKNOWN_" + k.upper() for k in unknown))
    return _result("HOST_CATEGORICAL_CLEAN_SIMULATED", "NOT_REAL_HOST_WITNESS")


def parse_synthetic_fixture_json(raw: object) -> dict[str, object]:
    """Bound JSON decode for an inert synthetic fixture, no I/O or logging."""
    if type(raw) is not bytes or len(raw) > MAX_JSON_BYTES:
        return _result("HOST_UNKNOWN_SIMULATED", "SCHEMA_NOT_CLOSED")
    try:
        return evaluate_synthetic_fixture(json.loads(raw))
    except (ValueError, TypeError, UnicodeError, OverflowError):
        return _result("HOST_UNKNOWN_SIMULATED", "SCHEMA_NOT_CLOSED")


def render_categorical_receipt(result: object) -> bytes:
    """Bound redacted output with exact internal schema, no raw exceptions."""
    if (type(result) is not dict or
            set(result) != {"evidence_mode", "synthetic_host_decision", "reason_codes",
                            "actual_host_job", "host_metadata_observed", "n1b_qualified_pre_foreign",
                            "real_external_loaded_source", "native_execution_authorized"}):
        raise ValueError("INVALID_RECEIPT_SCHEMA")
    if result.get("evidence_mode") != "SAFE_T0_SYNTHETIC_ONLY" or result.get("actual_host_job") != "NOT_RUN":
        raise ValueError("UNTRUSTED_REAL_HOST_CLAIM")
    reasons = result.get("reason_codes")
    allowed = ({"SCHEMA_NOT_CLOSED", "IDENTITY_SHAPE_INVALID", "IDENTITY_MISMATCH",
                "CATEGORIES_NOT_CLOSED", "HOST_IDENTITY_MISMATCH", "NOT_REAL_HOST_WITNESS"} |
               {prefix + c.upper() for prefix in ("RISK_", "UNKNOWN_") for c in CATEGORIES})
    if (type(reasons) is not list or len(reasons) > 8 or
            any(type(r) is not str or r not in allowed for r in reasons) or
            result.get("synthetic_host_decision") not in
            {"HOST_UNKNOWN_SIMULATED", "HOST_DENIED_SIMULATED", "HOST_CATEGORICAL_CLEAN_SIMULATED"} or
            result.get("host_metadata_observed") is not False or
            result.get("n1b_qualified_pre_foreign") is not False or
            result.get("real_external_loaded_source") != "NOT_ATTESTED" or
            result.get("native_execution_authorized") is not False):
        raise ValueError("UNTRUSTED_RECEIPT_CONTENT")
    data = json.dumps(result, sort_keys=True, separators=(",", ":")).encode("ascii")
    if len(data) > MAX_OUTPUT_BYTES:
        raise ValueError("RECEIPT_OUTPUT_BUDGET")
    return data


def native_execution_decision(*_args: object, **_kwargs: object) -> None:
    raise ValueError("NATIVE_T1_NOT_AUTHORIZED")
