"""PR113 one-time T1 CONTROL-PREPARATION ONLY: fail-closed, pure T0 utilities.

This module is not a native runner, workflow trigger, authorization verifier or
network sandbox. It must never launch Python/Go/Pipenv project commands.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
from typing import Callable, Mapping, NoReturn
from unittest.mock import patch

REPO = "chinanjjohn2012/mac-file-gateway"
PR = 113
BASE_SHA = "ec25c34492912f3a82175fa9c1060e0632814687"
HEAD_SHA = "fc94cc36ce793e32a3fb97d5a500a47608be6781"
HEAD_TREE = "fa51d2a7a881f8e4915badcfe0fb088f2fca0ee3"
DESIGN_BLOB = "d90df6de3bdbd81a314109d5f73959799b5a10a6"
CONTROLLER_REVISION = "PR113-T1-CONTROL-T0-001"
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")

SIX_COMMANDS = (
    ("S1", "py-direct", "direct", ("python", "-m", "pytest", "-q")),
    ("S2", "py-direct", "direct", ("python", "-m", "compileall", "-q", "./src")),
    ("S3", "py-pipenv", "pipenv", ("pipenv", "run", "python", "-m", "pytest", "-q")),
    ("S4", "go-project", "direct", ("go", "test", "./...")),
    ("S5", "go-project", "direct", ("go", "vet", "./...")),
    ("S6", "go-project", "direct", ("go", "build", "-o", "bin/app", "./cmd/app")),
)
TRANSPORTS = ("Direct", "REST", "MCP_SERVER_JSON_RPC")


class GateDenied(ValueError):
    """An unsafe or unqualified condition was rejected before execution."""


class UnsafeSpawnAttempt(GateDenied):
    """A negative-only T0 callback attempted to reach Popen."""


def _exact_string(value: object, expected: str, field: str) -> None:
    if type(value) is not str or value != expected:
        raise GateDenied(f"{field}: exact value required")


def _exact_int(value: object, expected: int, field: str) -> None:
    if type(value) is not int or value != expected:
        raise GateDenied(f"{field}: exact integer required")


def _only_keys(value: object, expected: frozenset[str], field: str) -> Mapping[str, object]:
    if type(value) is not dict or frozenset(value) != expected:
        raise GateDenied(f"{field}: exact key set required")
    return value


def check_product_identity(data: object) -> None:
    """T0 shape/identity check; does NOT grant execution authority."""
    keys = frozenset(("repository", "pr", "base_sha", "head_sha", "head_tree", "design_blob"))
    x = _only_keys(data, keys, "product")
    _exact_string(x["repository"], REPO, "repository")
    _exact_int(x["pr"], PR, "pr")
    for field, expected in (("base_sha", BASE_SHA), ("head_sha", HEAD_SHA),
                            ("head_tree", HEAD_TREE), ("design_blob", DESIGN_BLOB)):
        _exact_string(x[field], expected, field)


def exact_product_identity() -> dict[str, object]:
    return dict(repository=REPO, pr=PR, base_sha=BASE_SHA,
                head_sha=HEAD_SHA, head_tree=HEAD_TREE, design_blob=DESIGN_BLOB)


def check_event_shape(data: object, *, approved_run_id: int, control_sha: str,
                      expected_phase: str) -> None:
    """Untrusted event-claim shape only: Owner authentication is NOT implemented."""
    keys = frozenset(("repository", "pr", "head_sha", "head_tree", "actor",
                      "event_name", "run_id", "run_attempt", "control_sha", "phase"))
    x = _only_keys(data, keys, "event")
    if type(approved_run_id) is not int or approved_run_id <= 0:
        raise GateDenied("approved run id is unavailable")
    if type(control_sha) is not str or not re.fullmatch(r"[0-9a-f]{40}", control_sha):
        raise GateDenied("approved control commit is unavailable")
    if expected_phase not in ("six", "mixed"):
        raise GateDenied("unrecognized phase")
    _exact_string(x["repository"], REPO, "repository")
    _exact_int(x["pr"], PR, "pr")
    _exact_string(x["head_sha"], HEAD_SHA, "head_sha")
    _exact_string(x["head_tree"], HEAD_TREE, "head_tree")
    _exact_string(x["actor"], "chinanjjohn2012", "actor")
    _exact_string(x["event_name"], "workflow_dispatch", "event_name")
    _exact_int(x["run_id"], approved_run_id, "run_id")
    _exact_int(x["run_attempt"], 1, "run_attempt")
    _exact_string(x["control_sha"], control_sha, "control_sha")
    _exact_string(x["phase"], expected_phase, "phase")


def check_phase_order(phase: object, *, previous: object) -> None:
    """Checks proposed TWO-JOB chronology without creating a Job."""
    if phase == "six" and previous is None:
        return
    if phase == "mixed" and previous == "six_pass":
        return
    raise GateDenied("duplicate, skipped, or unsuccessful phase")


def check_deadline(*, elapsed_seconds: float, request_timeout_seconds: float,
                   total_seconds: float = 1200.0, reserve_seconds: float = 180.0) -> None:
    """Conservative future admission arithmetic: no process control."""
    vals = (elapsed_seconds, request_timeout_seconds, total_seconds, reserve_seconds)
    if any(type(x) not in (int, float) or not math.isfinite(x) for x in vals):
        raise GateDenied("non-finite or wrong-type deadline")
    if elapsed_seconds < 0 or request_timeout_seconds <= 0 or total_seconds <= 0 or reserve_seconds < 0:
        raise GateDenied("invalid deadline")
    if request_timeout_seconds > 120 or total_seconds > 1200 or reserve_seconds < 180:
        raise GateDenied("outside proposed bounded T1 profile")
    if elapsed_seconds + request_timeout_seconds + reserve_seconds >= total_seconds:
        raise GateDenied("insufficient hard job reserve before Popen")


def _no_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise GateDenied("duplicate JSON key")
        result[key] = value
    return result


def load_lock_json(path: Path) -> dict[str, object]:
    """Read inert UTF-8 JSON, with no imports of product or foreign packages."""
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 65536:
        raise GateDenied("unsafe lock manifest file")
    try:
        obj = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_no_duplicate_json_keys)
    except (UnicodeError, OSError, ValueError) as exc:
        raise GateDenied("malformed lock manifest") from exc
    if type(obj) is not dict:
        raise GateDenied("lock manifest must be object")
    return obj


def check_lock_metadata(lock: object) -> tuple[str, ...]:
    """Return PENDING fields: NEVER turns a data file into an Owner grant."""
    keys = frozenset(("schema", "target", "status", "network_profile", "owner_t1_authorized",
                      "control_commit", "control_tree", "owner_authorization_proof",
                      "inputs", "notes"))
    x = _only_keys(lock, keys, "lock")
    _exact_int(x["schema"], 1, "schema")
    check_product_identity(x["target"])
    if type(x["inputs"]) is not list or len(x["inputs"]) > 128:
        raise GateDenied("invalid input list")
    pending = []
    for i, raw in enumerate(x["inputs"]):
        ent = _only_keys(raw, frozenset(("name", "kind", "source_uri", "expected_size_bytes",
                                         "expected_sha256", "installed_record_sha256",
                                         "historical_observed_sha256", "status")), "input")
        if any(type(ent[k]) is not str or not ent[k] for k in ("name", "kind", "status")):
            raise GateDenied(f"malformed input identity {i}")
        if ent["status"] not in ("PENDING", "HISTORICAL_REFERENCE", "VERIFIED_NEW_INPUT"):
            raise GateDenied("unknown input status")
        for field in ("expected_sha256", "installed_record_sha256", "historical_observed_sha256"):
            value = ent[field]
            if value is not None and (type(value) is not str or not _HEX64.fullmatch(value)):
                raise GateDenied(f"bad {field} in input {i}")
        size = ent["expected_size_bytes"]
        if size is not None and (type(size) is not int or size < 0):
            raise GateDenied("bad input size")
        uri = ent["source_uri"]
        if uri is not None and (type(uri) is not str or not uri.startswith("https://")):
            raise GateDenied("unqualified URI")
        if ent["status"] == "VERIFIED_NEW_INPUT":
            if not ent["expected_sha256"] or size is None or not uri:
                raise GateDenied("verified input missing mandatory identity")
        else:
            pending.append(ent["name"])
    if type(x["notes"]) is not str:
        raise GateDenied("notes must be text")
    for field in ("control_commit", "control_tree", "owner_authorization_proof"):
        if x[field] is None:
            pending.append(field)
        elif type(x[field]) is not str:
            raise GateDenied(f"{field}: malformed claim")
    if x["network_profile"] == "UNDECIDED":
        pending.append("network_profile")
    elif x["network_profile"] not in ("OFFLINE_ONLY", "BOUNDED_TRUSTED_LOCAL"):
        raise GateDenied("unexpected network profile")
    if type(x["owner_t1_authorized"]) is not bool:
        raise GateDenied("owner_t1_authorized must be bool")
    if not x["owner_t1_authorized"]:
        pending.append("owner_t1_authorized")
    if x["status"] != "INCOMPLETE":
        # No pre-approved future status transition exists in this T0 module.
        raise GateDenied("lock status cannot confer execution permission")
    return tuple(pending)


def verify_temp_file_digest(path: Path, expected_sha256: str, temp_root: Path) -> bool:
    """Read only an existing normal file under a symlink-free temp root."""
    if type(expected_sha256) is not str or not _HEX64.fullmatch(expected_sha256):
        raise GateDenied("invalid digest")
    root = temp_root.absolute()
    child = path.absolute()
    if root.is_symlink() or child == root or root not in child.parents:
        raise GateDenied("outside disposable root")
    current = root
    for part in child.relative_to(root).parts:
        current = current / part
        if current.is_symlink():
            raise GateDenied("symlink in path")
    try:
        st = child.lstat()
        if not stat.S_ISREG(st.st_mode):
            raise GateDenied("not a regular file")
        digest = hashlib.sha256(child.read_bytes()).hexdigest()
    except OSError as exc:
        raise GateDenied("unreadable file") from exc
    return digest == expected_sha256


@dataclass(frozen=True)
class NegativeT0Observation:
    result_code: str
    attempted_popen: int
    control_kind: str = "negative_t0_only"


def probe_denied_argv_t0(call: Callable[[], str]) -> NegativeT0Observation:
    """Mock Popen in a negative-only process; NEVER run a real child here.

    Tests only this product's reviewed subprocess.Popen call path and cannot
    prove general OS process containment. No physical Git actions permitted
    inside the callback while patch is active.
    """
    attempts: list[object] = []

    def intercept(*args: object, **kwargs: object) -> NoReturn:
        attempts.append((args, kwargs))
        raise UnsafeSpawnAttempt("an unapproved subprocess.Popen was intercepted")

    with patch.object(subprocess, "Popen", side_effect=intercept):
        try:
            outcome = call()
        except UnsafeSpawnAttempt as exc:
            raise GateDenied("unauthorized launch reached Popen") from exc
    if attempts:
        raise GateDenied("one or more unauthorized Popen attempts")
    if outcome != "command_not_allowed":
        raise GateDenied("illegal argv was not rejected")
    return NegativeT0Observation(result_code=outcome, attempted_popen=0)


def consume_local_once_t0(directory: Path, run_id: int, phase: str) -> Path:
    """Local exclusive-create T0 demonstration, NOT cross-run/global authority.

    Must run only in a new private disposable temp directory. An actual
    GitHub two-job test needs a separately approved durable shared gate.
    """
    if type(run_id) is not int or run_id <= 0 or phase not in ("six", "mixed"):
        raise GateDenied("invalid one-use T0 claim")
    if directory.is_symlink() or not directory.is_dir():
        raise GateDenied("unsafe local T0 ledger")
    st = directory.stat()
    if st.st_uid != os.getuid() or st.st_mode & 0o077:
        raise GateDenied("ledger must be private to current user")
    path = directory / f"run-{run_id}-{phase}.one-use"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags, 0o600)
        with os.fdopen(fd, "w", encoding="ascii") as out:
            out.write(f"T0-only {run_id}:{phase}\n")
    except FileExistsError as exc:
        raise GateDenied("duplicate local phase T0 claim") from exc
    except OSError as exc:
        raise GateDenied("unable to record T0-only claim") from exc
    return path


def native_execution_decision(lock: object) -> NoReturn:
    """Unconditionally deny native T1; there is NO subprocess or exec API."""
    check_lock_metadata(lock)
    raise GateDenied("PR113 native T1 is NOT AUTHORIZED; network, input and Owner gates unresolved")


if __name__ == "__main__":
    print("PR113_T1_CONTROL_STATUS=NONOPERATIVE_T0_ONLY_NATIVE_T1_NOT_AUTHORIZED")
    raise SystemExit(2)
