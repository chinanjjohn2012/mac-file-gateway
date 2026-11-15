"""PR113 T1: safe offline *claims* inspector, never an execution authority.

All records, including apparently matching GitHub job/Owner data, are untrusted
input here. This module has no network, GitHub client, process launcher, package
installer, external-command adapter or code path that returns an ALLOW token.
"""
from __future__ import annotations

import hmac
import hashlib
import base64
import csv
import io
import stat
import zipfile
from pathlib import Path, PurePosixPath
import re
from typing import Mapping, NoReturn

from tools.pr113_t1_control_t0 import GateDenied, check_product_identity
from tools.pr113_t1_qualification_t0 import (
    COMMANDS, NETWORK_DESIGN_BLOB, PROFILE_B, REQUIRED_INPUT_CLASSES,
    TRANSPORTS, canonical_vector, check_command_vector, digest_existing_regular,
)

REPO = "chinanjjohn2012/mac-file-gateway"
PRODUCT_PR = 113
PRODUCT_HEAD = "fc94cc36ce793e32a3fb97d5a500a47608be6781"
PRODUCT_TREE = "fa51d2a7a881f8e4915badcfe0fb088f2fca0ee3"
OWNER_LOGIN = "chinanjjohn2012"
REVIEW_ROUND = "PR113-T1-NETWORK-DESIGN-002"
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
WORKFLOW_PATH = ".github/workflows/pr113-one-shot-native-t1-explicit-approval.yml"

# Values are not inspected here; passing names DOES NOT prove absent secrets.
CHILD_ENV_KEYS = frozenset((
    "PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "CI", "PYTHONDONTWRITEBYTECODE",
    "GOCACHE", "GOMODCACHE", "GOPROXY", "GOSUMDB", "GO111MODULE", "GOWORK",
    "PIP_NO_INDEX", "PIPENV_PIPFILE", "PIPENV_VENV_IN_PROJECT",
    "PIPENV_DONT_LOAD_ENV", "PIPENV_IGNORE_VIRTUALENVS", "PIPENV_SKIP_LOCK",
))
MANDATORY_CHILD_ENV_KEYS = frozenset(("PATH", "HOME", "TMPDIR"))


def _exact_record(raw: object, keys: frozenset[str], label: str) -> Mapping[str, object]:
    if type(raw) is not dict or frozenset(raw) != keys:
        raise GateDenied(f"{label}: exact keys required")
    return raw


def _sha(raw: object, size: int, label: str) -> str:
    if type(raw) is not str or not (HEX40 if size == 40 else HEX64).fullmatch(raw):
        raise GateDenied(f"{label}: lowercase immutable hex required")
    return raw


def _posint(raw: object, label: str) -> int:
    if type(raw) is not int or raw <= 0:
        raise GateDenied(f"{label}: strictly positive integer required")
    return raw


def inspect_untrusted_run_claim_t0(raw: object, *, expected_control_head: str,
                                   expected_control_tree: str, expected_lock_sha256: str,
                                   expected_run_id: int, expected_job_id: int,
                                   expected_phase: str) -> dict[str, object]:
    """Check fixed equality; caller-supplied expected fields are NOT authenticated.

    Even exact shape cannot verify an Owner's original consent, GitHub API
    origin, replay consumption, runner's actual source or network/secret scope.
    """
    fields = frozenset(("repository", "pr", "product_head", "product_tree",
                        "control_head", "control_tree", "network_design_blob",
                        "network_profile", "review_round", "workflow_path",
                        "event", "actor", "run_id", "run_attempt", "job_id",
                        "phase", "input_lock_sha256"))
    claim = _exact_record(raw, fields, "claimed GitHub run")
    head = _sha(expected_control_head, 40, "expected control HEAD")
    tree = _sha(expected_control_tree, 40, "expected control TREE")
    lock = _sha(expected_lock_sha256, 64, "expected input lock")
    run_id = _posint(expected_run_id, "expected run ID")
    job_id = _posint(expected_job_id, "expected job ID")
    if expected_phase not in ("six", "mixed"):
        raise GateDenied("unknown phase")
    exact = {
        "repository": REPO, "pr": PRODUCT_PR, "product_head": PRODUCT_HEAD,
        "product_tree": PRODUCT_TREE, "control_head": head, "control_tree": tree,
        "network_design_blob": NETWORK_DESIGN_BLOB, "network_profile": PROFILE_B,
        "review_round": REVIEW_ROUND, "workflow_path": WORKFLOW_PATH,
        "event": "workflow_dispatch", "actor": OWNER_LOGIN, "run_id": run_id,
        "run_attempt": 1, "job_id": job_id, "phase": expected_phase,
        "input_lock_sha256": lock,
    }
    for name, required in exact.items():
        if type(claim[name]) is not type(required) or claim[name] != required:
            raise GateDenied(f"run claim drift: {name}")
    return {
        "claim_shape": "MATCHED_UNTRUSTED_T0_ONLY", "owner_authenticated": False,
        "github_origin_authenticated": False, "one_shot_consumed": False,
        "native_execution_authorized": False,
    }


def inspect_two_job_transcript_t0(raw: object, *, run_id: int,
                                   expected_control_head: str) -> dict[str, object]:
    """Check complete ordered six->mixed trace shape, not global replay safety."""
    wanted = (("six", "STARTED"), ("six", "PASS"),
              ("mixed", "STARTED"), ("mixed", "PASS"))
    rid = _posint(run_id, "run ID")
    head = _sha(expected_control_head, 40, "control HEAD")
    if type(raw) is not list or len(raw) != 4:
        raise GateDenied("exact four history stages required")
    jobs: dict[str, int] = {}
    receipts_seen = set()
    for i, (entry, (phase, state)) in enumerate(zip(raw, wanted)):
        obj = _exact_record(entry, frozenset(("phase", "status", "run_id", "run_attempt",
                                              "job_id", "control_head", "receipt_sha256")), "history")
        if type(obj["phase"]) is not str or obj["phase"] != phase:
            raise GateDenied(f"history phase drift at stage {i}")
        if type(obj["status"]) is not str or obj["status"] != state:
            raise GateDenied(f"history status/order drift at stage {i}")
        if type(obj["run_id"]) is not int or obj["run_id"] != rid:
            raise GateDenied("history run identity drift")
        if type(obj["run_attempt"]) is not int or obj["run_attempt"] != 1:
            raise GateDenied("history attempt/replay drift")
        j = _posint(obj["job_id"], "job ID")
        if type(obj["control_head"]) is not str or obj["control_head"] != head:
            raise GateDenied("history source HEAD drift")
        rsha = _sha(obj["receipt_sha256"], 64, "receipt SHA256")
        if rsha in receipts_seen:
            raise GateDenied("reused phase receipt claim")
        receipts_seen.add(rsha)
        if phase in jobs and jobs[phase] != j:
            raise GateDenied("two jobs for a single phase")
        jobs[phase] = j
    if jobs["six"] == jobs["mixed"]:
        raise GateDenied("two separately witnessed jobs required")
    return {
        "chronology": "SHAPE_MATCH_ONLY", "distinct_jobs": 2,
        "receipts_authenticated": False, "globally_consumed": False,
        "replay_proof": "NOT_ATTESTED", "native_execution_authorized": False,
    }


def inspect_minimal_child_env_names_t0(raw: object) -> dict[str, object]:
    """Fail on unapproved selectors by NAME; don't read real host env or values."""
    if type(raw) is not list or not 3 <= len(raw) <= len(CHILD_ENV_KEYS):
        raise GateDenied("invalid proposed child environment key list")
    if any(type(k) is not str or not k or k not in CHILD_ENV_KEYS for k in raw):
        raise GateDenied("unexpected inherited/selector environment key")
    if len(set(raw)) != len(raw) or not MANDATORY_CHILD_ENV_KEYS.issubset(raw):
        raise GateDenied("duplicate key or missing minimal child identity keys")
    return {
        "environment_key_shape": "CLOSED_LIST_T0_ONLY", "observed_key_count": len(raw),
        "environment_values_qualified": False,
        "accessible_secret_files_absent_proven": False,
        "runner_metadata_credentials_absent_proven": False,
        "native_execution_authorized": False,
    }


def inspect_private_bytes_t0(root: Path, claims: object) -> tuple[dict[str, object], ...]:
    """Observe pre-existing bytes; matching caller-supplied hashes is not authority.

    Never fetch/install/execute bytes. The caller MUST subsequently acquire
    independent trusted source/input provenance; none is checked here.
    """
    if type(claims) is not list or not 1 <= len(claims) <= len(REQUIRED_INPUT_CLASSES):
        raise GateDenied("invalid byte-claim batch")
    if not isinstance(root, Path) or not root.is_absolute():
        raise GateDenied("private existing absolute root required")
    seen = set()
    result = []
    for claim in claims:
        obj = _exact_record(claim, frozenset(("input_class", "relative_path", "expected_sha256",
                                              "expected_size_bytes", "expected_git_blob")), "byte receipt")
        name = obj["input_class"]
        if type(name) is not str or name not in REQUIRED_INPUT_CLASSES or name in seen:
            raise GateDenied("invalid or duplicate input class")
        seen.add(name)
        rel = obj["relative_path"]
        if type(rel) is not str or not rel or len(rel) > 512 or "\\" in rel:
            raise GateDenied("invalid file-relative path")
        p = PurePosixPath(rel)
        if p.is_absolute() or any(s in ("", ".", "..") for s in rel.split("/")):
            raise GateDenied("unsafe relative path")
        expected = _sha(obj["expected_sha256"], 64, "file SHA256")
        bsha = obj["expected_git_blob"]
        if bsha is not None:
            _sha(bsha, 40, "Git blob")
        size = obj["expected_size_bytes"]
        if type(size) is not int or not 0 <= size <= 100_000_000:
            raise GateDenied("file size out of bounded range")
        actual, length = digest_existing_regular(root / rel, root)
        if length != size or not hmac.compare_digest(actual, expected):
            raise GateDenied("existing input bytes mismatch")
        # Never reopen a verified path: that would reintroduce a TOCTOU race.
        # A separate, source-reviewed same-FD Git-blob verifier is needed before
        # treating expected_git_blob as proven. Refuse this stronger claim here.
        if bsha is not None:
            raise GateDenied("Git blob object provenance is NOT_ATTESTED by this SHA256-only T0 verifier")
        result.append({
            "input_class": name, "bytes_observed": length,
            "status": "BYTES_MATCH_UNAUTHENTICATED_T0_ONLY",
            "source_provenance_qualified": False,
            "loaded_runtime_identity_attested": False,
            "native_execution_authorized": False,
        })
    return tuple(result)


def check_prod_claim_t0(product: object) -> None:
    """Verify exact PR113 product data only; does not read remote GitHub."""
    check_product_identity(product)


def native_execution_decision(*_args: object, **_kwargs: object) -> NoReturn:
    """Unconditional deny: no Owner authority adapter or foreign code call."""
    raise GateDenied("PR113 native T1 is NOT AUTHORIZED: no authenticated cross-run grant")


def inspect_wheel_record_bytes_t0(archive: object) -> dict[str, object]:
    """Check complete zip member vs RECORD hashes IN MEMORY without install/import.

    The supplied archive bytes and declared package identity remain untrusted;
    this is a strict T0 RECORD self-consistency check, not evidence that the
    runner selected/loaded these bytes, or that all dependency wheels are known.
    """
    if type(archive) is not bytes or not 0 < len(archive) <= 10_000_000:
        raise GateDenied("bounded wheel archive bytes required")
    try:
        with zipfile.ZipFile(io.BytesIO(archive), mode="r") as wheel:
            infos = wheel.infolist()
            if not 2 <= len(infos) <= 512:
                raise GateDenied("wheel member count outside T0 budget")
            names = set()
            folded = set()
            files = {}
            total_uncompressed = 0
            for info in infos:
                name = info.filename
                if (not name or len(name) > 500 or "\\" in name or "\x00" in name or
                    "\n" in name or ":" in name or name.startswith("/") or
                    any(p in ("", ".", "..") for p in name.rstrip("/").split("/"))):
                    raise GateDenied("unsafe wheel archive name")
                if name in names or name.casefold() in folded:
                    raise GateDenied("duplicate or case-shadowing wheel member")
                names.add(name)
                folded.add(name.casefold())
                unix_mode = info.external_attr >> 16
                if stat.S_IFMT(unix_mode) not in (0, stat.S_IFREG, stat.S_IFDIR):
                    raise GateDenied("wheel nonregular member is not qualified")
                if info.flag_bits & 0x1:
                    raise GateDenied("encrypted member disallowed")
                if not info.is_dir():
                    if info.file_size > 8_000_000 or info.compress_size > 10_000_000:
                        raise GateDenied("wheel member size outside T0 budget")
                    if info.file_size > 0 and info.file_size > max(info.compress_size, 1) * 1000:
                        raise GateDenied("wheel decompression ratio outside T0 budget")
                    files[name] = info
                    total_uncompressed += info.file_size
                if total_uncompressed > 32_000_000:
                    raise GateDenied("wheel uncompressed budget exceeded")
            record_paths = [n for n in files if n.endswith(".dist-info/RECORD")]
            wheel_paths = [n for n in files if n.endswith(".dist-info/WHEEL")]
            if len(record_paths) != 1 or len(wheel_paths) != 1:
                raise GateDenied("one RECORD and WHEEL metadata required")
            record_path = record_paths[0]
            if record_path.rsplit("/",1)[0] != wheel_paths[0].rsplit("/",1)[0]:
                raise GateDenied("wheel metadata directories disagree")
            if files[record_path].file_size > 256_000:
                raise GateDenied("RECORD is too large")
            body = wheel.read(record_path).decode("utf-8", "strict")
            rows = list(csv.reader(io.StringIO(body)))
            if len(rows) != len(files):
                raise GateDenied("RECORD does not list every file exactly once")
            covered = set()
            for row in rows:
                if len(row) != 3:
                    raise GateDenied("invalid RECORD row")
                path, hash_field, size_field = row
                if path not in files or path in covered:
                    raise GateDenied("RECORD unknown or duplicate file")
                covered.add(path)
                if path == record_path:
                    if hash_field != "" or size_field != "":
                        raise GateDenied("self-referential RECORD digest forbidden")
                    continue
                if not hash_field.startswith("sha256=") or not size_field.isascii() or not size_field.isdecimal():
                    raise GateDenied("RECORD must use explicit sha256 and size")
                encoded = hash_field.split("=", 1)[1]
                if not re.fullmatch(r"[A-Za-z0-9_-]{43}", encoded):
                    raise GateDenied("noncanonical RECORD SHA256")
                try:
                    digest_bytes = base64.urlsafe_b64decode(encoded + "=")
                except (ValueError, base64.binascii.Error) as exc:
                    raise GateDenied("invalid RECORD base64url") from exc
                if len(digest_bytes) != 32 or str(files[path].file_size) != size_field:
                    raise GateDenied("wheel file size/digest shape mismatch")
                running = hashlib.sha256()
                count = 0
                with wheel.open(files[path], mode="r") as member:
                    while True:
                        chunk = member.read(131072)
                        if not chunk:
                            break
                        count += len(chunk)
                        if count > files[path].file_size or count > 8_000_000:
                            raise GateDenied("wheel member exceeded declared size")
                        running.update(chunk)
                if count != files[path].file_size or not hmac.compare_digest(running.digest(), digest_bytes):
                    raise GateDenied("RECORD content digest mismatch")
            if covered != set(files):
                raise GateDenied("wheel contains undeclared loaded file")
    except (zipfile.BadZipFile, UnicodeError, RuntimeError, EOFError, OSError) as exc:
        raise GateDenied("unqualified wheel archive") from exc
    return {
        "record_self_consistency": "PASS_T0_ONLY", "declared_files_verified": len(files)-1,
        "wheel_acquisition_provenance_verified": False,
        "dependency_closure_qualified": False, "installed_record_verified": False,
        "actual_loaded_source_proven": False, "native_execution_authorized": False,
    }
