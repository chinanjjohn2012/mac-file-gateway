"""RC119 external-input qualification CANDIDATE; SAFE T0 only.

Never obtains dependencies, installs packages, imports selected binaries, launches
commands, probes the network/host, or returns native execution authorization.
Local selected bytes are checked only in a caller-provided disposable fixture
root; matching a caller-controlled hash is not independent provenance.
"""
from __future__ import annotations

import hashlib
import os
import re
import stat
from collections.abc import Mapping
from pathlib import Path

REPO = "chinanjjohn2012/mac-file-gateway"
RC_PR = 119
RC_HEAD = "33c30b6c2710cac0f8533370c1ca42f31ef6747a"
RC_TREE = "27e26c423e700cdbad0aeca27efcdf82594507c1"
PROFILE_B_BLOB = "1df5ccf9dbf920ff243e04d0e57f45a82e1b2a13"
SOURCE_CANDIDATE_ONLY = True
NATIVE_EXECUTION_AUTHORIZED = False
MAX_T0_FILE_BYTES = 16 * 1024 * 1024
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_COMPONENT = re.compile(r"[A-Za-z0-9_.-]+\Z")
REQUIRED_IDS = (
    "rc_product_checkout", "control_source_checkout", "checkout_action",
    "setup_python_action", "setup_go_action", "macos_image_claim",
    "cpython_binary", "cpython_stdlib", "pipenv_entrypoint",
    "pipenv_pipfile", "pipenv_lock", "pipenv_venv_python",
    "pipenv_venv_site", "runtime_wheelhouse", "installed_wheel_record_closure",
    "go_binary", "go_stdlib_modules", "go_module_fixture",
    "python_fixture", "generated_fixture_outputs", "import_source_precedence",
    "mcp_sdk_source",
)


class QualificationDenied(ValueError):
    """Invalid/unqualified claim; does not represent an executable denial gate."""


def _plain_int(v: object, *, minimum: int = 0, maximum: int = 2**63-1) -> bool:
    return type(v) is int and minimum <= v <= maximum


def _sha(v: object) -> bool:
    return type(v) is str and _SHA256.fullmatch(v) is not None


def inspect_input_template(obj: object) -> dict[str, object]:
    """Reconcile ALL 22 categories without accepting forged ATTESTED fields."""
    errors: list[str] = []
    if not isinstance(obj, Mapping):
        return _report(["NOT_OBJECT"], [])
    for key, expected in (("schema_version", 1),
                          ("kind", "RC119_T1_INPUT_IDENTITY_TEMPLATE_NONATTESTED"),
                          ("target_repo", REPO), ("target_pr", RC_PR),
                          ("target_head", RC_HEAD), ("target_tree", RC_TREE)):
        if type(obj.get(key)) is not type(expected) or obj.get(key) != expected:
            errors.append("IDENTITY_MISMATCH:" + key)
    rows = obj.get("inputs")
    if not isinstance(rows, list):
        return _report(errors + ["INPUTS_NOT_LIST"], [])
    seen: set[str] = set()
    for item in rows:
        if not isinstance(item, Mapping):
            errors.append("INPUT_NOT_MAPPING")
            continue
        name = item.get("id")
        if type(name) is not str or name not in REQUIRED_IDS:
            errors.append("UNKNOWN_ID")
            continue
        if name in seen:
            errors.append("DUPLICATE_ID:" + name)
        seen.add(name)
        # An asserted digest/origin/evidence is never enough to qualify a real
        # selected importer or child. Reject unreviewed optimistic grades.
        if item.get("evidence_status") != "NOT_ATTESTED":
            errors.append("UNTRUSTED_EVIDENCE_GRADE:" + name)
        for k in ("origin_uri", "source_version", "expected_size_bytes",
                  "expected_sha256", "observed_sha256", "fetched_bytes_location",
                  "verified_import_location", "independent_evidence_uri"):
            if item.get(k) is not None:
                errors.append("CLAIMED_EXTERNAL_INPUT_NOT_INDEPENDENT:" + name)
                break
    if seen != set(REQUIRED_IDS):
        errors.append("REQUIRED_ID_SET_MISMATCH")
    for key, expected in (("owner_native_test_permission", "NOT_GRANTED"),
                          ("replay_consumption", "NOT_IMPLEMENTED")):
        if obj.get(key) != expected:
            errors.append("UNTRUSTED_AUTHORIZATION_FIELD:" + key)
    return _report(errors, sorted(seen))


def _report(errors: list[str], seen: list[str]) -> dict[str, object]:
    return {"valid_nonattested_template": not errors,
            "errors": errors, "observed_categories": seen,
            "missing_categories": sorted(set(REQUIRED_IDS) - set(seen)),
            "native_execution_authorized": False,
            "selected_sources_attested": False,
            "source_grade": "NOT_ATTESTED"}


def _parts(path: str) -> list[str]:
    if type(path) is not str or not path or path.startswith("/") or "\\" in path:
        raise QualificationDenied("INVALID_RELATIVE_PATH")
    parts = path.split("/")
    if any((p in ("", ".", "..") or not _COMPONENT.fullmatch(p)) for p in parts):
        raise QualificationDenied("PATH_TRAVERSAL_OR_NONCANONICAL")
    return parts


def read_disposable_fixture(root: Path, relative_path: str,
                            expected_digest: str, expected_size: int,
                            max_bytes: int = MAX_T0_FILE_BYTES) -> dict[str, object]:
    """Read ONLY an existing regular private T0 fixture, no symlink following.

    Directory walk is fd-relative with O_DIRECTORY/O_NOFOLLOW where supported.
    This is neither a future macOS host/loader seal nor independent attestation.
    """
    parts = _parts(relative_path)
    if not _plain_int(max_bytes, minimum=1, maximum=MAX_T0_FILE_BYTES):
        raise QualificationDenied("BAD_BYTE_BUDGET")
    if not _sha(expected_digest) or not _plain_int(expected_size, maximum=max_bytes):
        raise QualificationDenied("BAD_EXPECTED_IDENTITY")
    # Fail closed if the underlying OS cannot provide no-follow/fd-relative
    # primitives; never silently downgrade to Path.read_bytes().
    if not all(hasattr(os, x) for x in ("O_NOFOLLOW", "O_DIRECTORY", "O_CLOEXEC")):
        raise QualificationDenied("NO_SAFE_DIRECTORY_OPEN_PRIMITIVES")
    dir_fd = None
    try:
        dir_fd = os.open(str(root), os.O_RDONLY | os.O_DIRECTORY |
                         os.O_NOFOLLOW | os.O_CLOEXEC)
        if not stat.S_ISDIR(os.fstat(dir_fd).st_mode):
            raise QualificationDenied("ROOT_NOT_DIRECTORY")
        for piece in parts[:-1]:
            next_fd = os.open(piece, os.O_RDONLY | os.O_DIRECTORY |
                              os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dir_fd)
            os.close(dir_fd)
            dir_fd = next_fd
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW |
                     os.O_CLOEXEC | getattr(os, "O_NONBLOCK", 0), dir_fd=dir_fd)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise QualificationDenied("NOT_SINGLE_LINK_REGULAR_FILE")
            if before.st_size != expected_size or before.st_size > max_bytes:
                raise QualificationDenied("FILE_SIZE_MISMATCH")
            h = hashlib.sha256()
            count = 0
            while True:
                chunk = os.read(fd, min(64 * 1024, max_bytes + 1 - count))
                if not chunk:
                    break
                count += len(chunk)
                if count > max_bytes:
                    raise QualificationDenied("FILE_BUDGET_OVERFLOW")
                h.update(chunk)
            after = os.fstat(fd)
            if (before.st_dev, before.st_ino, before.st_mtime_ns,
                before.st_ctime_ns, before.st_size) != (
                after.st_dev, after.st_ino, after.st_mtime_ns,
                after.st_ctime_ns, after.st_size):
                raise QualificationDenied("FILE_DRIFT_DURING_READ")
            if count != expected_size or h.hexdigest() != expected_digest:
                raise QualificationDenied("FILE_BYTES_MISMATCH")
        finally:
            os.close(fd)
    except (OSError, OverflowError) as exc:
        raise QualificationDenied("LOCAL_FIXTURE_READ_DENIED") from exc
    finally:
        if dir_fd is not None:
            os.close(dir_fd)
    return {"file_path": relative_path, "size_bytes": count,
            "observed_sha256": h.hexdigest(),
            "grade": "LOCAL_T0_DUMMY_BYTES_MATCHED_ONLY",
            "selected_source_provenance": "NOT_ATTESTED",
            "native_execution_authorized": False}


def classify_claimed_runtime_source(prelaunch_match: bool,
                                   observed_extra_helper: bool,
                                   complete_runtime_witness: bool) -> str:
    """Conservative Profile B source grade, no SOURCE_CLOSED native PASS."""
    if any(type(v) is not bool for v in (
            prelaunch_match, observed_extra_helper, complete_runtime_witness)):
        raise QualificationDenied("INVALID_GRADE_INPUT")
    if observed_extra_helper:
        return "DYNAMIC_FOREIGN_SOURCE_OBSERVED_BLOCKED"
    if not prelaunch_match:
        return "PRELAUNCH_INPUTS_NOT_ATTESTED"
    # The standalone local checker never possesses a separately independently
    # reviewed runtime witness; even a caller's True claim is not proof.
    return "RUNTIME_DYNAMIC_EXECUTION_NOT_ATTESTED"


def native_execution_decision(*_args: object, **_kwargs: object) -> None:
    raise QualificationDenied("NATIVE_T1_NOT_AUTHORIZED")
