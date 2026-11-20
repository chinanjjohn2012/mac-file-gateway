"""Offline PR101 source-archive evidence to RC119 qualification bridge.

Data-only SHA256 of ten *compressed* original archives in one fixed external
Artifact. Never extracts, imports, installs, or executes untrusted content.
A matching archive is not the installed/imported/loaded source of RC119 T1.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
import zipfile
from pathlib import Path

PR101_HEAD = "ec25c34492912f3a82175fa9c1060e0632814687"
PR101_TREE = "3a127bf341a0363b9fa77a570d88436a6fd48696"
RC119_HEAD = "33c30b6c2710cac0f8533370c1ca42f31ef6747a"
ARTIFACT_ID = 14545306271
ARTIFACT_SIZE = 81608549
ARTIFACT_SHA256 = "1e949b334398f51d9f5eadae716e3107877c61deff2654d9ad6c5052b741a67f"
RAW_PREFIX = "pr101-r015-review-raw-ten/"
PROVENANCE = RAW_PREFIX + "source-byte-provenance.json"
ARCHIVES = {
    "go1.27.3.darwin-arm64.tar.gz": (68196737, "dd3908cf20959d798c1e06ebe5b72213f0505ce01373b40ce3110975a6cd99c2"),
    "pipenv-2026.10.4-py3-none-any.whl": (2636779, "308125623e4d08dfe32936f7259a9ed33c5480baa2c9a291a1ff8a9328eeeb1f"),
    "certifi-2026.10.23-py3-none-any.whl": (135082, "e9b54de76e530bb6cf0ccd036787103acb58fd42ba930ea8bf948ddbaa2f61d1"),
    "packaging-26.3-py3-none-any.whl": (129956, "d7193f7c8e4e93f444fde0262bf90af30e16fa0ad0ad44cb553c87339b23cd1c"),
    "distlib-0.4.4-py2.py3-none-any.whl": (472099, "cf09d55b1e85a89576b036aeb71550bfd68320f3f21761ca329eadadad918638"),
    "filelock-4.2.4-py3-none-any.whl": (162475, "301241438c57936ef93f4243a94f2559022268bfcf9b375a9a72eb0f8db8358e"),
    "platformdirs-4.11.10-py3-none-any.whl": (24763, "973c4c082b964958c71588448488d2b14fb253893dfbdb82325a14c84e540e8f"),
    "python_discovery-1.6.1-py3-none-any.whl": (38664, "d43fcdef879fe795352bd13ccf8d185ba5a9f86f36cfcd00529f596e737442b3"),
    "setuptools-84.2.1-py3-none-any.whl": (876263, "ca140b45d5325a9478f880e351484f62fef15f336462e449ca0c03c873d589c2"),
    "virtualenv-21.15.0-py3-none-any.whl": (5558480, "013eb9c340466186ac8923ce920ae05becfa1390fdf3565b7eae0d191a2f4a2e"),
}
PROOF_FILES = frozenset({
    PROVENANCE,
    "pr101-r015-9-wheel-member-inventory.json",
    "lbe-p001-source-evidence.json", "lbe-p001-go-stage-evidence.json",
    "lbe-p007-go-source-report.json", "lbe-p003-wheel-byte-evidence.json",
})
ALL_MEMBERS = frozenset(RAW_PREFIX + name for name in ARCHIVES) | PROOF_FILES
NATIVE_EXECUTION_AUTHORIZED = False


class SourceBridgeDenied(ValueError):
    """A safe fixed-code refusal, never includes untrusted content."""


def _hash_stream(reader, max_size: int) -> tuple[int, str]:
    sha = hashlib.sha256()
    count = 0
    while True:
        buf = reader.read(min(65536, max_size + 1 - count))
        if not buf:
            break
        count += len(buf)
        if count > max_size:
            raise SourceBridgeDenied("STREAM_BUDGET_EXCEEDED")
        sha.update(buf)
    return count, sha.hexdigest()


def _member_identity_check(infos: list[zipfile.ZipInfo], *, expected: frozenset[str],
                           max_member: int) -> dict[str, zipfile.ZipInfo]:
    if len(infos) != len(expected) or len(infos) > 20:
        raise SourceBridgeDenied("MEMBER_COUNT_OR_SET_CHANGED")
    seen: dict[str, zipfile.ZipInfo] = {}
    for entry in infos:
        # Enforce exact names BEFORE using ZIP member paths; no extraction.
        if (entry.filename not in expected or entry.filename in seen or
                entry.filename.startswith("/") or ".." in entry.filename.split("/") or
                "\\" in entry.filename or entry.is_dir()):
            raise SourceBridgeDenied("UNAPPROVED_ARCHIVE_MEMBER")
        mode = entry.external_attr >> 16
        if (entry.flag_bits & 1 or entry.compress_type != zipfile.ZIP_STORED or
                (mode and not stat.S_ISREG(mode)) or entry.file_size > max_member or
                entry.file_size <= 0 or entry.compress_size != entry.file_size):
            raise SourceBridgeDenied("ARCHIVE_MEMBER_TYPE_OR_BUDGET")
        seen[entry.filename] = entry
    if set(seen) != expected:
        raise SourceBridgeDenied("MEMBER_COUNT_OR_SET_CHANGED")
    return seen


def _verify_entries(zf: zipfile.ZipFile, pins: dict[str, tuple[int, str]],
                    *, prefix: str, allowed_proofs: frozenset[str]) -> dict[str, dict[str, object]]:
    names = frozenset(prefix + x for x in pins) | allowed_proofs
    seen = _member_identity_check(zf.infolist(), expected=names,
                                  max_member=100 * 1024 * 1024)
    result = {}
    for filename, (expected_bytes, expected_sha) in sorted(pins.items()):
        entry = seen[prefix + filename]
        if entry.file_size != expected_bytes:
            raise SourceBridgeDenied("ARCHIVE_BYTE_LENGTH_DRIFT")
        with zf.open(entry, "r") as f:
            size, digest = _hash_stream(f, expected_bytes)
        if size != expected_bytes or digest != expected_sha:
            raise SourceBridgeDenied("ARCHIVE_SHA256_DRIFT")
        result[filename] = {"bytes": size, "sha256": digest}
    return result


def audit_fixture_zip(data: bytes, pins: dict[str, tuple[int, str]],
                      *, prefix: str = "test/", proof_names: frozenset[str] = frozenset()) -> dict:
    """Tiny inert synthetic ZIP oracle; NEVER produces actual provenance PASS."""
    import io
    if type(data) is not bytes or len(data) > 2_000_000 or type(pins) is not dict:
        raise SourceBridgeDenied("NOT_A_BOUNDED_T0_FIXTURE")
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            records = _verify_entries(z, pins, prefix=prefix, allowed_proofs=proof_names)
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile, RuntimeError, EOFError) as exc:
        raise SourceBridgeDenied("BAD_TEST_ZIP") from None
    return {"fixture_count": len(records), "evidence_grade": "SYNTHETIC_SAFE_T0_ONLY",
            "native_execution_authorized": False}


def audit_original_archive_bundle(path: Path) -> dict:
    """Validate exact GitHub Artifact; no extracted archive, imports or installer."""
    if not isinstance(path, Path) or path.is_symlink():
        raise SourceBridgeDenied("INVALID_LOCAL_ARTIFACT_PATH")
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size != ARTIFACT_SIZE:
            raise SourceBridgeDenied("WRONG_ARTIFACT_TYPE_OR_SIZE")
        if not hasattr(os, "O_NOFOLLOW"):
            raise SourceBridgeDenied("NO_SAFE_FILE_OPEN")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            opened = os.fstat(fd)
            if (opened.st_dev, opened.st_ino, opened.st_size) != (before.st_dev, before.st_ino, before.st_size):
                raise SourceBridgeDenied("SOURCE_FILE_RACE")
            with os.fdopen(fd, "rb", closefd=False) as f:
                size, digest = _hash_stream(f, ARTIFACT_SIZE)
                if size != ARTIFACT_SIZE or digest != ARTIFACT_SHA256:
                    raise SourceBridgeDenied("OUTER_ARTIFACT_SHA256_DRIFT")
                f.seek(0)
                with zipfile.ZipFile(f) as z:
                    archives = _verify_entries(z, ARCHIVES, prefix=RAW_PREFIX, allowed_proofs=PROOF_FILES)
                    proof_info = z.getinfo(PROVENANCE)
                    if proof_info.file_size > 8192:
                        raise SourceBridgeDenied("PROVENANCE_RECORD_TOO_LARGE")
                    obj = json.loads(z.read(PROVENANCE))
                    if (type(obj) is not dict or obj.get("pr") != 101 or
                            obj.get("head") != PR101_HEAD or obj.get("head_tree") != PR101_TREE or
                            obj.get("review_round") != "r015" or obj.get("exact_count") != 10 or
                            obj.get("go_native_T1") != "NOT_RUN" or
                            obj.get("pipenv_native_T1") != "NOT_RUN" or
                            obj.get("raw_archives") != archives):
                        raise SourceBridgeDenied("HISTORICAL_PROVENANCE_MISMATCH")
            after = os.fstat(fd)
            if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns,
                opened.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size,
                after.st_mtime_ns, after.st_ctime_ns):
                raise SourceBridgeDenied("SOURCE_FILE_DRIFT")
        finally:
            os.close(fd)
    except SourceBridgeDenied:
        raise
    except (OSError, ValueError, OverflowError, zipfile.BadZipFile,
            zipfile.LargeZipFile, RuntimeError, EOFError, KeyError, TypeError) as exc:
        # No raw local path/JSON/content in exception string or logs.
        raise SourceBridgeDenied("SOURCE_ARTIFACT_UNREADABLE_OR_MALFORMED") from None
    return {
        "archive_artifact_id": ARTIFACT_ID,
        "artifact_sha256": ARTIFACT_SHA256,
        "actual_archives_verified": len(ARCHIVES),
        "source_bundle_head": PR101_HEAD,
        "candidate_product_head": RC119_HEAD,
        "verified_archive_names": sorted(ARCHIVES),
        "source_grade": "TEN_ORIGINAL_COMPRESSED_ARCHIVES_VERIFIED_ONLY",
        "installed_or_loaded_source": "NOT_ATTESTED",
        "current_22_runtime_input_categories": "NOT_ATTESTED",
        "independent_b_c_security_signoff": "NOT_ISSUED",
        "native_execution_authorized": False,
        "integration_status": "NOT_TESTED",
    }


def native_execution_decision(*_args, **_kwargs):
    raise SourceBridgeDenied("NATIVE_T1_NOT_AUTHORIZED")
