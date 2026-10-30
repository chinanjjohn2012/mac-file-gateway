#!/usr/bin/env python3
"""P002 official PyPI RELEASE METADATA comparison, not a wheel downloader.

Only the six already enumerated third-party candidate release JSON files
are read, *after* repository G05 admission. This tool never imports a
candidate package, downloads any wheel, installs a dependency or approves
execution. A matching metadata hash is NOT a hash of actual wheel bytes.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import stat
import sys
from urllib.parse import urlsplit

PROPOSAL_ID = "PR101-PIPENV-T1-P002-METADATA-ONLY-CANDIDATE"
STATUS = "PUBLIC_PYPI_METADATA_CANDIDATES_ONLY_NO_ARTIFACT_DOWNLOAD_NO_INSTALL_NO_EXECUTION"
EXPECTED = {
    "distlib": ("0.4.4", "distlib-0.4.4-py2.py3-none-any.whl"),
    "filelock": ("4.2.4", "filelock-4.2.4-py3-none-any.whl"),
    "platformdirs": ("4.11.10", "platformdirs-4.11.10-py3-none-any.whl"),
    "python-discovery": ("1.6.1", "python_discovery-1.6.1-py3-none-any.whl"),
    "setuptools": ("84.2.1", "setuptools-84.2.1-py3-none-any.whl"),
    "virtualenv": ("21.15.0", "virtualenv-21.15.0-py3-none-any.whl"),
}
MAX_METADATA_BYTES = 4000000
MAX_WHEEL_BYTES = 12000000


class SourceMetadataError(ValueError):
    """Source-only qualification is insufficient. Fail closed."""


def _unique_pairs(items: list[tuple[str, object]]) -> dict[str, object]:
    out = {}
    for key, value in items:
        if key in out:
            raise SourceMetadataError("duplicate JSON key")
        out[key] = value
    return out


def _normalize_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def _load_regular_json(path: Path, limit: int) -> dict:
    """No-follow bounded local JSON; no code execution or dynamic import."""
    try:
        st = path.lstat()
        if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1
                or st.st_size < 2 or st.st_size > limit):
            raise SourceMetadataError("metadata path/type/size rejected")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW |
                     getattr(os, "O_CLOEXEC", 0))
        try:
            before = os.fstat(fd)
            if (before.st_ino, before.st_dev, before.st_size) != (
                    st.st_ino, st.st_dev, st.st_size):
                raise SourceMetadataError("metadata file identity changed")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                raw = stream.read(limit + 1)
            after = os.fstat(fd)
            if (len(raw) != before.st_size or
                    (before.st_ino, before.st_dev, before.st_size,
                     before.st_mtime_ns) !=
                    (after.st_ino, after.st_dev, after.st_size,
                     after.st_mtime_ns)):
                raise SourceMetadataError("metadata changed during read")
        finally:
            os.close(fd)
        parsed = json.loads(raw.decode("utf-8", "strict"),
                            object_pairs_hook=_unique_pairs)
        if not isinstance(parsed, dict):
            raise SourceMetadataError("metadata root must be an object")
        return parsed
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SourceMetadataError("metadata input unreadable") from exc


def read_lock(path: Path) -> list[dict[str, str]]:
    data = _load_regular_json(path, 20000)
    if data.get("proposal_id") != PROPOSAL_ID or data.get("status") != STATUS:
        raise SourceMetadataError("wrong candidate proposal/status")
    if data.get("existing_36_wheel_lock_reuse") != [
            "certifi==2026.10.23", "packaging==26.3"]:
        raise SourceMetadataError("existing original wheel assumptions changed")
    rows = data.get("additional_wheels")
    if not isinstance(rows, list) or len(rows) != len(EXPECTED):
        raise SourceMetadataError("unexpected candidate count")
    if [row.get("name") for row in rows if isinstance(row, dict)] != sorted(EXPECTED):
        raise SourceMetadataError("candidate set/order/normalization changed")
    for row in rows:
        if not isinstance(row, dict) or set(row) != {
                "name", "version", "filename", "sha256", "publication_provenance"}:
            raise SourceMetadataError("candidate record fields invalid")
        name = row["name"]
        if (not isinstance(name, str) or name not in EXPECTED or
                (row["version"], row["filename"]) != EXPECTED[name] or
                not isinstance(row["sha256"], str) or
                re.fullmatch(r"[0-9a-f]{64}", row["sha256"]) is None):
            raise SourceMetadataError("candidate identity/hash changed")
        if row["publication_provenance"] not in (
                "NOT_PRESENT_IN_PYPI_UI",
                "PYPI_PUBLISH_ATTESTATION_SHOWN_NOT_INDEPENDENTLY_VERIFIED"):
            raise SourceMetadataError("candidate provenance status invalid")
    return rows


def inspect_release(entry: dict[str, str], data: dict) -> dict:
    """Compare official declared wheel digest to a frozen *candidate*."""
    name, version, filename, expected_sha = (
        entry["name"], entry["version"], entry["filename"], entry["sha256"])
    info = data.get("info")
    files = data.get("urls")
    if not isinstance(info, dict) or not isinstance(files, list):
        raise SourceMetadataError("PyPI release shape invalid")
    if (_normalize_name(str(info.get("name", ""))) != name or
            info.get("version") != version or
            info.get("yanked") is True):
        raise SourceMetadataError("PyPI distribution identity mismatch")
    candidates = [
        x for x in files if isinstance(x, dict)
        and x.get("filename") == filename and
        x.get("packagetype") == "bdist_wheel"
    ]
    if len(candidates) != 1:
        raise SourceMetadataError("no unique matching wheel in release metadata")
    wheel = candidates[0]
    digest = wheel.get("digests")
    if (not isinstance(digest, dict) or
            digest.get("sha256") != expected_sha):
        raise SourceMetadataError("PyPI wheel digest != frozen candidate")
    size = wheel.get("size")
    if (type(size) is not int or not (0 < size <= MAX_WHEEL_BYTES) or
            wheel.get("yanked") is not False):
        raise SourceMetadataError("wheel size/yanked status invalid")
    raw_url = wheel.get("url")
    if not isinstance(raw_url, str) or len(raw_url) > 512:
        raise SourceMetadataError("wheel URL absent")
    try:
        u = urlsplit(raw_url)
        if (u.scheme != "https" or u.hostname != "files.pythonhosted.org"
                or u.username or u.password or u.port is not None
                or u.query or u.fragment or
                not u.path.startswith("/packages/") or
                not u.path.endswith("/" + filename) or
                ".." in u.path or "\\" in u.path):
            raise SourceMetadataError("wheel URL not official HTTPS identity")
    except SourceMetadataError:
        raise
    except ValueError as exc:
        raise SourceMetadataError("malformed official wheel URL") from exc
    reqs = info.get("requires_dist")
    if reqs is None:
        reqs = []
    if (not isinstance(reqs, list) or len(reqs) > 512 or
            any(not isinstance(x, str) or len(x) > 512 or
                any(ord(ch) < 32 or ord(ch) > 126 for ch in x)
                for x in reqs)):
        raise SourceMetadataError("unsafe/unbounded Requires-Dist metadata")
    requires_python = info.get("requires_python")
    if (not isinstance(requires_python, str) or
            not 0 < len(requires_python) < 128):
        raise SourceMetadataError("requires_python metadata absent")
    return {
        "distribution": name, "version": version, "filename": filename,
        "published_wheel_sha256_metadata": expected_sha, "published_size": size,
        "requires_python_raw": requires_python,
        "requires_dist_raw": sorted(reqs),
        "wheel_url_origin": "https://files.pythonhosted.org",
        "metadata_comparison": "MATCHED_FROZEN_CANDIDATE",
        "actual_wheel_bytes_verified": False,
        "wheel_installed_or_imported": False,
        "python313_marker_closure": "NOT_EVALUATED",
        "publication_provenance": entry["publication_provenance"],
    }


def inspect_metadata_dir(lock: Path, source_dir: Path) -> dict:
    rows = read_lock(lock)
    if (not source_dir.is_dir() or source_dir.is_symlink()
            or not source_dir.is_absolute()):
        raise SourceMetadataError("metadata directory unsafe")
    expected_files = {
        f"{row['name']}-{row['version']}.json" for row in rows
    }
    if {entry.name for entry in source_dir.iterdir()} != expected_files:
        raise SourceMetadataError("missing/extra release metadata JSON files")
    verified = []
    for row in rows:
        path = source_dir / f"{row['name']}-{row['version']}.json"
        verified.append(inspect_release(row, _load_regular_json(
            path, MAX_METADATA_BYTES)))
    return {
        "proposal_id": PROPOSAL_ID,
        "status": "PYPI_DECLARED_METADATA_MATCHED_CANDIDATE_ONLY",
        "entries": verified,
        "candidate_release_count": len(verified),
        "new_third_party_wheel_bytes_downloaded": False,
        "new_third_party_wheels_installed_or_imported": False,
        "pipenv_recursive_closure_qualified": False,
        "Go_or_Pipenv_native_T1": "NOT_RUN",
        "independent_BC_source_review": "NOT_ISSUED",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--metadata-dir", type=Path, required=True)
    parser.add_argument("--runner-temp", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        root = args.runner_temp
        if (not root.is_absolute() or not root.is_dir() or root.is_symlink()
                or os.environ.get("RUNNER_TEMP") != str(root)
                or root.resolve(strict=True) != root):
            raise SourceMetadataError("runner scratch identity mismatch")
        if (args.metadata_dir.parent != root or
                args.metadata_dir.is_symlink()):
            raise SourceMetadataError("metadata not directly under runner scratch")
        out = root / "lbe-p002-public-pypi-metadata-only.json"
        if out.exists() or out.is_symlink():
            raise SourceMetadataError("metadata evidence cannot be overwritten")
        report = inspect_metadata_dir(args.lock, args.metadata_dir)
        fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fp:
            json.dump(report, fp, sort_keys=True, indent=2)
            fp.write("\n")
    except (OSError, ValueError) as exc:
        print("LBE_P002_PUBLIC_METADATA=BLOCKED: " + str(exc),
              file=sys.stderr)
        return 2
    print("LBE_P002_OFFICIAL_PYPI_METADATA_CANDIDATES_MATCHED=6")
    print("LBE_P002_NEW_WHEEL_BYTES=NOT_DOWNLOADED")
    print("LBE_P002_FULL_TRANSITIVE_CLOSURE=NOT_QUALIFIED")
    print("LBE_P002_GO_PIPENV_NATIVE=NOT_RUN")
    print("LBE_P002_B_C_SOURCE_REVIEW=NOT_ISSUED")
    for row in report["entries"]:
        for req in row["requires_dist_raw"]:
            print("LBE_P002_RAW_REQUIRES_DIST=" + row["distribution"] + ": " + req)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
