#!/usr/bin/env python3
"""PR101 P003: EXACT six P002 wheel payloads, SHA/RECORD source inspection ONLY.

Allowed only in disposable GitHub-hosted macOS ARM64 CI after exact-Head G05.
Never install, import, unzip to disk, execute or approve downloaded wheel code.
This is not dependency resolution, source security signoff or native T1.
"""
from __future__ import annotations

import argparse
import base64
import csv
from email.parser import Parser
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
from urllib import request
from urllib.parse import urlsplit
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.lbe_pipenv_p002_metadata import (
    MAX_METADATA_BYTES, MAX_WHEEL_BYTES, _load_regular_json, _normalize_name,
    inspect_metadata_dir, inspect_release, read_lock,
)

PROFILE = "PR101-PIPENV-P003-SIX-WHEEL-BYTES-SOURCE-ONLY-20261030"
MAX_MEMBERS = 16000
MAX_MEMBER_SIZE = 50000000
MAX_EXPANDED = 320000000
MAX_RECORD = 4000000
MAX_METADATA = 524288


class ByteQualificationError(ValueError):
    """Untrusted external source bytes are not qualified."""


class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ByteQualificationError("wheel HTTP redirect denied")


def _official_wheel_url(url: str, filename: str) -> None:
    try:
        u = urlsplit(url)
        if (u.scheme != "https" or u.netloc != "files.pythonhosted.org"
                or not u.path.startswith("/packages/")
                or not u.path.endswith("/" + filename)
                or "\\" in u.path or ".." in u.path
                or u.query or u.fragment or len(url) > 512):
            raise ByteQualificationError("wheel URL outside exact HTTPS origin")
    except (TypeError, ValueError) as exc:
        if isinstance(exc, ByteQualificationError):
            raise
        raise ByteQualificationError("invalid wheel URL") from exc


def _archive_name(name: str) -> str:
    if (not isinstance(name, str) or not name or name.startswith("/")
            or "\\" in name or "\x00" in name or "//" in name
            or name.endswith("//") or name.startswith("~")
            or any(ord(c) < 32 or ord(c) == 127 for c in name)):
        raise ByteQualificationError("unsafe wheel archive member name")
    parts = name.rstrip("/").split("/")
    if any(x in ("", ".", "..") for x in parts):
        raise ByteQualificationError("ambiguous wheel archive member path")
    return name.rstrip("/")


def _download_wheel(url: str, destination: Path, size: int,
                    expected_sha: str, opener=None) -> None:
    """One HTTPS response, no redirects/proxies, exact hash; never import."""
    _official_wheel_url(url, destination.name)
    if (type(size) is not int or not 0 < size <= MAX_WHEEL_BYTES or
            not isinstance(expected_sha, str) or
            re.fullmatch(r"[a-f0-9]{64}", expected_sha) is None or
            destination.exists() or destination.is_symlink()
            or not destination.parent.is_dir()
            or destination.parent.is_symlink()):
        raise ByteQualificationError("wheel download target or size invalid")
    if opener is None:
        opener = request.build_opener(request.ProxyHandler({}), NoRedirect())
    try:
        response = opener.open(
            request.Request(url, headers={"User-Agent": "mfg-p003-source-only/1"}),
            timeout=45,
        )
        with response:
            if response.geturl() != url or response.status != 200:
                raise ByteQualificationError("unexpected wheel response/redirect")
            fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), 0o600)
            digest = hashlib.sha256()
            count = 0
            with os.fdopen(fd, "wb") as output:
                while True:
                    data = response.read(1048576)
                    if not data:
                        break
                    count += len(data)
                    if count > size or count > MAX_WHEEL_BYTES:
                        raise ByteQualificationError("wheel HTTP response oversize")
                    output.write(data)
                    digest.update(data)
        if count != size or digest.hexdigest() != expected_sha:
            raise ByteQualificationError("wheel actual HTTP bytes SHA/size mismatch")
    except (OSError, request.URLError) as exc:
        raise ByteQualificationError("wheel source fetch failed") from exc


def _audit_wheel(path: Path, row: dict, expected_size: int) -> dict:
    """Verify on one pinned FD: downloaded SHA256 and every RECORD file byte."""
    try:
        st = path.lstat()
        if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or
                st.st_size != expected_size or
                not 0 < st.st_size <= MAX_WHEEL_BYTES):
            raise ByteQualificationError("wheel file type/size/links rejected")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW |
                     getattr(os, "O_CLOEXEC", 0))
        with os.fdopen(fd, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if (opened.st_ino, opened.st_dev, opened.st_size,
                    opened.st_mtime_ns) != (
                    st.st_ino, st.st_dev, st.st_size, st.st_mtime_ns):
                raise ByteQualificationError("wheel changed before opening")
            digest = hashlib.sha256()
            while True:
                chunk = stream.read(1048576)
                if not chunk:
                    break
                digest.update(chunk)
            if digest.hexdigest() != row["sha256"]:
                raise ByteQualificationError("wheel downloaded SHA256 mismatch")
            stream.seek(0)
            with zipfile.ZipFile(stream) as wheel:
                infos = wheel.infolist()
                if not 3 <= len(infos) <= MAX_MEMBERS:
                    raise ByteQualificationError("wheel member count exceeded")
                seen = set()
                folded = set()
                regular = set()
                expanded = 0
                for info in infos:
                    name = _archive_name(info.filename)
                    if name in seen or name.casefold() in folded:
                        raise ByteQualificationError("duplicate/casefold wheel member")
                    seen.add(name)
                    folded.add(name.casefold())
                    mode = (info.external_attr >> 16) & 0o170000
                    if mode not in (0, stat.S_IFREG, stat.S_IFDIR):
                        raise ByteQualificationError("unsafe wheel link/special member")
                    if info.compress_type not in (
                            zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                        raise ByteQualificationError("unapproved wheel compression")
                    if not 0 <= info.file_size <= MAX_MEMBER_SIZE:
                        raise ByteQualificationError("wheel member size exceeded")
                    expanded += info.file_size
                    if expanded > MAX_EXPANDED:
                        raise ByteQualificationError("wheel expanded limit exceeded")
                    if not info.is_dir():
                        regular.add(name)
                prefix = row["filename"].split("-")[0] + "-" + row["version"] + ".dist-info/"
                metadata_name = prefix + "METADATA"
                wheel_name = prefix + "WHEEL"
                record_name = prefix + "RECORD"
                if not {metadata_name, wheel_name, record_name} <= regular:
                    raise ByteQualificationError("wheel dist-info identity missing")
                if (wheel.getinfo(metadata_name).file_size > MAX_METADATA or
                        wheel.getinfo(wheel_name).file_size > MAX_METADATA or
                        wheel.getinfo(record_name).file_size > MAX_RECORD):
                    raise ByteQualificationError("wheel metadata/RECORD too large")
                meta = Parser().parsestr(
                    wheel.read(metadata_name).decode("utf-8", "strict"))
                spec = Parser().parsestr(
                    wheel.read(wheel_name).decode("utf-8", "strict"))
                if (_normalize_name(meta.get("Name", "")) != row["name"] or
                        meta.get("Version") != row["version"] or
                        not spec.get("Wheel-Version") or not spec.get_all("Tag")):
                    raise ByteQualificationError("wheel METADATA/WHEEL identity mismatch")
                entries = set()
                record = wheel.read(record_name).decode("utf-8", "strict")
                for fields in csv.reader(io.StringIO(record)):
                    if len(fields) != 3:
                        raise ByteQualificationError("invalid wheel RECORD tuple")
                    name, checksum, size = fields
                    name = _archive_name(name)
                    if name in entries or name not in regular:
                        raise ByteQualificationError("unexpected/duplicate RECORD entry")
                    entries.add(name)
                    if name == record_name:
                        if checksum or size:
                            raise ByteQualificationError("wheel RECORD self-hash unexpected")
                        continue
                    if not checksum.startswith("sha256=") or not size.isdecimal():
                        raise ByteQualificationError("wheel member hash missing")
                    content = wheel.read(name)
                    sha = base64.urlsafe_b64encode(
                        hashlib.sha256(content).digest()
                    ).rstrip(b"=").decode("ascii")
                    if checksum[7:] != sha or int(size) != len(content):
                        raise ByteQualificationError("wheel RECORD byte mismatch")
                if entries != regular:
                    raise ByteQualificationError("wheel RECORD missing file")
            after = os.fstat(stream.fileno())
            now = path.lstat()
            for cur in (after, now):
                if (cur.st_dev, cur.st_ino, cur.st_size, cur.st_mtime_ns) != (
                        opened.st_dev, opened.st_ino, opened.st_size,
                        opened.st_mtime_ns):
                    raise ByteQualificationError("wheel modified during inspection")
        return {
            "distribution": row["name"], "version": row["version"],
            "filename": row["filename"], "actual_sha256": digest.hexdigest(),
            "official_metadata_sha256": row["sha256"],
            "bytes_verified": True, "record_files_verified": len(regular),
            "archive_members_inspected": len(infos),
            "uncompressed_bytes_declared": expanded,
            "installed": False, "imported": False, "executed": False,
            "security_source_review": "NOT_ISSUED",
            "python313_recursive_closure": "NOT_QUALIFIED",
        }
    except (OSError, ValueError, UnicodeError, zipfile.BadZipFile,
            EOFError, RuntimeError) as exc:
        if isinstance(exc, ByteQualificationError):
            raise
        raise ByteQualificationError("wheel archive or RECORD inspection failed") from exc


def source_only_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", required=True, type=Path)
    parser.add_argument("--runner-temp", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        root = args.runner_temp
        if (not root.is_absolute() or not root.is_dir() or
                root.is_symlink() or root.resolve(strict=True) != root or
                os.environ.get("RUNNER_TEMP") != str(root)):
            raise ByteQualificationError("untrusted runner scratch")
        json_dir = root / "lbe-p003-release-json"
        wheel_dir = root / "lbe-p003-six-wheel-bytes"
        output = root / "lbe-p003-wheel-byte-evidence.json"
        if output.exists() or output.is_symlink():
            raise ByteQualificationError("source evidence cannot be overwritten")
        rows = read_lock(args.lock)
        checked = inspect_metadata_dir(args.lock, json_dir)
        if checked["candidate_release_count"] != 6:
            raise ByteQualificationError("exact candidate count changed")
        planned = []
        for row in rows:
            release = _load_regular_json(
                json_dir / (row["name"] + "-" + row["version"] + ".json"),
                MAX_METADATA_BYTES)
            inspected = inspect_release(row, release)
            wheels = [x for x in release["urls"]
                      if isinstance(x, dict) and
                      x.get("filename") == row["filename"] and
                      x.get("packagetype") == "bdist_wheel"]
            if len(wheels) != 1:
                raise ByteQualificationError("ambiguous candidate wheel")
            url = wheels[0]["url"]
            _official_wheel_url(url, row["filename"])
            planned.append((row, url, inspected["published_size"]))
        if wheel_dir.exists() or wheel_dir.is_symlink():
            raise ByteQualificationError("wheel scratch must not preexist")
        wheel_dir.mkdir(mode=0o700)
        results = []
        for row, url, size in planned:
            path = wheel_dir / row["filename"]
            _download_wheel(url, path, size, row["sha256"])
            results.append(_audit_wheel(path, row, size))
        if len(results) != 6:
            raise ByteQualificationError("incomplete wheel count")
        evidence = {
            "profile_id": PROFILE, "stage": "ACTUAL_WHEEL_BYTES_SHA256_RECORD_ONLY",
            "source_only_user_scope": "SIX_EXACT_P002_WHEELS_DOWNLOAD_INSPECT",
            "entries": results, "wheel_count": len(results),
            "installed_or_imported": False, "new_native_run": "NOT_RUN",
            "independent_security_review": "NOT_ISSUED",
            "recursive_compatible_dependency_closure": "NOT_QUALIFIED",
            "production_approval": False,
        }
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(evidence, stream, sort_keys=True, indent=2)
            stream.write("\n")
    except (OSError, ValueError) as exc:
        print("LBE_P003_SOURCE_BYTES=BLOCKED: " + str(exc), file=sys.stderr)
        return 2
    for row in results:
        print("LBE_P003_WHEEL_SHA256=" + row["distribution"] + ":" +
              row["actual_sha256"])
    print("LBE_P003_ACTUAL_BYTES_AND_RECORD=PASS count=6")
    print("LBE_P003_WHEEL_INSTALL_IMPORT_OR_EXEC=NOT_RUN")
    print("LBE_P003_RECURSIVE_CLOSURE=NOT_QUALIFIED")
    print("LBE_P003_B_C_SOURCE_REVIEW=NOT_ISSUED")
    return 0


if __name__ == "__main__":
    raise SystemExit(source_only_main())
