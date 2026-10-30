#!/usr/bin/env python3
"""P001 source-byte/metadata qualification ONLY. Never import or run Go/Pipenv.

Call after exact-Head G05 on a disposable github-hosted macOS runner.
The admitted files come from the two owner-approved metadata candidates.
A verified artifact is NOT a verified toolchain, executable installation,
Pipenv dependency closure, or permission to run native commands.
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
import stat
import sys
import tarfile
import zipfile

GO_NAME = "go1.27.3.darwin-arm64.tar.gz"
GO_SHA256 = "dd3908cf20959d798c1e06ebe5b72213f0505ce01373b40ce3110975a6cd99c2"
GO_SIZE = 68196737
PIPENV_NAME = "pipenv-2026.10.4-py3-none-any.whl"
PIPENV_SHA256 = "308125623e4d08dfe32936f7259a9ed33c5480baa2c9a291a1ff8a9328eeeb1f"
MAX_GO_SIZE = 70000000
MAX_WHEEL_SIZE = 6000000
MAX_GO_MEMBERS = 60000
MAX_GO_EXPANDED = 1500000000
MAX_WHEEL_MEMBERS = 12000
MAX_WHEEL_EXPANDED = 300000000
GO_REQUIRED = frozenset((
    "go/VERSION", "go/bin/go", "go/pkg/tool/darwin_arm64/compile",
    "go/src/runtime/proc.go",
))


class QualificationError(ValueError):
    """An input is not qualified. Must fail before installation/execution."""


def verified_file(path: Path, expected_digest: str, expected_size: int,
                  max_size: int) -> int:
    """No-follow open; compare file inode/stat before and after SHA256."""
    try:
        first = path.lstat()
        if (not stat.S_ISREG(first.st_mode) or first.st_nlink != 1
                or first.st_size > max_size or first.st_size != expected_size):
            raise QualificationError("input size/type/link count invalid")
        if not hasattr(os, "O_NOFOLLOW"):
            raise QualificationError("O_NOFOLLOW unavailable")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
        try:
            opened = os.fstat(fd)
            same = lambda a, b: (
                a.st_dev, a.st_ino, a.st_size, a.st_mtime_ns
            ) == (
                b.st_dev, b.st_ino, b.st_size, b.st_mtime_ns
            )
            if not same(first, opened):
                raise QualificationError("input changed before open")
            digest = hashlib.sha256()
            total = 0
            while True:
                part = os.read(fd, 1048576)
                if not part:
                    break
                total += len(part)
                if total > max_size:
                    raise QualificationError("input exceeds source limit")
                digest.update(part)
            if not same(opened, os.fstat(fd)) or not same(opened, path.lstat()):
                raise QualificationError("input changed during read")
        finally:
            os.close(fd)
        if total != expected_size or digest.hexdigest() != expected_digest:
            raise QualificationError("downloaded input SHA256/size mismatch")
        return total
    except (OSError, ValueError) as exc:
        if isinstance(exc, QualificationError):
            raise
        raise QualificationError("input file could not be safely read") from exc


def safe_member_name(name: str) -> str:
    """Strict POSIX archive name; reject traversal and ambiguity pre-extract."""
    value = name.rstrip("/")
    if (not value or name.startswith("/") or "\\" in name
            or "\x00" in name or any(
                part in ("", ".", "..") for part in value.split("/")
            ) or value.startswith("~")):
        raise QualificationError("unsafe archive member path")
    return value


def inspect_go_archive(path: Path, expected_digest: str = GO_SHA256,
                       expected_size: int = GO_SIZE) -> dict[str, object]:
    verified_file(path, expected_digest, expected_size, MAX_GO_SIZE)
    seen: set[str] = set()
    expanded = 0
    count = 0
    try:
        with tarfile.open(path, mode="r:gz") as archive:
            for member in archive:
                count += 1
                if count > MAX_GO_MEMBERS:
                    raise QualificationError("Go archive member cap exceeded")
                name = safe_member_name(member.name)
                if name != "go" and not name.startswith("go/"):
                    raise QualificationError("Go archive escapes go/ prefix")
                if name in seen:
                    raise QualificationError("duplicate Go archive member")
                seen.add(name)
                if not (member.isfile() or member.isdir()):
                    raise QualificationError("unsafe Go symlink/hardlink/special member")
                if member.mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX):
                    raise QualificationError("unsafe Go archive mode")
                if member.size < 0 or member.size > 100000000:
                    raise QualificationError("oversize Go member")
                expanded += member.size
                if expanded > MAX_GO_EXPANDED:
                    raise QualificationError("Go expanded size cap exceeded")
    except (tarfile.TarError, EOFError, OSError, ValueError) as exc:
        if isinstance(exc, QualificationError):
            raise
        raise QualificationError("Go archive cannot be parsed safely") from exc
    if not GO_REQUIRED.issubset(seen):
        raise QualificationError("Go compiler/stdlib marker files missing")
    return {"status": "ARCHIVE_BYTES_VERIFIED_MEMBERS_INSPECTED",
            "archive_sha256": expected_digest, "archive_size": expected_size,
            "members": count, "declared_expanded_bytes": expanded,
            "toolchain_installed": False, "go_executed": False}


def inspect_pipenv_wheel(path: Path, expected_digest: str = PIPENV_SHA256,
                         expected_size: int | None = None) -> dict[str, object]:
    if expected_size is None:
        expected_size = path.lstat().st_size
    verified_file(path, expected_digest, expected_size, MAX_WHEEL_SIZE)
    prefix = "pipenv-2026.10.4.dist-info/"
    metadata_path = prefix + "METADATA"
    record_path = prefix + "RECORD"
    try:
        with zipfile.ZipFile(path) as wheel:
            infos = wheel.infolist()
            if len(infos) > MAX_WHEEL_MEMBERS:
                raise QualificationError("wheel member cap exceeded")
            members: set[str] = set()
            expanded = 0
            for info in infos:
                name = safe_member_name(info.filename)
                if name in members:
                    raise QualificationError("duplicate wheel member")
                members.add(name)
                if (not name.startswith(("pipenv/", prefix,
                        "pipenv-2026.10.4.data/"))):
                    raise QualificationError("wheel contains unrelated input tree")
                mode = (info.external_attr >> 16) & 0o170000
                if mode not in (0, stat.S_IFREG, stat.S_IFDIR):
                    raise QualificationError("unsafe wheel member type")
                if (info.file_size < 0 or info.file_size > 50000000
                        or info.compress_type not in (zipfile.ZIP_STORED,
                                                      zipfile.ZIP_DEFLATED)):
                    raise QualificationError("unsafe wheel member size/compression")
                expanded += info.file_size
                if expanded > MAX_WHEEL_EXPANDED:
                    raise QualificationError("wheel expanded size cap exceeded")
            if metadata_path not in members or record_path not in members:
                raise QualificationError("wheel METADATA/RECORD missing")
            meta = wheel.read(metadata_path)
            if len(meta) > 262144:
                raise QualificationError("oversize wheel METADATA")
            message = Parser().parsestr(meta.decode("utf-8", "strict"))
            if (message.get("Name", "").lower() != "pipenv"
                    or message.get("Version") != "2026.10.4"):
                raise QualificationError("wrong wheel package/version")
            requirements = message.get_all("Requires-Dist", [])
            record = wheel.read(record_path)
            if len(record) > 5000000:
                raise QualificationError("oversize wheel RECORD")
            records: set[str] = set()
            for row in csv.reader(io.StringIO(record.decode("utf-8", "strict"))):
                if len(row) != 3:
                    raise QualificationError("invalid wheel RECORD tuple")
                filename, digest, filesize = row
                filename = safe_member_name(filename)
                if filename in records or filename not in members:
                    raise QualificationError("duplicate/unknown wheel RECORD member")
                records.add(filename)
                if filename == record_path and not digest and not filesize:
                    continue
                if not digest.startswith("sha256=") or not filesize.isdecimal():
                    raise QualificationError("unhashed wheel member")
                data = wheel.read(filename)
                expected = base64.urlsafe_b64encode(
                    hashlib.sha256(data).digest()).rstrip(b"=").decode("ascii")
                if (digest[7:] != expected or int(filesize) != len(data)):
                    raise QualificationError("wheel RECORD byte mismatch")
            if records != {
                info.filename for info in infos if not info.is_dir()
            }:
                raise QualificationError("wheel RECORD does not cover all files")
    except (zipfile.BadZipFile, OSError, UnicodeError, ValueError) as exc:
        if isinstance(exc, QualificationError):
            raise
        raise QualificationError("wheel archive cannot be safely parsed") from exc
    return {"status": "WHEEL_BYTES_AND_RECORD_VERIFIED",
            "wheel_sha256": expected_digest, "wheel_size": expected_size,
            "members": len(members), "requires_dist": sorted(requirements),
            "pipenv_installed": False, "dependency_closure_locked": False,
            "pipenv_executed": False}


def qualification_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runner-temp", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        root = args.runner_temp
        if (not root.is_absolute() or root.is_symlink()
                or not root.is_dir() or root.resolve(strict=True) != root):
            raise QualificationError("untrusted RUNNER_TEMP")
        if os.environ.get("RUNNER_TEMP") != str(root):
            raise QualificationError("RUNNER_TEMP environment mismatch")
        go = root / GO_NAME
        pip = root / PIPENV_NAME
        report = root / "lbe-p001-source-evidence.json"
        if report.exists() or report.is_symlink():
            raise QualificationError("qualification report cannot be overwritten")
        checked_go = inspect_go_archive(go)
        checked_pip = inspect_pipenv_wheel(pip)
        payload = {
            "proposal_id": "PR101-LBE-T1-TOOLCHAINS-P001",
            "qualification": "DOWNLOADED_BYTES_AND_ARCHIVE_INSPECTION_ONLY",
            "go": checked_go,
            "pipenv": checked_pip,
            "transitive_pipenv_wheels": "NOT_SOURCE_LOCKED",
            "go_extracted_compiler_stdlib_modules": "NOT_ATTESTED",
            "real_go_pipenv_native": "NOT_RUN",
            "full_source_review": "NOT_ISSUED",
        }
        fd = os.open(report, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, sort_keys=True, indent=2)
            stream.write("\n")
    except (OSError, ValueError) as exc:
        print("LBE_P001_SOURCE_QUALIFICATION=BLOCKED: " + str(exc),
              file=sys.stderr)
        return 2
    print("LBE_P001_GO_ARCHIVE_BYTES=SHA256_VERIFIED_AND_INSPECTED")
    print("LBE_P001_PIPENV_WHEEL_BYTES=SHA256_RECORD_VERIFIED")
    print("LBE_P001_PIPENV_DEPENDENCY_CLOSURE=NOT_SOURCE_LOCKED")
    print("LBE_P001_GO_COMPILER_RUNTIME=NOT_EXECUTED_NOT_ATTESTED")
    print("LBE_P001_GO_PIPENV_T1=NOT_RUN")
    return 0


if __name__ == "__main__":
    raise SystemExit(qualification_main())
