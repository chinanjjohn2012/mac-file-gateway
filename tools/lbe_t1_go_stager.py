#!/usr/bin/env python3
"""P001 Go archive -> nonexecutable runner-temp byte attestation only.

NEVER execute or install the Go binary/compiler. The caller must already
have run exact-Head G05 and verified the official compressed Go SHA256.
This module verifies again, rejects unsafe archive types and names, copies
only one-link regular bytes into an exclusively created temporary tree with
NO executable file bits, then hashes every staged file. This is not a
toolchain source review, runtime permission, or native positive T1 result.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tarfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.lbe_t1_source_qualifier import (
    GO_NAME, GO_SHA256, GO_SIZE, GO_REQUIRED, MAX_GO_EXPANDED,
    MAX_GO_MEMBERS, QualificationError, inspect_go_archive,
    safe_member_name, verified_file,
)

MAX_FILE_BYTES = 100000000
READ_CHUNK = 1048576


def _safe_parents(root: Path, relative: Path) -> Path:
    """Create/read directories without traversing any symlink, owner-only."""
    directory = root
    for part in relative.parts:
        if part in ("", ".", ".."):
            raise QualificationError("invalid stage directory component")
        directory = directory / part
        try:
            directory.mkdir(mode=0o700)
        except FileExistsError:
            pass
        st = directory.lstat()
        if not stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode):
            raise QualificationError("stage path is not a real directory")
    return directory


def stage_nonexecutable_go(archive_path: Path, destination: Path, *,
                           expected_digest: str = GO_SHA256,
                           expected_size: int = GO_SIZE) -> dict[str, object]:
    """Exact archive bytes -> immutable-mode stage manifest, no tool execution."""
    inspected = inspect_go_archive(
        archive_path, expected_digest=expected_digest,
        expected_size=expected_size)
    if (not destination.is_absolute() or not destination.parent.is_dir()
            or destination.parent.is_symlink()
            or destination.exists() or destination.is_symlink()):
        raise QualificationError("stage target is not an unused real directory")
    destination.mkdir(mode=0o700)
    seen: set[str] = set()
    casefold: set[str] = set()
    manifest: list[str] = []
    total = 0
    count = 0
    try:
        with tarfile.open(archive_path, "r:gz") as source:
            for member in source:
                name = safe_member_name(member.name)
                if name != "go" and not name.startswith("go/"):
                    raise QualificationError("Go staging path not rooted at go/")
                if name in seen or name.casefold() in casefold:
                    raise QualificationError("duplicate/case-conflicting Go member")
                seen.add(name)
                casefold.add(name.casefold())
                count += 1
                if count > MAX_GO_MEMBERS:
                    raise QualificationError("Go stage member cap exceeded")
                if not (member.isdir() or member.isfile()):
                    raise QualificationError("Go stage symlink/hardlink/special rejected")
                if member.mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX):
                    raise QualificationError("Go stage forbidden permission bits")
                if member.isdir():
                    _safe_parents(destination, Path(name))
                    continue
                if member.size < 0 or member.size > MAX_FILE_BYTES:
                    raise QualificationError("Go stage file cap exceeded")
                total += member.size
                if total > MAX_GO_EXPANDED:
                    raise QualificationError("Go stage expanded byte cap exceeded")
                parent = _safe_parents(destination, Path(name).parent)
                output = parent / Path(name).name
                fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                             os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), 0o600)
                digest = hashlib.sha256()
                copied = 0
                try:
                    data = source.extractfile(member)
                    if data is None:
                        raise QualificationError("Go member file unreadable")
                    with data:
                        with os.fdopen(fd, "wb", closefd=False) as stream:
                            while copied < member.size:
                                part = data.read(min(READ_CHUNK,
                                                     member.size - copied))
                                if not part:
                                    raise QualificationError("Go member truncated")
                                stream.write(part)
                                digest.update(part)
                                copied += len(part)
                    if copied != member.size:
                        raise QualificationError("Go member byte count mismatch")
                finally:
                    os.close(fd)
                st = output.lstat()
                if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1
                        or st.st_size != member.size
                        or stat.S_IMODE(st.st_mode) & 0o111):
                    raise QualificationError("Go stage mode/type/size changed")
                manifest.append(digest.hexdigest() + "  ./" + name)
    except (OSError, ValueError, tarfile.TarError) as exc:
        if isinstance(exc, QualificationError):
            raise
        raise QualificationError("Go nonexecuting stage failed") from exc
    if not GO_REQUIRED.issubset(seen):
        raise QualificationError("staged Go toolchain marker files missing")
    verified_file(archive_path, expected_digest, expected_size, 70000000)
    manifest.sort()
    digest = hashlib.sha256(("\n".join(manifest) + "\n").encode("utf-8"))
    return {
        "status": "BYTES_STAGED_NONEXECUTABLE",
        "compressed_sha256": expected_digest,
        "archive_inspection": inspected["status"],
        "file_count": len(manifest),
        "member_count": count,
        "uncompressed_file_bytes": total,
        "staged_file_manifest_sha256": digest.hexdigest(),
        "all_regular_files_nonexecutable": True,
        "go_binary_executed": False,
        "go_runtime_approved": False,
        "source_review": "NOT_ISSUED",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runner-temp", required=True, type=Path)
    args = parser.parse_args(argv)
    root = args.runner_temp
    try:
        if (not root.is_absolute() or root.is_symlink()
                or root.resolve(strict=True) != root or
                os.environ.get("RUNNER_TEMP") != str(root)):
            raise QualificationError("untrusted stage root")
        report = root / "lbe-p001-go-stage-evidence.json"
        if report.exists() or report.is_symlink():
            raise QualificationError("staging report already exists")
        evidence = stage_nonexecutable_go(
            root / GO_NAME, root / "lbe-p001-go-nonexec")
        fd = os.open(report, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(evidence, stream, sort_keys=True, indent=2)
            stream.write("\n")
    except (OSError, ValueError) as exc:
        print("LBE_P001_GO_STAGE=BLOCKED: " + str(exc), file=sys.stderr)
        return 2
    print("LBE_P001_GO_STAGE_BYTES=NONEXECUTABLE_SHA_MANIFEST_ATTESTED")
    print("LBE_P001_GO_STAGE_FILE_COUNT=" + str(evidence["file_count"]))
    print("LBE_P001_GO_STAGE_FILE_MANIFEST_SHA256=" +
          str(evidence["staged_file_manifest_sha256"]))
    print("LBE_P001_GO_BIN_OR_COMPILER_EXECUTED=FALSE")
    print("LBE_P001_GO_RUNTIME_SOURCE_REVIEW=NOT_ISSUED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
