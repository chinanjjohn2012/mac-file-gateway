#!/usr/bin/env python3
"""P007: read-only Go 1.27.3 archive/stage byte provenance, not a security PASS.

Source-only, after P001; DOES NOT run Go/compiler/linker/project code.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tarfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.lbe_t1_source_qualifier import (
    GO_NAME, GO_SHA256, GO_SIZE, MAX_GO_MEMBERS, MAX_GO_EXPANDED,
    inspect_go_archive, safe_member_name, verified_file,
)

PINNED_FILES = 15657
PINNED_MANIFEST = "e43f516501f4e9b07de05dd470ffdab0b4c2acc086acf1e282d39c40fb00dc6a"
CRITICAL = frozenset({
    "go/VERSION", "go/bin/go", "go/pkg/tool/darwin_arm64/compile",
    "go/pkg/tool/darwin_arm64/link", "go/src/runtime/proc.go",
})
MAX_OUTPUT_BYTES = 5500000
MAX_ENTRY = 100000000
MAGICS = {b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf",
          b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xce"}


class ProvenanceError(ValueError):
    """Input was not eligible for a source-only qualification claim."""


def _origin(path: str, first_four: bytes) -> tuple[str, list[str]]:
    group = (
        "go_compiler_or_tool" if path.startswith(("go/bin/", "go/pkg/tool/"))
        else "stdlib_source" if path.startswith("go/src/")
        else "upstream_test" if path.startswith("go/test/")
        else "other_go_input"
    )
    flags = []
    if first_four in MAGICS:
        flags.append("macho_source_manual_review")
    if path.endswith((".a", ".o", ".syso", ".so", ".dylib", ".dll")):
        flags.append("compiled_or_native_manual_review")
    if path.startswith(("go/src/runtime/", "go/src/cmd/cgo/",
                        "go/src/cmd/vendor/", "go/pkg/tool/")):
        flags.append("compiler_runtime_cgo_vendor_manual_review")
    return group, flags


def inspect_stage(archive: Path, stage: Path, *, sha: str = GO_SHA256,
                  size: int = GO_SIZE,
                  stage_hash: str | None = None) -> dict:
    """Reconcile exact tar member bytes to an unexecutable one-link stage."""
    if (not stage.is_absolute() or not stage.is_dir() or stage.is_symlink()
            or stage.resolve(strict=True) != stage):
        raise ProvenanceError("Go stage root not canonical")
    proof = inspect_go_archive(archive, sha, size)
    if proof["status"] != "ARCHIVE_BYTES_VERIFIED_MEMBERS_INSPECTED":
        raise ProvenanceError("Go archive source qualification missing")
    records = []
    record_lines = []
    names = set()
    groups, signals = Counter(), Counter()
    total = 0
    try:
        with tarfile.open(archive, "r:gz") as source:
            for m in source:
                name = safe_member_name(m.name)
                if m.isdir():
                    continue
                if (not m.isfile() or name in names or
                        not name.startswith("go/") or
                        m.size < 0 or m.size > MAX_ENTRY):
                    raise ProvenanceError("unsafe/duplicated Go archive file")
                names.add(name)
                total += m.size
                if len(names) > MAX_GO_MEMBERS or total > MAX_GO_EXPANDED:
                    raise ProvenanceError("Go source inventory exceeds limits")
                path = stage / name
                st = path.lstat()
                if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or
                        st.st_size != m.size or
                        stat.S_IMODE(st.st_mode) & 0o111 or
                        not path.resolve(strict=True).is_relative_to(stage)):
                    raise ProvenanceError("staged Go member unsafe or executable")
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
                digest = hashlib.sha256()
                length = 0
                first = b""
                try:
                    with source.extractfile(m) as archived:
                        while length < m.size:
                            remote = archived.read(min(1048576, m.size - length))
                            if not remote:
                                raise ProvenanceError("short archived Go member")
                            actual = os.read(fd, len(remote))
                            if actual != remote:
                                raise ProvenanceError("staged source does not match archive")
                            if length == 0:
                                first = actual[:4]
                            digest.update(actual)
                            length += len(actual)
                    fdst = os.fstat(fd)
                finally:
                    os.close(fd)
                after = path.lstat()
                if ((st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns) !=
                        (fdst.st_dev, fdst.st_ino, fdst.st_size, fdst.st_mtime_ns)
                        or (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns) !=
                        (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
                    raise ProvenanceError("staged Go member changed during read")
                dhex = digest.hexdigest()
                label, flags = _origin(name, first)
                groups[label] += 1
                signals.update(flags)
                record_lines.append(dhex + "  ./" + name)
                records.append({"path": name, "sha256": dhex, "bytes": length,
                                "group": label, "manual_review_hints": flags})
        if not CRITICAL <= names:
            raise ProvenanceError("critical Go compiler/linker/source member missing")
        on_disk = set()
        for folder, directories, files in os.walk(stage, followlinks=False):
            parent = Path(folder)
            for d in directories:
                p = parent / d
                if p.is_symlink() or not p.is_dir():
                    raise ProvenanceError("symlink or special directory in staged Go")
            for f in files:
                p = parent / f
                s = p.lstat()
                if (not stat.S_ISREG(s.st_mode) or s.st_nlink != 1 or
                        stat.S_IMODE(s.st_mode) & 0o111):
                    raise ProvenanceError("unlisted executable/special staged Go file")
                on_disk.add(p.relative_to(stage).as_posix())
        if on_disk != names:
            raise ProvenanceError("Go stage has unlisted or missing files")
        # P001 sorts COMPLETE sha256-prefixed lines; path-only sorting is wrong.
        record_lines.sort()
        digest = hashlib.sha256(("\n".join(record_lines) + "\n").encode()).hexdigest()
        if stage_hash is not None and digest != stage_hash:
            raise ProvenanceError("P001 staged manifest SHA256 mismatch")
        verified_file(archive, sha, size, 70000000)
    except (OSError, ValueError, tarfile.TarError, EOFError) as exc:
        if isinstance(exc, ProvenanceError):
            raise
        raise ProvenanceError("Go archive/stage provenance inspection failed") from exc
    records.sort(key=lambda r: r["path"])
    return {"status": "GO_ARCHIVE_AND_NONEXEC_STAGE_BYTES_MATCH",
            "archive_sha256": sha, "stage_sha256_manifest": digest,
            "file_count": len(names), "expanded_source_bytes": total,
            "critical_sources": [r for r in records if r["path"] in CRITICAL],
            "group_counts": dict(groups), "manual_review_hint_counts": dict(signals),
            "files": records, "go_executed": False,
            "independent_source_security": "NOT_ISSUED", "native_T1": "NOT_RUN"}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--runner-temp", type=Path, required=True)
    args = ap.parse_args(argv)
    root = args.runner_temp
    try:
        if (not root.is_absolute() or not root.is_dir() or root.is_symlink()
                or root.resolve(strict=True) != root
                or os.environ.get("RUNNER_TEMP") != str(root)):
            raise ProvenanceError("untrusted runner scratch")
        prior = root / "lbe-p001-go-stage-evidence.json"
        proof = json.loads(prior.read_text("utf-8"))
        if (proof.get("status") != "BYTES_STAGED_NONEXECUTABLE" or
                proof.get("compressed_sha256") != GO_SHA256 or
                proof.get("file_count") != PINNED_FILES or
                proof.get("staged_file_manifest_sha256") != PINNED_MANIFEST or
                proof.get("go_binary_executed") is not False):
            raise ProvenanceError("P001 source staging not qualified")
        result = inspect_stage(
            root / GO_NAME, root / "lbe-p001-go-nonexec",
            stage_hash=PINNED_MANIFEST)
        if result["file_count"] != PINNED_FILES:
            raise ProvenanceError("Go staged file count changed")
        result["profile"] = "PR101-P007-GO-SOURCE-BYTES-20261030"
        report = root / "lbe-p007-go-source-report.json"
        if report.exists() or report.is_symlink():
            raise ProvenanceError("source evidence overwrite denied")
        serialized = json.dumps(result, sort_keys=True, separators=(",", ":"))
        if len(serialized) > MAX_OUTPUT_BYTES:
            raise ProvenanceError("Go source inventory report size exceeded")
        fd = os.open(report, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            out.write(serialized + "\n")
    except (OSError, ValueError, TypeError) as exc:
        print("LBE_P007_SOURCE_ONLY=BLOCKED: " + str(exc), file=sys.stderr)
        return 2
    print("LBE_P007_GO_RECONCILED_MEMBERS=PASS count=" + str(result["file_count"]))
    print("LBE_P007_GO_STAGE_MANIFEST_SHA256=" + result["stage_sha256_manifest"])
    for entry in result["critical_sources"]:
        print("LBE_P007_CRITICAL=" + entry["path"] + " sha256=" + entry["sha256"])
    print("LBE_P007_GO_COMPILER_OR_RUNTIME_EXECUTED=FALSE")
    print("LBE_P007_INDEPENDENT_B_C_REVIEW=NOT_ISSUED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
