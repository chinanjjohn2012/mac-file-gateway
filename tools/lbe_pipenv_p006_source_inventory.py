#!/usr/bin/env python3
"""PR101 P006: evidence-only source inventory of nine exact pinned Wheels.

Runs after P005 on a disposable GitHub-hosted macOS 15 ARM64 runner.
It DOES NOT import/execute third-party sources, authorize Go/Pipenv native
execution, or constitute independent Standards/Spec source code review.
Heuristic findings are NOT proof of safety or malicious behavior.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.lbe_pipenv_p003_wheel_bytes import (
    _archive_name, _audit_wheel,
)
from tools.lbe_pipenv_p005_closure import EXPECTED, NEW_SIX
from tools.lbe_t1_source_qualifier import inspect_pipenv_wheel

PROFILE = "PR101-PIPENV-P006-NINE-WHEEL-SOURCE-INVENTORY-20261030"
MAX_FILES = 18000
MAX_ENTRY_SIZE = 50000000
MAX_TOTAL_SIZE = 320000000
MAX_EVIDENCE = 7000000
ROOT_HINT_LIMIT = 48
PATTERNS = {
    "imports_process_or_network_modules": re.compile(
        r"(?m)^\s*(?:from|import)\s+"
        r"(?:os|subprocess|socket|ctypes|multiprocessing|runpy|http|urllib|requests|httpx)\b"),
    "process_or_signal_call": re.compile(
        r"\b(?:os\.(?:system|popen|fork|exec\w*|kill|killpg)"
        r"|subprocess\.(?:Popen|run|call|check_call|check_output))\s*\("),
    "dynamic_eval_or_import_call": re.compile(
        r"\b(?:eval|exec|__import__)\s*\("),
    "network_client_call": re.compile(
        r"\b(?:socket\.(?:socket|create_connection)"
        r"|urllib\.request\.(?:urlopen|urlretrieve)|requests\.(?:get|post)"
        r"|httpx\.(?:get|post))\s*\("),
}
NATIVE_SUFFIXES = (".so", ".dylib", ".dll", ".pyd", ".exe", ".a", ".o")
BOOTSTRAP_SUFFIXES = (".pth", ".egg-link", "sitecustomize.py", "usercustomize.py")


class InventoryError(ValueError):
    """Source inventory cannot safely reconstruct an exact wheel input."""


def source_path(root: Path, name: str) -> Path:
    """No user-controlled paths or resolver names may enter this mapping."""
    if name not in EXPECTED:
        raise InventoryError("unapproved distribution source name")
    filename = EXPECTED[name][1]
    if name in NEW_SIX:
        folder = "lbe-p003-six-wheel-bytes"
    elif name == "packaging":
        folder = "lbe-p004-packaging"
    elif name in ("pipenv", "certifi"):
        folder = "lbe-p005-primary-source-only"
    else:
        raise InventoryError("distribution not in fixed source inventory")
    path = root / folder / filename
    if (not path.parent.is_dir() or path.parent.is_symlink() or
            path.is_symlink()):
        raise InventoryError("source wheel path/scratch not regular")
    return path


def inventory_wheel(path: Path, name: str, expected: tuple[str, str, str]) -> dict:
    """A bounded, per-file byte-hash manifest and manual-review risk hints."""
    version, filename, digest = expected
    if name not in EXPECTED or EXPECTED[name] != expected or path.name != filename:
        raise InventoryError("source wheel name/version/digest identity changed")
    try:
        before = path.lstat()
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or not 0 < before.st_size <= 12000000):
            raise InventoryError("wheel source file type or size invalid")
        # Complete SHA256+RECORD verification is a prerequisite; P006 repeats
        # it on the specific source FD/path, independently of P003/P005 logs.
        if name == "pipenv":
            verified = inspect_pipenv_wheel(path, digest, before.st_size)
            if verified["status"] != "WHEEL_BYTES_AND_RECORD_VERIFIED":
                raise InventoryError("Pipenv source RECORD not verified")
        else:
            verified = _audit_wheel(
                path, {"name": name, "version": version,
                       "filename": filename, "sha256": digest}, before.st_size)
            if not verified["bytes_verified"]:
                raise InventoryError("source wheel RECORD not verified")
        files = []
        seen = set()
        casefolded = set()
        aggregate = hashlib.sha256()
        total = 0
        signal_counts = Counter()
        signal_paths = defaultdict(list)
        python_count = 0
        with zipfile.ZipFile(path) as wheel:
            infos = wheel.infolist()
            if len(infos) > MAX_FILES:
                raise InventoryError("unbounded source member inventory")
            for entry in infos:
                rel = _archive_name(entry.filename)
                if rel in seen or rel.casefold() in casefolded:
                    raise InventoryError("duplicate source member path")
                seen.add(rel)
                casefolded.add(rel.casefold())
                if entry.is_dir():
                    continue
                if (entry.file_size < 0 or entry.file_size > MAX_ENTRY_SIZE
                        or entry.compress_type not in (
                            zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)):
                    raise InventoryError("source member size/compression invalid")
                total += entry.file_size
                if total > MAX_TOTAL_SIZE:
                    raise InventoryError("expanded source size exceeds cap")
                data = wheel.read(entry)
                if len(data) != entry.file_size:
                    raise InventoryError("source member decompression mismatch")
                sha = hashlib.sha256(data).hexdigest()
                aggregate.update(rel.encode("utf-8", "strict"))
                aggregate.update(b"\x00")
                aggregate.update(sha.encode("ascii"))
                aggregate.update(b"\n")
                flags = []
                lower = rel.lower()
                if lower.endswith(".py"):
                    python_count += 1
                    # Unknown codecs are still hashed and appear in manifest.
                    # Non-UTF8 content is recorded, not interpreted as safe.
                    try:
                        txt = data.decode("utf-8", "strict")
                    except UnicodeError:
                        flags.append("non_utf8_python_source")
                    else:
                        for tag, pattern in PATTERNS.items():
                            if pattern.search(txt):
                                flags.append(tag)
                if lower.endswith(NATIVE_SUFFIXES):
                    flags.append("native_or_compiled_member")
                if lower.endswith(BOOTSTRAP_SUFFIXES):
                    flags.append("startup_or_path_hook")
                if lower.endswith("/entry_points.txt"):
                    flags.append("console_or_plugin_entrypoint_metadata")
                if ("/scripts/" in lower or ".data/scripts/" in lower or
                        lower.startswith("bin/")):
                    flags.append("packaged_script_or_tool")
                if rel.startswith("benchmarks/"):
                    flags.append("pipenv_benchmarks_unreviewed")
                for tag in flags:
                    signal_counts[tag] += 1
                    if len(signal_paths[tag]) < ROOT_HINT_LIMIT:
                        signal_paths[tag].append(rel)
                files.append({
                    "path": rel, "sha256": sha, "bytes": len(data),
                    "manual_review_hints": flags,
                })
        after = path.lstat()
        if (before.st_ino, before.st_dev, before.st_size,
                before.st_mtime_ns) != (
                after.st_ino, after.st_dev, after.st_size, after.st_mtime_ns):
            raise InventoryError("source archive changed during inventory")
        if not files:
            raise InventoryError("source wheel has no regular contents")
        files.sort(key=lambda x: x["path"])
        return {
            "distribution": name, "version": version, "filename": filename,
            "actual_sha256": digest, "bytes": before.st_size,
            "sha256_and_RECORD_checked": True,
            "source_files": files, "file_count": len(files),
            "python_source_files": python_count,
            "expanded_source_bytes": total,
            "member_hash_stream_sha256": aggregate.hexdigest(),
            "review_hint_counts": dict(sorted(signal_counts.items())),
            "review_hint_paths_bounded": dict(sorted(signal_paths.items())),
            "manual_security_source_review": "NOT_ISSUED",
            "safe_code_verdict": "NOT_ASSESSED",
            "wheel_imported_or_executed_by_P006": False,
        }
    except (OSError, ValueError, UnicodeError, RuntimeError,
            zipfile.BadZipFile, EOFError) as exc:
        if isinstance(exc, InventoryError):
            raise
        raise InventoryError("pinned source Wheel inventory rejected") from exc


def _load_proof(path: Path) -> dict:
    try:
        st = path.lstat()
        if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1
                or not 0 < st.st_size < MAX_EVIDENCE):
            raise InventoryError("prior source evidence missing or invalid")
        # Prior P005/P003 evidence is local-only on this same ephemeral runner.
        raw = path.read_bytes()
        data = json.loads(raw.decode("utf-8", "strict"))
        if not isinstance(data, dict):
            raise InventoryError("prior source evidence root invalid")
        return data
    except (OSError, UnicodeError, ValueError) as exc:
        if isinstance(exc, InventoryError):
            raise
        raise InventoryError("prior source evidence unavailable") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runner-temp", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        root = args.runner_temp
        if (not root.is_absolute() or root.is_symlink()
                or not root.is_dir() or root.resolve(strict=True) != root
                or os.environ.get("RUNNER_TEMP") != str(root)):
            raise InventoryError("ephemeral runner root identity invalid")
        earlier = _load_proof(root / "lbe-p005-base-graph-source-evidence.json")
        if (earlier.get("profile") !=
                "PR101-PIPENV-P005-BASE-RUNTIME-DECLARED-MARKER-GRAPH-20261030"
                or earlier.get("status") !=
                "SATISFIED_FOR_EXPLICIT_EXTRAS_EMPTY"):
            raise InventoryError("P005 source marker graph gate not satisfied")
        input_names = sorted(EXPECTED)
        reports = [inventory_wheel(source_path(root, name), name,
                                   EXPECTED[name]) for name in input_names]
        if (len(reports) != 9 or
                {x["distribution"] for x in reports} != set(EXPECTED)):
            raise InventoryError("source inventory incomplete")
        out = root / "lbe-p006-nine-wheel-review-inventory.json"
        if out.exists() or out.is_symlink():
            raise InventoryError("source review inventory cannot be overwritten")
        report = {
            "profile_id": PROFILE,
            "distributions": reports,
            "source_distributions": len(reports),
            "source_files_total": sum(x["file_count"] for x in reports),
            "source_python_files_total": sum(x["python_source_files"] for x in reports),
            "byte_and_internal_RECORD_verified": True,
            "scanner_heuristic_is_a_security_review": False,
            "B_Standards_security_review": "NOT_ISSUED",
            "C_Spec_security_review": "NOT_ISSUED",
            "newly_run_external_code": False,
            "Go_Pipenv_primary_program_native_T1": "NOT_RUN",
            "distlib_python313_requires_python": "NOT_DECLARED",
            "full_security_or_compatibility_qualification": "NOT_PROVEN",
        }
        body = json.dumps(report, sort_keys=True, indent=2, ensure_ascii=True)
        if len(body) > MAX_EVIDENCE:
            raise InventoryError("bounded source inventory report too large")
        fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(body)
            stream.write("\n")
    except (OSError, ValueError) as exc:
        print("LBE_P006_SOURCE_INVENTORY=BLOCKED: " + str(exc),
              file=sys.stderr)
        return 2
    for row in reports:
        summary = ",".join(
            tag + ":" + str(count)
            for tag, count in sorted(row["review_hint_counts"].items()))
        print("LBE_P006_SOURCE=" + row["distribution"] +
              " files=" + str(row["file_count"]) +
              " python=" + str(row["python_source_files"]) +
              " hint_counts=" + summary +
              " hash_stream=" + row["member_hash_stream_sha256"])
    print("LBE_P006_NINE_SHA_RECORD_SOURCE_INVENTORIES=PASS count=9")
    print("LBE_P006_B_C_INDEPENDENT_SOURCE_SECURITY_REVIEW=NOT_ISSUED")
    print("LBE_P006_NATIVE_GO_PIPENV=NOT_RUN")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
