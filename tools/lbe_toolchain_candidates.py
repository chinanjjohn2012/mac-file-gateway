#!/usr/bin/env python3
"""Read-only, pre-native inventory of Go/Pipenv executable *candidates*.

Do NOT import, invoke, install or bless these executables. A SHA256 of one
PATH-discovered executable does not source-lock the Go toolchain's compiler,
linker, standard library or modules, nor Pipenv's distribution/dependencies.
The sole purpose is to make missing external inputs inspectable before a
separately authorized, source-locked disposable T1. Never output PASS.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

MAX_PATH_ENTRIES = 64
MAX_CANDIDATES = 16
MAX_FILE_BYTES = 96 * 1024 * 1024
PROGRAMS = ("go", "pipenv")


def _candidate(path: Path) -> dict[str, object]:
    """Capture bounded file bytes without following the final open symlink."""
    record: dict[str, object] = {
        "path": str(path),
        "status": "UNSAFE_CANDIDATE",
        "native_qualified": False,
    }
    try:
        original = path.lstat()
        linked = stat.S_ISLNK(original.st_mode)
        resolved = path.resolve(strict=True)
        st = resolved.lstat()
        record["linked_path"] = linked
        record["resolved_path"] = str(resolved)
        if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1
                or not st.st_mode & 0o111 or st.st_size > MAX_FILE_BYTES):
            return record
        if not hasattr(os, "O_NOFOLLOW"):
            record["status"] = "NO_NOFOLLOW_SUPPORT"
            return record
        fd = os.open(
            resolved, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
        try:
            first = os.fstat(fd)
            if (first.st_dev, first.st_ino, first.st_size) != (
                    st.st_dev, st.st_ino, st.st_size):
                return record
            digest = hashlib.sha256()
            count = 0
            while True:
                data = os.read(fd, 1024 * 1024)
                if not data:
                    break
                count += len(data)
                if count > MAX_FILE_BYTES:
                    return record
                digest.update(data)
            last = os.fstat(fd)
        finally:
            os.close(fd)
        reread = path.resolve(strict=True)
        current = reread.lstat()
        if (reread != resolved or
                (first.st_dev, first.st_ino, first.st_size, first.st_mtime_ns)
                != (last.st_dev, last.st_ino, last.st_size, last.st_mtime_ns)
                or (last.st_dev, last.st_ino, last.st_size, last.st_mtime_ns)
                != (current.st_dev, current.st_ino, current.st_size,
                    current.st_mtime_ns)):
            record["status"] = "CHANGED_DURING_READ"
            return record
        record.update(status="CANDIDATE_ONLY", sha256=digest.hexdigest(),
                      bytes=count)
    except (OSError, RuntimeError, ValueError):
        # An unreadable, missing, replaced or unsafe file is never qualified.
        pass
    return record


def inspect(name: str, path_value: str) -> dict[str, object]:
    if name not in PROGRAMS:
        raise ValueError("unsupported program")
    result: dict[str, object] = {
        "program": name,
        "native_qualified": False,
        "external_dependency_qualified": False,
        "execution": "NOT_RUN",
        "status": "NOT_FOUND",
        "candidates": [],
    }
    pieces = path_value.split(os.pathsep)
    if (not path_value or len(pieces) > MAX_PATH_ENTRIES or
            any(not part or not Path(part).is_absolute() for part in pieces)):
        result["status"] = "UNSAFE_PATH_SEARCH"
        return result
    found: list[dict[str, object]] = []
    seen: set[str] = set()
    for raw in pieces:
        candidate = Path(raw) / name
        key = str(candidate)
        if key in seen:
            continue
        seen.add(key)
        try:
            candidate.lstat()
        except FileNotFoundError:
            continue
        except OSError:
            found.append({"path": key, "status": "UNSAFE_CANDIDATE",
                          "native_qualified": False})
            continue
        if len(found) >= MAX_CANDIDATES:
            result["status"] = "TOO_MANY_CANDIDATES"
            result["candidates"] = found
            return result
        found.append(_candidate(candidate))
    result["candidates"] = found
    if found:
        result["status"] = "CANDIDATES_UNQUALIFIED"
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    temp = os.environ.get("RUNNER_TEMP", "")
    if (not temp or not Path(temp).is_absolute() or
            args.output.parent.resolve(strict=True)
            != Path(temp).resolve(strict=True)):
        print("LBE_TOOLCHAIN_CANDIDATE_REPORT=INVALID_RUNNER_TEMP", file=sys.stderr)
        return 2
    findings = [inspect(name, os.environ.get("PATH", ""))
                for name in PROGRAMS]
    payload = {
        "kind": "LBE_TOOLCHAIN_CANDIDATES_ONLY_NOT_EXECUTION_AUTHORITY",
        "external_toolchains": findings,
        "all_native_qualified": False,
        "go_compiler_stdlib_modules": "NOT_ATTESTED",
        "pipenv_wheel_and_transitive_dependencies": "NOT_ATTESTED",
        "native_go_pipenv": "NOT_RUN",
    }
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    fd = os.open(args.output, flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, sort_keys=True, indent=2)
            stream.write("\n")
    except BaseException:
        raise
    for item in findings:
        print("LBE_CANDIDATE_%s=%s count=%s NATIVE_QUALIFIED=false"
              % (item["program"].upper(), item["status"],
                 len(item["candidates"])))
        for number, candidate in enumerate(item["candidates"]):
            if candidate.get("status") == "CANDIDATE_ONLY":
                print("LBE_CANDIDATE_%s_%s_SHA256=%s"
                      % (item["program"].upper(), number, candidate["sha256"]))
    print("LBE_NATIVE_GO_PIPENV_REAL_POSITIVE=NOT_RUN")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
