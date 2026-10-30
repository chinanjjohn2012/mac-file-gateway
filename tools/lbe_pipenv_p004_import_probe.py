#!/usr/bin/env python3
"""PR101 P004: attest seven pinned *installed* distributions before six imports.

This deliberately executes only the six owner-authorized imports on ephemeral
macOS 15 ARM64 Python 3.13 after P003 actual SHA/RECORD and offline pip --target.
It is not a sandbox, a security review, Go/Pipenv T1 or closure PASS.
"""
from __future__ import annotations

import argparse
import base64
import csv
from email.parser import Parser
import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.lbe_pipenv_p002_metadata import read_lock

PROFILE = "PR101-PIPENV-P004-EXACT-SIX-OFFLINE-IMPORT-20261030"
EXPECTED_IMPORTS = {
    "distlib": "distlib",
    "filelock": "filelock",
    "platformdirs": "platformdirs",
    "python-discovery": "python_discovery",
    "setuptools": "setuptools",
    "virtualenv": "virtualenv",
}
EXISTING_PINNED = {"packaging": "26.3"}
MAX_FILES_PER_DIST = 25000
MAX_FILE_BYTES = 50000000
MAX_TOTAL_INSTALLED = 320000000
MAX_IMPORT_SECONDS = 5.0


class P004Error(ValueError):
    """Fail closed: no assertion of qualified installed source or import."""


def _name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def _read_safe(root: Path, path: Path, limit: int) -> bytes:
    try:
        if path.is_symlink() or not path.is_file():
            raise P004Error("installed member symlink/nonregular rejected")
        st = path.lstat()
        if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1
                or not 0 <= st.st_size <= limit
                or not path.resolve(strict=True).is_relative_to(root)):
            raise P004Error("installed member source boundary invalid")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW |
                     getattr(os, "O_CLOEXEC", 0))
        try:
            at_open = os.fstat(fd)
            if (at_open.st_ino, at_open.st_dev, at_open.st_size,
                    at_open.st_mtime_ns) != (
                    st.st_ino, st.st_dev, st.st_size, st.st_mtime_ns):
                raise P004Error("installed file source identity changed")
            with os.fdopen(fd, "rb", closefd=False) as inp:
                data = inp.read(limit + 1)
            at_end = os.fstat(fd)
            if (at_end.st_ino, at_end.st_dev, at_end.st_size,
                    at_end.st_mtime_ns) != (
                    st.st_ino, st.st_dev, st.st_size, st.st_mtime_ns):
                raise P004Error("installed file mutated during read")
        finally:
            os.close(fd)
        if len(data) != st.st_size or len(data) > limit:
            raise P004Error("installed file read size mismatch")
        return data
    except OSError as exc:
        raise P004Error("installed file cannot be read safely") from exc


def verify_installed(root: Path, expected: dict[str, str]) -> dict[str, int]:
    """Attest installed RECORD bytes without importing any distribution."""
    if (not root.is_absolute() or not root.is_dir() or root.is_symlink()
            or root.resolve(strict=True) != root):
        raise P004Error("isolated install root invalid")
    record_paths = sorted(root.glob("*.dist-info/RECORD"))
    if len(record_paths) != len(expected):
        raise P004Error("unexpected installed distribution count")
    observed = {}
    total_size = 0
    for record in record_paths:
        metadata = record.parent / "METADATA"
        meta = Parser().parsestr(
            _read_safe(root, metadata, 524288).decode("utf-8", "strict"))
        name = _name(meta.get("Name", ""))
        version = meta.get("Version", "")
        if name in observed or name not in expected or expected[name] != version:
            raise P004Error("installed distribution identity changed")
        content = _read_safe(root, record, 4000000).decode("utf-8", "strict")
        inspected = set()
        file_count = 0
        for row in csv.reader(io.StringIO(content)):
            if len(row) != 3:
                raise P004Error("installed RECORD malformed")
            name_field, checksum, length = row
            path = Path(name_field)
            if (path.is_absolute() or not name_field or "\\" in name_field
                    or any(part in ("", ".", "..") for part in path.parts)):
                raise P004Error("installed RECORD traversal or ambiguity")
            path = root / path
            if name_field in inspected:
                raise P004Error("duplicate installed RECORD entry")
            inspected.add(name_field)
            if path == record:
                if checksum or length:
                    raise P004Error("installed RECORD must not claim self-hash")
                continue
            if not checksum.startswith("sha256=") or not length.isdecimal():
                raise P004Error("installed RECORD member unverified")
            data = _read_safe(root, path, MAX_FILE_BYTES)
            actual = base64.urlsafe_b64encode(
                hashlib.sha256(data).digest()).rstrip(b"=").decode("ascii")
            if checksum[7:] != actual or int(length) != len(data):
                raise P004Error("installed RECORD actual byte mismatch")
            total_size += len(data)
            file_count += 1
            if total_size > MAX_TOTAL_INSTALLED or file_count > MAX_FILES_PER_DIST:
                raise P004Error("installed dist source budget exceeded")
        if not inspected:
            raise P004Error("empty installed RECORD")
        observed[name] = file_count
    if set(observed) != set(expected):
        raise P004Error("missing installed distribution")
    return observed


def _forbid_external_side_effects(event: str, args: tuple) -> None:
    """Additional Python audit tripwire. Not a kernel sandbox."""
    if (event.startswith(("socket.connect", "socket.bind", "subprocess.Popen"))
            or event in ("os.system", "os.posix_spawn", "os.exec",
                         "os.execve", "os.fork", "os.forkpty",
                         "ctypes.dlopen", "ctypes.dlsym")):
        raise P004Error("import attempted forbidden external side effect")


def import_six(root: Path, import_names: dict[str, str]) -> dict[str, float]:
    if root.resolve(strict=True) != root:
        raise P004Error("import root not canonical")
    # -I -S disables user/site .pth execution. Only the already-attested
    # isolated distribution root may be added to Python's import search.
    sys.path.insert(0, str(root))
    sys.addaudithook(_forbid_external_side_effects)
    results = {}
    start_all = time.monotonic()
    for dist, mod_name in import_names.items():
        start = time.monotonic()
        module = importlib.import_module(mod_name)
        elapsed = time.monotonic() - start
        location = getattr(module, "__file__", None)
        if (not isinstance(location, str) or
                not Path(location).resolve(strict=True).is_relative_to(root)):
            raise P004Error("import resolved outside pinned install root: " + dist)
        if elapsed > MAX_IMPORT_SECONDS or time.monotonic() - start_all > MAX_IMPORT_SECONDS:
            raise P004Error("bounded import budget exceeded")
        results[dist] = round(elapsed, 6)
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runner-temp", required=True, type=Path)
    parser.add_argument("--lock", required=True, type=Path)
    parser.add_argument("--source-only", action="store_true")
    args = parser.parse_args(argv)
    try:
        root = args.runner_temp
        if (not root.is_absolute() or not root.is_dir() or root.is_symlink()
                or root.resolve(strict=True) != root or
                os.environ.get("RUNNER_TEMP") != str(root)):
            raise P004Error("runner scratch mismatch")
        source = root / "lbe-p003-wheel-byte-evidence.json"
        data = json.loads(_read_safe(root, source, 2000000))
        if (data.get("profile_id") !=
                "PR101-PIPENV-P003-SIX-WHEEL-BYTES-SOURCE-ONLY-20261030" or
                data.get("stage") != "ACTUAL_WHEEL_BYTES_SHA256_RECORD_ONLY" or
                data.get("wheel_count") != 6 or
                data.get("installed_or_imported") is not False):
            raise P004Error("P003 real byte proof missing/invalid")
        rows = read_lock(args.lock)
        observed = {x.get("distribution"): x for x in data.get("entries", [])}
        if (set(observed) != set(EXPECTED_IMPORTS) or
                any(not observed[r["name"]].get("bytes_verified") or
                    observed[r["name"]].get("actual_sha256") != r["sha256"] or
                    observed[r["name"]].get("executed") is not False
                    for r in rows)):
            raise P004Error("P003 wheel byte proof identity mismatch")
        expected = {x["name"]: x["version"] for x in rows}
        expected.update(EXISTING_PINNED)
        installed_root = root / "lbe-p004-private-site"
        attest = verify_installed(installed_root, expected)
        if args.source_only:
            print("LBE_P004_INSTALLED_RECORD_PREIMPORT=PASS count=7")
            return 0
        result_path = root / "lbe-p004-import-evidence.json"
        if result_path.exists() or result_path.is_symlink():
            raise P004Error("P004 evidence may not be overwritten")
        imported = import_six(installed_root, EXPECTED_IMPORTS)
        payload = {
            "profile_id": PROFILE,
            "status": "SIX_FIXED_DISTRIBUTION_IMPORTS_IN_EPHEMERAL_RUNNER",
            "installed_distribution_count": len(attest),
            "source_attested": sorted(attest),
            "imports": imported,
            "new_wheel_code_executed_as_import": True,
            "Go_Pipenv_executable_T1": "NOT_RUN",
            "recursive_python313_marker_closure": "NOT_QUALIFIED",
            "independent_BC_security_source_review": "NOT_ISSUED",
            "external_network_and_OS_signals": "NOT_AUTHORIZED",
            "production": False,
        }
        fd = os.open(result_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            json.dump(payload, out, indent=2, sort_keys=True)
            out.write("\n")
        # RECORD may be affected by import-time bytecode writes; ensure that
        # all pre-existing listed files are unchanged after import.
        if verify_installed(installed_root, expected) != attest:
            raise P004Error("installed RECORD drift after import")
    except (OSError, ValueError, ImportError, UnicodeError, TypeError) as exc:
        print("LBE_P004_ISOLATED_IMPORT=BLOCKED: " + str(exc), file=sys.stderr)
        return 2
    print("LBE_P004_SIX_IMPORTED=PASS count=6")
    print("LBE_P004_GO_OR_PIPENV_NATIVE=NOT_RUN")
    print("LBE_P004_FULL_RECURSIVE_CLOSURE=NOT_QUALIFIED")
    print("LBE_P004_B_C_SOURCE_SECURITY_REVIEW=NOT_ISSUED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
