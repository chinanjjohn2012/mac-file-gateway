#!/usr/bin/env python3
"""Select exactly the existing source-locked wheel versions before pip resolves.

This is not a provenance verifier. The unchanged R004 wheel SHA256 and installed
RECORD checks must still attest actual downloaded and installed bytes.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import re
import stat
import sys

_LINE = re.compile(r"([0-9a-f]{64})  ([A-Za-z0-9_.-]+\\.whl)\\Z")
_PART = re.compile(r"[A-Za-z0-9_]+\\Z")
_VERSION = re.compile(r"[0-9][A-Za-z0-9._]*\\Z")
_TAG = re.compile(r"[A-Za-z0-9_.]+\\Z")


def constraints_from_lock(path: Path, *, expected_count: int = 36) -> str:
    """Build pip constraints only from the fixed wheel-filename identities."""
    st = path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
        raise ValueError("wheel source lock must be one regular file, not a link")
    rows = path.read_text(encoding="ascii").splitlines()
    if len(rows) != expected_count:
        raise ValueError("wheel source lock must contain exactly %s wheels" % expected_count)
    filenames = []
    names = set()
    pins = []
    for row in rows:
        match = _LINE.fullmatch(row)
        if not match:
            raise ValueError("invalid source-lock record")
        filename = match.group(2)
        parts = filename[:-4].split("-")
        if len(parts) != 5:
            raise ValueError("unsupported wheel filename form")
        distribution, version, py, abi, platform = parts
        if (not _PART.fullmatch(distribution) or not _VERSION.fullmatch(version)
                or any(not _TAG.fullmatch(tag) for tag in (py, abi, platform))):
            raise ValueError("invalid locked wheel name, version or tag")
        canonical = re.sub(r"[-_.]+", "-", distribution).lower()
        if canonical in names:
            raise ValueError("duplicate canonical distribution in wheel lock")
        names.add(canonical)
        filenames.append(filename)
        pins.append("%s==%s" % (canonical, version))
    if filenames != sorted(filenames):
        raise ValueError("wheel lock filenames must be sorted and unique")
    return "\n".join(pins) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-lock", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        payload = constraints_from_lock(args.source_lock)
    except (OSError, UnicodeError, ValueError) as exc:
        print("CI_WHEEL_CONSTRAINTS=INCOMPLETE; " + str(exc), file=sys.stderr)
        return 2
    sys.stdout.write(payload)
    print("CI_WHEEL_CONSTRAINTS=PINNED_FROM_SOURCE_LOCK count=36", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
