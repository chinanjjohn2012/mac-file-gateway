"""Collect bounded macOS host-file candidates for later review (SAFE T0).

This is discovery only. It never makes the observed digest authoritative and
never grants PRODUCT_T1. A later commit must independently pin exact values to
the reviewed ImageVersion and then recheck them with the product source probe.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat

_CANDIDATES = (
    "/System/Library/CoreServices/SystemVersion.plist",
    "/usr/bin/env",
    "/usr/lib/dyld",
)
_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
_MAX = 32 * 1024 * 1024


def _collect(path: str) -> dict:
    if type(path) is not str or not path.startswith("/") or ".." in path.split("/"):
        return {"path": path if type(path) is str else "", "status": "INVALID"}
    parts = tuple(p for p in path.split("/") if p)
    parents = [os.open("/", _DIR)]
    try:
        for part in parts[:-1]:
            parents.append(os.open(part, _DIR, dir_fd=parents[-1]))
        fd = os.open(parts[-1], _FILE, dir_fd=parents[-1])
        try:
            st = os.fstat(fd)
            if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1
                    or st.st_uid not in (0, os.getuid())
                    or st.st_mode & 0o022 or not 0 < st.st_size <= _MAX):
                return {"path": path, "status": "UNQUALIFIED_METADATA"}
            remain = st.st_size
            h = hashlib.sha256()
            while remain:
                chunk = os.read(fd, min(65536, remain))
                if not chunk:
                    return {"path": path, "status": "SHORT_READ"}
                h.update(chunk)
                remain -= len(chunk)
            after = os.fstat(fd)
            before_id = (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns,
                         st.st_ctime_ns, st.st_mode, st.st_uid, st.st_nlink)
            after_id = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
                        after.st_ctime_ns, after.st_mode, after.st_uid, after.st_nlink)
            if before_id != after_id:
                return {"path": path, "status": "CHANGED_DURING_READ"}
            return {
                "path": path, "status": "CANDIDATE_ONLY",
                "sha256": h.hexdigest(), "size": st.st_size,
                "mode": oct(stat.S_IMODE(st.st_mode)), "uid": st.st_uid,
                "inode": st.st_ino, "device": st.st_dev,
            }
        finally:
            os.close(fd)
    except OSError as exc:
        return {"path": path, "status": "UNAVAILABLE", "errno": exc.errno}
    finally:
        for fd in reversed(parents):
            os.close(fd)


def main() -> int:
    rows = tuple(_collect(path) for path in _CANDIDATES)
    print(json.dumps({
        "profile": "D4_R006_HOST_SOURCE_CANDIDATE_COLLECTION_T0",
        "rows": rows,
        "independently_reviewed_allowlist": False,
        "source_qualified": False,
        "native_launch_allowed": False,
    }, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
