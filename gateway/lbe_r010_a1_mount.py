"""A1 exact autofs exception with whole-table pre-Popen freshness.

This is a product-source host predicate, not an execution capability. It
cannot substitute for an independently signed Owner Grant, provider Job,
credential/SSH checks, executable source identity, F1/R006 or a T1 grant.
The actual Darwin branch calls the existing metadata-only getmntinfo helper.
NEVER opens/stats/walks the autofs target, sends traffic, or launches a child.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
import sys

from .lbe_r006_macos_allowlist import _darwin_mount_rows

_AUTOFSTYPE = "autofs"
_AUTOFSTARGET = "/System/Volumes/Data/home"
_SOURCE_HASH = "6713f2a70c72b6c412839ad247f7605db53105c3e624c0a9cd778eb7fdeef5ad"
_AUTOFS_FLAGS = 72351744
_MOUNT_COUNT = 11
_MNT_RDONLY = 0x1
_MNT_LOCAL = 0x1000


class R010A1MountDenied(ValueError):
    """A1 selected-host mount identity or Job snapshot differs."""


@dataclass(frozen=True, slots=True)
class R010A1MountSnapshot:
    full_table_sha256: str
    mount_count: int
    autofs_source_sha256: str
    autofs_flags: int
    native_launch_allowed: bool = False


def _normalized_rows(rows: object) -> tuple[tuple[str, str, str, int], ...]:
    if type(rows) is not tuple or len(rows) != _MOUNT_COUNT:
        raise R010A1MountDenied("unreviewed Darwin mount table count")
    for row in rows:
        if (type(row) is not tuple or len(row) != 4
                or any(type(value) is not str or not value for value in row[:3])
                or type(row[3]) is not int or row[3] < 0):
            raise R010A1MountDenied("malformed mount table row")
        fstype, target, source, flags = row
        if (not target.startswith("/")
                or "/../" in target or target.endswith("/..")
                or "//" in target or "\x00" in target or "\x00" in source
                or any(ord(c) < 32 for c in target + source + fstype)
                or len(target) > 1024 or len(source) > 1024
                or len(fstype) > 64 or flags > 0xffffffff):
            raise R010A1MountDenied("noncanonical mount table entry")
    normalized = tuple(sorted(rows))
    if len(set(normalized)) != _MOUNT_COUNT:
        raise R010A1MountDenied("duplicate or ambiguous mount entry")
    if len({row[1] for row in normalized}) != _MOUNT_COUNT:
        raise R010A1MountDenied("duplicate mount target")
    if not any(row[1] == "/" for row in normalized):
        raise R010A1MountDenied("missing root mount")
    return normalized


def inspect_r010_a1_mounts(
    *, observed_rows: tuple[tuple[str, str, str, int], ...] | None = None,
) -> R010A1MountSnapshot:
    """Read full table without activating mount targets.

    observed_rows is ONLY for synthetic injected SAFE T0. A future trusted
    PREEXEC must obtain original Darwin rows itself, then bind the resulting
    hash into a verified same-Job Owner Grant; caller-supplied rows are not
    provider-authenticated evidence.
    """
    if observed_rows is None:
        if sys.platform != "darwin":
            raise R010A1MountDenied("real getmntinfo is Darwin-only")
        try:
            observed_rows = _darwin_mount_rows()
        except (OSError, ValueError, AttributeError):
            raise R010A1MountDenied("Darwin mount table unavailable") from None
    rows = _normalized_rows(observed_rows)
    writable_nonlocal = tuple(
        row for row in rows
        if not (row[3] & _MNT_RDONLY) and not (row[3] & _MNT_LOCAL)
    )
    if len(writable_nonlocal) != 1:
        raise R010A1MountDenied("unreviewed writable nonlocal mount")
    kind, target, source, flags = writable_nonlocal[0]
    source_sha = hashlib.sha256(source.encode("utf-8", "strict")).hexdigest()
    if (kind != _AUTOFSTYPE or target != _AUTOFSTARGET
            or source_sha != _SOURCE_HASH or flags != _AUTOFS_FLAGS):
        raise R010A1MountDenied("A1 single autofs exception mismatch")
    canonical = json.dumps(rows, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("ascii")
    return R010A1MountSnapshot(
        full_table_sha256=hashlib.sha256(canonical).hexdigest(),
        mount_count=len(rows), autofs_source_sha256=source_sha,
        autofs_flags=flags, native_launch_allowed=False)


def recheck_r010_a1_mounts(
    expected: R010A1MountSnapshot, *,
    observed_rows: tuple[tuple[str, str, str, int], ...] | None = None,
) -> R010A1MountSnapshot:
    """Require exact same Job full-table observation; never grants Exec."""
    if (type(expected) is not R010A1MountSnapshot
            or type(expected.full_table_sha256) is not str
            or re.fullmatch(r"[0-9a-f]{64}", expected.full_table_sha256,
                            flags=re.ASCII) is None
            or type(expected.mount_count) is not int
            or expected.mount_count != _MOUNT_COUNT
            or expected.autofs_source_sha256 != _SOURCE_HASH
            or type(expected.autofs_flags) is not int
            or expected.autofs_flags != _AUTOFS_FLAGS
            or expected.native_launch_allowed is not False):
        raise R010A1MountDenied("untrusted expected A1 mount snapshot")
    current = inspect_r010_a1_mounts(observed_rows=observed_rows)
    if current != expected:
        raise R010A1MountDenied("full Darwin mount table drift")
    return current
