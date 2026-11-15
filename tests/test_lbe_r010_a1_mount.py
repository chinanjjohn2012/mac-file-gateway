"""SAFE T0 for R010 A1 autofs mount exception and entire-table drift denial.

A synthetic 11-row Darwin getmntinfo tuple is injected. NO actual mount
target is inspected or activated; NO process, socket or network operation.
"""
from dataclasses import replace
import hashlib
import os
import subprocess

import pytest

from gateway.lbe_r010_a1_mount import (
    R010A1MountDenied, R010A1MountSnapshot,
    inspect_r010_a1_mounts, recheck_r010_a1_mounts,
)


AUTOFSTARGET = "/System/Volumes/Data/home"
AUTOFSSOURCE = "map auto_home"
AUTOFSFLAGS = 72351744
AUTOFSHASH = "6713f2a70c72b6c412839ad247f7605db53105c3e624c0a9cd778eb7fdeef5ad"


def _rows():
    # 10 safely mounted, distinct mock paths + one nonlocal autofs row.
    safe = [("apfs", "/", "/dev/disk0", 0x1000)]
    safe.extend(
        ("apfs", f"/private/safe{i}", f"/dev/disk{i}", 0x1000)
        for i in range(1, 10)
    )
    return tuple(sorted(safe + [
        ("autofs", AUTOFSTARGET, AUTOFSSOURCE, AUTOFSFLAGS),
    ]))


def _modified(index, changed):
    rows = list(_rows())
    rows[index] = changed
    return tuple(rows)


def _deny_native(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("R010 A1 mount SAFE T0 cannot perform native IO")
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(os, "kill", forbidden)
    monkeypatch.setattr(os, "killpg", forbidden, raising=False)


def test_exact_observed_autofs_and_full_table_can_be_rechecked(monkeypatch):
    _deny_native(monkeypatch)
    assert hashlib.sha256(AUTOFSSOURCE.encode()).hexdigest() == AUTOFSHASH
    before = inspect_r010_a1_mounts(observed_rows=_rows())
    assert before.mount_count == 11
    assert before.autofs_flags == AUTOFSFLAGS
    assert before.autofs_source_sha256 == AUTOFSHASH
    assert len(before.full_table_sha256) == 64
    assert before.native_launch_allowed is False
    assert recheck_r010_a1_mounts(
        before, observed_rows=tuple(reversed(_rows()))) == before


@pytest.mark.parametrize("badrow", [
    ("autofs", AUTOFSTARGET, "map auto_home.changed", AUTOFSFLAGS),
    ("autofs", AUTOFSTARGET, AUTOFSSOURCE, AUTOFSFLAGS+1),
    ("autofs", AUTOFSTARGET + "/nested", AUTOFSSOURCE, AUTOFSFLAGS),
    ("nfs", AUTOFSTARGET, AUTOFSSOURCE, AUTOFSFLAGS),
    ("autofs", AUTOFSTARGET, AUTOFSSOURCE, AUTOFSFLAGS | 0x1000),
    ("autofs", AUTOFSTARGET, AUTOFSSOURCE, AUTOFSFLAGS | 0x1),
    ("autofs", AUTOFSTARGET, AUTOFSSOURCE + "\n", AUTOFSFLAGS),
])
def test_wrong_autofs_identity_is_denied(badrow):
    rows = [x for x in _rows() if x[0] != "autofs"]
    rows.append(badrow)
    with pytest.raises(R010A1MountDenied):
        inspect_r010_a1_mounts(observed_rows=tuple(rows))


def test_second_writable_nonlocal_mount_denied_even_when_original_matches():
    rows = list(_rows())
    rows[0] = ("nfs", "/", "remote:/shared", 0)
    with pytest.raises(R010A1MountDenied):
        inspect_r010_a1_mounts(observed_rows=tuple(rows))


@pytest.mark.parametrize("change", [
    ("apfs", "/private/safe5", "/dev/disk5-new", 0x1000),
    ("apfs", "/private/safe5", "/dev/disk5", 0x1001),
    ("apfs", "/private/safe5", "/dev/disk5", 0x1000 | 0x2),
])
def test_even_safe_row_source_or_flags_drift_is_denied(change):
    initial = inspect_r010_a1_mounts(observed_rows=_rows())
    rows = tuple(
        change if x[1] == "/private/safe5" else x for x in _rows()
    )
    with pytest.raises(R010A1MountDenied):
        recheck_r010_a1_mounts(initial, observed_rows=rows)


def test_count_missing_root_duplicate_target_and_nested_addition_denied():
    rows = list(_rows())
    for invalid in (
        tuple(rows[:-1]),
        tuple(x for x in rows if x[1] != "/"),
        tuple(rows[:-1] + [rows[0]]),
        tuple(rows[:-1] + [("apfs", "/", "/dev/special", 0x1000)]),
        tuple(rows + [("nfs", AUTOFSTARGET + "/nested", "remote", 0)]),
    ):
        with pytest.raises(R010A1MountDenied):
            inspect_r010_a1_mounts(observed_rows=invalid)


def test_wrong_expected_snapshot_or_forged_native_ready_denied():
    valid = inspect_r010_a1_mounts(observed_rows=_rows())
    for invalid in (
        replace(valid, full_table_sha256="0"*64),
        replace(valid, mount_count=10),
        replace(valid, autofs_source_sha256="0"*64),
        replace(valid, autofs_flags=AUTOFSFLAGS + 1),
        replace(valid, native_launch_allowed=True),
    ):
        with pytest.raises(R010A1MountDenied):
            recheck_r010_a1_mounts(invalid, observed_rows=_rows())
    with pytest.raises(R010A1MountDenied):
        recheck_r010_a1_mounts(object(), observed_rows=_rows())


def test_os_darwin_read_without_injection_forbidden_on_unsupported_host(monkeypatch):
    import gateway.lbe_r010_a1_mount as product

    monkeypatch.setattr(product.sys, "platform", "linux")
    def forbid_mount():
        raise AssertionError("cannot probe actual mounts on a fake non-Darwin host")
    monkeypatch.setattr(product, "_darwin_mount_rows", forbid_mount)
    with pytest.raises(R010A1MountDenied):
        product.inspect_r010_a1_mounts()
