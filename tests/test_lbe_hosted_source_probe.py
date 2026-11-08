"""Actual read-only pinned host-source measurements, never native T1."""
from dataclasses import replace
import hashlib
from concurrent.futures import ThreadPoolExecutor
import os
import subprocess
import threading

import pytest

from gateway.lbe_hosted_source_probe import (
    D4HostedSelectedSourceObservation,
    D4HostedSelectedSourceRecheck,
    D4HostedSourceDenied,
    inspect_d4_hosted_selected_source_files,
)


def _staged(tmp_path):
    root = tmp_path / "sources"
    parent = root / "system"
    parent.mkdir(parents=True, mode=0o700)
    root.chmod(0o700)
    parent.chmod(0o700)
    data = b"exact static Darwin source bytes, NEVER executed\n"
    file = parent / "dyld-source"
    file.write_bytes(data)
    file.chmod(0o600)
    entry = (("system/dyld-source", hashlib.sha256(data).hexdigest()),)
    return root, parent, file, entry


def test_selected_real_file_bytes_match_not_full_mac_image(tmp_path, monkeypatch):
    root, parent, file, entry = _staged(tmp_path)
    events = []

    def forbidden(*_a, **_kw):
        events.append(True)
        raise AssertionError("a source-only host probe cannot spawn or signal")

    with monkeypatch.context() as patch:
        patch.setattr(subprocess, "Popen", forbidden)
        patch.setattr(os, "kill", forbidden)
        patch.setattr(os, "killpg", forbidden, raising=False)
        result = inspect_d4_hosted_selected_source_files(
            source_root=str(root), expected=entry)
    assert type(result) is D4HostedSelectedSourceObservation
    assert len(result.selected) == 1
    assert result.source_file_bytes_verified is True
    assert result.full_boot_image_identity_attested is False
    assert result.actual_loaded_source_graph_attested is False
    assert result.host_provider_attested is False
    assert result.native_launch_allowed is False
    assert events == []


@pytest.mark.parametrize("fault", [
    "wrong_digest", "missing", "symlink", "writable", "hardlink",
])
def test_selected_host_source_fails_closed(tmp_path, fault):
    root, parent, file, entry = _staged(tmp_path)
    if fault == "wrong_digest":
        entry = (("system/dyld-source", "1" * 64),)
    elif fault == "missing":
        file.unlink()
    elif fault == "symlink":
        file.unlink()
        file.symlink_to(root / "outside")
    elif fault == "writable":
        file.chmod(0o666)
    elif fault == "hardlink":
        os.link(file, root / "duplicate")
    with pytest.raises(D4HostedSourceDenied):
        inspect_d4_hosted_selected_source_files(
            source_root=str(root), expected=entry)


@pytest.mark.parametrize("entry", [
    (), (("system/dyld-source", "x" * 64),),
    (("../escape", "a" * 64),),
    (("system//dyld-source", "a" * 64),),
    (("system/dyld-source", "a" * 64), ("system/dyld-source", "a" * 64)),
    (("system/dyld-source", "a" * 64), ("aaa", "a" * 64)),
])
def test_selected_manifest_forgery_and_noncanonical_names_denied(tmp_path, entry):
    root, parent, file, good = _staged(tmp_path)
    with pytest.raises(D4HostedSourceDenied):
        inspect_d4_hosted_selected_source_files(
            source_root=str(root), expected=entry)


def test_real_parent_mode_drift_during_file_read_denied(tmp_path, monkeypatch):
    root, parent, file, entry = _staged(tmp_path)
    before_mode = parent.stat().st_mode & 0o777
    identity = (file.stat().st_dev, file.stat().st_ino)
    base_read = os.read
    visited = []

    def chmod_during_read(fd, n):
        raw = base_read(fd, n)
        st = os.fstat(fd)
        if (not visited and (st.st_dev, st.st_ino) == identity):
            parent.chmod(0o777)
            visited.append(True)
        return raw

    try:
        with monkeypatch.context() as patch:
            patch.setattr(os, "read", chmod_during_read)
            with pytest.raises(D4HostedSourceDenied):
                inspect_d4_hosted_selected_source_files(
                    source_root=str(root), expected=entry)
    finally:
        parent.chmod(before_mode)
    assert visited == [True]


def test_one_use_selected_source_recheck_burns_on_change_and_replay(tmp_path):
    root, parent, file, entry = _staged(tmp_path)
    observed = D4HostedSelectedSourceRecheck(
        source_root=str(root), expected=entry)
    assert observed.recheck_once() is None
    with pytest.raises(D4HostedSourceDenied):
        observed.recheck_once()
    another = D4HostedSelectedSourceRecheck(
        source_root=str(root), expected=entry)
    file.write_bytes(b"modified despite same source manifest\n")
    with pytest.raises(D4HostedSourceDenied):
        another.recheck_once()
    with pytest.raises(D4HostedSourceDenied):
        another.recheck_once()


def test_forged_observation_fields_are_not_an_authority(tmp_path):
    root, parent, file, entry = _staged(tmp_path)
    observed = inspect_d4_hosted_selected_source_files(
        source_root=str(root), expected=entry)
    forged = replace(observed,
                     full_boot_image_identity_attested=True,
                     actual_loaded_source_graph_attested=True,
                     host_provider_attested=True,
                     native_launch_allowed=True)
    assert forged.native_launch_allowed
    # A mutable/forged dataclass is not a proof: no production authorizer
    # accepts this record, and only an instance-owned live recheck is useful.
    assert not observed.native_launch_allowed


def test_one_use_host_receipt_concurrent_callers_burn_exactly_once(tmp_path):
    root, parent, file, entry = _staged(tmp_path)
    binding = D4HostedSelectedSourceRecheck(
        source_root=str(root), expected=entry)

    def compete(_index):
        try:
            binding.recheck_once()
            return "first"
        except D4HostedSourceDenied:
            return "rejected"

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(compete, range(2)))
    assert sorted(results) == ["first", "rejected"]
