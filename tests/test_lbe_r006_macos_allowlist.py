"""Safe T0 for fixed prior-run macOS source allowlist candidate."""
import hashlib
import os
from pathlib import Path
import subprocess
import pytest
from gateway import lbe_r006_macos_allowlist as profile
from gateway.lbe_r006_macos_allowlist import (
    D4R006HostAllowlistDenied, verify_r006_fixed_host_allowlist_t0,
)
def _env():
    return {
        "GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "pull_request",
        "GITHUB_REPOSITORY": "chinanjjohn2012/mac-file-gateway",
        "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "macOS",
        "RUNNER_ARCH": "ARM64", "ImageOS": "macos15",
        "ImageVersion": "20261104.0514.1",
    }
def _stage(tmp_path, monkeypatch):
    system = tmp_path / "System"; usr = tmp_path / "usr"
    (system / "Library" / "CoreServices").mkdir(parents=True)
    (usr / "bin").mkdir(parents=True); (usr / "lib").mkdir()
    rows = [
        (system / "Library" / "CoreServices" / "SystemVersion.plist", b"plist"),
        (usr / "bin" / "env", b"env"), (usr / "lib" / "dyld", b"dyld"),
    ]
    for path, data in rows:
        path.write_bytes(data); path.chmod(0o600)
    monkeypatch.setattr(profile, "_SYSTEM_EXPECTED", (
        ("Library/CoreServices/SystemVersion.plist", hashlib.sha256(b"plist").hexdigest()),))
    monkeypatch.setattr(profile, "_USR_EXPECTED", (
        ("bin/env", hashlib.sha256(b"env").hexdigest()),
        ("lib/dyld", hashlib.sha256(b"dyld").hexdigest()),))
    return str(system), str(usr)
def test_fixed_previous_values_rechecked_but_never_grant(tmp_path, monkeypatch):
    system, usr = _stage(tmp_path, monkeypatch)
    def forbidden(*_a, **_kw): raise AssertionError("fixed source T0 cannot execute or signal")
    monkeypatch.setattr(subprocess, "Popen", forbidden); monkeypatch.setattr(os, "kill", forbidden)
    item = verify_r006_fixed_host_allowlist_t0(
        environ=_env(), macos_release="15.8.2", system_root=system, usr_root=usr)
    assert item.selected_source_bytes_verified is True
    assert item.independently_reviewed_allowlist is False
    assert item.full_boot_image_attested is False
    assert item.actual_loaded_graph_proven is False
    assert item.owner_exact_run_grant_verified is False
    assert item.native_launch_allowed is False
@pytest.mark.parametrize("key,value", [
    ("RUNNER_ENVIRONMENT", "self-hosted"), ("RUNNER_ARCH", "X64"),
    ("ImageOS", "macos26"), ("ImageVersion", "20261105.0000.1"),
])
def test_image_or_provider_claim_drift_denied(tmp_path, monkeypatch, key, value):
    system, usr = _stage(tmp_path, monkeypatch); env = _env(); env[key] = value
    with pytest.raises(D4R006HostAllowlistDenied):
        verify_r006_fixed_host_allowlist_t0(
            environ=env, macos_release="15.8.2", system_root=system, usr_root=usr)
def test_os_release_and_selected_byte_drift_denied(tmp_path, monkeypatch):
    system, usr = _stage(tmp_path, monkeypatch)
    with pytest.raises(D4R006HostAllowlistDenied):
        verify_r006_fixed_host_allowlist_t0(
            environ=_env(), macos_release="15.9", system_root=system, usr_root=usr)
    Path(usr, "lib", "dyld").write_bytes(b"changed")
    with pytest.raises(D4R006HostAllowlistDenied):
        verify_r006_fixed_host_allowlist_t0(
            environ=_env(), macos_release="15.8.2", system_root=system, usr_root=usr)
