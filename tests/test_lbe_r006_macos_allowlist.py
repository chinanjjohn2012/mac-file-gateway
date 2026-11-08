"""Safe T0 for fixed R006 host/source + actual host safety audit."""
import hashlib
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

from gateway import lbe_r006_macos_allowlist as profile
from gateway.lbe_r006_macos_allowlist import (
    D4R006HostAllowlistDenied, verify_r006_fixed_host_allowlist_t0,
)

LOCAL = 0x1000
RDONLY = 0x1


def _env():
    return {
        "GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "pull_request",
        "GITHUB_REPOSITORY": "chinanjjohn2012/mac-file-gateway",
        "GITHUB_RUN_ID": "42460000123", "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_JOB": "observe-macos-15-arm64-t0",
        "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "macOS",
        "RUNNER_ARCH": "ARM64", "ImageOS": "macos15",
        "ImageVersion": "20261104.0514.1",
    }


def _uname(sysname="Darwin", machine="arm64"):
    return SimpleNamespace(sysname=sysname, machine=machine)


def _mounts():
    return (
        ("apfs", "/", "/dev/disk3s1s1", LOCAL),
        ("apfs", "/System/Volumes/Data", "/dev/disk3s5", LOCAL),
        ("devfs", "/dev", "devfs", LOCAL),
    )


def _stage(tmp_path, monkeypatch):
    system = tmp_path / "System"; usr = tmp_path / "usr"
    (system / "Library" / "CoreServices").mkdir(parents=True, exist_ok=True)
    (usr / "bin").mkdir(parents=True, exist_ok=True); (usr / "lib").mkdir(exist_ok=True)
    rows = [
        (system / "Library" / "CoreServices" / "SystemVersion.plist", b"plist"),
        (usr / "bin" / "env", b"env"), (usr / "lib" / "dyld", b"dyld"),
    ]
    for path, data in rows:
        path.write_bytes(data); path.chmod(0o600)
    monkeypatch.setattr(profile, "_SYSTEM_EXPECTED", (
        ("Library/CoreServices/SystemVersion.plist",
         hashlib.sha256(b"plist").hexdigest()),))
    monkeypatch.setattr(profile, "_USR_EXPECTED", (
        ("bin/env", hashlib.sha256(b"env").hexdigest()),
        ("lib/dyld", hashlib.sha256(b"dyld").hexdigest()),))
    return str(system), str(usr)


def _verify(tmp_path, monkeypatch, *, env=None, uname=None, mounts=None,
            release="15.8.2", version=("15.8.2", "24H232")):
    system, usr = _stage(tmp_path, monkeypatch)
    return verify_r006_fixed_host_allowlist_t0(
        environ=_env() if env is None else env,
        macos_release=release, uname=_uname() if uname is None else uname,
        mount_rows=_mounts() if mounts is None else mounts,
        system_version=version, system_root=system, usr_root=usr)


def test_actual_safe_host_and_fixed_previous_values_never_self_grant(
        tmp_path, monkeypatch):
    def forbidden(*_a, **_kw):
        raise AssertionError("host safety T0 cannot execute or signal")
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(os, "kill", forbidden)
    item = _verify(tmp_path, monkeypatch)
    assert item.actual_host_safety_verified is True
    assert item.kernel_sysname == "Darwin" and item.machine == "arm64"
    assert item.run_id == 42460000123 and item.run_attempt == 1
    assert item.no_ambient_credentials_observed is True
    assert item.no_ambient_proxy_observed is True
    assert item.no_writable_nonlocal_mounts_observed is True
    assert len(item.mount_table_fingerprint) == 64
    assert item.full_boot_image_attested is False
    assert item.actual_loaded_graph_proven is False
    assert item.owner_exact_run_grant_verified is False
    assert item.native_launch_allowed is False


@pytest.mark.parametrize("key,value", [
    ("RUNNER_ENVIRONMENT", "self-hosted"), ("RUNNER_ARCH", "X64"),
    ("ImageOS", "macos26"), ("ImageVersion", "20261105.0000.1"),
])
def test_image_or_provider_claim_drift_denied(
        tmp_path, monkeypatch, key, value):
    env=_env(); env[key]=value
    with pytest.raises(D4R006HostAllowlistDenied):
        _verify(tmp_path, monkeypatch, env=env)


@pytest.mark.parametrize("key", [
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "FTP_PROXY",
    "GITHUB_TOKEN", "ACTIONS_RUNTIME_TOKEN", "AWS_SECRET_ACCESS_KEY",
])
def test_stable_ambient_proxy_or_credential_denied(
        tmp_path, monkeypatch, key):
    env=_env(); env[key]="present-but-never-logged"
    with pytest.raises(D4R006HostAllowlistDenied):
        _verify(tmp_path, monkeypatch, env=env)


@pytest.mark.parametrize("uname", [
    SimpleNamespace(sysname="Linux", machine="arm64"),
    SimpleNamespace(sysname="Darwin", machine="x86_64"),
])
def test_actual_platform_mismatch_denied(tmp_path, monkeypatch, uname):
    with pytest.raises(D4R006HostAllowlistDenied):
        _verify(tmp_path, monkeypatch, uname=uname)


def test_writable_nonlocal_mount_denied_but_readonly_nonlocal_is_safe(
        tmp_path, monkeypatch):
    bad=_mounts()+(("nfs","/Volumes/shared","server:/shared",0),)
    with pytest.raises(D4R006HostAllowlistDenied):
        _verify(tmp_path, monkeypatch, mounts=bad)
    readonly=_mounts()+(("nfs","/Volumes/read","server:/read",RDONLY),)
    assert _verify(
        tmp_path, monkeypatch, mounts=readonly
    ).no_writable_nonlocal_mounts_observed is True


def test_os_release_build_and_selected_byte_drift_denied(
        tmp_path, monkeypatch):
    with pytest.raises(D4R006HostAllowlistDenied):
        _verify(tmp_path, monkeypatch, release="15.9")
    with pytest.raises(D4R006HostAllowlistDenied):
        _verify(tmp_path, monkeypatch, version=("15.8.2","24H999"))
    system, usr = _stage(tmp_path, monkeypatch)
    Path(usr, "lib", "dyld").write_bytes(b"changed")
    with pytest.raises(D4R006HostAllowlistDenied):
        verify_r006_fixed_host_allowlist_t0(
            environ=_env(), macos_release="15.8.2", uname=_uname(),
            mount_rows=_mounts(), system_version=("15.8.2","24H232"),
            system_root=system, usr_root=usr)


def test_sanitized_diagnostic_reports_names_not_values(
        tmp_path, monkeypatch):
    env = _env()
    env["HTTPS_PROXY"] = "secret-proxy-value"
    env["MY_PRIVATE_KEY"] = "secret-key-value"
    diagnostic = profile.collect_r006_host_safety_diagnostics_t0(
        environ=env, uname=_uname(), mount_rows=_mounts())
    assert diagnostic["credential_variable_names"] == ("MY_PRIVATE_KEY",)
    assert diagnostic["proxy_variable_names"] == ("HTTPS_PROXY",)
    serialized = str(diagnostic)
    assert "secret-proxy-value" not in serialized
    assert "secret-key-value" not in serialized
    assert diagnostic["native_launch_allowed"] is False
