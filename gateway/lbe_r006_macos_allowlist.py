"""Fixed R006 selected-host profile with fresh pre-Popen host safety audit.

The finite selected-file allowlist remains a deliberately weaker R006 witness,
not full-image or complete loaded-graph attestation.  Unlike the old candidate,
this verifier also reads the ACTUAL Darwin kernel/architecture, pinned
SystemVersion.plist bytes, ambient credential/proxy names and Darwin mount table.
Unsafe or unavailable host facts DENY; no value of a secret/proxy is logged.
"""
from __future__ import annotations

import ctypes
from dataclasses import dataclass
import hashlib
import json
import os
import platform
import plistlib
import re

from .lbe_hosted_source_probe import (
    D4HostedSelectedSourceObservation,
    inspect_d4_hosted_selected_source_files,
)

IMAGE_OS = "macos15"
IMAGE_VERSION = "20261104.0514.1"
MACOS_VERSION = "15.8.2"
OS_BUILD = "24H232"
_SYSTEM_EXPECTED = (
    ("Library/CoreServices/SystemVersion.plist",
     "7789975d8ee10cd0a331a22c8fded5232cdc3c4462fad0561a604cad5bb0d07e"),
)
_USR_EXPECTED = (
    ("bin/env",
     "ebda86b855682a1910382f8d03578f8df114c83277893d86082240b7e7345ed0"),
    ("lib/dyld",
     "02a4b237c9a87ea11ff4eeaac7bee360bd8cc94b07ea2e697cf88d5bd85610f9"),
)
_SECRET_NAMES = frozenset({
    "GITHUB_TOKEN", "GH_TOKEN", "ACTIONS_RUNTIME_TOKEN",
    "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY", "GOOGLE_APPLICATION_CREDENTIALS",
    "AZURE_CLIENT_SECRET", "SSH_AUTH_SOCK", "CI_JOB_TOKEN",
})
_SECRET_ENDINGS = (
    "_TOKEN", "_SECRET", "_PASSWORD", "_PRIVATE_KEY",
    "_ACCESS_KEY", "_CREDENTIALS",
)
_PROXY_NAMES = frozenset({
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "FTP_PROXY",
})
_RUN_ID = re.compile(r"[1-9][0-9]{0,18}\Z")
_JOB = re.compile(r"[A-Za-z0-9_.-]{1,120}\Z")
_MNT_RDONLY = 0x00000001
_MNT_LOCAL = 0x00001000
_MNT_NOWAIT = 2


def _fingerprint(value: object) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=True).encode("ascii")
    return hashlib.sha256(raw).hexdigest()


R006_HOST_SOURCE_FINGERPRINT = _fingerprint({
    "image_os": IMAGE_OS, "image_version": IMAGE_VERSION,
    "macos_version": MACOS_VERSION, "os_build": OS_BUILD,
    "system": _SYSTEM_EXPECTED, "usr": _USR_EXPECTED,
})
R006_RUNNER_PROFILE_FINGERPRINT = _fingerprint({
    "profile": "r007-fresh-host-safety-v1",
    "provider": "github-hosted", "runner_os": "macOS",
    "runner_arch": "ARM64", "image_os": IMAGE_OS,
    "image_version": IMAGE_VERSION, "macos_version": MACOS_VERSION,
    "os_build": OS_BUILD, "selected_source": R006_HOST_SOURCE_FINGERPRINT,
    "requires": [
        "actual-darwin-arm64", "no-ambient-credential-names",
        "no-ambient-proxy-settings", "no-writable-nonlocal-mounts",
        "exact-run-attempt-job",
    ],
})


class D4R006HostAllowlistDenied(ValueError):
    """Current host is not the fixed reviewed-candidate R006 profile."""


@dataclass(frozen=True, slots=True)
class D4R006HostAllowlistObservation:
    system: D4HostedSelectedSourceObservation
    usr: D4HostedSelectedSourceObservation
    source_fingerprint: str
    runner_profile_fingerprint: str
    image_version: str
    macos_version: str
    os_build: str
    kernel_sysname: str = ""
    machine: str = ""
    run_id: int = 0
    run_attempt: int = 0
    job_name: str = ""
    mount_table_fingerprint: str = ""
    actual_host_safety_verified: bool = False
    no_ambient_credentials_observed: bool = False
    no_ambient_proxy_observed: bool = False
    no_writable_nonlocal_mounts_observed: bool = False
    selected_source_bytes_verified: bool = True
    independently_reviewed_allowlist: bool = False
    full_boot_image_attested: bool = False
    actual_loaded_graph_proven: bool = False
    owner_exact_run_grant_verified: bool = False
    native_launch_allowed: bool = False
    status: str = "R006_FIXED_HOST_SOURCE_T0_MATCH_NOT_EXEC_AUTHORITY"


class _Fsid(ctypes.Structure):
    _fields_ = [("val", ctypes.c_int32 * 2)]


class _DarwinStatfs(ctypes.Structure):
    _fields_ = [
        ("f_bsize", ctypes.c_uint32),
        ("f_iosize", ctypes.c_int32),
        ("f_blocks", ctypes.c_uint64),
        ("f_bfree", ctypes.c_uint64),
        ("f_bavail", ctypes.c_uint64),
        ("f_files", ctypes.c_uint64),
        ("f_ffree", ctypes.c_uint64),
        ("f_fsid", _Fsid),
        ("f_owner", ctypes.c_uint32),
        ("f_type", ctypes.c_uint32),
        ("f_flags", ctypes.c_uint32),
        ("f_fssubtype", ctypes.c_uint32),
        ("f_fstypename", ctypes.c_char * 16),
        ("f_mntonname", ctypes.c_char * 1024),
        ("f_mntfromname", ctypes.c_char * 1024),
        ("f_flags_ext", ctypes.c_uint32),
        ("f_reserved", ctypes.c_uint32 * 7),
    ]


def _decode_c(value: object) -> str:
    raw = bytes(value).split(b"\0", 1)[0]
    try:
        result = raw.decode("utf-8", "strict")
    except UnicodeDecodeError:
        raise D4R006HostAllowlistDenied("Darwin mount name is non-UTF8") from None
    if not result or "\x00" in result:
        raise D4R006HostAllowlistDenied("Darwin mount name unavailable")
    return result


def _darwin_mount_rows() -> tuple[tuple[str, str, str, int], ...]:
    """Read getmntinfo in-process; never spawn mount/df or execute project code."""
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        func = libc.getmntinfo
    except (AttributeError, OSError):
        raise D4R006HostAllowlistDenied("Darwin getmntinfo unavailable") from None
    func.argtypes = [
        ctypes.POINTER(ctypes.POINTER(_DarwinStatfs)), ctypes.c_int]
    func.restype = ctypes.c_int
    pointer = ctypes.POINTER(_DarwinStatfs)()
    count = func(ctypes.byref(pointer), _MNT_NOWAIT)
    if not 1 <= count <= 512 or not bool(pointer):
        raise D4R006HostAllowlistDenied("Darwin mount table unavailable")
    rows = []
    for index in range(count):
        item = pointer[index]
        rows.append((
            _decode_c(item.f_fstypename), _decode_c(item.f_mntonname),
            _decode_c(item.f_mntfromname), int(item.f_flags),
        ))
    rows.sort()
    if len(rows) != len(set(rows)):
        raise D4R006HostAllowlistDenied("Darwin mount table is ambiguous")
    return tuple(rows)


def _checked_mount_rows(value: object) -> tuple[tuple[str, str, str, int], ...]:
    if type(value) is not tuple or not 1 <= len(value) <= 512:
        raise D4R006HostAllowlistDenied("Darwin mount table missing/oversized")
    checked = []
    for row in value:
        if (type(row) is not tuple or len(row) != 4
                or any(type(x) is not str or not x for x in row[:3])
                or type(row[3]) is not int or row[3] < 0):
            raise D4R006HostAllowlistDenied("Darwin mount row malformed")
        checked.append(row)
    rows = tuple(sorted(checked))
    if len(rows) != len(set(rows)) or not any(row[1] == "/" for row in rows):
        raise D4R006HostAllowlistDenied("Darwin root mount identity missing")
    return rows


def _audit_mounts(rows: tuple[tuple[str, str, str, int], ...]) -> str:
    """Reject every writable non-local mount; hash identities, never paths in output."""
    unsafe = [
        row for row in rows
        if not (row[3] & _MNT_RDONLY) and not (row[3] & _MNT_LOCAL)
    ]
    if unsafe:
        raise D4R006HostAllowlistDenied(
            "writable non-local/shared mount is present")
    return _fingerprint(rows)


def _actual_system_version(system_root: str) -> tuple[str, str]:
    path = os.path.join(
        system_root, "Library", "CoreServices", "SystemVersion.plist")
    fd = -1
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        st = os.fstat(fd)
        if not 0 < st.st_size <= 65536:
            raise D4R006HostAllowlistDenied("SystemVersion.plist size invalid")
        raw = os.read(fd, st.st_size + 1)
        after = os.fstat(fd)
        if (len(raw) != st.st_size
                or (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns,
                    st.st_ctime_ns, st.st_mode, st.st_uid, st.st_nlink)
                != (after.st_dev, after.st_ino, after.st_size,
                    after.st_mtime_ns, after.st_ctime_ns, after.st_mode,
                    after.st_uid, after.st_nlink)
                or hashlib.sha256(raw).hexdigest() != _SYSTEM_EXPECTED[0][1]):
            raise D4R006HostAllowlistDenied(
                "SystemVersion.plist identity changed")
        obj = plistlib.loads(raw)
    except (OSError, ValueError, plistlib.InvalidFileException):
        raise D4R006HostAllowlistDenied(
            "SystemVersion.plist unavailable") from None
    finally:
        if fd >= 0:
            os.close(fd)
    if type(obj) is not dict:
        raise D4R006HostAllowlistDenied("SystemVersion.plist malformed")
    version = obj.get("ProductVersion")
    build = obj.get("ProductBuildVersion")
    if type(version) is not str or type(build) is not str:
        raise D4R006HostAllowlistDenied("SystemVersion.plist fields missing")
    return version, build


def collect_r006_host_safety_diagnostics_t0(
    *, environ=None, uname=None, mount_rows=None,
) -> dict[str, object]:
    """Sanitized host blockers for T0 diagnostics; NEVER launch authority."""
    env = os.environ if environ is None else environ
    actual = os.uname() if uname is None else uname
    credential_names = tuple(sorted(
        name for name, value in env.items()
        if bool(value) and (
            name.upper() in _SECRET_NAMES
            or name.upper().endswith(_SECRET_ENDINGS)
        )
    ))
    proxy_names = tuple(sorted(
        name for name, value in env.items()
        if bool(value) and name.upper() in _PROXY_NAMES
    ))
    rows = _checked_mount_rows(
        _darwin_mount_rows() if mount_rows is None else mount_rows)
    unsafe = tuple(sorted(
        (row[0], row[1]) for row in rows
        if not (row[3] & _MNT_RDONLY) and not (row[3] & _MNT_LOCAL)
    ))
    return {
        "status": "R007_HOST_SAFETY_DIAGNOSTIC_ONLY_NOT_AUTHORITY",
        "kernel_sysname": getattr(actual, "sysname", ""),
        "machine": getattr(actual, "machine", ""),
        "credential_variable_names": credential_names,
        "proxy_variable_names": proxy_names,
        "mount_count": len(rows),
        "writable_nonlocal_mount_types_and_targets": unsafe,
        "native_launch_allowed": False,
    }


def verify_r006_fixed_host_allowlist_t0(
    *, environ=None, macos_release=None, uname=None, mount_rows=None,
    system_version=None, system_root="/System", usr_root="/usr",
) -> D4R006HostAllowlistObservation:
    """Fresh actual host safety + finite selected-source verification."""
    env = os.environ if environ is None else environ
    release = platform.mac_ver()[0] if macos_release is None else macos_release
    actual = os.uname() if uname is None else uname
    if (getattr(actual, "sysname", None) != "Darwin"
            or getattr(actual, "machine", None) not in ("arm64", "aarch64")):
        raise D4R006HostAllowlistDenied("actual host is not Darwin ARM64")
    expected = {
        "GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "pull_request",
        "GITHUB_REPOSITORY": "chinanjjohn2012/mac-file-gateway",
        "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "macOS",
        "RUNNER_ARCH": "ARM64", "ImageOS": IMAGE_OS,
        "ImageVersion": IMAGE_VERSION,
    }
    if any(type(env.get(k)) is not str or env.get(k) != v
           for k, v in expected.items()):
        raise D4R006HostAllowlistDenied("current GitHub/macOS image claim mismatch")
    run_id = env.get("GITHUB_RUN_ID", "")
    run_attempt = env.get("GITHUB_RUN_ATTEMPT", "")
    job_name = env.get("GITHUB_JOB", "")
    if (_RUN_ID.fullmatch(run_id) is None
            or _RUN_ID.fullmatch(run_attempt) is None
            or _JOB.fullmatch(job_name) is None):
        raise D4R006HostAllowlistDenied("current run/attempt/job claim missing")
    if release != MACOS_VERSION:
        raise D4R006HostAllowlistDenied("current macOS release mismatch")

    credentials = any(bool(value) and (
        name.upper() in _SECRET_NAMES
        or name.upper().endswith(_SECRET_ENDINGS)
    ) for name, value in env.items())
    proxies = any(
        bool(value) and name.upper() in _PROXY_NAMES
        for name, value in env.items())
    if credentials:
        raise D4R006HostAllowlistDenied(
            "ambient credential-bearing environment is present")
    if proxies:
        raise D4R006HostAllowlistDenied(
            "ambient proxy environment is present")

    rows = _checked_mount_rows(
        _darwin_mount_rows() if mount_rows is None else mount_rows)
    mount_fingerprint = _audit_mounts(rows)
    if system_version is None:
        actual_version, actual_build = _actual_system_version(system_root)
    else:
        if (type(system_version) is not tuple or len(system_version) != 2
                or any(type(x) is not str or not x for x in system_version)):
            raise D4R006HostAllowlistDenied(
                "injected SystemVersion identity malformed")
        actual_version, actual_build = system_version
    if actual_version != MACOS_VERSION or actual_build != OS_BUILD:
        raise D4R006HostAllowlistDenied("actual macOS version/build mismatch")

    try:
        system = inspect_d4_hosted_selected_source_files(
            source_root=system_root, expected=_SYSTEM_EXPECTED)
        usr = inspect_d4_hosted_selected_source_files(
            source_root=usr_root, expected=_USR_EXPECTED)
    except (OSError, ValueError):
        raise D4R006HostAllowlistDenied(
            "fixed selected host source mismatch") from None
    return D4R006HostAllowlistObservation(
        system=system, usr=usr,
        source_fingerprint=R006_HOST_SOURCE_FINGERPRINT,
        runner_profile_fingerprint=R006_RUNNER_PROFILE_FINGERPRINT,
        image_version=IMAGE_VERSION, macos_version=MACOS_VERSION,
        os_build=OS_BUILD, kernel_sysname=actual.sysname,
        machine=actual.machine, run_id=int(run_id),
        run_attempt=int(run_attempt), job_name=job_name,
        mount_table_fingerprint=mount_fingerprint,
        actual_host_safety_verified=True,
        no_ambient_credentials_observed=True,
        no_ambient_proxy_observed=True,
        no_writable_nonlocal_mounts_observed=True,
    )
