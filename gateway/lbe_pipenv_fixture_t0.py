"""Read-only no-follow candidate inspection of a Pipenv fixture (T0).

No Pipenv, Python, Go, subprocess, signal or network is started. Even a
passing file/digest check does NOT qualify the actual interpreter/loader,
site startup, installed vendor code, semantic safety or future Popen path.
"""
from __future__ import annotations

from contextlib import ExitStack
from dataclasses import dataclass
import hashlib
import json
import os
import re
import stat


class LbePipenvFixtureT0Denied(ValueError):
    """Unsafe or mismatched read-only first-party fixture snapshot."""


_SHA = re.compile(r"[0-9a-f]{64}\Z")
_FLAGS_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FLAGS_FILE = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
_MAX_FILE_BYTES = 1024 * 1024
_MAX_PYTHON_EXECUTABLE_BYTES = 128 * 1024 * 1024


@dataclass(frozen=True)
class PipenvFixtureSnapshotT0:
    pipfile_sha256: str
    pipfile_lock_sha256: str
    pyvenv_cfg_sha256: str
    python_file_sha256: str
    file_snapshot_observed: bool = True
    status: str = "NONOPERATIVE_PRIVATE_VENV_FILE_SNAPSHOT_T0"
    actual_interpreter_loaded: bool = False
    imported_site_qualified: bool = False
    source_publisher_qualified: bool = False
    native_launch_allowed: bool = False
    product_apply_allowed: bool = False
    blockers: tuple[str, ...] = (
        "UNQUALIFIED_REAL_SELECTED_PYTHON_AND_SEED_IMPORTS",
        "LOADED_SITE_AND_RECORD_UNLISTED_INPUTS_NOT_ATTESTED",
        "SOURCE_ENVIRONMENT_RUNNER_NETWORK_AND_RESOURCE_NOT_ATTESTED",
        "GATE_B_AND_PUBLIC_F1_REMAIN_DENIED",
    )


def _sha(value: object, label: str) -> None:
    if (type(value) is not str or _SHA.fullmatch(value) is None
            or value == "0" * 64):
        raise LbePipenvFixtureT0Denied("invalid expected sha256: " + label)


def _owned(st: os.stat_result, *, directory: bool, label: str) -> None:
    if ((not stat.S_ISDIR(st.st_mode) if directory
         else not stat.S_ISREG(st.st_mode))
            or st.st_uid != os.getuid() or st.st_mode & 0o022
            or (not directory and st.st_nlink != 1)):
        raise LbePipenvFixtureT0Denied("unsafe inode: " + label)


def _open_root_no_follow(path: str) -> int:
    if (type(path) is not str or not 2 <= len(path) <= 2048
            or not path.startswith("/") or "\\" in path
            or any(ord(x) < 33 or ord(x) == 127 for x in path)):
        raise LbePipenvFixtureT0Denied("invalid absolute project root")
    components = path[1:].split("/")
    if any(x in {"", ".", ".."} for x in components):
        raise LbePipenvFixtureT0Denied("noncanonical project root")
    fd = os.open("/", _FLAGS_DIR)
    try:
        # Walk EVERY ancestor with O_NOFOLLOW. A symlinked path prefix is
        # never accepted as a pinned source project.
        for name in components:
            next_fd = os.open(name, _FLAGS_DIR, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        _owned(os.fstat(fd), directory=True, label="project_root")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _dir(parent: int, name: str) -> int:
    fd = os.open(name, _FLAGS_DIR, dir_fd=parent)
    try:
        _owned(os.fstat(fd), directory=True, label=name)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _file(parent: int, name: str, *, executable: bool = False) -> bytes:
    # O_NONBLOCK prevents a malicious FIFO leaf from hanging before fstat.
    fd = os.open(name, _FLAGS_FILE, dir_fd=parent)
    try:
        before = os.fstat(fd)
        _owned(before, directory=False, label=name)
        if executable and not (before.st_mode & stat.S_IXUSR):
            raise LbePipenvFixtureT0Denied("python file not owner-executable")
        if before.st_size > _MAX_FILE_BYTES:
            raise LbePipenvFixtureT0Denied("fixture file oversized")
        data = bytearray()
        while len(data) < before.st_size:
            chunk = os.read(fd, min(8192, before.st_size - len(data)))
            if not chunk:
                raise LbePipenvFixtureT0Denied("fixture file changed during read")
            data.extend(chunk)
        after = os.fstat(fd)
        fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns",
                  "st_ctime_ns", "st_mode", "st_uid", "st_nlink")
        if any(getattr(before, key) != getattr(after, key) for key in fields):
            raise LbePipenvFixtureT0Denied("fixture inode changed during read")
        return bytes(data)
    finally:
        os.close(fd)



def _python_file_sha256(parent: int, name: str) -> str:
    """Stream bounded selected interpreter bytes, NEVER load or launch code.

    This limited nofollow FD digest is not a loaded/interpreter/stdlib or
    post-close pathname identity proof, and cannot authorize native work.
    """
    fd = os.open(name, _FLAGS_FILE, dir_fd=parent)
    try:
        before = os.fstat(fd)
        _owned(before, directory=False, label=name)
        if not (before.st_mode & stat.S_IXUSR):
            raise LbePipenvFixtureT0Denied("python file not owner-executable")
        if not 0 < before.st_size <= _MAX_PYTHON_EXECUTABLE_BYTES:
            raise LbePipenvFixtureT0Denied("fixture python file oversized or empty")
        remaining = before.st_size
        digest = hashlib.sha256()
        while remaining:
            chunk = os.read(fd, min(64 * 1024, remaining))
            if not chunk:
                raise LbePipenvFixtureT0Denied(
                    "fixture python file changed during read")
            digest.update(chunk)
            remaining -= len(chunk)
        after = os.fstat(fd)
        fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns",
                  "st_ctime_ns", "st_mode", "st_uid", "st_nlink")
        if any(getattr(before, k) != getattr(after, k) for k in fields):
            raise LbePipenvFixtureT0Denied(
                "fixture python inode changed during read")
        return digest.hexdigest()
    finally:
        os.close(fd)


def inspect_private_pipenv_fixture_t0(
    *, project_root: str,
    expected_pipfile_sha256: str,
    expected_lock_sha256: str,
    expected_pyvenv_cfg_sha256: str,
    expected_python_sha256: str,
) -> PipenvFixtureSnapshotT0:
    """Read fixed relative files only; NEVER qualify a live Pipenv launch."""
    expected = (
        expected_pipfile_sha256, expected_lock_sha256,
        expected_pyvenv_cfg_sha256, expected_python_sha256,
    )
    for label, digest in zip(
        ("Pipfile", "Pipfile.lock", "pyvenv.cfg", "bin/python"), expected,
    ):
        _sha(digest, label)
    with ExitStack() as stack:
        root = _open_root_no_follow(project_root)
        stack.callback(os.close, root)
        pipfile = _file(root, "Pipfile")
        lock = _file(root, "Pipfile.lock")
        venv = _dir(root, ".venv")
        stack.callback(os.close, venv)
        config = _file(venv, "pyvenv.cfg")
        bin_fd = _dir(venv, "bin")
        stack.callback(os.close, bin_fd)
        python_hash = _python_file_sha256(bin_fd, "python")
        observed = (
            hashlib.sha256(pipfile).hexdigest(),
            hashlib.sha256(lock).hexdigest(),
            hashlib.sha256(config).hexdigest(),
            python_hash,
        )
        if observed != expected:
            raise LbePipenvFixtureT0Denied("fixture source digest mismatch")
        try:
            lock_data = json.loads(lock)
            metadata = lock_data["_meta"]["hash"]["sha256"]
        except (ValueError, TypeError, KeyError):
            raise LbePipenvFixtureT0Denied("unqualified Pipfile.lock format") from None
        if type(metadata) is not str or _SHA.fullmatch(metadata) is None:
            raise LbePipenvFixtureT0Denied("unqualified Pipfile.lock metadata")
    return PipenvFixtureSnapshotT0(*observed)


def authorize_native_pipenv_from_t0(_snapshot: object) -> None:
    """No T0 file snapshot is an executable or source-security capability."""
    raise LbePipenvFixtureT0Denied(
        "PIPENV_NATIVE=NOT_RUN: real selected loader/site and Gate B unproven")
