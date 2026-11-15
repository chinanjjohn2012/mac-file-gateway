"""Read-only staged Go file identity snapshot for LBE D5 SAFE T0.

This verifies a few *selected* first-party file bytes only. It does not
launch Go, attest every Go stdlib/loader/embedded source, prevent TOCTOU after
closing descriptors, confine arbitrary project code or authorize PRODUCT_T1.
"""
from __future__ import annotations

from contextlib import ExitStack
from dataclasses import dataclass
import hashlib
import os
import re
import stat


class LbeGoFixtureT0Denied(ValueError):
    """Unqualified read-only staged Go candidate; no native process begun."""


_SHA = re.compile(r"[0-9a-f]{64}\Z")
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
_MAX_FILE_BYTES = 128 * 1024 * 1024
_DARWIN_TOOL = ("pkg", "tool", "darwin_arm64")


@dataclass(frozen=True)
class GoStagedFilesSnapshotT0:
    go_sha256: str
    compile_sha256: str
    link_sha256: str
    status: str = "NONOPERATIVE_STAGED_GO_FILES_T0"
    file_bytes_observed: bool = True
    loaded_toolchain_qualified: bool = False
    compiled_source_closure_qualified: bool = False
    actual_os_limits_enforced: bool = False
    native_launch_allowed: bool = False
    product_apply_allowed: bool = False
    blockers: tuple[str, ...] = (
        "ACTUAL_GO_LOADER_AND_STD_LIB_SOURCE_NOT_ATTESTED",
        "GO_PACKAGE_MODULE_AND_TOOLCHAIN_CLOSURE_NOT_ATTESTED",
        "POST_SNAPSHOT_PATHNAME_EXEC_RACE_NOT_CLOSED",
        "HOST_NETWORK_AND_RESOURCE_ENFORCEMENT_NOT_ESTABLISHED",
        "EXISTING_NATIVE_GATE_B_AND_PRODUCT_F1_DENY_STILL_ACTIVE",
    )


def _parts(path: object, label: str) -> tuple[str, ...]:
    if type(path) is not str or not 2 <= len(path) <= 2048:
        raise LbeGoFixtureT0Denied("invalid absolute path: " + label)
    if (not path.startswith("/") or "\\" in path or ":" in path
            or any(ord(ch) < 33 or ord(ch) == 127 for ch in path)):
        raise LbeGoFixtureT0Denied("invalid absolute path: " + label)
    components = path[1:].split("/")
    if any(comp in {"", ".", ".."} for comp in components):
        raise LbeGoFixtureT0Denied("noncanonical absolute path: " + label)
    return tuple(components)


def _digest(value: object, label: str) -> None:
    if (type(value) is not str or _SHA.fullmatch(value) is None
            or value == "0" * 64):
        raise LbeGoFixtureT0Denied("invalid expected hash: " + label)


def _check_dir(fd: int, label: str) -> None:
    st = os.fstat(fd)
    if (not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid()
            or st.st_mode & 0o022):
        raise LbeGoFixtureT0Denied("untrusted staged directory: " + label)


def _open_dir(parent: int, name: str) -> int:
    fd = os.open(name, _DIR_FLAGS, dir_fd=parent)
    try:
        _check_dir(fd, name)
    except BaseException:
        os.close(fd)
        raise
    return fd


def _open_private_root(path_parts: tuple[str, ...], stack: ExitStack) -> int:
    fd = os.open("/", _DIR_FLAGS)
    stack.callback(os.close, fd)
    # Ancestors may be OS-owned; check ownership from private_root onwards.
    for part in path_parts:
        next_fd = os.open(part, _DIR_FLAGS, dir_fd=fd)
        stack.callback(os.close, next_fd)
        fd = next_fd
    _check_dir(fd, "private_root")
    return fd


def _file_hash(parent: int, name: str) -> str:
    fd = os.open(name, _FILE_FLAGS, dir_fd=parent)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode)
                or before.st_uid != os.getuid()
                or before.st_mode & 0o022 or before.st_nlink != 1
                or not before.st_mode & stat.S_IXUSR
                or not 0 < before.st_size <= _MAX_FILE_BYTES):
            raise LbeGoFixtureT0Denied("unsafe staged Go executable: " + name)
        digest = hashlib.sha256()
        count = 0
        while True:
            chunk = os.read(fd, 64 * 1024)
            if not chunk:
                break
            count += len(chunk)
            if count > _MAX_FILE_BYTES:
                raise LbeGoFixtureT0Denied("staged Go executable oversized")
            digest.update(chunk)
        after = os.fstat(fd)
        fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns",
                  "st_ctime_ns", "st_mode", "st_uid", "st_nlink")
        if (count != before.st_size or
                any(getattr(before, k) != getattr(after, k) for k in fields)):
            raise LbeGoFixtureT0Denied("staged Go file changed during read")
        return digest.hexdigest()
    finally:
        os.close(fd)


def inspect_staged_go_files_t0(
    *, private_root: str, goroot: str,
    expected_go_sha256: str, expected_compile_sha256: str,
    expected_link_sha256: str,
) -> GoStagedFilesSnapshotT0:
    """Inspect private Go binary/compile/link bytes without running a tool."""
    private = _parts(private_root, "private_root")
    root = _parts(goroot, "goroot")
    if len(root) <= len(private) or root[:len(private)] != private:
        raise LbeGoFixtureT0Denied("Go root outside declared private staging")
    expected = (expected_go_sha256, expected_compile_sha256,
                expected_link_sha256)
    for label, digest in zip(("go", "compile", "link"), expected):
        _digest(digest, label)
    if len(set(expected)) != 3:
        raise LbeGoFixtureT0Denied("Go tool file hashes unexpectedly identical")

    try:
        with ExitStack() as stack:
            fd = _open_private_root(private, stack)
            for part in root[len(private):]:
                fd = _open_dir(fd, part)
                stack.callback(os.close, fd)
            go_dir = _open_dir(fd, "bin")
            stack.callback(os.close, go_dir)
            go_hash = _file_hash(go_dir, "go")
            pkg = _open_dir(fd, _DARWIN_TOOL[0])
            stack.callback(os.close, pkg)
            tool = _open_dir(pkg, _DARWIN_TOOL[1])
            stack.callback(os.close, tool)
            arch = _open_dir(tool, _DARWIN_TOOL[2])
            stack.callback(os.close, arch)
            compile_hash = _file_hash(arch, "compile")
            link_hash = _file_hash(arch, "link")
    except OSError:
        raise LbeGoFixtureT0Denied("Go staging sources unavailable or linked") from None

    if (go_hash, compile_hash, link_hash) != expected:
        raise LbeGoFixtureT0Denied("staged Go tool bytes do not match fixed hashes")
    return GoStagedFilesSnapshotT0(*expected)


def authorize_native_go_from_t0(_receipt: object) -> None:
    """No snapshot can authorize Go or bypass current external-source gates."""
    raise LbeGoFixtureT0Denied(
        "NATIVE_GO=NOT_RUN; PRODUCT_EXEC=DENIED; "
        "real loaded source, host-risk and owner permission not qualified")
