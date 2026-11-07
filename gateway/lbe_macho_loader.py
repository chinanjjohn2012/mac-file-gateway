"""Read-only Darwin ARM64 Mach-O direct loader declaration inspection.

This is PRODUCT source identity, not a dyld execution or full load closure.
The actual binary is read from the already selected private source by
owner-controlled nofollow file descriptors. Validated declarations include
LC_LOAD_DYLIB, weak/lazy/reexport/upward dylibs, LC_RPATH and dylinker.

A Mach-O LC_LOAD_DYLIB is a declared *possible* direct dependency, not
evidence of the code that dyld will resolve from an immutable host image.
Unresolved @rpath, @loader_path, @executable_path, system install names,
LC_CODE_SIGNATURE and static headers never establish actual loaded code,
signature trust, provider, whole-child resource limits or T1 authority.

No binary import, Popen, otool, codesign, signaling or external command.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
import stat
import struct
from typing import TYPE_CHECKING

from .lbe_runtime_source import (
    D4RuntimeSourceDenied, _below, _canonical, _open_private_directory,
)

if TYPE_CHECKING:
    from .lbe_launch_recipe import D4NativeLaunchRecipe
    from .lbe_runtime_source import D4RuntimeSourceObservation


class D4MachOLoaderDenied(ValueError):
    """Source Mach-O header or loaded-library declaration is unqualified."""


_MH64_LE = b"\xcf\xfa\xed\xfe"
_FAT32_BE = b"\xca\xfe\xba\xbe"
_FAT64_BE = b"\xca\xfe\xba\xbf"
_CPU_ARM64 = 0x0100000C
_MAX_FILE = 128 * 1024 * 1024
_MAX_LOAD_COMMAND_BYTES = 2 * 1024 * 1024
_MAX_COMMANDS = 4096
_MAX_SLICES = 8
_FSTAT_FIELDS = ("st_dev", "st_ino", "st_size", "st_mtime_ns",
                 "st_ctime_ns", "st_mode", "st_uid", "st_nlink")
_DYLIB_LOADS = frozenset((
    0x0C, 0x18 | 0x80000000, 0x1F | 0x80000000,
    0x20, 0x23 | 0x80000000,
))
_DYLINKER = 0x0E
_RPATH = 0x1C | 0x80000000
_CODE_SIGNATURE = 0x1D


@dataclass(frozen=True, slots=True)
class D4MachOLoaderObservation:
    selected_relative_executable: str
    selected_sha256: str
    selected_cpu: str
    selected_format: str
    declared_direct_libraries: tuple[str, ...]
    declared_rpaths: tuple[str, ...]
    declared_dylinker: tuple[str, ...]
    unresolved_install_names: tuple[str, ...]
    code_signature_command_present: bool
    selected_file_bytes_checked: bool = True
    format_header_inspected: bool = True
    actual_dyld_resolution_attested: bool = False
    full_loaded_source_graph_attested: bool = False
    immutable_runner_image_attested: bool = False
    code_signature_verified: bool = False
    whole_child_resource_domain_enforced: bool = False
    native_launch_allowed: bool = False
    status: str = "STATIC_MACHO_ARM64_DIRECT_DECLARATIONS_ONLY"


def _read_at(fd: int, off: int, length: int, size: int) -> bytes:
    if (type(off) is not int or type(length) is not int
            or off < 0 or length < 0 or off + length > size):
        raise D4MachOLoaderDenied("Mach-O read outside selected inode")
    data = os.pread(fd, length, off)
    if len(data) != length:
        raise D4MachOLoaderDenied("Mach-O source truncated")
    return data


def _selected_slice(fd: int, length: int) -> tuple[int, int, str]:
    header = _read_at(fd, 0, min(length, 8), length)
    if header.startswith(_MH64_LE):
        return 0, length, "THIN_64"
    if not (header.startswith(_FAT32_BE) or header.startswith(_FAT64_BE)):
        raise D4MachOLoaderDenied("selected source is not supported Mach-O")
    if len(header) < 8:
        raise D4MachOLoaderDenied("Mach-O fat header truncated")
    count = struct.unpack_from(">I", header, 4)[0]
    if not 1 <= count <= _MAX_SLICES:
        raise D4MachOLoaderDenied("Mach-O universal slice count unqualified")
    fat64 = header[:4] == _FAT64_BE
    entry_len = 32 if fat64 else 20
    table = _read_at(fd, 8, count * entry_len, length)
    chosen = []
    for i in range(count):
        if fat64:
            cpu, _subcpu, off, size, _align, _reserved = struct.unpack_from(
                ">IIQQII", table, i * entry_len)
        else:
            cpu, _subcpu, off, size, _align = struct.unpack_from(
                ">IIIII", table, i * entry_len)
        if (off < 8 + count * entry_len or size < 32
                or off + size > length):
            raise D4MachOLoaderDenied("Mach-O fat slice escapes file bounds")
        if cpu == _CPU_ARM64:
            chosen.append((off, size))
    if len(chosen) != 1:
        raise D4MachOLoaderDenied("one exact Darwin ARM64 slice required")
    off, size = chosen[0]
    return off, size, "FAT_64" if fat64 else "FAT_32"


def _load_name(command: bytes, minimum: int) -> str:
    if len(command) < minimum:
        raise D4MachOLoaderDenied("short Mach-O loader command")
    location = struct.unpack_from("<I", command, 8)[0]
    if location < minimum or location >= len(command):
        raise D4MachOLoaderDenied("Mach-O dynamic loader name offset invalid")
    name = command[location:].split(b"\x00", 1)
    if len(name) != 2 or not name[0] or len(name[0]) > 1024:
        raise D4MachOLoaderDenied("missing terminated Mach-O install name")
    try:
        text = name[0].decode("utf-8")
    except UnicodeDecodeError:
        raise D4MachOLoaderDenied("Mach-O install name not UTF-8") from None
    if (any(ord(c) < 33 or ord(c) == 127 for c in text)
            or "\\" in text):
        raise D4MachOLoaderDenied("unsafe Mach-O dynamic loader install name")
    return text


def _parse_commands(
    fd: int, total_size: int, slice_offset: int, slice_size: int,
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...], bool]:
    header = _read_at(fd, slice_offset, 32, total_size)
    if header[:4] != _MH64_LE:
        raise D4MachOLoaderDenied("selected architecture is not little-endian Mach-O64")
    (_magic, cpu, _subtype, file_type, count, command_bytes,
     _flags, _reserved) = struct.unpack("<IIIIIIII", header)
    if cpu != _CPU_ARM64 or file_type not in (2, 6, 8):
        raise D4MachOLoaderDenied("unqualified Mach-O target architecture or type")
    if (count > _MAX_COMMANDS or command_bytes > _MAX_LOAD_COMMAND_BYTES
            or (count == 0) != (command_bytes == 0)
            or command_bytes < 8 * count
            or 32 + command_bytes > slice_size):
        raise D4MachOLoaderDenied("Mach-O command area exceeds bounded header")
    raw = _read_at(fd, slice_offset + 32, command_bytes, total_size)
    cursor = 0
    libs: list[str] = []
    rpaths: list[str] = []
    dylinker: list[str] = []
    signature = False
    for _ in range(count):
        if cursor + 8 > len(raw):
            raise D4MachOLoaderDenied("Mach-O load command truncated")
        cmd, cmdsize = struct.unpack_from("<II", raw, cursor)
        if (cmdsize < 8 or cmdsize % 4 or cursor + cmdsize > len(raw)):
            raise D4MachOLoaderDenied("invalid Mach-O load command extent")
        segment = raw[cursor:cursor + cmdsize]
        if cmd in _DYLIB_LOADS:
            libs.append(_load_name(segment, 24))
        elif cmd == _RPATH:
            rpaths.append(_load_name(segment, 12))
        elif cmd == _DYLINKER:
            dylinker.append(_load_name(segment, 12))
        elif cmd == _CODE_SIGNATURE:
            if len(segment) != 16:
                raise D4MachOLoaderDenied("invalid Mach-O code-signature command")
            signature = True
        # Unknown required dyld semantics are NOT proved by this parser.
        # We still report only declarations, never an executable grant.
        cursor += cmdsize
    if cursor != len(raw):
        raise D4MachOLoaderDenied("Mach-O load command table not fully consumed")
    return tuple(libs), tuple(rpaths), tuple(dylinker), signature


def inspect_d4_selected_macho_loader(
    *, private_root: str, selected_executable: str, expected_sha256: str,
    require_execute_bit: bool = True,
) -> D4MachOLoaderObservation:
    """Read a pinned Mach-O binary, with correct executable/dylib modes.

    Selected go/python/compiler/linker executables MUST have the owner
    executable bit; Mach-O dylibs are often non-executable regular files,
    whose safe owner/byte/mode identity is still verified by nofollow FDs.
    This distinction does not grant any execution or dyld load permission.
    """
    if type(require_execute_bit) is not bool:
        raise D4MachOLoaderDenied("invalid executable/dylib source policy")
    if (type(expected_sha256) is not str
            or len(expected_sha256) != 64
            or any(c not in "0123456789abcdef" for c in expected_sha256)):
        raise D4MachOLoaderDenied("missing expected selected executable identity")
    fd = None
    dir_fd = None
    try:
        root = _canonical(private_root, "private root")
        selected = _canonical(selected_executable, "selected executable")
        _below(root, selected)
        dirname, name = selected.rsplit("/", 1)
        dir_fd = _open_private_directory(dirname, root)
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW
                     | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=dir_fd)
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                or before.st_nlink != 1 or before.st_mode & 0o022
                or (require_execute_bit and not before.st_mode & stat.S_IXUSR)
                or not 32 <= before.st_size <= _MAX_FILE):
            raise D4MachOLoaderDenied("unqualified native executable inode")
        offset, size, format_name = _selected_slice(fd, before.st_size)
        libs, rpaths, dyld, signature = _parse_commands(
            fd, before.st_size, offset, size)
        hashed = hashlib.sha256()
        remaining = before.st_size
        while remaining:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                raise D4MachOLoaderDenied("staged executable truncated during hash")
            hashed.update(chunk)
            remaining -= len(chunk)
        after = os.fstat(fd)
        if (any(getattr(before, x) != getattr(after, x)
                for x in _FSTAT_FIELDS)
                or hashed.hexdigest() != expected_sha256):
            raise D4MachOLoaderDenied("staged Mach-O source changed during inspection")
        unresolved = tuple(sorted(set(
            name for name in (*libs, *rpaths, *dyld)
            if not (name.startswith("/usr/lib/")
                    or name.startswith("/System/Library/"))
        )))
        return D4MachOLoaderObservation(
            selected_relative_executable=selected[len(root) + 1:],
            selected_sha256=expected_sha256,
            selected_cpu="arm64", selected_format=format_name,
            declared_direct_libraries=libs,
            declared_rpaths=rpaths,
            declared_dylinker=dyld,
            unresolved_install_names=unresolved,
            code_signature_command_present=signature,
        )
    except (D4RuntimeSourceDenied, OSError, ValueError, struct.error) as exc:
        if type(exc) is D4MachOLoaderDenied:
            raise
        raise D4MachOLoaderDenied(
            "native Mach-O loader source unavailable") from None
    finally:
        if fd is not None:
            os.close(fd)
        if dir_fd is not None:
            os.close(dir_fd)


def select_d4_macho_loader_source(
    observation: "D4RuntimeSourceObservation",
    recipe: "D4NativeLaunchRecipe",
    *, private_root: str,
) -> D4MachOLoaderObservation:
    """Choose the one interpreter/tool from the already checked recipe.

    Pipenv's bin/pipenv is an already checked #! script: the kernel actually
    selects the pinned private .venv/bin/python. Inspect THAT interpreter,
    not the script text. Go/direct Python inspect their selected executable.
    """
    from .lbe_launch_recipe import D4NativeLaunchRecipe
    from .lbe_runtime_source import D4RuntimeSourceObservation

    if (type(observation) is not D4RuntimeSourceObservation
            or type(recipe) is not D4NativeLaunchRecipe
            or observation.native_launch_allowed is not False
            or recipe.native_launch_allowed is not False
            or observation.workspace != recipe.workspace
            or observation.kind not in {"go", "pipenv", "python_direct"}):
        raise D4MachOLoaderDenied("unqualified selected product source")
    try:
        root = _canonical(private_root, "private root")
        if observation.kind == "pipenv":
            # This label is project-relative in the recorded source
            # observation, not relative to the private runner root.
            # The service has already checked the absolute project cwd.
            selected = recipe.working_directory + "/.venv/bin/python"
            path = selected[len(root) + 1:]
            sha = next(
                digest for name, digest in observation.staged_executables
                if name == "py-pipenv/.venv/bin/python")
        else:
            selected = recipe.resolved_executable
            path = selected[len(root) + 1:]
            sha = next(
                digest for name, digest in observation.staged_executables
                if name == path)
        if selected != root + "/" + path:
            raise D4MachOLoaderDenied("selected recipe source path mismatch")
        return inspect_d4_selected_macho_loader(
            private_root=root, selected_executable=selected,
            expected_sha256=sha)
    except (StopIteration, D4RuntimeSourceDenied, ValueError):
        raise D4MachOLoaderDenied("incomplete selected loader source") from None


def authorize_d4_native_from_static_macho(_observation: object) -> None:
    """A reported direct dependency list cannot grant real native T1."""
    raise D4MachOLoaderDenied(
        "PRODUCT_T1=NOT_AUTHORIZED: actual dyld selection, whole runtime "
        "imports, trusted image, OS child-domain and owner grant not proven"
    )
