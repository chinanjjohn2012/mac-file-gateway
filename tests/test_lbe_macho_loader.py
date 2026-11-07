"""Safe T0 for actual pinned ARM64 Mach-O native loader declarations.

Only inert synthetic binary BYTES are generated. The Mach-O header/parser
inspects memory and private nofollow FDs; no native child, dyld, Go, Python,
Pipenv, otool, codesign, signal, network or privileged operation is run.
"""
from __future__ import annotations

from dataclasses import replace
import hashlib
import os
from pathlib import Path
import stat
import struct
import subprocess

import pytest

from gateway.lbe_macho_loader import (
    D4MachOLoaderDenied, inspect_d4_selected_macho_loader,
    authorize_d4_native_from_static_macho,
)


_ARM64 = 0x0100000C
_X86_64 = 0x01000007


def _name_command(cmd: int, name: str, minimum: int) -> bytes:
    payload = name.encode("utf-8") + b"\x00"
    cmdsize = (minimum + len(payload) + 3) & ~3
    return (struct.pack("<III", cmd, cmdsize, minimum)
            + b"\x00" * (minimum - 12) + payload
            + b"\x00" * (cmdsize - minimum - len(payload)))


def _thin(*, cpu: int = _ARM64, extra: tuple[bytes, ...] = (),
          file_type: int = 2) -> bytes:
    cmds = (
        _name_command(0x0C, "/usr/lib/libSystem.B.dylib", 24),
        _name_command(0x8000001C, "@loader_path/../Frameworks", 12),
        _name_command(0x0E, "/usr/lib/dyld", 12),
        struct.pack("<IIII", 0x1D, 16, 0, 0),
        *extra,
    )
    return struct.pack(
        "<IIIIIIII", 0xFEEDFACF, cpu, 0, file_type, len(cmds),
        sum(len(x) for x in cmds), 0, 0) + b"".join(cmds)


def _fat() -> bytes:
    x86 = _thin(cpu=_X86_64)
    arm = _thin(extra=(
        _name_command(0x80000018, "@rpath/libPrivate.dylib", 24),))
    table = (struct.pack(">II", 0xCAFEBABE, 2)
             + struct.pack(">IIIII", _X86_64, 0, 64, len(x86), 2)
             + struct.pack(">IIIII", _ARM64, 0, 512, len(arm), 2))
    if len(x86) > 448:
        raise AssertionError("synthetic fat offset incorrect")
    return table + b"\x00" * (64 - len(table)) + x86 + (
        b"\x00" * (512 - 64 - len(x86))) + arm


def _private_binary(tmp_path: Path, data: bytes) -> tuple[Path, Path, str]:
    root = tmp_path / "runner-private"
    (root / "bin").mkdir(mode=0o700, parents=True)
    executable = root / "bin" / "selected"
    executable.write_bytes(data)
    executable.chmod(0o700)
    return root, executable, hashlib.sha256(data).hexdigest()


@pytest.mark.parametrize("fat", [False, True])
def test_macho_static_arm64_declarations_are_actual_bytes_not_loader_proof(
        tmp_path, monkeypatch, fat):
    root, executable, digest = _private_binary(
        tmp_path, _fat() if fat else _thin())
    def impossible(*_args, **_kwargs):
        raise AssertionError("Mach-O static T0 must not execute")
    with monkeypatch.context() as m:
        m.setattr(subprocess, "Popen", impossible)
        m.setattr(os, "kill", impossible)
        observed = inspect_d4_selected_macho_loader(
            private_root=str(root),
            selected_executable=str(executable), expected_sha256=digest)
    assert observed.selected_relative_executable == "bin/selected"
    assert observed.selected_cpu == "arm64"
    assert observed.selected_file_type == "MH_EXECUTE"
    assert observed.selected_format == ("FAT_32" if fat else "THIN_64")
    assert observed.selected_sha256 == digest
    assert "/usr/lib/libSystem.B.dylib" in observed.declared_direct_libraries
    assert observed.declared_dylinker == ("/usr/lib/dyld",)
    assert observed.declared_rpaths == ("@loader_path/../Frameworks",)
    assert observed.unresolved_install_names
    if fat:
        assert "@rpath/libPrivate.dylib" in observed.unresolved_install_names
    assert observed.code_signature_command_present is True
    assert observed.code_signature_verified is False
    assert observed.actual_dyld_resolution_attested is False
    assert observed.full_loaded_source_graph_attested is False
    assert observed.immutable_runner_image_attested is False
    assert observed.whole_child_resource_domain_enforced is False
    assert observed.native_launch_allowed is False
    with pytest.raises(D4MachOLoaderDenied, match="NOT_AUTHORIZED"):
        authorize_d4_native_from_static_macho(observed)
    forged = replace(observed, native_launch_allowed=True,
                     full_loaded_source_graph_attested=True)
    with pytest.raises(D4MachOLoaderDenied, match="NOT_AUTHORIZED"):
        authorize_d4_native_from_static_macho(forged)


@pytest.mark.parametrize("mutation", [
    "not_macho", "wrong_cpu", "wrong_type", "bad_commands",
    "truncated_commands", "unknown_slice", "short_fat_table",
    "bad_load_name_offset", "no_nul", "duplicate_arm64",
])
def test_macho_nonqualifying_format_does_not_produce_evidence(
        tmp_path, mutation):
    if mutation == "not_macho":
        data = b"not Mach-O at all" + b"0" * 80
    elif mutation == "wrong_cpu":
        data = _thin(cpu=_X86_64)
    elif mutation == "wrong_type":
        data = _thin(file_type=0)
    elif mutation == "bad_commands":
        data = bytearray(_thin())
        struct.pack_into("<I", data, 16, 99999)  # ncmds > 4096
        data = bytes(data)
    elif mutation == "truncated_commands":
        data = bytearray(_thin())
        struct.pack_into("<I", data, 20, 0x1000000)  # sizeofcmds > bound
        data = bytes(data)
    elif mutation == "unknown_slice":
        data = bytearray(_fat())
        struct.pack_into(">I", data, 8 + 20, _X86_64)
        data = bytes(data)
    elif mutation == "short_fat_table":
        data = struct.pack(">II", 0xCAFEBABE, 5) + b"\x00" * 32
    elif mutation == "bad_load_name_offset":
        data = bytearray(_thin())
        struct.pack_into("<I", data, 32 + 8, 10000)
        data = bytes(data)
    elif mutation == "no_nul":
        cmd = struct.pack("<III", 0x0C, 28, 24) + b"\x00" * 12 + b"fail"
        data = _thin(extra=(cmd,))
    else:
        # A universal file carrying two ARM64 members is ambiguous.
        data = bytearray(_fat())
        struct.pack_into(">I", data, 8, _ARM64)
        data = bytes(data)
    root, executable, digest = _private_binary(tmp_path, data)
    with pytest.raises(D4MachOLoaderDenied):
        inspect_d4_selected_macho_loader(
            private_root=str(root), selected_executable=str(executable),
            expected_sha256=digest)


@pytest.mark.parametrize("mutation", [
    "wrong_digest", "symlink", "hardlink", "writable",
    "nonexec", "directory_path", "outside_root", "changed_content",
])
def test_macho_source_fd_identity_and_digest_fail_closed(tmp_path, mutation):
    root, executable, digest = _private_binary(tmp_path, _thin())
    if mutation == "wrong_digest":
        digest = "f" * 64
    elif mutation == "symlink":
        real = executable.with_name("real")
        executable.rename(real)
        executable.symlink_to(real)
    elif mutation == "hardlink":
        os.link(executable, executable.with_name("second"))
    elif mutation == "writable":
        executable.chmod(0o777)
    elif mutation == "nonexec":
        executable.chmod(0o600)
    elif mutation == "directory_path":
        executable = executable.parent
    elif mutation == "outside_root":
        executable = tmp_path / "unrelated"
        executable.write_bytes(_thin())
    elif mutation == "changed_content":
        executable.write_bytes(_thin(extra=(
            _name_command(0x0C, "/usr/lib/another.dylib", 24),)))
    with pytest.raises(D4MachOLoaderDenied):
        inspect_d4_selected_macho_loader(
            private_root=str(root), selected_executable=str(executable),
            expected_sha256=digest)


def test_macho_unsafe_rpath_is_recorded_as_unresolved_not_a_qualification(
        tmp_path):
    extra = (
        _name_command(0x8000001C, "@rpath/../../foreign", 12),
        _name_command(0x0C, "/private/tmp/foreign.dylib", 24),
    )
    root, executable, digest = _private_binary(tmp_path, _thin(extra=extra))
    result = inspect_d4_selected_macho_loader(
        private_root=str(root), selected_executable=str(executable),
        expected_sha256=digest)
    assert "@rpath/../../foreign" in result.unresolved_install_names
    assert "/private/tmp/foreign.dylib" in result.unresolved_install_names
    assert result.native_launch_allowed is False
    assert result.full_loaded_source_graph_attested is False

@pytest.mark.parametrize("incorrect_type", [6, 8])
def test_macho_primary_rejects_library_or_bundle_even_if_executable(
        tmp_path, incorrect_type):
    root, executable, digest = _private_binary(
        tmp_path, _thin(file_type=incorrect_type))
    with pytest.raises(D4MachOLoaderDenied, match="role/type mismatch"):
        inspect_d4_selected_macho_loader(
            private_root=str(root), selected_executable=str(executable),
            expected_sha256=digest)


def test_macho_library_accepts_pinned_nonexecuting_dylib_but_not_executable_or_bundle(
        tmp_path):
    root, file, digest = _private_binary(tmp_path, _thin(file_type=6))
    file.chmod(0o600)
    observation = inspect_d4_selected_macho_loader(
        private_root=str(root), selected_executable=str(file),
        expected_sha256=digest, require_execute_bit=False)
    assert observation.selected_file_type == "MH_DYLIB"
    assert observation.native_launch_allowed is False
    for illegal in (2, 8):
        payload = _thin(file_type=illegal)
        file.write_bytes(payload)
        with pytest.raises(D4MachOLoaderDenied, match="role/type mismatch"):
            inspect_d4_selected_macho_loader(
                private_root=str(root), selected_executable=str(file),
                expected_sha256=hashlib.sha256(payload).hexdigest(),
                require_execute_bit=False)
