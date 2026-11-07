"""T0 only: static private Mach-O library candidate graph and fail-closed paths.

Synthetic ARM64 Mach-O data is written to disposable pytest tmp dirs.
No dylib is loaded, no import, subprocess, macOS runner or native T1 invoked.
"""
from __future__ import annotations

from dataclasses import replace
import hashlib
import os
from pathlib import Path
import struct
import subprocess

import pytest

from gateway.lbe_dylib_sources import (
    D4PrivateDylibDenied, inspect_d4_private_dylib_candidates,
    authorize_d4_native_from_private_dylibs,
)
from gateway.lbe_macho_loader import inspect_d4_selected_macho_loader
from gateway.lbe_native_loader_set import D4NativeLoaderSetObservation


def _cmd(cmd: int, text: str, base: int = 24) -> bytes:
    value = text.encode("utf-8") + b"\x00"
    size = (base + len(value) + 3) & ~3
    return (struct.pack("<III", cmd, size, base)
            + b"\x00" * (base - 12) + value
            + b"\x00" * (size - base - len(value)))


def _image(*, libs=(), rpaths=()) -> bytes:
    commands = tuple(_cmd(0x0C, name) for name in libs) + tuple(
        _cmd(0x8000001C, name, 12) for name in rpaths)
    return (
        struct.pack("<IIIIIIII", 0xFEEDFACF, 0x0100000C, 0, 2,
                    len(commands), sum(len(x) for x in commands), 0, 0)
        + b"".join(commands))


def _fixture(tmp_path: Path, *, rpath: bool = False):
    private = tmp_path / "private"
    (private / "bin").mkdir(parents=True, mode=0o700)
    (private / "lib").mkdir(mode=0o700)
    first = private / "bin/python"
    a = private / "lib/libA.dylib"
    b = private / "lib/libB.dylib"
    if rpath:
        head = _image(libs=("@rpath/libA.dylib",),
                      rpaths=("@loader_path/../lib",))
    else:
        head = _image(libs=("@loader_path/../lib/libA.dylib",))
    payloads = {
        first: head,
        a: _image(libs=("@loader_path/libB.dylib",)),
        b: _image(libs=("/usr/lib/libSystem.B.dylib",)),
    }
    for path, data in payloads.items():
        path.write_bytes(data)
        path.chmod(0o700 if path == first else 0o600)
    sha = {str(path.relative_to(private)):
           hashlib.sha256(data).hexdigest()
           for path, data in payloads.items()}
    executable = inspect_d4_selected_macho_loader(
        private_root=str(private), selected_executable=str(first),
        expected_sha256=sha["bin/python"])
    selected = D4NativeLoaderSetObservation(
        runtime_kind="python_direct",
        static_selected_executables=(("bin/python", executable),),
        unresolved_declared_install_names=executable.unresolved_install_names,
    )
    expected = tuple((name, sha[name]) for name in (
        "lib/libA.dylib", "lib/libB.dylib"))
    return private, a, b, selected, expected


@pytest.mark.parametrize("rpath", [False, True])
def test_private_macho_dylib_graph_checks_actual_nested_files_without_loading(
        tmp_path, monkeypatch, rpath):
    private, _a, _b, selected, expected = _fixture(tmp_path, rpath=rpath)
    def forbidden(*_args, **_kwargs):
        raise AssertionError("no native dylib import or subprocess in T0")
    with monkeypatch.context() as m:
        m.setattr(subprocess, "Popen", forbidden)
        m.setattr(os, "kill", forbidden)
        graph = inspect_d4_private_dylib_candidates(
            selected, private_root=str(private),
            expected_private_dylibs=expected)
    assert tuple(x for x, _ in graph.private_native_images) == (
        "lib/libA.dylib", "lib/libB.dylib")
    assert all(image.selected_cpu == "arm64"
               and image.native_launch_allowed is False
               for _path, image in graph.private_native_images)
    assert graph.unverified_system_library_names == (
        "/usr/lib/libSystem.B.dylib",)
    assert graph.unresolved_dynamic_loader_names == ()
    assert graph.actual_dyld_resolution_verified is False
    assert graph.dynamically_loaded_all_sources_proven is False
    assert graph.physical_resource_domain_attached is False
    assert graph.native_launch_allowed is False
    with pytest.raises(D4PrivateDylibDenied, match="NOT_AUTHORIZED"):
        authorize_d4_native_from_private_dylibs(graph)
    with pytest.raises(D4PrivateDylibDenied, match="NOT_AUTHORIZED"):
        authorize_d4_native_from_private_dylibs(
            replace(graph, native_launch_allowed=True))


def test_private_link_unknown_manifest_source_is_recorded_not_minted(tmp_path):
    private, _a, _b, selected, expected = _fixture(tmp_path)
    out = inspect_d4_private_dylib_candidates(
        selected, private_root=str(private),
        expected_private_dylibs=(expected[1],))
    assert not out.private_native_images
    assert "@loader_path/../lib/libA.dylib" in out.unresolved_dynamic_loader_names
    assert out.native_launch_allowed is False


@pytest.mark.parametrize("violation", [
    "wrong_sha", "symlink", "hardlink", "writable", "foreign_format",
])
def test_private_link_file_identity_and_actual_bytes_always_fail_closed(
        tmp_path, violation):
    private, a, b, selected, expected = _fixture(tmp_path)
    if violation == "wrong_sha":
        expected = (("lib/libA.dylib", "f" * 64), expected[1])
    elif violation == "symlink":
        a.rename(a.with_name("retained"))
        a.symlink_to(a.with_name("retained"))
    elif violation == "hardlink":
        os.link(a, a.with_name("second"))
    elif violation == "writable":
        a.chmod(0o777)
    else:
        a.write_bytes(b"bad Mach-O content exactly pinned" + b"x" * 60)
        expected = ((expected[0][0],
                     hashlib.sha256(a.read_bytes()).hexdigest()),
                    expected[1])
    with pytest.raises(D4PrivateDylibDenied):
        inspect_d4_private_dylib_candidates(
            selected, private_root=str(private),
            expected_private_dylibs=expected)


def test_private_link_rpath_without_private_candidate_stays_unresolved(tmp_path):
    private, a, b, selected, expected = _fixture(tmp_path, rpath=True)
    graph = inspect_d4_private_dylib_candidates(
        selected, private_root=str(private),
        expected_private_dylibs=())
    assert graph.private_native_images == ()
    assert "@rpath/libA.dylib" in graph.unresolved_dynamic_loader_names
    assert graph.native_launch_allowed is False


def test_private_link_declared_escape_is_not_read_as_host_source(tmp_path):
    private = tmp_path / "private"
    (private / "bin").mkdir(parents=True, mode=0o700)
    source = private / "bin/python"
    value = _image(libs=(
        "@loader_path/../../../../etc/passwd",
        "/private/tmp/unreviewed.dylib",
    ))
    source.write_bytes(value)
    source.chmod(0o700)
    digest = hashlib.sha256(value).hexdigest()
    selected_image = inspect_d4_selected_macho_loader(
        private_root=str(private), selected_executable=str(source),
        expected_sha256=digest)
    selected = D4NativeLoaderSetObservation(
        runtime_kind="python_direct",
        static_selected_executables=(("bin/python", selected_image),),
        unresolved_declared_install_names=selected_image.unresolved_install_names,
    )
    graph = inspect_d4_private_dylib_candidates(
        selected, private_root=str(private), expected_private_dylibs=())
    assert graph.private_native_images == ()
    assert len(graph.unresolved_dynamic_loader_names) == 2
    assert graph.native_launch_allowed is False


def test_private_macho_dylibs_non_executable_regular_files_remain_valid(
        tmp_path):
    private, a, b, selected, expected = _fixture(tmp_path)
    assert a.stat().st_mode & 0o100 == 0
    assert b.stat().st_mode & 0o100 == 0
    evidence = inspect_d4_private_dylib_candidates(
        selected, private_root=str(private),
        expected_private_dylibs=expected)
    assert len(evidence.private_native_images) == 2
    assert evidence.actual_dyld_resolution_verified is False
    assert evidence.native_launch_allowed is False

def test_private_dylib_inherits_main_rpath_for_nested_static_candidate(tmp_path):
    """Inherited runpaths can locate nested candidates, not prove dyld loads."""
    private, a, _b, selected, expected = _fixture(tmp_path, rpath=True)
    nested = _image(libs=("@rpath/libB.dylib",))
    a.write_bytes(nested)
    expected = (("lib/libA.dylib", hashlib.sha256(nested).hexdigest()),
                expected[1])
    graph = inspect_d4_private_dylib_candidates(
        selected, private_root=str(private), expected_private_dylibs=expected)
    assert tuple(label for label, _image in graph.private_native_images) == (
        "lib/libA.dylib", "lib/libB.dylib")
    assert graph.unresolved_dynamic_loader_names == ()
    assert graph.actual_dyld_resolution_verified is False
    assert graph.native_launch_allowed is False


def test_private_dylib_ambiguous_rpath_never_silently_selects_pinned_match(tmp_path):
    """An unpinned competing runpath must not be filtered out of candidates."""
    private, _a, _b, _selected, expected = _fixture(tmp_path, rpath=True)
    first = private / "bin/python"
    payload = _image(libs=("@rpath/libA.dylib",), rpaths=(
        "@loader_path/../lib", "@loader_path/../unlisted"))
    first.write_bytes(payload)
    image = inspect_d4_selected_macho_loader(
        private_root=str(private), selected_executable=str(first),
        expected_sha256=hashlib.sha256(payload).hexdigest())
    selected = D4NativeLoaderSetObservation(
        runtime_kind="python_direct",
        static_selected_executables=(("bin/python", image),),
        unresolved_declared_install_names=image.unresolved_install_names)
    graph = inspect_d4_private_dylib_candidates(
        selected, private_root=str(private), expected_private_dylibs=expected)
    assert graph.private_native_images == ()
    assert "@rpath/libA.dylib" in graph.unresolved_dynamic_loader_names
    assert graph.native_launch_allowed is False


def test_private_dylib_unqualified_rpath_is_explicit_gap(tmp_path):
    private, _a, _b, _selected, expected = _fixture(tmp_path, rpath=True)
    first = private / "bin/python"
    payload = _image(libs=("@loader_path/../lib/libA.dylib",), rpaths=(
        "@loader_path/../../unqualified",))
    first.write_bytes(payload)
    image = inspect_d4_selected_macho_loader(
        private_root=str(private), selected_executable=str(first),
        expected_sha256=hashlib.sha256(payload).hexdigest())
    selected = D4NativeLoaderSetObservation(
        runtime_kind="python_direct",
        static_selected_executables=(("bin/python", image),),
        unresolved_declared_install_names=image.unresolved_install_names)
    graph = inspect_d4_private_dylib_candidates(
        selected, private_root=str(private), expected_private_dylibs=expected)
    assert tuple(label for label, _image in graph.private_native_images) == (
        "lib/libA.dylib", "lib/libB.dylib")
    assert "LC_RPATH:@loader_path/../../unqualified" in (
        graph.unresolved_dynamic_loader_names)
    assert graph.native_launch_allowed is False
