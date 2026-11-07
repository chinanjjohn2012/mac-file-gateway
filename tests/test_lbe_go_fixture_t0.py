"""Go staged-file SAFE T0: real read-only bytes, zero Go execution."""
from dataclasses import replace
import hashlib
import os
from pathlib import Path
import shutil
import socket
import subprocess

import pytest

from gateway.lbe_go_fixture_t0 import (
    GoStagedFilesSnapshotT0,
    LbeGoFixtureT0Denied,
    authorize_native_go_from_t0,
    inspect_staged_go_files_t0,
)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@pytest.fixture
def staged(tmp_path: Path):
    private = tmp_path.resolve() / "stage-private"
    root = private / "go"
    (root / "bin").mkdir(parents=True, mode=0o700)
    (root / "pkg" / "tool" / "darwin_arm64").mkdir(
        parents=True, mode=0o700)
    inputs = {
        "bin/go": b"TEST-FILE-ONLY-NOT-GO\n",
        "pkg/tool/darwin_arm64/compile": b"TEST-FILE-ONLY-NOT-COMPILER\n",
        "pkg/tool/darwin_arm64/link": b"TEST-FILE-ONLY-NOT-LINKER\n",
    }
    for name, content in inputs.items():
        target = root / name
        target.write_bytes(content)
        target.chmod(0o700)
    expected = {
        "private_root": str(private),
        "goroot": str(root),
        "expected_go_sha256": _sha(inputs["bin/go"]),
        "expected_compile_sha256": _sha(inputs["pkg/tool/darwin_arm64/compile"]),
        "expected_link_sha256": _sha(inputs["pkg/tool/darwin_arm64/link"]),
    }
    return private, root, expected, inputs


def _inspect(expected):
    return inspect_staged_go_files_t0(**expected)


def test_valid_fixed_fake_go_files_do_not_authorize_native(staged, monkeypatch):
    _private, _root, expected, _inputs = staged

    def unexpected(*_a, **_k):
        raise AssertionError("source snapshot must not spawn or contact hosts")

    with monkeypatch.context() as m:
        m.setattr(subprocess, "Popen", unexpected)
        m.setattr(subprocess, "run", unexpected)
        m.setattr(socket, "socket", unexpected)
        candidate = _inspect(expected)
    assert type(candidate) is GoStagedFilesSnapshotT0
    assert candidate.status == "NONOPERATIVE_STAGED_GO_FILES_T0"
    assert candidate.file_bytes_observed is True
    assert candidate.loaded_toolchain_qualified is False
    assert candidate.compiled_source_closure_qualified is False
    assert candidate.native_launch_allowed is False
    assert candidate.product_apply_allowed is False
    assert candidate.actual_os_limits_enforced is False
    assert len(candidate.blockers) >= 4
    with pytest.raises(LbeGoFixtureT0Denied, match="NATIVE_GO=NOT_RUN"):
        authorize_native_go_from_t0(candidate)


@pytest.mark.parametrize("part", [
    "bin/go", "pkg/tool/darwin_arm64/compile",
    "pkg/tool/darwin_arm64/link",
])
def test_replacing_bytes_after_snapshot_denies_future_read(staged, part):
    _private, root, expected, _inputs = staged
    old = _inspect(expected)
    assert old.native_launch_allowed is False
    with (root / part).open("ab") as stream:
        stream.write(b"altered")
    with pytest.raises(LbeGoFixtureT0Denied, match="hashes"):
        _inspect(expected)


@pytest.mark.parametrize("part", [
    "bin/go", "pkg/tool/darwin_arm64/compile",
    "pkg/tool/darwin_arm64/link",
])
def test_symlink_to_same_content_is_not_a_qualified_tool(staged, part):
    _private, root, expected, _inputs = staged
    src = root / part
    replacement = src.parent / ("old-" + src.name)
    src.rename(replacement)
    src.symlink_to(replacement)
    with pytest.raises(LbeGoFixtureT0Denied):
        _inspect(expected)


@pytest.mark.parametrize("part", [
    "bin/go", "pkg/tool/darwin_arm64/compile",
    "pkg/tool/darwin_arm64/link",
])
def test_hardlink_identity_is_not_qualified(staged, part):
    _private, root, expected, _inputs = staged
    os.link(root / part, root / "extra-tool")
    with pytest.raises(LbeGoFixtureT0Denied, match="unsafe"):
        _inspect(expected)


@pytest.mark.parametrize("part", [
    "bin/go", "pkg/tool/darwin_arm64/compile",
    "pkg/tool/darwin_arm64/link",
])
def test_missing_staged_tool_denies(staged, part):
    _private, root, expected, _inputs = staged
    (root / part).unlink()
    with pytest.raises(LbeGoFixtureT0Denied):
        _inspect(expected)


@pytest.mark.parametrize("part", [
    "bin/go", "pkg/tool/darwin_arm64/compile",
    "pkg/tool/darwin_arm64/link",
])
def test_owner_executable_bit_is_required(staged, part):
    _private, root, expected, _inputs = staged
    (root / part).chmod(0o600)
    with pytest.raises(LbeGoFixtureT0Denied, match="unsafe"):
        _inspect(expected)


@pytest.mark.parametrize("part", [
    "bin/go", "pkg/tool/darwin_arm64/compile",
    "pkg/tool/darwin_arm64/link",
])
def test_group_or_world_writable_tool_denied(staged, part):
    _private, root, expected, _inputs = staged
    (root / part).chmod(0o777)
    with pytest.raises(LbeGoFixtureT0Denied, match="unsafe"):
        _inspect(expected)


@pytest.mark.parametrize("directory", ["go", "go/bin", "go/pkg",
                                        "go/pkg/tool",
                                        "go/pkg/tool/darwin_arm64"])
def test_writable_staging_directories_denied(staged, directory):
    private, _root, expected, _inputs = staged
    (private / directory).chmod(0o777)
    with pytest.raises(LbeGoFixtureT0Denied, match="untrusted"):
        _inspect(expected)


def test_symlinked_private_root_and_tool_dir_denied(staged):
    private, root, expected, _inputs = staged
    tool = root / "pkg" / "tool"
    tool.rename(root / "pkg" / "original-tool")
    tool.symlink_to(root / "pkg" / "original-tool",
                    target_is_directory=True)
    with pytest.raises(LbeGoFixtureT0Denied):
        _inspect(expected)
    tool.unlink()
    (root / "pkg" / "original-tool").rename(tool)

    private.rename(private.with_name("private-original"))
    private.symlink_to(private.with_name("private-original"),
                       target_is_directory=True)
    with pytest.raises(LbeGoFixtureT0Denied):
        _inspect(expected)


def test_go_binary_as_fifo_refused_without_blocking(staged):
    _private, root, expected, _inputs = staged
    binary = root / "bin" / "go"
    binary.unlink()
    os.mkfifo(binary, mode=0o600)
    with pytest.raises(LbeGoFixtureT0Denied, match="unsafe"):
        _inspect(expected)


@pytest.mark.parametrize("field,value", [
    ("private_root", "/outside"),
    ("private_root", "/tmp/../outside"),
    ("goroot", "/outside/go"),
    ("goroot", "/private/stage2/go"),
    ("goroot", "/tmp//go"),
    ("expected_go_sha256", "0" * 64),
    ("expected_compile_sha256", "X" * 64),
    ("expected_link_sha256", False),
    ("expected_link_sha256", "a" * 64),
])
def test_unqualified_root_or_digest_denied(staged, field, value):
    _private, _root, expected, _inputs = staged
    with pytest.raises(LbeGoFixtureT0Denied):
        _inspect({**expected, field: value})


def test_exact_str_only_and_no_hostile_string_callbacks(staged):
    _private, _root, expected, _inputs = staged
    callbacks = []

    class Forged(str):
        def __new__(cls):
            return str.__new__(cls, expected["goroot"])

        def __eq__(self, other):
            callbacks.append("eq")
            return True

        def __str__(self):
            callbacks.append("str")
            return expected["goroot"]

    with pytest.raises(LbeGoFixtureT0Denied):
        _inspect({**expected, "goroot": Forged()})
    assert callbacks == []


def test_forged_immutable_receipt_still_cannot_launch(staged):
    _private, _root, expected, _inputs = staged
    receipt = replace(_inspect(expected), native_launch_allowed=True,
                      product_apply_allowed=True, blockers=())
    with pytest.raises(LbeGoFixtureT0Denied, match="NATIVE_GO=NOT_RUN"):
        authorize_native_go_from_t0(receipt)
