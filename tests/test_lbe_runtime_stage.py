"""Safe T0 coverage of real private D4 runtime source materialization.

All staged binaries are inert data bytes in disposable pytest tmp_path roots.
Neither Go, Python, Pipenv nor a native original child is executed.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
import subprocess

import pytest

from gateway.lbe_runtime_stage import (
    D4RuntimeStageDenied, stage_d4_operator_runtime_tree,
)


def _tree(root: Path) -> tuple[tuple[str, str | None], ...]:
    rows: list[tuple[str, str | None]] = [("", None)]
    for entry in sorted(root.rglob("*")):
        name = entry.relative_to(root).as_posix()
        if entry.is_dir() and not entry.is_symlink():
            rows.append((name, None))
        else:
            rows.append((name, hashlib.sha256(entry.read_bytes()).hexdigest()))
    return tuple(rows)


def _stage_fixture(tmp_path: Path, *, kind: str = "go"):
    root = tmp_path / "owner-private"
    source = tmp_path / "operator-provisioned" / kind
    source.mkdir(parents=True)
    if kind == "go":
        (source / "bin").mkdir()
        (source / "bin" / "go").write_bytes(b"inert Go runtime entrypoint")
        (source / "bin" / "go").chmod(0o700)
        (source / "src" / "runtime").mkdir(parents=True)
        (source / "src" / "runtime" / "runtime.go").write_bytes(
            b"package runtime\n")
    elif kind == "bin":
        (source / "python").write_bytes(b"inert Python executable")
        (source / "python").chmod(0o700)
        (source / "pipenv").write_bytes(b"inert Pipenv wrapper")
        (source / "pipenv").chmod(0o700)
    elif kind == "lib":
        (source / "python").mkdir()
        (source / "python" / "site.py").write_bytes(b"x=42\n")
    else:
        raise AssertionError("bad fixture type")
    return root, source, _tree(source)


@pytest.mark.parametrize("kind", ["go", "bin", "lib"])
def test_real_private_stage_materializes_exact_files_with_no_exec_authority(
        tmp_path, monkeypatch, kind):
    root, source, manifest = _stage_fixture(tmp_path, kind=kind)
    def no_child(*_args, **_kwargs):
        raise AssertionError("safe T0 must not spawn original child")
    with monkeypatch.context() as m:
        m.setattr(subprocess, "Popen", no_child)
        result = stage_d4_operator_runtime_tree(
            private_root=str(root), provisioner_root=str(source.parent),
            kind=kind, expected=manifest)
    assert result.source_relative_root == kind
    assert result.selected_relative_root == kind
    assert result.entries == len(manifest)
    assert result.files == sum(sha is not None for _name, sha in manifest)
    assert len(result.source_identity_sha256) == 64
    assert len(result.staged_identity_sha256) == 64
    assert result.staged_identity_sha256 != result.source_identity_sha256
    assert result.staged_files_verified is True
    assert result.owner_provisioner_attested is False
    assert result.immutable_runner_image_attested is False
    assert result.loaded_runtime_sources_proven is False
    assert result.physical_child_resource_enforced is False
    assert result.native_launch_allowed is False
    for name, sha in manifest:
        target = root / kind / name
        if sha is None:
            assert target.is_dir()
            assert stat.S_IMODE(target.stat().st_mode) == 0o700
        else:
            assert hashlib.sha256(target.read_bytes()).hexdigest() == sha
            source_exec = bool((source / name).stat().st_mode & stat.S_IXUSR)
            assert stat.S_IMODE(target.stat().st_mode) == (
                0o700 if source_exec else 0o600)
    # Prior stage is never overwritten even with a matching source.
    with pytest.raises(D4RuntimeStageDenied, match="already exists"):
        stage_d4_operator_runtime_tree(
            private_root=str(root), provisioner_root=str(source.parent),
            kind=kind, expected=manifest)


@pytest.mark.parametrize("violation", [
    "wrong_digest", "extra_source", "deleted_file", "source_symlink",
    "source_hardlink", "source_writable", "unsafe_directory",
    "preexisting_destination", "destination_symlink",
    "bad_kind", "missing_provisioner",
])
def test_stage_denies_unqualified_and_never_replaces_any_destination(
        tmp_path, violation):
    root, source, expected = _stage_fixture(tmp_path)
    expected = list(expected)
    binary = source / "bin" / "go"
    if violation == "wrong_digest":
        expected = [(n, "f" * 64 if n == "bin/go" else d)
                    for n, d in expected]
    elif violation == "extra_source":
        (source / "src" / "unreviewed.go").write_bytes(b"foreign bytes")
    elif violation == "deleted_file":
        binary.unlink()
    elif violation == "source_symlink":
        binary.unlink()
        binary.symlink_to("/bin/sh")
    elif violation == "source_hardlink":
        os.link(binary, source / "bin" / "another_go")
    elif violation == "source_writable":
        binary.chmod(0o777)
    elif violation == "unsafe_directory":
        (source / "bin").chmod(0o777)
    elif violation == "preexisting_destination":
        (root / "go").mkdir()
        (root / "go" / "keep.txt").write_bytes(b"must-not-overwrite")
    elif violation == "destination_symlink":
        (root / "go").symlink_to("/tmp")
    elif violation == "missing_provisioner":
        (source / "bin" / "go").unlink()
        (source / "src" / "runtime" / "runtime.go").unlink()
        (source / "src" / "runtime").rmdir()
        (source / "src").rmdir()
        (source / "bin").rmdir()
        source.rmdir()
    with pytest.raises(D4RuntimeStageDenied):
        stage_d4_operator_runtime_tree(
            private_root=str(root), provisioner_root=str(source.parent),
            kind="other" if violation == "bad_kind" else "go",
            expected=tuple(expected),
        )
    if violation == "preexisting_destination":
        assert (root / "go" / "keep.txt").read_bytes() == b"must-not-overwrite"
    if violation == "destination_symlink":
        assert (root / "go").is_symlink()
    if violation not in ("preexisting_destination", "destination_symlink"):
        assert not (root / "go").exists()


def test_stage_detects_source_rewrite_during_copy_and_does_not_rollback(
        tmp_path, monkeypatch):
    root, source, expected = _stage_fixture(tmp_path)
    original = source / "bin" / "go"
    real_read = os.read
    read_count = 0
    def race(fd, size):
        nonlocal read_count
        content = real_read(fd, size)
        if content and content == b"inert Go runtime entrypoint":
            read_count += 1
            if read_count == 2:
                original.write_bytes(b"changed after copied bytes")
        return content
    with monkeypatch.context() as m:
        m.setattr(os, "read", race)
        with pytest.raises(D4RuntimeStageDenied):
            stage_d4_operator_runtime_tree(
                private_root=str(root), provisioner_root=str(source.parent),
                kind="go", expected=expected)
    assert read_count >= 2
    # The incomplete dest is never treated as committed and not re-used.
    assert (root / "go").exists()
    with pytest.raises(D4RuntimeStageDenied):
        stage_d4_operator_runtime_tree(
            private_root=str(root), provisioner_root=str(source.parent),
                kind="go", expected=expected)


def test_stage_rejects_symlinked_private_ancestor(tmp_path):
    root, _source, expected = _stage_fixture(tmp_path)
    alias = tmp_path / "alias"
    alias.symlink_to(root)
    with pytest.raises(D4RuntimeStageDenied):
        stage_d4_operator_runtime_tree(
            private_root=str(alias), provisioner_root=str(_source.parent),
            kind="go", expected=expected)
    assert not (root / "go").exists()


def test_stage_rejects_complete_manifest_with_executable_pth(tmp_path):
    root, source, _manifest = _stage_fixture(tmp_path, kind="lib")
    (source / "python" / "loader.pth").write_bytes(
        b"import untrusted_dynamic_startup\n")
    with pytest.raises(D4RuntimeStageDenied):
        stage_d4_operator_runtime_tree(
            private_root=str(root), provisioner_root=str(source.parent),
            kind="lib", expected=_tree(source))
    assert not (root / "lib").exists()


def test_stage_refuses_provisioner_inside_runtime_or_runtime_inside_provisioner(
        tmp_path):
    root, source, expected = _stage_fixture(tmp_path, kind="go")
    with pytest.raises(D4RuntimeStageDenied, match="must not overlap"):
        stage_d4_operator_runtime_tree(
            private_root=str(root), provisioner_root=str(root),
            kind="go", expected=expected)
    inside = root / "source-holder"
    inside.mkdir()
    with pytest.raises(D4RuntimeStageDenied, match="must not overlap"):
        stage_d4_operator_runtime_tree(
            private_root=str(root), provisioner_root=str(inside),
            kind="go", expected=expected)
    with pytest.raises(D4RuntimeStageDenied, match="must not overlap"):
        stage_d4_operator_runtime_tree(
            private_root=str(inside), provisioner_root=str(root),
            kind="go", expected=expected)
    assert not (root / "go").exists()


def test_stage_provisioner_cannot_alias_a_source_symlink(tmp_path):
    root, source, expected = _stage_fixture(tmp_path, kind="go")
    alias = tmp_path / "source-alias"
    alias.symlink_to(source.parent)
    with pytest.raises(D4RuntimeStageDenied):
        stage_d4_operator_runtime_tree(
            private_root=str(root), provisioner_root=str(alias),
            kind="go", expected=expected)
    assert not (root / "go").exists()


@pytest.mark.parametrize("kind,expected", [
    ("go", ("home", "tmp", "gopath", "modcache", "gocache", "gotmp")),
    ("pipenv", ("home", "tmp")),
    ("python_direct", ("home", "tmp")),
])
def test_real_runner_scratch_created_empty_once_and_then_refuses_reuse(
        tmp_path, kind, expected):
    from gateway.lbe_runtime_stage import create_d4_fresh_runner_scratch
    root = tmp_path / "private-runtime"
    root.mkdir(mode=0o700)
    names = create_d4_fresh_runner_scratch(
        private_root=str(root), kind=kind)
    assert names == expected
    for name in names:
        path = root / name
        assert path.is_dir() and not any(path.iterdir())
        assert stat.S_IMODE(path.stat().st_mode) == 0o700
    with pytest.raises(D4RuntimeStageDenied, match="preexisting"):
        create_d4_fresh_runner_scratch(private_root=str(root), kind=kind)


@pytest.mark.parametrize("name", ["home", "tmp", "modcache"])
def test_runner_scratch_rejects_existing_foreign_path_without_other_creation(
        tmp_path, name):
    from gateway.lbe_runtime_stage import create_d4_fresh_runner_scratch
    root = tmp_path / "private-runtime"
    root.mkdir(mode=0o700)
    (root / name).symlink_to("/tmp")
    with pytest.raises(D4RuntimeStageDenied, match="preexisting"):
        create_d4_fresh_runner_scratch(private_root=str(root), kind="go")
    assert (root / name).is_symlink()
    for other in ("home", "tmp", "gopath", "modcache", "gocache", "gotmp"):
        if other != name:
            assert not (root / other).exists()


def test_runner_scratch_denies_wrong_kind_without_writes(tmp_path):
    from gateway.lbe_runtime_stage import create_d4_fresh_runner_scratch
    root = tmp_path / "private-runtime"
    root.mkdir(mode=0o700)
    with pytest.raises(D4RuntimeStageDenied):
        create_d4_fresh_runner_scratch(private_root=str(root), kind="external")
    assert not list(root.iterdir())
