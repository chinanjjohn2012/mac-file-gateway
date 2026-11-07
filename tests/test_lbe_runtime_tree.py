"""Actual source-tree FD admission tests: safe T0 only, no native child."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess

import pytest

from gateway.lbe_runtime_tree import (
    D4RuntimeTreeDenied, inspect_d4_closed_staged_tree,
)


def _make_tree(tmp_path: Path):
    private = tmp_path / "private"
    root = private / "go"
    (root / "bin").mkdir(parents=True)
    (root / "src" / "pkg").mkdir(parents=True)
    (root / "bin" / "go").write_bytes(b"fake executable bytes only")
    (root / "bin" / "go").chmod(0o700)
    (root / "src" / "pkg" / "a.go").write_bytes(b"package pkg\n")
    (root / "src" / "pkg" / "b.go").write_bytes(b"package pkg\nvar x=2\n")
    return private, root


def _expected(root: Path):
    pairs = [("", None)]
    for p in sorted(root.rglob("*")):
        name = p.relative_to(root).as_posix()
        if p.is_dir() and not p.is_symlink():
            pairs.append((name, None))
        else:
            pairs.append((name, hashlib.sha256(p.read_bytes()).hexdigest()))
    return tuple(sorted(pairs))


def _check(private, root, expected):
    return inspect_d4_closed_staged_tree(
        private_root=str(private), staged_root=str(root),
        expected=expected)


def test_real_closed_staged_go_tree_source_snapshot_never_grants_native(
        tmp_path, monkeypatch):
    private, root = _make_tree(tmp_path)
    expected = _expected(root)
    with monkeypatch.context() as m:
        m.setattr(subprocess, "Popen", lambda *_a, **_k: (
            _ for _ in ()).throw(AssertionError("never spawn")))
        observed = _check(private, root, expected)
    assert observed.relative_root == "go"
    assert observed.entry_count == len(expected)
    assert observed.file_count == 3
    assert observed.total_file_bytes == sum(
        len((root / name).read_bytes()) for name, sha in expected if sha)
    assert len(observed.observed_identity_sha256) == 64
    assert observed.staged_sources_closed is True
    assert observed.actual_loader_selected_sources_proven is False
    assert observed.runner_attested is False
    assert observed.resource_domain_enforced is False
    assert observed.native_launch_allowed is False


@pytest.mark.parametrize("mutation", [
    "modified_file", "extra_source", "extra_empty_dir", "remove_source",
    "writable_file", "writable_dir", "hardlinked_source",
    "source_symlink", "directory_symlink", "unlisted_pth", "unlisted_sitecustomize",
])
def test_staged_source_drift_or_unqualified_file_type_denied(
        tmp_path, mutation):
    private, root = _make_tree(tmp_path)
    before = _expected(root)
    p = root / "src" / "pkg" / "a.go"
    if mutation == "modified_file":
        p.write_bytes(b"package pkg\nvar x=1234\n")
    elif mutation == "extra_source":
        (root / "src" / "pkg" / "shadow.go").write_bytes(b"package pkg\n")
    elif mutation == "extra_empty_dir":
        (root / "src" / "pkg" / "cache").mkdir()
    elif mutation == "remove_source":
        p.unlink()
    elif mutation == "writable_file":
        p.chmod(0o666)
    elif mutation == "writable_dir":
        (root / "src" / "pkg").chmod(0o777)
    elif mutation == "hardlinked_source":
        os.link(p, root / "src" / "pkg" / "hardlink.go")
    elif mutation == "source_symlink":
        p.unlink()
        p.symlink_to("/bin/sh")
    elif mutation == "directory_symlink":
        (root / "src" / "pkg" / "unlisted").symlink_to("/tmp")
    elif mutation == "unlisted_pth":
        (root / "src" / "pkg" / "evil.pth").write_bytes(
            b"import os; os.system('forbidden')\n")
    else:
        (root / "src" / "pkg" / "sitecustomize.py").write_bytes(b"x=1\n")
    with pytest.raises(D4RuntimeTreeDenied):
        _check(private, root, before)


@pytest.mark.parametrize("corrupt", [
    "empty", "non_tuple", "duplicate", "noncanonical", "wrong_digest",
    "missing_directory", "bad_file_type", "unexpected_entry",
    "missing_root", "root_hash", "str_subclass", "unqualified_pth",
])
def test_staged_manifest_is_exact_and_cannot_choose_arbitrary_source(
        tmp_path, corrupt):
    private, root = _make_tree(tmp_path)
    baseline = list(_expected(root))
    if corrupt == "empty":
        rows = ()
    elif corrupt == "non_tuple":
        rows = list(baseline)
    elif corrupt == "duplicate":
        rows = tuple(baseline + [baseline[-1]])
    elif corrupt == "noncanonical":
        rows = tuple(baseline + [("src/../outside.py", "a" * 64)])
    elif corrupt == "wrong_digest":
        rows = tuple(
            (path, "f" * 64 if path == "bin/go" else digest)
            for path, digest in baseline)
    elif corrupt == "missing_directory":
        rows = tuple(x for x in baseline if x[0] != "src")
    elif corrupt == "bad_file_type":
        rows = tuple((path, 7 if path == "bin/go" else digest)
                     for path, digest in baseline)
    elif corrupt == "unexpected_entry":
        rows = tuple(baseline + [("src/pkg/unknown.py", "a" * 64)])
    elif corrupt == "missing_root":
        rows = tuple(x for x in baseline if x[0])
    elif corrupt == "root_hash":
        rows = tuple((path, "a" * 64 if not path else digest)
                     for path, digest in baseline)
    elif corrupt == "str_subclass":
        class StringImpostor(str):
            pass
        rows = tuple((StringImpostor(path) if path == "bin/go" else path, digest)
                     for path, digest in baseline)
    else:
        rows = tuple(baseline + [("src/pkg/hook.pth", "a" * 64)])
    with pytest.raises(D4RuntimeTreeDenied):
        _check(private, root, rows)


def test_staged_source_rejects_private_root_escape_and_symlink_ancestor(tmp_path):
    private, root = _make_tree(tmp_path)
    expected = _expected(root)
    with pytest.raises(D4RuntimeTreeDenied):
        _check(private / "go", root, expected)
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    with pytest.raises(D4RuntimeTreeDenied):
        _check(private, outside, expected)
    alias = tmp_path / "alias"
    alias.symlink_to(private)
    with pytest.raises(D4RuntimeTreeDenied):
        _check(alias, alias / "go", expected)


def test_trusted_manifest_cannot_allow_pth_even_when_hash_is_exact(tmp_path):
    private, root = _make_tree(tmp_path)
    (root / "src" / "pkg" / "startup.pth").write_bytes(
        b"import unqualified_side_effect\n")
    with pytest.raises(D4RuntimeTreeDenied, match="startup"):
        _check(private, root, _expected(root))


def test_changed_inode_detected_during_stream_read(tmp_path, monkeypatch):
    private, root = _make_tree(tmp_path)
    original = _expected(root)
    real_read = os.read
    switched = []
    target = root / "src" / "pkg" / "a.go"
    def mutate_read(fd, size):
        data = real_read(fd, size)
        if not switched:
            switched.append(True)
            target.write_bytes(b"package pkg\nvar y=5\n")
        return data
    with monkeypatch.context() as m:
        m.setattr(os, "read", mutate_read)
        with pytest.raises(D4RuntimeTreeDenied):
            _check(private, root, original)
    assert switched
