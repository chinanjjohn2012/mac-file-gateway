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
    root.mkdir(mode=0o700)
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


@pytest.mark.parametrize("kind", ["go", "bin", "lib"])
def test_operator_source_manifest_exports_exact_real_bytes_for_approved_stage(
        tmp_path, monkeypatch, kind):
    """Operator observation helps prepare sources, but is NOT approval/T1."""
    from gateway.lbe_runtime_tree import observe_d4_operator_source_manifest

    private, source, externally_known_fixture = _stage_fixture(
        tmp_path, kind=kind)
    with monkeypatch.context() as m:
        def no_native(*_args, **_kwargs):
            raise AssertionError("manifest observation must never spawn")
        m.setattr(subprocess, "Popen", no_native)
        m.setattr(os, "listdir", no_native)
        proposed = observe_d4_operator_source_manifest(
            provisioner_root=str(source.parent), kind=kind)
        assert proposed.kind == kind
        assert proposed.proposed_manifest == tuple(sorted(externally_known_fixture))
        assert proposed.file_count == sum(
            sha is not None for _, sha in externally_known_fixture)
        assert proposed.entry_count == len(externally_known_fixture)
        assert len(proposed.observed_source_identity_sha256) == 64
        assert proposed.trusted_operator_attested is False
        assert proposed.manifest_independently_approved is False
        assert proposed.actual_loaded_source_graph_proven is False
        assert proposed.native_launch_allowed is False
        # Explicit test fixture approval; real operation must separately
        # review and pin these contents. The API does not self-approve them.
        done = stage_d4_operator_runtime_tree(
            private_root=str(private),
            provisioner_root=str(source.parent), kind=kind,
            expected=externally_known_fixture)
    assert done.files == proposed.file_count
    assert done.native_launch_allowed is False
    assert not (private / "home").exists()


@pytest.mark.parametrize("mutation", [
    "symlink_file", "symlink_directory", "hardlink_file", "writable_source",
    "pth", "special_fifo", "invalid_provisioner", "unknown_kind",
])
def test_operator_source_manifest_rejects_unqualified_live_inputs(
        tmp_path, mutation):
    from gateway.lbe_runtime_tree import (
        D4RuntimeTreeDenied, observe_d4_operator_source_manifest,
    )

    _private, source, _expected = _stage_fixture(tmp_path)
    kwargs = {"provisioner_root": str(source.parent), "kind": "go"}
    if mutation == "symlink_file":
        (source / "bin/go").unlink()
        (source / "bin/go").symlink_to("/bin/sh")
    elif mutation == "symlink_directory":
        (source / "bin").rename(source / "real-bin")
        (source / "bin").symlink_to(source / "real-bin")
    elif mutation == "hardlink_file":
        os.link(source / "bin/go", source / "bin/go-clone")
    elif mutation == "writable_source":
        (source / "src/runtime").chmod(0o777)
    elif mutation == "pth":
        (source / "src/runtime/bootstrap.pth").write_bytes(b"import os\n")
    elif mutation == "special_fifo":
        os.mkfifo(source / "bin/pipe")
    elif mutation == "invalid_provisioner":
        alias = tmp_path / "alias"
        alias.symlink_to(source.parent)
        kwargs["provisioner_root"] = str(alias)
    else:
        kwargs["kind"] = "python_direct"
    with pytest.raises(D4RuntimeTreeDenied):
        observe_d4_operator_source_manifest(**kwargs)


def test_operator_source_manifest_rejects_modified_inode_during_read(
        tmp_path, monkeypatch):
    from gateway.lbe_runtime_tree import (
        D4RuntimeTreeDenied, observe_d4_operator_source_manifest,
    )
    _private, source, _expected = _stage_fixture(tmp_path)
    real_read = os.read
    changed = []
    def rewrite_during_read(fd, count):
        data = real_read(fd, count)
        if data == b"inert Go runtime entrypoint" and not changed:
            (source / "bin/go").write_bytes(b"changed whilst observed")
            changed.append(True)
        return data

    with monkeypatch.context() as m:
        m.setattr(os, "read", rewrite_during_read)
        with pytest.raises(D4RuntimeTreeDenied):
            observe_d4_operator_source_manifest(
                provisioner_root=str(source.parent), kind="go")
    assert changed


def test_operator_manifest_entry_budget_refuses_unbounded_source_scan(
        tmp_path, monkeypatch):
    import gateway.lbe_runtime_tree as tree

    _private, source, _expected = _stage_fixture(tmp_path)
    for n in range(20):
        (source / "bin" / f"extra-{n}.txt").write_bytes(b"unused")
    def no_listdir(*_args, **_kwargs):
        raise AssertionError("unbounded listdir not allowed")
    with monkeypatch.context() as m:
        m.setattr(os, "listdir", no_listdir)
        m.setattr(tree, "_MAX_ENTRIES", 8)
        with pytest.raises(tree.D4RuntimeTreeDenied):
            tree.observe_d4_operator_source_manifest(
                provisioner_root=str(source.parent), kind="go")


def test_operator_reviewed_manifest_rejects_after_observation_source_drift(
        tmp_path):
    from gateway.lbe_runtime_tree import observe_d4_operator_source_manifest

    private, source, _expected = _stage_fixture(tmp_path)
    offered = observe_d4_operator_source_manifest(
        provisioner_root=str(source.parent), kind="go")
    (source / "src/runtime/runtime.go").write_bytes(b"package changed\n")
    with pytest.raises(D4RuntimeStageDenied):
        stage_d4_operator_runtime_tree(
            private_root=str(private), provisioner_root=str(source.parent),
            kind="go", expected=offered.proposed_manifest)
    assert not (private / "go").exists()



def test_review_pinned_operator_identity_rejects_same_bytes_replaced_inode(
        tmp_path, monkeypatch):
    """A pre-reviewed observed tree is not just a content-addressed manifest.

    Same file SHA after an atomic inode replacement must not transfer the old
    source-tree observation to a new, unreviewed staging attempt. No child.
    """
    from gateway.lbe_runtime_tree import observe_d4_operator_source_manifest

    private, source, expected = _stage_fixture(tmp_path, kind="go")
    original = observe_d4_operator_source_manifest(
        provisioner_root=str(source.parent), kind="go")
    selected = source / "bin/go"
    replacement = source.parent / "new-go"
    replacement.write_bytes(selected.read_bytes())
    replacement.chmod(0o700)
    prior_inode = selected.stat().st_ino
    os.replace(replacement, selected)
    assert selected.stat().st_ino != prior_inode
    assert hashlib.sha256(selected.read_bytes()).hexdigest() == (
        dict(original.proposed_manifest)["bin/go"])

    with monkeypatch.context() as m:
        m.setattr(subprocess, "Popen", lambda *_a, **_kw: (
            _ for _ in ()).throw(AssertionError("no native child")))
        with pytest.raises(D4RuntimeStageDenied, match="identity"):
            stage_d4_operator_runtime_tree(
                private_root=str(private),
                provisioner_root=str(source.parent), kind="go",
                expected=expected, expected_source_identity_sha256=(
                    original.observed_source_identity_sha256))
    assert not (private / "go").exists()


@pytest.mark.parametrize("invalid", [None, "f" * 64, "0" * 64,
                                    123, "", True, "A" * 64])
def test_review_pinned_source_tree_identity_type_and_value_before_staging(
        tmp_path, invalid):
    from gateway.lbe_runtime_tree import observe_d4_operator_source_manifest

    private, source, expected = _stage_fixture(tmp_path, kind="go")
    observed = observe_d4_operator_source_manifest(
        provisioner_root=str(source.parent), kind="go")
    # None preserves the existing unbound SOURCE-only internal interface.
    if invalid is None:
        receipt = stage_d4_operator_runtime_tree(
            private_root=str(private), provisioner_root=str(source.parent),
            kind="go", expected=expected)
        assert receipt.review_source_identity_bound is False
        assert receipt.source_identity_sha256 == (
            observed.observed_source_identity_sha256)
    else:
        with pytest.raises(D4RuntimeStageDenied):
            stage_d4_operator_runtime_tree(
                private_root=str(private),
                provisioner_root=str(source.parent), kind="go",
                expected=expected, expected_source_identity_sha256=invalid)
        assert not (private / "go").exists()


def test_review_pinned_operator_tree_staging_retains_nonoperative_provenance(
        tmp_path, monkeypatch):
    from gateway.lbe_runtime_tree import observe_d4_operator_source_manifest

    private, source, known_expected = _stage_fixture(tmp_path, kind="lib")
    reviewed = observe_d4_operator_source_manifest(
        provisioner_root=str(source.parent), kind="lib")
    assert reviewed.proposed_manifest == tuple(sorted(known_expected))
    with monkeypatch.context() as m:
        m.setattr(subprocess, "Popen", lambda *_a, **_kw: (
            _ for _ in ()).throw(AssertionError("identity cannot spawn")))
        receipt = stage_d4_operator_runtime_tree(
            private_root=str(private), provisioner_root=str(source.parent),
            kind="lib", expected=known_expected,
            expected_source_identity_sha256=(
                reviewed.observed_source_identity_sha256))
    assert receipt.review_source_identity_bound is True
    assert receipt.source_identity_sha256 == (
        reviewed.observed_source_identity_sha256)
    assert receipt.owner_provisioner_attested is False
    assert receipt.native_launch_allowed is False
