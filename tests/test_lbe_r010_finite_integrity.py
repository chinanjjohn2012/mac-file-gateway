"""R010 finite filesystem observations: real local FS, no native Exec (T0)."""
import hashlib
import os
import socket
import stat
import subprocess

import pytest

from gateway.lbe_r010_finite_integrity import (
    R010FiniteIntegrityDenied, R010GoArtifactObservation,
    observe_selected_source_files, recheck_selected_source_files,
    observe_go_output_absent, inspect_go_build_artifact,
)


@pytest.fixture(autouse=True)
def no_foreign_execution(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("R010 T0 must not execute or connect")
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(os, "kill", forbidden)
    monkeypatch.setattr(os, "killpg", forbidden, raising=False)
    monkeypatch.setattr(socket.socket, "connect", forbidden)


@pytest.fixture
def source_root(tmp_path):
    src = tmp_path / "selected"
    src.mkdir(mode=0o700)
    (src / "pkg").mkdir(mode=0o700)
    (src / "pkg" / "__init__.py").write_bytes(b"")
    (src / "pkg" / "main.py").write_bytes(b"print('valid')\n")
    fd = os.open(src, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        yield src, fd
    finally:
        os.close(fd)


def test_real_selected_sources_compare_identical_bytes_and_metadata(source_root):
    _, fd = source_root
    paths = ("pkg/__init__.py", "pkg/main.py")
    before = observe_selected_source_files(root_fd=fd, relative_paths=paths)
    assert before.native_launch_allowed is False
    assert before.total_bytes == len(b"print('valid')\n")
    assert before.files[1][2] == hashlib.sha256(b"print('valid')\n").hexdigest()
    assert recheck_selected_source_files(root_fd=fd, expected=before) == before


@pytest.mark.parametrize("candidate", [
    "../pwd", "pkg/../main.py", "pkg//main.py", "/etc/passwd",
    "pkg/./main.py", "pkg\\main.py", "pkg/main.py\x00other",
])
def test_path_traversal_or_noncanonical_parts_are_denied(source_root, candidate):
    _, fd = source_root
    with pytest.raises(R010FiniteIntegrityDenied):
        observe_selected_source_files(root_fd=fd, relative_paths=(candidate,))


def test_duplicate_and_unsorted_selected_source_sets_denied(source_root):
    _, fd = source_root
    for paths in ((), ("pkg/main.py", "pkg/main.py"),
                  ("pkg/main.py", "pkg/__init__.py")):
        with pytest.raises(R010FiniteIntegrityDenied):
            observe_selected_source_files(root_fd=fd, relative_paths=paths)


def test_source_modified_after_pre_observation_denied(source_root):
    src, fd = source_root
    before = observe_selected_source_files(root_fd=fd, relative_paths=("pkg/main.py",))
    (src / "pkg" / "main.py").write_text("print('changed')\n")
    with pytest.raises(R010FiniteIntegrityDenied, match="changed"):
        recheck_selected_source_files(root_fd=fd, expected=before)


def test_symlink_hardlink_and_writable_source_denied(source_root):
    src, fd = source_root
    (src / "pkg" / "alias.py").symlink_to("main.py")
    with pytest.raises(R010FiniteIntegrityDenied):
        observe_selected_source_files(root_fd=fd, relative_paths=("pkg/alias.py",))
    (src / "pkg" / "alias.py").unlink()
    os.link(src / "pkg" / "main.py", src / "pkg" / "alias.py")
    with pytest.raises(R010FiniteIntegrityDenied):
        observe_selected_source_files(root_fd=fd, relative_paths=("pkg/main.py",))
    (src / "pkg" / "alias.py").unlink()
    (src / "pkg" / "main.py").chmod(0o666)
    with pytest.raises(R010FiniteIntegrityDenied):
        observe_selected_source_files(root_fd=fd, relative_paths=("pkg/main.py",))


def test_symlinked_or_writable_ancestor_denied(source_root):
    src, fd = source_root
    (src / "shadow").symlink_to("pkg", target_is_directory=True)
    with pytest.raises(R010FiniteIntegrityDenied):
        observe_selected_source_files(root_fd=fd, relative_paths=("shadow/main.py",))
    (src / "pkg").chmod(0o777)
    with pytest.raises(R010FiniteIntegrityDenied):
        observe_selected_source_files(root_fd=fd, relative_paths=("pkg/main.py",))


def test_source_directory_owner_control_denied_when_writable(source_root):
    src, fd = source_root
    src.chmod(0o777)
    with pytest.raises(R010FiniteIntegrityDenied):
        observe_selected_source_files(root_fd=fd, relative_paths=("pkg/main.py",))


@pytest.fixture
def go_parent(tmp_path):
    build = tmp_path / "bin"
    build.mkdir(mode=0o700)
    fd = os.open(build, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        yield build, fd
    finally:
        os.close(fd)


def test_go_build_artifact_is_finite_verified_observation_not_grant(go_parent):
    build, fd = go_parent
    absent = observe_go_output_absent(parent_fd=fd)
    assert absent.native_launch_allowed is False
    (build / "app").write_bytes(b"fake benign compiled output")
    (build / "app").chmod(0o700)
    output = inspect_go_build_artifact(parent_fd=fd, output_was_absent=absent)
    assert isinstance(output, R010GoArtifactObservation)
    assert output.native_launch_allowed is False
    assert output.size_bytes == len(b"fake benign compiled output")
    assert output.sha256 == hashlib.sha256(b"fake benign compiled output").hexdigest()
    assert stat.S_ISREG(output.file_identity[3])


def test_go_existing_output_or_symlink_does_not_qualify(go_parent):
    build, fd = go_parent
    (build / "app").write_bytes(b"old")
    with pytest.raises(R010FiniteIntegrityDenied, match="not a new"):
        observe_go_output_absent(parent_fd=fd)
    (build / "app").unlink()
    absent = observe_go_output_absent(parent_fd=fd)
    (build / "app").symlink_to("missing")
    with pytest.raises(R010FiniteIntegrityDenied):
        inspect_go_build_artifact(parent_fd=fd, output_was_absent=absent)


@pytest.mark.parametrize("mode", [0o600, 0o722, 0o777])
def test_go_nonexecutable_or_world_writable_output_denied(go_parent, mode):
    build, fd = go_parent
    absent = observe_go_output_absent(parent_fd=fd)
    (build / "app").write_bytes(b"app")
    (build / "app").chmod(mode)
    with pytest.raises(R010FiniteIntegrityDenied):
        inspect_go_build_artifact(parent_fd=fd, output_was_absent=absent)


def test_go_hardlinked_and_empty_output_denied(go_parent):
    build, fd = go_parent
    absent = observe_go_output_absent(parent_fd=fd)
    (build / "app").touch(mode=0o700)
    with pytest.raises(R010FiniteIntegrityDenied):
        inspect_go_build_artifact(parent_fd=fd, output_was_absent=absent)
    (build / "app").write_bytes(b"x")
    (build / "app").chmod(0o700)
    os.link(build / "app", build / "other")
    with pytest.raises(R010FiniteIntegrityDenied):
        inspect_go_build_artifact(parent_fd=fd, output_was_absent=absent)


def test_go_replaced_output_parent_denied(go_parent):
    build, fd = go_parent
    absent = observe_go_output_absent(parent_fd=fd)
    build.rename(build.with_name("old-bin"))
    replacement = build
    replacement.mkdir(mode=0o700)
    fd2 = os.open(replacement, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        (replacement / "app").write_bytes(b"app")
        (replacement / "app").chmod(0o700)
        with pytest.raises(R010FiniteIntegrityDenied, match="parent was replaced"):
            inspect_go_build_artifact(parent_fd=fd2, output_was_absent=absent)
    finally:
        os.close(fd2)


def test_go_oversized_sparse_artifact_denied_without_reading(go_parent):
    build, fd = go_parent
    absent = observe_go_output_absent(parent_fd=fd)
    with open(build / "app", "wb") as out:
        out.truncate(67108865)
    (build / "app").chmod(0o700)
    with pytest.raises(R010FiniteIntegrityDenied):
        inspect_go_build_artifact(parent_fd=fd, output_was_absent=absent)
