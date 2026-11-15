"""Safe read-only fake Pipenv input fixture; never loads/interprets Python."""
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess

import pytest

from gateway.lbe_pipenv_fixture_t0 import (
    LbePipenvFixtureT0Denied, inspect_private_pipenv_fixture_t0,
    authorize_native_pipenv_from_t0,
)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@pytest.fixture
def fixture(tmp_path: Path):
    root = tmp_path.resolve() / "project"
    (root / ".venv" / "bin").mkdir(parents=True)
    files = {
        "Pipfile": b"[[source]]\nurl = 'offline-fixture'\n",
        "Pipfile.lock": json.dumps({
            "_meta": {"hash": {"sha256": "e" * 64}},
            "default": {},
        }).encode("ascii"),
        ".venv/pyvenv.cfg": b"home = /fake/fixed/python\n",
        ".venv/bin/python": b"non-executable-content-fixture-not-a-real-Python\n",
    }
    for relative, data in files.items():
        location = root / relative
        location.write_bytes(data)
        location.chmod(0o700 if relative == ".venv/bin/python" else 0o600)
    expected = {
        "project_root": str(root),
        "expected_pipfile_sha256": _sha(files["Pipfile"]),
        "expected_lock_sha256": _sha(files["Pipfile.lock"]),
        "expected_pyvenv_cfg_sha256": _sha(files[".venv/pyvenv.cfg"]),
        "expected_python_sha256": _sha(files[".venv/bin/python"]),
    }
    return root, expected


def _check(options):
    return inspect_private_pipenv_fixture_t0(**options)


def test_valid_source_files_snapshot_only_no_native_load(fixture, monkeypatch):
    _root, expected = fixture
    def forbidden(*_args, **_kwargs):
        raise AssertionError("native Popen/socket not authorized by T0")
    with monkeypatch.context() as m:
        m.setattr(subprocess, "Popen", forbidden)
        m.setattr(subprocess, "run", forbidden)
        m.setattr(socket, "socket", forbidden)
        witness = _check(expected)
    assert witness.file_snapshot_observed
    assert witness.status == "NONOPERATIVE_PRIVATE_VENV_FILE_SNAPSHOT_T0"
    assert witness.pipfile_sha256 == expected["expected_pipfile_sha256"]
    assert witness.actual_interpreter_loaded is False
    assert witness.imported_site_qualified is False
    assert witness.native_launch_allowed is False
    assert witness.product_apply_allowed is False
    with pytest.raises(LbePipenvFixtureT0Denied, match="PIPENV_NATIVE=NOT_RUN"):
        authorize_native_pipenv_from_t0(witness)


def test_pointer_regular_venv_file_does_not_redirect_outside_project(fixture):
    root, expected = fixture
    import shutil
    shutil.rmtree(root / ".venv")
    (root / ".venv").write_text("../other-env\n", encoding="ascii")
    with pytest.raises((LbePipenvFixtureT0Denied, OSError)):
        _check(expected)


def test_venv_symlink_inside_or_outside_rejected(fixture, tmp_path):
    root, expected = fixture
    original = root / ".venv"
    original.rename(root / ".venv-original")
    for destination in (root / ".venv-original", tmp_path.resolve()):
        alias = root / ".venv"
        alias.symlink_to(destination, target_is_directory=True)
        with pytest.raises((LbePipenvFixtureT0Denied, OSError)):
            _check(expected)
        alias.unlink()


def test_symlinked_project_ancestor_rejected(fixture, tmp_path):
    root, expected = fixture
    alias = tmp_path.resolve() / "project-link"
    alias.symlink_to(root, target_is_directory=True)
    with pytest.raises((LbePipenvFixtureT0Denied, OSError)):
        _check({**expected, "project_root": str(alias)})


@pytest.mark.parametrize("name", [
    "Pipfile", "Pipfile.lock", ".venv/pyvenv.cfg", ".venv/bin/python",
])
def test_symlinked_required_files_rejected(fixture, name):
    root, expected = fixture
    path = root / name
    content = path.read_bytes()
    path.unlink()
    alternative = root / "other-input"
    alternative.write_bytes(content)
    path.symlink_to(alternative)
    with pytest.raises((LbePipenvFixtureT0Denied, OSError)):
        _check(expected)


@pytest.mark.parametrize("name", [
    "Pipfile", "Pipfile.lock", ".venv/pyvenv.cfg", ".venv/bin/python",
])
def test_hardlinked_required_files_rejected(fixture, name):
    root, expected = fixture
    target = root / name
    os.link(target, root / "duplicate")
    with pytest.raises(LbePipenvFixtureT0Denied):
        _check(expected)


@pytest.mark.parametrize("name", [
    "Pipfile", "Pipfile.lock", ".venv/pyvenv.cfg", ".venv/bin/python",
])
def test_mutated_file_bytes_require_rechecking_current_snapshot(fixture, name):
    root, expected = fixture
    first = _check(expected)
    assert first.native_launch_allowed is False
    with (root / name).open("ab") as dest:
        dest.write(b"changed")
    with pytest.raises(LbePipenvFixtureT0Denied):
        _check(expected)


@pytest.mark.parametrize("name", ["project", "project/.venv", "project/.venv/bin"])
def test_group_writable_directories_are_not_a_qualified_fixture(
    fixture, tmp_path, name,
):
    _root, expected = fixture
    directory = tmp_path.resolve() / name
    old_mode = directory.stat().st_mode & 0o777
    try:
        directory.chmod(0o770)
        with pytest.raises(LbePipenvFixtureT0Denied):
            _check(expected)
    finally:
        directory.chmod(old_mode)


def test_non_owner_executable_python_rejected(fixture):
    root, expected = fixture
    (root / ".venv/bin/python").chmod(0o600)
    with pytest.raises(LbePipenvFixtureT0Denied):
        _check(expected)


@pytest.mark.parametrize("filename", [
    "Pipfile", "Pipfile.lock", ".venv/pyvenv.cfg", ".venv/bin/python",
])
def test_untrusted_permission_write_bit_denied(fixture, filename):
    root, expected = fixture
    (root / filename).chmod(0o666)
    with pytest.raises(LbePipenvFixtureT0Denied):
        _check(expected)


def test_malformed_pipfile_lock_metadata_denied_even_if_bytes_are_pinned(
    fixture,
):
    root, expected = fixture
    data = b'{"_meta":{"hash":{"sha256":"not-hex"}}}'
    path = root / "Pipfile.lock"
    path.write_bytes(data)
    replaced_options = {**expected, "expected_lock_sha256": _sha(data)}
    with pytest.raises(LbePipenvFixtureT0Denied):
        _check(replaced_options)


@pytest.mark.parametrize("field,value", [
    ("project_root", "../project"),
    ("project_root", "/tmp/../project"),
    ("expected_lock_sha256", "0" * 64),
    ("expected_lock_sha256", "B" * 64),
    ("expected_python_sha256", True),
    ("expected_pipfile_sha256", "x" * 64),
])
def test_bad_root_and_declared_hash_shape_denied(fixture, field, value):
    _root, expected = fixture
    with pytest.raises(LbePipenvFixtureT0Denied):
        _check({**expected, field: value})


def test_forged_file_snapshot_flags_cannot_authorize_native(fixture):
    _root, expected = fixture
    candidate = replace(
        _check(expected), native_launch_allowed=True,
        product_apply_allowed=True, imported_site_qualified=True,
        actual_interpreter_loaded=True, blockers=(),
    )
    with pytest.raises(LbePipenvFixtureT0Denied):
        authorize_native_pipenv_from_t0(candidate)



# D7 RED: a bounded private Python executable may be larger than the
# 1 MiB cap for metadata text. These are NON-PYTHON fixture bytes and
# MUST never be loaded or spawned.
def test_d7_large_fake_python_file_stream_snapshot_no_execute(fixture, monkeypatch):
    root, expected = fixture
    payload = b"D7-NOT-A-REAL-PYTHON-IMAGE\n" * 90000
    assert len(payload) > 1024 * 1024
    path = root / ".venv/bin/python"
    path.write_bytes(payload)
    path.chmod(0o700)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("T0 source hashing may not launch a process or network")

    with monkeypatch.context() as m:
        m.setattr(subprocess, "Popen", forbidden)
        m.setattr(subprocess, "run", forbidden)
        m.setattr(socket, "socket", forbidden)
        snap = _check({**expected, "expected_python_sha256": _sha(payload)})
    assert snap.python_file_sha256 == _sha(payload)
    assert snap.native_launch_allowed is False
    assert snap.product_apply_allowed is False
    with pytest.raises(LbePipenvFixtureT0Denied, match="PIPENV_NATIVE=NOT_RUN"):
        authorize_native_pipenv_from_t0(snap)


@pytest.mark.parametrize("text_path,expected_key", [
    ("Pipfile.lock", "expected_lock_sha256"),
    (".venv/pyvenv.cfg", "expected_pyvenv_cfg_sha256"),
])
def test_d7_large_text_source_keeps_small_metadata_limit(fixture, text_path, expected_key):
    root, expected = fixture
    # Exactly one byte beyond the existing 1 MiB *text* limit.
    payload = b"x" * (1024 * 1024 + 1)
    (root / text_path).write_bytes(payload)
    with pytest.raises(LbePipenvFixtureT0Denied, match="oversized"):
        _check({**expected, expected_key: _sha(payload)})


def test_d7_python_digest_detects_same_size_rewrite(fixture):
    root, expected = fixture
    path = root / ".venv/bin/python"
    first = path.read_bytes()
    assert _check(expected).native_launch_allowed is False
    replacement = b"Q" + first[1:]
    assert len(first) == len(replacement)
    path.write_bytes(replacement)
    with pytest.raises(LbePipenvFixtureT0Denied, match="digest mismatch"):
        _check(expected)


def test_d7_python_byte_limit_remains_bounded(fixture, monkeypatch):
    import gateway.lbe_pipenv_fixture_t0 as subject
    _root, expected = fixture
    with monkeypatch.context() as m:
        m.setattr(subject, "_MAX_PYTHON_EXECUTABLE_BYTES", 16)
        with pytest.raises(LbePipenvFixtureT0Denied, match="oversized"):
            _check(expected)



# r006: six deterministic original-FD metadata mutation regressions.
# Test-only os.read hook mutates disposable first-party fake bytes AFTER the
# source code's pre-read fstat but BEFORE post-read fstat. Never spawn code.
@pytest.mark.parametrize("relative", [
    "Pipfile", "Pipfile.lock", ".venv/pyvenv.cfg",
])
@pytest.mark.parametrize("mutation", ["chmod", "hardlink"])
def test_r006_inflight_pipenv_metadata_mutation_is_rejected(
    fixture, monkeypatch, relative, mutation,
):
    root, expected = fixture
    target = root / relative
    identity = target.stat()
    real_read = os.read
    touched = []

    def read_then_modify(fd, count):
        data = real_read(fd, count)
        if (data and not touched
                and os.fstat(fd).st_dev == identity.st_dev
                and os.fstat(fd).st_ino == identity.st_ino):
            touched.append(fd)
            if mutation == "chmod":
                target.chmod(0o666)
            else:
                os.link(target, root / "race-added-hardlink")
        return data

    with monkeypatch.context() as m:
        m.setattr(os, "read", read_then_modify)
        with pytest.raises(LbePipenvFixtureT0Denied,
                           match="fixture inode changed during read"):
            _check(expected)

    assert len(touched) == 1, "the original open FD was really inspected"
    with pytest.raises(OSError):
        os.fstat(touched[0])  # error path closes the selected file descriptor
    final = target.stat()
    if mutation == "chmod":
        assert final.st_mode & 0o022
    else:
        assert final.st_nlink == 2


@pytest.mark.parametrize("relative,field", [
    ("Pipfile", "expected_pipfile_sha256"),
    ("Pipfile.lock", "expected_lock_sha256"),
    (".venv/pyvenv.cfg", "expected_pyvenv_cfg_sha256"),
])
def test_r006_unchanged_one_mib_pipenv_metadata_is_allowed(
    fixture, relative, field,
):
    root, expected = fixture
    target = root / relative
    original = target.read_bytes()
    assert len(original) < 1024 * 1024
    data = original + b" " * (1024 * 1024 - len(original))
    target.write_bytes(data)
    result = _check({**expected, field: _sha(data)})
    assert result.file_snapshot_observed is True
    assert result.native_launch_allowed is False
    assert result.product_apply_allowed is False
