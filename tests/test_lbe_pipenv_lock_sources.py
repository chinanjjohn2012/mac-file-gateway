"""SOURCE-only Pipfile.lock-to-RECORD consistency, never Pipenv execution."""
import hashlib
import json
import os

import pytest

from gateway.lbe_pipenv_lock_sources import (
    D4PipenvLockDenied, inspect_d4_pipenv_lock_sources,
)


def _fixture(tmp_path, default=None, develop=None):
    root = tmp_path / "selected-pipenv"
    root.mkdir(mode=0o700)
    data = {
        "_meta": {"hash": {"sha256": "a" * 64}},
        "default": {"example-pkg": {"version": "==1.0"}}
        if default is None else default,
        "develop": {} if develop is None else develop,
    }
    raw = (json.dumps(data, separators=(",", ":")) + "\n").encode()
    (root / "Pipfile.lock").write_bytes(raw)
    return root, hashlib.sha256(raw).hexdigest()


def test_lock_matches_pinned_record_distributions_without_native(tmp_path, monkeypatch):
    root, digest = _fixture(tmp_path)
    candidate = inspect_d4_pipenv_lock_sources(
        project_root=str(root), expected_lock_sha256=digest,
        expected_distributions=(("example-pkg", "1.0"), ("pip", "25.0")))
    assert candidate.lock_sha256 == digest
    assert candidate.locked_distributions == (("example-pkg", "1.0"),)
    assert candidate.native_launch_allowed is False
    assert candidate.actual_loaded_source_graph_proven is False
    assert candidate.publisher_attested is False


@pytest.mark.parametrize("locked,selected", [
    ({"example-pkg": {"version": "==2.0"}}, (("example-pkg", "1.0"),)),
    ({"example-pkg": {"version": ">=1.0"}}, (("example-pkg", "1.0"),)),
    ({"example-pkg": {"path": "../other"}}, (("example-pkg", "1.0"),)),
    ({"example-pkg": {"version": "==1.0", "path": "../other"}}, (("example-pkg", "1.0"),)),
    ({}, (("example-pkg", "1.0"),)),
    ({"extra": {"version": "==1.0"}}, (("example-pkg", "1.0"),)),
    ({"example-pkg": {"version": "==1.0", "hashes": ["sha256:broken"]}}, (("example-pkg", "1.0"),)),
])
def test_lock_version_override_or_missing_distribution_denied(tmp_path, locked, selected):
    root, digest = _fixture(tmp_path, default=locked)
    with pytest.raises(D4PipenvLockDenied):
        inspect_d4_pipenv_lock_sources(
            project_root=str(root), expected_lock_sha256=digest,
            expected_distributions=selected)


def test_lock_develop_requires_exact_selected_site(tmp_path):
    root, digest = _fixture(tmp_path, develop={"pytest": {"version": "==8.2.0"}})
    with pytest.raises(D4PipenvLockDenied):
        inspect_d4_pipenv_lock_sources(
            project_root=str(root), expected_lock_sha256=digest,
            expected_distributions=(("example-pkg", "1.0"),))
    approved = inspect_d4_pipenv_lock_sources(
        project_root=str(root), expected_lock_sha256=digest,
        expected_distributions=(("example-pkg", "1.0"), ("pytest", "8.2.0")))
    assert len(approved.locked_distributions) == 2


@pytest.mark.parametrize("change", ["digest", "rewrite", "symlink", "hardlink", "duplicate_json"])
def test_lock_input_provenance_mutation_fails_closed(tmp_path, change):
    root, digest = _fixture(tmp_path)
    lock = root / "Pipfile.lock"
    if change == "digest":
        digest = "f" * 64
    elif change == "rewrite":
        lock.write_bytes(lock.read_bytes().replace(b"==1.0", b"==2.0"))
    elif change == "symlink":
        other = tmp_path / "outside.lock"
        other.write_bytes(lock.read_bytes())
        lock.unlink()
        lock.symlink_to(other)
    elif change == "hardlink":
        os.link(lock, tmp_path / "linked.lock")
    elif change == "duplicate_json":
        lock.write_bytes(b'{"_meta":{"hash":{"sha256":"' + b"a" * 64 +
                         b'"}},"default":{"example-pkg":{"version":"==1.0"},'
                         b'"example-pkg":{"version":"==2.0"}}}')
        digest = hashlib.sha256(lock.read_bytes()).hexdigest()
    with pytest.raises(D4PipenvLockDenied):
        inspect_d4_pipenv_lock_sources(
            project_root=str(root), expected_lock_sha256=digest,
            expected_distributions=(("example-pkg", "1.0"),))



@pytest.mark.parametrize("pipfile,expected_success", [
    ('[packages]\nexample-pkg = "==1.0"\n', True),
    ('[packages]\nexample-pkg = "*"\n', True),
    ('[packages]\nexample-pkg = "==2.0"\n', False),
    ('[packages]\nunknown = "==1.0"\n', False),
    ('[packages]\nexample-pkg = {path="../foreign"}\n', False),
    ('[packages]\nexample-pkg = {version="==1.0",index="other"}\n', False),
    ('[dev-packages]\nexample-pkg = "==1.0"\n', False),
    ('[packages]\n', False),
])
def test_real_pipfile_intent_matches_exact_lock_and_record(
        tmp_path, pipfile, expected_success):
    root, lock_digest = _fixture(tmp_path)
    raw = pipfile.encode("ascii")
    (root / "Pipfile").write_bytes(raw)
    expected = hashlib.sha256(raw).hexdigest()
    kwargs = dict(project_root=str(root), expected_lock_sha256=lock_digest,
                  expected_pipfile_sha256=expected,
                  expected_distributions=(("example-pkg", "1.0"),))
    if expected_success:
        receipt = inspect_d4_pipenv_lock_sources(**kwargs)
        assert receipt.pipfile_sha256 == expected
        assert receipt.direct_pipfile_requirements_checked is True
        assert receipt.native_launch_allowed is False
    else:
        with pytest.raises(D4PipenvLockDenied):
            inspect_d4_pipenv_lock_sources(**kwargs)


@pytest.mark.parametrize("tamper", ["rewrite", "symlink", "hardlink", "wrong_hash"])
def test_pipfile_source_change_or_unowned_leaf_denied(tmp_path, tamper):
    root, lock_digest = _fixture(tmp_path)
    pipfile = root / "Pipfile"
    pipfile.write_bytes(b'[packages]\nexample-pkg="==1.0"\n')
    expected = hashlib.sha256(pipfile.read_bytes()).hexdigest()
    if tamper == "rewrite":
        pipfile.write_bytes(b'[packages]\nexample-pkg="==2.0"\n')
    elif tamper == "symlink":
        other = tmp_path / "foreign-pipfile"
        other.write_bytes(pipfile.read_bytes())
        pipfile.unlink()
        pipfile.symlink_to(other)
    elif tamper == "hardlink":
        os.link(pipfile, tmp_path / "linked-pipfile")
    elif tamper == "wrong_hash":
        expected = "f" * 64
    with pytest.raises(D4PipenvLockDenied):
        inspect_d4_pipenv_lock_sources(
            project_root=str(root), expected_lock_sha256=lock_digest,
            expected_pipfile_sha256=expected,
            expected_distributions=(("example-pkg", "1.0"),))
