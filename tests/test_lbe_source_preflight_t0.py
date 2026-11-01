"""Nonoperative SOURCE_CANDIDATE-only T0. No native Go/Pipenv imports or child.

Positive means a static plan was inspected; it is NOT native Go/Pipenv PASS.
Deliberately exercise fail-closed GOFLAGS, private .venv and network claim.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess

import pytest

from gateway.lbe_source_preflight import (
    LbeSourcePreflightError,
    inspect_go_source_t0,
    inspect_pipenv_source_t0,
    require_real_egress_witness_t0,
)


def _make(root: Path, name: str, data: bytes, *, executable=False) -> str:
    item = root.joinpath(*name.split("/"))
    item.parent.mkdir(parents=True, exist_ok=True)
    item.write_bytes(data)
    if executable:
        item.chmod(0o700)
    return hashlib.sha256(data).hexdigest()


@pytest.fixture
def go_candidate(tmp_path: Path):
    root = tmp_path / "only-private"
    root.mkdir(mode=0o700)
    members = {
        "go/VERSION": _make(root, "go/VERSION", b"go1.27.3\n"),
        "go/bin/go": _make(root, "go/bin/go", b"not real Go native code", executable=True),
        "go/pkg/tool/darwin_arm64/compile": _make(
            root, "go/pkg/tool/darwin_arm64/compile", b"not real compile", executable=True),
        "go/pkg/tool/darwin_arm64/link": _make(
            root, "go/pkg/tool/darwin_arm64/link", b"not real link", executable=True),
        "go/src/runtime/proc.go": _make(
            root, "go/src/runtime/proc.go", b"package runtime\n"),
    }
    return root, members


@pytest.fixture
def pipenv_candidate(tmp_path: Path):
    root = tmp_path / "only-private"
    root.mkdir(mode=0o700)
    members = {
        "project/Pipfile": _make(root, "project/Pipfile", b"[packages]\n"),
        "project/Pipfile.lock": _make(root, "project/Pipfile.lock", b'{"_meta": {}}\n'),
        "project/.venv/pyvenv.cfg": _make(
            root, "project/.venv/pyvenv.cfg", b"version = 3.13\n"),
        "project/.venv/bin/python": _make(
            root, "project/.venv/bin/python", b"not a real Python interpreter", executable=True),
    }
    return root, members


def _go(scene, env=None):
    root, members = scene
    return inspect_go_source_t0(
        private_root=root, trusted_base=root.parent, expected_members=members,
        parent_env={"PATH": "/trusted/bin", **(env or {})},
        expected_parent_path="/trusted/bin")


def _pipenv(scene, env=None):
    root, members = scene
    return inspect_pipenv_source_t0(
        private_root=root, trusted_base=root.parent, expected_members=members,
        parent_env={"PATH": "/trusted/bin", **(env or {})},
        expected_parent_path="/trusted/bin")


def test_go_static_pass_never_authorizes_native(go_candidate, monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("any real process creation is forbidden in T0")
    monkeypatch.setattr(subprocess.Popen, "__init__", forbidden)
    x = _go(go_candidate)
    assert x["kind"] == "go"
    assert x["status"] == "SOURCE_CANDIDATE_ONLY"
    assert x["native_t1"] == "NOT_RUN"
    assert x["egress_enforcement"] == "NOT_ATTESTED"
    assert x["exec_authorized"] is False
    assert len(x["checked_member_sha256"]) == 5


@pytest.mark.parametrize("key,value", [
    ("GOFLAGS", "-toolexec=/outside/unqualified-helper"),
    ("GOFLAGS", "-exec=/outside"),
    ("GOEXPERIMENT", "loopvar"),
    ("GOCACHEPROG", "/outside/helper"),
    ("GOTOOLDIR", "/outside/compiler"),
    ("GOPROXY", "https://untrusted.invalid"),
    ("GOENV", "/outside/goenv"),
    ("CC", "/outside/compiler"),
    ("CXX", "/outside/compiler"),
    ("DYLD_INSERT_LIBRARIES", "/outside/lib.dylib"),
    ("PYTHONPATH", "/outside/site-packages"),
    ("PATH", "/outside"),
])
def test_go_inherited_tool_selector_fails_before_child(go_candidate, key, value):
    with pytest.raises(LbeSourcePreflightError):
        _go(go_candidate, {key: value})


def test_go_empty_GOFLAGS_is_not_an_authorization(go_candidate):
    x = _go(go_candidate, {"GOFLAGS": ""})
    assert x["exec_authorized"] is False


def test_go_missing_or_tampered_critical_source_fails(go_candidate):
    root, members = go_candidate
    with pytest.raises(LbeSourcePreflightError):
        inspect_go_source_t0(
            private_root=root, trusted_base=root.parent,
            expected_members={"go/bin/go": members["go/bin/go"]},
            parent_env={"PATH": "/trusted/bin"}, expected_parent_path="/trusted/bin")
    (root / "go/bin/go").write_bytes(b"replaced")
    with pytest.raises(LbeSourcePreflightError):
        _go(go_candidate)


def test_go_symlink_or_hardlink_member_fails(go_candidate, tmp_path):
    root, _ = go_candidate
    item = root / "go/bin/go"
    original = root / "go/bin/original"
    item.rename(original)
    item.symlink_to(original)
    with pytest.raises(LbeSourcePreflightError):
        _go(go_candidate)
    item.unlink()
    os.link(original, item)
    with pytest.raises(LbeSourcePreflightError):
        _go(go_candidate)


def test_untrusted_or_missing_private_root_is_denied(go_candidate):
    root, _ = go_candidate
    root.chmod(0o777)
    with pytest.raises(LbeSourcePreflightError):
        _go(go_candidate)
    root.chmod(0o700)
    root.rename(root.parent / "moved")
    with pytest.raises(LbeSourcePreflightError):
        _go(go_candidate)


def test_pipenv_private_directory_candidate_never_runs(pipenv_candidate, monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("no Pipenv/venv child is allowed in T0")
    monkeypatch.setattr(subprocess.Popen, "__init__", forbidden)
    x = _pipenv(pipenv_candidate)
    assert x["kind"] == "pipenv"
    assert x["status"] == "SOURCE_CANDIDATE_ONLY"
    assert x["native_t1"] == "NOT_RUN"
    assert x["exec_authorized"] is False
    assert x["selected_interpreter"].endswith("/project/.venv/bin/python")
    assert len(x["checked_member_sha256"]) == 4


@pytest.mark.parametrize("key,value", [
    ("WORKON_HOME", "/outside"),
    ("VIRTUAL_ENV", "/outside"),
    ("PIPENV_PYTHON", "/outside/bin/python"),
    ("PIPENV_ACTIVE", "1"),
    ("PIPENV_VIRTUALENV", "/outside"),
    ("PIPENV_VENV_IN_PROJECT", "1"),
    ("PIP_INDEX_URL", "https://untrusted.invalid"),
    ("PIP_CONFIG_FILE", "/outside/conf"),
    ("PYTHONPATH", "/outside"),
    ("DYLD_INSERT_LIBRARIES", "/outside/lib.dylib"),
    ("PATH", "/outside"),
])
def test_pipenv_selector_injection_fails_before_entrypoint(pipenv_candidate, key, value):
    with pytest.raises(LbeSourcePreflightError):
        _pipenv(pipenv_candidate, {key: value})


def test_pipenv_pointer_file_fails_even_when_target_exists(pipenv_candidate):
    root, _ = pipenv_candidate
    venv = root / "project/.venv"
    venv.rename(root / "project/real-venv")
    venv.write_text("../real-venv\n")
    with pytest.raises(LbeSourcePreflightError):
        _pipenv(pipenv_candidate)


def test_pipenv_symlink_private_venv_fails(pipenv_candidate):
    root, _ = pipenv_candidate
    venv = root / "project/.venv"
    venv.rename(root / "project/real-venv")
    venv.symlink_to(root / "project/real-venv", target_is_directory=True)
    with pytest.raises(LbeSourcePreflightError):
        _pipenv(pipenv_candidate)


def test_pipenv_wrong_interpreter_or_lock_fails(pipenv_candidate):
    root, _ = pipenv_candidate
    (root / "project/.venv/bin/python").write_bytes(b"other interpreter")
    with pytest.raises(LbeSourcePreflightError):
        _pipenv(pipenv_candidate)


def test_pipenv_external_interpreter_symlink_fails(pipenv_candidate):
    root, _ = pipenv_candidate
    py = root / "project/.venv/bin/python"
    py.unlink()
    py.symlink_to("/usr/bin/python3")
    with pytest.raises(LbeSourcePreflightError):
        _pipenv(pipenv_candidate)


def test_pipenv_hardlinked_lock_fails(pipenv_candidate):
    root, _ = pipenv_candidate
    lock = root / "project/Pipfile.lock"
    copy = root / "project/other.lock"
    os.link(lock, copy)
    with pytest.raises(LbeSourcePreflightError):
        _pipenv(pipenv_candidate)


@pytest.mark.parametrize("fake", [None, True, False, "OFFLINE_ONLY", {
    "offline": True, "attached_to_child": True, "owner_approved": True,
}])
def test_client_claim_cannot_self_authorize_egress_or_native_T1(fake):
    with pytest.raises(LbeSourcePreflightError, match="T1=NOT_RUN"):
        require_real_egress_witness_t0(fake)
