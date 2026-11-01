"""T0 only: synthetic source/env binding. Never import/launch Go or Pipenv."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess

import pytest

from gateway.lbe_prelaunch_binding_t0 import (
    LbePrelaunchBindingT0Error,
    bind_go_prelaunch_t0, bind_pipenv_prelaunch_t0,
)

_HOST = "/usr/bin:/bin:/usr/sbin:/sbin"


def _file(root, name, payload, executable=False):
    p = root / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(payload)
    if executable:
        p.chmod(0o700)
    return hashlib.sha256(payload).hexdigest()


@pytest.fixture
def scene(tmp_path):
    root = tmp_path / "stage"
    root.mkdir(mode=0o700)
    go = {
        "go/VERSION": _file(root, "go/VERSION", b"go1.27.3\\n"),
        "go/bin/go": _file(root, "go/bin/go", b"fake go", True),
        "go/pkg/tool/darwin_arm64/compile": _file(
            root, "go/pkg/tool/darwin_arm64/compile", b"fake compile", True),
        "go/pkg/tool/darwin_arm64/link": _file(
            root, "go/pkg/tool/darwin_arm64/link", b"fake link", True),
        "go/src/runtime/proc.go": _file(
            root, "go/src/runtime/proc.go", b"package runtime\\n"),
    }
    pipenv = {
        "project/Pipfile": _file(root, "project/Pipfile", b"[packages]\\n"),
        "project/Pipfile.lock": _file(root, "project/Pipfile.lock", b"{}\\n"),
        "project/.venv/pyvenv.cfg": _file(
            root, "project/.venv/pyvenv.cfg", b"version=3.13\\n"),
        "project/.venv/bin/python": _file(
            root, "project/.venv/bin/python", b"fake python", True),
        "pipenv-env/bin/pipenv": _file(
            root, "pipenv-env/bin/pipenv", b"fake pipenv", True),
    }
    return root, go, pipenv


def _call(scene, kind, **changes):
    root, go, pipenv = scene
    args = dict(private_root=root, trusted_base=root.parent,
                expected_members=go if kind == "go" else pipenv,
                parent_env={"PATH": _HOST}, expected_parent_path=_HOST,
                home=root / "home", temp=root / "tmp")
    if kind == "go":
        args.update(go_path=root / "gopath", mod_cache=root / "gomodcache",
                    build_cache=root / "gocache")
    args.update(changes)
    return (bind_go_prelaunch_t0 if kind == "go" else
            bind_pipenv_prelaunch_t0)(**args)


@pytest.mark.parametrize("kind", ["go", "pipenv"])
def test_positive_source_and_env_binds_but_never_grants_exec(scene, kind, monkeypatch):
    def forbidden(*_a, **_k):
        raise AssertionError("must never start child from T0")
    monkeypatch.setattr(subprocess.Popen, "__init__", forbidden)
    result = _call(scene, kind)
    assert result.kind == kind
    assert result.status == "NONOPERATIVE_PRELAUNCH_CANDIDATE_ONLY"
    assert result.exec_authorized is False
    assert result.original_child_native_t1 == "NOT_RUN"
    assert result.source_loaded_identity == "NOT_ATTESTED"
    assert result.network_precontact_isolation == "NOT_ATTESTED"
    assert result.child_env["PATH"].split(os.pathsep)[-4:] == [
        "/usr/bin", "/bin", "/usr/sbin", "/sbin"]
    assert result.checked_member_sha256
    with pytest.raises(TypeError):
        result.child_env["PATH"] = "/outside"
    with pytest.raises(TypeError):
        result.checked_member_sha256["fake"] = "x"


@pytest.mark.parametrize("kind", ["go", "pipenv"])
def test_hostile_parent_selector_rejected_even_with_valid_source(scene, kind):
    parent = {"PATH": _HOST, "GOFLAGS": "-toolexec=/outside"} if kind == "go" else {
        "PATH": _HOST, "PIPENV_PYTHON": "/outside/python"}
    with pytest.raises(LbePrelaunchBindingT0Error):
        _call(scene, kind, parent_env=parent)


@pytest.mark.parametrize("kind", ["go", "pipenv"])
@pytest.mark.parametrize("path", ["/outside/bin", "/usr/bin::/sbin",
                                  "/usr/bin:/bin:relative"])
def test_parent_path_shadow_or_empty_segment_denied(scene, kind, path):
    with pytest.raises(LbePrelaunchBindingT0Error):
        _call(scene, kind, parent_env={"PATH": path},
              expected_parent_path=path)


@pytest.mark.parametrize("kind", ["go", "pipenv"])
def test_wrong_trusted_base_denied(scene, kind):
    with pytest.raises(LbePrelaunchBindingT0Error):
        _call(scene, kind, trusted_base=scene[0])


@pytest.mark.parametrize("kind", ["go", "pipenv"])
def test_tampered_checked_source_is_denied(scene, kind):
    root = scene[0]
    changed = "go/bin/go" if kind == "go" else "project/.venv/bin/python"
    (root / changed).write_bytes(b"tampered")
    with pytest.raises(LbePrelaunchBindingT0Error):
        _call(scene, kind)


@pytest.mark.parametrize("kind", ["go", "pipenv"])
def test_missing_critical_member_denied(scene, kind):
    members = dict(scene[1] if kind == "go" else scene[2])
    members.pop("go/bin/go" if kind == "go" else "project/.venv/bin/python")
    with pytest.raises(LbePrelaunchBindingT0Error):
        _call(scene, kind, expected_members=members)


def test_missing_pinned_pipenv_entrypoint_denied(scene):
    members = dict(scene[2])
    members.pop("pipenv-env/bin/pipenv")
    with pytest.raises(LbePrelaunchBindingT0Error):
        _call(scene, "pipenv", expected_members=members)


def test_tampered_pipenv_entrypoint_denied(scene):
    (scene[0] / "pipenv-env/bin/pipenv").write_bytes(b"tampered")
    with pytest.raises(LbePrelaunchBindingT0Error):
        _call(scene, "pipenv")


def test_nonexecutable_pipenv_entrypoint_denied(scene):
    (scene[0] / "pipenv-env/bin/pipenv").chmod(0o600)
    with pytest.raises(LbePrelaunchBindingT0Error):
        _call(scene, "pipenv")


def test_pipenv_pointer_file_denied(scene):
    root = scene[0]
    original = root / "project/.venv"
    for item in sorted(original.rglob("*"), key=lambda p: len(p.parts), reverse=True):
        if item.is_file():
            item.unlink()
        elif item.is_dir():
            item.rmdir()
    original.rmdir()
    original.write_text("../outside-env")
    with pytest.raises(LbePrelaunchBindingT0Error):
        _call(scene, "pipenv")


def test_pipenv_entrypoint_symlink_denied(scene):
    root = scene[0]
    exe = root / "pipenv-env/bin/pipenv"
    orig = exe.with_name("trusted")
    exe.rename(orig)
    exe.symlink_to(orig)
    with pytest.raises(LbePrelaunchBindingT0Error):
        _call(scene, "pipenv")


@pytest.mark.parametrize("kind", ["go", "pipenv"])
def test_env_outside_private_root_denied(scene, kind):
    with pytest.raises(LbePrelaunchBindingT0Error):
        _call(scene, kind, home=Path("/outside/home"))


@pytest.mark.parametrize("kind", ["go", "pipenv"])
def test_colon_in_private_root_denied(scene, kind):
    root = scene[0]
    injected = root.parent / "stage:/outside"
    with pytest.raises(LbePrelaunchBindingT0Error):
        _call(scene, kind, private_root=injected)


@pytest.mark.parametrize("kind", ["go", "pipenv"])
def test_bad_root_mode_denied(scene, kind):
    root = scene[0]
    root.chmod(0o777)
    with pytest.raises(LbePrelaunchBindingT0Error):
        _call(scene, kind)


@pytest.mark.parametrize("kind", ["go", "pipenv"])
def test_source_probe_exception_fails_closed(scene, kind, monkeypatch):
    import gateway.lbe_prelaunch_binding_t0 as binding
    def broken(**_kwargs):
        raise OSError("cannot inspect source")
    target = ("inspect_go_source_t0" if kind == "go" else
              "inspect_pipenv_source_t0")
    monkeypatch.setattr(binding, target, broken)
    with pytest.raises(LbePrelaunchBindingT0Error):
        _call(scene, kind)


@pytest.mark.parametrize("kind", ["go", "pipenv"])
def test_untrusted_source_manifest_type_denied(scene, kind):
    with pytest.raises(LbePrelaunchBindingT0Error):
        _call(scene, kind, expected_members={"unexpected": "bad"})
