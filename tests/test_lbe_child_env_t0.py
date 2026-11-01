"""T0 for nonoperative effective child env; NEVER Go/Pipenv native tests."""
from dataclasses import FrozenInstanceError
from pathlib import Path
import subprocess
from types import MappingProxyType

import pytest

from gateway.lbe_child_env_t0 import (
    LbeChildEnvT0Error,
    make_go_child_env_t0,
    make_pipenv_child_env_t0,
)

BASE = Path("/test-owned/private")
GO = BASE / "go"
PROJECT = BASE / "project"
HOME = BASE / "home"
TMP = BASE / "temp"
HOST_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"


def _go(env=None, **changes):
    values = dict(
        private_root=BASE, go_root=GO, home=HOME, temp=TMP,
        go_path=BASE / "gopath", mod_cache=BASE / "gomodcache",
        build_cache=BASE / "gocache",
        parent_env={"PATH": HOST_PATH, **(env or {})},
    )
    values.update(changes)
    return make_go_child_env_t0(**values)


def _pipenv(env=None, **changes):
    values = dict(
        private_root=BASE, project_root=PROJECT,
        pipenv_bin=BASE / "pipenv-env/bin/pipenv",
        home=HOME, temp=TMP,
        parent_env={"PATH": HOST_PATH, **(env or {})},
    )
    values.update(changes)
    return make_pipenv_child_env_t0(**values)


def test_go_env_is_fresh_closed_offline_and_not_authorized():
    parent = {"PATH": HOST_PATH, "API_KEY": "must-never-leak", "SECRET_TOKEN": "not copied"}
    plan = _go(parent)
    assert plan.status == "NONOPERATIVE_ENV_CANDIDATE_ONLY"
    assert plan.kind == "go"
    assert plan.exec_authorized is False
    assert plan.original_child_native_t1 == "NOT_RUN"
    assert plan.source_loaded_identity == "NOT_ATTESTED"
    assert plan.network_precontact_isolation == "NOT_ATTESTED"
    assert plan.values["GOROOT"] == str(GO)
    assert plan.values["PATH"] == str(GO / "bin") + ":" + HOST_PATH
    assert plan.values["GOFLAGS"] == ""
    for name, value in {
        "GOTOOLCHAIN": "local", "GOPROXY": "off",
        "GOSUMDB": "off", "GOENV": "off", "GOWORK": "off",
        "GO111MODULE": "on", "CGO_ENABLED": "0",
        "GOTMPDIR": str(TMP), "GOPATH": str(BASE / "gopath"),
        "GOMODCACHE": str(BASE / "gomodcache"),
        "GOCACHE": str(BASE / "gocache"),
    }.items():
        assert plan.values[name] == value
    assert "API_KEY" not in plan.values
    assert "SECRET_TOKEN" not in plan.values
    assert "VIRTUAL_ENV" not in plan.values
    assert "CC" not in plan.values
    assert "DYLD_INSERT_LIBRARIES" not in plan.values
    assert "GOEXPERIMENT" not in plan.values
    assert set(plan.values) == {
        "HOME", "TMPDIR", "LANG", "LC_ALL", "PATH", "GOROOT",
        "GOTOOLCHAIN", "GOPROXY", "GOSUMDB", "GOENV", "GOFLAGS",
        "GOWORK", "GO111MODULE", "CGO_ENABLED",
        "GOPATH", "GOMODCACHE", "GOCACHE", "GOTMPDIR",
    }
    with pytest.raises(TypeError):
        plan.values["GOFLAGS"] = "-toolexec=/outside"
    with pytest.raises(FrozenInstanceError):
        plan.kind = "executable"


def test_go_empty_parent_GOFLAGS_is_allowed_but_never_grants_execution():
    plan = _go({"GOFLAGS": ""})
    assert plan.values["GOFLAGS"] == ""
    assert plan.exec_authorized is False


@pytest.mark.parametrize("key,value", [
    ("GOFLAGS", "-toolexec=/outside/unreviewed-helper"),
    ("GOFLAGS", "-overlay=/external/go.json"),
    ("GOEXPERIMENT", "unsafe"),
    ("GOCACHEPROG", "/outside/helper"),
    ("GOTOOLDIR", "/outside/compiler"),
    ("GOTOOLCHAIN", "auto"),
    ("GOPROXY", "https://outside.invalid"),
    ("GOENV", "/outside/goenv"),
    ("GOWORK", "/outside/go.work"),
    ("GOROOT", "/outside/go"),
    ("CGO_ENABLED", "1"),
    ("CC", "/outside/clang"),
    ("CXX", "/outside/clang++"),
    ("GCCGO", "/outside/gccgo"),
    ("DYLD_INSERT_LIBRARIES", "/outside/hook.dylib"),
    ("LD_PRELOAD", "/outside/hook.so"),
    ("PYTHONPATH", "/outside/overlay"),
    ("PIPENV_PYTHON", "/outside/python"),
    ("PIP_INDEX_URL", "https://outside.invalid"),
    ("WORKON_HOME", "/outside"),
    ("VIRTUAL_ENV", "/outside"),
    ("PATH", "/outside/bin"),
    ("BASH_ENV", "/outside/startup"),
])
def test_go_hostile_parent_selector_denied_before_any_env_candidate(key, value):
    with pytest.raises(LbeChildEnvT0Error):
        _go({key: value})


@pytest.mark.parametrize("key,value", [
    ("PIPENV_PYTHON", "/outside/bin/python"),
    ("PIPENV_VENV_IN_PROJECT", "1"),
    ("PIPENV_ACTIVE", "1"),
    ("PIPENV_PIPFILE", "/outside/Pipfile"),
    ("PIPENV_DONT_LOAD_ENV", "1"),
    ("PIPENV_VIRTUALENV", "/outside"),
    ("VIRTUAL_ENV", "/outside/venv"),
    ("WORKON_HOME", "/outside"),
    ("PIP_NO_INDEX", "1"),
    ("PIP_INDEX_URL", "https://outside.invalid"),
    ("PYTHONPATH", "/outside"),
    ("PYTHONHOME", "/outside"),
    ("PYTHONSTARTUP", "/outside/startup.py"),
    ("PIP_CONFIG_FILE", "/outside/pip.ini"),
    ("GOFLAGS", "-toolexec=/outside/helper"),
    ("GOEXPERIMENT", "unsafe"),
    ("CC", "/outside/cc"),
    ("LD_LIBRARY_PATH", "/outside"),
    ("DYLD_INSERT_LIBRARIES", "/outside"),
    ("PATH", "/outside"),
])
def test_pipenv_hostile_parent_selector_denied_before_env_candidate(key, value):
    with pytest.raises(LbeChildEnvT0Error):
        _pipenv({key: value})


def test_pipenv_frozen_env_is_private_project_only_and_no_authority():
    plan = _pipenv({"API_TOKEN": "inherited-secret-not-allowed"})
    assert plan.kind == "pipenv"
    assert plan.status == "NONOPERATIVE_ENV_CANDIDATE_ONLY"
    assert plan.exec_authorized is False
    assert plan.original_child_native_t1 == "NOT_RUN"
    assert plan.network_precontact_isolation == "NOT_ATTESTED"
    assert plan.source_loaded_identity == "NOT_ATTESTED"
    assert plan.values["PATH"] == (
        str(PROJECT / ".venv/bin") + ":" + str(BASE / "pipenv-env/bin")
        + ":" + HOST_PATH
    )
    assert plan.values["PIPENV_PIPFILE"] == str(PROJECT / "Pipfile")
    for name in ("PIPENV_VENV_IN_PROJECT", "PIPENV_DONT_LOAD_ENV",
                 "PIPENV_IGNORE_VIRTUALENVS", "PIPENV_SKIP_LOCK",
                 "PIPENV_NOSPIN", "PIP_NO_INDEX", "PYTHONUNBUFFERED",
                 "PYTHONDONTWRITEBYTECODE"):
        assert plan.values[name] == "1"
    assert "VIRTUAL_ENV" not in plan.values
    assert "WORKON_HOME" not in plan.values
    assert "API_TOKEN" not in plan.values
    assert "PYTHONPATH" not in plan.values
    assert "PIPENV_PYTHON" not in plan.values
    with pytest.raises(TypeError):
        plan.values["PIPENV_PIPFILE"] = "/outside"
    assert len(plan.values) == 14


@pytest.mark.parametrize("change", [
    {"private_root": Path("not-absolute")},
    {"private_root": Path("/")},
    {"private_root": Path("/test-owned/private/../elsewhere")},
    {"go_root": Path("/test-owned/private-outside/go")},
    {"go_root": Path("/elsewhere/go")},
    {"go_root": Path("relative/go")},
    {"home": Path("/test-owned/private2/home")},
    {"temp": Path("/outside/temp")},
    {"go_path": Path("/outside/gopath")},
    {"mod_cache": Path("/outside/modcache")},
    {"build_cache": Path("/outside/gocache")},
    {"home": TMP},
    {"go_root": BASE / "gopath"},
])
def test_go_invalid_private_path_shape_or_roots_denied(change):
    with pytest.raises(LbeChildEnvT0Error):
        _go(**change)


@pytest.mark.parametrize("change", [
    {"private_root": Path("/")},
    {"private_root": Path("relative")},
    {"project_root": Path("/outside/project")},
    {"project_root": Path("/test-owned/private-other/project")},
    {"project_root": Path("/test-owned/private/../elsewhere")},
    {"project_root": Path("project")},
    {"pipenv_bin": Path("/outside/pipenv")},
    {"pipenv_bin": BASE / "pipenv-env/bin/other"},
    {"pipenv_bin": BASE / "pipenv-env/pipenv"},
    {"home": Path("/outside/home")},
    {"temp": Path("/outside/temp")},
    {"temp": HOME},
    {"project_root": BASE / "pipenv-env"},
])
def test_pipenv_invalid_private_project_or_entrypoint_denied(change):
    with pytest.raises(LbeChildEnvT0Error):
        _pipenv(**change)


@pytest.mark.parametrize("bad", [
    {"PATH": HOST_PATH, "X": "\x00"},
    {"PATH": HOST_PATH, "X": "a" * 4097},
    {"PATH": HOST_PATH, "": "x"},
    {"PATH": HOST_PATH, "X": 12},
])
def test_bad_parent_env_value_denied(bad):
    with pytest.raises(LbeChildEnvT0Error):
        make_go_child_env_t0(
            private_root=BASE, go_root=GO, home=HOME, temp=TMP,
            go_path=BASE / "gopath", mod_cache=BASE / "gomodcache",
            build_cache=BASE / "gocache", parent_env=bad,
        )


def test_parent_env_input_is_not_mutated_and_no_subprocess_starts(monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("must never create Go/Pipenv child in T0")
    env = {"PATH": HOST_PATH, "SECRET_TOKEN": "hidden"}
    with monkeypatch.context() as patch:
        patch.setattr(subprocess.Popen, "__init__", forbidden)
        a = _go(env)
        b = _pipenv(env)
    assert env == {"PATH": HOST_PATH, "SECRET_TOKEN": "hidden"}
    assert a.exec_authorized is False and b.exec_authorized is False
    assert a.original_child_native_t1 == "NOT_RUN"
    assert b.original_child_native_t1 == "NOT_RUN"


def test_non_dict_parent_environment_is_not_accepted_as_trusted():
    with pytest.raises(LbeChildEnvT0Error):
        _go(MappingProxyType({"PATH": HOST_PATH}))
