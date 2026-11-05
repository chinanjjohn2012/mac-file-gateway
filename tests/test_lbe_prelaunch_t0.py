"""D2 first-party nonoperative Go/Pipenv effective environment negatives."""
from dataclasses import replace
import subprocess
import socket

import pytest

from gateway.lbe_prelaunch_t0 import (
    LbePrelaunchT0Denied, check_go_environment_t0,
    check_pipenv_environment_t0, launch_go_or_pipenv_t0,
)


_GO = {
    "LANG": "C", "LC_ALL": "C", "GOTOOLCHAIN": "local",
    "GOENV": "off", "GOFLAGS": "", "GOPROXY": "off",
    "GOSUMDB": "off", "GOWORK": "off", "GO111MODULE": "on",
    "CGO_ENABLED": "0",
    "GOROOT": "/locked/go",
    "PATH": "/locked/go/bin:/usr/bin:/bin",
    "HOME": "/private/job/home", "TMPDIR": "/private/job/tmp",
    "GOPATH": "/private/job/gopath",
    "GOMODCACHE": "/private/job/modcache",
    "GOCACHE": "/private/job/gocache",
    "GOTMPDIR": "/private/job/gotmp",
}
_PIPENV = {
    "LANG": "C", "LC_ALL": "C",
    "PIPENV_VENV_IN_PROJECT": "1", "PIPENV_DONT_LOAD_ENV": "1",
    "PIPENV_IGNORE_VIRTUALENVS": "1", "PIP_NO_INDEX": "1",
    "PIPENV_SKIP_LOCK": "1", "PYTHONNOUSERSITE": "1",
    "PYTHONDONTWRITEBYTECODE": "1",
    "PATH": "/private/job/bin:/private/job/project/.venv/bin:/usr/bin:/bin",
    "PIPENV_PIPFILE": "/private/job/project/Pipfile",
    "HOME": "/private/job/home", "TMPDIR": "/private/job/tmp",
}


def _go(**kw):
    data = {
        "goroot": "/locked/go",
        "go_entrypoint": "/locked/go/bin/go",
        "private_root": "/private/job",
        "home": "/private/job/home",
        "temporary": "/private/job/tmp",
        "gopath": "/private/job/gopath",
        "gomodcache": "/private/job/modcache",
        "gocache": "/private/job/gocache",
        "gotmpdir": "/private/job/gotmp",
        "staged_go_sha256": "a" * 64,
        "staged_compiler_sha256": "b" * 64,
        "parent_environment": {},
        "effective_environment": dict(_GO),
    }
    data.update(kw)
    return check_go_environment_t0(**data)


def _pipenv(**kw):
    data = {
        "project_root": "/private/job/project",
        "private_root": "/private/job",
        "pipenv_bin": "/private/job/bin",
        "pipenv_entrypoint": "/private/job/bin/pipenv",
        "pipfile": "/private/job/project/Pipfile",
        "venv_root": "/private/job/project/.venv",
        "selected_python": "/private/job/project/.venv/bin/python",
        "home": "/private/job/home",
        "temporary": "/private/job/tmp",
        "pipfile_lock_sha256": "1" * 64,
        "pipenv_sha256": "2" * 64,
        "python_sha256": "3" * 64,
        "parent_environment": {},
        "effective_environment": dict(_PIPENV),
    }
    data.update(kw)
    return check_pipenv_environment_t0(**data)


@pytest.mark.parametrize("mode", ["go", "pipenv"])
def test_structural_positive_never_grants_exec_and_never_spawns(mode, monkeypatch):
    def forbidden(*_a, **_k):
        raise AssertionError("T0 must never launch or open network")
    with monkeypatch.context() as m:
        m.setattr(subprocess, "Popen", forbidden)
        m.setattr(subprocess, "run", forbidden)
        m.setattr(socket, "socket", forbidden)
        p = _go() if mode == "go" else _pipenv()
    assert p.kind == mode
    assert p.status == "NONOPERATIVE_ENVIRONMENT_PROPOSAL_T0"
    assert p.actual_loader_qualified is False
    assert p.actual_venv_qualified is False
    assert p.actual_os_limits_enforced is False
    assert p.native_launch_allowed is False
    assert p.product_apply_allowed is False
    assert len(p.blockers) >= 4
    assert p.effective_environment == tuple(sorted((_GO if mode == "go" else _PIPENV).items()))
    with pytest.raises(LbePrelaunchT0Denied, match="NATIVE_GO_PIPENV=NOT_RUN"):
        launch_go_or_pipenv_t0(p, {"approved": True})


@pytest.mark.parametrize("name,value", [
    ("GOFLAGS", "-toolexec=/outside/shell"),
    ("GOFLAGS", "-overlay=/outside.json"),
    ("GOEXPERIMENT", "rangefunc"),
    ("GOCACHEPROG", "/outside/helper"),
    ("GOAUTH", "netrc"),
    ("GODEBUG", "execerrdot=0"),
    ("GOROOT", "/outside/go"),
    ("GOTOOLCHAIN", "auto"),
    ("GOPROXY", "https://example.invalid"),
    ("CC", "/bin/sh"),
    ("CXX", "/bin/sh"),
    ("PKG_CONFIG_PATH", "/outside"),
    ("DYLD_INSERT_LIBRARIES", "/outside/lib.dylib"),
    ("LD_PRELOAD", "/outside/lib.so"),
    ("PYTHONPATH", "/outside"),
    ("PIPENV_PYTHON", "/outside/python"),
    ("WORKON_HOME", "/outside"),
    ("VIRTUAL_ENV", "/outside"),
    ("PATH", "/outside/bin:/usr/bin:/bin"),
])
def test_unreviewed_parent_selector_denied_before_go_or_pipenv(name, value):
    for mode in (_go, _pipenv):
        with pytest.raises(LbePrelaunchT0Denied):
            mode(parent_environment={name: value})


@pytest.mark.parametrize("name,value", [
    ("GOFLAGS", "-toolexec=/outside"),
    ("GOTOOLCHAIN", "auto"),
    ("GOENV", "/outside/go.env"),
    ("GOPROXY", "https://example.invalid"),
    ("GOSUMDB", "sum.golang.org"),
    ("CGO_ENABLED", "1"),
    ("PATH", "/outside/go/bin:/usr/bin:/bin"),
    ("GOROOT", "/outside"),
    ("GOMODCACHE", "/outside"),
    ("GOEXPERIMENT", "asyncpreemptoff"),
    ("CC", "/bin/sh"),
])
def test_changed_or_unlisted_final_go_environment_denied(name, value):
    env = dict(_GO)
    env[name] = value
    with pytest.raises(LbePrelaunchT0Denied):
        _go(effective_environment=env)


@pytest.mark.parametrize("name,value", [
    ("PIPENV_PIPFILE", "/outside/Pipfile"),
    ("PIPENV_VENV_IN_PROJECT", "0"),
    ("PIPENV_IGNORE_VIRTUALENVS", "0"),
    ("PIPENV_DONT_LOAD_ENV", "0"),
    ("PIP_NO_INDEX", "0"),
    ("PATH", "/outside/pipenv:/usr/bin:/bin"),
    ("WORKON_HOME", "/outside"),
    ("VIRTUAL_ENV", "/outside"),
    ("PIPENV_PYTHON", "/outside/python"),
    ("PYTHONPATH", "/outside"),
    ("PYTHONHOME", "/outside"),
    ("PIP_CONFIG_FILE", "/outside/pip.conf"),
])
def test_changed_or_unlisted_final_pipenv_environment_denied(name, value):
    env = dict(_PIPENV)
    env[name] = value
    with pytest.raises(LbePrelaunchT0Denied):
        _pipenv(effective_environment=env)


@pytest.mark.parametrize("field,value", [
    ("go_entrypoint", "/outside/go"),
    ("goroot", "/locked/go/../hijack"),
    ("private_root", "/private/job/"),
    ("gomodcache", "/outside/cache"),
    ("gopath", "/private/job/gopath/../out"),
    ("gocache", "/private/job/link//cache"),
    ("temporary", "/private/job/tmp:other"),
    ("staged_compiler_sha256", "G" * 64),
    ("staged_go_sha256", "0" * 64),
    ("staged_go_sha256", 7),
    ("staged_compiler_sha256", "a" * 64),
])
def test_go_candidate_bad_paths_or_digest_denied(field, value):
    with pytest.raises(LbePrelaunchT0Denied):
        _go(**{field: value})


@pytest.mark.parametrize("field,value", [
    ("project_root", "/outside"),
    ("venv_root", "/private/job/other/.venv"),
    ("venv_root", "/private/job/project/other/.venv"),
    ("pipfile", "/outside/Pipfile"),
    ("selected_python", "/outside/python"),
    ("selected_python", "/private/job/project/.venv/bin/python3"),
    ("pipenv_entrypoint", "/private/job/bin/other"),
    ("pipfile_lock_sha256", ""),
    ("python_sha256", "0" * 64),
    ("python_sha256", "1" * 64),
])
def test_pipenv_candidate_redirected_paths_or_digest_denied(field, value):
    with pytest.raises(LbePrelaunchT0Denied):
        _pipenv(**{field: value})


@pytest.mark.parametrize("mode", ["go", "pipenv"])
def test_missing_unexpected_and_hostile_effective_environment_denied(mode):
    expected = _GO if mode == "go" else _PIPENV
    inspect = _go if mode == "go" else _pipenv
    for mutation in (
        {k: v for k, v in expected.items() if k != "PATH"},
        {**expected, "UNREVIEWED": "1"},
        {**expected, "PATH": True},
        {**expected, "PATH": 5},
        {**expected, 123: "evil"},
        {**expected, "HOME": "../private"},
        {"PATH": "unsafe"},
    ):
        with pytest.raises(LbePrelaunchT0Denied):
            inspect(effective_environment=mutation)


def test_custom_environment_mapping_and_value_hooks_rejected_without_call():
    observed = []

    class Impostor(dict):
        def __eq__(self, other):
            observed.append("eq")
            return True

    class StrImpostor(str):
        def __new__(cls):
            return super().__new__(cls, "/locked/go/bin:/usr/bin:/bin")

        def __eq__(self, other):
            observed.append("str_eq")
            return True

    with pytest.raises(LbePrelaunchT0Denied):
        _go(effective_environment=Impostor(_GO))
    with pytest.raises(LbePrelaunchT0Denied):
        _go(effective_environment={**_GO, "PATH": StrImpostor()})
    assert observed == []


def test_good_candidate_record_cannot_be_upgraded_to_native_authority():
    receipt = replace(
        _go(), native_launch_allowed=True, product_apply_allowed=True,
        actual_loader_qualified=True, actual_os_limits_enforced=True,
        blockers=(),
    )
    with pytest.raises(LbePrelaunchT0Denied):
        launch_go_or_pipenv_t0(receipt)


def test_only_plain_clean_parent_hint_can_be_used_for_nonoperative_proposal():
    assert _go(parent_environment={"GOFLAGS": "", "PATH": _GO["PATH"]}).kind == "go"
    assert _pipenv(parent_environment={"WORKON_HOME": ""}).kind == "pipenv"



# D4 test-first RED: a proposed Go binary/toolchain cannot sit OUTSIDE the
# explicit private staging root even when caller matches every SHA-shaped
# string and the final effective environment is internally consistent.
@pytest.mark.parametrize("goroot", [
    "/outside/go",
    "/private/job2/go",
    "/locked/go",
])
def test_go_consistent_external_toolchain_root_denied_before_any_authority(goroot):
    env = dict(_GO)
    env["GOROOT"] = goroot
    env["PATH"] = goroot + "/bin:/usr/bin:/bin"
    with pytest.raises(LbePrelaunchT0Denied):
        _go(
            goroot=goroot,
            go_entrypoint=goroot + "/bin/go",
            effective_environment=env,
            parent_environment={"PATH": env["PATH"]},
        )
