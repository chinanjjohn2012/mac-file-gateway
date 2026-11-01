"""Nonoperative T0 effective-child-environment candidates for Go and Pipenv.

This module NEVER launches/imports third-party code, does not perform actual
filesystem source qualification or precontact network isolation, and cannot
mint WorkspaceService, Worker or Native T1 authority. Returned environments
are immutable CANDIDATES for a separately approved future test/launcher.
Parent selector auditing is mandatory even though the child env is fresh.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Mapping

from .lbe_source_preflight import (
    LbeSourcePreflightError,
    _check_parent_env,
)

_HOST_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"
_BASE_KEYS = frozenset({"HOME", "TMPDIR", "LANG", "LC_ALL", "PATH"})
_GO_KEYS = _BASE_KEYS | frozenset({
    "GOROOT", "GOTOOLCHAIN", "GOPROXY", "GOSUMDB", "GOENV",
    "GOFLAGS", "GOWORK", "GO111MODULE", "CGO_ENABLED",
    "GOPATH", "GOMODCACHE", "GOCACHE", "GOTMPDIR",
})
_PIPENV_KEYS = _BASE_KEYS | frozenset({
    "PIPENV_PIPFILE", "PIPENV_VENV_IN_PROJECT",
    "PIPENV_DONT_LOAD_ENV", "PIPENV_IGNORE_VIRTUALENVS",
    "PIPENV_SKIP_LOCK", "PIPENV_NOSPIN", "PIP_NO_INDEX",
    "PYTHONUNBUFFERED", "PYTHONDONTWRITEBYTECODE",
})
_EXTRA_PARENT_SELECTORS = frozenset({
    "WORKON_HOME", "VIRTUAL_ENV", "PIPENV_ACTIVE", "PYTHONSTARTUP",
    "PYTHONINSPECT", "PYTHONUSERBASE", "PIP_CONFIG_FILE", "CC", "CXX",
    "GCCGO", "PKG_CONFIG", "BASH_ENV", "ENV",
})


class LbeChildEnvT0Error(ValueError):
    """An environment candidate cannot be used for the proposed native T1."""


@dataclass(frozen=True)
class ChildEnvCandidate:
    kind: str
    values: Mapping[str, str]
    status: str = "NONOPERATIVE_ENV_CANDIDATE_ONLY"
    source_loaded_identity: str = "NOT_ATTESTED"
    network_precontact_isolation: str = "NOT_ATTESTED"
    original_child_native_t1: str = "NOT_RUN"
    exec_authorized: bool = False


def _absolute_private(path: Path, *, parent: Path | None = None) -> str:
    """Lexical bounds ONLY; same-UID symlink and runtime proof NOT supplied."""
    if not isinstance(path, Path) or not path.is_absolute():
        raise LbeChildEnvT0Error("expected absolute private Path")
    parts = path.parts
    if (len(parts) < 3 or ".." in parts or
            any("\x00" in part for part in parts) or len(str(path)) > 2048):
        raise LbeChildEnvT0Error("unbounded or unsafe private path")
    if parent is not None:
        if (not isinstance(parent, Path) or not parent.is_absolute()
                or ".." in parent.parts
                or len(parts) <= len(parent.parts)
                or parts[:len(parent.parts)] != parent.parts):
            raise LbeChildEnvT0Error("path outside approved private root")
    return str(path)


def _check_parent(parent_env: Mapping[str, str], *, kind: str) -> None:
    """Check hostile selectors BEFORE calculating any candidate env."""
    if type(parent_env) is not dict or len(parent_env) > 256:
        raise LbeChildEnvT0Error("untrusted parent environment map")
    for name, value in parent_env.items():
        if (type(name) is not str or type(value) is not str
                or not name or len(name) > 128 or len(value) > 4096
                or "\x00" in name or "\x00" in value):
            raise LbeChildEnvT0Error("unbounded parent environment value")
        if (name in _EXTRA_PARENT_SELECTORS
                or name.startswith(("LD_", "DYLD_", "CGO_"))
                or (kind == "go" and name.startswith(("PIPENV_", "PIP_")))
                or (kind == "pipenv" and name.startswith("GO"))):
            raise LbeChildEnvT0Error("unreviewed inherited runtime selector")
    try:
        _check_parent_env(parent_env, kind=kind,
                          expected_parent_path=_HOST_PATH)
    except LbeSourcePreflightError:
        raise LbeChildEnvT0Error("unreviewed inherited runtime selector") from None


def _common(*, private_root: Path, home: Path,
            temp: Path) -> dict[str, str]:
    _absolute_private(private_root)
    home_text = _absolute_private(home, parent=private_root)
    temp_text = _absolute_private(temp, parent=private_root)
    if temp == home:
        raise LbeChildEnvT0Error("HOME and TMPDIR must be separate")
    return {
        "HOME": home_text,
        "TMPDIR": temp_text,
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": _HOST_PATH,
    }


def _freeze(kind: str, mapping: dict[str, str],
            expected_keys: frozenset[str]) -> ChildEnvCandidate:
    if set(mapping) != expected_keys:
        raise LbeChildEnvT0Error("unexpected or missing effective env key")
    for key, value in mapping.items():
        if (type(value) is not str or "\x00" in value
                or (not value and key != "GOFLAGS")
                or (key == "GOFLAGS" and value != "")):
            raise LbeChildEnvT0Error("invalid effective environment value")
    return ChildEnvCandidate(kind=kind, values=MappingProxyType(dict(mapping)))


def make_go_child_env_t0(*, private_root: Path, go_root: Path,
                         home: Path, temp: Path, go_path: Path,
                         mod_cache: Path, build_cache: Path,
                         parent_env: Mapping[str, str]) -> ChildEnvCandidate:
    """Build a CLOSED Go env from fixed keys; NO binary/Go source is run."""
    _check_parent(parent_env, kind="go")
    values = _common(private_root=private_root, home=home, temp=temp)
    go = _absolute_private(go_root, parent=private_root)
    gp = _absolute_private(go_path, parent=private_root)
    mc = _absolute_private(mod_cache, parent=private_root)
    gc = _absolute_private(build_cache, parent=private_root)
    if len({go, gp, mc, gc, str(temp), str(home)}) != 6:
        raise LbeChildEnvT0Error("Go private roots must be distinct")
    values.update({
        "PATH": str(go_root / "bin") + ":" + _HOST_PATH,
        "GOROOT": go,
        "GOTOOLCHAIN": "local",
        "GOPROXY": "off",
        "GOSUMDB": "off",
        "GOENV": "off",
        "GOFLAGS": "",
        "GOWORK": "off",
        "GO111MODULE": "on",
        "CGO_ENABLED": "0",
        "GOPATH": gp,
        "GOMODCACHE": mc,
        "GOCACHE": gc,
        "GOTMPDIR": str(temp),
    })
    return _freeze("go", values, _GO_KEYS)


def make_pipenv_child_env_t0(*, private_root: Path,
                             project_root: Path, pipenv_bin: Path,
                             home: Path, temp: Path,
                             parent_env: Mapping[str, str]) -> ChildEnvCandidate:
    """Compute proposed locked project/.venv environment, no Pipenv call.

    It DOES NOT check whether the venv actually exists, .pth hooks or selected
    interpreter bytes. The separately reviewed source-only FD preflight and
    future approved native loaded-identity proof are still REQUIRED.
    """
    _check_parent(parent_env, kind="pipenv")
    values = _common(private_root=private_root, home=home, temp=temp)
    project = _absolute_private(project_root, parent=private_root)
    runner = _absolute_private(pipenv_bin, parent=private_root)
    if pipenv_bin.name != "pipenv" or pipenv_bin.parent.name != "bin":
        raise LbeChildEnvT0Error("unqualified Pipenv entrypoint shape")
    if project_root == pipenv_bin.parent.parent:
        raise LbeChildEnvT0Error("project and Pipenv installation overlap")
    values.update({
        "PATH": str(project_root / ".venv/bin") + ":"
                + str(pipenv_bin.parent) + ":" + _HOST_PATH,
        "PIPENV_PIPFILE": str(project_root / "Pipfile"),
        "PIPENV_VENV_IN_PROJECT": "1",
        "PIPENV_DONT_LOAD_ENV": "1",
        "PIPENV_IGNORE_VIRTUALENVS": "1",
        "PIPENV_SKIP_LOCK": "1",
        "PIPENV_NOSPIN": "1",
        "PIP_NO_INDEX": "1",
        "PYTHONUNBUFFERED": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
    })
    return _freeze("pipenv", values, _PIPENV_KEYS)
