"""Closed effective-environment *candidate* for a future trusted LBE runner.

D2 is PURE, NONOPERATIVE T0: zero process, filesystem, network, OS-sandbox
or source-loader inspection. The returned frozen record cannot authorize
Popen, Go/Pipenv imports or WorkspaceService positive apply. A future
separately reviewed real launcher must repeat every check with observed
runner, file, loaded source, owner, OS environment and exact permissions.
"""
from __future__ import annotations

from dataclasses import dataclass
import re


class LbePrelaunchT0Denied(ValueError):
    """Unqualified input for a nonoperative execution-environment proposal."""


_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_BAD_PARENT_PREFIX = (
    "GO", "CGO_", "PIPENV_", "PIP_", "PYTHON", "LD_", "DYLD_",
    "PKG_CONFIG", "BASH_ENV", "SHELLOPTS",
)
_BAD_PARENT_EXACT = frozenset((
    "CC", "CXX", "GCCGO", "VIRTUAL_ENV", "WORKON_HOME",
    "ENV", "CDPATH", "IFS",
))
_GO_CONSTANTS = {
    "LANG": "C", "LC_ALL": "C",
    "GOTOOLCHAIN": "local", "GOENV": "off", "GOFLAGS": "",
    "GOPROXY": "off", "GOSUMDB": "off", "GOWORK": "off",
    "GO111MODULE": "on", "CGO_ENABLED": "0",
}
_PIPENV_CONSTANTS = {
    "LANG": "C", "LC_ALL": "C", "PIPENV_VENV_IN_PROJECT": "1",
    "PIPENV_DONT_LOAD_ENV": "1", "PIPENV_IGNORE_VIRTUALENVS": "1",
    "PIP_NO_INDEX": "1", "PIPENV_SKIP_LOCK": "1",
    "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1",
}
_BLOCKERS = (
    "NATIVE_SOURCE_AND_LOADED_INTERPRETER_NOT_OBSERVED",
    "ACTUAL_VENV_FILE_TYPES_OWNER_AND_SEED_NOT_INSPECTED",
    "RUNNER_OS_RESOURCE_AND_NETWORK_BOUNDARY_NOT_PROVEN",
    "CURRENT_GATE_B_AND_PRODUCT_F1_AUTHORIZATION_NOT_MET",
    "NATIVE_GO_PIPENV_AND_PRODUCT_INTEGRATION_NOT_RUN",
)


@dataclass(frozen=True)
class ClosedLbeEnvironmentT0:
    kind: str
    selected_entrypoint: str
    effective_environment: tuple[tuple[str, str], ...]
    status: str = "NONOPERATIVE_ENVIRONMENT_PROPOSAL_T0"
    actual_loader_qualified: bool = False
    actual_venv_qualified: bool = False
    actual_os_limits_enforced: bool = False
    native_launch_allowed: bool = False
    product_apply_allowed: bool = False
    blockers: tuple[str, ...] = _BLOCKERS


def _path(value: object, *, label: str) -> str:
    if type(value) is not str or not 2 <= len(value) <= 2048:
        raise LbePrelaunchT0Denied("invalid proposed path: " + label)
    if (not value.startswith("/") or "\\" in value or ":" in value
            or any(ord(ch) < 33 or ord(ch) == 127 for ch in value)):
        raise LbePrelaunchT0Denied("invalid proposed path: " + label)
    if any(p in {"", ".", ".."} for p in value[1:].split("/")):
        raise LbePrelaunchT0Denied("invalid proposed path: " + label)
    return value


def _within(value: str, root: str) -> bool:
    return value.startswith(root + "/")


def _sha(value: object, label: str) -> None:
    if (type(value) is not str or _SHA256.fullmatch(value) is None
            or value == "0" * 64):
        raise LbePrelaunchT0Denied("unqualified proposed source hash: " + label)


def _env(value: object, label: str) -> dict[str, str]:
    # Reject custom dict, keys and values before hashing/comparing attacker
    # objects. This is a copy of primitive data, not a live os.environ sample.
    if type(value) is not dict or len(value) > 40:
        raise LbePrelaunchT0Denied("unqualified " + label)
    for key, item in value.items():
        if (type(key) is not str or not 1 <= len(key) <= 80
                or not key.isascii() or
                any(not (ch.isupper() or ch.isdigit() or ch == "_")
                    for ch in key)
                or type(item) is not str or len(item) > 4096
                or any(ord(ch) < 32 or ord(ch) == 127 for ch in item)):
            raise LbePrelaunchT0Denied("unqualified " + label)
    return dict(value)


def _parent(source: dict[str, str], expected_path: str) -> None:
    for key, value in source.items():
        if value and (key in _BAD_PARENT_EXACT or
                      key.startswith(_BAD_PARENT_PREFIX)):
            raise LbePrelaunchT0Denied(
                "inherited execution-selector environment is not approved")
    if "PATH" in source and source["PATH"] != expected_path:
        raise LbePrelaunchT0Denied(
            "inherited PATH disagrees with fixed expected child PATH")


def _validate(*, kind: str, selected_entrypoint: str,
              expected: dict[str, str], parent_environment: object,
              effective_environment: object) -> ClosedLbeEnvironmentT0:
    parent = _env(parent_environment, "parent environment")
    effective = _env(effective_environment, "effective child environment")
    _parent(parent, expected["PATH"])
    # An exact-map comparison is safe only after each key/value has passed
    # primitive checks. A clean environment proposal is not an actual OS env.
    if effective != expected:
        raise LbePrelaunchT0Denied("child environment is not the closed profile")
    return ClosedLbeEnvironmentT0(
        kind=kind, selected_entrypoint=selected_entrypoint,
        effective_environment=tuple(sorted(effective.items())),
    )


def check_go_environment_t0(
    *, goroot: str, go_entrypoint: str, private_root: str,
    home: str, temporary: str, gopath: str, gomodcache: str,
    gocache: str, gotmpdir: str, staged_go_sha256: str,
    staged_compiler_sha256: str, parent_environment: dict[str, str],
    effective_environment: dict[str, str],
) -> ClosedLbeEnvironmentT0:
    """Validate proposal only. No Go process, compilation or module lookup."""
    root = _path(goroot, label="goroot")
    private = _path(private_root, label="private_root")
    entry = _path(go_entrypoint, label="go_entrypoint")
    # Prevent a self-consistent but outside-private GOROOT, Go binary and
    # final PATH from becoming a structurally qualified runner proposal.
    # Still not a real no-follow/loaded-source/OS execution attestation.
    if entry != root + "/bin/go" or not _within(root, private):
        raise LbePrelaunchT0Denied(
            "Go entrypoint must reside below the proposed private root")
    _sha(staged_go_sha256, "go")
    _sha(staged_compiler_sha256, "compiler")
    if staged_go_sha256 == staged_compiler_sha256:
        raise LbePrelaunchT0Denied("Go and compiler sources cannot share a digest")
    paths = {
        "HOME": home, "TMPDIR": temporary, "GOPATH": gopath,
        "GOMODCACHE": gomodcache, "GOCACHE": gocache, "GOTMPDIR": gotmpdir,
    }
    for key, value in paths.items():
        _path(value, label=key)
        if not _within(value, private):
            raise LbePrelaunchT0Denied("Go path outside proposed private root")
    expected = dict(_GO_CONSTANTS)
    expected.update(paths)
    expected.update({"PATH": root + "/bin:/usr/bin:/bin", "GOROOT": root})
    return _validate(
        kind="go", selected_entrypoint=entry, expected=expected,
        parent_environment=parent_environment,
        effective_environment=effective_environment,
    )


def check_pipenv_environment_t0(
    *, project_root: str, private_root: str, pipenv_bin: str,
    pipenv_entrypoint: str, pipfile: str, venv_root: str,
    selected_python: str, home: str, temporary: str,
    pipfile_lock_sha256: str, pipenv_sha256: str,
    python_sha256: str, parent_environment: dict[str, str],
    effective_environment: dict[str, str],
) -> ClosedLbeEnvironmentT0:
    """Validate a closed Pipenv proposal, NOT real .venv inode or loader."""
    project = _path(project_root, label="project")
    private = _path(private_root, label="private_root")
    binary = _path(pipenv_bin, label="pipenv_bin")
    entry = _path(pipenv_entrypoint, label="pipenv_entrypoint")
    pipfile_path = _path(pipfile, label="pipfile")
    venv = _path(venv_root, label="venv_root")
    python = _path(selected_python, label="selected_python")
    if (pipfile_path != project + "/Pipfile"
            or venv != project + "/.venv"
            or python != venv + "/bin/python"
            or entry != binary + "/pipenv"
            or not _within(project, private)
            or not _within(binary, private)):
        raise LbePrelaunchT0Denied("Pipenv selection is not a fixed private path")
    for label, digest in (
        ("Pipfile.lock", pipfile_lock_sha256),
        ("Pipenv", pipenv_sha256),
        ("Python", python_sha256),
    ):
        _sha(digest, label)
    if len({pipfile_lock_sha256, pipenv_sha256, python_sha256}) != 3:
        raise LbePrelaunchT0Denied("Pipenv proposed source digests collide")
    for key, value in (("HOME", home), ("TMPDIR", temporary)):
        _path(value, label=key)
        if not _within(value, private):
            raise LbePrelaunchT0Denied("Pipenv env path outside private root")
    expected = dict(_PIPENV_CONSTANTS)
    expected.update({
        "HOME": home, "TMPDIR": temporary,
        "PATH": binary + ":" + venv + "/bin:/usr/bin:/bin",
        "PIPENV_PIPFILE": pipfile_path,
    })
    return _validate(
        kind="pipenv", selected_entrypoint=entry, expected=expected,
        parent_environment=parent_environment,
        effective_environment=effective_environment,
    )


def launch_go_or_pipenv_t0(*_args: object, **_kwargs: object) -> None:
    """Always DENY. Candidate records and caller receipts confer no rights."""
    raise LbePrelaunchT0Denied(
        "NATIVE_GO_PIPENV=NOT_RUN; PRODUCT_EXEC=DENIED; "
        "external source, Gate B, owner and native test evidence missing")
