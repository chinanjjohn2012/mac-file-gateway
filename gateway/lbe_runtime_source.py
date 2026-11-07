"""D4 R003 actual staged-source and closed-environment prelaunch observation.

This is service-owned PRODUCT source, not the declaration-only D2 packet.
It re-inspects real staged Go/Pipenv executable bytes and project fixtures
using private nofollow FDs, derives a NEW exact child environment and records
the real local kernel name/architecture. It never imports, spawns or signals
foreign code. Selected hashes and clean env do NOT prove the full loaded
source closure, GitHub runner image, mount/credential absence, OS resource
domain or owner T1 execution authorization. No output from this module grants
permission to Popen or to turn off F1/NativeLauncher refusal.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
import re
import stat
from typing import TYPE_CHECKING

from .lbe_product_fixture import (
    D4FixtureCandidate, D4FixtureDenied, check_d4_r003_fixture,
)
from .lbe_go_fixture_t0 import (
    inspect_staged_go_files_t0, LbeGoFixtureT0Denied,
)
from .lbe_pipenv_fixture_t0 import (
    inspect_private_pipenv_fixture_t0, LbePipenvFixtureT0Denied,
)
from .lbe_prelaunch_t0 import (
    check_go_environment_t0, check_pipenv_environment_t0,
    LbePrelaunchT0Denied,
)

if TYPE_CHECKING:
    from .workspaces import WorkspaceContext


class D4RuntimeSourceDenied(ValueError):
    """Actual selected staged-source or environment evidence is incomplete."""


_SHA = re.compile(r"[0-9a-f]{64}\Z")
_BAD_PARENT_PREFIXES = (
    "GO", "CGO_", "PIPENV_", "PIP_", "PYTHON", "DYLD_", "LD_",
    "PKG_CONFIG", "BASH_ENV", "SHELLOPTS", "SSH_", "GIT_",
)
_BAD_PARENT_EXACT = frozenset((
    "CC", "CXX", "GCCGO", "VIRTUAL_ENV", "WORKON_HOME",
    "ENV", "CDPATH", "IFS", "GITHUB_TOKEN", "GH_TOKEN",
    "ACTIONS_RUNTIME_TOKEN", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
))
_ENV_CONSTANT_GO = {
    "LANG": "C", "LC_ALL": "C", "GOTOOLCHAIN": "local",
    "GOENV": "off", "GOFLAGS": "", "GOPROXY": "off",
    "GOSUMDB": "off", "GOWORK": "off", "GO111MODULE": "on",
    "CGO_ENABLED": "0",
}
_ENV_CONSTANT_PIPENV = {
    "LANG": "C", "LC_ALL": "C", "PIPENV_VENV_IN_PROJECT": "1",
    "PIPENV_DONT_LOAD_ENV": "1", "PIPENV_IGNORE_VIRTUALENVS": "1",
    "PIP_NO_INDEX": "1", "PIPENV_SKIP_LOCK": "1",
    "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1",
}
_BLOCKERS = (
    "RUNNER_IMAGE_DIGEST_AND_PROVIDER_NOT_ATTESTED",
    "TOKEN_MOUNT_PROXY_AND_G05_EXECUTION_IDENTITY_NOT_ATTESTED",
    "FULL_GO_OR_PIPENV_LOADED_SOURCE_GRAPH_NOT_ATTESTED",
    "PHYSICALLY_ATTACHED_WHOLE_CHILD_DOMAIN_CPU_RAM_NOT_PROVEN",
    "EXACT_OWNER_NATIVE_T1_AND_REVIEWED_EXECUTION_GRANT_NOT_PRESENT",
    "R003_NOT_AN_OPERATIVE_F1_GO_PIPENV_EXCEPTION",
)


@dataclass(frozen=True, slots=True)
class D4RuntimeSourceObservation:
    workspace: str
    kind: str
    requested_argv: tuple[str, ...]
    effective_argv: tuple[str, ...]
    staged_executables: tuple[tuple[str, str], ...]
    private_first_party_sources: tuple[tuple[str, str], ...]
    closed_child_environment: tuple[tuple[str, str], ...]
    observed_kernel: str
    observed_machine: str
    status: str = "ACTUAL_STAGED_SOURCE_ONLY_NO_EXECUTION_AUTHORITY"
    staged_file_bytes_checked: bool = True
    child_environment_constructed: bool = True
    actual_import_graph_attested: bool = False
    runner_image_attested: bool = False
    credentials_and_mounts_attested: bool = False
    physical_resource_domain_attached: bool = False
    owner_native_t1_grant: bool = False
    native_launch_allowed: bool = False
    blockers: tuple[str, ...] = _BLOCKERS


def _canonical(value: object, label: str) -> str:
    if (type(value) is not str or not 2 <= len(value) <= 2048
            or not value.startswith("/") or "\\" in value or ":" in value
            or any(ord(ch) < 33 or ord(ch) >= 127 for ch in value)
            or any(p in ("", ".", "..") for p in value[1:].split("/"))):
        raise D4RuntimeSourceDenied("invalid private runtime path: " + label)
    return value


def _child(root: str, name: str) -> str:
    if (type(name) is not str or not name
            or any(x in ("", ".", "..") for x in name.split("/"))
            or any(not re.fullmatch(r"[A-Za-z0-9_.-]+", part)
                   for part in name.split("/"))):
        raise D4RuntimeSourceDenied("invalid private runtime subpath")
    return root + "/" + name


def _below(root: str, path: str) -> None:
    if path == root or not path.startswith(root + "/"):
        raise D4RuntimeSourceDenied("selected source is outside private runner")


def _open_private_directory(path: str, root: str) -> int:
    """Walk each component by nofollow FD; caller owns the returned FD."""
    path = _canonical(path, "directory")
    _below(root, path)
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                 | os.O_CLOEXEC)
    try:
        components = path[1:].split("/")
        root_components = root[1:].split("/")
        for i, part in enumerate(components):
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY
                            | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = child
            if i + 1 >= len(root_components):
                meta = os.fstat(fd)
                if (not stat.S_ISDIR(meta.st_mode)
                        or meta.st_uid != os.getuid()
                        or meta.st_mode & 0o022):
                    raise D4RuntimeSourceDenied(
                        "private runtime directory not owner controlled")
        return fd
    except OSError:
        os.close(fd)
        raise D4RuntimeSourceDenied(
            "private runtime directory cannot be inspected") from None
    except BaseException:
        os.close(fd)
        raise


def _stat_private_directory(path: str, root: str) -> None:
    fd = _open_private_directory(path, root)
    os.close(fd)


def _hash_expected(value: object, label: str) -> str:
    if (type(value) is not str or _SHA.fullmatch(value) is None
            or value == "0" * 64):
        raise D4RuntimeSourceDenied("missing fixed staged SHA: " + label)
    return value


def _parent_selector_guard() -> None:
    """Read ACTUAL parent env names without copying any value to child."""
    for key, value in os.environ.items():
        if not value:
            continue
        # Parent secret variables would still be in the same-UID host's
        # memory even if not forwarded. Never log their values.
        if (key in _BAD_PARENT_EXACT
                or key.startswith(_BAD_PARENT_PREFIXES)
                or key.endswith(("_TOKEN", "_SECRET", "_PRIVATE_KEY",
                                 "_ACCESS_KEY"))):
            raise D4RuntimeSourceDenied(
                "unqualified inherited selector or secret-bearing environment")


def _private_file_hash(path: str, root: str) -> str:
    """Read private staged Pipenv entrypoint by nofollow FDs, bounded bytes."""
    directory, basename = path.rsplit("/", 1)
    # Use the SAME pinned nofollow descriptor to open the leaf. Reopening
    # an absolute path after validation would reintroduce a prefix race.
    dir_fd = _open_private_directory(directory, root)
    try:
        fd = os.open(basename, os.O_RDONLY | os.O_NOFOLLOW
                     | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=dir_fd)
        try:
            before = os.fstat(fd)
            if (not stat.S_ISREG(before.st_mode)
                    or before.st_uid != os.getuid()
                    or before.st_mode & 0o022 or before.st_nlink != 1
                    or not before.st_mode & stat.S_IXUSR
                    or not 0 < before.st_size <= 128 * 1024 * 1024):
                raise D4RuntimeSourceDenied("staged native entrypoint unsafe")
            digest = hashlib.sha256()
            remaining = before.st_size
            while remaining:
                data = os.read(fd, min(65536, remaining))
                if not data:
                    raise D4RuntimeSourceDenied("staged native entrypoint truncated")
                remaining -= len(data)
                digest.update(data)
            after = os.fstat(fd)
            fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns",
                      "st_ctime_ns", "st_mode", "st_uid", "st_nlink")
            if any(getattr(before, x) != getattr(after, x) for x in fields):
                raise D4RuntimeSourceDenied("staged entrypoint changed during read")
            return digest.hexdigest()
        finally:
            os.close(fd)
    except OSError:
        raise D4RuntimeSourceDenied("staged entrypoint not safely readable") from None
    finally:
        os.close(dir_fd)


def inspect_d4_runtime_sources(
    ctx: "WorkspaceContext", candidate: D4FixtureCandidate, *,
    private_root: str, expected_hashes: dict[str, str],
) -> D4RuntimeSourceObservation:
    """Real staged source inspection and closed-env selection, no execution.

    expected_hashes MUST originate from a separately reviewed trusted
    provisioning source. This function validates bytes against supplied
    digests but does NOT attest who supplied the digests; a client-provided
    dict, a forged dataclass or this return value is NEVER an Exec grant.
    """
    from .workspaces import WorkspaceContext

    if (type(ctx) is not WorkspaceContext
            or type(candidate) is not D4FixtureCandidate
            or type(expected_hashes) is not dict):
        raise D4RuntimeSourceDenied("trusted context and expected source required")
    root = _canonical(private_root, "private_root")
    project = _canonical(str(ctx.gateway._root_path), "Workspace root")
    _below(root, project)
    _stat_private_directory(project, root)
    if candidate.plan.workspace != ctx.name:
        raise D4RuntimeSourceDenied("Workspace identity mismatch")
    if (candidate.native_launch_allowed is not False
            or candidate.owner_approval_attested is not False):
        raise D4RuntimeSourceDenied("source-only candidate cannot carry native grant")
    if (not candidate.source_sha256 or not candidate.directory_identity):
        raise D4RuntimeSourceDenied("first-party source snapshot missing")
    try:
        fresh = check_d4_r003_fixture(ctx, candidate.plan)
    except (D4FixtureDenied, OSError):
        raise D4RuntimeSourceDenied("first-party Workspace source changed") from None
    if (fresh.source_sha256 != candidate.source_sha256
            or fresh.source_identity != candidate.source_identity
            or fresh.directory_identity != candidate.directory_identity):
        raise D4RuntimeSourceDenied("first-party input changed during staging")

    _parent_selector_guard()
    for path in ("home", "tmp"):
        _stat_private_directory(_child(root, path), root)
    if candidate.plan.cwd == "go-project" and candidate.plan.runner == "direct":
        if set(expected_hashes) != {"go", "compile", "link"}:
            raise D4RuntimeSourceDenied("missing exact Go stage input set")
        go_root = _child(root, "go")
        hashes = {k: _hash_expected(v, k) for k,v in expected_hashes.items()}
        try:
            observed = inspect_staged_go_files_t0(
                private_root=root, goroot=go_root,
                expected_go_sha256=hashes["go"],
                expected_compile_sha256=hashes["compile"],
                expected_link_sha256=hashes["link"],
            )
        except (LbeGoFixtureT0Denied, OSError):
            raise D4RuntimeSourceDenied("actual Go staged files are not qualified") from None
        env = dict(_ENV_CONSTANT_GO)
        env.update({
            "GOROOT": go_root,
            "PATH": go_root + "/bin:/usr/bin:/bin",
            "HOME": _child(root, "home"),
            "TMPDIR": _child(root, "tmp"),
            "GOPATH": _child(root, "gopath"),
            "GOMODCACHE": _child(root, "modcache"),
            "GOCACHE": _child(root, "gocache"),
            "GOTMPDIR": _child(root, "gotmp"),
        })
        for name in ("gopath", "modcache", "gocache", "gotmp"):
            _stat_private_directory(_child(root, name), root)
        try:
            check_go_environment_t0(
                private_root=root, goroot=go_root,
                go_entrypoint=go_root + "/bin/go",
                home=env["HOME"], temporary=env["TMPDIR"],
                gopath=env["GOPATH"], gomodcache=env["GOMODCACHE"],
                gocache=env["GOCACHE"], gotmpdir=env["GOTMPDIR"],
                staged_go_sha256=observed.go_sha256,
                staged_compiler_sha256=observed.compile_sha256,
                parent_environment={}, effective_environment=env,
            )
        except LbePrelaunchT0Denied:
            raise D4RuntimeSourceDenied("constructed Go env not closed") from None
        staged = (("go/bin/go", observed.go_sha256),
                  ("go/pkg/tool/darwin_arm64/compile", observed.compile_sha256),
                  ("go/pkg/tool/darwin_arm64/link", observed.link_sha256))
        kind = "go"
    elif candidate.plan.cwd == "py-pipenv" and candidate.plan.runner == "pipenv":
        if set(expected_hashes) != {
            "Pipfile", "Pipfile.lock", "pyvenv.cfg", "python", "pipenv",
        }:
            raise D4RuntimeSourceDenied("missing exact Pipenv source input set")
        hashes = {k: _hash_expected(v, k) for k,v in expected_hashes.items()}
        try:
            observed = inspect_private_pipenv_fixture_t0(
                project_root=project,
                expected_pipfile_sha256=hashes["Pipfile"],
                expected_lock_sha256=hashes["Pipfile.lock"],
                expected_pyvenv_cfg_sha256=hashes["pyvenv.cfg"],
                expected_python_sha256=hashes["python"],
            )
        except (LbePipenvFixtureT0Denied, OSError):
            raise D4RuntimeSourceDenied("actual Pipenv staged files are not qualified") from None
        pipenv_entry = _child(root, "bin/pipenv")
        staged_pipenv_sha = _private_file_hash(pipenv_entry, root)
        if staged_pipenv_sha != hashes["pipenv"]:
            raise D4RuntimeSourceDenied("staged Pipenv entrypoint drifted")
        env = dict(_ENV_CONSTANT_PIPENV)
        env.update({
            "PATH": root + "/bin:" + project + "/.venv/bin:/usr/bin:/bin",
            "PIPENV_PIPFILE": project + "/Pipfile",
            "HOME": _child(root, "home"),
            "TMPDIR": _child(root, "tmp"),
        })
        try:
            check_pipenv_environment_t0(
                project_root=project, private_root=root,
                pipenv_bin=root + "/bin", pipenv_entrypoint=pipenv_entry,
                pipfile=project + "/Pipfile",
                venv_root=project + "/.venv",
                selected_python=project + "/.venv/bin/python",
                home=env["HOME"], temporary=env["TMPDIR"],
                pipfile_lock_sha256=observed.pipfile_lock_sha256,
                pipenv_sha256=staged_pipenv_sha,
                python_sha256=observed.python_file_sha256,
                parent_environment={}, effective_environment=env,
            )
        except LbePrelaunchT0Denied:
            raise D4RuntimeSourceDenied("constructed Pipenv env not closed") from None
        staged = (("bin/pipenv", staged_pipenv_sha),
                  (candidate.plan.cwd + "/.venv/bin/python",
                   observed.python_file_sha256))
        kind = "pipenv"
    else:
        raise D4RuntimeSourceDenied("unapproved native stage selection")

    kernel = os.uname()
    return D4RuntimeSourceObservation(
        workspace=ctx.name, kind=kind,
        requested_argv=candidate.plan.requested_argv,
        effective_argv=candidate.plan.effective_argv,
        staged_executables=staged,
        private_first_party_sources=fresh.source_sha256,
        closed_child_environment=tuple(sorted(env.items())),
        observed_kernel=kernel.sysname,
        observed_machine=kernel.machine,
    )


def authorize_d4_native_from_observation(_evidence: object) -> None:
    """Hard denial even for a forged/fully populated source-only observation."""
    raise D4RuntimeSourceDenied(
        "D4_NATIVE_T1=NOT_AUTHORIZED: qualified runner, full loader source, "
        "whole-domain OS resource evidence and exact owner grant required")
