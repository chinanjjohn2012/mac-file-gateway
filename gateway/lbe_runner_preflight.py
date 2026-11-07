"""D4 R003 observed runner prelaunch boundary: read-only product source.

No native process, VM, subprocess, network, signaling or resource-domain
attachment occurs. Actual kernel, UID, pinned source-root inode and per-process
rlimit measurements must not be confused with the unobserved GitHub provider,
immutable runner image, credential/mount isolation, loaded source or an attached
whole-original-child plus descendants CPU/RAM domain. A CI label, declared
image digest or per-process rlimit never grants real PRODUCT_T1 execution.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
import resource
import stat
from typing import TYPE_CHECKING

from .lbe_launch_recipe import D4NativeLaunchRecipe, _PROPOSED_LIMITS
from .lbe_runtime_source import _canonical, _below, D4RuntimeSourceDenied

if TYPE_CHECKING:
    from .workspaces import WorkspaceContext


class D4RunnerProbeDenied(ValueError):
    """Unsafe live runner source or absent required native execution proof."""


_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_INODE_FIELDS = ("st_dev", "st_ino", "st_mode", "st_uid",
                 "st_mtime_ns", "st_ctime_ns")
_SECRET_NAMES = frozenset({
    "GITHUB_TOKEN", "GH_TOKEN", "ACTIONS_RUNTIME_TOKEN",
    "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY", "GOOGLE_APPLICATION_CREDENTIALS",
    "AZURE_CLIENT_SECRET", "SSH_AUTH_SOCK", "CI_JOB_TOKEN",
})
_SECRET_ENDINGS = ("_TOKEN", "_SECRET", "_PASSWORD", "_PRIVATE_KEY",
                   "_ACCESS_KEY", "_CREDENTIALS")
_PROXY_NAMES = frozenset({
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "FTP_PROXY",
})
_BLOCKERS = (
    "GITHUB_PROVIDER_IMMUTABLE_IMAGE_NOT_ATTESTED",
    "NO_CREDENTIALS_AND_NO_SHARED_WRITABLE_MOUNTS_NOT_PROVEN",
    "FULL_GO_PIPENV_PYTHON_LOADED_SOURCE_NOT_ATTESTED",
    "WHOLE_CHILD_DOMAIN_CPU_2000M_RAM_4096M_NOT_ATTACHED",
    "EXACT_OWNER_MACOS_PRODUCT_T1_AUTHORIZATION_ABSENT",
    "OPERATIVE_D0_F1_POSITIVE_EXCEPTION_NOT_ISSUED",
)


@dataclass(frozen=True, slots=True)
class D4ObservedRunnerPreflight:
    """Real host observations; none is a runnable capability or T1 proof."""

    workspace: str
    source_fingerprint: str
    kernel_sysname: str
    kernel_release: str
    machine: str
    pid: int
    uid: int
    effective_uid: int
    gid: int
    private_root_inode: tuple[int, ...]
    workspace_inode: tuple[int, ...]
    rlimit_cpu_seconds_soft: int | None
    rlimit_as_bytes_soft: int | None
    claimed_ci_label_present: bool
    ambient_sensitive_credentials_present: bool
    ambient_proxy_settings_present: bool
    proposed_limits: tuple[tuple[str, int], ...] = _PROPOSED_LIMITS
    status: str = "ACTUAL_HOST_SOURCE_ONLY_NATIVE_ADMISSION_BLOCKED"
    kernel_and_private_paths_observed: bool = True
    immutable_github_image_observed: bool = False
    github_provider_attested: bool = False
    no_shared_mounts_proven: bool = False
    no_host_credentials_proven: bool = False
    loaded_source_graph_proven: bool = False
    physical_whole_child_cpu_memory_attached: bool = False
    exact_owner_native_t1_authorized: bool = False
    native_launch_allowed: bool = False
    blockers: tuple[str, ...] = _BLOCKERS


def _pinned_directory(path: str, owner_root: str) -> tuple[int, ...]:
    """Open from / by nofollow FDs; verify every private owned component."""
    try:
        path = _canonical(path, "selected runner directory")
        owner_root = _canonical(owner_root, "private runner root")
        if path != owner_root:
            _below(owner_root, path)
    except D4RuntimeSourceDenied:
        raise D4RunnerProbeDenied("invalid private directory") from None
    components = path[1:].split("/")
    root_parts = owner_root[1:].split("/")
    try:
        fd = os.open("/", _DIR_FLAGS)
    except OSError:
        raise D4RunnerProbeDenied("cannot open pinned filesystem root") from None
    try:
        for index, part in enumerate(components):
            child = os.open(part, _DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = child
            if index + 1 >= len(root_parts):
                st = os.fstat(fd)
                if (not stat.S_ISDIR(st.st_mode)
                        or st.st_uid != os.getuid()
                        or st.st_mode & 0o022):
                    raise D4RunnerProbeDenied(
                        "private runner directory is not owner controlled")
        st = os.fstat(fd)
        return tuple(getattr(st, attr) for attr in _INODE_FIELDS)
    except OSError:
        raise D4RunnerProbeDenied("private runner FD cannot be read") from None
    finally:
        os.close(fd)


def _process_soft_limit(kind: int) -> int | None:
    """Observe rlimits, which are NOT whole-descendant CPU/memory limits."""
    try:
        soft, _hard = resource.getrlimit(kind)
    except (OSError, ValueError):
        return None
    return None if soft == resource.RLIM_INFINITY else soft


def observe_d4_runner_preflight(
    ctx: "WorkspaceContext", recipe: D4NativeLaunchRecipe, *,
    private_root: str,
) -> D4ObservedRunnerPreflight:
    """Read actual source-root/kernel/process facts, without granting launch."""
    from .workspaces import WorkspaceContext

    if (type(ctx) is not WorkspaceContext
            or type(recipe) is not D4NativeLaunchRecipe
            or type(private_root) is not str
            or recipe.workspace != ctx.name
            or recipe.native_launch_allowed is not False
            or recipe.owner_t1_grant_present is not False
            or recipe.physical_cpu_memory_enforcement_proven is not False
            or recipe.actual_loaded_source_graph_proven is not False
            or recipe.real_runner_qualified is not False
            or recipe.required_limits != _PROPOSED_LIMITS
            or type(recipe.selected_source_fingerprint) is not str
            or len(recipe.selected_source_fingerprint) != 64
            or any(c not in "0123456789abcdef"
                   for c in recipe.selected_source_fingerprint)):
        raise D4RunnerProbeDenied("untrusted or promoted native recipe")
    try:
        root = _canonical(private_root, "private root")
        workspace = _canonical(str(ctx.gateway._root_path), "workspace")
        _below(root, workspace)
    except D4RuntimeSourceDenied:
        raise D4RunnerProbeDenied("invalid runner/Workspace source scope") from None
    if (not hasattr(os, "uname") or os.geteuid() != os.getuid()
            or not recipe.resolved_executable.startswith(root + "/")
            or not recipe.working_directory.startswith(workspace + "/")):
        raise D4RunnerProbeDenied("unqualified live process or source selection")

    root_inode = _pinned_directory(root, root)
    workspace_inode = _pinned_directory(workspace, root)
    uname = os.uname()
    # Only booleans are retained: never serialize token or proxy values.
    credentials = any(bool(value) and (
        name in _SECRET_NAMES or name.upper().endswith(_SECRET_ENDINGS)
    ) for name, value in os.environ.items())
    proxies = any(bool(value) and name.upper() in _PROXY_NAMES
                  for name, value in os.environ.items())
    return D4ObservedRunnerPreflight(
        workspace=ctx.name,
        source_fingerprint=recipe.selected_source_fingerprint,
        kernel_sysname=uname.sysname, kernel_release=uname.release,
        machine=uname.machine, pid=os.getpid(), uid=os.getuid(),
        effective_uid=os.geteuid(), gid=os.getgid(),
        private_root_inode=root_inode, workspace_inode=workspace_inode,
        rlimit_cpu_seconds_soft=_process_soft_limit(resource.RLIMIT_CPU),
        rlimit_as_bytes_soft=_process_soft_limit(resource.RLIMIT_AS),
        claimed_ci_label_present=bool(os.environ.get("GITHUB_ACTIONS")),
        ambient_sensitive_credentials_present=credentials,
        ambient_proxy_settings_present=proxies,
    )


def require_d4_native_runner_admission(
    _observation: object, _recipe: object,
) -> None:
    """A host probe or forged dataclass cannot satisfy a real T1 gate."""
    raise D4RunnerProbeDenied(
        "PRODUCT_T1=NOT_AUTHORIZED: immutable runner image and attached "
        "original-child/descendant CPU/RAM domain have not been proven"
    )
