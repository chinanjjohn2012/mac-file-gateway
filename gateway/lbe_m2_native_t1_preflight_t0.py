"""NONOPERATIVE M2 SOURCE_TOOLCHAIN_T1 test-plan and offline-egress preflight T0.

This code NEVER runs Go/Pipenv, calls Popen, opens a socket, installs tooling,
creates/attaches a network policy, or mints a WorkspaceService permission.
It validates the shape of a proposed test plan, NOT actual source-loaded identity,
runner identity, OS-enforced CPU/RAM bounds, precontact isolation or a canary.
A successful plan is still HARD BLOCKED from launching native executables.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from types import MappingProxyType
from typing import Mapping

from .lbe_prelaunch_binding_t0 import PrelaunchBindingT0


class LbeM2T1PreflightError(ValueError):
    """Malformed or out-of-scope standalone native T1 proposal."""


_HEX40 = re.compile(r"[0-9a-f]{40}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_SAFE_MEMBER = re.compile(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*\Z")
_SAFE_IMAGE = re.compile(r"[A-Za-z0-9_.:/@-]{3,160}\Z")

_GO_MATRIX = frozenset({
    ("go", "test", "./..."),
    ("go", "vet", "./..."),
    ("go", "build", "./cmd/service"),
    ("go", "build", "-o", "bin/service", "./cmd/service"),
})
_PIPENV_MATRIX = frozenset({("pipenv", "run", "python", "ok.py")})
_REQUIRED_MEMBERS = {
    "go": frozenset({
        "go/VERSION", "go/bin/go",
        "go/pkg/tool/darwin_arm64/compile",
        "go/pkg/tool/darwin_arm64/link",
        "go/src/runtime/proc.go",
        "fixture/go.mod", "fixture/cmd/service/main.go",
    }),
    "pipenv": frozenset({
        "project/Pipfile", "project/Pipfile.lock",
        "project/.venv/pyvenv.cfg", "project/.venv/bin/python",
        "pipenv-env/bin/pipenv", "project/ok.py",
    }),
}
_RUNNER_KEYS = frozenset({
    "provider", "os", "os_major", "arch", "python", "image_id",
})
_BUDGET_KEYS = frozenset({
    "job_seconds", "child_seconds", "cpu_seconds", "memory_mib",
    "stdout_raw_bytes", "stderr_raw_bytes",
    "stdout_redacted_chars", "stderr_redacted_chars",
    "active_source_children",
})
_EGRESS_KEYS = frozenset({
    "mode", "mechanism", "tcp", "udp", "dns", "proxy",
    "descendants", "attachment", "canary",
})
_BLOCKERS = (
    "T1_EXECUTED_CODE_AND_DEPENDENCIES_NOT_ATTESTED",
    "ACTUAL_GO_PIPENV_LOADED_SOURCE_NOT_ATTESTED",
    "ACTUAL_MACOS_RUNNER_IMAGE_PYTHON_NOT_ATTESTED",
    "OS_CPU_MEMORY_LIMITS_NOT_ENFORCED",
    "PRECONTACT_DENY_ALL_EGRESS_NOT_ATTESTED",
    "SAME_DOMAIN_PRECONTACT_DENIAL_CANARY_NOT_RUN",
    "NATIVE_SOURCE_T1_NOT_RUN",
)


@dataclass(frozen=True)
class M2SourceT1PlanT0:
    """Immutable proposal. No field in this type is an execution capability."""

    kind: str
    argv: tuple[str, ...]
    proposed_head: str
    proposed_tree: str
    source_lock: Mapping[str, str]
    runner_proposal: Mapping[str, str]
    budget_proposal: Mapping[str, int]
    egress_proposal: Mapping[str, str]
    review_target: str = "STANDALONE_SOURCE_TOOLCHAIN_T1"
    status: str = "NONOPERATIVE_M2_TEST_PLAN_T0"
    loaded_source_identity: str = "NOT_ATTESTED"
    runner_execution_identity: str = "NOT_ATTESTED"
    resource_enforcement: str = "NOT_ATTESTED"
    precontact_egress_enforcement: str = "NOT_ATTESTED"
    same_domain_canary: str = "NOT_RUN"
    native_t1: str = "NOT_RUN"
    blockers: tuple[str, ...] = _BLOCKERS
    launch_allowed: bool = False
    workspace_service_exec_authorized: bool = False


def _validate_candidate(candidate: PrelaunchBindingT0, kind: str) -> None:
    if (type(candidate) is not PrelaunchBindingT0
            or candidate.kind != kind
            or candidate.status != "NONOPERATIVE_PRELAUNCH_CANDIDATE_ONLY"
            or candidate.exec_authorized is not False
            or candidate.source_loaded_identity != "NOT_ATTESTED"
            or candidate.network_precontact_isolation != "NOT_ATTESTED"
            or candidate.original_child_native_t1 != "NOT_RUN"
            or not isinstance(candidate.checked_member_sha256, Mapping)
            or not isinstance(candidate.child_env, Mapping)
            or not candidate.checked_member_sha256
            or not candidate.child_env):
        raise LbeM2T1PreflightError("unqualified M1 source/env candidate")


def _validate_source_lock(
    kind: str, proposal: dict[str, str], candidate: PrelaunchBindingT0,
) -> None:
    if (type(proposal) is not dict
            or len(proposal) > 20000
            or not _REQUIRED_MEMBERS[kind].issubset(proposal)
            or set(candidate.checked_member_sha256) - set(proposal)):
        raise LbeM2T1PreflightError("incomplete or untrusted T1 source lock")
    for name, digest in proposal.items():
        if (type(name) is not str
                or len(name) > 512
                or not _SAFE_MEMBER.fullmatch(name)
                or any(part in {".", ".."} for part in name.split("/"))
                or type(digest) is not str
                or not _HEX64.fullmatch(digest)):
            raise LbeM2T1PreflightError("invalid source lock member or digest")
    for name, digest in candidate.checked_member_sha256.items():
        if type(digest) is not str or proposal[name] != digest:
            raise LbeM2T1PreflightError("M1/T1 source identity drift")


def _validate_runner(proposal: dict[str, str]) -> None:
    if (type(proposal) is not dict
            or set(proposal) != _RUNNER_KEYS
            or proposal.get("provider") != "GITHUB_HOSTED_DISPOSABLE"
            or proposal.get("os") != "macOS"
            or proposal.get("os_major") != "15"
            or proposal.get("arch") != "ARM64"
            or proposal.get("python") != "3.13"
            or type(proposal.get("image_id")) is not str
            or not _SAFE_IMAGE.fullmatch(proposal["image_id"])):
        raise LbeM2T1PreflightError("unsupported or unpinned proposed runner")
    # image_id is PROPOSED text, not the runner's observed image identity.


def _validate_budget(proposal: dict[str, int]) -> None:
    if type(proposal) is not dict or set(proposal) != _BUDGET_KEYS:
        raise LbeM2T1PreflightError("incomplete bounded native T1 budget")
    if any(type(value) is not int for value in proposal.values()):
        raise LbeM2T1PreflightError("budget values must be plain integers")
    if (not 60 <= proposal["job_seconds"] <= 1200
            or not 1 <= proposal["child_seconds"] <= 120
            or not 1 <= proposal["cpu_seconds"] <= 120
            or not 256 <= proposal["memory_mib"] <= 2048
            or proposal["active_source_children"] != 1
            or any(not 1 <= proposal[key] <= 48000 for key in (
                "stdout_raw_bytes", "stderr_raw_bytes",
                "stdout_redacted_chars", "stderr_redacted_chars"))):
        raise LbeM2T1PreflightError("native T1 resource proposal exceeds bounds")
    # No RLIMIT, sandbox, Job timeout or pipe budget is installed here.


def _validate_offline_proposal(proposal: dict[str, str]) -> None:
    if type(proposal) is not dict or set(proposal) != _EGRESS_KEYS:
        raise LbeM2T1PreflightError("offline precontact policy is incomplete")
    if (proposal.get("mode") != "OFFLINE_ONLY"
            or proposal.get("mechanism") not in (
                "ISOLATED_DISPOSABLE_VM", "AUDITED_ATTACHED_HOST_POLICY")
            or any(proposal.get(k) != "DENY" for k in (
                "tcp", "udp", "dns", "proxy"))
            or proposal.get("descendants") != "SAME_ENFORCEMENT_DOMAIN"
            or proposal.get("attachment") != "BEFORE_ANY_NATIVE_INSTRUCTION"
            or proposal.get("canary") != "SAME_DOMAIN_DENIAL_REQUIRED"):
        raise LbeM2T1PreflightError("unacceptable precontact egress proposal")
    if any(type(value) is not str for value in proposal.values()):
        raise LbeM2T1PreflightError("untrusted offline policy input")
    # These are requested policy characteristics, NOT attached OS policy
    # evidence. A boolean from CI, user data, or env cannot prove isolation.


def prepare_m2_source_t1_plan_t0(
    *, kind: str, argv: tuple[str, ...],
    candidate: PrelaunchBindingT0,
    proposed_head: str, proposed_tree: str,
    source_lock: dict[str, str], runner: dict[str, str],
    budget: dict[str, int], offline_policy: dict[str, str],
) -> M2SourceT1PlanT0:
    """T0 structural proposal only: never returns launch authority.

    Native Go/Pipenv T1 needs a SEPARATELY REVIEWED executable attester and
    enforceable isolation domain, neither present in this file or this PR.
    """
    if kind not in _REQUIRED_MEMBERS:
        raise LbeM2T1PreflightError("unsupported SOURCE_TOOLCHAIN_T1 kind")
    if (type(argv) is not tuple
            or any(type(item) is not str for item in argv)
            or argv not in (_GO_MATRIX if kind == "go" else _PIPENV_MATRIX)):
        raise LbeM2T1PreflightError("unreviewed standalone native T1 command")
    if (type(proposed_head) is not str or not _HEX40.fullmatch(proposed_head)
            or type(proposed_tree) is not str
            or not _HEX40.fullmatch(proposed_tree)
            or proposed_head == proposed_tree):
        raise LbeM2T1PreflightError("invalid test-code identity proposal")
    _validate_candidate(candidate, kind)
    _validate_source_lock(kind, source_lock, candidate)
    _validate_runner(runner)
    _validate_budget(budget)
    _validate_offline_proposal(offline_policy)
    return M2SourceT1PlanT0(
        kind=kind,
        argv=tuple(argv),
        proposed_head=proposed_head,
        proposed_tree=proposed_tree,
        source_lock=MappingProxyType(dict(sorted(source_lock.items()))),
        runner_proposal=MappingProxyType(dict(runner)),
        budget_proposal=MappingProxyType(dict(budget)),
        egress_proposal=MappingProxyType(dict(offline_policy)),
    )
