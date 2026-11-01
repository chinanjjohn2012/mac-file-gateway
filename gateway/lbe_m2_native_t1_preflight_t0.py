"""NONOPERATIVE M2 SOURCE_TOOLCHAIN_T1 test-plan and offline-egress preflight T0.

This code NEVER runs Go/Pipenv, calls Popen, opens a socket, installs tooling,
creates/attaches a network policy, or mints a WorkspaceService permission.
It validates the shape of a proposed test plan, NOT actual source-loaded identity,
runner identity, OS-enforced CPU/RAM bounds, precontact isolation or a canary.
A successful plan is still HARD BLOCKED from launching native executables.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import gc
import re
from types import MappingProxyType
from typing import Mapping

from .lbe_prelaunch_binding_t0 import (
    PrelaunchBindingT0, LbePrelaunchBindingT0Error,
    bind_go_prelaunch_t0, bind_pipenv_prelaunch_t0,
)


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
_M1_COMMON_INPUTS = frozenset({
    "private_root", "trusted_base", "expected_members",
    "parent_env", "expected_parent_path", "home", "temp",
})
_M1_INPUTS = {
    "go": _M1_COMMON_INPUTS | frozenset({
        "go_path", "mod_cache", "build_cache",
    }),
    "pipenv": _M1_COMMON_INPUTS,
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
    """A mutable-by-reconstruction dataclass is NOT an attested source."""
    if type(candidate) is not PrelaunchBindingT0:
        raise LbeM2T1PreflightError("unqualified M1 source/env candidate")
    if (type(candidate.kind) is not str
            or type(candidate.status) is not str
            or type(candidate.source_loaded_identity) is not str
            or type(candidate.network_precontact_isolation) is not str
            or type(candidate.original_child_native_t1) is not str
            or type(candidate.checked_member_sha256) is not MappingProxyType
            or type(candidate.child_env) is not MappingProxyType):
        raise LbeM2T1PreflightError("untrusted M1 candidate fields")
    if (candidate.kind != kind
            or candidate.status != "NONOPERATIVE_PRELAUNCH_CANDIDATE_ONLY"
            or candidate.exec_authorized is not False
            or candidate.source_loaded_identity != "NOT_ATTESTED"
            or candidate.network_precontact_isolation != "NOT_ATTESTED"
            or candidate.original_child_native_t1 != "NOT_RUN"):
        raise LbeM2T1PreflightError("unqualified M1 source/env candidate")


def _plain_immutable_strings(view: Mapping[str, str]) -> dict[str, str]:
    """Only accept an exact built-in dict behind a mappingproxy.

    MappingProxyType can wrap a user-defined dict subclass, not just a plain
    dict. Calling proxy.items(), proxy.copy(), or iter(proxy) could execute
    overridden methods that lie about actual GOFLAGS/PATH/member identities
    or raise arbitrary exceptions. Inspect ONLY the CPython GC referent type
    before accessing contents through unoverrideable dict.items. If a Python
    runtime cannot expose exactly one plain-dict backing referent, fail
    closed. This T0 structural defense is NOT unforgeable provenance,
    loaded-source verification, or a race-free native executor authorization.
    """
    if type(view) is not MappingProxyType:
        raise LbeM2T1PreflightError("expected immutable M1 snapshot")
    try:
        referents = gc.get_referents(view)
    except (TypeError, ValueError, RuntimeError, OSError) as exc:
        raise LbeM2T1PreflightError("M1 mapping backing not inspectable") from exc
    if len(referents) != 1 or type(referents[0]) is not dict:
        raise LbeM2T1PreflightError(
            "M1 snapshot is not backed by a canonical plain dict")
    # Use the exact built-in dict.items descriptor on an exact built-in dict.
    # No caller-provided MappingProxyType.items / subclass .items / .__iter__
    # hook is invoked. The first-party M1 binder makes these plain dicts.
    try:
        pairs = tuple(dict.items(referents[0]))
        if (not pairs or
                any(type(k) is not str or type(v) is not str
                    for k, v in pairs)):
            raise LbeM2T1PreflightError("untrusted M1 snapshot members")
        copied = dict(pairs)
    except (TypeError, ValueError, RuntimeError, OSError, KeyError) as exc:
        raise LbeM2T1PreflightError("unreadable M1 snapshot") from exc
    if len(copied) != len(pairs):
        raise LbeM2T1PreflightError("duplicate M1 snapshot source")
    return copied

def _recheck_actual_m1_stage(
    kind: str, candidate: PrelaunchBindingT0,
    inputs: dict[str, object],
) -> PrelaunchBindingT0:
    """Rehash original staged members and reconstruct exact closed env.

    A caller can manufacture dataclass instances or claim SHA values.
    We never use their status/map as proof: re-run M1's FD/no-follow source
    admission against caller-supplied approved private roots and verify
    that the input snapshot equals the newly reconstructed result.
    Even this is T0-only; same-UID TOCTOU and true loaded source unproved.
    """
    if type(inputs) is not dict or set(inputs) != _M1_INPUTS[kind]:
        raise LbeM2T1PreflightError("M1 revalidation inputs missing")
    members = inputs["expected_members"]
    parent = inputs["parent_env"]
    if (type(members) is not dict or type(parent) is not dict
            or any(type(key) is not str or type(value) is not str
                   for key, value in members.items())
            or any(type(key) is not str or type(value) is not str
                   for key, value in parent.items())
            or type(inputs["expected_parent_path"]) is not str
            or any(not isinstance(inputs[key], Path) for key in (
                "private_root", "trusted_base", "home", "temp"))
            or (kind == "go" and any(
                not isinstance(inputs[key], Path) for key in (
                    "go_path", "mod_cache", "build_cache")))):
        raise LbeM2T1PreflightError("untrusted M1 source/env recheck input")
    try:
        if kind == "go":
            fresh = bind_go_prelaunch_t0(**inputs)
        else:
            fresh = bind_pipenv_prelaunch_t0(**inputs)
    except (LbePrelaunchBindingT0Error, TypeError, ValueError,
            KeyError, OSError) as exc:
        raise LbeM2T1PreflightError(
            "M1 source/env stage identity no longer verified") from exc
    if (_plain_immutable_strings(candidate.checked_member_sha256)
            != _plain_immutable_strings(fresh.checked_member_sha256)
            or _plain_immutable_strings(candidate.child_env)
            != _plain_immutable_strings(fresh.child_env)):
        raise LbeM2T1PreflightError("forged or drifted M1 source/env snapshot")
    return fresh


def _validate_source_lock(
    kind: str, proposal: dict[str, str], candidate: PrelaunchBindingT0,
) -> None:
    if type(proposal) is not dict or len(proposal) > 20000:
        raise LbeM2T1PreflightError("incomplete or untrusted T1 source lock")
    for name, digest in proposal.items():
        if (type(name) is not str
                or len(name) > 512
                or not _SAFE_MEMBER.fullmatch(name)
                or any(part in {".", ".."} for part in name.split("/"))
                or type(digest) is not str
                or not _HEX64.fullmatch(digest)):
            raise LbeM2T1PreflightError("invalid source lock member or digest")
    verified = _plain_immutable_strings(candidate.checked_member_sha256)
    if (not _REQUIRED_MEMBERS[kind].issubset(proposal)
            or set(verified) - set(proposal)):
        raise LbeM2T1PreflightError("incomplete or untrusted T1 source lock")
    for name, digest in verified.items():
        if type(digest) is not str or proposal[name] != digest:
            raise LbeM2T1PreflightError("M1/T1 source identity drift")


def _validate_runner(proposal: dict[str, str]) -> None:
    if (type(proposal) is not dict
            or set(proposal) != _RUNNER_KEYS
            or any(type(value) is not str for value in proposal.values())
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
            or proposal["job_seconds"] < proposal["child_seconds"] + 60
            or not 1 <= proposal["cpu_seconds"] <= 120
            or not 256 <= proposal["memory_mib"] <= 2048
            or proposal["active_source_children"] != 1
            or any(not 1 <= proposal[key] <= 48000 for key in (
                "stdout_raw_bytes", "stderr_raw_bytes",
                "stdout_redacted_chars", "stderr_redacted_chars"))):
        raise LbeM2T1PreflightError("native T1 resource proposal exceeds bounds")
    # No RLIMIT, sandbox, Job timeout or pipe budget is installed here.


def _validate_offline_proposal(proposal: dict[str, str]) -> None:
    if (type(proposal) is not dict or set(proposal) != _EGRESS_KEYS
            or any(type(value) is not str for value in proposal.values())):
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
    # These are requested policy characteristics, NOT attached OS policy
    # evidence. A boolean from CI, user data, or env cannot prove isolation.


def prepare_m2_source_t1_plan_t0(
    *, kind: str, argv: tuple[str, ...],
    candidate: PrelaunchBindingT0,
    m1_recheck_inputs: dict[str, object],
    proposed_head: str, proposed_tree: str,
    source_lock: dict[str, str], runner: dict[str, str],
    budget: dict[str, int], offline_policy: dict[str, str],
) -> M2SourceT1PlanT0:
    """T0 structural proposal only: never returns launch authority.

    Native Go/Pipenv T1 needs a SEPARATELY REVIEWED executable attester and
    enforceable isolation domain, neither present in this file or this PR.
    """
    if type(kind) is not str or kind not in _REQUIRED_MEMBERS:
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
    # This is a fresh M1 no-follow SHA and closed-env recheck, not a
    # cryptographic constructor token or a real native loaded-source proof.
    checked = _recheck_actual_m1_stage(kind, candidate, m1_recheck_inputs)
    _validate_source_lock(kind, source_lock, checked)
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
