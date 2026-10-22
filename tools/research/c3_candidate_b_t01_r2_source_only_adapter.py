"""C3 B03-T01 R2b-R2b-R2: REVIEW-ONLY Python binding source.

This module is deliberately incapable of loading or invoking C. It does not
import ctypes, cffi, subprocess, importlib, OS process interfaces or a native
Adapter/probe. A valid request yields an immutable SOURCE-ONLY binding plan,
NEVER a native dispatch, runtime admission or 19-field C result.

All future Python -> linked-C call paths and first-load authority require a
separately reviewed fixed-Head source/binary/loader gate. NO group signal.
"""
from __future__ import annotations

from dataclasses import dataclass

REVIEW_ONLY_NO_LOAD = True
GROUP_SIGNAL_AUTHORIZED = False
C_DISPATCH_IMPLEMENTED = False
ABI_VERSION = 1
FIXTURE = "fixture:synthetic-owned-anchor-group-T01"
MODE = "escalate-positive"
REVIEWED_R1_HEAD = "a39124235c89a92794eb973a0c718e766eb4f64d"
REVIEWED_C_SHA256 = "5a1292787584632fac20c86bbe62e50153e82b0ecb36ad190446bf4b7b714195"
REVIEWED_HEADER_SHA256 = "7c9bd037ecf65da8de91605846c4ac4fc7ceaebbd0ca2fe983ecfef630c9958e"
# These are evidence from PR #44's original Jobs, NOT an approval to load.
HISTORICAL_LINKED_SHA256 = (
    ("Darwin-arm64", "87d87fd11bc2a38f066e41b1c51d8282eafe2d174f35a87354fdd728a01c5c9a"),
    ("Linux-x86_64", "9bbf2acd784cebb363fb9fb1bc6a2b71781b84d76c38262e44cc60bbe56d8918"),
)

TERM_DENIALS = (
    "root-unsafe", "anchor-not-direct-owned-child", "anchor-exited",
    "anchor-reaped-or-wait-consumed", "anchor-pid-pgid-mismatch",
    "anchor-sid-ppid-drift", "anchor-initial-sigterm-ignore-missing",
    "controller-in-anchor-group", "controller-not-owned-child",
    "worker-not-controller-child", "worker-not-armed",
    "worker-not-in-anchor-group", "worker-term-resistant-unproven",
    "ipc-writer-spoofed", "term-cutoff-equal", "term-cutoff-late",
)
KILL_DENIALS = (
    "anchor-post-term-ignore-missing", "anchor-post-term-sequence-stale",
    "anchor-early-exit", "anchor-reaped-before-kill",
    "anchor-identity-reused", "controller-not-live-after-grace",
    "controller-entered-anchor-group", "controller-lost-worker-wait",
    "worker-parent-changed", "worker-pgid-changed",
    "worker-exited-during-grace", "native-identity-recheck-missing",
    "ipc-post-term-forged", "grace-not-finished",
    "kill-cutoff-equal", "kill-cutoff-late",
    "late-term-with-finished-grace", "rebase-original-policy",
    "incorrect-term-timestamp", "forged-successful-term-ledger",
    "kill-without-term",
)
ERRORS = (
    ("term", "EINTR"), ("term", "ESRCH"), ("term", "EPERM"),
    ("kill", "EINTR"), ("kill", "ESRCH"), ("kill", "EPERM"),
)
EVIDENCE_DENIALS = (
    "worker-wait-not-by-controller", "anchor-wait-not-by-owner",
    "controller-final-forged", "controller-final-missing",
    "fd-close-unproven", "outer-deadline-exceeded",
    "only-note-exit-observed", "worker-wait-unknown",
)
TERM_MUTANTS = (
    "omit-anchor-term-ignore", "omit-controller-outside-group",
    "omit-worker-legal-parent", "omit-worker-group-check",
)
KILL_MUTANTS = (
    "omit-anchor-post-term-witness", "omit-anchor-reap-check",
    "omit-controller-live-check", "omit-kill-cutoff",
    "omit-grace", "allow-policy-rebase",
)
REPLAY_MUTANTS = ("allow-second-term", "allow-second-kill")
EVIDENCE_MUTANTS = ("accept-fake-final", "ignore-fd-close")
FAULT_CATALOG = (
    tuple(("TERM", value) for value in TERM_DENIALS)
    + tuple(("KILL", value) for value in KILL_DENIALS)
    + tuple(("ERRNO", phase + "-" + errno) for phase, errno in ERRORS)
    + tuple(("EVIDENCE", value) for value in EVIDENCE_DENIALS)
    + tuple(("MUTATION", value) for value in (
        TERM_MUTANTS + KILL_MUTANTS + REPLAY_MUTANTS
    ))
    + tuple(("EVIDENCE_MUTATION", value) for value in EVIDENCE_MUTANTS)
    + (("MODE", "different-mode"), ("KILL", "nominal-synthetic"))
)
FAULT_IDS = {item: i for i, item in enumerate(FAULT_CATALOG, 1)}
assert len(FAULT_IDS) == len(FAULT_CATALOG) == 67

REQUEST_FIELDS = frozenset((
    "abi_version", "mode", "fixture_target", "phase", "fault", "nonce",
    "original_policy", "attempt_policy", "now_ms", "term_sent_at_ms",
    "mock_only", "attempt_sequence",
))
# This frozen byte-by-value field order is the c3b03_t01_deadline_t ABI order.
POLICY_FIELD_ORDER = (
    "t0_ms", "outer_budget_ms", "cleanup_reserve_ms",
    "term_grace_ms", "kill_entry_margin_ms", "outer_deadline_ms",
    "term_cutoff_ms", "kill_cutoff_ms",
)
_STEP_ENUM = {"TERM": 1, "KILL": 2}
_INT64_MAX = (1 << 63) - 1
_UINT64_MAX = (1 << 64) - 1


@dataclass(frozen=True)
class SourceBindingPlan:
    """Immutable data-only C ABI *proposal*, never a dispatch token."""

    scenario_id: int
    phase_enum: int
    nonce: int
    attempt_steps: tuple[int, ...]
    original_deadline: tuple[int, ...]
    attempt_deadline: tuple[int, ...]
    now_ms: int
    term_sent_at_ms: int

    @property
    def native_dispatches(self) -> int:
        return 0

    @property
    def native_execution_allowed(self) -> bool:
        return False


def _is_int64(value: object, *, positive: bool = False) -> bool:
    return type(value) is int and (0 < value <= _INT64_MAX
                                    if positive else 0 <= value <= _INT64_MAX)


def _valid_policy(value: object) -> tuple[int, ...] | None:
    if type(value) is not dict or set(value) != set(POLICY_FIELD_ORDER):
        return None
    if not all(_is_int64(value[key]) for key in POLICY_FIELD_ORDER):
        return None
    p = tuple(value[key] for key in POLICY_FIELD_ORDER)
    t0, budget, reserve, grace, margin, outer, term, kill = p
    if min(budget, reserve, grace, margin) <= 0:
        return None
    if t0 + budget > _INT64_MAX or outer != t0 + budget:
        return None
    if kill != outer - reserve or term != kill - grace - margin:
        return None
    if not (t0 < term < kill < outer):
        return None
    return p


def _expected_steps(phase: str, fault: str) -> tuple[str, ...]:
    if phase == "TERM" or (phase == "ERRNO" and fault.startswith("term-")):
        return ("TERM",)
    if phase == "MUTATION":
        if fault in TERM_MUTANTS:
            return ("TERM",)
        if fault == "allow-second-term":
            return ("TERM", "TERM")
        if fault == "allow-second-kill":
            return ("TERM", "KILL", "KILL")
    return ("TERM", "KILL")


def _phase_enum(phase: str, fault: str) -> int:
    if phase == "TERM" or (phase == "ERRNO" and fault.startswith("term-")):
        return 1
    if phase == "MUTATION" and (fault in TERM_MUTANTS or
                                fault == "allow-second-term"):
        return 1
    if phase in {"KILL", "ERRNO", "MUTATION"}:
        return 2
    return 3


class SourceOnlyAdapter:
    """Source validator with one-use nonce ledger; has NO loader interface."""

    def __init__(self) -> None:
        self._seen: set[int] = set()

    def plan(self, request: object) -> SourceBindingPlan | None:
        # Consume even a malformed request's valid nonce. Replay cannot rearm.
        if type(request) is not dict:
            return None
        nonce = request.get("nonce")
        if type(nonce) is not int or not 0 < nonce <= _UINT64_MAX:
            return None
        if nonce in self._seen:
            return None
        self._seen.add(nonce)

        if set(request) != REQUEST_FIELDS:
            return None
        if type(request["abi_version"]) is not int or request["abi_version"] != 1:
            return None
        if type(request["mode"]) is not str or request["mode"] != MODE:
            return None
        if (type(request["fixture_target"]) is not str or
                request["fixture_target"] != FIXTURE):
            return None
        if request["mock_only"] is not True:
            return None
        phase, fault = request["phase"], request["fault"]
        if type(phase) is not str or type(fault) is not str:
            return None
        scenario = FAULT_IDS.get((phase, fault))
        if scenario is None or scenario == 66:
            return None
        if not _is_int64(request["now_ms"]):
            return None
        if not _is_int64(request["term_sent_at_ms"]):
            return None
        original = _valid_policy(request["original_policy"])
        attempt = _valid_policy(request["attempt_policy"])
        if original is None or attempt is None:
            return None
        steps = request["attempt_sequence"]
        if type(steps) is not tuple or steps != _expected_steps(phase, fault):
            return None
        return SourceBindingPlan(
            scenario_id=scenario,
            phase_enum=_phase_enum(phase, fault),
            nonce=nonce,
            attempt_steps=tuple(_STEP_ENUM[x] for x in steps),
            original_deadline=original,
            attempt_deadline=attempt,
            now_ms=request["now_ms"],
            term_sent_at_ms=request["term_sent_at_ms"],
        )


def native_call(*args: object, **kwargs: object) -> None:
    """Explicitly disabled: this source stage has no actual C call chain."""
    raise RuntimeError("SOURCE_ONLY_NO_C_LOAD: independent PRE-LOAD review required")
