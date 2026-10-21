"""B03-T01-R2 pure, no-signal admission and synthetic event accounting.

RESEARCH ONLY. This module cannot spawn a process, send TERM/SIGKILL,
obtain a host PID/PGID, or assert native waitpid evidence.

The strictly test-owned fixture target and recorder are in-memory only.
Even a successful synthetic "KILL" is not an OS signal or a G2 qualification.
The native owner must perform its own kernel/IPC checks in a later,
separately authorized stage; these Python facts are *claims*, not proof.
"""
from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import NamedTuple

# Deliberately not configurable from CLI/env/runtime input.
_FIXTURE_TARGET = "fixture:synthetic-owned-anchor-group-T01"

_TERM_KEYS = frozenset((
    "private_root_owned_0700",
    "owner_unique_signal_authority",
    "owner_outside_anchor_group",
    "anchor_exact_spawn_child",
    "anchor_unreaped_live",
    "anchor_pid_equals_pgid",
    "anchor_sid_and_ppid_match",
    "anchor_sigterm_ign_ready",
    "controller_exact_spawn_child",
    "controller_self_led_outside_group",
    "controller_live_and_same_sid",
    "worker_controller_child",
    "worker_armed",
    "worker_joined_anchor_pgid",
    "worker_term_resistant_native",
    "trusted_ipc_writer_isolated",
    "kernel_identity_fresh",
))
_KILL_KEYS = _TERM_KEYS | frozenset((
    "anchor_sigterm_ign_after_term",
    "anchor_post_term_seq_new",
    "anchor_live_after_grace",
    "anchor_wait_not_consumed",
    "controller_live_after_grace",
    "controller_self_group_rechecked",
    "worker_live_after_grace",
    "worker_parent_pgid_sid_rechecked",
    "native_entry_identity_fresh",
))
_POLICY_KEYS = frozenset((
    "t0_ms", "outer_deadline_ms", "kill_cutoff_ms", "term_cutoff_ms",
    "cleanup_reserve_ms", "term_grace_ms", "kill_entry_margin_ms",
))
_ISSUER = object()  # Private, in-process synthetic recorder provenance only.


def derive_cutoffs(
    t0_ms: int,
    outer_budget_ms: int,
    cleanup_reserve_ms: int,
    term_grace_ms: int,
    kill_entry_margin_ms: int,
) -> dict:
    """Freeze one monotonic deadline. Caller may not reset it after TERM."""
    v = (
        t0_ms, outer_budget_ms, cleanup_reserve_ms,
        term_grace_ms, kill_entry_margin_ms,
    )
    if any(type(n) is not int for n in v):
        raise ValueError("all deadline quantities must be exact integers")
    if t0_ms < 0 or any(n <= 0 for n in v[1:]):
        raise ValueError("non-positive or invalid deadline quantity")
    if outer_budget_ms <= (
        cleanup_reserve_ms + term_grace_ms + kill_entry_margin_ms
    ):
        raise ValueError("no positive startup/ARM admission budget")
    outer = t0_ms + outer_budget_ms
    kill = outer - cleanup_reserve_ms
    term = kill - term_grace_ms - kill_entry_margin_ms
    return {
        "t0_ms": t0_ms,
        "outer_deadline_ms": outer,
        "kill_cutoff_ms": kill,
        "term_cutoff_ms": term,
        "cleanup_reserve_ms": cleanup_reserve_ms,
        "term_grace_ms": term_grace_ms,
        "kill_entry_margin_ms": kill_entry_margin_ms,
    }


def _valid_policy(p: object) -> bool:
    if type(p) is not dict or frozenset(p) != _POLICY_KEYS:
        return False
    if any(type(p[k]) is not int for k in _POLICY_KEYS):
        return False
    try:
        derived = derive_cutoffs(
            p["t0_ms"],
            p["outer_deadline_ms"] - p["t0_ms"],
            p["cleanup_reserve_ms"],
            p["term_grace_ms"],
            p["kill_entry_margin_ms"],
        )
    except ValueError:
        return False
    return derived == p


def _valid_facts(claims: object, required: frozenset) -> bool:
    if type(claims) is not dict or frozenset(claims) != required:
        return False
    return all(type(claims[name]) is bool and claims[name] is True
               for name in required)


def term_admitted(cutoffs: dict, now_ms: int, facts: dict) -> bool:
    """Pure predicate; this does not observe the Darwin process table."""
    if not _valid_policy(cutoffs) or type(now_ms) is not int:
        return False
    return (
        _valid_facts(facts, _TERM_KEYS)
        and cutoffs["t0_ms"] <= now_ms < cutoffs["term_cutoff_ms"]
        and now_ms < cutoffs["outer_deadline_ms"]
    )


def kill_admitted(
    cutoffs: dict, now_ms: int, term_sent_at_ms: int, facts: dict,
) -> bool:
    """Pure post-grace admission. No standalone bool authorizes a syscall."""
    if not _valid_policy(cutoffs):
        return False
    if type(now_ms) is not int or type(term_sent_at_ms) is not int:
        return False
    if not _valid_facts(facts, _KILL_KEYS):
        return False
    grace_end = term_sent_at_ms + cutoffs["term_grace_ms"]
    return (
        cutoffs["t0_ms"] <= term_sent_at_ms < cutoffs["term_cutoff_ms"]
        and grace_end < cutoffs["kill_cutoff_ms"]
        and grace_end <= now_ms < cutoffs["kill_cutoff_ms"]
        and now_ms < cutoffs["outer_deadline_ms"]
    )


class _LedgerSnapshot(NamedTuple):
    """Private immutable snapshot: public ledger observations never authorize a transition."""

    values: Mapping
    term_event: object | None
    original_policy: tuple[tuple[str, int], ...] | None


class _Ledger(Mapping):
    """Externally read-only one-use synthetic authority, shared by all aliases.

    It intentionally exposes no state mutators or event-creation methods.
    The gate functions change the private snapshot with object.__setattr__;
    ordinary setattr, Mapping mutation or callable ledger methods cannot
    forge a recorder event or reopen an already closed authority.
    This is unit-test integrity, NOT a sandbox against Python reflection.
    """

    __slots__ = ("__snapshot",)

    def __init__(self, issuer: object):
        if issuer is not _ISSUER:
            raise ValueError("synthetic ledger may only be issued by this module")
        values = MappingProxyType({
            "term_attempts": 0,
            "term_succeeded": False,
            "term_sent_at_ms": None,
            "term_target_ref": None,
            "kill_attempts": 0,
            "kill_succeeded": False,
            "kill_errno_class": "NONE",
            "signals_closed": False,
            "group_signals_after_close": 0,
        })
        object.__setattr__(
            self, "_Ledger__snapshot", _LedgerSnapshot(values, None, None)
        )

    def __setattr__(self, key, value):
        raise AttributeError("synthetic ledger is externally read-only")

    def __delattr__(self, key):
        raise AttributeError("synthetic ledger is externally read-only")

    def __getitem__(self, key):
        return self.__snapshot.values[key]

    def __iter__(self):
        return iter(self.__snapshot.values)

    def __len__(self):
        return len(self.__snapshot.values)


def begin_ledger() -> Mapping:
    """Issue an unspent, non-forgeable-via-public-methods test-only ledger."""
    return _Ledger(_ISSUER)


def _ledger_or_closed(value: object) -> _Ledger:
    if type(value) is _Ledger:
        return value
    # A forged public dict or arbitrary caller object has no authority.
    denied = _Ledger(_ISSUER)
    snap = denied._Ledger__snapshot
    object.__setattr__(
        denied,
        "_Ledger__snapshot",
        _LedgerSnapshot(
            MappingProxyType({**snap.values, "signals_closed": True}),
            None,
            None,
        ),
    )
    return denied


def _policy_binding(cutoffs: dict) -> tuple[tuple[str, int], ...]:
    """Value snapshot of every policy field, never a caller-owned dict alias."""
    return tuple((key, cutoffs[key]) for key in sorted(_POLICY_KEYS))


def _fixture_target(target_ref: object) -> bool:
    return type(target_ref) is str and target_ref == _FIXTURE_TARGET


def attempt_term_no_signal(
    cutoffs: dict, now_ms: int, facts: dict,
    ledger: Mapping, recorder: object, owned_ref: object,
) -> Mapping:
    """Exactly one fake TERM recorder call, or irrevocable refusal."""
    state = _ledger_or_closed(ledger)

    # This closure is local to the controlled transition. No ledger methods
    # or externally callable event/state setters exist.
    def commit(changes: dict, *, event=None, original_policy=None):
        snap = state._Ledger__snapshot
        object.__setattr__(
            state, "_Ledger__snapshot",
            _LedgerSnapshot(
                MappingProxyType({**snap.values, **changes}),
                snap.term_event if event is None else event,
                snap.original_policy if original_policy is None else original_policy,
            ),
        )

    if state["signals_closed"]:
        return state
    if (
        state["term_attempts"] != 0
        or state["kill_attempts"] != 0
        or not _fixture_target(owned_ref)
        or not term_admitted(cutoffs, now_ms, facts)
    ):
        commit({"signals_closed": True})
        return state

    # Only after a verified TERM gate: snapshot the ORIGINAL complete
    # absolute policy by value, before handing off to the fake transport.
    first_policy = _policy_binding(cutoffs)
    commit({"term_attempts": 1})
    try:
        response = recorder.send("TERM", owned_ref)
    except Exception:
        commit({"signals_closed": True, "term_succeeded": False})
        return state

    if type(response) is str and response == "OK":
        commit(
            {
                "term_succeeded": True,
                "term_sent_at_ms": now_ms,
                "term_target_ref": owned_ref,
            },
            event=object(), original_policy=first_policy,
        )
    else:
        commit({"signals_closed": True, "term_succeeded": False})
    return state


def attempt_kill_no_signal(
    cutoffs: dict, now_ms: int, term_sent_at_ms: int, facts: dict,
    ledger: Mapping, recorder: object, owned_ref: object,
) -> Mapping:
    """Only a recorder-proven TERM under the SAME absolute policy may KILL."""
    state = _ledger_or_closed(ledger)

    def commit(changes: dict):
        snap = state._Ledger__snapshot
        object.__setattr__(
            state, "_Ledger__snapshot",
            _LedgerSnapshot(
                MappingProxyType({**snap.values, **changes}),
                snap.term_event, snap.original_policy,
            ),
        )

    if state["signals_closed"]:
        return state

    # A self-consistent *different* policy cannot rebase t0 or the old
    # deadline. Check value equality of all seven original absolute fields
    # before using the current policy for post-grace admission.
    policy_valid = _valid_policy(cutoffs)
    original_policy = state._Ledger__snapshot.original_policy
    if not (
        _fixture_target(owned_ref)
        and state._Ledger__snapshot.term_event is not None
        and original_policy is not None
        and policy_valid
        and _policy_binding(cutoffs) == original_policy
        and state["term_attempts"] == 1
        and state["term_succeeded"] is True
        and state["kill_attempts"] == 0
        and type(term_sent_at_ms) is int
        and term_sent_at_ms == state["term_sent_at_ms"]
        and owned_ref == state["term_target_ref"]
        and kill_admitted(cutoffs, now_ms, term_sent_at_ms, facts)
    ):
        commit({"signals_closed": True})
        return state

    # Count and close before fake transport. No retries, even on EINTR.
    commit({"kill_attempts": 1, "signals_closed": True})
    try:
        response = recorder.send("KILL", owned_ref)
    except Exception:
        commit({"kill_succeeded": False, "kill_errno_class": "OTHER"})
        return state

    if type(response) is str and response == "OK":
        commit({"kill_succeeded": True, "kill_errno_class": "NONE"})
    else:
        error = response if type(response) is str and response in (
            "ESRCH", "EPERM", "EINTR"
        ) else "OTHER"
        commit({"kill_succeeded": False, "kill_errno_class": error})
    return state


# Exact schema is copied from the independently frozen B03-R1 11-mode
# contract, not dynamically imported from tests or native observations.
_BOOL_FIELDS = (
    "anchor_ignore_ready", "anchor_ignore_after_term",
    "anchor_live_at_kill_gate", "anchor_reaped",
    "anchor_sigkill_observed", "controller_own_pgid_at_term",
    "controller_own_pgid_at_kill", "controller_live_at_kill_gate",
    "worker_spawned", "worker_armed", "worker_term_resistant",
    "worker_live_after_grace", "term_gate_checked", "term_attempts",
    "term_succeeded", "kill_gate_checked", "kill_attempts",
    "kill_succeeded", "signals_closed", "group_signals_after_close",
    "after_loss_kill_attempts", "controller_waited_worker",
    "controller_final_trusted", "owner_children_reaped",
    "owner_fds_closed", "controller_worker_fds_closed",
    "canary_survived", "known_descendant_observed",
    "independent_exit_observer_ready", "orphan_preflight_proven",
    "audit_post_wait_without_final", "kill_cutoff_expired",
    "outer_live_at_refusal", "positive_kill_margin",
    "reuse_proven", "g2_qualified",
)
_ENUM_FIELDS = ("worker_result", "anchor_result", "cleanup", "kill_errno_class")
_POSITIVE_ONES = frozenset((
    "anchor_ignore_ready", "anchor_ignore_after_term",
    "anchor_live_at_kill_gate", "anchor_reaped",
    "anchor_sigkill_observed", "controller_own_pgid_at_term",
    "controller_own_pgid_at_kill", "controller_live_at_kill_gate",
    "worker_spawned", "worker_armed", "worker_term_resistant",
    "worker_live_after_grace", "term_gate_checked", "term_attempts",
    "term_succeeded", "kill_gate_checked", "kill_attempts",
    "kill_succeeded", "signals_closed", "controller_waited_worker",
    "controller_final_trusted", "owner_children_reaped",
    "owner_fds_closed", "controller_worker_fds_closed",
    "positive_kill_margin",
))
_RESULT_ENUMS = {
    "worker_result": "OBSERVED_SIGNAL_SIGKILL",
    "anchor_result": "OBSERVED_SIGNAL_SIGKILL",
    "cleanup": "VERIFIED",
    "kill_errno_class": "NONE",
}
_EXPECTED_FIELDS = frozenset(("mode",) + _BOOL_FIELDS + _ENUM_FIELDS)


def classify_t01(record: object) -> str:
    """Strict *fixture* record classifier, NOT lawful native wait evidence."""
    if type(record) is not dict or frozenset(record) != _EXPECTED_FIELDS:
        return "BLOCK"
    if type(record["mode"]) is not str or record["mode"] != "escalate-positive":
        return "BLOCK"
    for name in _BOOL_FIELDS:
        value = record[name]
        if type(value) is not int:
            return "BLOCK"
        if value != (1 if name in _POSITIVE_ONES else 0):
            return "BLOCK"
    for name in _ENUM_FIELDS:
        if (type(record[name]) is not str
                or record[name] != _RESULT_ENUMS[name]):
            return "BLOCK"
    return "POSITIVE_EXPERIMENT"


def t01_mode_admitted(mode: object, *, orphan_preflight_proven=False) -> bool:
    """Freeze T01 exclusivity across all 11 modes and malformed inputs."""
    return (
        type(orphan_preflight_proven) is bool
        and type(mode) is str
        and mode == "escalate-positive"
    )
