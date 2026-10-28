"""R2-N N2: purely in-memory, NONSPAWNING contract and deterministic Fake.

NOT wired to WorkspaceService, HTTP, MCP, Runner, ExecStateStore or configuration.
A Fake result is NEVER operator consent, OS ownership, fsync, Native cleanup,
real response delivery or positive Exec qualification. No OS/file/network APIs.
Actual F1 continues to deny dry_run=False before Worker/PREPARED/Runner.
"""
from __future__ import annotations

from dataclasses import dataclass
import re


class N2Blocked(RuntimeError):
    """Fail-closed hypothetical model denial; not a production error grant."""


_WORKSPACE = re.compile(r"[a-z][a-z0-9_-]{0,31}\Z")


@dataclass(frozen=True, slots=True)
class FakeScope:
    workspace: str
    root_dev: int
    root_ino: int
    exec_paths: tuple[str, ...]
    backend_version: str
    risk_version: str

    def __post_init__(self) -> None:
        if type(self.workspace) is not str or not _WORKSPACE.fullmatch(self.workspace):
            raise ValueError("invalid Workspace")
        if any(type(v) is not int or v <= 0 for v in (self.root_dev, self.root_ino)):
            raise ValueError("invalid pinned-root identity")
        if (type(self.exec_paths) is not tuple or not self.exec_paths
                or any(type(v) is not str or not v for v in self.exec_paths)
                or len(set(self.exec_paths)) != len(self.exec_paths)):
            raise ValueError("invalid effective Exec scope")
        if any(type(v) is not str or not v or len(v) > 128
               for v in (self.backend_version, self.risk_version)):
            raise ValueError("invalid backend/risk version")


@dataclass(frozen=True, slots=True)
class FakeTicket:
    attempt_id: int
    attempt_generation: int
    owner_generation: int
    consent_epoch: int
    scope: FakeScope


@dataclass(frozen=True, slots=True)
class FakeResponseDecision:
    attempt_id: int
    sequence: int
    kind: str  # LIMITED_HISTORICAL_COMPLETION_COMMITTED or QUARANTINED_OR_CLEANUP_UNKNOWN
    cleanup_scope: str  # original_group_only or none (hypothetical)
    full_descendant_tree_clean: str = "not_proven"
    transport_ack: None = None  # No transport, ACK or sent response exists.


class N2MemoryFake:
    """TEST-ONLY single-threaded event ordering, not a Runner or durable store.

    Each method is one chosen hypothetical ordering. There is NO claim that a
    mutex, simulated commit, or this object is an actual prestart/OS guarantee.
    An external provisioning witness and namespace are separate fake booleans.
    The marker models *intent*, not physical persistence or real fsync.
    """

    def __init__(self, *, max_records: int = 4096) -> None:
        if type(max_records) is not int or not 1 <= max_records <= 4096:
            raise ValueError("invalid bounded record quota")
        self._max_records = max_records
        self._provisioned_once = False
        self._namespace_present = False
        self._witness_present = False
        self._boot_fence_armed = False
        self._available = True
        self._quarantined = False
        self._consent_active = False
        self._consent_epoch = 0
        self._scope: FakeScope | None = None
        self._owner_generation = 1
        self._attempt_generation = 0
        self._records: dict[int, dict] = {}
        self._decisions: dict[int, FakeResponseDecision] = {}
        self._sequence = 0
        self._hypothetical_dispatches = 0
        self._orphan_positive = False
        self._failed_late_event_durability = False
        self._fail_at: str | None = None

    @staticmethod
    def deny_apply(*_args: object, **_kwargs: object) -> None:
        """ALWAYS deny: a Fake ticket can never authorize ordinary Exec."""
        raise N2Blocked("exec_cleanup_proof_required")

    def snapshot(self) -> dict:
        """Return copied read-only *data*, not an authority handle."""
        return {
            "profile": "preview_only", "completion_capability": "none",
            "available_for_real_exec": False,
            "consent_epoch": self._consent_epoch,
            "consent_active_fake": self._consent_active,
            "owner_generation": self._owner_generation,
            "attempt_generation": self._attempt_generation,
            "boot_fence_armed_fake": self._boot_fence_armed,
            "namespace_present_fake": self._namespace_present,
            "provisioning_witness_fake": self._witness_present,
            "quarantined": self._quarantined,
            "available_fake": self._available,
            "hypothetical_dispatches": self._hypothetical_dispatches,
            "orphan_positive": self._orphan_positive,
            "failed_late_event_durability_fake": self._failed_late_event_durability,
            "phases": {k: v["phase"] for k, v in self._records.items()},
            "decisions": dict(self._decisions),
        }

    def _check_healthy(self) -> None:
        if not self._available or self._quarantined:
            raise N2Blocked("exec_quarantined_or_state_unavailable")
        if not self._provisioned_once:
            # An untouched test-only instance may be explicitly provisioned.
            # This is NOT permission to auto-reinitialize a lost old namespace.
            raise N2Blocked("native_namespace_or_provisioning_witness_missing")
        if not self._namespace_present or not self._witness_present:
            self._quarantined = True
            raise N2Blocked("native_namespace_or_provisioning_witness_missing")

    def provision_initial_fake(self) -> None:
        """Explicit first-install hypothetical action, NEVER implicit on boot."""
        if self._provisioned_once or self._consent_active or self._quarantined:
            raise N2Blocked("offline_first_init_or_recovery_required")
        self._provisioned_once = True
        self._namespace_present = self._witness_present = True

    def lose_namespace_fake(self) -> None:
        """Simulate ENTIRE namespace loss while consent/witness remains."""
        self._namespace_present = False
        if self._provisioned_once:
            self._quarantined = True

    def lose_witness_fake(self) -> None:
        self._witness_present = False
        if self._provisioned_once:
            self._quarantined = True

    def approve_fake(self, scope: FakeScope) -> int:
        if type(scope) is not FakeScope:
            raise N2Blocked("invalid_fake_scope")
        self._check_healthy()
        if self._consent_active:
            raise N2Blocked("fake_consent_already_active")
        self._consent_epoch += 1
        self._scope = scope
        self._consent_active = True
        return self._consent_epoch

    def fake_content_changed(self) -> None:
        """Candidate A: permitted mutable source edits do NOT rotate consent."""
        self._check_healthy()

    def change_effective_scope_fake(self, scope: FakeScope) -> None:
        if type(scope) is not FakeScope:
            raise N2Blocked("invalid_fake_scope")
        self._check_healthy()
        if scope == self._scope:
            return
        self.revoke_fake()
        self._scope = scope  # changed binding is not silently reapproved

    def revoke_fake(self) -> None:
        self._consent_epoch += 1
        self._consent_active = False
        for record in self._records.values():
            if record["phase"] in ("PREPARED", "STARTING", "RUNNING"):
                record["phase"] = "UNKNOWN"
                self._quarantined = True

    def fault_next_fake_commit(self, stage: str) -> None:
        if stage not in ("arm", "prepare", "starting", "dispatch", "retire", "response", "late_event"):
            raise ValueError("unknown Fake commit stage")
        self._fail_at = stage

    def _fake_commit(self, stage: str) -> None:
        """Only simulated failure point; not I/O, atomicity or fsync proof."""
        if self._fail_at == stage:
            self._fail_at = None
            self._available = False
            self._quarantined = True
            raise N2Blocked("fake_commit_unavailable:" + stage)

    def prepare_fake(self, scope: FakeScope) -> FakeTicket:
        self._check_healthy()
        if not self._consent_active or type(scope) is not FakeScope or scope != self._scope:
            raise N2Blocked("fake_consent_or_binding_invalid")
        if len(self._records) >= self._max_records:
            self._available = False
            self._quarantined = True
            raise N2Blocked("fake_forensic_quota_full")
        self._fake_commit("arm")
        self._boot_fence_armed = True  # fake ordering, not a durable disk fact
        self._fake_commit("prepare")
        self._attempt_generation += 1
        t = FakeTicket(self._attempt_generation, self._attempt_generation,
                       self._owner_generation, self._consent_epoch, scope)
        self._records[t.attempt_id] = {"ticket": t, "phase": "PREPARED"}
        return t

    def _current_ticket(self, ticket: FakeTicket) -> dict:
        if type(ticket) is not FakeTicket:
            raise N2Blocked("invalid_ticket")
        r = self._records.get(ticket.attempt_id)
        if (r is None or r["ticket"] is not ticket
                or ticket.owner_generation != self._owner_generation
                or ticket.consent_epoch != self._consent_epoch
                or ticket.scope != self._scope):
            raise N2Blocked("stale_or_forged_fake_ticket")
        return r

    def simulate_first_dispatch_fake(self, ticket: FakeTicket) -> None:
        """Increment a memory counter only; DOES NOT call any backend/OS API."""
        self._check_healthy()
        r = self._current_ticket(ticket)
        if not self._consent_active or r["phase"] != "PREPARED" or not self._boot_fence_armed:
            raise N2Blocked("fake_first_dispatch_not_qualified")
        self._fake_commit("starting")
        r["phase"] = "STARTING"
        self._fake_commit("dispatch")
        r["phase"] = "RUNNING"
        self._hypothetical_dispatches += 1

    def retire_limited_fake(self, ticket: FakeTicket) -> None:
        """Synthetic observation ONLY, never native cleanup qualification."""
        self._check_healthy()
        r = self._current_ticket(ticket)
        if r["phase"] != "RUNNING":
            raise N2Blocked("fake_retirement_without_hypothetical_run")
        self._fake_commit("retire")
        r["phase"] = "RETIRED_LIMITED"
        # Intentionally keep the boot fence armed after limited retirement.

    def late_survivor_fake(self, ticket: FakeTicket | None) -> None:
        """Hypothetical attribution, not an observer of real descendants."""
        self._quarantined = True  # live admission closes even if event write fails
        if self._fail_at == "late_event":
            self._failed_late_event_durability = True
            self._fake_commit("late_event")
        r = (self._records.get(ticket.attempt_id)
             if type(ticket) is FakeTicket else None)
        if r is not None and r["ticket"] is ticket:
            r["phase"] = "UNKNOWN"  # may supersede an earlier response decision
        else:
            self._orphan_positive = True
        for v in self._records.values():
            if v["phase"] in ("PREPARED", "STARTING", "RUNNING"):
                v["phase"] = "UNKNOWN"
        self._sequence += 1

    def decide_response_fake(self, ticket: FakeTicket) -> FakeResponseDecision:
        """One hypothetical *server decision*, no enqueue/send/client ACK."""
        if type(ticket) is not FakeTicket:
            raise N2Blocked("invalid_ticket")
        r = self._records.get(ticket.attempt_id)
        if r is None or r["ticket"] is not ticket:
            raise N2Blocked("foreign_fake_attempt")
        if ticket.attempt_id in self._decisions:
            return self._decisions[ticket.attempt_id]  # historical, immutable
        self._fake_commit("response")
        self._sequence += 1
        limited = r["phase"] == "RETIRED_LIMITED" and not self._quarantined
        d = FakeResponseDecision(
            ticket.attempt_id, self._sequence,
            "LIMITED_HISTORICAL_COMPLETION_COMMITTED" if limited
            else "QUARANTINED_OR_CLEANUP_UNKNOWN",
            "original_group_only" if limited else "none",
        )
        self._decisions[ticket.attempt_id] = d
        return d

    def restart_fake(self) -> None:
        """Reboot order model, not a physical fsync/recovery claim."""
        self._owner_generation += 1
        if (self._boot_fence_armed or not self._namespace_present
                or not self._witness_present or not self._available):
            self._quarantined = True
        for r in self._records.values():
            if r["phase"] in ("PREPARED", "STARTING", "RUNNING"):
                r["phase"] = "UNKNOWN"
                self._quarantined = True
