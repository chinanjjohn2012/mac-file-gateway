"""N3-M T0: isolated, nonspawning, nonpersistent contract model.

NOT imported by Gateway runtime, official MCP/REST, Runner or any state store.
No OS/FD/file/socket/signal/process operations. All transitions are hypothetical
single-threaded memory events, not consent, durability or Native qualification.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import hmac
import json
import re


class N3MBlocked(RuntimeError):
    """Contract rejection inside the test-only model, never a live grant."""


_ID = re.compile(r"[a-z][a-z0-9_-]{0,63}\Z")
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_ACK = ("host_user_scope", "irreversible_effects", "detached_survivors")
_PENDING = frozenset(("PREPARED", "STARTING", "RUNNING", "CLEANUP_PENDING"))
_TERMINAL = frozenset(("UNKNOWN", "RETIRED_LIMITED"))
_DECISIONS = frozenset(("LIMITED_HISTORICAL_COMPLETION_COMMITTED", "QUARANTINED_OR_CLEANUP_UNKNOWN"))


def _id(value: object) -> bool:
    return type(value) is str and _ID.fullmatch(value) is not None


def _positive(value: object) -> bool:
    return type(value) is int and 0 < value < 2**63


def _canonical(data: dict) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def strict_json(text: str, required: frozenset[str]) -> dict:
    """Reject duplicate/unknown keys, nonfinite constants, wrong top-level type."""
    if type(text) is not str or len(text.encode("utf-8")) > 65536:
        raise N3MBlocked("invalid_json_size")

    def pairs(items: list[tuple[str, object]]) -> dict:
        data: dict = {}
        for key, value in items:
            if key in data:
                raise N3MBlocked("duplicate_json_key")
            data[key] = value
        return data

    def bad_constant(_value: str) -> None:
        raise N3MBlocked("nonfinite_json")

    try:
        data = json.loads(text, object_pairs_hook=pairs, parse_constant=bad_constant)
    except (ValueError, TypeError, RecursionError, UnicodeError) as exc:
        raise N3MBlocked("invalid_json") from exc
    if type(data) is not dict or data.keys() != required:
        raise N3MBlocked("unexpected_json_schema")
    return data


@dataclass(frozen=True, slots=True)
class N3MBinding:
    workspace: str
    root_dev: int
    root_ino: int
    server_exec_enabled: bool
    workspace_exec_enabled: bool
    server_exec_paths: tuple[str, ...]
    workspace_exec_paths: tuple[str, ...]
    runner_id: str
    backend_id: str
    backend_version: str
    backend_config_sha256: str
    risk_contract_sha256: str
    consent_format: str
    operator_issuer: str
    risk_ack: tuple[str, ...]
    expiry_epoch: int | None

    def __post_init__(self) -> None:
        if not _id(self.workspace) or not all(_positive(x) for x in (self.root_dev, self.root_ino)):
            raise ValueError("invalid_workspace_root")
        if type(self.server_exec_enabled) is not bool or type(self.workspace_exec_enabled) is not bool:
            raise ValueError("invalid_exec_grant_type")
        for group in (self.server_exec_paths, self.workspace_exec_paths):
            if (type(group) is not tuple or not group
                    or any(not _id(x) for x in group)
                    or tuple(sorted(set(group))) != group):
                raise ValueError("invalid_effective_exec_paths")
        if any(not _id(x) for x in (self.runner_id, self.backend_id, self.backend_version,
                                    self.consent_format, self.operator_issuer)):
            raise ValueError("invalid_authority_identity")
        if not all(type(x) is str and _HEX.fullmatch(x) for x in
                   (self.backend_config_sha256, self.risk_contract_sha256)):
            raise ValueError("invalid_authority_fingerprint")
        if self.risk_ack != _ACK:
            raise ValueError("incomplete_risk_ack")
        if self.runner_id not in self.server_exec_paths or self.runner_id not in self.workspace_exec_paths:
            raise ValueError("runner_not_in_effective_grants")
        if self.expiry_epoch is not None and not _positive(self.expiry_epoch):
            raise ValueError("invalid_expiry")

    def digest(self) -> str:
        """Deterministic equality fingerprint; NOT a signature or antirollback proof."""
        return hashlib.sha256(_canonical(asdict(self)).encode("ascii")).hexdigest()


@dataclass(frozen=True, slots=True)
class N3MControl:
    schema_id: str
    namespace_id: str
    lineage_generation: int
    owner_generation: int
    state_generation: int
    consent_epoch: int
    consent_active: bool
    consent_binding_digest: str
    consent_expiry_epoch: int | None
    owner_lock_dev: int
    owner_lock_ino: int
    global_quarantined: bool

    def __post_init__(self) -> None:
        if self.schema_id != "native-n3-v1" or not _id(self.namespace_id):
            raise ValueError("foreign_control_schema_or_namespace")
        if not all(_positive(v) for v in (self.lineage_generation, self.owner_generation,
                                          self.state_generation, self.owner_lock_dev, self.owner_lock_ino)):
            raise ValueError("invalid_control_generation")
        if type(self.consent_epoch) is not int or not 0 <= self.consent_epoch < 2**63:
            raise ValueError("invalid_control_consent_epoch")
        if type(self.consent_active) is not bool or type(self.global_quarantined) is not bool:
            raise ValueError("invalid_control_flags")
        if (type(self.consent_binding_digest) is not str
                or not _HEX.fullmatch(self.consent_binding_digest)):
            raise ValueError("invalid_control_binding")
        if self.consent_expiry_epoch is not None and not _positive(self.consent_expiry_epoch):
            raise ValueError("invalid_control_expiry")

    def encoded(self) -> str:
        return _canonical(asdict(self))


def decode_control(text: str) -> N3MControl:
    fields = frozenset(N3MControl.__dataclass_fields__)
    try:
        return N3MControl(**strict_json(text, fields))
    except (TypeError, ValueError) as exc:
        raise N3MBlocked("invalid_control_data") from exc


@dataclass(frozen=True, slots=True)
class N3MAttempt:
    namespace_id: str
    lineage_generation: int
    owner_generation: int
    consent_epoch: int
    binding_digest: str
    attempt_id: str
    attempt_generation: int
    workspace: str
    root_dev: int
    root_ino: int
    evidence_ref: str = "none"

    def __post_init__(self) -> None:
        if not all(_id(x) for x in (self.namespace_id, self.attempt_id, self.workspace)):
            raise ValueError("invalid_attempt_id")
        if not all(_positive(x) for x in (self.lineage_generation, self.owner_generation,
                                          self.consent_epoch, self.attempt_generation,
                                          self.root_dev, self.root_ino)):
            raise ValueError("invalid_attempt_generation")
        if type(self.binding_digest) is not str or not _HEX.fullmatch(self.binding_digest):
            raise ValueError("invalid_attempt_binding")
        if type(self.evidence_ref) is not str or len(self.evidence_ref) > 4096:
            raise ValueError("invalid_evidence_ref")


def verify_attempt(text: str, expected: N3MAttempt) -> N3MAttempt:
    if type(expected) is not N3MAttempt:
        raise N3MBlocked("untrusted_attempt_identity")
    try:
        attempt = N3MAttempt(**strict_json(text, frozenset(N3MAttempt.__dataclass_fields__)))
    except (TypeError, ValueError) as exc:
        raise N3MBlocked("invalid_attempt_data") from exc
    if not hmac.compare_digest(_canonical(asdict(attempt)), _canonical(asdict(expected))):
        raise N3MBlocked("foreign_or_replayed_attempt")
    return attempt  # still not an authority credential


@dataclass(frozen=True, slots=True)
class N3MDecision:
    decision_id: str
    namespace_id: str
    lineage_generation: int
    owner_generation: int
    consent_epoch: int
    binding_digest: str
    attempt_id: str
    attempt_generation: int
    decision_sequence: int
    phase_at_decision: str
    kind: str
    cleanup_scope: str
    full_descendant_tree_clean: str = "not_proven"
    transport_ack: None = None

    def __post_init__(self) -> None:
        if not _id(self.decision_id) or not _id(self.attempt_id) or not _id(self.namespace_id):
            raise ValueError("invalid_decision_ids")
        if not all(_positive(x) for x in (self.lineage_generation, self.owner_generation,
                                          self.consent_epoch, self.attempt_generation,
                                          self.decision_sequence)):
            raise ValueError("invalid_decision_generation")
        if type(self.binding_digest) is not str or not _HEX.fullmatch(self.binding_digest):
            raise ValueError("invalid_decision_binding")
        if self.kind not in _DECISIONS or self.phase_at_decision not in _TERMINAL:
            raise ValueError("invalid_decision_phase")
        if (self.kind == "LIMITED_HISTORICAL_COMPLETION_COMMITTED") != (self.phase_at_decision == "RETIRED_LIMITED"):
            raise ValueError("inconsistent_limited_decision")
        expected = "original_group_only" if self.phase_at_decision == "RETIRED_LIMITED" else "none"
        if self.cleanup_scope != expected or self.full_descendant_tree_clean != "not_proven" or self.transport_ack is not None:
            raise ValueError("unqualified_cleanup_or_ack")

    def encoded(self) -> str:
        return _canonical(asdict(self))


def verify_decision(text: str, expected: N3MDecision, attempt: N3MAttempt) -> N3MDecision:
    """Verify EVERY immutable identity field and exact registered decision bytes.

    Matching local hashes cannot attest persisted foreign-key provenance. Callers
    must independently prove the real source/owner before using such a record.
    """
    if type(expected) is not N3MDecision or type(attempt) is not N3MAttempt:
        raise N3MBlocked("untrusted_decision_identity")
    record = strict_json(text, frozenset(asdict(expected)))
    try:
        received = N3MDecision(**record)
    except (TypeError, ValueError) as exc:
        raise N3MBlocked("invalid_decision_data") from exc
    foreign = ("namespace_id", "lineage_generation", "owner_generation", "consent_epoch",
               "binding_digest", "attempt_id", "attempt_generation")
    if (any(getattr(received, key) != getattr(attempt, key) for key in foreign)
            or not hmac.compare_digest(received.encoded(), expected.encoded())):
        raise N3MBlocked("foreign_or_replayed_decision")
    return received  # historical only, never a current health or send/ACK claim


class N3MOfflineModel:
    """Standalone deterministic T0 model, WITHOUT persistent/runtime authority."""

    def __init__(self, namespace_id: str, lineage_generation: int, *, max_attempts: int = 4096,
                 max_record_bytes: int = 4096, max_payload_bytes: int = 16 * 1024 * 1024) -> None:
        if not _id(namespace_id) or not _positive(lineage_generation):
            raise ValueError("invalid_namespace_lineage")
        if (type(max_attempts) is not int or not 1 <= max_attempts <= 4096
                or type(max_record_bytes) is not int or not 256 <= max_record_bytes <= 4096
                or type(max_payload_bytes) is not int or not 256 <= max_payload_bytes <= 16*1024*1024):
            raise ValueError("invalid_bounded_limits")
        self.namespace_id = namespace_id
        self.lineage_generation = lineage_generation
        self.owner_generation = 1
        self.consent_epoch = 0
        self._binding: N3MBinding | None = None
        self._consent_active = False
        self._last_clock: int | None = None
        self._provisioned = False
        self._namespace_present = False
        self._witness_present = False
        self._boot_fence_fake = False
        self._quarantined = False
        self._attempt_sequence = 0
        self._decision_sequence = 0
        self._records: dict[str, tuple[N3MAttempt, str]] = {}
        self._decisions: dict[str, N3MDecision] = {}
        self._payload_bytes = 0
        self._max_attempts = max_attempts
        self._max_record_bytes = max_record_bytes
        self._max_payload_bytes = max_payload_bytes
        self._hypothetical_dispatches = 0
        self._orphan_positive = False
        self._fail_at: str | None = None

    @staticmethod
    def deny_apply(*_args: object, **_kwargs: object) -> None:
        raise N3MBlocked("exec_cleanup_proof_required")

    def snapshot(self) -> dict:
        return {"profile": "preview_only", "completion_capability": "none",
                "available_for_real_exec": False, "quarantined_fake": self._quarantined,
                "owner_generation": self.owner_generation, "consent_epoch": self.consent_epoch,
                "attempt_generation": self._attempt_sequence,
                "boot_deny_armed_fake": self._boot_fence_fake,
                "namespace_present_fake": self._namespace_present,
                "witness_present_fake": self._witness_present,
                "hypothetical_dispatches": self._hypothetical_dispatches,
                "orphan_positive_fake": self._orphan_positive,
                "attempt_bytes_fake": self._payload_bytes,
                "phases": {k: v[1] for k, v in self._records.items()},
                "decisions": dict(self._decisions)}

    def provision_offline_fake(self) -> None:
        if self._provisioned or self._quarantined:
            raise N3MBlocked("offline_recovery_required")
        self._provisioned = self._namespace_present = self._witness_present = True

    def lose_provenance_fake(self, *, namespace: bool = False, witness: bool = False) -> None:
        if type(namespace) is not bool or type(witness) is not bool:
            raise ValueError("invalid_loss_flags")
        if namespace:
            self._namespace_present = False
        if witness:
            self._witness_present = False
        if namespace or witness:
            self._quarantined = True

    def restart_fake(self) -> None:
        self.owner_generation += 1
        if self._boot_fence_fake or not self._provisioned or not self._namespace_present or not self._witness_present:
            self._quarantined = True
        self._records = {k: (r, "UNKNOWN" if phase in _PENDING else phase)
                         for k, (r, phase) in self._records.items()}

    def _healthy(self) -> None:
        if self._quarantined or not self._provisioned or not self._namespace_present or not self._witness_present:
            raise N3MBlocked("unqualified_fake_provenance_or_quarantine")

    def _time(self, now: int) -> None:
        if type(now) is not int or now <= 0:
            self._quarantined = True
            raise N3MBlocked("untrusted_clock")
        if self._last_clock is not None and now < self._last_clock:
            self._quarantined = True
            raise N3MBlocked("clock_rollback")
        self._last_clock = now

    def approve_fake(self, binding: N3MBinding, *, now: int) -> int:
        self._healthy()
        self._time(now)
        if type(binding) is not N3MBinding or not binding.server_exec_enabled or not binding.workspace_exec_enabled:
            raise N3MBlocked("fake_consent_invalid_grants")
        if binding.expiry_epoch is not None and now >= binding.expiry_epoch:
            raise N3MBlocked("fake_consent_expired")
        if self._consent_active:
            raise N3MBlocked("fake_consent_already_active")
        self.consent_epoch += 1
        self._binding = binding
        self._consent_active = True
        return self.consent_epoch

    def revoke_fake(self) -> None:
        self.consent_epoch += 1
        self._consent_active = False
        for k, (r, phase) in tuple(self._records.items()):
            if phase in _PENDING:
                self._records[k] = (r, "UNKNOWN")
                self._quarantined = True

    def validate_binding_fake(self, binding: N3MBinding, *, now: int) -> None:
        self._healthy()
        self._time(now)
        if (type(binding) is not N3MBinding or self._binding is None
                or not hmac.compare_digest(self._binding.digest(), binding.digest())
                or not self._consent_active):
            self.revoke_fake()
            raise N3MBlocked("fake_binding_or_consent_changed")
        if binding.expiry_epoch is not None and now >= binding.expiry_epoch:
            self.revoke_fake()
            raise N3MBlocked("fake_consent_expired")

    def content_changed_fake(self, *, now: int) -> None:
        self._healthy()
        self._time(now)  # mutable script contents intentionally NOT a binding field

    def fault_next_fake_commit(self, stage: str) -> None:
        if stage not in ("arm", "prepare", "response", "late_event"):
            raise ValueError("invalid_fault_stage")
        self._fail_at = stage

    def _fake_commit(self, stage: str) -> None:
        if self._fail_at == stage:
            self._fail_at = None
            self._quarantined = True
            raise N3MBlocked("fake_commit_unavailable:" + stage)

    def prepare_fake(self, binding: N3MBinding, *, now: int, evidence_ref: str = "none") -> N3MAttempt:
        self.validate_binding_fake(binding, now=now)
        if len(self._records) >= self._max_attempts:
            self._quarantined = True
            raise N3MBlocked("fake_record_count_full")
        next_attempt = self._attempt_sequence + 1
        attempt = N3MAttempt(self.namespace_id, self.lineage_generation, self.owner_generation,
                             self.consent_epoch, binding.digest(), "a" + str(next_attempt),
                             next_attempt, binding.workspace, binding.root_dev, binding.root_ino,
                             evidence_ref)
        size = len(_canonical(asdict(attempt)).encode("ascii"))
        if size > self._max_record_bytes or self._payload_bytes + size > self._max_payload_bytes:
            self._quarantined = True
            raise N3MBlocked("fake_record_byte_quota_full")
        self._fake_commit("arm")
        self._boot_fence_fake = True
        self._fake_commit("prepare")
        self._attempt_sequence = next_attempt
        self._records[attempt.attempt_id] = (attempt, "PREPARED")
        self._payload_bytes += size
        return attempt

    def _record(self, attempt: N3MAttempt) -> str:
        if type(attempt) is not N3MAttempt:
            raise N3MBlocked("invalid_attempt_type")
        row = self._records.get(attempt.attempt_id)
        if row is None or row[0] is not attempt:
            raise N3MBlocked("foreign_or_forged_attempt")
        return row[1]

    def fake_first_dispatch(self, attempt: N3MAttempt, *, now: int) -> None:
        self._healthy()
        if self._binding is None:
            raise N3MBlocked("fake_binding_missing")
        self.validate_binding_fake(self._binding, now=now)
        phase = self._record(attempt)
        if attempt.attempt_id in self._decisions:
            raise N3MBlocked("fake_dispatch_after_response")
        if (not self._consent_active or attempt.owner_generation != self.owner_generation
                or attempt.consent_epoch != self.consent_epoch or not self._boot_fence_fake
                or phase != "PREPARED"):
            raise N3MBlocked("fake_dispatch_unqualified")
        self._records[attempt.attempt_id] = (attempt, "RUNNING")
        self._hypothetical_dispatches += 1  # NO process, OS or native action

    def retire_limited_fake(self, attempt: N3MAttempt) -> None:
        self._healthy()
        if self._record(attempt) != "RUNNING":
            raise N3MBlocked("fake_retirement_unqualified")
        self._records[attempt.attempt_id] = (attempt, "RETIRED_LIMITED")
        # Keep boot-deny armed across this synthetic limited retirement.

    def late_positive_fake(self, attempt: N3MAttempt | None) -> None:
        self._quarantined = True
        if type(attempt) is not N3MAttempt or (self._records.get(attempt.attempt_id) or (None,))[0] is not attempt:
            self._orphan_positive = True
        self._fake_commit("late_event")
        for k, (r, phase) in tuple(self._records.items()):
            if phase in _PENDING or (type(attempt) is N3MAttempt and r is attempt):
                self._records[k] = (r, "UNKNOWN")

    def decide_fake(self, attempt: N3MAttempt) -> N3MDecision:
        phase = self._record(attempt)
        prior = self._decisions.get(attempt.attempt_id)
        if prior is not None:
            return prior
        if phase in _PENDING:
            self._quarantined = True
            for k, (r, ph) in tuple(self._records.items()):
                if ph in _PENDING:
                    self._records[k] = (r, "UNKNOWN")
            raise N3MBlocked("response_before_terminal")
        if phase not in _TERMINAL:
            self._quarantined = True
            raise N3MBlocked("unknown_response_phase")
        self._fake_commit("response")
        self._decision_sequence += 1
        limited = phase == "RETIRED_LIMITED" and not self._quarantined
        phase_for_decision = "RETIRED_LIMITED" if limited else "UNKNOWN"
        decision = N3MDecision(
            decision_id="d" + str(self._decision_sequence),
            namespace_id=attempt.namespace_id, lineage_generation=attempt.lineage_generation,
            owner_generation=attempt.owner_generation, consent_epoch=attempt.consent_epoch,
            binding_digest=attempt.binding_digest, attempt_id=attempt.attempt_id,
            attempt_generation=attempt.attempt_generation,
            decision_sequence=self._decision_sequence, phase_at_decision=phase_for_decision,
            kind="LIMITED_HISTORICAL_COMPLETION_COMMITTED" if limited else "QUARANTINED_OR_CLEANUP_UNKNOWN",
            cleanup_scope="original_group_only" if limited else "none",
        )
        self._decisions[attempt.attempt_id] = decision
        return decision

    def read_decision_fake(self, text: str, attempt: N3MAttempt) -> N3MDecision:
        self._record(attempt)
        prior = self._decisions.get(attempt.attempt_id)
        if prior is None:
            raise N3MBlocked("missing_registered_decision")
        return verify_decision(text, prior, attempt)
