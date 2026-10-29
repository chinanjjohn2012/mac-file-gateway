"""N3-F0 T0-only private-state read-only adapter contract.

Consumes *hypothetical* pre-observed inode/byte snapshots. It DOES NOT open,
create, lock, read or fsync any OS object. The future physical FD port remains
explicitly disabled until a distinct, resource-specific T1 approval and review.
Not imported or wired by the Gateway, ExecStateStore, S2, REST, MCP or Runner.
All outcomes retain available=False and completion_capability='none'.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import re


class N3F0NotAuthorized(RuntimeError):
    """Real private-FS access is not part of this T0 release."""


_ID = re.compile(r"[a-z][a-z0-9_-]{0,63}\Z")
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_CTRL_FIELDS = frozenset({
    "schema_id", "namespace_id", "lineage_generation", "owner_generation",
    "state_generation", "consent_epoch", "consent_record_id", "consent_active",
    "consent_expiry_or_null", "consent_binding_digest", "owner_lock_dev",
    "owner_lock_ino", "global_quarantined", "global_quarantine_reason",
    "max_attempts", "max_attempt_bytes", "max_total_attempt_payload",
    "unresolved_retired_tombstone_count",
})
_WITNESS_FIELDS = frozenset({
    "schema_id", "namespace_id", "lineage_generation", "state_generation",
    "operator_provisioned",
})
_STATE_NAMES = frozenset({"owner.lock", "control.v1", "attempts", "responses"})
_LINEAGE_NAMES = frozenset({"provision-witness.v1", "owner-authority.v1"})
_MAX_OBJECT = 4096


def _positive(value: object) -> bool:
    return type(value) is int and 0 < value < 2**63


def _json_record(raw: object, fields: frozenset[str]) -> dict:
    if type(raw) is not bytes or not 1 <= len(raw) <= _MAX_OBJECT:
        raise ValueError("record_size_invalid")

    def unique(items: list[tuple[str, object]]) -> dict:
        result: dict = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate_key")
            result[key] = value
        return result

    def reject_nonfinite(_value: str) -> None:
        raise ValueError("nonfinite_json")

    try:
        parsed = json.loads(raw.decode("utf-8"), object_pairs_hook=unique,
                            parse_constant=reject_nonfinite)
    except (UnicodeError, RecursionError, ValueError, TypeError) as exc:
        raise ValueError("invalid_record_json") from exc
    if type(parsed) is not dict or parsed.keys() != fields:
        raise ValueError("unknown_record_schema")
    return parsed


def _control(raw: bytes) -> dict:
    c = _json_record(raw, _CTRL_FIELDS)
    if c["schema_id"] != "native-n3-v1" or not _ID.fullmatch(str(c["namespace_id"])):
        raise ValueError("foreign_n3_schema")
    for key in ("lineage_generation", "owner_generation", "state_generation",
                "owner_lock_dev", "owner_lock_ino"):
        if not _positive(c[key]):
            raise ValueError("invalid_generation_or_inode")
    for key in ("consent_active", "global_quarantined"):
        if type(c[key]) is not bool:
            raise ValueError("invalid_boolean")
    if (type(c["consent_epoch"]) is not int or not 0 <= c["consent_epoch"] < 2**63
            or (c["consent_active"] and c["consent_epoch"] == 0)):
        raise ValueError("invalid_consent_epoch")
    if (type(c["consent_record_id"]) is not str
            or not _ID.fullmatch(c["consent_record_id"])):
        raise ValueError("invalid_consent_id")
    if (type(c["consent_binding_digest"]) is not str
            or not _HEX.fullmatch(c["consent_binding_digest"])):
        raise ValueError("invalid_consent_digest")
    if (c["consent_expiry_or_null"] is not None
            and not _positive(c["consent_expiry_or_null"])):
        raise ValueError("invalid_consent_expiry")
    if (type(c["global_quarantine_reason"]) is not str
            or not _ID.fullmatch(c["global_quarantine_reason"])
            or c["global_quarantined"] == (c["global_quarantine_reason"] == "none")):
        raise ValueError("inconsistent_quarantine")
    if (type(c["max_attempts"]) is not int or not 1 <= c["max_attempts"] <= 4096
            or type(c["max_attempt_bytes"]) is not int
            or not 256 <= c["max_attempt_bytes"] <= 4096
            or type(c["max_total_attempt_payload"]) is not int
            or not 256 <= c["max_total_attempt_payload"] <= 16 * 1024 * 1024
            or type(c["unresolved_retired_tombstone_count"]) is not int
            or not 0 <= c["unresolved_retired_tombstone_count"] <= c["max_attempts"]):
        raise ValueError("invalid_quota")
    return c


def _witness(raw: bytes) -> dict:
    w = _json_record(raw, _WITNESS_FIELDS)
    if (w["schema_id"] != "native-n3-lineage-v1"
            or type(w["namespace_id"]) is not str
            or not _ID.fullmatch(w["namespace_id"])
            or not _positive(w["lineage_generation"])
            or not _positive(w["state_generation"])
            or w["operator_provisioned"] is not True):
        raise ValueError("invalid_offline_provenance")
    return w


@dataclass(frozen=True, slots=True)
class N3F0Node:
    """Untrusted fake fstat projection; not physical FD or ownership proof."""
    kind: str
    dev: int
    ino: int
    uid: int
    mode: int
    nlink: int = 1

    def valid(self, kind: str, uid: int, *, private: bool) -> bool:
        return (type(self.kind) is str and self.kind == kind
                and _positive(self.dev) and _positive(self.ino)
                and type(self.uid) is int and self.uid >= 0
                and type(self.mode) is int and 0 <= self.mode <= 0o7777
                and type(self.nlink) is int and self.nlink >= 1
                and (not private or (self.uid == uid and self.mode ==
                                     (0o700 if kind == "directory" else 0o600)
                                     and (kind == "directory" or self.nlink == 1))))


@dataclass(frozen=True, slots=True)
class N3F0SyntheticTopology:
    """T0-only model of COMPLETE pinned ancestry from a common control root.

    Chains are ordered from a separately trusted common control ancestor to
    the named root, including its direct parent. Sharing a common prefix is
    permitted; rejoining, cross-root containment and unknown chains are not.
    This FAKE structure cannot prove an OS FD ancestry or local consent.
    A future T1 adapter must derive complete identities from real pinned FDs,
    not a client flag, JSON field or this model's values.
    """
    state_ancestor_ids: tuple[tuple[int, int], ...]
    lineage_ancestor_ids: tuple[tuple[int, int], ...]


@dataclass(frozen=True, slots=True)
class N3F0Observation:
    """Test-provided fake snapshot. Never construct from a remote request."""
    service_uid: int
    state_parent: N3F0Node | None
    lineage_parent: N3F0Node | None
    state_root: N3F0Node | None
    lineage_root: N3F0Node | None
    owner_lock: N3F0Node | None
    owner_lock_fd_dev: int
    owner_lock_fd_ino: int
    exclusive_lock_held: bool
    verified_pinned_parents: bool
    roots_disjoint_from_workspaces: bool
    state_entries: tuple[str, ...]
    lineage_entries: tuple[str, ...]
    attempt_entries: tuple[str, ...]
    response_entries: tuple[str, ...]
    control_bytes: bytes | None
    witness_bytes: bytes | None
    topology: N3F0SyntheticTopology | None = None


@dataclass(frozen=True, slots=True)
class N3F0Scan:
    durability_state: str
    quarantine_reason_code: str
    available: bool = False
    completion_capability: str = "none"
    t0_model_only: bool = True

    def __post_init__(self) -> None:
        if (self.available is not False or self.completion_capability != "none"
                or self.t0_model_only is not True):
            raise ValueError("N3-F0 cannot mint real execution authority")


def _deny(reason: str, *, quarantine: bool = False) -> N3F0Scan:
    return N3F0Scan("quarantined" if quarantine else "unavailable", reason)


def _consistent_synthetic_topology(v: N3F0Observation) -> bool:
    """Conservatively check fake complete parent/leaf identity chains.

    This is ONLY internal T0 structural consistency, never a genuine proof
    that any real filesystem ancestors were independently pinned. Missing or
    ambiguous projection is not allowed to become healthy metadata.
    """
    t = v.topology
    if type(t) is not N3F0SyntheticTopology:
        return False
    state, lineage = t.state_ancestor_ids, t.lineage_ancestor_ids
    for chain, parent, root in ((state, v.state_parent, v.state_root),
                                (lineage, v.lineage_parent, v.lineage_root)):
        if type(chain) is not tuple or not 3 <= len(chain) <= 64:
            return False
        if any(type(item) is not tuple or len(item) != 2
               or not all(_positive(number) for number in item)
               for item in chain):
            return False
        if len(set(chain)) != len(chain):
            return False
        if chain[-2] != (parent.dev, parent.ino) or chain[-1] != (root.dev, root.ino):
            return False
    # The modeled roots may have shared ancestors ABOVE their divergence;
    # they may never share a node after branching or contain each other.
    if state[0] != lineage[0]:
        return False
    common = 0
    while common < min(len(state), len(lineage)) and state[common] == lineage[common]:
        common += 1
    if common == len(state) or common == len(lineage):
        return False
    if set(state[common:]) & set(lineage[common:]):
        return False
    # A regular owner.lock cannot share any directory dev/ino, including an
    # intermediate pinned ancestor, even if the five leaves looked unique.
    owner = (v.owner_lock.dev, v.owner_lock.ino)
    if owner in state or owner in lineage:
        return False
    return True


class N3F0OfflinePrivateFSAdapter:
    """Read-only, T0-inert adapter over synthetic fstat/bytes observations.

    A later physical adapter must independently prove pinned-FD origins,
    lifetime owner.lock, non-overlap and real durability before any T1 claim.
    Even fully valid modeled metadata never grants Native execution.
    """

    @staticmethod
    def boot_read_order() -> tuple[str, ...]:
        return ("verify_separate_existing_parents", "pin_existing_roots",
                "verify_complete_ancestry_separation",
                "acquire_existing_owner_lock_exclusively", "verify_lock_fd_identity",
                "read_existing_lineage_witness", "read_existing_n3_control",
                "enumerate_attempt_response_and_fences", "deny_on_ambiguity")

    @staticmethod
    def open_physical_private_store(*_args: object, **_kwargs: object) -> None:
        raise N3F0NotAuthorized("n3_f0_t1_resources_not_authorized")

    @staticmethod
    def scan_observation(value: object) -> N3F0Scan:
        if type(value) is not N3F0Observation:
            return _deny("state_io_unavailable")
        v = value
        if type(v.service_uid) is not int or v.service_uid < 0:
            return _deny("state_io_unavailable")
        for p in (v.state_parent, v.lineage_parent):
            if type(p) is not N3F0Node or not p.valid("directory", v.service_uid, private=False):
                return _deny("state_io_unavailable")
        if (v.state_parent.dev, v.state_parent.ino) == (v.lineage_parent.dev, v.lineage_parent.ino):
            return _deny("lineage_not_independent")
        for p in (v.state_root, v.lineage_root):
            if type(p) is not N3F0Node or not p.valid("directory", v.service_uid, private=True):
                return _deny("state_io_unavailable")
        if (v.state_root.dev, v.state_root.ino) == (v.lineage_root.dev, v.lineage_root.ino):
            return _deny("lineage_not_independent")
        if (v.verified_pinned_parents is not True
                or v.roots_disjoint_from_workspaces is not True):
            return _deny("private_boundary_unverified")
        if (type(v.owner_lock) is not N3F0Node
                or not v.owner_lock.valid("file", v.service_uid, private=True)
                or type(v.owner_lock_fd_dev) is not int
                or type(v.owner_lock_fd_ino) is not int
                or (v.owner_lock_fd_dev, v.owner_lock_fd_ino) !=
                   (v.owner_lock.dev, v.owner_lock.ino)
                or v.exclusive_lock_held is not True):
            return _deny("owner_lock_unavailable")
        all_nodes = (v.state_parent, v.lineage_parent, v.state_root,
                     v.lineage_root, v.owner_lock)
        identities = tuple((item.dev, item.ino) for item in all_nodes)
        if len(set(identities)) != len(identities):
            return _deny("lineage_not_independent")
        if not _consistent_synthetic_topology(v):
            return _deny("private_boundary_unverified")
        for entries in (v.state_entries, v.lineage_entries,
                        v.attempt_entries, v.response_entries):
            if (type(entries) is not tuple or len(entries) > 4096
                    or any(type(n) is not str or len(n) > 128 for n in entries)
                    or len(entries) != len(set(entries))):
                return _deny("corrupt_record", quarantine=True)
        state = set(v.state_entries)
        if "boot-deny.v1" in state:
            return _deny("restart_hazard", quarantine=True)
        if state != _STATE_NAMES or set(v.lineage_entries) != _LINEAGE_NAMES:
            return _deny("corrupt_record", quarantine=True)
        if v.attempt_entries or v.response_entries:
            return _deny("unresolved_attempt", quarantine=True)
        try:
            control = _control(v.control_bytes)
            witness = _witness(v.witness_bytes)
        except (ValueError, TypeError):
            return _deny("corrupt_record", quarantine=True)
        if (control["namespace_id"] != witness["namespace_id"]
                or control["lineage_generation"] != witness["lineage_generation"]
                or control["state_generation"] != witness["state_generation"]):
            return _deny("lineage_mismatch", quarantine=True)
        if ((control["owner_lock_dev"], control["owner_lock_ino"]) !=
                (v.owner_lock.dev, v.owner_lock.ino)):
            return _deny("owner_lock_unavailable", quarantine=True)
        if control["global_quarantined"]:
            return _deny("cleanup_unknown", quarantine=True)
        if control["consent_active"]:
            return _deny("consent_not_qualified", quarantine=True)
        if control["unresolved_retired_tombstone_count"]:
            return _deny("unresolved_attempt", quarantine=True)
        return N3F0Scan("healthy_metadata_only", "metadata_only_no_exec_proof")
