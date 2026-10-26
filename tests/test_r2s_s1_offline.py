"""R2-S S1: PURE MEMORY fake consent, fencing and outcome schedules.

This is deliberately TEST-ONLY: no imports from gateway/, no real filesystem,
network, subprocess, PID/PGID signals, owner.lock or service admission hooks.
A fake dispatch counter is NOT a Native Runner implementation or OS proof.
The operative R1/F1 WorkspaceService remains default-deny. All tested v2
states are hypothetical predicates from the independently reviewed S0 design.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, dataclass

import pytest


class Denied(RuntimeError):
    """A fake lifecycle operation did not qualify."""


class DurabilityUnavailable(RuntimeError):
    """Injected abstract commit failure, NOT a real fsync experiment."""


@dataclass
class MemoryJournal:
    """Only deep-copied Python dicts; 'fsync' is a deterministic fake switch."""

    snapshot: dict | None = None
    fail_next_commit: bool = False
    commits: int = 0
    unresolved_failed_commit: bool = False

    def commit(self, value: dict) -> None:
        # Separate T0 journal uncertainty marker: survives an OfflineS1 owner
        # restart that shares THIS MemoryJournal object. This is NOT an actual
        # disk-durable fence and cannot qualify a native storage backend.
        if self.fail_next_commit:
            self.fail_next_commit = False
            self.unresolved_failed_commit = True
            raise DurabilityUnavailable("injected fake journal failure")
        if self.unresolved_failed_commit:
            raise DurabilityUnavailable("fake journal has unresolved failed commit")
        self.snapshot = deepcopy(value)
        self.commits += 1

    def read(self) -> dict | None:
        return deepcopy(self.snapshot)


@dataclass(frozen=True)
class Ticket:
    """Test-only identity; deterministic IDs are NOT unforgeable grants."""

    attempt_id: str
    consent_epoch: int
    owner_generation: int
    attempt_generation: int
    root: tuple[int, int]
    exec_scope: str
    backend_version: str


class OfflineS1:
    """Sequential event scheduler, not an executable gateway or real lock.

    A method call is one explicit order point. The fake 'dispatch' only bumps
    a counter. In particular no callback, API or argument launches a process.
    The journal is in-memory: cold_boot() tests conservative predicates, not
    crash-consistent storage or actual macOS process containment.
    """

    def __init__(self, journal: MemoryJournal | None = None, *,
                 max_records: int = 4096):
        self.journal = journal if journal is not None else MemoryJournal()
        if type(max_records) is not int or not 1 <= max_records <= 4096:
            raise ValueError("invalid fake record budget")
        self.max_records = max_records
        self.fake_starts = 0
        self.fake_signals = 0
        previous = self.journal.read()
        if previous is None:
            self.state = self._new_state()
            if self.journal.unresolved_failed_commit:
                self._boot_denied("unresolved-journal-transaction")
        elif not self._compatible_snapshot(previous):
            # Keep the exact suspect bytes in journal.snapshot for forensics;
            # do not parse unknown records as a healthy active grant or
            # overwrite a corrupt snapshot with an empty healthy one.
            self.state = self._new_state()
            self._boot_denied("unsupported-persisted-state")
        else:
            self.state = previous
            self.state["owner_generation"] += 1
            # Every unretired and limited-group-only prior attempt is a
            # conservative T0 boot obstacle. Completed response/slot release
            # never proves an escaped process absent.
            uncertain = {"PREPARED", "STARTING", "RUNNING",
                         "CLEANUP_PENDING", "RETIRED_LIMITED", "UNKNOWN"}
            if any(x["phase"] in uncertain
                   for x in self.state["attempts"].values()):
                self.state["quarantined"] = True
            if self.journal.unresolved_failed_commit:
                self._boot_denied("unresolved-journal-transaction")
            elif self.state["quarantined"]:
                try:
                    self._commit()
                except DurabilityUnavailable:
                    pass  # in-memory unavailable still denies; no positive path

    @staticmethod
    def _new_state() -> dict:
        return {
            "state_schema": 2, "profile": "offline_fake_v2",
            "consent_epoch": 0, "consent_active": False,
            "owner_generation": 1, "next_attempt": 1,
            "root": (101, 202), "exec_scope": "runner-grants-v1",
            "backend_version": "fake-backend-v1", "source_revision": "mutable-a",
            "quarantined": False, "available": True,
            "attempts": {}, "events": [],
        }

    def _boot_denied(self, reason: str) -> None:
        self.state["quarantined"] = True
        self.state["available"] = False
        self.state["events"].append("boot:" + reason)

    @staticmethod
    def _compatible_snapshot(value: object) -> bool:
        """Validate exact S1 fake schema and attribution BEFORE trusting grants.

        No v1 migration, unknown profile, backend version, record shape or
        phase is a valid authority. The fake performs no actual serialization,
        OS liveness observation, cryptographic proof, or storage qualification.
        """
        if type(value) is not dict:
            return False
        expected = {
            "state_schema", "profile", "consent_epoch", "consent_active",
            "owner_generation", "next_attempt", "root", "exec_scope",
            "backend_version", "source_revision", "quarantined", "available",
            "attempts", "events",
        }
        if set(value) != expected:
            return False
        if value["state_schema"] != 2 or value["profile"] != "offline_fake_v2":
            return False
        for key, minimum in (("consent_epoch", 0),
                             ("owner_generation", 1), ("next_attempt", 1)):
            if type(value[key]) is not int or value[key] < minimum:
                return False
        for key in ("consent_active", "quarantined", "available"):
            if type(value[key]) is not bool:
                return False
        root = value["root"]
        if (type(root) is not tuple or len(root) != 2
                or any(type(x) is not int or x <= 0 for x in root)):
            return False
        if (type(value["exec_scope"]) is not str
                or not value["exec_scope"]):
            return False
        if value["backend_version"] != "fake-backend-v1":
            return False
        if (type(value["source_revision"]) is not str
                or not value["source_revision"]):
            return False
        if (type(value["events"]) is not list
                or not all(type(x) is str for x in value["events"])):
            return False
        records = value["attempts"]
        if type(records) is not dict or len(records) > 4096:
            return False
        ticket_keys = set(Ticket.__dataclass_fields__)
        record_keys = {
            "ticket", "phase", "fake_dispatches", "cleanup_scope",
            "full_tree_clean", "was_limited", "delivery_committed",
            "delivery_ack", "late_positive",
        }
        phases = {
            "PREPARED", "STARTING", "RUNNING", "CLEANUP_PENDING",
            "RETIRED_LIMITED", "UNKNOWN",
        }
        for attempt_id, item in records.items():
            if (type(attempt_id) is not str or len(attempt_id) != 32
                    or any(c not in "0123456789abcdef" for c in attempt_id)
                    or type(item) is not dict or set(item) != record_keys
                    or item["phase"] not in phases):
                return False
            t = item["ticket"]
            if type(t) is not dict or set(t) != ticket_keys:
                return False
            if t["attempt_id"] != attempt_id:
                return False
            if (type(t["consent_epoch"]) is not int
                    or not 0 <= t["consent_epoch"] <= value["consent_epoch"]):
                return False
            if (type(t["owner_generation"]) is not int
                    or not 1 <= t["owner_generation"] <= value["owner_generation"]):
                return False
            if (type(t["attempt_generation"]) is not int
                    or not 1 <= t["attempt_generation"] < value["next_attempt"]
                    or int(attempt_id, 16) != t["attempt_generation"]):
                return False
            tr = t["root"]
            if (type(tr) is not tuple or len(tr) != 2
                    or any(type(x) is not int or x <= 0 for x in tr)):
                return False
            if (type(t["exec_scope"]) is not str or not t["exec_scope"]
                    or type(t["backend_version"]) is not str
                    or not t["backend_version"]):
                return False
            if (type(item["fake_dispatches"]) is not int
                    or not 0 <= item["fake_dispatches"] <= 1
                    or item["cleanup_scope"] not in
                    ("none", "original_group_only")
                    or item["full_tree_clean"] != "not_proven"):
                return False
            if (type(item["was_limited"]) is not bool
                    or type(item["late_positive"]) is not bool
                    or item["delivery_committed"] not in
                    (None, "limited", "quarantined")
                    or item["delivery_ack"] not in (None, True, False)):
                return False
            if (item["phase"] == "PREPARED"
                    and item["fake_dispatches"] != 0):
                return False
        return True

    @property
    def quarantined(self) -> bool:
        return self.state["quarantined"] or not self.state["available"]

    def _commit(self) -> None:
        try:
            self.journal.commit(self.state)
        except DurabilityUnavailable:
            self.state["available"] = False
            self.state["quarantined"] = True
            raise

    def _admissible(self) -> None:
        if self.quarantined:
            raise Denied("fake global Exec quarantined/unavailable")
        if not self.state["consent_active"]:
            raise Denied("no local operator consent")
        if len(self.state["attempts"]) >= self.max_records:
            self.state["quarantined"] = True
            self.state["events"].append("quota:do-not-evict")
            self._commit()
            raise Denied("fake forensic record budget exhausted")

    def approve_local(self) -> int:
        """An explicit *test-only* local operation; never public API consent."""
        if self.quarantined:
            raise Denied("fake quarantine cannot be cleared by reapproval")
        self.state["consent_epoch"] += 1
        self.state["consent_active"] = True
        # A new local approval epoch is NEVER a free pass to finalize a
        # command already issued under the old one. Fence any in-flight
        # PREPARED/STARTING/RUNNING work before accepting the new epoch.
        for record in self.state["attempts"].values():
            if record["phase"] in ("PREPARED", "STARTING", "RUNNING",
                                   "CLEANUP_PENDING"):
                record["phase"] = "UNKNOWN"
                self.state["quarantined"] = True
        self._commit()
        return self.state["consent_epoch"]

    def revoke_local(self) -> None:
        self.state["consent_epoch"] += 1
        self.state["consent_active"] = False
        for record in self.state["attempts"].values():
            if record["phase"] in ("PREPARED", "STARTING", "RUNNING",
                                   "CLEANUP_PENDING"):
                record["phase"] = "UNKNOWN"
                self.state["quarantined"] = True
        self._commit()

    def edit_workspace(self, new_revision: str) -> None:
        """A normal mutable source/Git/Pipenv change is NOT a consent epoch."""
        self.state["source_revision"] = new_revision
        self._commit()

    def change_binding(self, *, root: tuple[int, int] | None = None,
                       exec_scope: str | None = None,
                       backend_version: str | None = None) -> None:
        changes = {
            "root": root, "exec_scope": exec_scope,
            "backend_version": backend_version,
        }
        actually_changed = False
        for key, value in changes.items():
            if value is not None and self.state[key] != value:
                self.state[key] = value
                actually_changed = True
        if actually_changed:
            self.revoke_local()

    def prepare(self) -> Ticket:
        self._admissible()
        number = self.state["next_attempt"]
        ticket = Ticket(
            attempt_id=f"{number:032x}",
            consent_epoch=self.state["consent_epoch"],
            owner_generation=self.state["owner_generation"],
            attempt_generation=number,
            root=self.state["root"],
            exec_scope=self.state["exec_scope"],
            backend_version=self.state["backend_version"],
        )
        self.state["next_attempt"] += 1
        self.state["attempts"][ticket.attempt_id] = {
            "ticket": asdict(ticket),
            "phase": "PREPARED",
            "fake_dispatches": 0,
            "cleanup_scope": "none",
            "full_tree_clean": "not_proven",
            "was_limited": False,
            "delivery_committed": None,
            "delivery_ack": None,
            "late_positive": False,
        }
        self._commit()  # abstract PREPARED-before-any-fake-dispatch
        return ticket

    def _checked(self, ticket: Ticket) -> dict:
        if type(ticket) is not Ticket:
            raise Denied("not a typed fake attempt")
        record = self.state["attempts"].get(ticket.attempt_id)
        if record is None or record["ticket"] != asdict(ticket):
            raise Denied("stale or forged fake attempt identity")
        if ticket.owner_generation != self.state["owner_generation"]:
            raise Denied("stale service owner callback")
        return record

    def dispatch(self, ticket: Ticket, *, lose_ack: bool = False) -> None:
        """FAKE first irreversible dispatch = increment an integer, NEVER Popen."""
        record = self._checked(ticket)
        if record["phase"] != "PREPARED":
            raise Denied("fake start_once cannot be replayed")
        expected = (ticket.consent_epoch == self.state["consent_epoch"]
                    and self.state["consent_active"]
                    and ticket.root == self.state["root"]
                    and ticket.exec_scope == self.state["exec_scope"]
                    and ticket.backend_version == self.state["backend_version"])
        if self.quarantined or not expected:
            record["phase"] = "UNKNOWN"
            self.state["quarantined"] = True
            self._commit()
            raise Denied("revoked/changed consent before first fake start")
        record["phase"] = "STARTING"
        self._commit()  # abstract intent write must succeed before dispatch
        record["fake_dispatches"] += 1
        self.fake_starts += 1
        if not lose_ack:
            record["phase"] = "RUNNING"
        self._commit()

    def reconcile_uncertain(self, ticket: Ticket) -> None:
        record = self._checked(ticket)
        if record["phase"] in ("STARTING", "RUNNING"):
            record["phase"] = "UNKNOWN"
            self.state["quarantined"] = True
            self._commit()

    def retire_limited(self, ticket: Ticket, *, fake_leader_reaped: bool,
                       fake_group_absent: bool) -> None:
        """Hypothetical group-only outcome, never a full-descendant proof."""
        record = self._checked(ticket)
        still_authorized = (
            ticket.consent_epoch == self.state["consent_epoch"]
            and self.state["consent_active"]
            and ticket.root == self.state["root"]
            and ticket.exec_scope == self.state["exec_scope"]
            and ticket.backend_version == self.state["backend_version"]
        )
        if not still_authorized:
            record["phase"] = "UNKNOWN"
            self.state["quarantined"] = True
            self._commit()
            raise Denied("stale consent at fake cleanup finalization")
        if record["phase"] != "RUNNING" or not (
                fake_leader_reaped and fake_group_absent) or self.quarantined:
            raise Denied("no qualified fake limited retirement")
        record["phase"] = "RETIRED_LIMITED"
        record["was_limited"] = True
        record["cleanup_scope"] = "original_group_only"
        record["full_tree_clean"] = "not_proven"
        self._commit()

    def commit_delivery(self, ticket: Ticket, *, ack: bool | None = True) -> str:
        """Transport commitment is distinct from earlier command/cleanup."""
        record = self._checked(ticket)
        status = ("limited" if record["phase"] == "RETIRED_LIMITED"
                  and not self.quarantined else "quarantined")
        if record["delivery_committed"] is not None:
            # A committed reply cannot be erased by late evidence or replayed.
            return record["delivery_committed"]
        record["delivery_committed"] = status
        record["delivery_ack"] = ack
        self._commit()
        return status

    def late_positive_survivor(self, attempt_id: str) -> None:
        """Synthetic authenticated observer event, not a real OS probe."""
        self.state["quarantined"] = True
        record = self.state["attempts"].get(attempt_id)
        if record is None:
            self.state["events"].append("orphan:unknown-attribution")
        elif not record["late_positive"]:
            record["late_positive"] = True
            record["phase"] = "UNKNOWN"  # prior limited evidence retained
            self.state["events"].append("survivor:" + attempt_id)
        for other in self.state["attempts"].values():
            if other["phase"] in ("PREPARED", "STARTING", "RUNNING",
                                  "CLEANUP_PENDING"):
                other["phase"] = "UNKNOWN"
        self._commit()  # failure => unavailable; reboot must not trust limited

    def state_of(self, ticket: Ticket) -> dict:
        return deepcopy(self.state["attempts"][ticket.attempt_id])


@pytest.fixture
def fake() -> OfflineS1:
    instance = OfflineS1()
    assert instance.approve_local() == 1
    return instance


def _limited(fake: OfflineS1) -> Ticket:
    a = fake.prepare()
    fake.dispatch(a)
    fake.retire_limited(a, fake_leader_reaped=True, fake_group_absent=True)
    assert fake.state_of(a)["full_tree_clean"] == "not_proven"
    return a


def test_t0_rev_01_revoke_before_prepare_zero_fake_starts(fake):
    fake.revoke_local()
    with pytest.raises(Denied, match="no local"):
        fake.prepare()
    assert fake.fake_starts == 0
    assert not fake.state["attempts"]


def test_t0_rev_02_prepared_then_revoke_no_grandfathered_start(fake):
    a = fake.prepare()
    assert fake.state_of(a)["phase"] == "PREPARED"
    fake.revoke_local()
    with pytest.raises(Denied):
        fake.dispatch(a)
    assert fake.fake_starts == 0
    assert fake.state_of(a)["phase"] == "UNKNOWN"
    assert fake.quarantined


def test_t0_rev_03_dispatch_first_then_revoke_lost_ack_never_replays(fake):
    a = fake.prepare()
    fake.dispatch(a, lose_ack=True)
    assert fake.state_of(a)["phase"] == "STARTING"
    fake.revoke_local()
    assert fake.state_of(a)["phase"] == "UNKNOWN"
    with pytest.raises(Denied):
        fake.dispatch(a)
    assert fake.fake_starts == 1
    with pytest.raises(Denied):
        fake.prepare()


def test_t0_rev_04_three_epochs_and_clean_restart(fake):
    epoch = fake.state["consent_epoch"]
    old_owner = fake.state["owner_generation"]
    restarted = OfflineS1(fake.journal)
    assert restarted.state["consent_epoch"] == epoch
    assert restarted.state["owner_generation"] == old_owner + 1
    assert not restarted.quarantined
    a = restarted.prepare()
    stale = Ticket(a.attempt_id, a.consent_epoch, old_owner,
                   a.attempt_generation, a.root, a.exec_scope,
                   a.backend_version)
    with pytest.raises(Denied, match="stale"):
        restarted.dispatch(stale)
    assert restarted.fake_starts == 0
    restarted.dispatch(a)
    assert restarted.fake_starts == 1
    with pytest.raises(Denied, match="replayed"):
        restarted.dispatch(a)


def test_t0_rev_05_mutable_workspace_change_not_backend_version_pin(fake):
    epoch = fake.state["consent_epoch"]
    fake.edit_workspace("changed-git-head-and-pipenv")
    assert fake.state["consent_epoch"] == epoch
    a = fake.prepare()
    fake.dispatch(a)
    assert fake.fake_starts == 1

    clean = OfflineS1()
    clean.approve_local()
    clean.change_binding(backend_version="fake-backend-v2")
    assert not clean.state["consent_active"]
    with pytest.raises(Denied, match="no local"):
        clean.prepare()


def test_t0_late_01_after_delivery_and_b_prepared_never_starts_b(fake):
    a = _limited(fake)
    assert fake.commit_delivery(a, ack=True) == "limited"
    b = fake.prepare()
    fake.late_positive_survivor(a.attempt_id)
    assert fake.state_of(a)["was_limited"] is True
    assert fake.state_of(a)["phase"] == "UNKNOWN"
    assert fake.state_of(a)["delivery_committed"] == "limited"
    assert fake.state_of(b)["phase"] == "UNKNOWN"
    with pytest.raises(Denied):
        fake.dispatch(b)
    assert fake.fake_starts == 1
    assert fake.quarantined


def test_t0_late_02_b_dispatch_first_while_late_event_pending(fake):
    a = _limited(fake)
    b = fake.prepare()
    fake.dispatch(b, lose_ack=True)
    fake.late_positive_survivor(a.attempt_id)
    assert fake.fake_starts == 2  # A and the already issued fake B
    assert fake.state_of(b)["phase"] == "UNKNOWN"
    with pytest.raises(Denied):
        fake.dispatch(b)
    with pytest.raises(Denied):
        fake.prepare()


def test_t0_late_03_fsync_failure_crash_and_fresh_boot_fail_closed(fake):
    a = _limited(fake)
    fake.journal.fail_next_commit = True
    with pytest.raises(DurabilityUnavailable):
        fake.late_positive_survivor(a.attempt_id)
    assert fake.quarantined
    assert fake.journal.snapshot["attempts"][a.attempt_id]["phase"] == "RETIRED_LIMITED"
    cold_boot = OfflineS1(fake.journal)
    assert cold_boot.quarantined  # no reliance on lost in-memory late latch
    assert cold_boot.state_of(a)["phase"] == "RETIRED_LIMITED"
    with pytest.raises(Denied):
        cold_boot.prepare()


def test_p3_response_not_committed_when_late_latch_wins(fake):
    a = _limited(fake)
    fake.late_positive_survivor(a.attempt_id)
    assert fake.commit_delivery(a) == "quarantined"
    assert fake.quarantined


def test_p3_prior_committed_delivery_is_historical_not_retracted(fake):
    a = _limited(fake)
    assert fake.commit_delivery(a, ack=None) == "limited"
    fake.late_positive_survivor(a.attempt_id)
    assert fake.state_of(a)["delivery_committed"] == "limited"
    assert fake.state_of(a)["delivery_ack"] is None
    assert fake.commit_delivery(a) == "limited"  # not an instruction to resend
    assert fake.quarantined


def test_boundary_duplicate_late_event_is_idempotent(fake):
    a = _limited(fake)
    fake.late_positive_survivor(a.attempt_id)
    before = list(fake.state["events"])
    fake.late_positive_survivor(a.attempt_id)
    assert fake.state["events"] == before
    assert fake.quarantined
    assert fake.fake_signals == 0


def test_boundary_orphan_event_and_quota_do_not_gc(fake):
    fake.late_positive_survivor("f" * 32)
    assert "orphan:unknown-attribution" in fake.state["events"]
    with pytest.raises(Denied):
        fake.prepare()

    full = OfflineS1(max_records=1)
    full.approve_local()
    a = _limited(full)
    with pytest.raises(Denied, match="budget"):
        full.prepare()
    assert a.attempt_id in full.state["attempts"]
    assert full.state_of(a)["phase"] == "RETIRED_LIMITED"
    assert full.quarantined


def test_boundary_failed_prepared_write_never_dispatches(fake):
    fake.journal.fail_next_commit = True
    with pytest.raises(DurabilityUnavailable):
        fake.prepare()
    assert fake.fake_starts == 0
    assert fake.quarantined
    with pytest.raises(Denied):
        fake.prepare()


def test_boundary_v1_retired_never_auto_upgrades_to_native():
    journal = MemoryJournal(snapshot={
        "consent_epoch": 0, "consent_active": False,
        "owner_generation": 1, "next_attempt": 2,
        "root": (101, 202), "exec_scope": "runner-grants-v1",
        "backend_version": "fake-backend-v1", "source_revision": "x",
        "quarantined": False, "available": True, "events": [],
        "attempts": {"1" * 32: {
            "ticket": {"attempt_id": "1" * 32}, "phase": "RETIRED",
            "cleanup_scope": "original_group_only",
        }},
    })
    # A historical v1 group-only RETIRED is NOT a safe v2 boot marker.
    old = OfflineS1(journal)
    assert old.quarantined
    assert not old.state["consent_active"]
    with pytest.raises(Denied):
        old.prepare()


def test_negative_no_production_backend_or_real_os_side_effects():
    # Deliberately no dependency on the gateway package or host process API.
    import ast
    from pathlib import Path

    node = ast.parse(Path(__file__).read_text(encoding="utf-8"))
    imports = [
        name.name for item in ast.walk(node) if isinstance(item, ast.Import)
        for name in item.names
    ]
    assert "subprocess" not in imports
    assert "socket" not in imports
    assert "gateway" not in imports
    assert "os" not in imports
    pure = OfflineS1()
    with pytest.raises(Denied, match="no local"):
        pure.prepare()
    with pytest.raises(TypeError):
        pure.dispatch(profile="native_limited", proof=True)
    assert pure.fake_starts == 0
    assert pure.fake_signals == 0


# r002 B/C independently derived counterexamples. Append tests first to obtain
# original RED on old S1 model before making the implementation safe.
def test_b85_p2_01_foreign_phase_boot_blocks_consent(fake):
    a = _limited(fake)
    snap = fake.journal.read()
    snap["attempts"][a.attempt_id]["phase"] = "FOREIGN_PHASE"
    fake.journal.commit(snap)
    boot = OfflineS1(fake.journal)
    assert boot.quarantined
    assert boot.fake_starts == 0
    with pytest.raises(Denied):
        boot.prepare()


@pytest.mark.parametrize(
    ("field", "invalid"), [
        ("state_schema", 999),
        ("state_schema", None),
        ("profile", "strict_f3"),
        ("backend_version", "unsupported-fake-backend"),
    ],
)
def test_b85_p2_01_unknown_version_profile_backend_boot_blocks(fake, field, invalid):
    snap = fake.journal.read()  # a valid, active consent, no running attempt
    if invalid is None:
        snap.pop(field, None)
    else:
        snap[field] = invalid
    fake.journal.commit(snap)
    boot = OfflineS1(fake.journal)
    assert boot.quarantined
    assert boot.fake_starts == 0
    with pytest.raises(Denied):
        boot.prepare()


def test_b85_p2_01_missing_record_fields_cold_boot_is_safe(fake):
    snap = fake.journal.read()
    snap["attempts"]["1" * 32] = {"ticket": {"attempt_id": "1" * 32}}
    fake.journal.commit(snap)
    boot = OfflineS1(fake.journal)
    assert boot.quarantined
    with pytest.raises(Denied):
        boot.prepare()


def test_b85_p2_02_failed_revoke_commit_then_empty_boot_never_rearms(fake):
    initial = fake.journal.read()
    assert initial["consent_active"] and not initial["attempts"]
    fake.journal.fail_next_commit = True
    with pytest.raises(DurabilityUnavailable):
        fake.revoke_local()
    assert fake.quarantined
    assert fake.journal.snapshot == initial  # failed commit left older consent
    reboot = OfflineS1(fake.journal)
    assert reboot.quarantined
    assert reboot.fake_starts == 0
    with pytest.raises(Denied):
        reboot.prepare()


def test_b85_p2_02_failed_binding_revoke_then_boot_stays_closed(fake):
    fake.journal.fail_next_commit = True
    with pytest.raises(DurabilityUnavailable):
        fake.change_binding(root=(403, 404))
    reboot = OfflineS1(fake.journal)
    assert reboot.quarantined
    with pytest.raises(Denied):
        reboot.prepare()
    assert reboot.fake_starts == 0


def test_c85_p2_reissue_during_running_fences_old_finalization(fake):
    a = fake.prepare()
    fake.dispatch(a)
    assert fake.state_of(a)["phase"] == "RUNNING"
    assert fake.approve_local() == 2  # a new consent epoch is not A's grant
    with pytest.raises(Denied):
        fake.retire_limited(a, fake_leader_reaped=True, fake_group_absent=True)
    assert fake.state_of(a)["phase"] == "UNKNOWN"
    assert fake.quarantined
    assert fake.commit_delivery(a) == "quarantined"
    assert fake.state_of(a)["full_tree_clean"] == "not_proven"
    assert fake.fake_starts == 1


def test_c85_p2_valid_same_epoch_retirement_remains_legal(fake):
    a = _limited(fake)
    assert fake.state_of(a)["phase"] == "RETIRED_LIMITED"
    assert fake.state_of(a)["full_tree_clean"] == "not_proven"
    assert fake.commit_delivery(a) == "limited"
    assert not fake.quarantined


def test_c85_p2_late02_restarts_owner_before_old_a_observer(fake):
    a = _limited(fake)
    assert fake.commit_delivery(a, ack=True) == "limited"
    b = fake.prepare()
    fake.dispatch(b, lose_ack=True)
    old_owner = fake.state["owner_generation"]
    assert fake.fake_starts == 2  # A and B dispatched BEFORE restart
    reboot = OfflineS1(fake.journal)
    assert reboot.state["owner_generation"] == old_owner + 1
    assert reboot.quarantined  # unretired B and limited A are uncertain
    with pytest.raises(Denied, match="stale"):
        reboot.dispatch(b)
    reboot.late_positive_survivor(a.attempt_id)  # trusted synthetic observer
    assert reboot.state_of(a)["phase"] == "UNKNOWN"
    assert reboot.state_of(a)["delivery_committed"] == "limited"
    assert reboot.state_of(b)["phase"] == "UNKNOWN"
    assert reboot.fake_starts == 0  # never attribute preboot B as fresh launch
    assert reboot.fake_signals == 0
    with pytest.raises(Denied):
        reboot.prepare()


def test_b85_p2_01_legal_clean_consent_boot_still_dispatches(fake):
    before_epoch = fake.state["consent_epoch"]
    reboot = OfflineS1(fake.journal)
    assert not reboot.quarantined
    assert reboot.state["consent_epoch"] == before_epoch
    a = reboot.prepare()
    reboot.dispatch(a)
    assert reboot.fake_starts == 1


# r003 NEW source-level B/C counterexamples; test-first RED on the r002 model.
# No external processes, locks, signals, filesystem or product imports.
@pytest.mark.parametrize(
    ("binding", "value"), [
        ("backend_version", "unsupported-fake-backend"),
        ("root", (0, 0)),
        ("root", ("0", 2)),
        ("exec_scope", ""),
    ],
)
def test_r003_unsupported_live_binding_reapproval_fails_closed(fake, binding, value):
    with pytest.raises(Denied):
        fake.change_binding(**{binding: value})
    assert fake.fake_starts == 0
    assert fake.quarantined
    with pytest.raises(Denied):
        fake.approve_local()
    with pytest.raises(Denied):
        fake.prepare()


@pytest.mark.parametrize(
    ("binding", "value"), [
        ("backend_version", "unsupported-fake-backend"),
        ("root", (0, 0)),
        ("exec_scope", ""),
    ],
)
def test_r003_invalid_mutated_live_binding_denies_prepare(fake, binding, value):
    fake.state[binding] = value
    with pytest.raises(Denied):
        fake.prepare()
    assert fake.fake_starts == 0
    assert fake.quarantined


def test_r003_valid_new_root_local_reapproval_allows_exactly_one_fake_start(fake):
    previous_epoch = fake.state["consent_epoch"]
    fake.change_binding(root=(707, 808))
    assert not fake.state["consent_active"]
    assert not fake.quarantined
    assert fake.approve_local() == previous_epoch + 2  # revoke and new grant
    a = fake.prepare()
    assert a.root == (707, 808)
    fake.dispatch(a)
    assert fake.fake_starts == 1
    with pytest.raises(Denied):
        fake.dispatch(a)


@pytest.mark.parametrize(
    ("leader", "group"), [
        ("false", "false"),
        (1, 1),
        (True, "true"),
        (None, True),
        (False, True),
        (True, False),
        (True, None),
        ([True], True),
    ],
)
def test_r003_untrusted_cleanup_evidence_cannot_retire_limited(fake, leader, group):
    a = fake.prepare()
    fake.dispatch(a)
    with pytest.raises(Denied):
        fake.retire_limited(
            a, fake_leader_reaped=leader, fake_group_absent=group,
        )
    assert fake.state_of(a)["phase"] == "UNKNOWN"
    assert fake.state_of(a)["full_tree_clean"] == "not_proven"
    assert fake.commit_delivery(a) == "quarantined"
    assert fake.quarantined
    assert fake.fake_starts == 1


def test_r003_zero_epoch_copied_active_consent_cannot_start():
    journal = MemoryJournal()
    bogus = OfflineS1._new_state()
    bogus["consent_active"] = True
    assert bogus["consent_epoch"] == 0
    journal.commit(bogus)
    boot = OfflineS1(journal)
    assert boot.quarantined
    assert not boot.state["available"]
    assert journal.snapshot == bogus  # retain suspect snapshot as evidence
    with pytest.raises(Denied):
        boot.prepare()
    assert boot.fake_starts == 0


@pytest.mark.parametrize("bad_schema", [2.0, "2", True])
def test_r003_non_integer_schema_never_accepted_as_version_two(bad_schema):
    journal = MemoryJournal()
    source = OfflineS1._new_state()
    source["state_schema"] = bad_schema
    source["consent_active"] = True
    source["consent_epoch"] = 1
    journal.commit(source)
    boot = OfflineS1(journal)
    assert boot.quarantined
    with pytest.raises(Denied):
        boot.prepare()


@pytest.mark.parametrize("bad_phase", [[], {"stage": "RUNNING"}])
def test_r003_unhashable_phase_is_conservative_boot_not_exception(fake, bad_phase):
    a = _limited(fake)
    snapshot = fake.journal.read()
    snapshot["attempts"][a.attempt_id]["phase"] = bad_phase
    fake.journal.commit(snapshot)
    boot = OfflineS1(fake.journal)
    assert boot.quarantined
    assert not boot.state["available"]
    assert fake.journal.snapshot == snapshot  # no forced forensic rewrite
    with pytest.raises(Denied):
        boot.prepare()


def test_r003_two_clean_restarts_have_distinct_persisted_owner_epochs(fake):
    before = fake.state["owner_generation"]
    boot_one = OfflineS1(fake.journal)
    boot_two = OfflineS1(fake.journal)
    assert not boot_one.quarantined
    assert not boot_two.quarantined
    assert boot_one.state["owner_generation"] == before + 1
    assert boot_two.state["owner_generation"] == before + 2
    assert fake.journal.read()["owner_generation"] == before + 2
    a = boot_two.prepare()
    boot_two.dispatch(a)
    assert boot_two.fake_starts == 1


def test_r003_clean_boot_owner_epoch_commit_failure_denies(fake):
    fake.journal.fail_next_commit = True
    boot = OfflineS1(fake.journal)
    assert boot.quarantined
    assert fake.journal.unresolved_failed_commit
    with pytest.raises(Denied):
        boot.prepare()
    second_boot = OfflineS1(fake.journal)
    assert second_boot.quarantined
    with pytest.raises(Denied):
        second_boot.prepare()


def test_r003_same_epoch_true_booleans_remain_limited_not_full(fake):
    a = fake.prepare()
    fake.dispatch(a)
    fake.retire_limited(a, fake_leader_reaped=True, fake_group_absent=True)
    assert fake.state_of(a)["phase"] == "RETIRED_LIMITED"
    assert fake.state_of(a)["full_tree_clean"] == "not_proven"
    assert fake.commit_delivery(a) == "limited"
    assert not fake.quarantined
