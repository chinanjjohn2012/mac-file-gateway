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

    def commit(self, value: dict) -> None:
        if self.fail_next_commit:
            self.fail_next_commit = False
            raise DurabilityUnavailable("injected fake journal failure")
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
            self.state = {
                "consent_epoch": 0,
                "consent_active": False,
                "owner_generation": 1,
                "next_attempt": 1,
                "root": (101, 202),
                "exec_scope": "runner-grants-v1",
                "backend_version": "fake-backend-v1",
                "source_revision": "mutable-a",
                "quarantined": False,
                "available": True,
                "attempts": {},
                "events": [],
            }
        else:
            self.state = previous
            self.state["owner_generation"] += 1
            # An old group-limited result cannot become a new-boot proof of
            # no escaped descendants. This is a deliberately conservative
            # proposed S1 boot gate, NOT an implemented production mechanism.
            uncertain = {"PREPARED", "STARTING", "RUNNING",
                         "CLEANUP_PENDING", "RETIRED_LIMITED", "UNKNOWN",
                         "RETIRED"}  # v1 group-only result cannot authorize v2
            if any(x["phase"] in uncertain
                   for x in self.state["attempts"].values()):
                self.state["quarantined"] = True
            if self.state["quarantined"]:
                try:
                    self._commit()
                except DurabilityUnavailable:
                    pass  # in-memory unavailable still denies; no positive path

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
