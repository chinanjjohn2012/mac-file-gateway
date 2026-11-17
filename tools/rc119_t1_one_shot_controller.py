"""RC119 one-shot T1 controller STATE-MACHINE CANDIDATE, SAFE T0 ONLY.

This module intentionally has NO external Owner authentication, GitHub event
verification, cross-runner durable lease, host qualification, package installer,
network access, subprocess/Popen or native execution adapter. SQLite here is a
*local* disposable test ledger, NOT evidence of cross-VM exclusivity.
All transitions, including a full synthetic SIX->MIXED trace, explicitly
return native_execution_authorized=False. Never call this a T1 permit.
"""
from __future__ import annotations

import hashlib
import json
from contextlib import closing
import re
import sqlite3
from pathlib import Path
from typing import Any

REPO = "chinanjjohn2012/mac-file-gateway"
RC_PR = 119
RC_HEAD = "33c30b6c2710cac0f8533370c1ca42f31ef6747a"
RC_TREE = "27e26c423e700cdbad0aeca27efcdf82594507c1"
PROFILE_B_BLOB = "1df5ccf9dbf920ff243e04d0e57f45a82e1b2a13"
OWNER = "chinanjjohn2012"
NATIVE_EXECUTION_ENABLED = False
AUTHORITY_GRADE = "SYNTHETIC_T0_UNAUTHENTICATED"
SOURCE_GRADE = "NOT_ATTESTED"
HOST_GRADE = "NOT_QUALIFIED"
_SHA40 = re.compile(r"[0-9a-f]{40}\Z")
_SHA64 = re.compile(r"[0-9a-f]{64}\Z")
_FIELDS = frozenset({
    "schema_version", "repo", "product_pr", "product_head", "product_tree",
    "profile_blob", "control_head", "control_tree", "input_lock_sha256",
    "actor", "event_name", "run_id", "run_attempt", "nonce_sha256",
    "checked_at", "expires_at", "authority_grade", "source_grade", "host_grade",
})
_STATES = frozenset({
    "SIX_RESERVED", "SIX_CONSUMED", "SIX_PASSED", "MIXED_CONSUMED",
    "MIXED_FINALIZED", "FAILED", "REVOKED", "EXPIRED", "UNKNOWN",
})
_TRANSITIONS = {
    "START_SIX": ("SIX_RESERVED", "SIX_CONSUMED"),
    "COMPLETE_SIX": ("SIX_CONSUMED", "SIX_PASSED"),
    "START_MIXED": ("SIX_PASSED", "MIXED_CONSUMED"),
    "COMPLETE_MIXED": ("MIXED_CONSUMED", "MIXED_FINALIZED"),
}


class ControllerDenied(ValueError):
    """A rejected T0 claim or transition, never a runtime grant."""


def _hex(v: object, pattern: re.Pattern[str]) -> bool:
    return type(v) is str and pattern.fullmatch(v) is not None


def _int(v: object, low: int, high: int) -> bool:
    return type(v) is int and low <= v <= high


def _canonical(obj: dict[str, Any]) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def validate_synthetic_claim(claim: object, *, now: int, require_fresh: bool = True) -> str:
    """Return an exact identity fingerprint, NOT an Owner approval signature."""
    if type(claim) is not dict or set(claim) != _FIELDS:
        raise ControllerDenied("INVALID_OR_EXTRA_FIELDS")
    required = {
        "schema_version": 1, "repo": REPO, "product_pr": RC_PR,
        "product_head": RC_HEAD, "product_tree": RC_TREE,
        "profile_blob": PROFILE_B_BLOB, "actor": OWNER,
        "event_name": "workflow_dispatch", "run_attempt": 1,
        "authority_grade": AUTHORITY_GRADE,
        "source_grade": SOURCE_GRADE, "host_grade": HOST_GRADE,
    }
    for k, v in required.items():
        if type(claim[k]) is not type(v) or claim[k] != v:
            raise ControllerDenied("IDENTITY_OR_AUTHORITY_MISMATCH:" + k)
    if not _hex(claim["control_head"], _SHA40) or not _hex(claim["control_tree"], _SHA40):
        raise ControllerDenied("UNBOUND_CONTROL_SOURCE")
    if not _hex(claim["nonce_sha256"], _SHA64) or not _hex(claim["input_lock_sha256"], _SHA64):
        raise ControllerDenied("UNBOUND_NONCE_OR_INPUT_LOCK")
    if not _int(claim["run_id"], 1, 2**63 - 1):
        raise ControllerDenied("INVALID_RUN_ID")
    if not _int(now, 0, 2**63 - 1) or not _int(claim["checked_at"], 0, 2**63-1) or not _int(claim["expires_at"], 0, 2**63 - 1):
        raise ControllerDenied("INVALID_TIME")
    if require_fresh and abs(claim["checked_at"] - now) > 120:
        raise ControllerDenied("STALE_CLAIM_CHECK_TIME")
    if not claim["checked_at"] < claim["expires_at"] <= claim["checked_at"] + 2 * 3600:
        raise ControllerDenied("EXPIRED_OR_EXCESS_LIFETIME")
    if require_fresh and now >= claim["expires_at"]:
        raise ControllerDenied("RUN_ALREADY_EXPIRED")
    return hashlib.sha256(_canonical(claim).encode("utf-8")).hexdigest()


def _view(state: str) -> dict[str, object]:
    return {
        "t0_state": state,
        "native_execution_authorized": False,
        "authentic_owner_event_attested": False,
        "cross_runner_lease_qualified": False,
        "selected_native_source_attested": False,
        "host_no_accessible_secrets_attested": False,
        "grade": "LOCAL_SQLITE_SIMULATION_ONLY",
    }


class LocalT0Controller:
    """SQLite simulated state, atomic only among clients of ONE local db file.

    Each private SQLite file admits at most ONE synthetic run for its whole
    lifetime, including after finalization, revocation, UNKNOWN or expiry.
    That is a conservative local no-rearm oracle, not a global runner lease.
    Caller must use a private synthetic path. This is NOT approved for GitHub
    workflows, shared runners, production, or actual original-child execution.
    """

    def __init__(self, db_file: Path) -> None:
        self.db_file = Path(db_file)
        if self.db_file.is_symlink():
            raise ControllerDenied("SYMLINK_DATABASE_DENIED")
        with closing(self._db()) as conn:
            conn.execute("""CREATE TABLE IF NOT EXISTS attempts (
                run_id INTEGER PRIMARY KEY, nonce_sha256 TEXT UNIQUE NOT NULL,
                fingerprint TEXT NOT NULL, expires_at INTEGER NOT NULL,
                state TEXT NOT NULL, six_receipt_sha256 TEXT,
                mixed_receipt_sha256 TEXT
            )""")

    def _db(self) -> sqlite3.Connection:
        # Local synthetic path only. Recheck obvious symlink replacement;
        # this still DOES NOT close a concurrent pathname/SQLite open race.
        if self.db_file.is_symlink():
            raise ControllerDenied("SYMLINK_DATABASE_DENIED")
        # No immutable auth data, tokens or actual foreign sources are stored.
        db = sqlite3.connect(self.db_file, timeout=2.0, isolation_level=None)
        db.execute("PRAGMA busy_timeout=2000")
        return db

    def reserve(self, claim: object, *, now: int) -> dict[str, object]:
        fp = validate_synthetic_claim(claim, now=now)
        assert isinstance(claim, dict)
        try:
            with closing(self._db()) as conn:
                conn.execute("BEGIN IMMEDIATE")
                # One disposable ledger represents exactly ONE attempt, forever.
                # Do not infer process cleanup from FINALIZED/EXPIRED/FAILED.
                # BEGIN IMMEDIATE serializes competing clients of THIS ONE file.
                if conn.execute("SELECT 1 FROM attempts LIMIT 1").fetchone():
                    raise ControllerDenied("DUPLICATE_OR_PRIVATE_LEDGER_ALREADY_USED")
                conn.execute("""INSERT INTO attempts
                    (run_id, nonce_sha256, fingerprint, expires_at, state)
                    VALUES(?,?,?,?,?)""", (
                    claim["run_id"], claim["nonce_sha256"], fp,
                    claim["expires_at"], "SIX_RESERVED"))
                conn.execute("COMMIT")
        except sqlite3.Error as exc:
            raise ControllerDenied("DUPLICATE_OR_LEDGER_UNAVAILABLE") from exc
        return _view("SIX_RESERVED")

    def state(self, *, run_id: int, claim: object, now: int) -> dict[str, object]:
        fp = validate_synthetic_claim(claim, now=now, require_fresh=False)
        if not _int(run_id, 1, 2**63 - 1) or run_id != claim["run_id"]:
            raise ControllerDenied("RUN_ID_MISMATCH")
        try:
            with closing(self._db()) as conn:
                conn.execute("BEGIN IMMEDIATE")
                row = conn.execute("""SELECT fingerprint,expires_at,state FROM attempts
                                         WHERE run_id=?""", (run_id,)).fetchone()
                if row is None or row[0] != fp:
                    raise ControllerDenied("UNKNOWN_OR_CHANGED_RUN_BINDING")
                if row[1] <= now and row[2] not in ("EXPIRED", "REVOKED", "FAILED", "UNKNOWN", "MIXED_FINALIZED"):
                    conn.execute("UPDATE attempts SET state='EXPIRED' WHERE run_id=?", (run_id,))
                    row = (row[0],row[1],"EXPIRED")
                conn.execute("COMMIT")
                return _view(row[2])
        except sqlite3.Error as exc:
            raise ControllerDenied("LEDGER_UNAVAILABLE") from exc

    def advance(self, claim: object, *, now: int, event: str,
                receipt: object = None) -> dict[str, object]:
        fp = validate_synthetic_claim(claim, now=now, require_fresh=False)
        assert isinstance(claim, dict)
        if event not in _TRANSITIONS:
            raise ControllerDenied("INVALID_PHASE_EVENT")
        start, end = _TRANSITIONS[event]
        receipt_sha = None
        if event in ("COMPLETE_SIX", "COMPLETE_MIXED"):
            if not isinstance(receipt, dict) or set(receipt) != {
                "kind", "run_id", "attempt", "binding", "result", "grade"
            } or receipt != {
                "kind": event, "run_id": claim["run_id"], "attempt": 1,
                "binding": fp, "result": "PASS", "grade": "SYNTHETIC_T0"
            }:
                raise ControllerDenied("UNTRUSTED_PHASE_RECEIPT")
            receipt_sha = hashlib.sha256(_canonical(receipt).encode()).hexdigest()
        elif receipt is not None:
            raise ControllerDenied("UNEXPECTED_PHASE_RECEIPT")
        try:
            with closing(self._db()) as conn:
                conn.execute("BEGIN IMMEDIATE")
                row = conn.execute("""SELECT fingerprint,expires_at,state,six_receipt_sha256
                                      FROM attempts WHERE run_id=?""", (claim["run_id"],)).fetchone()
                if row is None or row[0] != fp:
                    raise ControllerDenied("UNKNOWN_OR_CHANGED_RUN_BINDING")
                if row[1] <= now:
                    conn.execute("UPDATE attempts SET state='EXPIRED' WHERE run_id=? AND state NOT IN ('REVOKED','FAILED','UNKNOWN','MIXED_FINALIZED')", (claim["run_id"],))
                    conn.execute("COMMIT")
                    raise ControllerDenied("RUN_EXPIRED")
                if row[2] != start:
                    raise ControllerDenied("STATE_REPLAY_OR_ILLEGAL_ORDER")
                if event == "START_MIXED" and not _hex(row[3], _SHA64):
                    raise ControllerDenied("MISSING_SIX_RECEIPT")
                col = ("six_receipt_sha256" if event == "COMPLETE_SIX"
                       else "mixed_receipt_sha256" if event == "COMPLETE_MIXED" else None)
                if col:
                    conn.execute(f"UPDATE attempts SET state=?,{col}=? WHERE run_id=? AND state=?",
                                 (end,receipt_sha,claim["run_id"],start))
                else:
                    conn.execute("UPDATE attempts SET state=? WHERE run_id=? AND state=?",
                                 (end,claim["run_id"],start))
                conn.execute("COMMIT")
        except sqlite3.Error as exc:
            raise ControllerDenied("LEDGER_UNAVAILABLE") from exc
        return _view(end)

    def cancel(self, claim: object, *, now: int, reason: str = "REVOKED") -> dict[str, object]:
        fp = validate_synthetic_claim(claim, now=now, require_fresh=False)
        assert isinstance(claim, dict)
        if reason not in ("FAILED", "REVOKED", "UNKNOWN"):
            raise ControllerDenied("INVALID_TERMINAL_REASON")
        try:
            with closing(self._db()) as conn:
                conn.execute("BEGIN IMMEDIATE")
                row = conn.execute("SELECT fingerprint,state FROM attempts WHERE run_id=?",
                                   (claim["run_id"],)).fetchone()
                if row is None or row[0] != fp:
                    raise ControllerDenied("UNKNOWN_OR_CHANGED_RUN_BINDING")
                if row[1] in ("MIXED_FINALIZED", "REVOKED", "FAILED", "EXPIRED", "UNKNOWN"):
                    raise ControllerDenied("TERMINAL_STATE_IMMUTABLE")
                conn.execute("UPDATE attempts SET state=? WHERE run_id=?", (reason,claim["run_id"]))
                conn.execute("COMMIT")
        except sqlite3.Error as exc:
            raise ControllerDenied("LEDGER_UNAVAILABLE") from exc
        return _view(reason)


def receipt_for_t0(claim: dict[str, Any], *, now: int, kind: str) -> dict[str, object]:
    """Synthetic receipt helper strictly for offline tests. Never authenticated."""
    if kind not in ("COMPLETE_SIX", "COMPLETE_MIXED"):
        raise ControllerDenied("INVALID_T0_RECEIPT_KIND")
    return {"kind": kind, "run_id": claim["run_id"], "attempt": 1,
            "binding": validate_synthetic_claim(claim, now=now, require_fresh=False),
            "result": "PASS", "grade": "SYNTHETIC_T0"}


def native_execution_decision(*_args: object, **_kwargs: object) -> None:
    raise ControllerDenied("NATIVE_T1_NOT_AUTHORIZED_OR_IMPLEMENTED")
