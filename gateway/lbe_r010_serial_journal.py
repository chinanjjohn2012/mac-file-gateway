"""R010 one-use durable nonce journal. Never launches or authorizes Exec.

This source is an actual fsync/O_EXCL Job-local safety primitive. It does not
authenticate provider or owner, cannot issue a trusted original-child receipt,
and intentionally cannot advance to row 2 without that separately reviewed
component. No synthetic input may produce PRODUCT_T1 PASS.
"""
from __future__ import annotations

import hashlib
import json
import re

from .lbe_r010_job_envelope import (
    R010CreatedJobEnvelope, R010JobEnvelopeDenied, _write_once,
)
from .lbe_r010_owned_row import R010OwnedRowSourceObservation

_HEX64 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_REASON = re.compile(r"[a-z][a-z0-9_]{0,79}\Z", re.ASCII)


class R010SerialAdmissionDenied(ValueError):
    """One-use Job row admission is permanently unavailable."""


class R010SerialNonceJournal:
    """Owner-process-only durable row-1 burn; no public/native capability."""

    def __init__(self, envelope: R010CreatedJobEnvelope, *,
                 six_nonce_sha256: tuple[str, ...]) -> None:
        if type(envelope) is not R010CreatedJobEnvelope:
            raise R010SerialAdmissionDenied("invalid Job envelope")
        if (type(six_nonce_sha256) is not tuple
                or len(six_nonce_sha256) != 6
                or any(type(x) is not str or _HEX64.fullmatch(x) is None
                       for x in six_nonce_sha256)
                or len(set(six_nonce_sha256)) != 6):
            raise R010SerialAdmissionDenied("six distinct row nonces required")
        with envelope._lock:
            try:
                envelope._require_live()
            except R010JobEnvelopeDenied:
                raise R010SerialAdmissionDenied("Job envelope unavailable") from None
            if getattr(envelope, "_r010_nonce_journal_claimed", False):
                raise R010SerialAdmissionDenied("Job row adapter already claimed")
            envelope._r010_nonce_journal_claimed = True
        self._envelope = envelope
        self._digests = six_nonce_sha256
        self._burned = False
        self._failed = False

    def _require_live(self) -> None:
        if self._failed:
            raise R010SerialAdmissionDenied("Job failure latched")
        try:
            self._envelope._require_live()
        except R010JobEnvelopeDenied:
            raise R010SerialAdmissionDenied("Job envelope unavailable") from None

    def burn_first_nonce(self, nonce: str) -> dict[str, object]:
        """Atomically burn once before any future, separately approved Popen."""
        with self._envelope._lock:
            self._require_live()
            if self._burned:
                raise R010SerialAdmissionDenied("first row already burned")
            if (type(nonce) is not str or _HEX64.fullmatch(nonce) is None
                    or hashlib.sha256(bytes.fromhex(nonce)).hexdigest()
                    != self._digests[0]):
                raise R010SerialAdmissionDenied("wrong row-1 nonce")
            record = (json.dumps({
                "version": "R010_ROW_BURN_V1",
                "row": 1,
                "nonce_sha256": self._digests[0],
                "status": "ROW_RUNNING",
                "native_launch_allowed": False,
            }, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
            try:
                _write_once(self._envelope._journal_fd, "row-01-burn.json", record)
            except R010JobEnvelopeDenied:
                self._failed = True
                raise R010SerialAdmissionDenied("row burn uncertain, deny forever") from None
            self._burned = True
            return {
                "row": 1, "nonce_burned": True,
                "native_launch_allowed": False,
                "row_success_attested": False,
            }

    def latch_failure(self, code: str) -> None:
        """Mark all remaining rows VOID, never signal or retry a process."""
        if type(code) is not str or _REASON.fullmatch(code) is None:
            raise R010SerialAdmissionDenied("invalid failure code")
        with self._envelope._lock:
            self._require_live()
            record = (json.dumps({
                "status": "JOB_FAILED_LATCHED",
                "reason": code,
                "rows_remaining": "ROW_VOID",
                "native_launch_allowed": False,
            }, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
            try:
                _write_once(self._envelope._journal_fd,
                            "r010-row-failure.json", record)
            except R010JobEnvelopeDenied:
                self._failed = True
                raise R010SerialAdmissionDenied("failure latch uncertain, deny forever") from None
            self._failed = True

    def latch_from_owned_row(self, observation: R010OwnedRowSourceObservation) -> None:
        """Durably void the Job for an actual source-observed NONPOSITIVE row.

        Neither a healthy FakeChild exit0 nor a forged public observation can
        advance this journal. Trusted positive row acceptance and row 2..6
        remain disabled pending complete private FS/Provider/Grant qualification.
        This is a deny-only bridge; it cannot mint execution authority.
        """
        if (type(observation) is not R010OwnedRowSourceObservation
                or observation.row != 1 or
                observation.nonce_sha256 != self._digests[0] or
                observation.native_launch_allowed is not False or
                observation.row_positive_success is not False or
                observation.six_command_product_t1_pass is not False or
                not self._burned):
            raise R010SerialAdmissionDenied("observation not bound to burned row")
        reason = {
            "ROW_OBSERVED_NONZERO": "original_nonzero",
            "ROW_OBSERVED_ZERO_INVALID_OUTPUT_OR_FS": "invalid_output_or_fs",
            "ROW_AMBIGUOUS": "owner_reader_ambiguous",
        }.get(observation.outcome)
        if reason is None:
            raise R010SerialAdmissionDenied(
                "healthy zero still lacks full product integrity and owner Grant")
        self.latch_failure(reason)

    def begin_later_row(self, *_args: object, **_kwargs: object) -> None:
        raise R010SerialAdmissionDenied("trusted row-success adapter not implemented")

    def claim_six_command_pass(self, *_args: object, **_kwargs: object) -> None:
        raise R010SerialAdmissionDenied("original six-row evidence not proven")
