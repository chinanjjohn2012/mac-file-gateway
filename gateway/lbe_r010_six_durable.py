"""R010 append-only durable SIX-row transition kernel (no runtime authority).

This is real O_EXCL/fsync serialization with one global expected row, chained
records, one-use nonces and durable failed-row/VOID semantics. The current
entrypoint is deliberately SOURCE-MODEL ONLY: any injected "positive"
classification is *not* a real Owner/Worker/Provider/Grant observation.
No existing R010SerialNonceJournal, WorkspaceService, Worker or launcher
imports this class to permit row 2 or native execution. A future separately
qualified adapter can reuse the persistence algorithm only after binding a
trusted private original-child receipt and live Owner PRODUCT_T1 grant.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re

from .lbe_r010_job_envelope import (
    R010CreatedJobEnvelope, R010JobEnvelopeDenied, _write_once,
)
from .lbe_r010_six_state import (
    R010SixRowPolicy, R010SixRowPolicyDenied,
)

_HEX64 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_SUCCESS = "ROW_POSITIVE_SUCCESS"
_FAILURE = frozenset({
    "ROW_OBSERVED_NONZERO",
    "ROW_OBSERVED_ZERO_INVALID_OUTPUT_OR_FS",
    "ROW_AMBIGUOUS",
})


class R010SixDurableDenied(ValueError):
    """Unqualified or already consumed Job/nonce/source model transition."""


@dataclass(frozen=True, slots=True)
class R010DurableModelSnapshot:
    job_key_sha256: str
    source_sha256: str
    job_state_model: str
    expected_row_model: int | None
    active_row_model: int | None
    rows_model: tuple[str, ...]
    last_record_sha256: str
    records_written: int
    source_model_only: bool = True
    native_launch_allowed: bool = False
    row_positive_success: bool = False
    six_command_product_t1_pass: bool = False


class R010SixRowDurableKernel:
    """Real persistent global row ordering; zero ability to start a child.

    All records share the canonical create-once Job envelope's pre-existing
    command-journal dirfd and instance lock. No alternate root or reopen.
    A successful *synthetic* model state is not original PRODUCT_T1 evidence.
    """

    def __init__(
        self, envelope: R010CreatedJobEnvelope, *,
        nonce_sha256: tuple[str, ...], source_sha256: str,
    ) -> None:
        if (type(envelope) is not R010CreatedJobEnvelope
                or type(nonce_sha256) is not tuple or len(nonce_sha256) != 6
                or len(set(nonce_sha256)) != 6
                or any(type(x) is not str or _HEX64.fullmatch(x) is None
                       for x in nonce_sha256)
                or type(source_sha256) is not str
                or _HEX64.fullmatch(source_sha256) is None):
            raise R010SixDurableDenied("unqualified canonical Job/nonce/source")
        with envelope._lock:
            try:
                envelope._require_live()
            except R010JobEnvelopeDenied:
                raise R010SixDurableDenied("canonical Job unavailable") from None
            if getattr(envelope, "_r010_six_kernel_claimed", False):
                raise R010SixDurableDenied("six-row kernel already claimed")
            # A failed create/fsync still consumes this Job. NEVER retry.
            envelope._r010_six_kernel_claimed = True
            key_sha256 = envelope._key.key_sha256()
            payload = self._encode({
                "version": "R010_SOURCE_MODEL_SIX_ROW_MANIFEST_V1",
                "source_model_only": True,
                "job_key_sha256": key_sha256,
                "source_sha256": source_sha256,
                "nonce_sha256": nonce_sha256,
                "native_launch_allowed": False,
                "six_command_product_t1_pass": False,
            })
            try:
                _write_once(
                    envelope._journal_fd, "r010-source-model-six-manifest.json",
                    payload)
            except R010JobEnvelopeDenied:
                raise R010SixDurableDenied(
                    "six-row manifest uncertain; permanent denial") from None
        self._envelope = envelope
        self._key_sha256 = key_sha256
        self._source_sha256 = source_sha256
        self._model = R010SixRowPolicy.hold(nonce_sha256)
        self._failed = False
        self._records = 1
        self._last_sha256 = hashlib.sha256(payload).hexdigest()

    @staticmethod
    def _encode(data: dict[str, object]) -> bytes:
        return (json.dumps(
            data, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True) + "\n").encode("ascii")

    def _require_live(self) -> None:
        if self._failed:
            raise R010SixDurableDenied("durability uncertain; permanent denial")
        try:
            self._envelope._require_live()
        except R010JobEnvelopeDenied:
            raise R010SixDurableDenied("canonical Job unavailable") from None

    def _write(self, name: str, payload: dict[str, object]) -> None:
        payload.update({
            "version": "R010_SOURCE_MODEL_SIX_ROW_TRANSITION_V1",
            "job_key_sha256": self._key_sha256,
            "source_sha256": self._source_sha256,
            "previous_record_sha256": self._last_sha256,
            "source_model_only": True,
            "native_launch_allowed": False,
            "row_positive_success": False,
            "six_command_product_t1_pass": False,
        })
        encoded = self._encode(payload)
        try:
            _write_once(self._envelope._journal_fd, name, encoded)
        except R010JobEnvelopeDenied:
            self._failed = True
            raise R010SixDurableDenied(
                "row record write uncertain; permanent denial") from None
        self._last_sha256 = hashlib.sha256(encoded).hexdigest()
        self._records += 1

    def burn_model_row(self, row: int, nonce: str) -> R010DurableModelSnapshot:
        """Atomically fsync exact row nonce; NEVER returns Worker/Popen permit."""
        with self._envelope._lock:
            self._require_live()
            if (type(row) is not int or not 1 <= row <= 6
                    or type(nonce) is not str or
                    _HEX64.fullmatch(nonce) is None):
                raise R010SixDurableDenied("invalid row or nonce")
            try:
                current = (self._model.ready_model_first()
                           if row == 1 else self._model)
                next_model = current.burn_model(row, nonce)
            except R010SixRowPolicyDenied:
                raise R010SixDurableDenied(
                    "out-of-order, duplicate or wrong nonce") from None
            self._write("r010-source-model-%02d-burn.json" % row, {
                "row": row,
                "nonce_sha256": next_model.used_nonce_sha256[-1],
                "job_state_model": next_model.job_state,
                "expected_row_model": next_model.expected_row,
                "transition_number": next_model.transition_number,
            })
            self._model = next_model
            return self._snapshot_unlocked()

    def finish_model_row(
        self, row: int, classification: str, *,
        evidence_sha256: str,
    ) -> R010DurableModelSnapshot:
        """Durably write ONE classification+next index in ONE fsynced record.

        An evidence SHA256 here is just a model artifact; there is no
        independently verified provider, real reaped original child or Grant.
        Thus even six simulated success records never become PRODUCT_T1 PASS.
        """
        with self._envelope._lock:
            self._require_live()
            if (type(row) is not int or
                    type(classification) is not str or
                    classification not in _FAILURE | {_SUCCESS} or
                    type(evidence_sha256) is not str or
                    _HEX64.fullmatch(evidence_sha256) is None):
                raise R010SixDurableDenied("unqualified model terminal row")
            try:
                next_model = self._model.finish_model(
                    row, classification)
            except R010SixRowPolicyDenied:
                raise R010SixDurableDenied(
                    "row terminal not the active global row") from None
            self._write("r010-source-model-%02d-result.json" % row, {
                "row": row, "classification_model": classification,
                "evidence_sha256_model": evidence_sha256,
                "job_state_model": next_model.job_state,
                "expected_row_model": next_model.expected_row,
                "active_row_model": next_model.active_row,
                "rows_model": next_model.rows,
                "transition_number": next_model.transition_number,
                "remaining_rows_void": classification in _FAILURE,
            })
            self._model = next_model
            return self._snapshot_unlocked()

    def latch_unstarted_model(self, *, evidence_sha256: str
                              ) -> R010DurableModelSnapshot:
        """Any unstarted-row loss permanently VOID-s remaining rows."""
        with self._envelope._lock:
            self._require_live()
            if (type(evidence_sha256) is not str
                    or _HEX64.fullmatch(evidence_sha256) is None):
                raise R010SixDurableDenied("unqualified loss evidence")
            try:
                next_model = self._model.fail_unstarted_model()
            except R010SixRowPolicyDenied:
                raise R010SixDurableDenied(
                    "cannot reclassify active row without its outcome") from None
            self._write("r010-source-model-unstarted-failure.json", {
                "evidence_sha256_model": evidence_sha256,
                "job_state_model": next_model.job_state,
                "rows_model": next_model.rows,
                "expected_row_model": None,
                "remaining_rows_void": True,
                "transition_number": next_model.transition_number,
            })
            self._model = next_model
            return self._snapshot_unlocked()

    def _snapshot_unlocked(self) -> R010DurableModelSnapshot:
        state = self._model.snapshot()
        return R010DurableModelSnapshot(
            job_key_sha256=self._key_sha256,
            source_sha256=self._source_sha256,
            job_state_model=state["job_state_model"],
            expected_row_model=state["expected_row_model"],
            active_row_model=state["active_row_model"],
            rows_model=state["rows_model"],
            last_record_sha256=self._last_sha256,
            records_written=self._records,
        )

    def snapshot(self) -> R010DurableModelSnapshot:
        with self._envelope._lock:
            self._require_live()
            return self._snapshot_unlocked()

    def grant_native_launch(self, *_args, **_kwargs) -> None:
        raise R010SixDurableDenied("no authenticated product execution grant")

    def claim_product_t1_pass(self, *_args, **_kwargs) -> None:
        raise R010SixDurableDenied("synthetic rows are not PRODUCT_T1")
