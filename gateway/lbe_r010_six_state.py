"""R010 six-row global serial transition policy, without execution authority.

The state transition algebra is shared by the durable Job journal and future
reviewed execution gate. It is deliberately PURE: any caller can simulate a
six-row successful state; it is NEVER an Owner Grant, private reaper witness,
provider-attested Job, durable fsync proof, or license to call Popen.
Only the actual Job journal may persist decisions after independent admission.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import hmac
import re

_HEX = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_FAILURES = frozenset({
    "ROW_OBSERVED_NONZERO",
    "ROW_OBSERVED_ZERO_INVALID_OUTPUT_OR_FS",
    "ROW_AMBIGUOUS",
})
_SUCCESS = "ROW_POSITIVE_SUCCESS"


class R010SixRowPolicyDenied(ValueError):
    """Transition violates exact global R010 order or one-use nonce."""


@dataclass(frozen=True, slots=True)
class R010SixRowPolicy:
    """Immutable global sequence state. NO capability, even when model done."""

    nonce_hashes: tuple[str, ...]
    job_state: str
    expected_row: int | None
    active_row: int | None
    rows: tuple[str, ...]
    used_nonce_sha256: tuple[str, ...]
    transition_number: int = 0
    status: str = "R010_SIX_ROW_SOURCE_POLICY_MODEL_ONLY"
    native_launch_allowed: bool = False
    six_command_product_t1_pass: bool = False

    @classmethod
    def hold(cls, nonce_hashes: tuple[str, ...]) -> "R010SixRowPolicy":
        if (type(nonce_hashes) is not tuple or len(nonce_hashes) != 6
                or any(type(v) is not str or _HEX.fullmatch(v) is None
                       for v in nonce_hashes)
                or len(set(nonce_hashes)) != 6):
            raise R010SixRowPolicyDenied("six unique nonce commitments required")
        return cls(
            nonce_hashes=nonce_hashes, job_state="JOB_PREEXEC_HOLD",
            expected_row=1, active_row=None,
            rows=("ROW_NOT_RUN",) * 6, used_nonce_sha256=(),
        )

    def _require_source_model(self) -> None:
        if (type(self) is not R010SixRowPolicy
                or self.status != "R010_SIX_ROW_SOURCE_POLICY_MODEL_ONLY"
                or self.native_launch_allowed is not False
                or self.six_command_product_t1_pass is not False
                or type(self.rows) is not tuple or len(self.rows) != 6
                or type(self.nonce_hashes) is not tuple
                or len(self.nonce_hashes) != 6):
            raise R010SixRowPolicyDenied("unqualified model identity")

    def ready_model_first(self) -> "R010SixRowPolicy":
        """T0-only readiness; NOT verification of a real Owner Grant."""
        self._require_source_model()
        if (self.job_state != "JOB_PREEXEC_HOLD"
                or self.expected_row != 1 or self.active_row is not None
                or self.used_nonce_sha256 or
                self.rows != ("ROW_NOT_RUN",) * 6):
            raise R010SixRowPolicyDenied("not an unused PREEXEC model")
        return replace(self, job_state="JOB_READY_FOR_ROW_1",
                       transition_number=self.transition_number + 1)

    def burn_model(self, row: int, nonce: str) -> "R010SixRowPolicy":
        """Pure no-I/O version of the REQUIRED pre-Worker nonce burn."""
        self._require_source_model()
        if (type(row) is not int or not 1 <= row <= 6
                or type(nonce) is not str or _HEX.fullmatch(nonce) is None
                or self.expected_row != row or self.active_row is not None
                or self.job_state != "JOB_READY_FOR_ROW_" + str(row)
                or self.rows[row - 1] != "ROW_NOT_RUN"):
            raise R010SixRowPolicyDenied("row cannot burn out of sequence")
        hashed = hashlib.sha256(bytes.fromhex(nonce)).hexdigest()
        if (not hmac.compare_digest(hashed, self.nonce_hashes[row - 1])
                or hashed in self.used_nonce_sha256):
            raise R010SixRowPolicyDenied("wrong or replayed row nonce")
        state_rows = list(self.rows)
        state_rows[row - 1] = "ROW_RUNNING"
        return replace(
            self, rows=tuple(state_rows), active_row=row,
            job_state="JOB_ROW_RUNNING_" + str(row),
            used_nonce_sha256=self.used_nonce_sha256 + (hashed,),
            transition_number=self.transition_number + 1,
        )

    def finish_model(self, row: int, classification: str) -> "R010SixRowPolicy":
        """Pure classified transition; outcome MUST be externally proven.

        An arbitrary string, FakeChild or returned model state is NEVER
        authenticated evidence. The real journal may not use an unauthenticated
        model outcome to advance to next row.
        """
        self._require_source_model()
        if (type(row) is not int or not 1 <= row <= 6
                or type(classification) is not str
                or classification not in _FAILURES | {_SUCCESS}
                or self.expected_row != row or self.active_row != row
                or self.job_state != "JOB_ROW_RUNNING_" + str(row)
                or self.rows[row - 1] != "ROW_RUNNING"):
            raise R010SixRowPolicyDenied("not the currently running row")
        new_rows = list(self.rows)
        new_rows[row - 1] = classification
        if classification in _FAILURES:
            for index in range(row, 6):
                if new_rows[index] == "ROW_NOT_RUN":
                    new_rows[index] = "ROW_VOID"
            return replace(
                self, rows=tuple(new_rows), active_row=None,
                expected_row=None, job_state="JOB_FAILED_LATCHED",
                transition_number=self.transition_number + 1,
            )
        if row == 6:
            return replace(
                self, rows=tuple(new_rows), active_row=None,
                expected_row=None, job_state="JOB_SIX_COMMAND_COMPLETE",
                transition_number=self.transition_number + 1,
            )
        return replace(
            self, rows=tuple(new_rows), active_row=None,
            expected_row=row + 1, job_state="JOB_READY_FOR_ROW_" + str(row + 1),
            transition_number=self.transition_number + 1,
        )

    def fail_unstarted_model(self) -> "R010SixRowPolicy":
        self._require_source_model()
        if (self.active_row is not None or self.job_state not in (
                "JOB_PREEXEC_HOLD",
                *("JOB_READY_FOR_ROW_" + str(i) for i in range(1, 7)))):
            raise R010SixRowPolicyDenied("active row requires classified outcome")
        rows = tuple(
            "ROW_VOID" if state == "ROW_NOT_RUN" else state
            for state in self.rows)
        return replace(self, rows=rows, active_row=None, expected_row=None,
                       job_state="JOB_FAILED_LATCHED",
                       transition_number=self.transition_number + 1)

    def snapshot(self) -> dict[str, object]:
        """Never returns product authority or a claim of real T1 PASS."""
        self._require_source_model()
        return {
            "status": self.status, "job_state_model": self.job_state,
            "expected_row_model": self.expected_row,
            "active_row_model": self.active_row,
            "rows_model": self.rows,
            "used_nonces_count": len(self.used_nonce_sha256),
            "transition_number": self.transition_number,
            "native_launch_allowed": False,
            "six_command_product_t1_pass": False,
            "authenticated_original_child_results": False,
        }
