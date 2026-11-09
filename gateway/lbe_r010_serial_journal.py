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
from .lbe_r010_owned_row import (
    R010OwnedRowSourceObservation, observe_r010_private_owner_row,
)
from .lbe_r010_row_fs import (
    R010FiniteRowObservation, R010PrivateTreeSnapshot,
    validate_r010_fixed_row_plan, verify_r010_finite_row_after,
)
from .lbe_r010_finite_integrity import R010SelectedSourceSnapshot
from .lbe_direct_owner import DirectChildOwner
from .lbe_r010_private_capture import (
    R010PrivateWorkerCapture, R010PrivateCaptureDenied)
from .lbe_r010_six_state import R010SixRowPolicy, R010SixRowPolicyDenied
from .lbe_worker import LbeWorkPlan
from typing import Any

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
            # Persist all six unique nonce commitments in the ONLY
            # create-once Job journal, before any row may be burned.
            # A partial write or crash leaves the root consumed forever.
            manifest = (json.dumps({
                "version": "R010_SIX_NONCE_MANIFEST_V1",
                "six_nonce_sha256": list(six_nonce_sha256),
                "state_domain": "R010_EPHEMERAL_JOB_STATE_V1",
                "native_launch_allowed": False,
            }, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
            try:
                _write_once(
                    envelope._journal_fd, "six-nonce-manifest.json", manifest)
            except R010JobEnvelopeDenied:
                envelope._r010_nonce_journal_claimed = True
                raise R010SerialAdmissionDenied(
                    "Job nonce manifest uncertain, permanent deny") from None
            envelope._r010_nonce_journal_claimed = True
        self._envelope = envelope
        self._digests = six_nonce_sha256
        # One canonical six-row model under the same envelope lock.
        # Its synthetic positive transitions NEVER authenticate an exit or
        # authorize NativeLauncher; the current product journal only uses
        # actual source-only first-row and permanent failure transitions.
        self._state_model = R010SixRowPolicy.hold(six_nonce_sha256)
        self._burned = False
        self._failed = False
        self._source_recorded = False
        self._row1_finalization_claimed = False
        self._row1_capture_claimed = False
        self._six_source_bound = False
        self._six_source_plan = None
        self._six_source_sha256 = None

    def _require_live(self) -> None:
        if self._failed:
            raise R010SerialAdmissionDenied("Job failure latched")
        try:
            self._envelope._require_live()
        except R010JobEnvelopeDenied:
            raise R010SerialAdmissionDenied("Job envelope unavailable") from None

    def bind_six_source_before_first_burn(
        self, *, service: object, ctx: object, source_plan: object,
    ) -> dict[str, object]:
        """Durably seal six SAME-service plan/source digests before burn.

        This is a source-only journal operation, not provider attestation,
        native execution or a valid Owner PRODUCT_T1 Grant. It neither
        consumes row 2 nor permits an original Popen.
        """
        from .lbe_r010_six_service import (
            R010SixSourcePlan, R010SixSourceDenied,
            fingerprint_r010_six_source,
        )
        with self._envelope._lock:
            self._require_live()
            if (self._burned or self._six_source_bound
                    or self._source_recorded or self._row1_capture_claimed
                    or type(source_plan) is not R010SixSourcePlan):
                raise R010SerialAdmissionDenied(
                    "six-source binding unavailable after row admission")
            try:
                digest, row_digests = fingerprint_r010_six_source(
                    service=service, ctx=ctx, snapshot=source_plan)
                payload = (json.dumps({
                    "version": "R010_SIX_ROW_SOURCE_BINDING_V1",
                    "job_key_sha256": self._envelope._key.key_sha256(),
                    "workspace": source_plan.workspace,
                    "source_sha256": digest,
                    "source_row_sha256": row_digests,
                    "nonce_sha256": self._digests,
                    "native_launch_allowed": False,
                    "row_positive_success": False,
                    "six_command_product_t1_pass": False,
                }, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
            except (R010SixSourceDenied, R010JobEnvelopeDenied,
                    ValueError, TypeError, OSError):
                # Deterministic source/shape rejection is NOT an uncertain
                # disk write. The caller must persist JOB_FAILED/ROW_VOID.
                raise R010SerialAdmissionDenied(
                    "six-row source identity denied") from None
            try:
                _write_once(
                    self._envelope._journal_fd,
                    "six-row-source-binding.json", payload)
            except R010JobEnvelopeDenied:
                # O_EXCL/fsync may have partially persisted: never retry,
                # re-adopt this Job or fabricate a successful VOID write.
                self._failed = True
                raise R010SerialAdmissionDenied(
                    "durable six-row source write uncertain") from None
            self._six_source_bound = True
            self._six_source_sha256 = digest
            self._six_source_plan = source_plan
            return {
                "source_sha256": digest, "row_count": 6,
                "status": "SIX_ROW_SOURCE_BOUND_NO_T1",
                "native_launch_allowed": False,
                "six_command_product_t1_pass": False,
            }

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
            try:
                changed_model = self._state_model.ready_model_first().burn_model(
                    1, nonce)
            except R010SixRowPolicyDenied:
                raise R010SerialAdmissionDenied(
                    "invalid global first-row state") from None
            record = (json.dumps({
                "version": "R010_ROW_BURN_V1",
                "row": 1,
                "nonce_sha256": self._digests[0],
                "status": "ROW_RUNNING",
                "job_state": "JOB_ROW_RUNNING_1",
                "expected_row": 1,
                "rows": ["ROW_RUNNING"] + ["ROW_NOT_RUN"] * 5,
                "native_launch_allowed": False,
            }, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
            try:
                _write_once(self._envelope._journal_fd, "row-01-burn.json", record)
            except R010JobEnvelopeDenied:
                self._failed = True
                raise R010SerialAdmissionDenied("row burn uncertain, deny forever") from None
            self._burned = True
            self._state_model = changed_model
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
            # Append-only failure record has the complete six-row outcome.
            # This does NOT edit the original PREEXEC_HOLD creation record.
            failure_row = {
                "original_nonzero": "ROW_OBSERVED_NONZERO",
                "invalid_output_or_fs": "ROW_OBSERVED_ZERO_INVALID_OUTPUT_OR_FS",
                "owner_reader_ambiguous": "ROW_AMBIGUOUS",
            }.get(code, "ROW_AMBIGUOUS")
            try:
                if self._burned:
                    failed_model = self._state_model.finish_model(
                        1, failure_row)
                else:
                    failed_model = self._state_model.fail_unstarted_model()
            except R010SixRowPolicyDenied:
                self._failed = True
                raise R010SerialAdmissionDenied(
                    "global state model corrupt, permanent deny") from None
            rows = list(failed_model.rows)
            record = (json.dumps({
                "status": "JOB_FAILED_LATCHED",
                "reason": code,
                "active_row": 1 if self._burned else None,
                "next_expected_row": None,
                "rows": rows,
                "rows_remaining": "ROW_VOID",
                "native_launch_allowed": False,
            }, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
            try:
                _write_once(self._envelope._journal_fd,
                            "r010-row-failure.json", record)
            except R010JobEnvelopeDenied:
                self._failed = True
                raise R010SerialAdmissionDenied("failure latch uncertain, deny forever") from None
            self._state_model = failed_model
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

    def record_source_only_first_row_zero(
        self, *, owned: R010OwnedRowSourceObservation,
        finite: R010FiniteRowObservation,
    ) -> dict[str, object]:
        """Persist finite source evidence, WITHOUT advancing to row 2.

        Both inputs are constructible data, not current provider/Owner Grant
        or native execution proof. A forged FakeChild exit0 can at most create
        an explicitly unqualified SOURCE_ONLY record. The Job's expected row
        remains 1 and no method releases a Popen capability.
        """
        with self._envelope._lock:
            self._require_live()
            if not self._burned or self._source_recorded:
                raise R010SerialAdmissionDenied(
                    "no active first row or duplicate source observation")
            valid_owner = (
                type(owned) is R010OwnedRowSourceObservation
                and type(owned.row) is int and owned.row == 1
                and owned.nonce_sha256 == self._digests[0]
                and owned.outcome ==
                "ORIGINAL_ZERO_READER_HEALTHY_FINITE_FS_NOT_CHECKED"
                and type(owned.observed_original_exit_code) is int
                and owned.observed_original_exit_code == 0
                and owned.original_child_reaped is True
                and owned.owner_reader_healthy is True
                and owned.output_complete is True
                and owned.native_launch_allowed is False
                and owned.row_positive_success is False
                and owned.six_command_product_t1_pass is False
                and owned.descendant_cleanup_proven is False
            )
            valid_finite = (
                type(finite) is R010FiniteRowObservation
                and type(finite.row) is int and finite.row == 1
                and finite.requested_argv ==
                    ("python", "-m", "pytest", "-q")
                and finite.effective_argv ==
                    ("python", "-m", "pytest", "-q")
                and finite.status ==
                    "FINITE_SOURCE_AND_PRIVATE_DELTAS_VALID_NOT_T1"
                and finite.selected_source_stable is True
                and finite.finite_private_delta_valid is True
                and finite.transient_mutation_absence_proven is False
                and finite.unobserved_host_side_effects_proven_absent is False
                and finite.go_build_artifact_sha256 is None
                and finite.native_launch_allowed is False
                and finite.row_positive_success is False
                and finite.six_command_product_t1_pass is False
                and type(finite.private_tree_before_sha256) is str
                and _HEX64.fullmatch(finite.private_tree_before_sha256)
                is not None
                and type(finite.private_tree_after_sha256) is str
                and _HEX64.fullmatch(finite.private_tree_after_sha256)
                is not None
            )
            if not valid_owner or not valid_finite:
                # Caller must explicitly latch the detected failure via the
                # existing durable failure path. Never issue a positive row.
                raise R010SerialAdmissionDenied(
                    "first row finite/owner source evidence unqualified")
            record = (json.dumps({
                "version": "R010_FIRST_ROW_SOURCE_ONLY_V1",
                "row": 1, "nonce_sha256": self._digests[0],
                "original_exit_code": 0,
                "source_only": True,
                "job_key_sha256": self._envelope._key.key_sha256(),
                "six_source_binding_sha256": self._six_source_sha256,
                "private_before_sha256": finite.private_tree_before_sha256,
                "private_after_sha256": finite.private_tree_after_sha256,
                "status": "ROW_FINITE_ZERO_SOURCE_ONLY_NOT_PRODUCT_T1",
                "next_row_allowed": False,
                "native_launch_allowed": False,
                "row_positive_success": False,
                "six_command_product_t1_pass": False,
            }, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
            try:
                _write_once(
                    self._envelope._journal_fd,
                    "row-01-source-only.json", record)
            except R010JobEnvelopeDenied:
                self._failed = True
                raise R010SerialAdmissionDenied(
                    "source observation write uncertain, permanent deny") from None
            self._source_recorded = True
            return {
                "status": "ROW_FINITE_ZERO_SOURCE_ONLY_NOT_PRODUCT_T1",
                "row": 1, "next_row_allowed": False,
                "native_launch_allowed": False,
                "six_command_product_t1_pass": False,
            }

    def finalize_first_row_from_actual_owner_source_only(
        self, *, owner: DirectChildOwner, reservation: object,
        plan: LbeWorkPlan, worker_result: dict[str, Any],
        selected_root_fd: int,
        selected_before: R010SelectedSourceSnapshot,
        private_root_fd: int,
        private_before: R010PrivateTreeSnapshot,
    ) -> dict[str, object]:
        """One-use Owner/Worker/finite-FS adapter for row 1; NO native grant.

        Worker and Owner must have completed the same private reservation.
        This entrypoint observes the actual Owner/reader (not a supplied
        success dataclass), then post-checks pinned source/private FDs.
        Failure permanently latches this Job; healthy zero writes only a
        SOURCE_ONLY record. No path can advance to row 2 or invoke Popen.

        This is still NOT an authenticated runtime adapter: same-UID callers
        can supply mutable Python objects, and no provider/Owner product
        Grant, host provenance or actual loaded-source closure is proven.
        Only the pre-authorized nonoperative SAFE T0 path may call it.
        """
        with self._envelope._lock:
            self._require_live()
            if (not self._burned or self._source_recorded
                    or self._row1_finalization_claimed):
                raise R010SerialAdmissionDenied(
                    "first row not active or finalization already consumed")
            # Claim exactly one finalization BEFORE inspecting mutable Worker
            # or files. A concurrent/later ACK cannot reclassify this row.
            self._row1_finalization_claimed = True
        try:
            validate_r010_fixed_row_plan(1, plan)
            owned = observe_r010_private_owner_row(
                owner=owner, reservation=reservation, plan=plan,
                worker_result=worker_result, row=1,
                nonce_sha256=self._digests[0])
            if owned.outcome in (
                "ROW_OBSERVED_NONZERO",
                "ROW_OBSERVED_ZERO_INVALID_OUTPUT_OR_FS",
                "ROW_AMBIGUOUS",
            ):
                self.latch_from_owned_row(owned)
                return {
                    "row": 1, "status": owned.outcome,
                    "durably_latched": True,
                    "next_row_allowed": False,
                    "native_launch_allowed": False,
                    "six_command_product_t1_pass": False,
                }
            if (owned.outcome !=
                    "ORIGINAL_ZERO_READER_HEALTHY_FINITE_FS_NOT_CHECKED"):
                raise R010SerialAdmissionDenied("unknown private owner status")
            try:
                finite = verify_r010_finite_row_after(
                    row=1, plan=plan,
                    selected_root_fd=selected_root_fd,
                    selected_before=selected_before,
                    private_root_fd=private_root_fd,
                    private_before=private_before)
            except Exception:
                # Trusted original zero + healthy reader, but finite
                # source/cache postcheck missing/failed/ambiguous.
                self.latch_failure("invalid_output_or_fs")
                return {
                    "row": 1, "status": "ROW_OBSERVED_ZERO_INVALID_OUTPUT_OR_FS",
                    "durably_latched": True,
                    "next_row_allowed": False,
                    "native_launch_allowed": False,
                    "six_command_product_t1_pass": False,
                }
            return self.record_source_only_first_row_zero(
                owned=owned, finite=finite)
        except Exception:
            # Any unexpected source/Owner/record failure leaves a burned
            # non-retryable nonce. Try to persist the ambiguity; a failed
            # fsync also remains a permanent denial on this Job.
            if not self._failed:
                try:
                    self.latch_failure("owner_reader_ambiguous")
                except Exception:
                    self._failed = True
            raise R010SerialAdmissionDenied(
                "original owner row-1 finalization uncertain, denied") from None

    def make_first_row_private_capture(
        self, *, owner: DirectChildOwner, plan: LbeWorkPlan,
        source_plan: object = None,
    ) -> R010PrivateWorkerCapture:
        """Bind the next private Worker reservation to the burned Job row.

        No Popen and no product grant. The capture cannot be replayed or
        transferred to another owner or plan.
        """
        with self._envelope._lock:
            self._require_live()
            if (not self._burned or self._row1_capture_claimed
                    or self._source_recorded or self._row1_finalization_claimed
                    or type(owner) is not DirectChildOwner
                    or type(plan) is not LbeWorkPlan
                    or (self._six_source_bound
                        and (source_plan is not self._six_source_plan
                             or plan is not
                             self._six_source_plan.rows[0].candidate.plan))):
                raise R010SerialAdmissionDenied(
                    "first-row private capture unavailable or already claimed")
            try:
                validate_r010_fixed_row_plan(1, plan)
            except Exception:
                raise R010SerialAdmissionDenied(
                    "private capture plan does not match fixed row") from None
            self._row1_capture_claimed = True
            return R010PrivateWorkerCapture._issue_source_only(
                journal=self, owner=owner, plan=plan,
                nonce_sha256=self._digests[0])

    def finalize_first_row_from_worker_capture_source_only(
        self, *, capture: R010PrivateWorkerCapture,
        selected_root_fd: int,
        selected_before: R010SelectedSourceSnapshot,
        private_root_fd: int,
        private_before: R010PrivateTreeSnapshot,
    ) -> dict[str, object]:
        """Take a Worker-created reservation result, not user Worker metadata."""
        if type(capture) is not R010PrivateWorkerCapture:
            raise R010SerialAdmissionDenied("invalid Worker capture")
        try:
            owner, reservation, plan, result, nonce_hash = (
                capture._take_for_journal(self))
            if (not self._row1_capture_claimed
                    or nonce_hash != self._digests[0]):
                raise R010PrivateCaptureDenied("capture does not match row")
        except R010PrivateCaptureDenied:
            if not self._failed and not self._source_recorded:
                try:
                    self.latch_failure("owner_reader_ambiguous")
                except Exception:
                    self._failed = True
            raise R010SerialAdmissionDenied(
                "first-row original Worker capture unavailable") from None
        return self.finalize_first_row_from_actual_owner_source_only(
            owner=owner, reservation=reservation, plan=plan,
            worker_result=result,
            selected_root_fd=selected_root_fd,
            selected_before=selected_before,
            private_root_fd=private_root_fd,
            private_before=private_before)

    def _require_active_private_capture(
        self, capture: R010PrivateWorkerCapture,
        source_plan: object,
    ) -> None:
        """Guard the exact unlatched Job immediately before Worker launcher."""
        with self._envelope._lock:
            self._require_live()
            if (type(capture) is not R010PrivateWorkerCapture
                    or capture._journal is not self
                    or not self._burned or not self._row1_capture_claimed
                    or self._source_recorded or self._row1_finalization_claimed
                    or self._state_model.job_state != "JOB_ROW_RUNNING_1"
                    or self._state_model.active_row != 1
                    or (self._six_source_bound
                        and source_plan is not self._six_source_plan)):
                raise R010SerialAdmissionDenied(
                    "private Worker receipt lost live Job identity")

    def row_state_snapshot(self) -> dict[str, object]:
        """Status-only six-row observability; never a source of authority."""
        with self._envelope._lock:
            self._require_live()
            return {
                **self._state_model.snapshot(),
                "six_source_durable_binding_present": self._six_source_bound,
                "six_source_sha256": self._six_source_sha256,
            }

    def begin_later_row(self, *_args: object, **_kwargs: object) -> None:
        raise R010SerialAdmissionDenied("trusted row-success adapter not implemented")

    def claim_six_command_pass(self, *_args: object, **_kwargs: object) -> None:
        raise R010SerialAdmissionDenied("original six-row evidence not proven")
