"""R010 private Owner/Worker result correlation, not a native Exec grant.

Read the actual existing LbeWorker/DirectChildOwner/BoundedPipeDrain state for
one reservation after a separately authorized (or FakeChild T0) attempt.
A dict representing a Worker result is never sufficient alone. This component
reports source-observed health only: even healthy exit0 CANNOT complete a row,
advance a Job nonce or prove selected-source/private-FS deltas.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import re
from typing import Any

from .lbe_direct_owner import DirectChildOwner, _Reservation, LbeOwnerError
from .lbe_pipe_drain import BoundedPipeDrain
from .lbe_worker import LbeWorkPlan, LbeWorker

_SHA64 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_HEALTHY_ZERO = "ORIGINAL_ZERO_READER_HEALTHY_FINITE_FS_NOT_CHECKED"
_NONZERO = "ROW_OBSERVED_NONZERO"
_BAD_OUTPUT = "ROW_OBSERVED_ZERO_INVALID_OUTPUT_OR_FS"
_AMBIGUOUS = "ROW_AMBIGUOUS"


class R010OwnedRowDenied(ValueError):
    """Untrusted owner/reservation type or row identity."""


@dataclass(frozen=True, slots=True)
class R010OwnedRowSourceObservation:
    """Candidate original-child result; NEVER a pass or execution capability."""

    row: int
    nonce_sha256: str
    outcome: str
    observed_original_exit_code: int | None
    original_child_reaped: bool
    owner_reader_healthy: bool
    output_complete: bool
    status: str = "PRIVATE_OWNER_SOURCE_ONLY_NOT_NATIVE_ATTESTED"
    native_launch_allowed: bool = False
    row_positive_success: bool = False
    six_command_product_t1_pass: bool = False
    descendant_cleanup_proven: bool = False


def observe_r010_private_owner_row(
    *, owner: DirectChildOwner, reservation: object,
    plan: LbeWorkPlan, worker_result: dict[str, Any],
    row: int, nonce_sha256: str,
) -> R010OwnedRowSourceObservation:
    """Classify one existing Owner reservation; no wait/spawn retry or signals.

    The caller MUST obtain the exact reservation from the trusted Worker
    invocation, not a REST/MCP field. This function does not establish that
    private provenance: only a future reviewed Worker adapter may connect it
    to one durable Job envelope. Current negative/positive output is T0-only.
    """
    if (type(owner) is not DirectChildOwner
            or type(reservation) is not _Reservation
            or reservation.owner is not owner
            or type(plan) is not LbeWorkPlan
            or type(worker_result) is not dict
            or type(row) is not int or not 1 <= row <= 6
            or type(nonce_sha256) is not str or _SHA64.fullmatch(nonce_sha256)
            is None):
        raise R010OwnedRowDenied("not an exact internal row/Owner observation")
    # Reuse actual Worker plan safety; no untrusted hash/comparison callback.
    LbeWorker._check_plan(plan)
    if reservation.workspace != plan.workspace:
        raise R010OwnedRowDenied("reservation belongs to another Workspace")

    result = _AMBIGUOUS
    code: int | None = None
    reaped = False
    healthy = False
    complete = False
    try:
        # The real source owner observes its OWN reaper/wait() result.
        observation = owner.observe(reservation, wait_seconds=0)
        owner_state = owner.snapshot()
        drain = reservation.pipe_drain
        if type(drain) is not BoundedPipeDrain:
            raise R010OwnedRowDenied("missing trusted private pipe reader")
        pipe = drain.snapshot()
        # After the last reader snapshot, sample the owner latch again:
        # selector.close failures AFTER both EOFs must still fail closed.
        final_owner_state = owner.snapshot()

        if (observation.status == "exited"
                and type(observation.exit_code) is int
                and observation.timed_out is False
                and type(reservation.exit_code) is int
                and reservation.exit_code == observation.exit_code
                and reservation.phase == "DIRECT_CHILD_REAPED"):
            reaped = True
            code = observation.exit_code
        # An actual Worker result is consistent but is NOT independently
        # sufficient to identify the original reaper or private reservation.
        wanted = {
            "workspace": plan.workspace,
            "cwd": plan.cwd,
            "requested_argv": list(plan.requested_argv),
            "effective_argv": list(plan.effective_argv),
            "runner": plan.runner,
            "runner_project": plan.runner_project,
            "status": "exited", "executed": True, "timed_out": False,
            "exit_code": code, "process_may_be_running": True,
            "cleanup_proven": False,
            "full_descendant_tree_clean": "not_proven",
            "mode": "local_best_effort", "dry_run": False,
        }
        consistent = reaped and not reservation.waiter_disconnected
        for name, value in wanted.items():
            if type(worker_result.get(name)) is not type(value):
                consistent = False
                break
            if worker_result[name] != value:
                consistent = False
                break
        for name in ("stdout", "stderr", "stdout_truncated",
                     "stderr_truncated", "output_complete",
                     "pipe_reader_failed"):
            if (name not in pipe or type(worker_result.get(name))
                    is not type(pipe[name]) or worker_result[name] != pipe[name]):
                consistent = False
                break
        healthy = (
            consistent
            and pipe.get("pipe_reader_finished") is True
            and pipe.get("pipe_reader_failed") is False
            and worker_result.get("pipe_reader_failed") is False
            and owner_state.get("unavailable") is False
            and owner_state.get("closing") is False
            and final_owner_state.get("unavailable") is False
            and final_owner_state.get("closing") is False
        )
        complete = pipe.get("output_complete") is True
        if healthy:
            if code != 0:
                result = _NONZERO
            elif (complete and pipe.get("stdout_truncated") is False
                  and pipe.get("stderr_truncated") is False):
                # Not ROW_POSITIVE_SUCCESS: source, private root, artifact,
                # Job/owner grant and actual host checks are separate.
                result = _HEALTHY_ZERO
            else:
                result = _BAD_OUTPUT
    except (LbeOwnerError, R010OwnedRowDenied, ValueError, TypeError,
            KeyError, AttributeError, RuntimeError):
        # Ambiguity never becomes zero or a guessed exit code.
        result = _AMBIGUOUS
        healthy = False

    return R010OwnedRowSourceObservation(
        row=row, nonce_sha256=nonce_sha256,
        outcome=result, observed_original_exit_code=code,
        original_child_reaped=reaped, owner_reader_healthy=healthy,
        output_complete=complete,
    )
