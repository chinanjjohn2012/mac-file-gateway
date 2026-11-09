"""One-use R010 source-only capture of a real Worker reservation and result.

This is a private identity correlation object, NOT an Owner T1 Grant. It is
created from the already-burned row-1 Job journal and attached by LbeWorker
immediately after DirectChildOwner.reserve(), BEFORE the launcher callback.
The actual Worker stores a detached result snapshot; a user-supplied REST/
MCP result dict, later fake ACK, second reservation or changed dictionary
cannot produce a trusted runtime receipt. Even a healthy FakeChild does not
authorize Go/Pipenv/Python PRODUCT_T1 or advance the Job to row 2.
"""
from __future__ import annotations

import threading
from typing import Any

from .lbe_direct_owner import DirectChildOwner, _Reservation
from .lbe_worker import LbeWorkPlan

_MARKER = object()


class R010PrivateCaptureDenied(ValueError):
    """Private source capture was mismatched, missing or consumed."""


class R010PrivateWorkerCapture:
    """Source only, never returns a spawn, grant or execution capability."""

    __slots__ = (
        "_owner", "_plan", "_journal", "_nonce_sha256", "_reservation",
        "_result", "_consumed", "_lock", "_source_binding",
    )

    def __init__(self, marker: object, *, owner: DirectChildOwner,
                 plan: LbeWorkPlan, journal: object, nonce_sha256: str):
        if (marker is not _MARKER or type(owner) is not DirectChildOwner
                or type(plan) is not LbeWorkPlan
                or type(nonce_sha256) is not str or len(nonce_sha256) != 64):
            raise R010PrivateCaptureDenied("not a journal-minted source capture")
        self._owner = owner
        self._plan = plan
        self._journal = journal
        self._nonce_sha256 = nonce_sha256
        self._reservation = None
        self._result = None
        self._consumed = False
        self._lock = threading.Lock()
        self._source_binding = None

    @classmethod
    def _issue_source_only(cls, *, journal: object, owner: DirectChildOwner,
                           plan: LbeWorkPlan,
                           nonce_sha256: str) -> "R010PrivateWorkerCapture":
        """Called only by the first-row journal, never public request data."""
        return cls(_MARKER, owner=owner, plan=plan, journal=journal,
                   nonce_sha256=nonce_sha256)

    def _bind_six_source(self, *, service: object, ctx: object,
                         source_plan: object) -> None:
        """Bind the original source service instance before any Worker step."""
        from .lbe_r010_six_service import (
            R010SixSourcePlan, recheck_r010_service_six_source,
        )
        from .workspaces import WorkspaceService, WorkspaceContext
        if (type(service) is not WorkspaceService
                or type(ctx) is not WorkspaceContext
                or type(source_plan) is not R010SixSourcePlan
                or service._lbe_owner is not self._owner
                or source_plan.rows[0].candidate.plan is not self._plan):
            raise R010PrivateCaptureDenied("source binding not from same service")
        try:
            recheck_r010_service_six_source(
                service=service, ctx=ctx, snapshot=source_plan)
        except Exception:
            raise R010PrivateCaptureDenied(
                "source drift before Worker binding") from None
        with self._lock:
            if self._source_binding is not None or self._consumed:
                raise R010PrivateCaptureDenied(
                    "source service binding already consumed")
            self._source_binding = (service, ctx, source_plan)

    def _recheck_six_source(self) -> None:
        """Second first-party check at the actual Worker launch boundary."""
        with self._lock:
            binding = self._source_binding
        if binding is None:
            # No service-bound source can be claimed by a test-only capture.
            # This never makes an unbound capture a native authorization.
            return
        from .lbe_r010_six_service import recheck_r010_service_six_source
        try:
            recheck_r010_service_six_source(
                service=binding[0], ctx=binding[1],
                snapshot=binding[2])
        except Exception:
            raise R010PrivateCaptureDenied(
                "service-selected first-party source drift before launcher"
            ) from None

    def _check_for_worker(self, owner: DirectChildOwner,
                          plan: LbeWorkPlan) -> None:
        with self._lock:
            if (self._owner is not owner or self._plan is not plan
                    or self._reservation is not None or self._result is not None
                    or self._consumed):
                raise R010PrivateCaptureDenied(
                    "capture not bound to this exact Worker plan")
        self._recheck_six_source()

    def _bind_reserved(self, owner: DirectChildOwner,
                       reservation: _Reservation,
                       plan: LbeWorkPlan) -> None:
        with self._lock:
            if (self._owner is not owner or self._plan is not plan
                    or self._reservation is not None or self._consumed
                    or type(reservation) is not _Reservation
                    or reservation.owner is not owner
                    or reservation.workspace != plan.workspace):
                raise R010PrivateCaptureDenied(
                    "Worker reservation differs from first-row capture")
            self._reservation = reservation

    def _record_worker_result(self, owner: DirectChildOwner,
                              reservation: _Reservation,
                              plan: LbeWorkPlan,
                              result: dict[str, Any]) -> None:
        with self._lock:
            if (self._owner is not owner or self._plan is not plan
                    or self._reservation is not reservation
                    or self._result is not None or self._consumed
                    or type(result) is not dict):
                raise R010PrivateCaptureDenied(
                    "returned Worker result is not from reserved attempt")
            self._result = dict(result)

    def _take_for_journal(self, journal: object):
        """Consume EXACT original private references once, never an ACK."""
        with self._lock:
            if (self._journal is not journal or self._consumed
                    or self._reservation is None or self._result is None):
                raise R010PrivateCaptureDenied(
                    "first-row Worker capture not complete or already used")
            self._consumed = True
            return (self._owner, self._reservation,
                    self._plan, dict(self._result), self._nonce_sha256)

    def status(self) -> dict[str, object]:
        """No reservation, PID, secret, nonce or output in the diagnostic."""
        with self._lock:
            return {
                "status": "PRIVATE_WORKER_SOURCE_CAPTURE_ONLY",
                "reservation_bound": self._reservation is not None,
                "worker_result_recorded": self._result is not None,
                "consumed": self._consumed,
                "same_service_source_bound": self._source_binding is not None,
                "native_launch_allowed": False,
                "row_positive_success": False,
            }
