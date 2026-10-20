"""Owner-bound, memory-only execution admission; no process implementation."""
from __future__ import annotations

from dataclasses import dataclass
import math
import threading
import time
from typing import Callable, Literal
import weakref

from .core import GatewayError
from .exec_contracts import ExecutionIntent, ExecutionRequest, ExecutionOutcome


@dataclass(frozen=True, eq=False)
class ExecutionLease:
    ticket_id: str
    workspace: str


@dataclass(frozen=True)
class RegistrySnapshot:
    active_total: int
    workspace_counts: tuple[tuple[str, int], ...]
    closing: bool


@dataclass
class _Record:
    timeout: int
    state: str = "RESERVED"
    deadline: float | None = None
    stop_reason: str | None = None


class ExecRegistry:
    def __init__(self, *, clock: Callable[[], float] = time.monotonic):
        self._clock = clock
        self._condition = threading.Condition()
        self._active: dict[ExecutionLease, _Record] = {}
        # Weak issuance evidence permits idempotent finish without retaining
        # completed jobs, outcomes or strong references to their owners.
        self._issued: weakref.WeakSet[ExecutionLease] = weakref.WeakSet()
        self._next_id = 0
        self._closing = False

    def reserve(self, intent: ExecutionIntent) -> ExecutionLease:
        if (type(intent) is not ExecutionIntent or type(intent.request) is not ExecutionRequest or
                intent.runtime_ready is not False or intent.request.dry_run is not False or
                type(intent.request.workspace) is not str or not intent.request.workspace or
                type(intent.request.timeout_seconds) is not int or
                not 1 <= intent.request.timeout_seconds <= 300):
            raise GatewayError("invalid_argument", "Invalid execution admission intent.")
        with self._condition:
            if self._closing:
                raise GatewayError("service_closing", "Execution admission is closing.")
            workspace = intent.request.workspace
            if len(self._active) >= 4 or any(lease.workspace == workspace for lease in self._active):
                raise GatewayError("exec_busy", "Execution capacity is occupied.")
            self._next_id += 1
            lease = ExecutionLease(f"exec-{self._next_id}", workspace)
            self._active[lease] = _Record(intent.request.timeout_seconds)
            self._issued.add(lease)
            return lease

    def _lookup(self, lease: ExecutionLease) -> _Record:
        if type(lease) is not ExecutionLease or lease not in self._issued or lease not in self._active:
            raise GatewayError("invalid_argument", "Invalid or completed execution lease.")
        return self._active[lease]

    def _now(self) -> float:
        # Never call injected code under the admission/state lock.
        now = self._clock()
        if type(now) not in (float, int) or not math.isfinite(now):
            raise GatewayError("exec_state", "Invalid monotonic execution clock.")
        return float(now)

    def record_attempt(self, lease: ExecutionLease) -> None:
        with self._condition:
            record = self._lookup(lease)
            if self._closing or record.state != "RESERVED":
                raise GatewayError("exec_state", "Execution attempt cannot be recorded.")
            record.state = "STARTING"

    def record_started(self, lease: ExecutionLease) -> None:
        now = self._now()
        with self._condition:
            record = self._lookup(lease)
            if record.state != "STARTING":
                raise GatewayError("exec_state", "Execution was not starting.")
            record.state = "RUNNING"
            record.deadline = now + record.timeout

    def request_stop(self, lease: ExecutionLease, reason: Literal["timeout", "shutdown"]) -> None:
        if reason not in ("timeout", "shutdown"):
            raise GatewayError("invalid_argument", "Invalid execution stop reason.")
        with self._condition:
            record = self._lookup(lease)
            if record.state not in ("RUNNING", "STOPPING"):
                raise GatewayError("exec_state", "Execution is not running.")
            if record.state != "STOPPING":
                record.state, record.stop_reason = "STOPPING", reason

    def mark_expired(self) -> tuple[str, ...]:
        now = self._now()
        expired = []
        with self._condition:
            for lease, record in self._active.items():
                if record.state == "RUNNING" and record.deadline is not None and now >= record.deadline:
                    record.state, record.stop_reason = "STOPPING", "timeout"
                    expired.append(lease.ticket_id)
        return tuple(expired)

    def finish(self, lease: ExecutionLease, outcome: ExecutionOutcome) -> None:
        if type(outcome) is not ExecutionOutcome:
            raise GatewayError("invalid_argument", "Invalid execution outcome.")
        with self._condition:
            if type(lease) is not ExecutionLease or lease not in self._issued:
                raise GatewayError("invalid_argument", "Unrecognized execution lease.")
            if lease not in self._active:
                return
            # Only the holder of the issued object can complete the record.
            # No reader, HTTP context manager, finalizer, or timer releases it.
            del self._active[lease]
            self._condition.notify_all()

    def begin_close(self) -> None:
        with self._condition:
            self._closing = True
            self._condition.notify_all()

    def wait_idle(self) -> None:
        with self._condition:
            while self._active:
                self._condition.wait()

    def snapshot(self) -> RegistrySnapshot:
        with self._condition:
            counts: dict[str, int] = {}
            for lease in self._active:
                counts[lease.workspace] = counts.get(lease.workspace, 0) + 1
            return RegistrySnapshot(len(self._active), tuple(sorted(counts.items())), self._closing)
