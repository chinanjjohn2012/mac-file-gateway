"""Dormant in-memory ownership for original direct children in proposed LBE V1.

This module is *not* imported by the running Gateway and never starts or
signals an operating-system process. An eventual authorized Worker must
separately enforce the approved operator grant, pinned Workspace/cwd and old
private-state admission BEFORE invoking the owner. Tests inject fake children;
a fake wait() is not native process or descendants cleanup evidence.

The unit of capacity and observed completion is the original direct child,
not the request waiter, a process group, or any descendant. There is no
retry, durable journal, PID-based recovery, signal or force-kill facility.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
import threading
import time
from typing import Protocol


class LbeOwnerError(RuntimeError):
    """An in-memory child-owner decision. No OS process status is implied."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class WaitableChild(Protocol):
    def wait(self) -> int:
        """Block until the *original* child exited and return its code."""


@dataclass(frozen=True)
class DirectObservation:
    status: str
    exit_code: int | None
    timed_out: bool
    process_may_be_running: bool
    cleanup_proven: bool = False
    full_descendant_tree_clean: str = "not_proven"


class _Reservation:
    """Private reference-identity token, never an externally reusable grant."""

    __slots__ = ("owner", "workspace", "phase", "child", "waiter",
                 "exit_code", "waiter_disconnected")

    def __init__(self, owner: "DirectChildOwner", workspace: str) -> None:
        self.owner = owner
        self.workspace = workspace
        self.phase = "VALIDATED"
        self.child: WaitableChild | None = None
        self.waiter: threading.Thread | None = None
        self.exit_code: int | None = None
        self.waiter_disconnected = False


class DirectChildOwner:
    """A single service's bounded ownership ledger; currently NOT wired.

    A reservation and its reaper Thread object are allocated before spawn.
    Only an explicit spawn_failed() can release a reservation with no child.
    After binding a child, *only observed wait()* completion releases capacity.
    If thread start/wait fails, latch unavailable and retain the slot. Timeout,
    disconnect, close and cancellation never signal an unqualified PID/PGID.
    """

    _TOTAL = 4

    def __init__(self) -> None:
        self._condition = threading.Condition(threading.RLock())
        self._pid = os.getpid()
        self._by_workspace: dict[str, _Reservation] = {}
        self._unavailable = False
        self._closing = False

    def _valid_process(self) -> bool:
        if os.getpid() != self._pid:
            # A fork must not inherit assumed direct-child ownership.
            self._unavailable = True
            return False
        return True

    def reserve(self, workspace: str) -> _Reservation:
        """Reserve one slot with a preallocated daemon reaper; no spawn."""
        with self._condition:
            if not self._valid_process() or self._unavailable:
                raise LbeOwnerError("exec_state_unavailable")
            if self._closing:
                raise LbeOwnerError("service_closing")
            if type(workspace) is not str or not workspace:
                raise LbeOwnerError("workspace_required")
            if workspace in self._by_workspace or len(self._by_workspace) >= self._TOTAL:
                raise LbeOwnerError("busy")
            item = _Reservation(self, workspace)
            try:
                # Preallocate the only required reaper object before any caller
                # has an opportunity to launch the original process.
                item.waiter = threading.Thread(
                    target=self._reap, args=(item,),
                    name="lbe-direct-child-reaper", daemon=True,
                )
            except (Exception, KeyboardInterrupt):
                self._unavailable = True
                raise LbeOwnerError("exec_state_unavailable") from None
            self._by_workspace[workspace] = item
            return item

    def _check(self, item: _Reservation) -> None:
        if (type(item) is not _Reservation or item.owner is not self
                or self._by_workspace.get(item.workspace) is not item):
            raise LbeOwnerError("invalid_reservation")

    def spawn_failed(self, item: _Reservation) -> None:
        """No child exists: release the reservation without signalling."""
        with self._condition:
            self._check(item)
            if item.phase != "VALIDATED":
                raise LbeOwnerError("invalid_reservation")
            item.phase = "SPAWN_FAILED"
            del self._by_workspace[item.workspace]
            self._condition.notify_all()

    def bind(self, item: _Reservation, child: WaitableChild) -> None:
        """Record an already-created original child; start its one waiter.

        A start failure AFTER the caller has spawned a child is uncertain.
        We deliberately retain its slot and permanently latch unavailable.
        The caller must not signal the child or claim it was reaped.
        """
        with self._condition:
            self._check(item)
            if item.phase != "VALIDATED" or item.waiter is None:
                raise LbeOwnerError("invalid_reservation")
            if child is None or not callable(getattr(child, "wait", None)):
                # Do not release: a malformed post-spawn handle cannot prove
                # there is no original direct child to wait for.
                self._unavailable = True
                raise LbeOwnerError("exec_state_unavailable")
            item.child = child
            item.phase = "DIRECT_CHILD_ACTIVE"
            try:
                item.waiter.start()
            except (Exception, KeyboardInterrupt):
                self._unavailable = True
                item.phase = "UNREAPABLE"
                self._condition.notify_all()
                raise LbeOwnerError("exec_state_unavailable") from None

    def _reap(self, item: _Reservation) -> None:
        try:
            child = item.child
            if child is None:
                raise RuntimeError("missing bound original child")
            code = child.wait()
            if type(code) is not int:
                raise RuntimeError("unqualified direct child exit code")
        except BaseException:
            with self._condition:
                # Do not recycle capacity or use PID signals if wait fails.
                self._unavailable = True
                item.phase = "UNREAPABLE"
                self._condition.notify_all()
            return
        with self._condition:
            item.exit_code = code
            item.phase = "DIRECT_CHILD_REAPED"
            # The actual original child, not the waiter, has exited.
            if self._by_workspace.get(item.workspace) is item:
                del self._by_workspace[item.workspace]
            self._condition.notify_all()

    def observe(self, item: _Reservation, *, wait_seconds: float) -> DirectObservation:
        """Wait for original-child exit without releasing slots on timeout.

        The host Worker must enforce its own externally configured integer
        timeout 1..300 s. This private primitive additionally permits zero
        so deterministic T0 tests can inspect an active fake child.
        """
        if type(wait_seconds) not in (float, int) or not 0 <= wait_seconds <= 300:
            raise LbeOwnerError("invalid_argument")
        deadline = time.monotonic() + wait_seconds
        with self._condition:
            if type(item) is not _Reservation or item.owner is not self:
                raise LbeOwnerError("invalid_reservation")
            if item.phase == "VALIDATED" or item.phase == "SPAWN_FAILED":
                raise LbeOwnerError("invalid_reservation")
            if item.waiter_disconnected:
                raise LbeOwnerError("waiter_disconnected")
            while item.phase == "DIRECT_CHILD_ACTIVE":
                if not self._valid_process():
                    raise LbeOwnerError("exec_state_unavailable")
                remain = deadline - time.monotonic()
                if remain <= 0:
                    # This is an annotation about the waiter only. Child still
                    # owns capacity; even a successful later exit cannot prove
                    # that detached descendants were cleaned.
                    return DirectObservation("timed_out", None, True, True)
                self._condition.wait(timeout=remain)
            if item.phase == "DIRECT_CHILD_REAPED":
                return DirectObservation("exited", item.exit_code, False, True)
            raise LbeOwnerError("exec_state_unavailable")

    def detach_waiter(self, item: _Reservation) -> None:
        """Record loss of caller/ACK; never cancel or release the child."""
        with self._condition:
            if type(item) is not _Reservation or item.owner is not self:
                raise LbeOwnerError("invalid_reservation")
            if item.phase in {"VALIDATED", "SPAWN_FAILED"}:
                raise LbeOwnerError("invalid_reservation")
            item.waiter_disconnected = True
            self._condition.notify_all()

    def snapshot(self) -> dict[str, int | bool]:
        """Status counts only known original child handles, never PID/PGID."""
        with self._condition:
            valid = self._valid_process()
            return {
                "running_direct_children": sum(
                    item.child is not None
                    for item in self._by_workspace.values()),
                "reserved_slots": len(self._by_workspace),
                "capacity_exhausted": len(self._by_workspace) >= self._TOTAL,
                "unavailable": self._unavailable or not valid,
                "closing": self._closing,
            }

    def close(self) -> None:
        """Refuse new reservations without joining or killing active children."""
        with self._condition:
            self._closing = True
            self._condition.notify_all()

