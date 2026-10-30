"""Dormant LBE Worker orchestration: ONE original child, pipe drain and truth.

This module is NOT imported from the public WorkspaceService/REST/MCP Exec
apply route. F1 always rejects dry_run=False before reaching any launcher.
Its mandatory launcher is an injected callable, with NO default Popen or OS
spawn facility. T0 tests provide fake original-child/pipe objects only.

After independent exact-version D0 exception approval, the normal synchronous
WorkspaceService must validate operator configuration, private state, pinned
root/cwd, command/output scope, runner and Exec capacity BEFORE constructing
a trusted plan and supplying its separately reviewed real launcher. There
must never be an alternative public or caller-provided Exec authorization.
"""
from __future__ import annotations

from dataclasses import dataclass
import threading
import time
from typing import Any, Callable, Protocol

from .lbe_direct_owner import DirectChildOwner, LbeOwnerError
from .core import GatewayError, _parts
from .executor import _validate_command
from .lbe_pipe_drain import BoundedPipeDrain, LbePipeError


class LbeWorkerError(RuntimeError):
    """Sanitized attempt error; true means a direct child may have launched."""

    def __init__(self, code: str, *, process_may_be_running: bool = False) -> None:
        self.code = code
        self.process_may_be_running = process_may_be_running
        super().__init__(code)


class LbeNoChildStarted(Exception):
    """Trusted launcher witness: launch rejected BEFORE any child existed.

    A general OSError/FileNotFoundError is never this proof. Only the future
    reviewed launcher may emit this explicit negative launch witness.
    """


class OriginalChild(Protocol):
    stdout: Any
    stderr: Any

    def wait(self) -> int:
        """Reap only the direct child; never assume descendants are gone."""


@dataclass(frozen=True)
class LbeWorkPlan:
    """Data from a future *already-authorized* shared service decision.

    This is not a grant or a safe command validator. The plan cannot upgrade
    private F1/D0 authority, replace pinned-FD checks or be submitted by MCP.
    """

    workspace: str
    cwd: str
    requested_argv: tuple[str, ...]
    effective_argv: tuple[str, ...]
    runner: str
    runner_project: str
    timeout_seconds: int


class LbeWorker:
    """Source-only composition of an owned child and bounded output drain.

    No default launcher exists; this Worker is not wired to production.
    Once a direct child exists, every error retains its owner/reaper; the
    caller never sends PID/PGID signals or assumes rollback/recovery.
    """

    def __init__(
        self, owner: DirectChildOwner, *,
        launcher: Callable[[LbeWorkPlan], OriginalChild],
        drain_factory: Callable[[Any], BoundedPipeDrain] = BoundedPipeDrain,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if type(owner) is not DirectChildOwner:
            raise LbeWorkerError("invalid_owner")
        if not callable(launcher) or not callable(drain_factory) or not callable(clock):
            raise LbeWorkerError("invalid_worker_dependency")
        self._owner = owner
        self._launcher = launcher
        self._drain_factory = drain_factory
        self._clock = clock

    @staticmethod
    def _check_plan(plan: LbeWorkPlan) -> None:
        if type(plan) is not LbeWorkPlan:
            raise LbeWorkerError("invalid_plan")
        if (type(plan.workspace) is not str or not plan.workspace
                or type(plan.cwd) is not str or not plan.cwd
                or type(plan.runner_project) is not str or not plan.runner_project
                or plan.runner not in {"direct", "pipenv"}
                or type(plan.timeout_seconds) is not int
                or not 1 <= plan.timeout_seconds <= 300):
            raise LbeWorkerError("invalid_plan")
        for argv in (plan.requested_argv, plan.effective_argv):
            if (type(argv) is not tuple or not 1 <= len(argv) <= 64
                    or sum(len(s) for s in argv if type(s) is str) > 8192
                    or any(type(s) is not str or not s or len(s) > 1024
                           or "\x00" in s or any(ord(c) < 32 for c in s)
                           for s in argv)):
                raise LbeWorkerError("invalid_plan")
        try:
            _parts(plan.cwd)
            _parts(plan.runner_project)
            if plan.requested_argv[0] == "go":
                # Go build's -o and actual pinned output checks are *always*
                # mandatory in the shared service preflight. This internal
                # shape check is NOT a replacement for GoPolicy validation.
                if (len(plan.requested_argv) < 3
                        or plan.requested_argv[1] not in {"test", "vet", "build"}
                        or plan.runner != "direct"):
                    raise LbeWorkerError("invalid_plan")
            else:
                _validate_command(list(plan.requested_argv))
        except GatewayError:
            raise LbeWorkerError("invalid_plan") from None
        if plan.runner == "pipenv":
            if plan.effective_argv != ("pipenv", "run", *plan.requested_argv):
                raise LbeWorkerError("invalid_plan")
        elif plan.effective_argv != plan.requested_argv:
            raise LbeWorkerError("invalid_plan")

    @staticmethod
    def _base(plan: LbeWorkPlan, *, status: str, executed: bool,
              exit_code: int | None, timed_out: bool,
              may_run: bool, output: dict[str, Any]) -> dict[str, Any]:
        return {
            "workspace": plan.workspace,
            "cwd": plan.cwd,
            "requested_argv": list(plan.requested_argv),
            "effective_argv": list(plan.effective_argv),
            "runner": plan.runner,
            "runner_project": plan.runner_project,
            "dry_run": False,
            "mode": "local_best_effort",
            "status": status,
            "executed": executed,
            "exit_code": exit_code,
            "timed_out": timed_out,
            "process_may_be_running": may_run,
            "cleanup_proven": False,
            "full_descendant_tree_clean": "not_proven",
            "stdout": output.get("stdout", ""),
            "stderr": output.get("stderr", ""),
            "stdout_truncated": bool(output.get("stdout_truncated", False)),
            "stderr_truncated": bool(output.get("stderr_truncated", False)),
            "output_complete": bool(output.get("output_complete", False)),
            "pipe_reader_failed": bool(output.get("pipe_reader_failed", False)),
            "output_limit_chars": 48000,
            "content_trust": "untrusted_command_output",
        }

    def run(self, plan: LbeWorkPlan, *,
            cancelled: threading.Event | None = None) -> dict[str, Any]:
        """Run with an injected launcher; no OS process is created by tests.

        Once a child is returned, bind the preallocated original-child reaper
        BEFORE attaching pipes; if pipe registration fails, the reaper keeps
        wait() ownership and admission becomes unavailable.
        """
        self._check_plan(plan)
        if cancelled is not None and type(cancelled) is not threading.Event:
            raise LbeWorkerError("invalid_argument")
        if cancelled is not None and cancelled.is_set():
            raise LbeWorkerError("waiter_disconnected")
        try:
            reservation = self._owner.reserve(plan.workspace)
        except LbeOwnerError as exc:
            raise LbeWorkerError(exc.code) from None
        drain = None
        try:
            drain = self._drain_factory(reservation.capture)
            self._owner.prepare_pipe_drain(reservation, drain)
        except BaseException:
            # No child can exist yet. The drain factory may have returned a
            # selector that the owner never adopted: close it explicitly.
            if drain is not None and reservation.pipe_drain is not drain:
                try:
                    drain.abandon_without_child()
                except BaseException:
                    self._owner.latch_unavailable(reservation)
                    raise LbeWorkerError("exec_state_unavailable") from None
            try:
                self._owner.spawn_failed(reservation)
            except BaseException:
                raise LbeWorkerError("exec_state_unavailable") from None
            raise LbeWorkerError("exec_state_unavailable") from None

        # A disconnect can arrive while preallocating the selector/reader.
        # Recheck before invoking the only launcher callback. This is still
        # a proven no-child path; release its reservation and pipe resources.
        # Never start a new command for a waiter already observed as cancelled.
        if cancelled is not None and cancelled.is_set():
            try:
                self._owner.spawn_failed(reservation)
            except BaseException:
                raise LbeWorkerError("exec_state_unavailable") from None
            raise LbeWorkerError("waiter_disconnected")

        try:
            child = self._launcher(plan)
        except LbeNoChildStarted:
            # Explicit, reviewed launcher-side negative witness only.
            # Ordinary OSError/InterruptedError etc. cannot prove no child.
            try:
                self._owner.spawn_failed(reservation)
            except BaseException:
                raise LbeWorkerError("exec_state_unavailable") from None
            return self._base(
                plan, status="launch_failed", executed=False, exit_code=None,
                timed_out=False, may_run=False,
                output={"output_complete": False},
            )
        except BaseException:
            # No negative witness exists; even a native OSError might have
            # occurred AFTER a child was launched and before it was returned.
            # Preserve the uncertain slot and refuse all further admission.
            self._owner.latch_unavailable(reservation)
            raise LbeWorkerError(
                "exec_state_unavailable", process_may_be_running=True,
            ) from None

        try:
            # Do not let pipe setup failures disable the original wait().
            self._owner.bind(reservation, child)
            drain.attach(child.stdout, child.stderr)
        except BaseException:
            self._owner.latch_unavailable(reservation)
            raise LbeWorkerError(
                "exec_state_unavailable", process_may_be_running=True,
            ) from None

        try:
            deadline = self._clock() + plan.timeout_seconds
            while True:
                if cancelled is not None and cancelled.is_set():
                    self._owner.detach_waiter(reservation)
                    # No ACK or retry is promised for a disconnected client.
                    raise LbeWorkerError(
                        "waiter_disconnected", process_may_be_running=True,
                    )
                remaining = max(0.0, deadline - self._clock())
                # Short bounded waits let us observe client cancellation
                # without changing reaper/pipe ownership.
                obs = self._owner.observe(
                    reservation, wait_seconds=min(remaining, 0.04),
                )
                if obs.status == "exited":
                    # The reader may still be draining after witnessed exit.
                    # EOF grace is already bounded independently in drain.
                    drain.wait_finished(0.8)
                    output = drain.snapshot()
                    if output["pipe_reader_failed"]:
                        self._owner.latch_unavailable(reservation)
                    return self._base(
                        plan, status="exited", executed=True,
                        exit_code=obs.exit_code, timed_out=False, may_run=True,
                        output=output,
                    )
                if remaining <= 0:
                    # Timeout annotates the waiter only: child/reaper/reader
                    # remain active; output_complete is never invented.
                    return self._base(
                        plan, status="timed_out", executed=True,
                        exit_code=None, timed_out=True, may_run=True,
                        output=drain.snapshot(),
                    )
        except LbeWorkerError:
            raise
        except BaseException:
            # Lost caller does not release child and never signals unknown PID.
            try:
                self._owner.detach_waiter(reservation)
            except LbeOwnerError:
                pass
            raise LbeWorkerError(
                "exec_state_unavailable", process_may_be_running=True,
            ) from None

