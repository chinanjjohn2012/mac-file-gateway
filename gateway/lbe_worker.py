"""Bounded LBE Worker for original-child ownership, output and result truth.

Public schema-v2 preview uses LbeWorker._check_plan through lbe_plan; the
ordinary public WorkspaceService/REST/MCP apply route still F1-denies
dry_run=False before any Worker launch. The separately owner-approved,
disposable GitHub-hosted Python-only T1 uses an injected real launcher and
Worker; other T0 tests inject fake children. No default Popen facility or
caller/config-granted positive Exec exists in this module.

Any future normal product apply needs a separately approved D0 exception
plus shared-service private-state, scope, origin and capacity enforcement
before a trusted launcher is supplied. No alternate public authorization.
"""
from __future__ import annotations

from dataclasses import dataclass
import threading
import time
from typing import Any, Callable, Protocol

from .lbe_direct_owner import DirectChildOwner, LbeOwnerError
from .core import GatewayError, _parts
from .executor import _validate_command
from .lbe_go_policy import GoPolicyError, _components
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
    """Trusted-context plan for preview or separately approved hosted T1.

    This is NOT positive execution authorization. It cannot upgrade F1/D0
    authority, replace pinned-FD checks or be supplied by an MCP caller.
    """

    workspace: str
    cwd: str
    requested_argv: tuple[str, ...]
    effective_argv: tuple[str, ...]
    runner: str
    runner_project: str
    timeout_seconds: int
    # Informational canonical Go -o target, not a write receipt or grant.
    planned_go_output: str | None = None
    planned_script_sha256: str | None = None
    planned_pipfile_sha256: str | None = None


class LbeWorker:
    """Injected child/pipe composition; no default launcher or public grant.

    Used with fake T0 children and in authorized disposable Python-only T1.
    Ordinary public positive Exec is NOT wired: F1 denies it before Worker.
    After a child starts, owner/reaper state survives errors and the caller
    never signals PID/PGID or assumes rollback/recovery.
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
                # Reject hostile comparator/hasher objects before membership.
                # A frozen dataclass does not enforce its field annotations.
                or type(plan.runner) is not str
                or plan.runner not in {"direct", "pipenv"}
                or type(plan.timeout_seconds) is not int
                or not 1 <= plan.timeout_seconds <= 300):
            raise LbeWorkerError("invalid_plan")
        if (plan.planned_go_output is not None
                and (type(plan.planned_go_output) is not str
                     or not plan.planned_go_output)):
            raise LbeWorkerError("invalid_plan")
        # Exact lowercase SHA-256 of bounded selected source bytes.
        # An untrusted caller object must never reach equality or hashing.
        for source_digest in (
            plan.planned_script_sha256, plan.planned_pipfile_sha256
        ):
            if (source_digest is not None
                    and (type(source_digest) is not str
                         or len(source_digest) != 64
                         or any(ch not in "0123456789abcdef"
                                for ch in source_digest))):
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
            if plan.planned_go_output is not None:
                # Unlike the generic file API normalizer, response metadata
                # must already be in the exact canonical Workspace form.
                if ("/".join(_parts(plan.planned_go_output))
                        != plan.planned_go_output):
                    raise LbeWorkerError("invalid_plan")
            if plan.requested_argv[0] == "go":
                if (plan.planned_script_sha256 is not None
                        or plan.planned_pipfile_sha256 is not None):
                    raise LbeWorkerError("invalid_plan")
                # Go build's -o and actual pinned output checks are *always*
                # mandatory in the shared service preflight. This internal
                # shape check is NOT a replacement for GoPolicy validation.
                if (len(plan.requested_argv) < 3
                        or plan.requested_argv[1] not in {"test", "vet", "build"}
                        or plan.runner != "direct"):
                    raise LbeWorkerError("invalid_plan")
                # Bind any Go -o preview target to the actual argv,
                # regardless of separated versus = syntax. This is a
                # shape check, NOT a substitute for the OS/path-policy
                # preflight in the trusted WorkspaceService.
                selected_output = None
                index = 2
                while index < len(plan.requested_argv):
                    token = plan.requested_argv[index]
                    if token == "-o" or token.startswith("-o="):
                        if (plan.requested_argv[1] != "build"
                                or selected_output is not None):
                            raise LbeWorkerError("invalid_plan")
                        if token == "-o":
                            index += 1
                            if index >= len(plan.requested_argv):
                                raise LbeWorkerError("invalid_plan")
                            output = plan.requested_argv[index]
                        else:
                            output = token[3:]
                        selected_output = "/".join((
                            *_parts(plan.cwd), *_components(output)))
                    index += 1
                if plan.planned_go_output != selected_output:
                    raise LbeWorkerError("invalid_plan")
            else:
                if plan.planned_go_output is not None:
                    raise LbeWorkerError("invalid_plan")
                script = _validate_command(list(plan.requested_argv))
                if (script is None) != (plan.planned_script_sha256 is None):
                    raise LbeWorkerError("invalid_plan")
        except (GatewayError, GoPolicyError):
            raise LbeWorkerError("invalid_plan") from None
        if plan.runner == "pipenv":
            if plan.planned_pipfile_sha256 is None:
                raise LbeWorkerError("invalid_plan")
            if plan.effective_argv != ("pipenv", "run", *plan.requested_argv):
                raise LbeWorkerError("invalid_plan")
        else:
            if plan.planned_pipfile_sha256 is not None:
                raise LbeWorkerError("invalid_plan")
            if plan.effective_argv != plan.requested_argv:
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
            "planned_go_output": plan.planned_go_output,
            "planned_script_sha256": plan.planned_script_sha256,
            "planned_pipfile_sha256": plan.planned_pipfile_sha256,
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
            # EOF is not terminal cleanup: expose the observed Reader finish
            # witness so every native/REST/MCP result can reject early clean
            # acceptance while selector.close is pending or faulting.
            "pipe_reader_finished": bool(output.get("pipe_reader_finished", False)),
            "output_limit_chars": 48000,
            "content_trust": "untrusted_command_output",
        }

    def run(self, plan: LbeWorkPlan, *,
            cancelled: threading.Event | None = None,
            product_attempt: object = None,
            r010_source_capture: object = None) -> dict[str, Any]:
        """Run via a trusted injected launcher, never public Exec authority.

        Fake T0 tests create no real child. The separately owner-approved
        hosted Python-only T1 does launch a real original child through this
        Worker; Go/Pipenv primary and ordinary product apply remain denied.
        Bind the preallocated reaper BEFORE attaching returned child pipes;
        an attachment failure retains wait() ownership and latches admission.
        """
        self._check_plan(plan)
        if r010_source_capture is not None:
            from .lbe_r010_private_capture import (
                R010PrivateCaptureDenied, R010PrivateWorkerCapture)
            if type(r010_source_capture) is not R010PrivateWorkerCapture:
                raise LbeWorkerError("invalid_worker_dependency")
            try:
                r010_source_capture._check_for_worker(self._owner, plan)
            except R010PrivateCaptureDenied:
                raise LbeWorkerError("invalid_worker_dependency") from None
        # Retain the exact launcher selected before rechecks or drain setup:
        # no injected callback may switch it between validation and invocation.
        launcher = self._launcher
        if cancelled is not None and type(cancelled) is not threading.Event:
            raise LbeWorkerError("invalid_argument")
        if product_attempt is not None:
            # Future internal R003 attempts must burn a plan-bound marker
            # atomically before any reservation/launch, even on cancellation.
            # This object is NOT native authority; no public service path can
            # supply it, and the current F1/Go/Pipenv refusal is unchanged.
            from .lbe_product_fixture import (
                D4FixtureDenied, D4OneUseAttemptMarker,
            )
            if type(product_attempt) is not D4OneUseAttemptMarker:
                raise LbeWorkerError("invalid_argument")
            try:
                product_attempt.consume_for(plan)
            except D4FixtureDenied:
                raise LbeWorkerError("attempt_replay_denied") from None
            # A prepared macOS Runner cannot lend its one-use source receipt
            # to a different launcher, even another bound method. Old fake
            # source-only T0 markers confer no executable authority.
            try:
                product_attempt.require_bound_launcher(launcher)
            except D4FixtureDenied:
                raise LbeWorkerError("invalid_worker_dependency") from None
        if cancelled is not None and cancelled.is_set():
            raise LbeWorkerError("waiter_disconnected")
        try:
            reservation = self._owner.reserve(plan.workspace)
        except LbeOwnerError as exc:
            raise LbeWorkerError(exc.code) from None
        if r010_source_capture is not None:
            try:
                r010_source_capture._bind_reserved(self._owner, reservation, plan)
            except BaseException:
                try:
                    self._owner.spawn_failed(reservation)
                except BaseException:
                    self._owner.latch_unavailable(reservation)
                raise LbeWorkerError("invalid_worker_dependency") from None
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
        # This last observed check is the best-effort launch-commit boundary:
        # if cancellation arrives AFTER this check (even before native Popen
        # returns), the launcher may already have started a child. Treat
        # postcheck cancellation as possibly started and leave child/reaper
        # ownership intact. No atomic OS Event/Popen guarantee is claimed.
        if cancelled is not None and cancelled.is_set():
            try:
                self._owner.spawn_failed(reservation)
            except BaseException:
                raise LbeWorkerError("exec_state_unavailable") from None
            raise LbeWorkerError("waiter_disconnected")

        if r010_source_capture is not None:
            # No Popen can occur before the SAME full six-row source packet
            # has been rechecked after the reservation/reader setup.
            try:
                r010_source_capture._recheck_six_source()
            except BaseException:
                try:
                    self._owner.spawn_failed(reservation)
                except BaseException:
                    self._owner.latch_unavailable(reservation)
                raise LbeWorkerError("invalid_worker_dependency") from None
        try:
            child = launcher(plan)
        except LbeNoChildStarted:
            # Explicit, reviewed launcher-side negative witness only.
            # Ordinary OSError/InterruptedError etc. cannot prove no child.
            try:
                self._owner.spawn_failed(reservation)
            except BaseException:
                raise LbeWorkerError("exec_state_unavailable") from None
            response = self._base(
                plan, status="launch_failed", executed=False, exit_code=None,
                timed_out=False, may_run=False,
                output={"output_complete": False},
            )
            if r010_source_capture is not None:
                r010_source_capture._record_worker_result(
                    self._owner, reservation, plan, response)
            return response
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
                    reader_finalized = drain.wait_finished(0.8)
                    output = drain.snapshot()
                    # EOF is not terminal reader health: close/unregister
                    # may still be pending, and a later cleanup failure may
                    # latch Owner AFTER an otherwise false clean response.
                    # Keep true original-child exit, but no clean receipt
                    # without observed reader-finalization.
                    if (not reader_finalized
                            or output["pipe_reader_finished"] is not True):
                        output["output_complete"] = False
                    if output["pipe_reader_failed"]:
                        self._owner.latch_unavailable(reservation)
                    response = self._base(
                        plan, status="exited", executed=True,
                        exit_code=obs.exit_code, timed_out=False, may_run=True,
                        output=output,
                    )
                    if r010_source_capture is not None:
                        r010_source_capture._record_worker_result(
                            self._owner, reservation, plan, response)
                    return response
                if remaining <= 0:
                    # Timeout annotates the waiter only: child/reaper/reader
                    # remain active; output_complete is never invented.
                    response = self._base(
                        plan, status="timed_out", executed=True,
                        exit_code=None, timed_out=True, may_run=True,
                        output=drain.snapshot(),
                    )
                    if r010_source_capture is not None:
                        r010_source_capture._record_worker_result(
                            self._owner, reservation, plan, response)
                    return response
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

