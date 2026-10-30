"""Dormant LBE original-child stdout/stderr nonblocking reader.

A future *separately approved* Worker may attach the two original-child PIPE
objects to a single preallocated selector/thread, then signal observed direct
exit with note_original_exit(). The reader keeps draining past a timed-out
waiter without retaining unbounded output. After witnessed direct-child exit,
the reader waits only a bounded EOF grace before closing parent-side pipes.
EOF is only marked on an actual zero-length read, never on exit/closure.

This source is NOT imported into a live positive Exec path; construction does
not spawn a process or send signals. T0 tests inject fake selectors/readers
rather than claiming an actual macOS/Linux native-pipe integration.
"""
from __future__ import annotations

import os
import selectors
import threading
import time
from typing import Any, Callable

from .lbe_output_capture import BoundedCapture

_READ_SIZE = 8192
_POLL_SECONDS = 0.04
_EOF_GRACE_SECONDS = 0.25


class LbePipeError(RuntimeError):
    """A pipe-reader resource/setup/error state, without raw OS details."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class BoundedPipeDrain:
    """At most two read FDs and ONE reader thread per attached direct child.

    Callers must construct this BEFORE future child launch and guarantee that
    the reaper notifies observed direct exit. If an attachment fails AFTER a
    child launched, the owner MUST latch admission unavailable; it cannot
    signal an unqualified process or free a live child's slot.
    """

    def __init__(
        self,
        capture: BoundedCapture,
        *,
        selector_factory: Callable[[], Any] = selectors.DefaultSelector,
        read_fn: Callable[[int, int], bytes] = os.read,
        set_nonblocking: Callable[[int, bool], None] = os.set_blocking,
        clock: Callable[[], float] = time.monotonic,
        eof_grace: float = _EOF_GRACE_SECONDS,
    ) -> None:
        if type(capture) is not BoundedCapture:
            raise LbePipeError("invalid_capture")
        if type(eof_grace) not in (int, float) or not 0 <= eof_grace <= 1:
            raise LbePipeError("invalid_eof_grace")
        # Resource allocation before any future child can be launched.
        self._selector = selector_factory()
        self._thread = threading.Thread(
            target=self._drain, name="lbe-pipe-drainer", daemon=True)
        self._capture = capture
        self._read = read_fn
        self._set_nonblocking = set_nonblocking
        self._clock = clock
        self._eof_grace = float(eof_grace)
        self._original_exited = threading.Event()
        self._done = threading.Event()
        self._mutex = threading.Lock()
        self._pipes: dict[str, Any] = {}
        self._armed = False
        self._closed = False
        self._fault = False

    def attach(self, stdout: Any, stderr: Any) -> None:
        """Adopt both PIPE objects; register no-follow FD read interest.

        Post-launch failure is *not* proof of child absence. Close only
        parent-side output resources and surface the error to the owner.
        """
        with self._mutex:
            if self._armed or self._closed:
                raise LbePipeError("invalid_pipe_state")
            self._armed = True
            self._pipes = {"stdout": stdout, "stderr": stderr}
            try:
                fds = {}
                for name, pipe in self._pipes.items():
                    fd = pipe.fileno()
                    if type(fd) is not int or fd < 0 or fd in fds.values():
                        raise ValueError("invalid or duplicate pipe FD")
                    fds[name] = fd
                for name, fd in fds.items():
                    self._set_nonblocking(fd, False)
                    self._selector.register(fd, selectors.EVENT_READ, name)
                # The OS-Popen path is NOT wired yet; source-only T0 fakes test
                # this preallocated reader thread's complete state machine.
                self._thread.start()
                return
            except BaseException:
                self._fault = True
                self._release_resources()
                self._done.set()
                raise LbePipeError("pipe_setup_unavailable") from None

    def note_original_exit(self) -> None:
        """May be called by a trusted reaper only, never by a REST/MCP user."""
        self._original_exited.set()

    def _release_resources(self) -> None:
        # Called with _mutex held at setup or from the lone reader on finish.
        try:
            self._selector.close()
        except Exception:
            self._fault = True
        for pipe in self._pipes.values():
            try:
                pipe.close()
            except Exception:
                self._fault = True
        self._pipes.clear()
        self._closed = True

    def _drain(self) -> None:
        open_streams = set(self._pipes)
        deadline = None
        try:
            while open_streams:
                if self._original_exited.is_set():
                    if deadline is None:
                        deadline = self._clock() + self._eof_grace
                    if self._clock() >= deadline:
                        break
                    timeout = min(_POLL_SECONDS, max(0.0, deadline - self._clock()))
                else:
                    timeout = _POLL_SECONDS
                ready = self._selector.select(timeout)
                for key, _mask in ready:
                    name = key.data
                    if name not in open_streams:
                        continue
                    try:
                        chunk = self._read(key.fd, _READ_SIZE)
                    except BlockingIOError:
                        continue
                    if type(chunk) is not bytes:
                        raise LbePipeError("invalid_pipe_read")
                    if chunk:
                        self._capture.feed(name, chunk)
                    else:
                        # Only zero-length os.read proves EOF for THIS pipe.
                        self._capture.eof(name)
                        open_streams.remove(name)
                        self._selector.unregister(key.fd)
                        self._pipes[name].close()
                # A descendant may hold pipe FDs after the direct child
                # exited; the deadline closes them without inferring EOF.
        except BaseException:
            self._fault = True
        finally:
            with self._mutex:
                self._release_resources()
            self._done.set()

    def abandon_without_child(self) -> None:
        """Release preallocated resources when spawn did not occur."""
        with self._mutex:
            if self._armed or self._closed:
                raise LbePipeError("invalid_pipe_state")
            self._release_resources()
            self._done.set()

    def snapshot(self) -> dict[str, Any]:
        """A bounded/redacted snapshot; completion and errors remain separate."""
        output = self._capture.snapshot()
        with self._mutex:
            return {
                **output,
                "pipe_reader_failed": self._fault,
                "pipe_reader_finished": self._done.is_set(),
            }

    def wait_finished(self, timeout: float = 1.0) -> bool:
        if type(timeout) not in (int, float) or not 0 <= timeout <= 10:
            raise LbePipeError("invalid_argument")
        return self._done.wait(timeout)

