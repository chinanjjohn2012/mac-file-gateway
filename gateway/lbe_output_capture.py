"""Dormant bounded byte capture for proposed LBE direct-child output.

Pure in-memory T0 component: no process, pipe reader, PID, OS selector or
signal is created here. A future authorized Worker must allocate and own
bounded/nonblocking pipe-drain resources *before* launching a real child,
continue draining while the child survives timeout/disconnect, and enforce a
bounded EOF grace after original-child exit. Buffer tests do NOT establish
those physical lifecycle properties.

Output uses the existing best-effort Gateway redactor. A truncated prefix
is not proof that the complete subprocess output was observed or safe.
"""
from __future__ import annotations

import threading
from typing import Any

_STREAMS = frozenset({"stdout", "stderr"})
_KEEP_PER_STREAM = 48_000


class LbeCaptureError(ValueError):
    """Invalid source-only output-stream operation."""


class BoundedCapture:
    """Thread-safe, at most 48 KB stored per stream; no plaintext logging."""

    def __init__(self) -> None:
        self._mutex = threading.Lock()
        self._bytes: dict[str, bytearray] = {
            "stdout": bytearray(), "stderr": bytearray(),
        }
        self._truncated = {"stdout": False, "stderr": False}
        self._eof = {"stdout": False, "stderr": False}

    @staticmethod
    def _check_stream(stream: str) -> None:
        if type(stream) is not str or stream not in _STREAMS:
            raise LbeCaptureError("unknown output stream")

    def feed(self, stream: str, chunk: bytes) -> None:
        """Consume raw bytes without buffering beyond the hard byte cap."""
        self._check_stream(stream)
        if type(chunk) is not bytes:
            raise LbeCaptureError("output chunk must be exact bytes")
        with self._mutex:
            if self._eof[stream]:
                raise LbeCaptureError("cannot feed after observed EOF")
            free = _KEEP_PER_STREAM - len(self._bytes[stream])
            if len(chunk) > free:
                self._truncated[stream] = True
            if free > 0:
                self._bytes[stream].extend(chunk[:free])

    def eof(self, stream: str) -> None:
        """Mark only an actually observed EOF; never infer it from exit."""
        self._check_stream(stream)
        with self._mutex:
            self._eof[stream] = True

    def stored_bytes(self) -> int:
        """Local diagnostic only, not intended for a public API response."""
        with self._mutex:
            return sum(len(value) for value in self._bytes.values())

    def snapshot(self) -> dict[str, Any]:
        """Best-effort redacted copy, with honest EOF and truncation facts."""
        with self._mutex:
            data = {name: bytes(buf) for name, buf in self._bytes.items()}
            truncated = dict(self._truncated)
            eof = dict(self._eof)

        # Reuse the existing source-reviewed output redaction and char cap.
        # Redaction happens on the combined retained bytes, not each chunk.
        from .executor import _bounded_text

        stdout, out_char_trunc = _bounded_text(data["stdout"])
        stderr, err_char_trunc = _bounded_text(data["stderr"])
        return {
            "stdout": stdout,
            "stderr": stderr,
            "stdout_truncated": truncated["stdout"] or out_char_trunc,
            "stderr_truncated": truncated["stderr"] or err_char_trunc,
            "output_complete": eof["stdout"] and eof["stderr"],
        }

