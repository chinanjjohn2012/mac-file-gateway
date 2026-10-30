"""T0 byte-cap/EOF/redaction boundaries for the dormant LBE output buffer.

No native pipe or subprocess IO is tested. A bounded reader/selector with
post-exit EOF grace is still required before any real positive Exec.
"""
from __future__ import annotations

import os
import subprocess
import threading

import pytest

from gateway.lbe_direct_owner import DirectChildOwner
from gateway.lbe_output_capture import BoundedCapture, LbeCaptureError


def test_initial_snapshot_is_empty_and_explicitly_incomplete():
    b = BoundedCapture()
    state = b.snapshot()
    assert state == {
        "stdout": "", "stderr": "",
        "stdout_truncated": False, "stderr_truncated": False,
        "output_complete": False,
    }
    assert b.stored_bytes() == 0


def test_chunks_accumulate_with_one_shared_stream_prefix():
    b = BoundedCapture()
    b.feed("stdout", b"alpha ")
    b.feed("stdout", b"beta")
    b.feed("stderr", b"message")
    state = b.snapshot()
    assert "alpha beta" in state["stdout"]
    assert "message" in state["stderr"]
    assert state["output_complete"] is False
    assert not state["stdout_truncated"]
    assert not state["stderr_truncated"]


def test_child_exit_does_not_automatically_prove_stream_eof():
    b = BoundedCapture()
    b.feed("stdout", b"parent returned, descendant may still own pipe")
    assert b.snapshot()["output_complete"] is False
    b.eof("stdout")
    assert b.snapshot()["output_complete"] is False
    b.eof("stderr")
    assert b.snapshot()["output_complete"] is True
    b.eof("stderr")  # repeated EOF is idempotent
    assert b.snapshot()["output_complete"] is True


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_each_stream_retains_at_most_48000_bytes_and_marks_truncation(stream):
    b = BoundedCapture()
    for _ in range(100):
        b.feed(stream, b"x" * 8192)
    assert b.stored_bytes() == 48000
    state = b.snapshot()
    assert state[stream + "_truncated"] is True
    assert len(state[stream]) <= 48000
    other = "stderr" if stream == "stdout" else "stdout"
    assert state[other] == ""
    assert state["output_complete"] is False
    b.eof("stdout")
    b.eof("stderr")
    assert b.snapshot()["output_complete"] is True


def test_both_stream_caps_bound_memory_independently():
    b = BoundedCapture()
    b.feed("stdout", b"x" * 200000)
    b.feed("stderr", b"y" * 200000)
    assert b.stored_bytes() == 96000
    s = b.snapshot()
    assert s["stdout_truncated"] and s["stderr_truncated"]
    assert s["output_complete"] is False


@pytest.mark.parametrize("kind", ["", "STDOUT", "foo", None, True, 1, b"stdout"])
def test_unknown_stream_rejected(kind):
    b = BoundedCapture()
    with pytest.raises(LbeCaptureError, match="stream"):
        b.feed(kind, b"ok")
    with pytest.raises(LbeCaptureError, match="stream"):
        b.eof(kind)
    assert b.stored_bytes() == 0


@pytest.mark.parametrize("payload", ["hello", bytearray(b"abc"), None, 1, True])
def test_feed_requires_exact_bytes_not_mutable_or_coercible(payload):
    b = BoundedCapture()
    with pytest.raises(LbeCaptureError, match="bytes"):
        b.feed("stdout", payload)
    assert b.stored_bytes() == 0


def test_feeding_after_observed_eof_rejected_without_modifying_snapshot():
    b = BoundedCapture()
    b.feed("stdout", b"hello")
    b.eof("stdout")
    before = b.snapshot()
    with pytest.raises(LbeCaptureError, match="EOF"):
        b.feed("stdout", b"secret later")
    assert b.snapshot() == before


def test_invalid_utf8_is_replaced_safely_and_bounds_still_hold():
    b = BoundedCapture()
    b.feed("stdout", b"hi-\xff-\xfe")
    state = b.snapshot()
    assert "hi-" in state["stdout"]
    assert "\ufffd" in state["stdout"]
    assert b.stored_bytes() == len(b"hi-\xff-\xfe")
    assert state["output_complete"] is False


def test_reservations_preallocate_independent_buffers_before_spawn():
    owner = DirectChildOwner()
    first = owner.reserve("a")
    second = owner.reserve("b")
    first.capture.feed("stdout", b"one")
    second.capture.feed("stderr", b"two")
    assert "one" in first.capture.snapshot()["stdout"]
    assert first.capture.snapshot()["stderr"] == ""
    assert "two" in second.capture.snapshot()["stderr"]
    assert second.capture.snapshot()["stdout"] == ""
    owner.spawn_failed(first)
    owner.spawn_failed(second)
    owner.close()


def test_no_subprocess_signal_or_file_io_in_memory_capture(monkeypatch):
    calls = []

    def forbidden(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("no native process or direct file open")

    with monkeypatch.context() as m:
        m.setattr(subprocess, "Popen", forbidden)
        m.setattr(os, "kill", forbidden)
        m.setattr(os, "killpg", forbidden, raising=False)
        b = BoundedCapture()
        b.feed("stdout", b"safe")
        b.eof("stdout")
        assert "safe" in b.snapshot()["stdout"]
        assert b.snapshot()["output_complete"] is False
    assert calls == []


def test_concurrent_fake_feeds_are_bounded_and_eof_truthful():
    b = BoundedCapture()
    ready = threading.Event()
    started = []

    def writer(stream):
        ready.wait(timeout=2)
        for _ in range(40):
            b.feed(stream, b"z" * 4096)
        b.eof(stream)

    threads = [threading.Thread(target=writer, args=(name,))
               for name in ("stdout", "stderr")]
    for t in threads:
        t.start()
        started.append(t)
    ready.set()
    for t in started:
        t.join(timeout=5)
        assert not t.is_alive()
    state = b.snapshot()
    assert state["output_complete"] is True
    assert state["stdout_truncated"] and state["stderr_truncated"]
    assert b.stored_bytes() == 96000

