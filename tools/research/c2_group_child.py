#!/usr/bin/env python3
"""Disposable synthetic descendants for C2. Never load into Gateway."""
from __future__ import annotations

import os
import signal
import sys
import time

MODES = (
    "term", "kill", "worker-first", "leader-exit", "stale", "close-stdout",
    "deadline-before-term", "term-false-eof", "fault-register",
    "fault-before-arm", "fault-after-arm", "fault-waitpid-eintr",
    "fault-kevent-eintr",
)
MAX_LIFETIME_SECONDS = 5.0


def spawn_descendant():
    read_end, write_end = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(read_end)
        # Install the synthetic negative control BEFORE the parent sees readiness.
        # The group leader remains TERM-terminable; only this descendant ignores it.
        if sys.argv[1] in ("close-stdout", "term-false-eof"):
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
        try:
            os.write(write_end, b"R")
        finally:
            os.close(write_end)
        # Second byte is an explicit arm barrier: no synthetic TTL starts until
        # the native parent has registered NOTE_EXIT on this still-living PID.
        if os.read(0, 1) != b"A":
            os._exit(13)
        if sys.argv[1] in ("close-stdout", "term-false-eof"):
            os.close(1)  # EOF can now occur without this descendant exiting.
        time.sleep(MAX_LIFETIME_SECONDS if sys.argv[1] not in ("leader-exit", "stale") else 1.5)
        os._exit(0)
    os.close(write_end)
    ready = os.read(read_end, 1)
    os.close(read_end)
    if ready != b"R":
        raise RuntimeError("synthetic descendant did not become ready")
    return pid


def worker_first_descendant():
    report_read, report_write = os.pipe()
    worker_pid = os.fork()
    if worker_pid == 0:
        os.close(report_read)
        descendant_pid = spawn_descendant()
        os.write(report_write, str(descendant_pid).encode("ascii") + b"\n")
        os.close(report_write)
        os._exit(0)
    os.close(report_write)
    report = os.read(report_read, 64)
    os.close(report_read)
    os.waitpid(worker_pid, 0)
    # The intermediate workload leader is gone; the original owned group anchor lives.
    return int(report.strip().decode("ascii"))


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in MODES:
        return 2
    if os.read(0, 1) != b"R":
        return 3
    mode = sys.argv[1]
    if mode == "kill":
        # TERM-resistant synthetic group: force authorized KILL escalation.
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
    descendant = worker_first_descendant() if mode == "worker-first" else spawn_descendant()
    print(f"C2_READY descendant={descendant} group={os.getpgrp()}", flush=True)
    if mode == "leader-exit":
        os._exit(0)
    # For refusal cases this short deadline stops descendants without group signaling.
    time.sleep(1.7 if mode == "stale" else MAX_LIFETIME_SECONDS)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
