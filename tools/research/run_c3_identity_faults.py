#!/usr/bin/env python3
"""C3 P2 negative-control suite: separate *test-compiled* Darwin synthetic children.

Unauthorized negative-PGID call is always compiled behind C3_ID_TEST_KILL_STUB:
the injection returns ESRCH and NEVER invokes the real kill(-pgid) syscall.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
import sys
import tempfile
import time

NATIVE = Path(__file__).resolve().parent / "c3_identity_probe.c"
MODES = (
    "fault-unauthorized-esrch",
    "fault-broken-pipe",
    "fault-waiter-ready",
    "fault-waiter-timeout",
    "fault-waiter-result",
)
# attempts, after_loss_attempts, direct-PID signals, real EPIPE,
# contested, observed legitimate waiter completion, cleanup verified
EXPECTED = {
    "fault-unauthorized-esrch": (1, 1, 0, 0, 0, 0, 1),
    "fault-broken-pipe": (0, 0, 0, 1, 0, 0, 1),
    "fault-waiter-ready": (0, 0, 0, 0, 1, 1, 1),
    "fault-waiter-timeout": (0, 0, 0, 0, 1, 1, 1),
    "fault-waiter-result": (0, 0, 0, 0, 1, 1, 1),
}
REASONS = {
    "fault-unauthorized-esrch": "unauthorized_signal_attempt",
    "fault-broken-pipe": "broken_pipe_epipe",
    "fault-waiter-ready": "fault_waiter_ready",
    "fault-waiter-timeout": "fault_waiter_timeout",
    "fault-waiter-result": "fault_waiter_result",
}
_FIELDS = (
    "attempts", "after_loss_attempts", "pid_signals", "epipe",
    "waiter_contested", "waiter_done", "cleanup_complete", "reuse_proven",
)
_RE = re.compile(
    r"\AC3_ID_FAULT mode=(fault-unauthorized-esrch|fault-broken-pipe|"
    r"fault-waiter-ready|fault-waiter-timeout|fault-waiter-result)"
    r" attempts=([01]) after_loss_attempts=([01]) pid_signals=([01])"
    r" epipe=([01]) waiter_contested=([01]) waiter_done=([01])"
    r" cleanup_complete=([01]) reuse_proven=([01])\n\Z"
)


def parse_native(stdout: str) -> dict:
    match = _RE.fullmatch(stdout)
    if match is None:
        raise ValueError("malformed/duplicate/forged C3 native fault evidence")
    return {
        "mode": match.group(1),
        **dict(zip(_FIELDS, (int(v) for v in match.groups()[1:]))),
    }


def classify(mode: str, record: dict) -> str:
    if mode not in EXPECTED or type(record) is not dict:
        return "BLOCK"
    truth = EXPECTED[mode]
    expected = {"mode": mode, **dict(zip(_FIELDS, truth + (0,)))}
    if record.keys() != expected.keys() or any(
        type(record[k]) is not type(value) or record[k] != value
        for k, value in expected.items()
    ):
        return "BLOCK"
    return "EXPECTED_BLOCK"


def compile_native(binary: Path, *, suppress_attempt_counting: bool = False) -> bool:
    args = [
        "cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-pthread",
        "-DC3_ID_TEST_FAULTS", "-DC3_ID_TEST_KILL_STUB",
    ]
    if suppress_attempt_counting:
        args.append("-DC3_ID_TEST_SUPPRESS_ATTEMPT_ACCOUNTING")
    args.extend((str(NATIVE), "-o", str(binary)))
    try:
        build = subprocess.run(
            args, text=True, capture_output=True, timeout=35, check=False
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return build.returncode == 0


def run_one(binary: Path, root: Path, mode: str) -> dict:
    began = time.monotonic()
    try:
        completed = subprocess.run(
            (str(binary), mode, str(root)),
            capture_output=True, text=True, timeout=9, check=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        return {"mode": mode, "status": "BLOCK", "reason": "timeout_or_launch",
                "elapsed_ms": int((time.monotonic() - began) * 1000)}
    elapsed = int((time.monotonic() - began) * 1000)
    if (completed.returncode != 70 or
        completed.stderr != "C3_ID_BLOCK phase=" + REASONS[mode] + "\n"):
        return {"mode": mode, "status": "BLOCK", "reason": "invalid_block_exit",
                "elapsed_ms": elapsed}
    try:
        record = parse_native(completed.stdout)
    except ValueError:
        return {"mode": mode, "status": "BLOCK", "reason": "native_record_invalid",
                "elapsed_ms": elapsed}
    return {**record, "status": classify(mode, record), "elapsed_ms": elapsed}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parsed = parser.parse_args()
    if sys.platform != "darwin" or platform.machine() != "arm64":
        print("C3_ID_FAULT_NOT_RUN_NON_DARWIN; G2 BLOCK")
        return 3
    place = parsed.evidence_dir
    information = os.lstat(place)
    if (not stat.S_ISDIR(information.st_mode) or
        information.st_uid != os.geteuid() or information.st_mode & 0o077):
        print("C3_ID_FAULT_BLOCK evidence_dir_not_private")
        return 4

    with tempfile.TemporaryDirectory(prefix="c3-id-faults-") as dirname:
        root = Path(dirname)
        os.chmod(root, 0o700)
        marker = root / "C3_ID_TEST_MARKER"
        marker.write_bytes(b"synthetic")
        os.chmod(marker, 0o600)
        fault_binary = root / "c3_identity_native"
        if not compile_native(fault_binary):
            print("C3_ID_FAULT_BLOCK native_compile")
            return 4
        cases = [run_one(fault_binary, root, mode) for mode in MODES]
        # Source-mutation RED/GREEN: if pre-syscall accounting is removed,
        # the ESRCH stub remains safe but the evidence MUST fail classification.
        mutant_root = root / "mutant"
        mutant_root.mkdir(mode=0o700)
        mutant_marker = mutant_root / "C3_ID_TEST_MARKER"
        mutant_marker.write_bytes(b"synthetic")
        os.chmod(mutant_marker, 0o600)
        # The C private_root policy requires this exact executable basename.
        mutant = mutant_root / "c3_identity_native"
        if not compile_native(mutant, suppress_attempt_counting=True):
            print("C3_ID_FAULT_BLOCK mutation_compile")
            return 4
        mutated = run_one(mutant, mutant_root, "fault-unauthorized-esrch")
        mutation_detected = (
            mutated.get("status") == "BLOCK"
            and mutated.get("attempts") == 0
            and mutated.get("after_loss_attempts") == 0
        )

    accepted = (
        all(c["status"] == "EXPECTED_BLOCK" and
            c["elapsed_ms"] < 6500 and c["pid_signals"] == 0 and
            c["cleanup_complete"] == 1
            for c in cases)
        and mutation_detected
    )
    decision = "FAULT_CONTROLS_PASS_NOT_G2" if accepted else "BLOCK_RESEARCH"
    evidence = {
        "decision": decision, "g2_qualified": False,
        "native_os": "Darwin", "native_arch": "arm64",
        "python_version": platform.python_version(),
        "cases": cases, "mutation_detected": mutation_detected,
        "pid_pgid_reuse": "NOT_PROVEN",
    }
    output = place / "c3_identity_faults_private.json"
    output.write_text(json.dumps(evidence, sort_keys=True, indent=2) + "\n",
                      encoding="utf-8")
    os.chmod(output, 0o600)
    for c in cases:
        print("C3_ID_FAULT_CASE mode={mode} status={status} "
              "attempts={attempts} after_loss_attempts={late} "
              "pid_signals={pid} epipe={epipe} waiter_done={done} "
              "cleanup_complete={cleanup}".format(
                  mode=c["mode"], status=c["status"],
                  attempts=c.get("attempts", -1),
                  late=c.get("after_loss_attempts", -1),
                  pid=c.get("pid_signals", -1), epipe=c.get("epipe", -1),
                  done=c.get("waiter_done", -1),
                  cleanup=c.get("cleanup_complete", -1)))
    print("C3_ID_FAULT_MUTATION_DETECTED=" + str(mutation_detected).lower())
    print("C3_ID_FAULT_RESULT=" + decision)
    return 0 if accepted else 2


if __name__ == "__main__":
    raise SystemExit(main())
