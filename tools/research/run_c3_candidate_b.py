#!/usr/bin/env python3
"""B-01 genuine, bounded, *synthetic* Darwin cross-parent PGID join probe.

No PID, PGID, executable, command or Workspace is accepted from the caller.
No negative-PGID signals are present in this B-01 experiment. G2 BLOCK.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time

NATIVE = Path(__file__).resolve().parent / "c3_candidate_b_anchor.c"
MODES = (
    "join-positive", "owner-reject-missing", "join-nonexistent",
    "join-cross-session", "gate-denied",
)
_FIELDS = (
    "anchor_held", "controller_outside", "sid_distinct", "spawn_attempted",
    "worker_spawned", "join_verified", "parentage_verified", "owner_granted",
    "gate_opened", "workload_started", "controller_waited",
    "cleanup_complete", "reuse_proven", "g2_qualified",
)
# anchor, controller_outside, different_sid, spawn_called, worker_created,
# genuine_join, correct_reported_parentage, authorized, gate, work,
# controller_waited, cleanup, verdict.
EXPECTED = {
    "join-positive":        (1,1,0,1,1,1,1,1,1,1,1,1,"POSITIVE_EXPERIMENT"),
    "owner-reject-missing": (0,0,0,0,0,0,0,0,0,0,0,1,"EXPECTED_BLOCK"),
    "join-nonexistent":    (0,1,0,1,0,0,0,0,0,0,0,1,"EXPECTED_BLOCK"),
    "join-cross-session":  (1,1,1,1,0,0,0,0,0,0,0,1,"EXPECTED_BLOCK"),
    "gate-denied":         (1,1,0,1,1,1,1,0,0,0,1,1,"EXPECTED_BLOCK"),
}
_RE = re.compile(
    r"\AC3B_RESULT mode=(join-positive|owner-reject-missing|join-nonexistent|"
    r"join-cross-session|gate-denied)"
    + "".join(r" " + field + r"=([01])" for field in _FIELDS)
    + r"\n\Z"
)


def parse_native(stdout: str) -> dict:
    match = _RE.fullmatch(stdout)
    if not match:
        raise ValueError("missing, repeated or forged native observation")
    return {
        "mode": match.group(1),
        **dict(zip(_FIELDS, (int(s) for s in match.groups()[1:]))),
    }


def classify(mode: str, record: dict) -> str:
    if mode not in EXPECTED or type(record) is not dict:
        return "BLOCK"
    wanted = {
        "mode": mode,
        **dict(zip(_FIELDS, EXPECTED[mode][:-1] + (0, 0))),
    }
    if record.keys() != wanted.keys() or any(
        type(record[k]) is not type(expected) or record[k] != expected
        for k, expected in wanted.items()
    ):
        return "BLOCK"
    return EXPECTED[mode][-1]


def run_case(binary: Path, root: Path, mode: str) -> dict:
    before = time.monotonic()
    try:
        p = subprocess.run(
            (str(binary), mode, str(root)), text=True, capture_output=True,
            timeout=9, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {"mode": mode, "status": "BLOCK",
                "reason": "native_launch_or_timeout", "elapsed_ms": -1}
    elapsed = int((time.monotonic() - before) * 1000)
    if p.returncode != 0 or p.stderr:
        return {"mode": mode, "status": "BLOCK",
                "reason": "native_failed", "elapsed_ms": elapsed}
    try:
        obs = parse_native(p.stdout)
    except ValueError:
        return {"mode": mode, "status": "BLOCK",
                "reason": "native_invalid_record", "elapsed_ms": elapsed}
    return {**obs, "status": classify(mode, obs), "elapsed_ms": elapsed}


def main() -> int:
    arg = argparse.ArgumentParser(description=__doc__)
    arg.add_argument("--evidence-dir", type=Path, required=True)
    parsed = arg.parse_args()
    if sys.platform != "darwin" or platform.machine() != "arm64":
        print("C3B_NOT_RUN_NON_DARWIN; G2 BLOCK")
        return 3
    evidence_dir = parsed.evidence_dir
    st = os.lstat(evidence_dir)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid() or (st.st_mode & 0o077):
        print("C3B_BLOCK untrusted_evidence_directory")
        return 4

    with tempfile.TemporaryDirectory(prefix="c3b-synthetic-") as path:
        private = Path(path)
        os.chmod(private, 0o700)
        compile_binary = private / "c3_candidate_b_compiled"
        try:
            built = subprocess.run(
                ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-pthread",
                 str(NATIVE), "-o", str(compile_binary)],
                text=True, capture_output=True, timeout=40, check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            print("C3B_BLOCK compiler_unavailable")
            return 4
        if built.returncode != 0:
            # Toolchain details stay private; public CI never emits user paths.
            print("C3B_BLOCK compile_error")
            return 4
        cases = []
        for mode in MODES:
            root = private / mode
            root.mkdir(mode=0o700)
            os.chmod(root, 0o700)
            marker = root / "C3B_TEST_MARKER"
            marker.write_bytes(b"synthetic")
            os.chmod(marker, 0o600)
            binary = root / "c3_candidate_b_native"
            shutil.copyfile(compile_binary, binary)
            os.chmod(binary, 0o700)
            cases.append(run_case(binary, root, mode))
        # Mutation: a Worker file-action/attribute preparation failure must
        # never be accepted as evidence of native posix_spawn group rejection.
        mutant_compiled = private / "c3b_mutant_compiled"
        try:
            mutant_build = subprocess.run(
                ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-pthread",
                 "-DC3B_FAULT_PRESPAWN", str(NATIVE), "-o", str(mutant_compiled)],
                text=True, capture_output=True, timeout=40, check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            print("C3B_BLOCK mutation_compile_unavailable")
            return 4
        if mutant_build.returncode != 0:
            print("C3B_BLOCK mutation_compile")
            return 4
        mutant_root = private / "mutation"
        mutant_root.mkdir(mode=0o700)
        os.chmod(mutant_root, 0o700)
        marker = mutant_root / "C3B_TEST_MARKER"
        marker.write_bytes(b"synthetic")
        os.chmod(marker, 0o600)
        mutant = mutant_root / "c3_candidate_b_native"
        shutil.copyfile(mutant_compiled, mutant)
        os.chmod(mutant, 0o700)
        try:
            m = subprocess.run(
                (str(mutant), "join-nonexistent", str(mutant_root)),
                capture_output=True, text=True, timeout=9, check=False,
            )
            mutation_detected = (
                m.returncode == 70
                and m.stdout == (
                    "C3B_MUTATION mode=join-nonexistent invoked=0 "
                    "gate=0 worker_started=0\n"
                )
                and m.stderr == "C3B_BLOCK phase=typed_outcome\n"
            )
        except (OSError, subprocess.TimeoutExpired):
            mutation_detected = False
    success = (
        mutation_detected and
        [c["status"] for c in cases] == [EXPECTED[m][-1] for m in MODES]
        and all(0 <= c["elapsed_ms"] < 6000 and
                c.get("cleanup_complete") == 1 and
                c.get("reuse_proven") == 0 and
                c.get("g2_qualified") == 0
                for c in cases)
    )
    decision = "PARTIAL_B01_NATIVE_NOT_G2" if success else "BLOCK_RESEARCH"
    evidence = {
        "decision": decision, "g2_qualified": False, "reuse_proven": False,
        "native_os": "Darwin", "native_arch": "arm64",
        "python_version": platform.python_version(), "cases": cases,
        "mutation_detected": mutation_detected,
    }
    output = evidence_dir / "c3_candidate_b_private.json"
    output.write_text(json.dumps(evidence, sort_keys=True, indent=2) + "\n",
                      encoding="utf-8")
    os.chmod(output, 0o600)
    for c in cases:
        print("C3B_CASE mode={mode} status={status} anchor_held={anchor} "
              "sid_distinct={sid} attempted={attempted} worker_started={worker} "
              "join_verified={join} grant={grant} gate={gate} "
              "workload={work} controller_waited={waited} cleanup={cleanup}".format(
                  mode=c["mode"], status=c["status"],
                  anchor=c.get("anchor_held", -1),
                  sid=c.get("sid_distinct", -1),
                  attempted=c.get("spawn_attempted", -1),
                  worker=c.get("worker_spawned", -1),
                  join=c.get("join_verified", -1),
                  grant=c.get("owner_granted", -1),
                  gate=c.get("gate_opened", -1),
                  work=c.get("workload_started", -1),
                  waited=c.get("controller_waited", -1),
                  cleanup=c.get("cleanup_complete", -1)))
    print("C3B_MUTATION_DETECTED=" + str(mutation_detected).lower())
    print("C3B_NATIVE_RESULT=" + decision)
    return 0 if success else 2


if __name__ == "__main__":
    raise SystemExit(main())
