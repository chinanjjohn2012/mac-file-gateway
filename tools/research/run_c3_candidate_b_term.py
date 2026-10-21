#!/usr/bin/env python3
"""Isolated Candidate B B-02 Darwin ARM64 group TERM research (NOT G2).

Only fixed research modes and a fresh private synthetic process tree. No user
commands, existing PID/PGID, Workspace, Gateway or production ExecSupervisor.
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

NATIVE = Path(__file__).resolve().parent / "c3_candidate_b_term.c"
MODES = (
    "term-positive", "missing-sigdef", "missing-sigmask",
    "controller-group-regression", "anchor-lost-before-term",
    "deadline-before-term",
    "canary-isolation",
    "controller-result-lost",
)
MUTATIONS = ("omit-sigdef", "omit-sigmask", "omit-controller-group")
SAFETY_FAULTS = ("stale-anchor-gate", "owner-fd-close", "controller-fd-close")
FIELDS = (
    "anchor_held", "controller_group_leader",
    "controller_inherited_ignore", "controller_inherited_block",
    "worker_spawned", "worker_default_term", "worker_unblocked_term",
    "worker_armed", "term_attempts", "term_succeeded",
    "controller_waited", "worker_observed_term",
    "admission_cutoff_expired", "outer_live_at_refusal",
    "gate_opened", "cleanup_complete", "canary_survived",
    "worker_result_unknown", "result_lost_after_wait",
    "owner_children_reaped", "anchor_loss_gate_checked",
    "after_loss_attempts", "owner_fds_closed", "controller_worker_fds_closed",
    "reuse_proven", "g2_qualified",
)
# Each bit is a *native observable* fixed by the design, never inferred from EOF.
EXPECTED = {
    "term-positive": (
        (1,1,1,1,1,1,1,1,1,1,1,1,0,0,1,1,0,0,0,1,0,0,1,1,0,0), "POSITIVE_EXPERIMENT",
    ),
    "missing-sigdef": (
        (1,1,1,1,1,0,1,1,1,1,1,0,0,0,1,1,0,0,0,1,0,0,1,1,0,0), "EXPECTED_BLOCK",
    ),
    "missing-sigmask": (
        (1,1,1,1,1,1,0,1,1,1,1,0,0,0,1,1,0,0,0,1,0,0,1,1,0,0), "EXPECTED_BLOCK",
    ),
    "controller-group-regression": (
        (1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,1,0,0,1,0,0,0), "SAFE_REFUSAL",
    ),
    "anchor-lost-before-term": (
        (0,1,1,1,1,1,1,1,0,0,1,0,0,0,1,1,0,0,0,1,1,0,1,1,0,0), "SAFE_REFUSAL",
    ),
    "deadline-before-term": (
        (1,1,1,1,1,1,1,1,0,0,1,0,1,1,1,1,0,0,0,1,0,0,1,1,0,0), "EXPECTED_BLOCK",
    ),
    "canary-isolation": (
        (1,1,1,1,1,1,1,1,1,1,1,1,0,0,1,1,1,0,0,1,0,0,1,1,0,0), "POSITIVE_EXPERIMENT",
    ),
    "controller-result-lost": (
        (1,1,1,1,1,1,1,1,1,1,0,0,0,0,1,0,0,1,1,1,0,0,1,0,0,0), "EXPECTED_BLOCK",
    ),
}
_RESULT = re.compile(
    r"\AC3B02_RESULT mode=("
    + "|".join(re.escape(mode) for mode in MODES)
    + r")"
    + "".join(r" " + name + r"=([01])" for name in FIELDS)
    + r"\n\Z"
)
_MUTANT = {
    "omit-sigdef": (
        "C3B02_MUT_OMIT_SIGDEF",
        "C3B02_MUTANT name=omit-sigdef worker_default_term=0 "
        "worker_unblocked_term=1 term_attempts=0 cleanup_complete=1\n",
        "C3B02_BLOCK phase=worker_signal_ineligible\n",
    ),
    "omit-sigmask": (
        "C3B02_MUT_OMIT_SIGMASK",
        "C3B02_MUTANT name=omit-sigmask worker_default_term=1 "
        "worker_unblocked_term=0 term_attempts=0 cleanup_complete=1\n",
        "C3B02_BLOCK phase=worker_signal_ineligible\n",
    ),
    "omit-controller-group": (
        "C3B02_MUT_CTRL_GROUP",
        "C3B02_MUTANT name=omit-controller-group controller_group_leader=0 "
        "worker_spawned=0 term_attempts=0 cleanup_complete=1\n",
        "C3B02_BLOCK phase=controller_group\n",
    ),
}


_SAFETY_FAULT = {
    "stale-anchor-gate": (
        ("C3B02_MUT_SKIP_ANCHOR_CHECK", "C3B02_TEST_STALE_KILL_STUB"),
        "anchor-lost-before-term",
        "C3B02_FAULT name=stale-anchor-gate gate_checked=1 "
        "worker_armed=1 after_loss_attempts=1 term_attempts=1 "
        "native_signals=0 cleanup_complete=1\n",
        "C3B02_BLOCK phase=anchor_gate_violation\n",
    ),
    "owner-fd-close": (
        ("C3B02_FAULT_OWNER_CLOSE",),
        "term-positive",
        "C3B02_FAULT name=owner-fd-close owner_fds_closed=0 "
        "controller_worker_fds_closed=1 cleanup_complete=0\n",
        "C3B02_BLOCK phase=fd_close\n",
    ),
    "controller-fd-close": (
        ("C3B02_FAULT_CONTROLLER_CLOSE",),
        "term-positive",
        "C3B02_FAULT name=controller-fd-close owner_fds_closed=1 "
        "controller_worker_fds_closed=0 cleanup_complete=0\n",
        "C3B02_BLOCK phase=fd_close\n",
    ),
}


def term_admitted(now: int, cutoff: int, outer: int) -> bool:
    return 0 <= now < cutoff < outer


def parse_native(output: str) -> dict:
    match = _RESULT.fullmatch(output)
    if not match:
        raise ValueError("invalid/duplicate/forged native record")
    return {
        "mode": match.group(1),
        **dict(zip(FIELDS, (int(x) for x in match.groups()[1:]))),
    }


def classify(mode: str, record: dict) -> str:
    if mode not in EXPECTED or type(record) is not dict:
        return "BLOCK"
    reference = {
        "mode": mode, **dict(zip(FIELDS, EXPECTED[mode][0])),
    }
    if record.keys() != reference.keys() or any(
        type(record[k]) is not type(v) or record[k] != v
        for k, v in reference.items()
    ):
        return "BLOCK"
    return EXPECTED[mode][1]


def compile_binary(
    out: Path, mutation: str | None = None, fault: str | None = None,
) -> bool:
    if mutation is not None and fault is not None:
        return False
    args = ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-pthread"]
    if mutation is not None:
        args.append("-D" + _MUTANT[mutation][0])
    if fault is not None:
        for flag in _SAFETY_FAULT[fault][0]:
            args.append("-D" + flag)
    args.extend([str(NATIVE), "-o", str(out)])
    try:
        result = subprocess.run(
            args, capture_output=True, text=True, check=False, timeout=45
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    # Never print the compiler's absolute source paths in public CI.
    return result.returncode == 0


def prepare(root: Path, compiled: Path) -> Path:
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    marker = root / "C3B02_TEST_MARKER"
    marker.write_bytes(b"synthetic")
    marker.chmod(0o600)
    binary = root / "c3_candidate_b_term"
    shutil.copyfile(compiled, binary)
    binary.chmod(0o700)
    return binary


def execute(binary: Path, root: Path, mode: str, timeout: float = 10.5):
    start = time.monotonic()
    try:
        p = subprocess.run(
            (str(binary), mode, str(root)), capture_output=True,
            text=True, check=False, timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None, int((time.monotonic() - start) * 1000)
    return p, int((time.monotonic() - start) * 1000)


def mode_case(binary: Path, root: Path, mode: str) -> dict:
    proc, elapsed = execute(binary, root, mode)
    if proc is None:
        return {"mode": mode, "status": "BLOCK",
                "reason": "launch_or_timeout", "elapsed_ms": elapsed}
    if proc.returncode != 0 or proc.stderr:
        return {"mode": mode, "status": "BLOCK",
                "reason": "native_error", "elapsed_ms": elapsed}
    try:
        result = parse_native(proc.stdout)
    except ValueError:
        return {"mode": mode, "status": "BLOCK",
                "reason": "malformed_record", "elapsed_ms": elapsed}
    return {**result, "status": classify(mode, result),
            "elapsed_ms": elapsed}


def mutation_case(binary: Path, root: Path, name: str) -> bool:
    proc, elapsed = execute(binary, root, "term-positive")
    _, wanted_stdout, wanted_stderr = _MUTANT[name]
    return (
        proc is not None and 0 <= elapsed < 10000
        and proc.returncode == 70
        and proc.stdout == wanted_stdout
        and proc.stderr == wanted_stderr
    )


def fault_case(binary: Path, root: Path, name: str) -> bool:
    flags, mode, expected_stdout, expected_stderr = _SAFETY_FAULT[name]
    assert flags  # only compiled research-test macros, never runtime PID args
    proc, elapsed = execute(binary, root, mode)
    return (
        proc is not None and 0 <= elapsed < 10000
        and proc.returncode == 70
        and proc.stdout == expected_stdout
        and proc.stderr == expected_stderr
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != "darwin" or platform.machine() != "arm64":
        print("C3B02_NOT_RUN_NON_DARWIN; G2 BLOCK")
        return 3
    evidence_dir = args.evidence_dir
    try:
        st = os.lstat(evidence_dir)
        okay = (
            stat.S_ISDIR(st.st_mode)
            and st.st_uid == os.geteuid()
            and not st.st_mode & 0o077
        )
    except OSError:
        okay = False
    if not okay:
        print("C3B02_BLOCK untrusted_evidence_root")
        return 4

    with tempfile.TemporaryDirectory(prefix="c3-b02-private-") as folder:
        private = Path(folder)
        private.chmod(0o700)
        compiled = private / "c3_b02_compiled"
        if not compile_binary(compiled):
            print("C3B02_BLOCK compilation")
            return 4
        cases = [
            mode_case(prepare(private / mode, compiled), private / mode, mode)
            for mode in MODES
        ]
        mutants = {}
        for name in MUTATIONS:
            compiled_variant = private / ("compiled-" + name)
            if not compile_binary(compiled_variant, name):
                mutants[name] = False
                continue
            root = private / ("mutation-" + name)
            binary = prepare(root, compiled_variant)
            mutants[name] = mutation_case(binary, root, name)
        faults = {}
        for name in SAFETY_FAULTS:
            compiled_variant = private / ("compiled-fault-" + name)
            if not compile_binary(compiled_variant, fault=name):
                faults[name] = False
                continue
            root = private / ("fault-" + name)
            binary = prepare(root, compiled_variant)
            faults[name] = fault_case(binary, root, name)

    passed = (
        [c["status"] for c in cases] == [EXPECTED[m][1] for m in MODES]
        and all(0 <= c["elapsed_ms"] < 9500
                and c.get("cleanup_complete") ==
                    (0 if c["mode"] == "controller-result-lost" else 1)
                and c.get("owner_children_reaped") == 1
                and c.get("reuse_proven") == 0
                and c.get("g2_qualified") == 0
                for c in cases)
        and mutants == {m: True for m in MUTATIONS}
        and faults == {f: True for f in SAFETY_FAULTS}
    )
    decision = "PARTIAL_B02_TERM_NOT_G2" if passed else "BLOCK_RESEARCH"
    evidence = {
        "decision": decision, "native_os": "Darwin", "native_arch": "arm64",
        "python_version": platform.python_version(),
        "g2_qualified": False, "reuse_proven": False,
        "cases": cases, "mutation_detected": mutants,
        "fault_detected": faults,
    }
    target = evidence_dir / "c3_b02_term_private.json"
    target.write_text(json.dumps(evidence, sort_keys=True, indent=2) + "\n",
                      encoding="utf-8")
    target.chmod(0o600)
    for c in cases:
        print(
            "C3B02_CASE mode={mode} status={status} "
            "anchor_held={anchor} controller_group={group} "
            "inherited_ignore={ignore} inherited_block={block} "
            "worker_default={default} worker_unblocked={unblocked} "
            "armed={armed} term_attempts={attempts} "
            "term_sent={sent} waited={waited} observed_term={term} "
            "cutoff_elapsed={cutoff} outer_live={outer} cleanup={cleanup} "
            "canary_survived={canary} unknown={unknown} "
            "postwait_lost={postwait} owner_children_reaped={reaped}".format(
                mode=c["mode"], status=c["status"],
                anchor=c.get("anchor_held", -1),
                group=c.get("controller_group_leader", -1),
                ignore=c.get("controller_inherited_ignore", -1),
                block=c.get("controller_inherited_block", -1),
                default=c.get("worker_default_term", -1),
                unblocked=c.get("worker_unblocked_term", -1),
                armed=c.get("worker_armed", -1),
                attempts=c.get("term_attempts", -1),
                sent=c.get("term_succeeded", -1),
                waited=c.get("controller_waited", -1),
                term=c.get("worker_observed_term", -1),
                cutoff=c.get("admission_cutoff_expired", -1),
                outer=c.get("outer_live_at_refusal", -1),
                cleanup=c.get("cleanup_complete", -1),
                canary=c.get("canary_survived", -1),
                unknown=c.get("worker_result_unknown", -1),
                postwait=c.get("result_lost_after_wait", -1),
                reaped=c.get("owner_children_reaped", -1),
            )
        )
    print("C3B02_MUTATIONS_DETECTED=" + str(all(mutants.values())).lower())
    print("C3B02_FAULTS_DETECTED=" + str(all(faults.values())).lower())
    print("C3B02_NATIVE_RESULT=" + decision)
    return 0 if passed else 2


if __name__ == "__main__":
    raise SystemExit(main())
