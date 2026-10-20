#!/usr/bin/env python3
"""C3-05/06/13 Darwin identity-barrier research, disposable synthetic children ONLY.

No CLI option permits an existing PID, PGID, workspace, executable or command.
The native helper never makes a production G2 claim.
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

HERE = Path(__file__).resolve().parent
NATIVE = HERE / "c3_identity_probe.c"
MODES = (
    "exit-unreaped", "competing-reap", "group-isolation", "stale-after-reap",
)
# exit_observed, owner_reaped, successful_group_signals, attempted_group_calls,
# attempts_after_identity_loss, successful_calls_after_loss, canary, refused, verdict
EXPECTED = {
    "exit-unreaped": (1, 1, 0, 0, 0, 0, 0, 1, "SAFE_REFUSAL"),
    "competing-reap": (1, 0, 0, 0, 0, 0, 0, 1, "EXPECTED_BLOCK"),
    "group-isolation": (1, 1, 1, 1, 0, 0, 1, 0, "POSITIVE_EXPERIMENT"),
    "stale-after-reap": (1, 1, 0, 0, 0, 0, 1, 1, "EXPECTED_BLOCK"),
}
_RE = re.compile(
    r"\AC3_ID_RESULT mode=(exit-unreaped|competing-reap|group-isolation|stale-after-reap)"
    r" exit_observed=([01]) owner_reaped=([01]) group_signals=([01])"
    r" group_attempts=([01]) after_loss_attempts=([01])"
    r" after_loss_signals=([01]) canary_alive=([01]) refused=([01])"
    r" reuse_proven=([01])\n\Z"
)
_FIELDS = (
    "exit_observed", "owner_reaped", "group_signals",
    "group_attempts", "after_loss_attempts", "after_loss_signals",
    "canary_alive", "refused", "reuse_proven",
)


def parse_native(stdout: str) -> dict:
    match = _RE.fullmatch(stdout)
    if match is None:
        raise ValueError("malformed or repeated native identity observation")
    return {"mode": match.group(1), **dict(zip(
        _FIELDS, (int(v) for v in match.groups()[1:])
    ))}


def classify(mode: str, record: dict) -> str:
    if mode not in EXPECTED or type(record) is not dict:
        return "BLOCK"
    values = EXPECTED[mode]
    expected = {
        "mode": mode,
        **dict(zip(_FIELDS, values[:-1] + (0,))),
    }
    if record.keys() != expected.keys() or any(
        type(record[k]) is not type(v) or record[k] != v
        for k, v in expected.items()
    ):
        return "BLOCK"
    return values[-1]


def run_case(binary: Path, root: Path, mode: str) -> dict:
    try:
        p = subprocess.run(
            [str(binary), mode, str(root)],
            capture_output=True, text=True, timeout=14, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {"mode": mode, "status": "BLOCK", "reason": "native_launch_or_timeout",
                "after_loss_signals": -1, "reuse_proven": 0}
    if p.returncode != 0 or p.stderr:
        return {"mode": mode, "status": "BLOCK", "reason": "native_failed_or_stderr",
                "after_loss_signals": -1, "reuse_proven": 0}
    try:
        observation = parse_native(p.stdout)
    except ValueError:
        return {"mode": mode, "status": "BLOCK", "reason": "native_record_invalid",
                "after_loss_signals": -1, "reuse_proven": 0}
    return {**observation, "status": classify(mode, observation)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != "darwin" or platform.machine() != "arm64":
        print("C3_ID_NOT_RUN_NON_DARWIN; G2 BLOCK")
        return 3

    evidence_dir = args.evidence_dir
    details = os.lstat(evidence_dir)
    if not stat.S_ISDIR(details.st_mode) or details.st_uid != os.geteuid() or (
        details.st_mode & 0o077
    ):
        print("C3_ID_BLOCK invalid_private_evidence_dir")
        return 4

    with tempfile.TemporaryDirectory(prefix="c3-id-synthetic-") as private:
        root = Path(private)
        os.chmod(root, 0o700)
        marker = root / "C3_ID_TEST_MARKER"
        marker.write_bytes(b"synthetic")
        os.chmod(marker, 0o600)
        binary = root / "c3_identity_native"
        try:
            compiled = subprocess.run(
                ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-pthread",
                 str(NATIVE), "-o", str(binary)],
                text=True, capture_output=True, timeout=40, check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            print("C3_ID_BLOCK compiler_unavailable")
            return 4
        if compiled.returncode != 0:
            print("C3_ID_BLOCK native_compile")
            return 4
        cases = [run_case(binary, root, mode) for mode in MODES]

    expected = [EXPECTED[m][-1] for m in MODES]
    decision = (
        "PARTIAL_C3_IDENTITY_NOT_G2"
        if [c["status"] for c in cases] == expected
        else "BLOCK_RESEARCH"
    )
    evidence = {
        "decision": decision, "g2_qualified": False,
        "native_os": "Darwin", "native_arch": "arm64",
        "python_version": platform.python_version(), "cases": cases,
        "pid_pgid_reuse": "NOT_PROVEN",
    }
    path = evidence_dir / "c3_identity_private.json"
    path.write_text(json.dumps(evidence, sort_keys=True, indent=2) + "\n",
                    encoding="utf-8")
    os.chmod(path, 0o600)

    # Public CI prints only exact, strictly parsed enums and flags. Never real PIDs.
    for c in cases:
        print("C3_ID_CASE mode={mode} status={status} refused={refused} "
              "group_signals={group_signals} group_attempts={attempts} "
              "after_loss_attempts={late_attempts} after_loss_signals={late} "
              "reuse_proven=0".format(
                  mode=c["mode"], status=c["status"],
                  refused=c.get("refused", -1),
                  group_signals=c.get("group_signals", -1),
                  attempts=c.get("group_attempts", -1),
                  late_attempts=c.get("after_loss_attempts", -1),
                  late=c.get("after_loss_signals", -1)))
    print("C3_ID_NATIVE_RESULT=" + decision)
    return 0 if decision == "PARTIAL_C3_IDENTITY_NOT_G2" else 2


if __name__ == "__main__":
    raise SystemExit(main())
