#!/usr/bin/env python3
"""Isolated Darwin SIGCHLD disposition research, never a G2 product qualification."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import platform
import stat
import subprocess
import sys
import tempfile

SOURCE = Path(__file__).with_name("c2_sigchld_probe.c")
CASES = ("DEFAULT", "IGNORE", "NOCLDWAIT")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", type=Path)
    args = parser.parse_args()
    if sys.platform != "darwin":
        print("NOT_RUN_NON_DARWIN")
        return 3
    if platform.machine().lower() != "arm64" or sys.version_info < (3, 13):
        print("NOT_RUN_UNSUPPORTED_NATIVE_RUNTIME")
        return 3
    os.umask(0o077)
    if args.evidence_dir:
        if args.evidence_dir.is_symlink() or not args.evidence_dir.is_dir():
            print("NOT_RUN_INVALID_EVIDENCE_DIR")
            return 3
        current = args.evidence_dir.stat()
        if current.st_uid != os.geteuid() or stat.S_IMODE(current.st_mode) & 0o077:
            print("NOT_RUN_EVIDENCE_DIR_NOT_PRIVATE")
            return 3

    with tempfile.TemporaryDirectory(prefix="mfg-c2-sigchld-") as work:
        binary = Path(work) / "c2_sigchld_probe"
        try:
            result = subprocess.run(
                ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", str(SOURCE), "-o", str(binary)],
                text=True, capture_output=True, check=False, timeout=30,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            print("NOT_RUN_NO_COMPILER_OR_TIMEOUT")
            return 3
        if result.returncode != 0:
            print("BLOCK: synthetic SIGCHLD helper compilation failed")
            return 2

        observations = []
        for mode in CASES:
            try:
                case = subprocess.run([str(binary), mode], capture_output=True,
                                      text=True, check=False, timeout=8)
            except subprocess.TimeoutExpired:
                observations.append({"mode": mode, "status": "BLOCK", "reason": "deadline"})
                continue
            valid = (case.returncode == 0 and
                     case.stdout == f"C2_SIGCHLD_PASS mode={mode} waitable=1\n" and
                     case.stderr == "")
            observations.append({"mode": mode,
                                 "status": "POSITIVE_EXPERIMENT" if valid else "BLOCK"})
        decision = ("PARTIAL_NATIVE_SIGCHLD_ONLY_NOT_G2"
                    if all(item["status"] == "POSITIVE_EXPERIMENT" for item in observations)
                    else "BLOCK_SIGCHLD_EXPERIMENT")
        data = {"source": "C2_SYNTHETIC_SIGCHLD_RESEARCH_ONLY",
                "decision": decision, "cases": observations,
                "g2_qualified": False,
                "limits": ["synthetic self-injection only, not inherited through exec",
                           "no proof of concurrent waitpid ownership in Gateway",
                           "no proof of PGID reuse or group signal atomicity"]}
        if args.evidence_dir:
            with (args.evidence_dir / "c2_sigchld_private.json").open("x", encoding="utf-8") as stream:
                json.dump(data, stream, sort_keys=True, indent=2)
                stream.write("\n")
        print(json.dumps({"decision": decision, "cases": observations,
                          "g2_qualified": False}, sort_keys=True))
        return 0 if decision == "PARTIAL_NATIVE_SIGCHLD_ONLY_NOT_G2" else 2


if __name__ == "__main__":
    raise SystemExit(main())
