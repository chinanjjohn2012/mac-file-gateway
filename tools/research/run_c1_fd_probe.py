#!/usr/bin/env python3
"""Native macOS *research only* for descriptor cwd + spawn group creation.

No Gateway import, no changes to actual user workspaces, no signals.
Success NEVER qualifies C1/G2's descendant cleanup, PGID reuse, or Pipenv.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
from pathlib import Path
import re
import subprocess
import sys
import tempfile

SOURCE = Path(__file__).with_name("c1_fd_spawn.c")
_ANCHOR = re.compile(r"(?m)^C1_ANCHOR pid=([1-9][0-9]*) pgid=([1-9][0-9]*) dir_dev=([0-9]+) dir_ino=([1-9][0-9]*)$")


def parse_anchor(stderr: str) -> tuple[int, int, int]:
    """Parse exact verified group leader and held-directory metadata."""
    matches = _ANCHOR.findall(stderr)
    if len(matches) != 1:
        raise ValueError("missing or duplicate native process group anchor")
    pid, pgid, dev, ino = map(int, matches[0])
    if pid != pgid or pid < 1:
        raise ValueError("not a dedicated process group leader")
    return pid, dev, ino


def evaluate_observation(expected: dict, actual: dict) -> bool:
    return all(type(expected.get(key)) is int and type(actual.get(key)) is int
               and expected[key] == actual[key]
               for key in ("cwd_dev", "cwd_ino", "pgid")) and actual.get("handshake") == "R"


CHILD = (
    "import os,sys,json; "
    "b=sys.stdin.buffer.read(1); "
    "s=os.stat('.'); "
    "print(json.dumps({'cwd_dev':s.st_dev,'cwd_ino':s.st_ino,"
    "'pgid':os.getpgrp(),'handshake':b.decode('ascii')}))"
)


def run_case(binary: Path, root: Path, mode: str) -> dict:
    project = root / ("project_" + mode)
    project.mkdir(mode=0o700)
    (project / "C1_TEST_MARKER").write_text("synthetic", encoding="utf-8")
    original = project.stat()
    cmd = [str(binary), "--" + mode, str(project), sys.executable, "-I", "-c", CHILD]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=25, check=False)
    except subprocess.TimeoutExpired:
        return {"mode": mode, "status": "BLOCK", "reason": "helper_deadline"}
    if proc.returncode != 0:
        return {"mode": mode, "status": "BLOCK", "reason": "native_helper_exit", "exit": proc.returncode,
                "native_stage": re.search(r"C1_BLOCK phase=([a-z_]+)", proc.stderr).group(1)
                if re.search(r"C1_BLOCK phase=([a-z_]+)", proc.stderr) else "unknown"}
    try:
        pid, held_dev, held_ino = parse_anchor(proc.stderr)
        actual = json.loads(proc.stdout)
    except (ValueError, TypeError, json.JSONDecodeError):
        return {"mode": mode, "status": "BLOCK", "reason": "invalid_child_evidence"}
    expected = {"cwd_dev": original.st_dev, "cwd_ino": original.st_ino, "pgid": pid, "handshake": "R"}
    if held_dev != original.st_dev or held_ino != original.st_ino:
        return {"mode": mode, "status": "BLOCK", "reason": "held_fd_identity_mismatch"}
    if "C1_REAP_OK" not in proc.stderr:
        return {"mode": mode, "status": "BLOCK", "reason": "reap_unconfirmed"}
    if not evaluate_observation(expected, actual):
        return {"mode": mode, "status": "BLOCK", "reason": "wrong_child_cwd_or_group"}
    if mode == "race":
        # A new directory now exists at the original spelling, and MUST differ.
        replacement = project.stat()
        held = project.with_name(project.name + ".held").stat()
        if (replacement.st_dev, replacement.st_ino) == (original.st_dev, original.st_ino):
            return {"mode": mode, "status": "BLOCK", "reason": "replacement_used"}
        if (held.st_dev, held.st_ino) != (original.st_dev, original.st_ino):
            return {"mode": mode, "status": "BLOCK", "reason": "rename_identity_changed"}
    return {"mode": mode, "status": "POSITIVE_EXPERIMENT", "one_spawn_per_case": True,
            "cwd_dev": original.st_dev, "cwd_ino": original.st_ino,
            "child_pgid": pid, "process_group_created": True, "waitpid_reaped": True}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", type=Path, help="existing local directory for private evidence")
    args = parser.parse_args()
    if sys.platform != "darwin":
        print("NOT_RUN_NON_DARWIN: no native experiment or product modification")
        return 3
    if platform.machine().lower() != "arm64":
        print("NOT_RUN_NON_ARM64")
        return 3
    if sys.version_info < (3, 13):
        print("NOT_RUN_PYTHON_TOO_OLD")
        return 3
    os.umask(0o077)
    if args.evidence_dir and (not args.evidence_dir.is_dir() or args.evidence_dir.is_symlink()):
        print("BLOCK: evidence directory is not a normal directory")
        return 3
    # All synthetic directories and the native binary live in an isolated temp.
    with tempfile.TemporaryDirectory(prefix="mfg-c1-research-") as work:
        workdir = Path(work)
        binary = workdir / "c1_spawn"
        compile_result = subprocess.run(
            ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", str(SOURCE), "-o", str(binary)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30, check=False,
        )
        if compile_result.returncode != 0:
            print("BLOCK: native compile failed (private compiler diagnostics omitted)")
            return 2
        cases = [run_case(binary, workdir, mode) for mode in ("normal", "race")]
        statuses = [item["status"] for item in cases]
        data = {"source": "C1_DESCRIPTOR_SPAWN_RESEARCH_ONLY", "platform": "darwin",
                "python": f"{sys.version_info.major}.{sys.version_info.minor}",
                "cases": cases,
                "g2_qualified": False,
                "not_proved": ["Pipenv runner/Pipfile binding", "PGID number reuse", "leader-exits-before-descendants",
                               "signal ownership and TERM/KILL", "real Gateway subprocess integration"],
                "decision": "PARTIAL_NATIVE_OBSERVATION_NOT_G2" if statuses == ["POSITIVE_EXPERIMENT"] * 2
                            else "BLOCK_NATIVE_EXPERIMENT"}
        if args.evidence_dir:
            path = args.evidence_dir / "c1_fd_probe_private.json"
            # Never overwrite a previous run's evidence, even if matching.
            with path.open("x", encoding="utf-8") as out:
                json.dump(data, out, indent=2, sort_keys=True)
                out.write("\n")
        print(json.dumps({"decision": data["decision"],
                          "cases": [{"mode": x["mode"], "status": x["status"]} for x in cases],
                          "g2_qualified": False}, sort_keys=True))
        return 0 if data["decision"] == "PARTIAL_NATIVE_OBSERVATION_NOT_G2" else 2


if __name__ == "__main__":
    raise SystemExit(main())
