#!/usr/bin/env python3
"""C2 research only: native-owned PGID and bounded synthetic descendants.

This does NOT qualify G2, production group kill, Pipenv, or the Gateway.
Every synthetic descendant self-expires; no business Workspace is accessed.
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

HERE = Path(__file__).resolve().parent
NATIVE = HERE / "c2_pgid_anchor.c"
CHILD = HERE / "c2_group_child.py"
MODES = ("term", "kill", "worker-first", "leader-exit", "stale")
NEGATIVE_MODES = ("close-stdout",)
_NEGATIVE_EOF = ("C2_EXPECTED_BLOCK phase=descendant_still_alive "
                 "stdout_eof=1 witness_before_eof=0 descendant_alive=1\n")
_RE = re.compile(
    r"\AC2_RESULT mode=(term|kill|worker-first|leader-exit|stale)"
    r" term=([01]) kill=([01]) refused=([01]) held=([01])"
    r" reaped=([01]) drain=([01]) descendant_verified=([01])\n\Z"
)
_FIELDS = ("term", "kill", "refused", "held", "reaped", "drain", "descendant_verified")


def parse_native_result(stdout: str) -> dict:
    """Accept exactly one fully specified, sanitized native verdict line."""
    match = _RE.fullmatch(stdout)
    if match is None:
        raise ValueError("no unique valid native verdict")
    return {"mode": match.group(1), **dict(zip(_FIELDS, (int(x) for x in match.groups()[1:])) )}


def classify_observation(mode: str, actual: dict) -> str:
    if mode not in MODES or not isinstance(actual, dict):
        return "BLOCK"
    expected = {
        "mode": mode,
        "term": int(mode in ("term", "kill", "worker-first")),
        "kill": int(mode == "kill"),
        "refused": int(mode in ("leader-exit", "stale")),
        "held": int(mode != "leader-exit"),
        "reaped": 1,
        "drain": 1,
        "descendant_verified": 1,
    }
    if actual.keys() != expected.keys() or any(
        type(actual[key]) is not type(value) or actual[key] != value
        for key, value in expected.items()
    ):
        return "BLOCK"
    return "SAFE_REFUSAL" if mode in ("leader-exit", "stale") else "POSITIVE_EXPERIMENT"


def run_case(binary: Path, root: Path, mode: str) -> dict:
    try:
        proc = subprocess.run(
            [str(binary), mode, str(root), sys.executable],
            capture_output=True, text=True, timeout=18, check=False,
        )
    except subprocess.TimeoutExpired:
        return {"mode": mode, "status": "BLOCK", "reason": "helper_deadline"}
    if proc.returncode != 0:
        stage = re.search(r"C2_BLOCK phase=([a-z_]+)", proc.stderr)
        return {"mode": mode, "status": "BLOCK", "reason": stage.group(1) if stage else "native_exit"}
    if mode == "close-stdout":
        # Native negative control must prove EOF while the child is alive.
        # Never report a negative case as successful descendant termination.
        if proc.stdout != _NEGATIVE_EOF or proc.stderr:
            return {"mode": mode, "status": "BLOCK", "reason": "negative_evidence_invalid"}
        return {"mode": mode, "status": "EXPECTED_BLOCK",
                "reason": "descendant_still_alive", "g2_qualified": False}
    try:
        data = parse_native_result(proc.stdout)
    except ValueError:
        return {"mode": mode, "status": "BLOCK", "reason": "invalid_evidence"}
    if proc.stderr:
        return {"mode": mode, "status": "BLOCK", "reason": "unexpected_native_stderr"}
    result = classify_observation(mode, data)
    return {"mode": mode, "status": result, "signals": {
        "term": data["term"], "kill": data["kill"], "refused": data["refused"]
    }, "owned_reaped": data["reaped"] == 1, "stdout_eof": data["drain"] == 1}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", type=Path, help="existing private folder, never uploaded")
    args = parser.parse_args()
    if sys.platform != "darwin":
        print("NOT_RUN_NON_DARWIN: no native execution")
        return 3
    if platform.machine().lower() != "arm64":
        print("NOT_RUN_NON_ARM64")
        return 3
    if sys.version_info < (3, 13):
        print("NOT_RUN_PYTHON_TOO_OLD")
        return 3
    os.umask(0o077)
    if args.evidence_dir:
        if args.evidence_dir.is_symlink() or not args.evidence_dir.is_dir():
            print("NOT_RUN_INVALID_EVIDENCE_DIR")
            return 3
        st = args.evidence_dir.stat()
        if st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) & 0o077:
            print("NOT_RUN_EVIDENCE_DIR_NOT_PRIVATE")
            return 3
    with tempfile.TemporaryDirectory(prefix="mfg-c2-synthetic-") as private:
        root = Path(private)
        (root / "C2_TEST_MARKER").write_text("synthetic", encoding="ascii")
        shutil.copyfile(CHILD, root / "c2_group_child.py")
        (root / "c2_group_child.py").chmod(0o600)
        binary = root / "c2_group_owner"
        try:
            compiler = subprocess.run(
                ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", str(NATIVE), "-o", str(binary)],
                capture_output=True, text=True, timeout=30, check=False,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            print("NOT_RUN_NO_COMPILER_OR_DEADLINE")
            return 3
        if compiler.returncode != 0:
            print("BLOCK_NATIVE_COMPILE: private compiler details omitted")
            return 2
        cases = [run_case(binary, root, mode) for mode in MODES + NEGATIVE_MODES]
        wanted = ["POSITIVE_EXPERIMENT"] * 3 + ["SAFE_REFUSAL"] * 2 + ["EXPECTED_BLOCK"]
        decision = ("PARTIAL_NATIVE_OBSERVATION_NOT_G2"
                    if [case["status"] for case in cases] == wanted
                    else "BLOCK_NATIVE_EXPERIMENT")
        data = {
            "source": "C2_OWNED_GROUP_RESEARCH_ONLY",
            "python": f"{sys.version_info.major}.{sys.version_info.minor}",
            "cases": cases,
            "g2_qualified": False,
            "not_proved": [
                "known synthetic descendant NOTE_EXIT does not prove arbitrary cleanup",
                "real PGID reuse under hostile timing",
                "detached/out-of-group descendants",
                "Gateway-owned process integration and lifecycle",
                "Direct/Pipenv authorized Workspace and binding",
                "native owner signal/reap proof independent review",
            ],
            "decision": decision,
        }
        if args.evidence_dir:
            path = args.evidence_dir / "c2_pgid_private.json"
            with path.open("x", encoding="utf-8") as stream:
                json.dump(data, stream, indent=2, sort_keys=True)
                stream.write("\n")
        print(json.dumps({
            "decision": decision, "g2_qualified": False,
            "cases": [{"mode": x["mode"], "status": x["status"],
                       **({"reason": x["reason"]} if "reason" in x else {})} for x in cases],
        }, sort_keys=True))
        return 0 if decision == "PARTIAL_NATIVE_OBSERVATION_NOT_G2" else 2


if __name__ == "__main__":
    raise SystemExit(main())
