#!/usr/bin/env python3
"""C3 Darwin synthetic Relay experiment ONLY — never the Gateway ExecSupervisor.

Runs a strict, fixed six-mode experiment against newly created private children.
No caller-provided PID, PGID, executable, workspace, or command is accepted.
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
NATIVE = HERE / "c3_relay_probe.c"
MODES = ("term-default", "kill-unknown", "leader-exit",
         "competing-reap", "ipc-forgery", "identity-loss")
# (worker, cleanup, term, kill, ipc, Owner terminal, experiment label)
EXPECTED = {
    "term-default":   ("OBSERVED_SIGNAL", "VERIFIED", 1, 0, 1, "SIGNALS_CLOSED", "POSITIVE_EXPERIMENT"),
    "kill-unknown":   ("UNKNOWN", "UNRESOLVED", 1, 1, 1, "SIGNALS_CLOSED", "POSITIVE_EXPERIMENT"),
    "leader-exit":    ("UNKNOWN", "UNRESOLVED", 0, 0, 1, "QUARANTINED", "SAFE_REFUSAL"),
    "competing-reap": ("UNKNOWN", "UNRESOLVED", 0, 0, 0, "QUARANTINED", "EXPECTED_BLOCK"),
    "ipc-forgery":    ("OBSERVED_EXIT", "VERIFIED", 0, 0, 1, "SIGNALS_CLOSED", "EXPECTED_BLOCK"),
    "identity-loss":  ("UNKNOWN", "UNRESOLVED", 0, 0, 0, "QUARANTINED", "SAFE_REFUSAL"),
}

_RE = re.compile(
    r"\AC3_RESULT mode=(term-default|kill-unknown|leader-exit|competing-reap|ipc-forgery|identity-loss)"
    r" worker=(OBSERVED_EXIT|OBSERVED_SIGNAL|UNKNOWN)"
    r" cleanup=(VERIFIED|UNRESOLVED)"
    r" term=([01]) kill=([01]) owner_reaped=([01]) after_loss_signals=([01])"
    r" ipc_proven=([01]) state=(SIGNALS_CLOSED|QUARANTINED)\n\Z"
)

def parse_native_result(stdout: str) -> dict:
    """One bounded sanitized line, never business or spoofed workload stdout."""
    m = _RE.fullmatch(stdout)
    if m is None:
        raise ValueError("C3 native record not uniquely framed")
    mode, worker, cleanup, term, kill, reap, late, ipc, state = m.groups()
    return {
        "mode": mode, "worker": worker, "cleanup": cleanup,
        "term": int(term), "kill": int(kill), "owner_reaped": int(reap),
        "after_loss_signals": int(late), "ipc_proven": int(ipc),
        "state": state,
    }


def classify_native_result(mode: str, evidence: dict) -> str:
    if mode not in EXPECTED or type(evidence) is not dict:
        return "BLOCK"
    worker, cleanup, term, kill, ipc, state, wanted = EXPECTED[mode]
    expected = {"mode": mode, "worker": worker, "cleanup": cleanup,
                "term": term, "kill": kill, "owner_reaped": 1,
                "after_loss_signals": 0, "ipc_proven": ipc, "state": state}
    if evidence.keys() != expected.keys() or any(
        type(evidence[k]) is not type(v) or evidence[k] != v
        for k, v in expected.items()
    ):
        return "BLOCK"
    return wanted


def run_case(binary: Path, root: Path, mode: str) -> dict:
    try:
        completed = subprocess.run(
            [str(binary), mode, str(root)], text=True,
            capture_output=True, timeout=12, check=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        return {"mode": mode, "status": "BLOCK", "reason": "native_launch_or_timeout",
                "after_loss_signals": -1}
    if completed.returncode != 0 or completed.stderr:
        return {"mode": mode, "status": "BLOCK", "reason": "native_nonzero_or_stderr",
                "after_loss_signals": -1}
    try:
        event = parse_native_result(completed.stdout)
    except ValueError:
        return {"mode": mode, "status": "BLOCK", "reason": "native_record_invalid",
                "after_loss_signals": -1}
    return {**event, "status": classify_native_result(mode, event)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != "darwin" or platform.machine() != "arm64":
        print("C3_NOT_RUN_NON_DARWIN (G2 BLOCK)")
        return 3
    evidence_dir = args.evidence_dir
    meta = os.lstat(evidence_dir)
    if not stat.S_ISDIR(meta.st_mode) or meta.st_uid != os.geteuid() or (meta.st_mode & 0o077):
        print("C3_BLOCK evidence_dir_policy")
        return 4

    with tempfile.TemporaryDirectory(prefix="c3-synthetic-") as tmp:
        root = Path(tmp)
        os.chmod(root, 0o700)
        marker = root / "C3_TEST_MARKER"
        marker.write_bytes(b"synthetic")
        os.chmod(marker, 0o600)
        binary = root / "c3_native"
        compiled = subprocess.run(
            ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-pthread",
             str(NATIVE), "-o", str(binary)],
            text=True, capture_output=True, timeout=40, check=False,
        )
        if compiled.returncode != 0:
            print("C3_BLOCK native_compile")
            return 4
        cases = [run_case(binary, root, mode) for mode in MODES]

    expected = [EXPECTED[mode][-1] for mode in MODES]
    decision = ("PARTIAL_NATIVE_C3_ONLY_NOT_G2"
                if [case["status"] for case in cases] == expected
                else "BLOCK_RESEARCH")
    evidence = {"decision": decision, "g2_qualified": False,
                "native_os": "Darwin", "native_arch": "arm64",
                "python_version": platform.python_version(), "cases": cases}
    path = evidence_dir / "c3_relay_private.json"
    path.write_text(json.dumps(evidence, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    os.chmod(path, 0o600)
    print("C3_NATIVE_RESULT=" + decision)
    return 0 if decision == "PARTIAL_NATIVE_C3_ONLY_NOT_G2" else 2


if __name__ == "__main__":
    raise SystemExit(main())
