"""C3 Candidate B B03-R2 pre-signal synthetic containment preflight.

No group TERM or SIGKILL is ever sent by this executable. It probes fresh
cross-parent membership, Owner grant, legal waits, and checked FD closure.
The orphan-loss modes T04/T08b/T10 explicitly remain NOT_RUN/BLOCK.
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

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "tools/research/c3_candidate_b_kill_preflight.c"
FIELDS = (
    "anchor_held", "controller_self_led", "worker_joined",
    "worker_parentage", "owner_granted", "worker_armed",
    "controller_waited", "owner_reaped", "fds_closed",
    "anchor_term_ignore_ready", "term_attempts", "kill_attempts",
    "orphan_preflight_proven", "reuse_proven", "g2_qualified",
)
EXPECTED = dict(zip(FIELDS, (1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0)))
PREFIX = "C3B03_R2_PREFLIGHT"
ORPHAN_MODES = (
    "controller-loss-before-worker-wait",
    "controller-lost-after-term",
    "known-descendant-observation",
)
RESULT = "PRE_SIGNAL_PREFLIGHT_ONLY_NOT_G2"
SIMPLE = re.compile(r"^C3B03_R2_PREFLIGHT(?: [a-z_]+=[01])+\n\Z")


def parse_native(output: str) -> dict[str, int]:
    if not SIMPLE.fullmatch(output):
        raise ValueError("missing, duplicate, or forged native record")
    tokens = output.rstrip("\n").split(" ")
    if len(tokens) != len(FIELDS) + 1 or tokens[0] != PREFIX:
        raise ValueError("native field count")
    keys = tuple(token.split("=", 1)[0] for token in tokens[1:])
    if keys != FIELDS:
        raise ValueError("unknown or reordered fields")
    return {
        key: int(token.split("=", 1)[1])
        for key, token in zip(FIELDS, tokens[1:])
    }


def classify(record: dict) -> str:
    if type(record) is not dict or record.keys() != EXPECTED.keys():
        return "BLOCK"
    if any(type(record[k]) is not int or record[k] != v
           for k, v in EXPECTED.items()):
        return "BLOCK"
    return RESULT


def eligible_for_group_kill(preflight: dict) -> bool:
    """This stage can NEVER grant KILL; future native gates are separate."""
    return False


def private_evidence_root(path: Path) -> bool:
    try:
        st = os.lstat(path)
        return (stat.S_ISDIR(st.st_mode) and not stat.S_ISLNK(st.st_mode)
                and st.st_uid == os.geteuid() and not (st.st_mode & 0o077))
    except OSError:
        return False


def compile_preflight(target: Path) -> bool:
    cmd = ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-pthread",
           str(SOURCE), "-o", str(target)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              check=False, timeout=45)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return proc.returncode == 0


def create_root(private: Path, binary: Path) -> Path:
    root = private / "enrolled"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    marker = root / "C3B03_R2_SYNTHETIC"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(marker, flags, 0o600)
    try:
        assert os.write(fd, b"synthetic") == 9
    finally:
        os.close(fd)
    executable = root / "c3_candidate_b_kill_preflight"
    shutil.copyfile(binary, executable)
    executable.chmod(0o700)
    return executable


def run_preflight(executable: Path):
    """Bounded native owner; do not send ANY host signal on timeout.

    If this times out, record unresolved; the research process's self-expiry
    is not proof of cleanup and no Actions runner cleanup may be counted.
    """
    try:
        proc = subprocess.Popen(
            [str(executable), "preflight", str(executable.parent)],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True,
        )
    except OSError:
        return None, "launch"
    try:
        stdout, stderr = proc.communicate(timeout=12)
    except subprocess.TimeoutExpired:
        # Never use proc.kill() or terminate() to disguise a failed preflight.
        # Runner must not claim VERIFIED if its native owner is unresolved.
        return None, "owner_timeout_unresolved"
    if proc.returncode != 0 or stderr:
        return None, "native_rejected"
    try:
        return parse_native(stdout), None
    except ValueError:
        return None, "invalid_native_record"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != "darwin" or platform.machine() != "arm64":
        print("C3B03_R2_NOT_RUN_NON_DARWIN; no evidence")
        return 3
    if not private_evidence_root(args.evidence_dir):
        print("C3B03_R2_BLOCK untrusted_evidence_directory")
        return 4
    with tempfile.TemporaryDirectory(prefix="c3b03-r2-private-") as folder:
        private = Path(folder)
        private.chmod(0o700)
        binary = private / "preflight_compiled"
        if not compile_preflight(binary):
            print("C3B03_R2_BLOCK compilation")
            return 4
        executable = create_root(private, binary)
        observed, reason = run_preflight(executable)
    verdict = classify(observed) if observed is not None else "BLOCK"
    # No preflight observation can prove orphan handling or KILL permission.
    data = {
        "decision": RESULT if verdict == RESULT else "BLOCK_RESEARCH",
        "native_os": "Darwin",
        "native_arch": platform.machine(),
        "python_version": platform.python_version(),
        "preflight": observed if verdict == RESULT else None,
        "reason": reason,
        "orphan_modes": {mode: "NOT_RUN/BLOCK" for mode in ORPHAN_MODES},
        "orphan_preflight_proven": False,
        "group_kill_authorized": False,
        "reuse_proven": False,
        "g2_qualified": False,
    }
    out = args.evidence_dir / "c3_b03_r2_preflight_private.json"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(out, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(data, stream, sort_keys=True, indent=2)
        stream.write("\n")
    print("C3B03_R2_PREFLIGHT_RESULT=" + data["decision"])
    print("C3B03_R2_GROUP_KILL_AUTHORIZED=false")
    print("C3B03_R2_ORPHAN_MODES=NOT_RUN/BLOCK")
    return 0 if verdict == RESULT else 2


if __name__ == "__main__":
    raise SystemExit(main())
