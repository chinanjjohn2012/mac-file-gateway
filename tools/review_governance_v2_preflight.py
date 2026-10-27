"""Strict read-only PR #75 V2.0 candidate Git HEAD source admission.

Runs on a disposable CI checkout before importing candidate model code.
This proves only declared repository source identity for that checkout,
not third-party dependencies, production runtime or Project sync.
"""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess


def git(*args: str) -> bytes:
    return subprocess.check_output(("git",) + args, stderr=subprocess.PIPE)


def decode(path: bytes) -> str:
    return os.fsdecode(path)


def fail(message: str) -> None:
    raise ValueError(message)


def verify(expected_head: str) -> None:
    if not re.fullmatch(r"[0-9a-f]{40}", expected_head):
        fail("EXPECTED_HEAD must be a complete Git SHA-1")
    head = git("rev-parse", "HEAD").decode().strip()
    tree = git("rev-parse", "HEAD^{tree}").decode().strip()
    if head != expected_head:
        fail("HEAD_MISMATCH")
    if git("config", "--bool", "core.filemode").strip() != b"true":
        fail("CORE_FILEMODE_DISABLED")
    root = Path(os.fsdecode(git("rev-parse", "--show-toplevel").strip())).resolve()
    if Path.cwd().resolve() != root:
        fail("NOT_AT_REPO_ROOT")

    original_tree: dict[str, tuple[str, str]] = {}
    for raw in filter(None, git("ls-tree", "-r", "-z", "HEAD").split(b"\0")):
        meta, name = raw.split(b"\t", 1)
        mode, kind, blob = meta.decode("ascii").split(" ")
        path = decode(name)
        if (mode not in ("100644", "100755") or kind != "blob"
                or path in original_tree):
            fail("UNSUPPORTED_TREE_ENTRY: " + path)
        original_tree[path] = (mode, blob)

    indexed: dict[str, tuple[str, str]] = {}
    for raw in filter(None, git("ls-files", "--stage", "-z").split(b"\0")):
        meta, name = raw.split(b"\t", 1)
        mode, blob, stage = meta.decode("ascii").split(" ")
        path = decode(name)
        if stage != "0" or path in indexed:
            fail("INDEX_STAGE_OR_DUPLICATE: " + path)
        indexed[path] = (mode, blob)
    if indexed != original_tree:
        fail("HEAD_TREE_INDEX_DRIFT")
    flags = {}
    for raw in filter(None, git("ls-files", "-v", "-z").split(b"\0")):
        flag, name = raw.split(b" ", 1)
        path = decode(name)
        if path in flags or flag != b"H":
            fail("HIDDEN_INDEX_FLAG_OR_DUPLICATE: " + path)
        flags[path] = flag
    if set(flags) != set(indexed):
        fail("INDEX_FLAG_SET_MISMATCH")

    for path, (mode, blob) in original_tree.items():
        relative = Path(path)
        if relative.is_absolute() or ".." in relative.parts:
            fail("UNSAFE_TRACKED_PATH: " + path)
        for parent in list(relative.parents)[:-1]:
            if parent.is_symlink():
                fail("SYMLINK_PARENT: " + path)
        node = relative.lstat()
        if not stat.S_ISREG(node.st_mode):
            fail("NONREGULAR_WORKTREE_PATH: " + path)
        actual_exec = bool(stat.S_IMODE(node.st_mode) & 0o111)
        if actual_exec != (mode == "100755"):
            fail("WORKTREE_EXEC_MODE_DRIFT: " + path)
        observed = git("hash-object", "--no-filters", "--", path).decode().strip()
        if observed != blob:
            fail("BLOB_BYTES_DIFFER_FROM_HEAD: " + path)

    if git("ls-files", "--others", "--exclude-standard", "-z"):
        fail("UNTRACKED_REPOSITORY_INPUT")
    if git("ls-files", "--others", "--ignored", "--exclude-standard", "-z"):
        fail("IGNORED_REPOSITORY_INPUT")
    if git("status", "--porcelain", "--untracked-files=all"):
        fail("WORKTREE_NOT_CLEAN")
    if "MANIFEST.sha256" not in original_tree:
        fail("MANIFEST_NOT_TRACKED")
    expected_manifest = [
        hashlib.sha256(Path(p).read_bytes()).hexdigest() + "  ./" + p
        for p in sorted(original_tree) if p != "MANIFEST.sha256"
    ]
    actual_manifest = Path("MANIFEST.sha256").read_text(encoding="utf-8").splitlines()
    if actual_manifest != expected_manifest:
        fail("MANIFEST_MISMATCH")
    print("G05_V2_CANDIDATE_HEAD=" + head)
    print("G05_V2_CANDIDATE_TREE=" + tree)
    print(f"G05_V2_CANDIDATE_TRACKED_BLOBS={len(original_tree)}")
    print(f"G05_V2_CANDIDATE_MANIFEST_RECORDS={len(actual_manifest)}")
    print("G05_V2_CANDIDATE_UNTRACKED_IGNORED=NONE")
    print("G05_V2_CANDIDATE_MODE_CHECK=PASS")
    print("G05_V2_CANDIDATE_PREIMPORT=PASS")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-head", required=True)
    arguments = parser.parse_args()
    verify(arguments.expected_head)
