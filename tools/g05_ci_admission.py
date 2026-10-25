#!/usr/bin/env python3
"""Fail-closed, read-only GitHub checkout/source admission (G05).

Run with: python3 -I -S tools/g05_ci_admission.py --expected-head <PR HEAD SHA>
IMMEDIATELY after checkout, before dependency installation, builds, imports, or tests.

All untracked and ignored paths are denied at this boundary, including ordinarily
benign caches. This strict choice avoids guessing what could affect an import,
build, script, tool, or symlink resolution. This does *not* attest third-party
package provenance, developer-local worktrees, or downstream OS/process safety.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.machinery
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

HEX_SHA = re.compile(r"[0-9a-f]{40}\Z")
HEX256 = re.compile(r"[0-9a-f]{64}\Z")
BLOCKED_ENV = (
    "PYTHONPATH",
    "PYTHONHOME",
    "PYTHONUSERBASE",
    "PYTHONSTARTUP",
    "PYTHONPYCACHEPREFIX",
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_COMMON_DIR",
    "GIT_OBJECT_DIRECTORY",
    "GIT_CONFIG_COUNT",
    "GIT_CONFIG_PARAMETERS",
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_SYSTEM",
)


class AdmissionError(Exception):
    """A required CI source-integrity contract is not demonstrated."""


def git(root: Path, *argv: str) -> bytes:
    result = subprocess.run(
        ["git", *argv], cwd=root, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, check=False, timeout=30,
    )
    if result.returncode:
        raise AdmissionError(
            f"git {' '.join(argv)} failed with exit {result.returncode}: "
            + result.stderr.decode("utf-8", "replace")[:250]
        )
    return result.stdout


def paths_from_nul(data: bytes, label: str) -> set[str]:
    if data and not data.endswith(b"\0"):
        raise AdmissionError(f"{label}: missing NUL terminator")
    try:
        result = [s.decode("utf-8", "strict") for s in data.split(b"\0") if s]
    except UnicodeDecodeError as exc:
        raise AdmissionError(f"{label}: non-UTF8 path") from exc
    if len(result) != len(set(result)):
        raise AdmissionError(f"{label}: duplicate Git paths")
    return set(result)


def verify_checkout(root: Path, expected_head: str) -> tuple[str, str, set[str]]:
    if not HEX_SHA.fullmatch(expected_head):
        raise AdmissionError("expected Head must be a full lowercase 40-char Git SHA")
    if not root.is_dir() or root.is_symlink():
        raise AdmissionError("checkout root must be an actual directory, not a symlink")
    if Path.cwd().resolve() != root.resolve():
        raise AdmissionError("preflight must run from the checkout root")
    for name in BLOCKED_ENV:
        if os.environ.get(name):
            raise AdmissionError(f"unapproved import/Git environment variable: {name}")
    # Git may hide real content or executable-bit changes through index flags
    # or local configuration. Do not rely on git status as the only integrity
    # oracle, and reject the anomalous settings themselves.
    if git(root, "config", "--local", "--bool", "core.filemode").strip() != b"true":
        raise AdmissionError("Git core.filemode must be true for G05 admission")
    top = Path(os.fsdecode(git(root, "rev-parse", "--show-toplevel")).strip())
    if top.resolve() != root.resolve():
        raise AdmissionError("checkout is not the Git repository root")
    head = git(root, "rev-parse", "HEAD").decode("ascii").strip()
    tree = git(root, "rev-parse", "HEAD^{tree}").decode("ascii").strip()
    if head != expected_head or not HEX_SHA.fullmatch(tree):
        raise AdmissionError("checked-out Head does not match authorized PR Head/Tree")
    # Check the entire tracked worktree, including index state. Git status alone
    # misses ignored files, so both ignored and untracked are checked separately.
    if git(root, "status", "--porcelain=v1", "-z", "--untracked-files=all"):
        raise AdmissionError("checkout contains tracked changes or untracked paths")
    other = paths_from_nul(
        git(root, "ls-files", "--others", "--exclude-standard", "-z"),
        "untracked paths",
    )
    ignored = paths_from_nul(
        git(root, "ls-files", "--others", "--ignored", "--exclude-standard", "-z"),
        "ignored paths",
    )
    if other or ignored:
        examples = sorted(other | ignored)[:5]
        raise AdmissionError(
            f"untracked/ignored checkout inputs are forbidden: {examples!r}"
        )
    tracked = paths_from_nul(git(root, "ls-files", "--cached", "-z"), "tracked paths")
    # A hidden assume-unchanged (lowercase h) or skip-worktree (S) entry
    # can make porcelain status falsely clean; require normal H entries only.
    flags = git(root, "ls-files", "-v", "-z")
    names = paths_from_nul(flags, "Git index flags")
    if names != {"H " + path for path in tracked}:
        raise AdmissionError("Git index flags hide tracked changes or differ from HEAD")
    if "MANIFEST.sha256" not in tracked or "gateway/__init__.py" not in tracked:
        raise AdmissionError("required tracked Manifest or gateway entry point missing")
    return head, tree, tracked


def verify_head_tree(root: Path, tracked: set[str]) -> int:
    """Bind actual on-disk bytes and executable bits to immutable HEAD blobs.

    This intentionally does not consult index stat caches, Git attributes,
    smudge filters, filemode configuration, or the mutable Manifest for truth.
    Manifest itself is included, so it cannot be modified with matching edits
    to the source and still receive G05 PASS.
    """
    entries = git(root, "ls-tree", "--full-tree", "-r", "-z", "HEAD")
    if not entries or not entries.endswith(b"\0"):
        raise AdmissionError("native HEAD Git Tree is incomplete")
    actual: set[str] = set()
    for row in entries.split(b"\0")[:-1]:
        meta, tab, path = row.partition(b"\t")
        parts = meta.split(b" ")
        if tab != b"\t" or len(parts) != 3:
            raise AdmissionError("malformed native HEAD Tree record")
        mode, kind, object_id = parts
        if mode not in {b"100644", b"100755"} or kind != b"blob" or not HEX_SHA.fullmatch(object_id.decode("ascii")):
            raise AdmissionError("not a regular file or unsupported tracked HEAD Tree entry")
        try:
            name = path.decode("utf-8", "strict")
        except UnicodeDecodeError as exc:
            raise AdmissionError("non-UTF8 native HEAD path") from exc
        if not name or name.startswith("/") or any(p in {"", ".", ".."} for p in name.split("/")) or name in actual:
            raise AdmissionError("unsafe or duplicate native HEAD Tree path")
        actual.add(name)
        file = root
        for part in name.split("/")[:-1]:
            file = file / part
            if not stat.S_ISDIR(file.lstat().st_mode):
                raise AdmissionError("tracked path parent is not an actual directory")
        file = file / name.split("/")[-1]
        before = file.lstat()
        if not stat.S_ISREG(before.st_mode):
            raise AdmissionError(f"HEAD path is no longer a regular file: {name}")
        expected_exec = mode == b"100755"
        if bool(before.st_mode & 0o111) != expected_exec:
            raise AdmissionError(f"HEAD Tree executable mode mismatch: {name}")
        raw = file.read_bytes()
        # Git's object hash for this SHA-1 repository, no Git filters/index.
        header = b"blob " + str(len(raw)).encode("ascii") + b"\0"
        if hashlib.sha1(header + raw).hexdigest().encode("ascii") != object_id:
            raise AdmissionError(f"HEAD Tree blob content mismatch: {name}")
        after = file.lstat()
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns, before.st_mode) != (
            after.st_size, after.st_mtime_ns, after.st_ctime_ns, after.st_mode
        ):
            raise AdmissionError(f"tracked path changed while verifying HEAD: {name}")
    if actual != tracked:
        raise AdmissionError("native HEAD Tree and cached tracked path set differ")
    return len(actual)


def verify_manifest(root: Path, tracked: set[str]) -> int:
    manifest = root / "MANIFEST.sha256"
    if manifest.is_symlink() or not manifest.is_file():
        raise AdmissionError("Manifest must be a regular tracked file")
    try:
        rows = manifest.read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeError) as exc:
        raise AdmissionError("Manifest unreadable/non-ASCII") from exc
    listed: list[bytes] = []
    for row in rows:
        if "  ./" not in row:
            raise AdmissionError("malformed Manifest record")
        digest, name = row.split("  ./", 1)
        if not HEX256.fullmatch(digest) or not name:
            raise AdmissionError("malformed Manifest SHA-256 or path")
        parts = Path(name).parts
        if Path(name).is_absolute() or any(x in {"", ".", ".."} for x in parts):
            raise AdmissionError("Manifest contains unsafe relative path")
        raw = name.encode("utf-8")
        listed.append(raw)
        file = root / name
        if file.is_symlink() or not file.is_file() or not stat.S_ISREG(file.stat().st_mode):
            raise AdmissionError(f"tracked Manifest path is not a regular file: {name}")
        if hashlib.sha256(file.read_bytes()).hexdigest() != digest:
            raise AdmissionError(f"tracked Manifest content hash mismatch: {name}")
    if listed != sorted(set(listed)):
        raise AdmissionError("Manifest path order/uniqueness is invalid")
    tracked_without_manifest = tracked - {"MANIFEST.sha256"}
    if {x.decode("utf-8") for x in listed} != tracked_without_manifest:
        raise AdmissionError("Manifest is not identical to the full tracked file set")
    if not rows:
        raise AdmissionError("Manifest is empty")
    return len(rows)


def verify_project_import_root(root: Path, tracked: set[str]) -> str:
    # PathFinder metadata inspection does not execute gateway/__init__.py.
    # Actual pytest uses the workspace root as an import root; independently
    # verify that the gateway package resolves to the tracked tree there.
    spec = importlib.machinery.PathFinder.find_spec("gateway", [str(root)])
    expected = root / "gateway" / "__init__.py"
    if spec is None or spec.origin is None or not spec.submodule_search_locations:
        raise AdmissionError("gateway package does not resolve from tracked checkout")
    if Path(spec.origin).resolve() != expected.resolve():
        raise AdmissionError("gateway package import is shadowed")
    if "gateway/__init__.py" not in tracked:
        raise AdmissionError("import root is not tracked")
    return "gateway/__init__.py"


def admit(root: Path, expected_head: str) -> None:
    head, tree, tracked = verify_checkout(root, expected_head)
    head_count = verify_head_tree(root, tracked)
    count = verify_manifest(root, tracked)
    if head_count != count + 1:
        raise AdmissionError("Manifest and HEAD Tree counts differ")
    entry = verify_project_import_root(root, tracked)
    # A second scan detects mutations that occur while source hashes are read.
    # This is a preflight of an isolated runner, not an adversarial OS sandbox.
    check_head, check_tree, check_tracked = verify_checkout(root, expected_head)
    if (head, tree, tracked) != (check_head, check_tree, check_tracked):
        raise AdmissionError("checkout changed during source preflight")
    # A second on-disk-to-HEAD proof is needed; another status scan alone can
    # remain falsely green when Git index flags/configuration mask drift.
    if verify_head_tree(root, check_tracked) != head_count:
        raise AdmissionError("native HEAD source identity changed during preflight")
    print("G05_CHECKED_OUT_HEAD=" + head)
    print("G05_CHECKED_OUT_TREE=" + tree)
    print("G05_HEAD_BLOB_AND_EXEC_MODE=PASS count=" + str(head_count))
    print("G05_TRACKED_SHA256_MANIFEST=PASS count=" + str(count))
    print("G05_EXECUTION_IMPORT_ROOT=" + entry)
    print("G05_UNTRACKED_IGNORED_RUNTIME_INPUTS=NONE")
    print("G05_REPOSITORY_ADMISSION=PASS")
    print("G05_THIRD_PARTY_DEPENDENCY_PROVENANCE=NOT_ATTESTED")
    print("G05_DEVELOPER_LOCAL_WORKTREE=NOT_OBSERVED")
    print("G05_INTEGRATION_STATUS=NOT_TESTED")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-head", required=True)
    args = parser.parse_args(argv)
    try:
        admit(Path.cwd(), args.expected_head)
    except (AdmissionError, OSError, ValueError, subprocess.TimeoutExpired) as exc:
        print("G05_REPOSITORY_ADMISSION=FAIL", file=sys.stderr)
        print("G05_R01_GATE=INCOMPLETE", file=sys.stderr)
        print("G05_REASON=" + str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
