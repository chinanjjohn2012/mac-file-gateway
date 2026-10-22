"""B03-T01 R2b-R2b-R2-S0: actual SOURCE + compile-only C ABI evidence.

Only Python stdlib, git inspection, and a strictly fixed C compiler -c call
on the review-only _Static_assert translation unit. NEVER link/load/execute
the candidate C, create a library, obtain a host PGID, or send a signal.
Driver SHA is collected BEFORE the compiler starts, but the nested driver /
linker / SDK/resource closure is NOT pinned: S1/P3-01 remain OPEN.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "tools/research/c3_candidate_b_t01_no_signal_candidate.c"
HEADER = ROOT / "tests/native/c3_b03_t01_no_signal_contract.h"
ABI_C = ROOT / "tests/native/c3_b03_t01_abi_compile_only.c"
SOURCE_ONLY = ROOT / "tools/research/c3_candidate_b_t01_r2_source_only_adapter.py"
MANIFEST = ROOT / "MANIFEST.sha256"
PARENT_HEAD = "37bd517932b6b99952fa19e091b5b8d94d45939a"
PARENT_TREE = "ed661fe5ea2297b89c9ba96bd312e01a5a4f8778"
REVIEWED_C_SHA256 = "5a1292787584632fac20c86bbe62e50153e82b0ecb36ad190446bf4b7b714195"
REVIEWED_HEADER_SHA256 = "7c9bd037ecf65da8de91605846c4ac4fc7ceaebbd0ca2fe983ecfef630c9958e"
_GIT_OID = re.compile(r"[a-f0-9]{40}\Z")
_SHA256 = re.compile(r"[a-f0-9]{64}\Z")
_ALLOWED_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"
_COMPILE_FLAGS = (
    "-std=c11", "-O0", "-Wall", "-Wextra", "-Werror", "-pedantic",
    "-fno-builtin", "-fno-stack-protector", "-DC3B03_TEST_NO_SIGNAL_STUB=1",
)


def _sha_regular(path: Path) -> tuple[str, os.stat_result]:
    """Byte SHA from a nofollow FD; refuse alternate file types and changes."""
    if path.is_symlink():
        raise ValueError("SYMLINK_SOURCE")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        first = os.fstat(fd)
        if not stat.S_ISREG(first.st_mode):
            raise ValueError("NOT_REGULAR")
        h = hashlib.sha256()
        while True:
            chunk = os.read(fd, 131072)
            if not chunk:
                break
            h.update(chunk)
        last = os.fstat(fd)
        if (first.st_dev, first.st_ino, first.st_size, first.st_mtime_ns) != (
            last.st_dev, last.st_ino, last.st_size, last.st_mtime_ns
        ):
            raise ValueError("FILE_CHANGED_DURING_HASH")
        return h.hexdigest(), first
    finally:
        os.close(fd)


def _manifest_checked_path(root: Path, rel: str) -> Path:
    """Reject symlinks on EVERY manifest component before resolve/check.

    This is a source-stage best-effort path gate, not an atomic S5 loader
    custody mechanism: a hostile concurrent writer still requires proof.
    """
    if not rel.startswith("./") or not rel[2:] or "\0" in rel:
        raise ValueError("UNSAFE_MANIFEST_PATH")
    parts = rel[2:].split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise ValueError("UNSAFE_MANIFEST_PATH")
    node = root
    for part in parts:
        node = node / part
        if node.is_symlink():
            raise ValueError("MANIFEST_SYMLINK_COMPONENT")
    resolved = node.resolve(strict=True)
    if not resolved.is_relative_to(root.resolve(strict=True)):
        raise ValueError("MANIFEST_PATH_ESCAPED")
    return resolved


def checked_manifest() -> dict[str, str]:
    digest, _ = _sha_regular(MANIFEST)
    assert _SHA256.fullmatch(digest)
    items: dict[str, str] = {}
    previous = ""
    for line in MANIFEST.read_text(encoding="ascii").splitlines():
        sha, separator, rel = line.partition("  ")
        if separator != "  " or not _SHA256.fullmatch(sha):
            raise ValueError("INVALID_MANIFEST_ROW")
        if (not rel.startswith("./") or rel <= previous or
                "/../" in rel or rel.endswith("/..")):
            raise ValueError("UNSORTED_OR_UNSAFE_MANIFEST_PATH")
        previous = rel
        path = _manifest_checked_path(ROOT, rel)
        observed, _ = _sha_regular(path)
        if observed != sha:
            raise ValueError("MANIFEST_BYTES_MISMATCH:" + rel)
        items[rel] = sha
    for required in (SOURCE, HEADER, ABI_C, SOURCE_ONLY):
        name = "./" + required.relative_to(ROOT).as_posix()
        if name not in items:
            raise ValueError("UNTRACKED_BUILD_INPUT:" + name)
    if items["./" + SOURCE.relative_to(ROOT).as_posix()] != REVIEWED_C_SHA256:
        raise ValueError("REVIEWED_C_SOURCE_DRIFT")
    if items["./" + HEADER.relative_to(ROOT).as_posix()] != REVIEWED_HEADER_SHA256:
        raise ValueError("REVIEWED_C_HEADER_DRIFT")
    return items


def _fixed_run(argv: tuple[str, ...], *, env: dict[str, str], timeout=30):
    return subprocess.run(
        argv, cwd=ROOT, env=env, timeout=timeout, check=False,
        capture_output=True, text=True,
    )


def _git(arg: str) -> str:
    cmd = ("/usr/bin/git", "rev-parse", arg)
    p = _fixed_run(cmd, env={"PATH": _ALLOWED_PATH, "LC_ALL": "C"})
    if p.returncode:
        raise ValueError("GIT_REV_PARSE_FAILED:" + p.stderr)
    result = p.stdout.strip()
    if not _GIT_OID.fullmatch(result):
        raise ValueError("INVALID_GIT_OBJECT_ID")
    return result


def current_revision() -> tuple[str, str]:
    head, tree = _git("HEAD"), _git("HEAD^{tree}")
    # Under GitHub exact checkout, parent is a fixed reviewed ancestor. This
    # function reports the current child tree but does not self-approve it.
    assert head != PARENT_HEAD, "Use this proof only on a NEW child commit"
    return head, tree


def _compiler_entry() -> tuple[Path, str]:
    entry = shutil.which("cc", path=_ALLOWED_PATH)
    if not entry:
        raise ValueError("C_COMPILER_NOT_FOUND")
    # This pins only one pre-spawn *entry* binary. A shim/driver may choose an
    # unverified backend and SDK: never label S1 complete or allow Native load.
    resolved = Path(entry).resolve(strict=True)
    digest, _ = _sha_regular(resolved)
    return resolved, digest


def _compile_abi_once(
    *,
    header: bytes | None = None,
    variant: str = "reviewed",
) -> dict[str, object]:
    """Compile a C11 _Static_assert TU to a temp .o. NO link or execution."""
    if not re.fullmatch(r"[a-z-]{1,25}", variant):
        raise ValueError("BAD_VARIANT_NAME")
    compiler, driver_sha_before = _compiler_entry()
    env = {"PATH": _ALLOWED_PATH, "LC_ALL": "C"}
    # Capture snapshot strictly BEFORE subprocess.run(cc -c) starts.
    entry_hashed_at_ns = time.monotonic_ns()
    with tempfile.TemporaryDirectory(prefix="c3b03-abi-static-no-load-") as temp:
        root = Path(temp).resolve(strict=True)
        if stat.S_IMODE(root.stat().st_mode) != 0o700:
            raise ValueError("ABI_TEMP_NOT_PRIVATE")
        obj = root / "abi-proof.o"
        if header is None:
            include = HEADER.parent
            source = ABI_C
        else:
            local_header = root / HEADER.name
            local_source = root / ABI_C.name
            local_header.write_bytes(header)
            local_source.write_bytes(ABI_C.read_bytes())
            include, source = root, local_source
        argv = (
            str(compiler), *_COMPILE_FLAGS, "-I", str(include),
            "-c", "-o", str(obj), str(source),
        )
        if any(x in argv for x in ("-shared", "-dynamiclib", "-Wl",
                                   "-fPIC", "-fsyntax-only")):
            raise ValueError("UNAPPROVED_ABI_COMPILER_ARGS")
        spawned_at_ns = time.monotonic_ns()
        out = _fixed_run(argv, env=env)
        _, driver_sha_after = _compiler_entry()
        if driver_sha_before != driver_sha_after:
            raise ValueError("COMPILER_ENTRY_CHANGED")
        object_sha = None
        if out.returncode == 0:
            object_sha, attrs = _sha_regular(obj)
            if attrs.st_nlink != 1 or attrs.st_uid != os.getuid():
                raise ValueError("ABI_OBJECT_CUSTODY_FAILED")
        return {
            "variant": variant,
            "compiler_entry_realpath": str(compiler),
            "compiler_entry_sha256_precompile": driver_sha_before,
            "compiler_entry_sha256_postcompile": driver_sha_after,
            "entry_hashed_before_compiler_spawn": entry_hashed_at_ns < spawned_at_ns,
            "compiler_argv_sha256": hashlib.sha256(
                "\0".join(argv).encode("utf-8")
            ).hexdigest(),
            "compiler_returncode": out.returncode,
            "compiler_stderr": out.stderr,
            "abi_object_sha256": object_sha,
            "compiler_sdk_linker_closure_complete": False,
            "native_loader_invoked": False,
            "candidate_c_executed": False,
            "group_signal_authorized": False,
            "native_dispatches": 0,
            "admission": "REVIEW_REQUIRED_NO_LOAD" if out.returncode == 0 else "REJECT",
        }


def collect_static_abi_evidence() -> dict[str, object]:
    """Actual source + compiler-entry + ABI object evidence, NOT S1-S6."""
    items = checked_manifest()
    head, tree = current_revision()
    proof = _compile_abi_once()
    if proof["compiler_returncode"] != 0:
        raise ValueError("ABI_STATIC_ASSERT_FAILED:" + str(proof["compiler_stderr"]))
    if not proof["entry_hashed_before_compiler_spawn"]:
        raise ValueError("NOT_PRECOMPILE_PROVENANCE")
    if not proof["abi_object_sha256"]:
        raise ValueError("NO_ABI_OBJECT")
    proof.update({
        "reviewed_parent_head": PARENT_HEAD,
        "reviewed_parent_tree": PARENT_TREE,
        "current_head": head,
        "current_tree": tree,
        "manifest_entry_count": len(items),
        "manifest_sha256": _sha_regular(MANIFEST)[0],
        "reviewed_c_sha256": _sha_regular(SOURCE)[0],
        "reviewed_c_header_sha256": _sha_regular(HEADER)[0],
        "abi_assertions_sha256": _sha_regular(ABI_C)[0],
        "source_only_adapter_sha256": _sha_regular(SOURCE_ONLY)[0],
        "abi_struct_sizes": {
            "c3b03_t01_deadline_t": 64,
            "c3b03_t01_mock_input_t": 208,
            "c3b03_t01_mock_output_t": 48,
        },
        "real_preload_chain_proven": False,
        "ffi_binding_proven": False,
        "first_c_load_authorized": False,
    })
    return proof
