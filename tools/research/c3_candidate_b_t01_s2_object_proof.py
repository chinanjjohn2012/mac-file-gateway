"""B03-T01 R2b-R2b-R2-S2: real CANDIDATE OBJECT evidence, no link/load.

Only the frozen inert C test model is compiled with fixed flags using cc -c.
The resulting ephemeral relocatable .o is inspected using fixed OS utilities,
never linked, loaded or called. All evidence is PARTIAL: an entry binary's SHA
cannot prove its actual compiler backend, SDK resource closure, or the final
runtime library/call graph. Unknown results fail the object-inspection stage.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import stat
import tempfile
import time

import c3_candidate_b_t01_s0_abi_proof as s0

ROOT = s0.ROOT
SOURCE = s0.SOURCE
HEADER = s0.HEADER
MANIFEST = s0.MANIFEST
SYMBOL = "c3b03_t01_no_signal_candidate"
FLAGS = (
    "-std=c11", "-O0", "-fPIC", "-Wall", "-Wextra", "-Werror",
    "-pedantic", "-fno-stack-protector", "-fno-builtin",
    "-fno-asynchronous-unwind-tables", "-fno-unwind-tables",
    "-DC3B03_TEST_NO_SIGNAL_STUB=1",
)
TOOLS = {
    "Darwin": ("/usr/bin/nm", "/usr/bin/file", "/usr/bin/otool"),
    "Linux": ("/usr/bin/nm", "/usr/bin/file", "/usr/bin/objdump"),
}
ENV = {"PATH": s0._ALLOWED_PATH, "LC_ALL": "C"}

_REVIEWED_INCLUDES = frozenset({
    '"c3_b03_t01_no_signal_contract.h"', "<stdint.h>",
})


def _validated_source_includes(text: str) -> None:
    """Conservative exact #include set, after removing C comments."""
    code = re.sub(r"/\*[\s\S]*?\*/", "", text)
    code = re.sub(r"//[^\n]*", "", code)
    includes = re.findall(r'^\s*#\s*include\s*([<"][^>"]+[>"])', code, re.M)
    if len(includes) != 2 or frozenset(includes) != _REVIEWED_INCLUDES:
        raise ValueError("UNREVIEWED_C_INCLUDE_CLOSURE")


def _metadata_gate(platform: str, file_description: str,
                   defined: str, undefined: str, disassembly: str) -> str:
    """Narrow C *object* gate, not a complete machine-code CFG verifier.

    A caller cannot pass a forged success flag or an arbitrary symbol name.
    """
    if platform not in TOOLS:
        raise ValueError("UNKNOWN_OBJECT_PLATFORM")
    expected_file = (
        ("Mach-O", "64-bit", "arm64", "object") if platform == "Darwin"
        else ("ELF", "64-bit", "x86-64", "relocatable")
    )
    if not all(x.lower() in file_description.lower() for x in expected_file):
        raise ValueError("UNEXPECTED_OBJECT_ARCH_OR_FORMAT")
    if undefined.strip():
        raise ValueError("OBJECT_UNDEFINED_SYMBOLS")
    entries = [line.strip() for line in defined.splitlines() if line.strip()]
    symbol = "_" + SYMBOL if platform == "Darwin" else SYMBOL
    if len(entries) != 1 or re.fullmatch(
        r"[a-fA-F0-9]{8,16}\s+T\s+" + re.escape(symbol), entries[0]
    ) is None:
        raise ValueError("UNEXPECTED_OBJECT_SYMBOLS")
    if len(disassembly) < 100 or SYMBOL not in disassembly:
        raise ValueError("OBJECT_DISASSEMBLY_MISSING")
    lower = disassembly.lower()
    for forbidden in (
        "\tsyscall", "\tsysenter", "svc #", "int $0x80",
        "\tud2", "\thlt", "\tint3",
    ):
        if forbidden in lower:
            raise ValueError("OBJECT_KNOWN_FORBIDDEN_INSTRUCTION")
    return "OBJECT_INSPECTION_PARTIAL_NO_LOAD"


def _run_tool(argv: tuple[str, ...]) -> str:
    if not argv or argv[0] not in TOOLS["Darwin"] + TOOLS["Linux"]:
        raise ValueError("DISALLOWED_OBJECT_INSPECTION_TOOL")
    result = s0._fixed_run(argv, env=ENV)
    if result.returncode != 0:
        raise ValueError("OBJECT_INSPECTION_FAILED: " + result.stderr[:450])
    return result.stdout


def _compile_candidate(variant: str = "reviewed") -> dict[str, object]:
    """Actual object S2 observation, immediately discarded; NO link or C run.

    variant is test-controlled and can only be 1, 0, 2 or absent. A rejected
    no-signal macro must fail compilation; never create an execution fallback.
    """
    if variant not in ("reviewed", "missing", "zero", "two"):
        raise ValueError("UNKNOWN_TEST_VARIANT")
    files = s0.checked_manifest()
    current_head, current_tree = s0.current_revision()
    _validated_source_includes(SOURCE.read_text(encoding="utf-8"))
    source_before, _ = s0._sha_regular(SOURCE)
    header_before, _ = s0._sha_regular(HEADER)
    if source_before != s0.REVIEWED_C_SHA256 or header_before != s0.REVIEWED_HEADER_SHA256:
        raise ValueError("REVIEWED_SOURCE_BYTES_CHANGED")
    if files["./" + SOURCE.relative_to(ROOT).as_posix()] != source_before:
        raise ValueError("SOURCE_MANIFEST_MISMATCH")
    if files["./" + HEADER.relative_to(ROOT).as_posix()] != header_before:
        raise ValueError("HEADER_MANIFEST_MISMATCH")
    compiler, compiler_sha_before = s0._compiler_entry()
    platform = "Darwin" if os.uname().sysname == "Darwin" else "Linux"
    if platform not in TOOLS:
        raise ValueError("UNKNOWN_OBJECT_PLATFORM")
    with tempfile.TemporaryDirectory(prefix="c3b03-candidate-s2-object-no-load-") as tmp:
        temp = Path(tmp).resolve(strict=True)
        if stat.S_IMODE(temp.stat().st_mode) != 0o700:
            raise ValueError("OBJECT_TEMP_NOT_PRIVATE")
        obj = temp / "candidate-inert.o"
        args = [str(compiler), *(flag for flag in FLAGS if
                not flag.startswith("-DC3B03_TEST_NO_SIGNAL_STUB="))]
        if variant == "reviewed":
            args.append("-DC3B03_TEST_NO_SIGNAL_STUB=1")
        elif variant == "zero":
            args.append("-DC3B03_TEST_NO_SIGNAL_STUB=0")
        elif variant == "two":
            args.append("-DC3B03_TEST_NO_SIGNAL_STUB=2")
        args.extend(("-I", str(HEADER.parent), "-c", "-o", str(obj), str(SOURCE)))
        argv = tuple(args)
        if (any(flag in argv for flag in ("-shared", "-dynamiclib", "-Wl", "-E",
                                         "-fsyntax-only")) or
                argv.count("-c") != 1 or argv.count("-o") != 1):
            raise ValueError("UNREVIEWED_BUILD_ARGS")
        hash_observed_at_ns = time.monotonic_ns()
        # The preceding byte hash is complete BEFORE entering subprocess.run.
        # This timestamp describes when Python submitted the call, not an
        # atomic kernel-level fexecve identity or nested toolchain proof.
        compiler_call_started_at_ns = time.monotonic_ns()
        compiler_result = s0._fixed_run(argv, env=ENV)
        # These times are ordering witnesses only, not loader authority.
        compiler_after, compiler_sha_after = s0._compiler_entry()
        if compiler_after != compiler or compiler_sha_before != compiler_sha_after:
            raise ValueError("COMPILER_ENTRY_CHANGED")
        if s0._sha_regular(SOURCE)[0] != source_before or (
            s0._sha_regular(HEADER)[0] != header_before
        ):
            raise ValueError("BUILD_INPUT_CHANGED")
        if variant != "reviewed":
            if compiler_result.returncode == 0 or obj.exists():
                raise ValueError("BAD_NO_SIGNAL_MACRO_ACCEPTED")
            if "test C candidate requires exact no-signal stub 1" not in (
                compiler_result.stderr
            ):
                raise ValueError("REJECTED_WITH_UNEXPECTED_REASON")
            return {
                "variant": variant, "admission": "REJECT",
                "compiler_returncode": compiler_result.returncode,
                "candidate_object_sha256": None, "candidate_c_executed": False,
                "native_loader_invoked": False, "group_signal_authorized": False,
            }
        if compiler_result.returncode != 0:
            raise ValueError("CANDIDATE_OBJECT_COMPILE_FAILED:" +
                             compiler_result.stderr[:400])
        obj_sha, attrs = s0._sha_regular(obj)
        if attrs.st_nlink != 1 or attrs.st_uid != os.getuid():
            raise ValueError("OBJECT_OWNER_OR_NLINK")
        nm, filetool, disassembler = TOOLS[platform]
        file_description = _run_tool((filetool, str(obj)))
        undefined = _run_tool((nm, "-u", str(obj)))
        defined = _run_tool((nm, "-g", str(obj)))
        disassembler_args = ((disassembler, "-tv", str(obj)) if platform == "Darwin"
                             else (disassembler, "-dr", str(obj)))
        disasm = _run_tool(disassembler_args)
        _metadata_gate(platform, file_description, defined, undefined, disasm)
        return {
            "current_head": current_head,
            "current_tree": current_tree,
            "reviewed_parent_head": s0.PARENT_HEAD,
            "reviewed_parent_tree": s0.PARENT_TREE,
            "manifest_sha256": s0._sha_regular(MANIFEST)[0],
            "source_sha256_precompile": source_before,
            "source_sha256_postcompile": s0._sha_regular(SOURCE)[0],
            "header_sha256_precompile": header_before,
            "header_sha256_postcompile": s0._sha_regular(HEADER)[0],
            "compiler_entry_sha256_precompile": compiler_sha_before,
            "compiler_entry_sha256_postcompile": compiler_sha_after,
            "compiler_entry_realpath": str(compiler),
            "compile_argv_sha256": hashlib.sha256(
                "\0".join(argv).encode("utf-8")
            ).hexdigest(),
            "compiler_entry_hash_recorded_before_compile": (
                hash_observed_at_ns < compiler_call_started_at_ns
            ),
            "platform": platform,
            "candidate_object_sha256": obj_sha,
            "object_format": file_description.strip(),
            "defined_global_symbol": defined.strip(),
            "undefined_symbols": 0,
            "disassembly_sha256": hashlib.sha256(
                disasm.encode("utf-8")
            ).hexdigest(),
            "disassembly": disasm,
            "candidate_c_executed": False,
            "native_loader_invoked": False,
            "group_signal_authorized": False,
            "native_dispatches": 0,
            "complete_toolchain_sdk_closure_proven": False,
            "complete_object_cfg_proven": False,
            "final_linked_image_proven": False,
            "python_ffi_binding_proven": False,
            "preload_custody_proven": False,
            "first_c_load_authorized": False,
            "admission": "REVIEW_REQUIRED_NO_LOAD",
        }
