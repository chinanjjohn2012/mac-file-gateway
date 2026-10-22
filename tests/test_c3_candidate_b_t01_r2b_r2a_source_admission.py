"""B03-T01-R2b-R2a: SOURCE/OBJECT admission checks; NEVER execute C.

This is a compile-and-inspect-only stage. Subprocess usage is limited to
compiler/object-inspection tooling. No ctypes, dlopen, native binary launch,
process group signal, or user-specified PID/PGID is permitted.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import re
import subprocess
import tempfile

import pytest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tools/research/c3_candidate_b_t01_no_signal_candidate.c"
HEADER = ROOT / "tests/native/c3_b03_t01_no_signal_contract.h"
PLAN = ROOT / "docs/research/phase2-lite-c3/candidate-b-b03-t01-r2b-r2a-source-admission.md"
WORKFLOW = ROOT / ".github/workflows/c3-candidate-b-t01-r2b-r2a-source-admission.yml"
SYMBOL = "c3b03_t01_no_signal_candidate"

# The C candidate and its test-owned header may use no operating-system or
# C-runtime services. The object is inspected, never linked or loaded.
_ALLOWED_INCLUDES = {
    '"c3_b03_t01_no_signal_contract.h"',
    "<stdint.h>",
}


def _run(command: list[str], *, timeout=30) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command, capture_output=True, text=True, check=False, timeout=timeout,
        cwd=ROOT,
    )


def _compile(mode: str | None, *, syntax_only: bool, output: Path | None = None):
    assert output is None if syntax_only else output is not None
    args = [
        "cc", "-std=c11", "-O0", "-Wall", "-Wextra", "-Werror",
        "-pedantic", "-fno-stack-protector", "-fno-builtin",
        "-I", str(HEADER.parent),
    ]
    if mode is not None:
        args.append("-DC3B03_TEST_NO_SIGNAL_STUB=" + mode)
    if syntax_only:
        args.append("-fsyntax-only")
    else:
        args.extend(("-c", "-o", str(output)))
    args.append(str(SOURCE))
    assert not any(x in args for x in ("-shared", "-dynamiclib", "-oexe", "-Wl"))
    return _run(args)


def _strip_comments(text: str) -> str:
    """Conservative parser for this reviewed comment/string-light C subset."""
    text = re.sub(r"/\*[\s\S]*?\*/", "", text)
    text = re.sub(r"//[^\n]*", "", text)
    return text


def test_source_is_test_only_and_no_os_api_surface():
    assert SOURCE.is_file()
    assert HEADER.is_file()
    assert PLAN.is_file() and WORKFLOW.is_file()
    code = SOURCE.read_text(encoding="utf-8")
    parsed = _strip_comments(code)
    includes = set(re.findall(r'^\s*#\s*include\s*([<"][^>"]+[>"])', parsed, re.M))
    assert includes == _ALLOWED_INCLUDES
    assert "#elif C3B03_TEST_NO_SIGNAL_STUB != 1" in parsed
    assert "#ifndef C3B03_TEST_NO_SIGNAL_STUB" not in parsed
    assert "#include <signal.h>" not in parsed
    assert "pid_t" not in parsed and "pgid_t" not in parsed
    for unsafe in (
        r"\bkill\s*\(", r"\bkillpg\s*\(", r"\bsyscall\s*\(",
        r"\bposix_spawn\s*\(", r"\bfork\s*\(", r"\bexec[a-z]*\s*\(",
        r"\bwaitpid\s*\(", r"\bsystem\s*\(", r"\bpopen\s*\(",
        r"\bdlopen\s*\(", r"\bdlsym\s*\(", r"\b__asm__\b",
        r"\b__attribute__\b",
    ):
        assert re.search(unsafe, parsed) is None, unsafe
    assert "int " + SYMBOL + "(" in parsed
    assert "C3B03_T01_SYNTHETIC_KILL_ADMITTED" in parsed
    assert "C3_TERM_TEST_FACTS" in parsed and "C3_KILL_TEST_FACTS" in parsed


@pytest.mark.parametrize("flag,allowed", (
    (None, False), ("0", False), ("2", False), ("1", True),
))
def test_source_compile_macro_admission_requires_exact_one(flag, allowed):
    r = _compile(flag, syntax_only=True)
    if allowed:
        assert r.returncode == 0, r.stdout + r.stderr
    else:
        assert r.returncode != 0, "unsafe preprocessor build admitted"
        assert "exact no-signal stub 1" in r.stderr or (
            "C3B03_TEST_NO_SIGNAL_STUB must be exactly 1" in r.stderr
        )


def test_compiled_object_has_zero_undefined_symbols_and_no_syscall_opcode():
    """Only object compilation and inspection, never dynamic loading."""
    with tempfile.TemporaryDirectory(prefix="c3b03-t01-object-proof-") as tmp:
        object_path = Path(tmp) / "synthetic-no-signal.o"
        built = _compile("1", syntax_only=False, output=object_path)
        assert built.returncode == 0, built.stderr
        assert object_path.is_file()
        sha = hashlib.sha256(object_path.read_bytes()).hexdigest()
        assert len(sha) == 64
        undefined = _run(["nm", "-u", str(object_path)])
        assert undefined.returncode == 0, undefined.stderr
        assert not undefined.stdout.strip(), (
            "candidate links to external services: " + undefined.stdout
        )
        defined = _run(["nm", "-g", str(object_path)])
        assert defined.returncode == 0, defined.stderr
        exported = defined.stdout.splitlines()
        assert len(exported) == 1, exported
        assert SYMBOL in exported[0], exported

        # Review original disassembly without executing any C instructions.
        mac = _run(["uname", "-s"])
        assert mac.returncode == 0
        if mac.stdout.strip() == "Darwin":
            disassembly = _run(["otool", "-tv", str(object_path)])
        else:
            disassembly = _run(["objdump", "-dr", str(object_path)])
        assert disassembly.returncode == 0, disassembly.stderr
        asm = disassembly.stdout.lower()
        assert len(asm) > 100
        for forbidden in ("svc #", "\tsyscall", "\tsysenter", "int $0x80"):
            assert forbidden not in asm, forbidden
        # Expose the ORIGINAL object proof to independent GitHub reviewers.
        # Without pytest -s, successful test stdout is hidden by capture.
        print(f"C3B03_T01_R2B_R2A_OBJECT_SHA256={sha}")
        print("C3B03_T01_R2B_R2A_UNDEFINED_SYMBOLS=0")
        print("C3B03_T01_R2B_R2A_EXPORTED=" + exported[0].strip())
        print("C3B03_T01_R2B_R2A_DISASSEMBLY_SHA256=" +
              hashlib.sha256(disassembly.stdout.encode("utf-8")).hexdigest())
        print("C3B03_T01_R2B_R2A_DISASSEMBLY_BEGIN")
        print(disassembly.stdout)
        print("C3B03_T01_R2B_R2A_DISASSEMBLY_END")
        print("C3B03_T01_R2B_R2A_C_EXECUTED=false")


def test_source_is_not_native_owner_or_runtime_group_signal():
    doc = PLAN.read_text(encoding="utf-8")
    workflow = WORKFLOW.read_text(encoding="utf-8")
    for phrase in (
        "SOURCE_AND_OBJECT_ADMISSION_ONLY",
        "C_EXECUTED=false",
        "group_kill_authorized=false",
        "reuse_proven=false",
        "g2_qualified=false",
        "P3-01",
        "Adapter",
        "NOT_RUN/BLOCK",
        "no live group-signal path",
        "binary provenance",
    ):
        assert phrase in doc, phrase
    assert "workflow_dispatch" not in workflow
    assert "persist-credentials: false" in workflow
    assert "permissions:" in workflow
    assert "C3B03_T01_R2B_R2A_C_EXECUTION_ALLOWED: \"false\"" in workflow
    assert "C3B03_T01_R2B_R2A_GROUP_SIGNAL_AUTHORIZED: \"false\"" in workflow
    assert "tests/test_c3_candidate_b_t01_r2b_r2a_source_admission.py" in workflow
    assert "test ! -e tools/research/c3_candidate_b_kill.c" in workflow
    assert "MANIFEST.sha256" in workflow
    assert "|| true" not in workflow and "continue-on-error:" not in workflow


def test_new_workflow_does_not_run_native_model():
    y = WORKFLOW.read_text(encoding="utf-8")
    assert "ctypes" not in y and "dlopen" not in y
    assert "python -m pytest -q" in y
    assert "r2b_contract_red.py" not in y  # New 172 contracts remain real RED.
    assert "-fsyntax-only" not in y or "test_only" not in y
    # Compilation into an object is allowed; no executable linking command.
    assert "cc -o " not in y
