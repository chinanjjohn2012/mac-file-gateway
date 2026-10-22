"""R2b-R2b-R1: link and INSPECT synthetic C library; never load/execute C.

All native-process work here is limited to cc, nm, file, otool, readelf and
objdump. No Python Adapter, ctypes/cffi, dlopen, process-group signal or C
function invocation. Every library exists only inside a private ephemeral
directory and is removed without loading it.
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

import pytest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tools/research/c3_candidate_b_t01_no_signal_candidate.c"
HEADER = ROOT / "tests/native/c3_b03_t01_no_signal_contract.h"
DESIGN = ROOT / "docs/research/phase2-lite-c3/candidate-b-b03-t01-r2b-r2b-d0-linked-adapter-provenance-design.md"
PLAN = ROOT / "docs/research/phase2-lite-c3/candidate-b-b03-t01-r2b-r2b-r1-linked-binary-inspection.md"
WORKFLOW = ROOT / ".github/workflows/c3-candidate-b-t01-r2b-r2b-r1-linked-inspect.yml"
MANIFEST = ROOT / "MANIFEST.sha256"

PARENT_HEAD = "ebbc5eeefe7acbe1334c54b35e89c15f096c5575"
PARENT_TREE = "f3bcb24827039c0e0284683f0f4ff77455b32483"
PARENT_SOURCE_SHA = "5a1292787584632fac20c86bbe62e50153e82b0ecb36ad190446bf4b7b714195"
PARENT_HEADER_SHA = "7c9bd037ecf65da8de91605846c4ac4fc7ceaebbd0ca2fe983ecfef630c9958e"
NAME = "c3b03_t01_no_signal_candidate"
LIBRARY = "libc3b03_t01_no_signal_inspect"
COMPILE_FLAGS = (
    "-std=c11", "-O0", "-fPIC", "-Wall", "-Wextra", "-Werror",
    "-pedantic", "-fno-stack-protector", "-fno-builtin",
    "-fno-asynchronous-unwind-tables", "-fno-unwind-tables",
    "-DC3B03_TEST_NO_SIGNAL_STUB=1",
)


def _tool(argv: list[str]) -> str:
    # No shell; arguments and executable are from this fixed reviewed test.
    allowed = {"cc", "nm", "file", "otool", "readelf", "objdump", "uname"}
    assert argv and argv[0] in allowed, argv
    p = subprocess.run(
        argv, cwd=ROOT, capture_output=True, text=True,
        check=False, timeout=45,
    )
    assert p.returncode == 0, (argv, p.stdout, p.stderr)
    return p.stdout


def _platform() -> str:
    value = _tool(["uname", "-s"]).strip()
    assert value in {"Darwin", "Linux"}, value
    return value


def _compile_link(root: Path, platform: str, *, source: Path = SOURCE):
    """Use a pre-reviewed fixed flag tuple. No executable, only linkable .so/.dylib."""
    obj = root / "candidate.o"
    image = root / (LIBRARY + (".dylib" if platform == "Darwin" else ".so"))
    compile_argv = [
        "cc", *COMPILE_FLAGS, "-I", str(HEADER.parent),
        "-c", "-o", str(obj), str(source),
    ]
    _tool(compile_argv)
    if platform == "Darwin":
        link_argv = [
            "cc", "-dynamiclib", "-nostdlib", "-Wl,-undefined,error",
            "-Wl,-install_name," + image.name, "-o", str(image), str(obj),
        ]
    else:
        link_argv = [
            "cc", "-shared", "-nostdlib", "-Wl,-z,defs",
            "-Wl,--no-undefined", "-Wl,-z,relro", "-Wl,-z,now",
            "-Wl,-soname," + image.name, "-o", str(image), str(obj),
        ]
    _tool(link_argv)
    assert obj.is_file() and image.is_file()
    return obj, image, compile_argv, link_argv


def _private_custody(root: Path, image: Path) -> tuple[str, int, int]:
    """Canonical private root plus descriptor-based byte hash; NO dynamic load."""
    canonical = root.resolve(strict=True)
    assert canonical.is_dir() and not canonical.is_symlink()
    for part in (canonical, image):
        l = os.lstat(part)
        assert not stat.S_ISLNK(l.st_mode)
        assert l.st_uid == os.getuid()
    root_st = os.lstat(canonical)
    assert stat.S_IMODE(root_st.st_mode) == 0o700
    assert image.parent.resolve(strict=True) == canonical
    assert image.name == LIBRARY + image.suffix
    os.chmod(image, 0o400)
    before = os.lstat(image)
    assert stat.S_ISREG(before.st_mode)
    assert before.st_nlink == 1
    assert stat.S_IMODE(before.st_mode) == 0o400
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(image, flags), "rb") as fd:
        here = os.fstat(fd.fileno())
        assert (here.st_dev, here.st_ino, here.st_size) == (
            before.st_dev, before.st_ino, before.st_size
        )
        digest = hashlib.sha256(fd.read()).hexdigest()
    after = os.lstat(image)
    assert (after.st_dev, after.st_ino, after.st_size) == (
        before.st_dev, before.st_ino, before.st_size
    )
    assert len(digest) == 64
    return digest, before.st_dev, before.st_ino


def _exact_export(nm_global: str, platform: str) -> None:
    expected = ("_" if platform == "Darwin" else "") + NAME
    lines = [s.strip() for s in nm_global.splitlines() if s.strip()]
    assert len(lines) == 1, ("unexpected global/export count", lines)
    symbol = re.fullmatch(r"[0-9a-fA-F]+\s+([A-Za-z])\s+(\S+)", lines[0])
    assert symbol is not None, ("unparseable nm line", lines)
    assert symbol.group(1) == "T", ("not strong defined TEXT", lines)
    assert symbol.group(2) == expected, ("alias or unexpected export", lines)


def _audit(image: Path, platform: str) -> dict[str, str]:
    desc = _tool(["file", "-b", str(image)]).strip()
    if platform == "Darwin":
        assert "mach-o" in desc.lower() and "arm64" in desc.lower(), desc
    else:
        assert "elf 64-bit" in desc.lower() and "x86-64" in desc.lower(), desc
        assert "shared object" in desc.lower(), desc

    undefined = _tool(["nm", "-u", str(image)])
    assert not undefined.strip(), ("undefined linked symbols", undefined)
    exports = _tool(["nm", "-g", str(image)])
    _exact_export(exports, platform)

    if platform == "Darwin":
        nm_verbose = _tool(["nm", "-m", str(image)])
        assert "weak external" not in nm_verbose.lower(), nm_verbose
        loads = _tool(["otool", "-l", str(image)])
        linked = _tool(["otool", "-L", str(image)])
        relocation = _tool(["otool", "-rv", str(image)])
        disassembly = _tool(["otool", "-tv", str(image)])
        assert "LC_ID_DYLIB" in loads, loads
        for forbidden in (
            "LC_LOAD_DYLIB", "LC_LOAD_WEAK_DYLIB", "LC_REEXPORT_DYLIB",
            "LC_RPATH", "LC_DYLD_ENVIRONMENT", "LC_LOAD_DYLINKER",
            "LC_LOAD_UPWARD_DYLIB", "LC_LAZY_LOAD_DYLIB",
            "__mod_init_func", "__interpose", "__la_symbol_ptr",
            "__nl_symbol_ptr",
        ):
            assert forbidden not in loads, ("unapproved loader/initializer", forbidden)
        assert len([x for x in linked.splitlines() if x.strip()]) == 2, linked
        assert not re.search(r"\b[1-9][0-9]*\s+entries\b", relocation), relocation
    else:
        header = _tool(["readelf", "-hW", str(image)])
        sections = _tool(["readelf", "-SW", str(image)])
        dynamic = _tool(["readelf", "-dW", str(image)])
        relocation = _tool(["readelf", "-rW", str(image)])
        dyn_symbols = _tool(["nm", "-D", "--defined-only", str(image)])
        _exact_export(dyn_symbols, platform)
        phdr = _tool(["readelf", "-lW", str(image)])
        disassembly = _tool(["objdump", "-dr", str(image)])
        assert re.search(r"Type:\s+DYN\s+\(Shared object file\)", header)
        assert "X86-64" in header
        assert "INTERP" not in phdr, phdr
        for forbidden in (
            "(NEEDED)", "(RPATH)", "(RUNPATH)", "(INIT)", "(FINI)",
            "(INIT_ARRAY)", "(PREINIT_ARRAY)", "(FINI_ARRAY)",
            "(TEXTREL)", "(JMPREL)", "(PLTGOT)",
        ):
            assert forbidden not in dynamic, ("unexpected dynamic tag", forbidden)
        for forbidden in (".init_array", ".preinit_array", ".fini_array", ".plt", ".got.plt"):
            assert forbidden not in sections, ("unexpected section", forbidden)
        assert "There are no relocations in this file." in relocation, relocation

    asm = disassembly.lower()
    assert len(asm) > 100
    for forbidden in (
        "\tsyscall", "\tsysenter", "int $0x80", "svc #", "\tsvc\t",
        "\tblr\t", "\tbr\t", "\tcallq\t*", "\tcall\t*", "\tjmp\t*",
    ):
        assert forbidden not in asm, ("dangerous trap/indirect branch", forbidden)
    return {
        "file": desc, "export": exports.strip(),
        "reloc": relocation, "disasm": disassembly,
        "loader": loads if platform == "Darwin" else dynamic,
    }


def _print_attestation(platform: str, image_sha: str, object_sha: str,
                       proof: dict[str, str], compile_argv: list[str],
                       link_argv: list[str]) -> None:
    print("C3B03_T01_R2B_R2B_R1_PLATFORM=" + platform)
    print("C3B03_T01_R2B_R2B_R1_PARENT_HEAD=" + PARENT_HEAD)
    print("C3B03_T01_R2B_R2B_R1_PARENT_TREE=" + PARENT_TREE)
    print("C3B03_T01_R2B_R2B_R1_SOURCE_SHA256=" + PARENT_SOURCE_SHA)
    print("C3B03_T01_R2B_R2B_R1_HEADER_SHA256=" + PARENT_HEADER_SHA)
    print("C3B03_T01_R2B_R2B_R1_CC_VERSION=" +
          _tool(["cc", "--version"]).splitlines()[0])
    compiler = shutil.which("cc")
    assert compiler
    compiler_path = Path(compiler).resolve(strict=True)
    print("C3B03_T01_R2B_R2B_R1_CC_REALPATH=" + str(compiler_path))
    print("C3B03_T01_R2B_R2B_R1_CC_SHA256=" +
          hashlib.sha256(compiler_path.read_bytes()).hexdigest())
    print("C3B03_T01_R2B_R2B_R1_CC_FLAGS=" + repr(compile_argv))
    print("C3B03_T01_R2B_R2B_R1_LINK_FLAGS=" + repr(link_argv))
    print("C3B03_T01_R2B_R2B_R1_OBJECT_SHA256=" + object_sha)
    print("C3B03_T01_R2B_R2B_R1_LINKED_SHA256=" + image_sha)
    print("C3B03_T01_R2B_R2B_R1_UNDEFINED_SYMBOLS=0")
    print("C3B03_T01_R2B_R2B_R1_EXACT_EXPORT=" + proof["export"])
    for name in ("reloc", "loader", "disasm"):
        body = proof[name]
        print("C3B03_T01_R2B_R2B_R1_" + name.upper() + "_SHA256=" +
              hashlib.sha256(body.encode()).hexdigest())
        print("C3B03_T01_R2B_R2B_R1_" + name.upper() + "_BEGIN")
        print(body)
        print("C3B03_T01_R2B_R2B_R1_" + name.upper() + "_END")
    print("C3B03_T01_R2B_R2B_R1_LINKED_ARTIFACT_CREATED=true")
    print("C3B03_T01_R2B_R2B_R1_C_EXECUTED=false")
    print("C3B03_T01_R2B_R2B_R1_LIBRARY_LOADED=false")
    print("C3B03_T01_R2B_R2B_R1_GROUP_SIGNAL_AUTHORIZED=false")


def test_r1_linked_binary_is_inspected_without_loading():
    """Artifact exists only transiently within this exact test lifetime."""
    assert hashlib.sha256(SOURCE.read_bytes()).hexdigest() == PARENT_SOURCE_SHA
    assert hashlib.sha256(HEADER.read_bytes()).hexdigest() == PARENT_HEADER_SHA
    assert PLAN.is_file() and DESIGN.is_file() and WORKFLOW.is_file()
    platform = _platform()
    with tempfile.TemporaryDirectory(prefix="c3b03-t01-r2b-r2b-r1-") as tmp:
        root = Path(tmp).resolve(strict=True)
        assert stat.S_IMODE(root.stat().st_mode) == 0o700
        obj, image, comp, link = _compile_link(root, platform)
        object_sha = hashlib.sha256(obj.read_bytes()).hexdigest()
        linked_sha, dev, ino = _private_custody(root, image)
        assert dev > 0 and ino > 0
        evidence = _audit(image, platform)
        _print_attestation(platform, linked_sha, object_sha, evidence, comp, link)


@pytest.mark.parametrize("mutant", ("alias", "extra", "weak", "constructor"))
def test_real_linked_synthetic_mutant_is_blocked_before_load(mutant):
    """Genuine linked toy binaries, never imported/called/executed."""
    platform = _platform()
    if mutant == "alias":
        body = "int unsafe_c3b03_t01_no_signal_candidate_alias(void) {return 1;}\n"
    elif mutant == "extra":
        body = (
            "int c3b03_t01_no_signal_candidate(void) {return 1;}\n"
            "int unrelated_extra_export(void) {return 2;}\n"
        )
    elif mutant == "weak":
        body = (
            "__attribute__((weak)) "
            "int c3b03_t01_no_signal_candidate(void) {return 1;}\n"
        )
    else:
        body = (
            "static volatile int test_fixture_marker = 0;\n"
            "__attribute__((constructor)) static void inactive_init(void) "
            "{test_fixture_marker = 1;}\n"
            "int c3b03_t01_no_signal_candidate(void) "
            "{return test_fixture_marker;}\n"
        )
    with tempfile.TemporaryDirectory(prefix="c3b03-t01-r2b-r2b-r1-negative-") as tmp:
        root = Path(tmp).resolve(strict=True)
        mutant_source = root / "synthetic-mutant.c"
        mutant_source.write_text(body, encoding="utf-8")
        obj, image, _comp, _link = _compile_link(
            root, platform, source=mutant_source
        )
        assert obj.is_file()
        sha, _dev, _ino = _private_custody(root, image)
        assert sha
        with pytest.raises(AssertionError):
            _audit(image, platform)


def test_document_manifest_and_workflow_scope_are_no_load():
    s = PLAN.read_text(encoding="utf-8")
    y = WORKFLOW.read_text(encoding="utf-8")
    for marker in (
        "R2b-R2b-R1", "PRE-LOAD", "P3-01", "P3-02", "NO_LOAD",
        "group_kill_authorized=false", "reuse_proven=false",
        "g2_qualified=false", "NOT_RUN/BLOCK", "C_EXECUTED=false",
        "R2b-R2b-R2", "R2b-R2b-R3", "exact export",
        "relocations", "linked SHA256", "no dynamic load",
    ):
        assert marker in s, marker
    for marker in (
        "C3B03_T01_R2B_R2B_R1_NO_LOAD=true",
        "C3B03_T01_R2B_R2B_R1_GROUP_SIGNAL_AUTHORIZED=false",
        "test ! -e tools/research/c3_candidate_b_kill.c",
        "test ! -e tools/research/c3_candidate_b_kill_t01_no_signal_probe.py",
        "test ! -e tools/research/run_c3_candidate_b_kill.py",
        "MANIFEST.sha256", "persist-credentials: false",
        "tests/test_c3_candidate_b_t01_r2b_r2b_r1_linked_inspection.py",
    ):
        assert marker in y, marker
    for forbidden in (
        "workflow_dispatch", "continue-on-error:", "|| true",
        "ctypes.CDLL(", "dlopen(", "signal.SIGKILL", "os.kill(",
    ):
        assert forbidden not in y, forbidden
    assert ROOT.joinpath("tests/test_c3_candidate_b_t01_r2b_contract_red.py").is_file()
