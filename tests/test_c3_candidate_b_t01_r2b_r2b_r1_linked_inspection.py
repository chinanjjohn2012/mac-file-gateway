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
import struct
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


def _compile_link(root: Path, platform: str, *, source: Path = SOURCE,
                  mutation_headerpad: bool = False):
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
            "-Wl,-install_name," + image.name,
            # The headerpad flag is ONLY for constructing a never-loaded
            # LC_ROUTINES_64 negative mutant with adequate header slack.
            *(['-Wl,-headerpad,0x200'] if mutation_headerpad else []),
            "-o", str(image), str(obj),
            # macOS dyld/linker requires one libSystem load command for dylibs.
            # Whitelist EXACTLY this dependency at PRE-LOAD, no C execution.
            "-lSystem",
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


def _only_darwin_libsystem_dependency(
    load_commands: str, linked_list: str, own_name: str
) -> None:
    """Fail-closed one-platform exception: exactly one libSystem dependency."""
    chunks = re.split(r"(?m)^Load command \d+\s*$", load_commands)
    explicit = [
        c for c in chunks
        if re.search(r"(?m)^\s*cmd LC_LOAD_DYLIB\s*$", c)
    ]
    assert len(explicit) == 1, ("unexpected count of LC_LOAD_DYLIB", len(explicit))
    assert re.search(
        r"(?m)^\s*name /usr/lib/libSystem\.B\.dylib \(offset \d+\)\s*$",
        explicit[0],
    ), ("unexpected dependency", explicit[0])
    lines = [x.strip() for x in linked_list.splitlines() if x.strip()]
    assert len(lines) == 3, ("unapproved dependency list", lines)
    assert re.fullmatch(re.escape(own_name) + r" \(.+\)", lines[1]), lines
    assert re.fullmatch(r"/usr/lib/libSystem\.B\.dylib \(.+\)", lines[2]), lines


def _inspect_darwin_chained_fixups(image: Path, loads: str) -> None:
    """No dynamic import may be concealed by LC_DYLD_CHAINED_FIXUPS.

    Decode the header bytes from the final linked image, not C results or a
    tool's self-report. Constructor sections are checked independently.
    """
    pieces = re.split(r"(?m)^Load command \d+\s*$", loads)
    chunks = [
        c for c in pieces
        if re.search(r"(?m)^\s*cmd LC_DYLD_CHAINED_FIXUPS\s*$", c)
    ]
    assert len(chunks) <= 1, "duplicate chained fixup commands"
    if not chunks:
        return
    c = chunks[0]
    off = re.search(r"(?m)^\s*dataoff (\d+)\s*$", c)
    size = re.search(r"(?m)^\s*datasize (\d+)\s*$", c)
    assert off is not None and size is not None, "unparseable chained fixups"
    dataoff, datasize = int(off.group(1)), int(size.group(1))
    raw = image.read_bytes()
    assert 28 <= datasize <= len(raw) - dataoff
    version, starts, imports, symbols, count, fmt, symbol_fmt = struct.unpack_from(
        "<7I", raw, dataoff
    )
    assert version == 0, ("unknown fixups version", version)
    assert count == 0, ("unreviewed dynamically bound imports", count)
    assert starts <= datasize and imports <= datasize and symbols <= datasize
    assert fmt <= 3 and symbol_fmt <= 1
    print("C3B03_T01_R2B_R2B_R1_DARWIN_CHAINED_IMPORTS=0")
    print("C3B03_T01_R2B_R2B_R1_DARWIN_FIXUPS_HEADER=" +
          repr((version, starts, imports, symbols, count, fmt, symbol_fmt)))



# Frozen exact real Darwin ARM64 load-command sequence in PR #44 Job.
# Numeric command IDs from Apple mach-o/loader.h, not a user-derived input.
_DARWIN_EXACT_LC = (
    ("LC_SEGMENT_64", 0x19, 152),
    ("LC_SEGMENT_64", 0x19, 72),
    ("LC_ID_DYLIB", 0x0D, 64),
    ("LC_DYLD_CHAINED_FIXUPS", 0x80000034, 16),
    ("LC_DYLD_EXPORTS_TRIE", 0x80000033, 16),
    ("LC_SYMTAB", 0x02, 24),
    ("LC_DYSYMTAB", 0x0B, 80),
    ("LC_UUID", 0x1B, 24),
    ("LC_BUILD_VERSION", 0x32, 32),
    ("LC_SOURCE_VERSION", 0x2A, 16),
    ("LC_LOAD_DYLIB", 0x0C, 56),
    ("LC_FUNCTION_STARTS", 0x26, 16),
    ("LC_DATA_IN_CODE", 0x29, 16),
    ("LC_CODE_SIGNATURE", 0x1D, 16),
)
_DARWIN_SYSTEM_DEPENDENCY = "/usr/lib/libSystem.B.dylib"


def _macho_header(raw: bytes) -> tuple[int, int]:
    assert len(raw) >= 32, "UNAPPROVED_MACHO_HEADER: truncated"
    magic, cpu, subtype, kind, count, size, flags, reserved = struct.unpack_from(
        "<IiiIIIII", raw, 0
    )
    assert magic == 0xFEEDFACF, "UNAPPROVED_MACHO_HEADER: magic"
    assert cpu == 0x0100000C and kind == 6, (
        "UNAPPROVED_MACHO_HEADER: ARM64 MH_DYLIB only"
    )
    assert count == len(_DARWIN_EXACT_LC), (
        "UNAPPROVED_MACHO_LOAD_COMMAND: count", count
    )
    assert size == sum(x[2] for x in _DARWIN_EXACT_LC), (
        "UNAPPROVED_MACHO_LOAD_COMMAND: sizeofcmds", size
    )
    assert 32 + size <= len(raw), "UNAPPROVED_MACHO_HEADER: bounds"
    return count, size


def _macho_lc_name(raw: bytes, pos: int, size: int) -> str:
    assert size >= 24
    off = struct.unpack_from("<I", raw, pos + 8)[0]
    assert 24 <= off < size, "UNAPPROVED_MACHO_LOAD_COMMAND: dylib offset"
    field = raw[pos + off:pos + size].split(b"\0", 1)
    assert len(field) == 2, "UNAPPROVED_MACHO_LOAD_COMMAND: unterminated"
    return field[0].decode("ascii")


def _validate_darwin_macho_commands(
    image: Path, otool_loads: str | None = None
) -> None:
    """Parse RAW linked bytes AND optionally independently decoded otool text.

    A new LC_* command (including LC_ROUTINES/LC_ROUTINES_64) or unrecognized
    payload/section is BLOCK, not an unsafe assumption that it cannot execute.
    """
    raw = image.read_bytes()
    count, size = _macho_header(raw)
    pos = 32
    seen = []
    for i, (name, want_cmd, want_size) in enumerate(_DARWIN_EXACT_LC):
        assert pos + 8 <= len(raw), "UNAPPROVED_MACHO_LOAD_COMMAND: truncated"
        cmd, cmdsize = struct.unpack_from("<II", raw, pos)
        assert (cmd, cmdsize) == (want_cmd, want_size), (
            "UNAPPROVED_MACHO_LOAD_COMMAND", i, name, hex(cmd), cmdsize
        )
        assert cmdsize % 8 == 0 and pos + cmdsize <= 32 + size
        if name == "LC_SEGMENT_64":
            seg = raw[pos + 8:pos + 24].split(b"\0", 1)[0].decode("ascii")
            nsects = struct.unpack_from("<I", raw, pos + 64)[0]
            sections = tuple(
                raw[pos + 72 + j * 80:pos + 88 + j * 80]
                .split(b"\0", 1)[0].decode("ascii")
                for j in range(nsects)
            )
            expected = (("__TEXT", ("__text",)), ("__LINKEDIT", ()))
            assert (seg, sections) == expected[i], (
                "UNAPPROVED_MACHO_SECTION", i, seg, sections
            )
            assert cmdsize == 72 + 80 * nsects, (
                "UNAPPROVED_MACHO_SECTION_SIZE", i
            )
        if name == "LC_ID_DYLIB":
            assert _macho_lc_name(raw, pos, cmdsize) == image.name, (
                "UNAPPROVED_MACHO_INSTALL_ID", image.name
            )
        if name == "LC_LOAD_DYLIB":
            assert _macho_lc_name(raw, pos, cmdsize) == _DARWIN_SYSTEM_DEPENDENCY, (
                "UNAPPROVED_MACHO_DEPENDENCY", image.name
            )
        seen.append((name, cmdsize))
        pos += cmdsize
    assert pos == 32 + size, "UNAPPROVED_MACHO_LOAD_COMMAND: trailing"
    if otool_loads is not None:
        chunks = re.split(r"(?m)^Load command (\d+)\s*$", otool_loads)
        assert len(chunks) == 1 + 2 * count, (
            "UNAPPROVED_MACHO_LOAD_COMMAND: otool count", len(chunks)
        )
        for i, pair in enumerate(seen):
            assert int(chunks[1 + 2 * i]) == i, (
                "UNAPPROVED_MACHO_LOAD_COMMAND: otool index", i
            )
            body = chunks[2 + 2 * i]
            name = re.search(r"(?m)^\s*cmd (LC_[A-Z0-9_]+)\s*$", body)
            size = re.search(r"(?m)^\s*cmdsize (\d+)\s*$", body)
            assert name is not None and size is not None, (
                "UNAPPROVED_MACHO_LOAD_COMMAND: unreadable otool", i
            )
            assert (name.group(1), int(size.group(1))) == pair, (
                "UNAPPROVED_MACHO_LOAD_COMMAND: otool disagreement", i
            )
    print("C3B03_T01_R2B_R2B_R1_DARWIN_EXACT_LC_COUNT=" + str(count))
    print("C3B03_T01_R2B_R2B_R1_DARWIN_EXACT_LC_SEQUENCE=" + repr(seen))
    print("C3B03_T01_R2B_R2B_R1_LC_ROUTINES_ADMITTED=false")



def _forge_routines_lc_on_real_linked_image(image: Path) -> str:
    """Make structurally valid LC_ROUTINES_64 in a REAL linked image's slack.

    This modifies only Mach-O load-command DATA. It never runs this function,
    the binary, or any library initializer, and cannot authorize a load.
    """
    raw = bytearray(image.read_bytes())
    count, size = _macho_header(raw)
    assert count == len(_DARWIN_EXACT_LC)
    first_section = 32 + 72
    # section_64: sectname[16], segname[16], addr uint64, size uint64,
    # offset uint32. The byte offset is 48 into the section record.
    section_addr = struct.unpack_from("<Q", raw, first_section + 32)[0]
    text_file_off = struct.unpack_from("<I", raw, first_section + 48)[0]
    start = 32 + size
    # LC_ROUTINES_64 = 8-byte header, 2 uint64 and six reserved uint64.
    routines = struct.pack("<IIQQ6Q", 0x1A, 72, section_addr, 0,
                           0, 0, 0, 0, 0, 0)
    assert len(routines) == 72
    assert section_addr > 0
    assert start + len(routines) <= text_file_off, (
        "negative mutant needs real linked header padding"
    )
    assert raw[start:start + len(routines)] == bytes(len(routines)), (
        "negative mutant would overwrite a nonzero linked byte"
    )
    raw[start:start + len(routines)] = routines
    struct.pack_into("<II", raw, 16, count + 1, size + len(routines))
    image.write_bytes(raw)
    digest = hashlib.sha256(raw).hexdigest()
    # Read back the final linked-mutant bytes. Probe the exact extra command
    # identity, size, and initialization address (not an invalid stub).
    assert struct.unpack_from("<IIQQ", raw, start) == (
        0x1A, 72, section_addr, 0
    )
    assert struct.unpack_from("<II", raw, 16) == (count + 1, size + 72)
    print("C3B03_T01_R2B_R2B_R1_ROUTINES_MUTANT_LINKED_SHA256=" + digest)
    print("C3B03_T01_R2B_R2B_R1_ROUTINES_MUTANT_INIT_ADDRESS=" +
          hex(section_addr))
    print("C3B03_T01_R2B_R2B_R1_ROUTINES_MUTANT_CMD=LC_ROUTINES_64")
    return digest


def _audit(image: Path, platform: str) -> dict[str, str]:
    # Raw Mach-O command admission first: a routines mutant is denied
    # because of its actual load command, not a later nm/otool side effect.
    if platform == "Darwin":
        _validate_darwin_macho_commands(image)
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
        _validate_darwin_macho_commands(image, loads)
        linked = _tool(["otool", "-L", str(image)])
        relocation = _tool(["otool", "-rv", str(image)])
        disassembly = _tool(["otool", "-tv", str(image)])
        assert "LC_ID_DYLIB" in loads, loads
        for forbidden in (
            "LC_LOAD_WEAK_DYLIB", "LC_REEXPORT_DYLIB",
            "LC_RPATH", "LC_DYLD_ENVIRONMENT", "LC_LOAD_DYLINKER",
            "LC_LOAD_UPWARD_DYLIB", "LC_LAZY_LOAD_DYLIB",
            "__mod_init_func", "__init_offsets", "__interpose",
            "__la_symbol_ptr",
            "__nl_symbol_ptr",
        ):
            assert forbidden not in loads, ("unapproved loader/initializer", forbidden)
        _only_darwin_libsystem_dependency(loads, linked, image.name)
        _inspect_darwin_chained_fixups(image, loads)
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
        # This mutation MUST survive the real linker; otherwise the
        # negative test cannot prove that the final-image gate rejects it.
        if mutant == "constructor":
            if platform == "Darwin":
                initial = _tool(["otool", "-l", str(obj)])
                final = _tool(["otool", "-l", str(image)])
                assert "__mod_init_func" in initial
                assert "__init_offsets" in final or "__mod_init_func" in final
            else:
                final = _tool(["readelf", "-SW", str(image)])
                assert ".init_array" in final
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

@pytest.mark.parametrize("dependency", (
    "/usr/lib/libobjc.A.dylib", "/usr/lib/libSystem.B.dylib.extra",
    "@rpath/libSystem.B.dylib", "/tmp/libSystem.B.dylib", "",
))
def test_mach_o_dependency_override_or_fallback_is_denied_offline(dependency):
    """Synthetic load-command negatives complement actual Mach-O inspection."""
    chunk = (
        "Load command 1\n      cmd LC_LOAD_DYLIB\n"
        "  cmdsize 56\n"
        f"     name {dependency} (offset 24)\n"
    )
    linked = (
        "libc3b03_t01_no_signal_inspect.dylib:\n"
        "    libc3b03_t01_no_signal_inspect.dylib (compatibility version 0.0.0)\n"
        f"    {dependency} (compatibility version 1.0.0)\n"
    )
    with pytest.raises(AssertionError):
        _only_darwin_libsystem_dependency(
            chunk, linked, "libc3b03_t01_no_signal_inspect.dylib"
        )


def test_mach_o_exact_libsystem_dependency_fixture():
    chunk = (
        "Load command 1\n      cmd LC_LOAD_DYLIB\n"
        "  cmdsize 56\n"
        "     name /usr/lib/libSystem.B.dylib (offset 24)\n"
    )
    linked = (
        "libc3b03_t01_no_signal_inspect.dylib:\n"
        "    libc3b03_t01_no_signal_inspect.dylib (compatibility version 0.0.0)\n"
        "    /usr/lib/libSystem.B.dylib (compatibility version 1.0.0)\n"
    )
    _only_darwin_libsystem_dependency(
        chunk, linked, "libc3b03_t01_no_signal_inspect.dylib"
    )

def test_darwin_routines_lc_in_real_linked_mutant_is_denied_before_load():
    """Actual linked Mach-O with an additional valid LC_ROUTINES_64 record.

    On Linux exercise a standalone raw-byte negative as well; no skipping or
    fake C run. The Mac variant obtains header slack from test-only -headerpad.
    """
    if _platform() != "Darwin":
        head = struct.pack(
            "<IiiIIIII", 0xFEEDFACF, 0x0100000C, 0, 6,
            len(_DARWIN_EXACT_LC), sum(x[2] for x in _DARWIN_EXACT_LC), 0, 0
        )
        parts = []
        for i, (_name, cmd, size) in enumerate(_DARWIN_EXACT_LC):
            if i == 0:
                cmd = 0x1A
            parts.append(struct.pack("<II", cmd, size) + bytes(size - 8))
        with tempfile.TemporaryDirectory(prefix="c3b03-macho-lc-fixture-") as tmp:
            fixture = Path(tmp) / (LIBRARY + ".dylib")
            fixture.write_bytes(head + b"".join(parts))
            with pytest.raises(AssertionError, match="UNAPPROVED_MACHO_LOAD_COMMAND"):
                _validate_darwin_macho_commands(fixture)
        return
    with tempfile.TemporaryDirectory(prefix="c3b03-routines-real-linked-") as tmp:
        root = Path(tmp).resolve(strict=True)
        _obj, image, _comp, _link = _compile_link(
            root, "Darwin", mutation_headerpad=True
        )
        assert stat.S_IMODE(root.stat().st_mode) == 0o700
        # The unmutated REAL linked image is allowed by the RAW command gate.
        _validate_darwin_macho_commands(image)
        sha = _forge_routines_lc_on_real_linked_image(image)
        assert len(sha) == 64
        # Confirm otool independently observes the *actual* new command.
        visible = _tool(["otool", "-l", str(image)])
        assert re.search(
            r"(?m)^\s*cmd LC_ROUTINES_64\s*$", visible
        ), "routines load command not preserved in REAL linked mutant"
        print("C3B03_T01_R2B_R2B_R1_ROUTINES_OTool_OBSERVED=true")
        # The _audit entrypoint MUST reject precisely because the RAW Mach-O
        # admission gate saw LC_ROUTINES_64, before any nm/tool fallback.
        with pytest.raises(AssertionError, match="UNAPPROVED_MACHO_LOAD_COMMAND"):
            _audit(image, "Darwin")
        print("C3B03_T01_R2B_R2B_R1_ROUTINES_REJECT_REASON="
              "UNAPPROVED_MACHO_LOAD_COMMAND")
        print("C3B03_T01_R2B_R2B_R1_ROUTINES_MUTANT_LOADED=false")


@pytest.mark.parametrize("command", (0x11, 0x1A, 0x8000001C, 0xDEADBEEF))
def test_raw_mach_o_unknown_and_initializer_command_ids_rejected(command):
    """LC_ROUTINES, LC_ROUTINES_64, LC_RPATH and unknown MUST FAIL CLOSED."""
    head = struct.pack(
        "<IiiIIIII", 0xFEEDFACF, 0x0100000C, 0, 6,
        len(_DARWIN_EXACT_LC), sum(x[2] for x in _DARWIN_EXACT_LC), 0, 0
    )
    chunks = []
    for i, (_name, code, size) in enumerate(_DARWIN_EXACT_LC):
        if i == 0:
            code = command
        chunks.append(struct.pack("<II", code, size) + bytes(size - 8))
    with tempfile.TemporaryDirectory(prefix="c3b03-routines-synthetic-") as tmp:
        fixture = Path(tmp) / (LIBRARY + ".dylib")
        fixture.write_bytes(head + b"".join(chunks))
        with pytest.raises(AssertionError, match="UNAPPROVED_MACHO_LOAD_COMMAND"):
            _validate_darwin_macho_commands(fixture)


def test_stage_contract_has_one_darwin_libsystem_policy():
    """Code + document share a single Darwin exception; Linux none."""
    s = PLAN.read_text(encoding="utf-8")
    assert "Exactly one Darwin LC_LOAD_DYLIB" in s
    assert "/usr/lib/libSystem.B.dylib" in s
    assert "own install ID plus precisely one system dependency" in s
    assert "Linux has zero DT_NEEDED" in s
    assert "no libSystem or other dylib" not in s
    assert "-lSystem" in s and "-lSystem" in _compile_link.__code__.co_consts
    assert _DARWIN_SYSTEM_DEPENDENCY == "/usr/lib/libSystem.B.dylib"

