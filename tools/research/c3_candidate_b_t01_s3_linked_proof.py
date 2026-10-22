"""S3 partial: SAME-SESSION real inert object -> linked image, static only.

No candidate C call, no FFI, no loader and no group signal. This produces
observations, NOT a complete S1/S3 CFG/custody or first-load authorization.
The deliberately frozen compile/link flags mirror the reviewed R1 NO-LOAD
experiment, but every byte digest is freshly observed in this build session.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import tempfile

import c3_candidate_b_t01_s0_abi_proof as s0
import c3_candidate_b_t01_s2_object_proof as s2

ROOT = s0.ROOT
SOURCE = s0.SOURCE
HEADER = s0.HEADER
MANIFEST = s0.MANIFEST
ENV = dict(s2.ENV)
NAME = "libc3b03_t01_no_signal_inspect"
SYM = s2.SYMBOL
_TOOLS = {
    "Darwin": ("/usr/bin/file", "/usr/bin/nm", "/usr/bin/otool"),
    "Linux": ("/usr/bin/file", "/usr/bin/nm", "/usr/bin/readelf",
              "/usr/bin/objdump"),
}
# Frozen R1 Mach-O command identity/order/size, NOT a portable loader policy.
_DARWIN_CMDS = (
    (0x19, 152), (0x19, 72), (0x0d, 64), (0x80000034, 16),
    (0x80000033, 16), (0x02, 24), (0x0b, 80), (0x1b, 24),
    (0x32, 32), (0x2a, 16), (0x0c, 56), (0x26, 16),
    (0x29, 16), (0x1d, 16),
)


def _digest(payload: dict[str, object]) -> str:
    """Ordered observation chain; a digest is NOT atomic custody proof."""
    return hashlib.sha256(json.dumps(
        payload, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")).hexdigest()


def _platform() -> str:
    name, arch = os.uname().sysname, os.uname().machine
    if (name, arch) not in (("Darwin", "arm64"), ("Linux", "x86_64")):
        raise ValueError("UNREVIEWED_PLATFORM_OR_ARCH")
    return name


def _run_inspection(argv: tuple[str, ...], platform: str) -> str:
    if not argv or argv[0] not in _TOOLS[platform]:
        raise ValueError("UNREVIEWED_INSPECTION_TOOL")
    p = s0._fixed_run(argv, env=ENV)
    if p.returncode:
        raise ValueError("STATIC_INSPECTION_FAILED:" + p.stderr[:250])
    return p.stdout


def _link_args(compiler: Path, obj: Path, image: Path, platform: str
               ) -> tuple[str, ...]:
    if platform == "Darwin":
        return (str(compiler), "-dynamiclib", "-nostdlib",
                "-Wl,-undefined,error", "-Wl,-install_name," + image.name,
                "-o", str(image), str(obj), "-lSystem")
    if platform == "Linux":
        return (str(compiler), "-shared", "-nostdlib", "-Wl,-z,defs",
                "-Wl,--no-undefined", "-Wl,-z,relro", "-Wl,-z,now",
                "-Wl,-soname," + image.name, "-o", str(image), str(obj))
    raise ValueError("UNREVIEWED_LINK_PLATFORM")


def _c_string(raw: bytes, pos: int, size: int) -> str:
    if size < 24:
        raise ValueError("UNREVIEWED_MACHO_DYLIB_COMMAND")
    off = struct.unpack_from("<I", raw, pos + 8)[0]
    if not 24 <= off < size:
        raise ValueError("UNREVIEWED_MACHO_DYLIB_NAME_OFFSET")
    data = raw[pos + off:pos + size]
    if b"\0" not in data:
        raise ValueError("UNTERMINATED_MACHO_DYLIB_NAME")
    return data.split(b"\0", 1)[0].decode("ascii")


def _linked_header_gate(raw: bytes, platform: str, filename: str) -> str:
    """Bounded, byte-based format check, NOT CFG or loader identity proof."""
    if platform == "Linux":
        if (len(raw) < 64 or raw[:6] != b"\x7fELF\x02\x01" or
                struct.unpack_from("<HH", raw, 16) != (3, 62)):
            raise ValueError("UNREVIEWED_ELF_HEADER")
        return "ELF64_ET_DYN_PARTIAL"
    if platform != "Darwin" or len(raw) < 32:
        raise ValueError("UNREVIEWED_LINKED_PLATFORM")
    magic, cpu, _subtype, kind, count, total, _flags, _reserved = (
        struct.unpack_from("<IiiIIIII", raw, 0)
    )
    if ((magic, cpu, kind, count, total) != (
        0xFEEDFACF, 0x0100000C, 6,
        len(_DARWIN_CMDS), sum(size for _, size in _DARWIN_CMDS),
    ) or len(raw) < 32 + total):
        raise ValueError("UNREVIEWED_MACHO_HEADER")
    pos = 32
    for i, (expected_cmd, expected_size) in enumerate(_DARWIN_CMDS):
        cmd, size = struct.unpack_from("<II", raw, pos)
        if (cmd, size) != (expected_cmd, expected_size):
            raise ValueError("UNREVIEWED_MACHO_LOAD_COMMAND")
        if cmd == 0x19:
            expected_seg = b"__TEXT" if i == 0 else b"__LINKEDIT"
            expected_count = 1 if i == 0 else 0
            segment = raw[pos + 8:pos + 24].split(b"\0", 1)[0]
            nsects = struct.unpack_from("<I", raw, pos + 64)[0]
            if (segment, nsects) != (expected_seg, expected_count):
                raise ValueError("UNREVIEWED_MACHO_SECTIONS")
            if i == 0:
                section = raw[pos + 72:pos + 88].split(b"\0", 1)[0]
                if section != b"__text":
                    raise ValueError("UNREVIEWED_MACHO_TEXT_SECTION")
        if cmd in (0x0d, 0x0c):
            actual = _c_string(raw, pos, size)
            expected = filename if cmd == 0x0d else "/usr/lib/libSystem.B.dylib"
            if actual != expected:
                raise ValueError("UNREVIEWED_MACHO_DEPENDENCY")
        pos += size
    if pos != 32 + total:
        raise ValueError("UNREVIEWED_MACHO_TRAILING_COMMANDS")
    return "MACHO_ARM64_MH_DYLIB_PARTIAL"


def _metadata_gate(platform: str, meta: dict[str, str]) -> str:
    """Narrow externally observed metadata gate. Unknown -> STOP."""
    if platform not in _TOOLS:
        raise ValueError("UNKNOWN_LINKED_PLATFORM")
    desc = meta["file"].lower()
    expected = ("mach-o", "arm64") if platform == "Darwin" else (
        "elf", "64-bit", "x86-64", "shared object",
    )
    if not all(x in desc for x in expected):
        raise ValueError("LINKED_FORMAT_MISMATCH")
    if meta["undefined"].strip():
        raise ValueError("LINKED_UNDEFINED_SYMBOL")
    sym = ("_" if platform == "Darwin" else "") + SYM
    if re.fullmatch(r"[a-fA-F0-9]{8,16}\s+T\s+" + re.escape(sym),
                    meta["exports"].strip()) is None:
        raise ValueError("LINKED_EXPORT_MISMATCH")
    disasm = meta["disasm"].lower()
    if len(disasm) < 100 or SYM not in disasm:
        raise ValueError("LINKED_DISASSEMBLY_MISSING")
    for marker in ("\tsyscall", "\tsysenter", "\tint3", "\tud2",
                   "\thlt", "\tblr\t", "\tbr\t", "\tcallq\t*",
                   "\tcall\t*", "\tjmp\t*", "svc #"):
        if marker in disasm:
            raise ValueError("KNOWN_UNREVIEWED_INSTRUCTION")
    if platform == "Linux":
        if not re.search(r"Type:\s+DYN\s+\(Shared object file\)", meta["header"]):
            raise ValueError("UNREVIEWED_ELF_TYPE")
        if "X86-64" not in meta["header"] or "INTERP" in meta["program"]:
            raise ValueError("UNREVIEWED_ELF_LOAD_CONFIGURATION")
        if meta["reloc"].strip() != "There are no relocations in this file.":
            raise ValueError("UNREVIEWED_ELF_RELOCATIONS")
        for token in ("(NEEDED)", "(RPATH)", "(RUNPATH)", "(INIT)",
                      "(FINI)", "(INIT_ARRAY)", "(FINI_ARRAY)",
                      "(PREINIT_ARRAY)", "(TEXTREL)", "(JMPREL)",
                      "(PLTGOT)"):
            if token in meta["loader"]:
                raise ValueError("UNREVIEWED_ELF_DYNAMIC_TAG")
        for token in (".init_array", ".preinit_array", ".fini_array",
                      ".plt", ".got.plt"):
            if token in meta["sections"]:
                raise ValueError("UNREVIEWED_ELF_SECTION")
        if meta["dynamic_export"].strip() != meta["exports"].strip():
            raise ValueError("UNREVIEWED_ELF_DYNAMIC_EXPORT")
    else:
        for token in ("LC_LOAD_WEAK_DYLIB", "LC_REEXPORT_DYLIB", "LC_RPATH",
                      "LC_LOAD_UPWARD_DYLIB", "LC_ROUTINES", "__mod_init_func",
                      "__init_offsets", "__interpose", "__la_symbol_ptr",
                      "__nl_symbol_ptr"):
            if token in meta["loader"]:
                raise ValueError("UNREVIEWED_MACHO_LOADER_SURFACE")
        linked = [line.strip() for line in meta["dependencies"].splitlines()
                  if line.strip()]
        if (len(linked) != 3 or
                not linked[1].startswith(NAME + ".dylib (") or
                not linked[2].startswith("/usr/lib/libSystem.B.dylib (")):
            raise ValueError("UNREVIEWED_MACHO_DEPENDENCIES")
        if "weak external" in meta["verbose_symbols"].lower():
            raise ValueError("UNREVIEWED_MACHO_WEAK_SYMBOL")
        if re.search(r"\b[1-9][0-9]*\s+entries\b", meta["reloc"]):
            raise ValueError("UNREVIEWED_MACHO_RELOCATIONS")
    return "LINKED_METADATA_PARTIAL_NO_LOAD"


def _inspect(platform: str, image: Path) -> dict[str, str]:
    tools = _TOOLS[platform]
    filetool, nm = tools[0:2]
    data = {
        "file": _run_inspection((filetool, "-b", str(image)), platform),
        "exports": _run_inspection((nm, "-g", str(image)), platform),
        "undefined": _run_inspection((nm, "-u", str(image)), platform),
    }
    if platform == "Darwin":
        otool = tools[2]
        data.update({
            "loader": _run_inspection((otool, "-l", str(image)), platform),
            "dependencies": _run_inspection((otool, "-L", str(image)), platform),
            "verbose_symbols": _run_inspection((nm, "-m", str(image)), platform),
            "reloc": _run_inspection((otool, "-rv", str(image)), platform),
            "disasm": _run_inspection((otool, "-tv", str(image)), platform),
        })
    else:
        readelf, objdump = tools[2:4]
        data.update({
            "header": _run_inspection((readelf, "-hW", str(image)), platform),
            "program": _run_inspection((readelf, "-lW", str(image)), platform),
            "sections": _run_inspection((readelf, "-SW", str(image)), platform),
            "loader": _run_inspection((readelf, "-dW", str(image)), platform),
            "reloc": _run_inspection((readelf, "-rW", str(image)), platform),
            "dynamic_export": _run_inspection(
                (nm, "-D", "--defined-only", str(image)), platform),
            "disasm": _run_inspection((objdump, "-dr", str(image)), platform),
        })
    _metadata_gate(platform, data)
    return data


def _compile_link_observe() -> dict[str, object]:
    """Fresh real object and linked-image evidence from ONE temp build session."""
    items = s0.checked_manifest()
    head, tree = s0.current_revision()
    s2._validated_source_includes(SOURCE.read_text(encoding="utf-8"))
    source_sha, _ = s0._sha_regular(SOURCE)
    header_sha, _ = s0._sha_regular(HEADER)
    if (source_sha, header_sha) != (
        s0.REVIEWED_C_SHA256, s0.REVIEWED_HEADER_SHA256,
    ):
        raise ValueError("REVIEWED_C_BYTES_DRIFT")
    platform = _platform()
    compiler, compiler_pre = s0._compiler_entry()
    s0_stage = _digest({
        "head": head, "tree": tree, "manifest": s0._sha_regular(MANIFEST)[0],
        "source": source_sha, "header": header_sha, "entries": len(items),
    })
    with tempfile.TemporaryDirectory(prefix="c3b03-s3-linked-no-load-") as tmp:
        root = Path(tmp).resolve(strict=True)
        if (stat.S_IMODE(root.stat().st_mode) != 0o700 or
                root.is_symlink() or root.stat().st_uid != os.getuid()):
            raise ValueError("LINK_TEMP_NOT_PRIVATE")
        obj = root / "candidate-inert.o"
        image = root / (NAME + (".dylib" if platform == "Darwin" else ".so"))
        compile_argv = (
            str(compiler), *s2.FLAGS, "-I", str(HEADER.parent), "-c",
            "-o", str(obj), str(SOURCE),
        )
        link_argv = _link_args(compiler, obj, image, platform)
        s1_stage = _digest({
            "previous": s0_stage, "compiler_entry_pre": compiler_pre,
            "compile_argv": compile_argv, "link_argv": link_argv,
            "environment": ENV, "platform": platform,
        })
        compiled = s0._fixed_run(compile_argv, env=ENV, timeout=60)
        if compiled.returncode:
            raise ValueError("S3_OBJECT_COMPILE_FAILED:" + compiled.stderr[:250])
        obj_sha, obj_stat = s0._sha_regular(obj)
        if obj_stat.st_uid != os.getuid() or obj_stat.st_nlink != 1:
            raise ValueError("S3_OBJECT_CUSTODY")
        nm = _TOOLS[platform][1]
        other = _TOOLS[platform][2]
        desc = _run_inspection((_TOOLS[platform][0], str(obj)), platform)
        defined = _run_inspection((nm, "-g", str(obj)), platform)
        undefined = _run_inspection((nm, "-u", str(obj)), platform)
        disasm = _run_inspection(
            (other, "-tv", str(obj)) if platform == "Darwin"
            else (_TOOLS[platform][3], "-dr", str(obj)), platform,
        )
        s2._metadata_gate(platform, desc, defined, undefined, disasm)
        s2_stage = _digest({
            "previous": s1_stage, "object_sha256": obj_sha,
            "object_format": desc, "exports": defined,
            "undefined": undefined,
        })
        linked = s0._fixed_run(link_argv, env=ENV, timeout=60)
        if linked.returncode:
            raise ValueError("S3_LINK_FAILED:" + linked.stderr[:300])
        os.chmod(image, 0o400)
        image_sha, image_stat = s0._sha_regular(image)
        if (image_stat.st_uid != os.getuid() or image_stat.st_nlink != 1 or
                stat.S_IMODE(image_stat.st_mode) != 0o400):
            raise ValueError("S3_IMAGE_CUSTODY")
        with image.open("rb") as f:
            header = f.read(4096)
        kind = _linked_header_gate(header, platform, image.name)
        metadata = _inspect(platform, image)
        # Fresh checks AFTER linker and inspection: still observational,
        # no atomic binding to actual child exec or any future loader inode.
        compiler_after, compiler_post = s0._compiler_entry()
        if compiler_after != compiler or compiler_post != compiler_pre:
            raise ValueError("S3_COMPILER_ENTRY_CHANGED")
        if (s0._sha_regular(SOURCE)[0] != source_sha or
                s0._sha_regular(HEADER)[0] != header_sha or
                s0._sha_regular(obj)[0] != obj_sha or
                s0._sha_regular(image)[0] != image_sha):
            raise ValueError("S3_INPUT_OR_OUTPUT_CHANGED")
        s3_stage = _digest({
            "previous": s2_stage, "linked_sha256": image_sha,
            "linked_header": kind, "link_argv": link_argv,
        })
        return {
            "current_head": head, "current_tree": tree,
            "reviewed_s2_parent_head":
                "21d0f6b00e21f154d41703d1f1910080b066c884",
            "reviewed_s2_parent_tree":
                "8610fa21b8bd7470e8d3d155be5a2453c8d1d90b",
            "platform": platform, "source_sha256": source_sha,
            "header_sha256": header_sha,
            "compiler_entry_sha256_precompile": compiler_pre,
            "compiler_entry_sha256_postlink": compiler_post,
            "manifest_sha256": s0._sha_regular(MANIFEST)[0],
            "compile_argv": compile_argv, "link_argv": link_argv,
            "object_sha256": obj_sha, "linked_image_sha256": image_sha,
            "linked_header": kind, "image_owner_uid": image_stat.st_uid,
            "image_device": image_stat.st_dev, "image_inode": image_stat.st_ino,
            "stage_digests": {
                "S0_observation": s0_stage, "S1_partial": s1_stage,
                "S2_object": s2_stage, "S3_linked_partial": s3_stage,
            },
            "inspection": metadata,
            "image_header_bytes": header,
            "linked_image_bytes_observed": True,
            "toolchain_sdk_closure_proven": False,
            "complete_final_binary_cfg_proven": False,
            "final_linked_image_lock_proven": False,
            "adapter_ffi_proven": False, "loader_inode_custody_proven": False,
            "first_c_load_authorized": False,
            "candidate_c_executed": False, "native_loader_invoked": False,
            "native_dispatches": 0, "group_kill_authorized": False,
            "reuse_proven": False, "g2_qualified": False,
            "admission": "REVIEW_REQUIRED_NO_LOAD",
        }
