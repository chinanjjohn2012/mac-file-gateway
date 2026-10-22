"""S3/S6 additional static executable-range ledger (NO LOAD / NO C EXEC).

Finite pure-Python ELF64 x86_64 / Mach-O arm64 byte-header checks for
RESEARCH OBSERVATION ONLY. This is NOT a disassembler, reachable CFG proof,
code-signature verifier, full loader validation or future inode custody.
Never import/load/call the observed candidate library.
"""
from __future__ import annotations

import hashlib
import struct
from typing import Any

import c3_candidate_b_t01_s3_linked_proof as s3
import c3_candidate_b_t01_s6_offline_deny_proof as s6

PARENT_HEAD = "27f959e305cec18e36bbc75126b602d78b9fd7f9"
PARENT_TREE = "161da4d379f772359a7c03671c333c744991daec"
NO_LOAD = "REVIEW_REQUIRED_NO_LOAD"
MAX_HEADERS = 128

# A deliberately finite *observed* ELF tag list from this research compiler.
# Unknown tags -> reject; these are not a generic dynamic-loader policy.
ELF_DYNAMIC_TAGS = frozenset({
    0, 5, 6, 10, 11, 14, 30, 0x6FFFFFFB, 0x6FFFFEF5,
})
ELF_SEGMENT_TYPES = frozenset({
    1, 2, 4, 0x6474E551, 0x6474E552, 0x6474E553,
})


def _range(raw: bytes, offset: int, size: int, label: str) -> None:
    if (type(offset) is not int or type(size) is not int or offset < 0
            or size < 0 or offset > len(raw)
            or size > len(raw) - offset):
        raise ValueError("STATIC_BINARY_RANGE:" + label)


def _name(table: bytes, index: int) -> str:
    if not 0 <= index < len(table):
        raise ValueError("BAD_SECTION_NAME_OFFSET")
    end = table.find(b"\x00", index)
    if end < 0:
        raise ValueError("UNTERMINATED_SECTION_NAME")
    name = table[index:end]
    try:
        return name.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("NON_ASCII_SECTION_NAME") from exc


def _executable_row(raw: bytes, *, name: str, off: int,
                    size: int, va: int) -> dict[str, object]:
    if size <= 0:
        raise ValueError("EMPTY_EXECUTABLE_SECTION")
    _range(raw, off, size, name)
    return {
        "name": name,
        "file_offset": off,
        "file_size": size,
        "virtual_address": va,
        "actual_bytes_sha256": hashlib.sha256(raw[off:off + size]).hexdigest(),
    }


def _elf(raw: bytes) -> dict[str, object]:
    if len(raw) < 64 or raw[:16] != (
        b"\x7fELF\x02\x01\x01" + b"\x00" * 9
    ):
        raise ValueError("ELF64_IDENTITY")
    (kind, machine, version, entry, phoff, shoff, flags, ehsize,
     phentsize, phnum, shentsize, shnum, shstrndx) = struct.unpack_from(
        "<HHIQQQIHHHHHH", raw, 16,
    )
    if (kind, machine, version, entry, flags, ehsize,
            phentsize, shentsize) != (3, 62, 1, 0, 0, 64, 56, 64):
        raise ValueError("ELF64_UNREVIEWED_HEADER")
    if not (0 < phnum <= MAX_HEADERS and 1 < shnum <= MAX_HEADERS
            and 0 < shstrndx < shnum):
        raise ValueError("ELF64_UNREVIEWED_COUNTS")
    _range(raw, phoff, phnum * phentsize, "ELF_PROGRAM_HEADERS")
    _range(raw, shoff, shnum * shentsize, "ELF_SECTION_HEADERS")

    segments: list[dict[str, int]] = []
    executable_loads: list[dict[str, int]] = []
    dynamic: list[dict[str, int]] = []
    for i in range(phnum):
        (typ, mode, off, va, _pa, fsize, msize, align) = (
            struct.unpack_from("<IIQQQQQQ", raw, phoff + i * 56)
        )
        if typ not in ELF_SEGMENT_TYPES or mode & ~7 or (
            (mode & 3) == 3
        ) or (mode & 1 and typ != 1):
            raise ValueError("ELF_UNKNOWN_OR_WRITABLE_EXEC_SEGMENT")
        if (fsize > msize or
                (align > 1 and (align & (align - 1) or
                                off % align != va % align))):
            raise ValueError("ELF_BAD_SEGMENT_ALIGNMENT_OR_SIZE")
        _range(raw, off, fsize, "ELF_SEGMENT")
        seg = {
            "type": typ, "flags": mode, "offset": off,
            "vaddr": va, "filesz": fsize, "memsz": msize,
        }
        segments.append(seg)
        if mode & 1:
            if fsize <= 0 or mode != 5:
                raise ValueError("ELF_UNREVIEWED_EXEC_SEGMENT")
            executable_loads.append(seg)
        if typ == 2:
            if fsize == 0 or fsize % 16:
                raise ValueError("ELF_DYNAMIC_RECORD_BOUNDARY")
            dynamic.append(seg)
        if typ == 0x6474E551 and mode & 1:
            raise ValueError("ELF_EXEC_STACK")
    if len(executable_loads) != 1 or len(dynamic) != 1:
        raise ValueError("ELF_UNKNOWN_EXEC_OR_DYNAMIC_SEGMENTS")
    # LOAD-backed FILE intervals may touch but must not overlap.
    nonempty_loads = sorted(
        (x["offset"], x["offset"] + x["filesz"])
        for x in segments if x["type"] == 1 and x["filesz"]
    )
    if len(nonempty_loads) != 3 or any(
        a[1] > b[0] for a, b in zip(nonempty_loads, nonempty_loads[1:])
    ):
        raise ValueError("ELF_LOAD_FILE_INTERVALS")

    # Read the real dynamic table bytes, not a copied readelf screenshot.
    dyn = dynamic[0]
    tags = []
    terminated = False
    for at in range(dyn["offset"], dyn["offset"] + dyn["filesz"], 16):
        tag, val = struct.unpack_from("<qQ", raw, at)
        if terminated:
            if tag != 0 or val != 0:
                raise ValueError("ELF_NONZERO_AFTER_DYNAMIC_TERMINATOR")
            continue
        if tag not in ELF_DYNAMIC_TAGS:
            raise ValueError("ELF_UNREVIEWED_DYNAMIC_TAG")
        tags.append(tag)
        if tag == 0:
            if val != 0:
                raise ValueError("ELF_NONZERO_NULL_DYNAMIC_VALUE")
            terminated = True
    if not terminated or tags.count(0) != 1:
        raise ValueError("ELF_MISSING_DYNAMIC_TERMINATOR")

    entries = []
    for i in range(shnum):
        entries.append(struct.unpack_from(
            "<IIQQQQIIQQ", raw, shoff + i * 64,
        ))
    if entries[0][1] != 0:
        raise ValueError("ELF_INVALID_NULL_SECTION")
    strings = entries[shstrndx]
    if strings[1] != 3 or not strings[5]:
        raise ValueError("ELF_INVALID_SECTION_NAMES")
    _range(raw, strings[4], strings[5], "ELF_SHSTRTAB")
    table = raw[strings[4]:strings[4] + strings[5]]
    found: set[str] = set()
    executable = []
    for i, ent in enumerate(entries[1:], 1):
        nameid, typ, flags, va, off, size, _link, _info, align, _entsize = ent
        name = _name(table, nameid)
        if not name or name in found:
            raise ValueError("ELF_DUPLICATE_OR_EMPTY_SECTION_NAME")
        found.add(name)
        if typ != 8:
            _range(raw, off, size, "ELF_SECTION")
        if align > 1 and (align & (align - 1) or off % align):
            raise ValueError("ELF_INVALID_SECTION_ALIGNMENT")
        if flags & 1 and flags & 4:
            raise ValueError("ELF_WRITABLE_EXEC_SECTION")
        if typ in (4, 9, 19) and size:
            raise ValueError("ELF_UNREVIEWED_RELOCATION_SECTION")
        if flags & 4:
            if typ != 1 or (flags & 7) != 6 or name != ".text":
                raise ValueError("ELF_UNREVIEWED_EXECUTABLE_SECTION")
            executable.append(_executable_row(
                raw, name=name, off=off, size=size, va=va
            ))
    if len(executable) != 1:
        raise ValueError("ELF_EXECUTABLE_SECTION_COUNT")
    code = executable[0]
    load = executable_loads[0]
    if not (
        load["offset"] <= code["file_offset"] and
        code["file_offset"] + code["file_size"] <=
        load["offset"] + load["filesz"] and
        load["vaddr"] <= code["virtual_address"] and
        code["virtual_address"] + code["file_size"] <=
        load["vaddr"] + load["memsz"] and
        code["virtual_address"] - load["vaddr"] ==
        code["file_offset"] - load["offset"]
    ):
        raise ValueError("ELF_CODE_NOT_IN_EXECUTABLE_LOAD")
    return {
        "format": "ELF64_LINUX_X86_64_STATIC_PARTIAL",
        "program_header_count": phnum,
        "section_header_count": shnum,
        "dynamic_tag_values": tags,
        "executable_regions": executable,
        "one_code_section_bound_to_one_exec_load": True,
        "complete_cfg_proven": False,
        "all_loader_side_effects_proven": False,
    }


def _macho(raw: bytes) -> dict[str, object]:
    if len(raw) < 32 or len(raw) > s3._STATIC_ARTIFACT_LIMIT:
        raise ValueError("MACHO_IMAGE_BYTES_OUT_OF_BOUNDS")
    # Delegate fixed command order/kind/dependency-name gate to reviewed S3.
    actual = s3._linked_header_gate(
        raw[:4096], "Darwin", s3.NAME + ".dylib"
    )
    if actual != "MACHO_ARM64_MH_DYLIB_PARTIAL":
        raise ValueError("MACHO_UNREVIEWED_LINKED_TYPE")
    _magic, _cpu, _subtype, _kind, count, total, _flags, _reserved = (
        struct.unpack_from("<IiiIIIII", raw, 0)
    )
    if count != len(s3._DARWIN_CMDS):
        raise ValueError("MACHO_UNREVIEWED_COMMAND_COUNT")
    _range(raw, 32, total, "MACHO_LOAD_COMMANDS")
    segments: list[dict[str, int]] = []
    executable = []
    imports_count: int | None = None
    offset = 32
    for i, (expected_cmd, expected_size) in enumerate(s3._DARWIN_CMDS):
        cmd, size = struct.unpack_from("<II", raw, offset)
        if (cmd, size) != (expected_cmd, expected_size):
            raise ValueError("MACHO_UNREVIEWED_LOAD_COMMAND")
        if cmd == 0x19:  # LC_SEGMENT_64
            (_cmd, _size, name, va, vmsize, fileoff, filesize,
             maxprot, initprot, nsects, segflags) = struct.unpack_from(
                 "<II16sQQQQiiII", raw, offset
             )
            name = name.split(b"\x00", 1)[0]
            _range(raw, fileoff, filesize, "MACHO_SEGMENT")
            if (maxprot < 0 or initprot < 0 or
                    maxprot & ~7 or initprot & ~7 or
                    (maxprot & 3) == 3 or (initprot & 3) == 3 or
                    (initprot & ~maxprot) or filesize > vmsize or
                    segflags != 0):
                raise ValueError("MACHO_UNREVIEWED_SEGMENT_PROTECTION")
            seg = {"offset": fileoff, "size": filesize,
                   "vaddr": va, "vmsize": vmsize, "initprot": initprot}
            segments.append(seg)
            if i == 0:
                if name != b"__TEXT" or nsects != 1 or (
                    maxprot, initprot
                ) != (5, 5):
                    raise ValueError("MACHO_UNREVIEWED_TEXT_SEGMENT")
                (section, section_seg, s_addr, s_size, s_off, align,
                 reloff, nreloc, secflags, reserved1, reserved2,
                 reserved3) = struct.unpack_from(
                     "<16s16sQQIIIIIIII", raw, offset + 72
                 )
                if (
                    section.split(b"\x00", 1)[0] != b"__text"
                    or section_seg.split(b"\x00", 1)[0] != b"__TEXT"
                    or secflags != 0x80000400 or reloff or nreloc
                    or reserved1 or reserved2 or reserved3 or align > 12
                    or s_off % (1 << align)
                ):
                    raise ValueError("MACHO_UNREVIEWED_TEXT_SECTION")
                executable.append(_executable_row(
                    raw, name="__TEXT/__text", off=s_off,
                    size=s_size, va=s_addr
                ))
                if not (
                    fileoff <= s_off and s_off + s_size <= fileoff + filesize
                    and va <= s_addr and s_addr + s_size <= va + vmsize
                    and s_addr - va == s_off - fileoff
                ):
                    raise ValueError("MACHO_TEXT_NOT_IN_SEGMENT")
            else:
                if name != b"__LINKEDIT" or nsects != 0 or (
                    maxprot, initprot
                ) != (1, 1):
                    raise ValueError("MACHO_UNREVIEWED_LINKEDIT_SEGMENT")
        if cmd == 0x80000034:  # LC_DYLD_CHAINED_FIXUPS
            _cmd, _cmdsize, dataoff, datasize = struct.unpack_from(
                "<IIII", raw, offset
            )
            if datasize < 28:
                raise ValueError("MACHO_EMPTY_FIXUP_HEADER")
            _range(raw, dataoff, datasize, "MACHO_CHAINED_FIXUPS")
            fields = struct.unpack_from("<7I", raw, dataoff)
            (_version, start_off, import_off, symbol_off, imports_count,
             _import_format, _symbol_format) = fields
            if (_version != 0 or imports_count != 0 or
                    not 28 <= start_off <= datasize or
                    not 28 <= import_off <= datasize or
                    not 28 <= symbol_off <= datasize):
                raise ValueError("MACHO_UNREVIEWED_CHAINED_IMPORTS")
        if cmd in (0x80000033, 0x26, 0x29, 0x1d):
            _cmd, _size, dataoff, datasize = struct.unpack_from(
                "<IIII", raw, offset
            )
            _range(raw, dataoff, datasize, "MACHO_LINKEDIT_DATA")
        if cmd == 0x02:  # LC_SYMTAB, 64-bit nlist entry is 16 bytes
            _cmd, _size, symoff, nsyms, stroff, strsize = (
                struct.unpack_from("<6I", raw, offset)
            )
            if not 1 <= nsyms <= 1024 or strsize == 0:
                raise ValueError("MACHO_UNREVIEWED_SYMBOL_TABLE")
            _range(raw, symoff, nsyms * 16, "MACHO_SYMBOLS")
            _range(raw, stroff, strsize, "MACHO_STRING_TABLE")
        if cmd == 0x0b:  # LC_DYSYMTAB nundefsym
            if struct.unpack_from("<I", raw, offset + 28)[0] != 0:
                raise ValueError("MACHO_UNREVIEWED_UNDEFINED_SYMBOLS")
        offset += size
    if imports_count != 0 or len(segments) != 2 or len(executable) != 1:
        raise ValueError("MACHO_MISSING_STATIC_STRUCTURE")
    if not (
        segments[0]["offset"] + segments[0]["size"] <=
        segments[1]["offset"] and
        segments[0]["offset"] == 0 and
        segments[1]["offset"] + segments[1]["size"] == len(raw)
    ):
        raise ValueError("MACHO_INVALID_FILE_SEGMENT_INTERVALS")
    return {
        "format": "MACHO_ARM64_STATIC_PARTIAL",
        "load_command_count": count,
        "segment_count": len(segments),
        "chained_import_count": imports_count,
        "executable_regions": executable,
        "one_code_section_bound_to_one_exec_load": True,
        "complete_cfg_proven": False,
        "all_loader_side_effects_proven": False,
    }


def static_executable_ranges(raw: object, platform: str) -> dict[str, object]:
    """Scan bytes only; never pass a pathname to the OS loader."""
    if (type(raw) is not bytes or not 0 < len(raw) <=
            s3._STATIC_ARTIFACT_LIMIT):
        raise ValueError("UNREVIEWED_OR_NON_BYTES_LINKED_IMAGE")
    if platform == "Linux":
        return _elf(raw)
    if platform == "Darwin":
        return _macho(raw)
    raise ValueError("UNREVIEWED_EXECUTABLE_PLATFORM")


def collect_actual_static_regions() -> tuple[dict[str, dict], dict[str, object]]:
    """Reuse existing actual NO LOAD S3/S4/S5 collectors and denial check."""
    bundle, parent = s6.collect_real_partial_evidence()
    s3item = bundle[s6.STAGES[0]]
    if parent["admission"] != NO_LOAD:
        raise ValueError("PARENT_OFFLINE_REJECT_OR_NOT_REVIEWABLE")
    image = s3item["linked_image_bytes"]
    if hashlib.sha256(image).hexdigest() != s3item["linked_image_sha256"]:
        raise ValueError("ACTUAL_LINKED_IMAGE_DIGEST_CHANGED")
    ledger = static_executable_ranges(image, s3item["platform"])
    if ledger["complete_cfg_proven"] or ledger["all_loader_side_effects_proven"]:
        raise ValueError("STATIC_LEDGER_PROMOTED_TO_AUTHORITY")
    summary = {
        "current_head": parent["head"],
        "current_tree": parent["tree"],
        "reviewed_parent_head": PARENT_HEAD,
        "reviewed_parent_tree": PARENT_TREE,
        "manifest_sha256": parent["manifest_sha256"],
        "linked_image_sha256": s3item["linked_image_sha256"],
        "object_sha256": s3item["object_sha256"],
        "linked_image_byte_count": len(image),
        "platform": s3item["platform"],
        "ledger": ledger,
        "native_loader_invoked": False,
        "candidate_c_executed": False,
        "native_dispatches": 0,
        "complete_final_cfg_proven": False,
        "complete_recursive_toolchain_sdk_closure_proven": False,
        "future_loader_same_inode_proven": False,
        "full_s6_independent_approval_granted": False,
        "first_c_load_authorized": False,
        "group_kill_authorized": False,
        "reuse_proven": False,
        "g2_qualified": False,
        "admission": NO_LOAD,
    }
    return bundle, summary
