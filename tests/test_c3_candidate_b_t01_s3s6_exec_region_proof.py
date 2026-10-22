"""Actual NO LOAD binary executable-range ledger and byte-level mutants."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import struct
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools/research"))
import c3_candidate_b_t01_s3s6_exec_region_proof as scan  # noqa: E402

DOC = ROOT / "docs/research/phase2-lite-c3/candidate-b-b03-t01-s3s6-exec-range-ledger.md"
WF = ROOT / ".github/workflows/c3-candidate-b-t01-s3s6-exec-range-ledger.yml"


@pytest.fixture(scope="module")
def actual():
    bundle, summary = scan.collect_actual_static_regions()
    print("C3B03_S3S6_ACTUAL_STATIC_EXEC_RANGE_LEDGER=" + json.dumps(
        summary, sort_keys=True, separators=(",", ":")
    ))
    return bundle[scan.s6.STAGES[0]], summary


def test_actual_bound_header_and_one_executable_region(actual):
    image, summary = actual
    assert summary["reviewed_parent_head"] == (
        "27f959e305cec18e36bbc75126b602d78b9fd7f9"
    )
    assert summary["reviewed_parent_tree"] == (
        "161da4d379f772359a7c03671c333c744991daec"
    )
    assert summary["current_head"] != summary["reviewed_parent_head"]
    assert summary["linked_image_sha256"] == hashlib.sha256(
        image["linked_image_bytes"]
    ).hexdigest()
    assert summary["linked_image_byte_count"] == len(
        image["linked_image_bytes"]
    )
    ledger = summary["ledger"]
    assert ledger["complete_cfg_proven"] is False
    assert ledger["all_loader_side_effects_proven"] is False
    assert ledger["one_code_section_bound_to_one_exec_load"] is True
    assert len(ledger["executable_regions"]) == 1
    code = ledger["executable_regions"][0]
    start, size = code["file_offset"], code["file_size"]
    assert 0 < size <= len(image["linked_image_bytes"])
    assert hashlib.sha256(image["linked_image_bytes"][
        start:start + size
    ]).hexdigest() == code["actual_bytes_sha256"]
    assert code["virtual_address"] >= 0
    assert summary["admission"] == "REVIEW_REQUIRED_NO_LOAD"
    assert summary["native_dispatches"] == 0
    assert summary["group_kill_authorized"] is False
    for key in (
        "native_loader_invoked", "candidate_c_executed",
        "complete_final_cfg_proven",
        "complete_recursive_toolchain_sdk_closure_proven",
        "future_loader_same_inode_proven",
        "full_s6_independent_approval_granted",
        "first_c_load_authorized", "reuse_proven", "g2_qualified",
    ):
        assert summary[key] is False


def test_real_platform_ledger_observations(actual):
    _, summary = actual
    ledger = summary["ledger"]
    if summary["platform"] == "Linux":
        assert ledger["format"] == "ELF64_LINUX_X86_64_STATIC_PARTIAL"
        assert ledger["section_header_count"] == 13
        assert ledger["program_header_count"] == 10
        assert ledger["load_virtual_intervals_disjoint"] is True
        assert ledger["load_virtual_pages_disjoint"] is True
        assert ledger["dynamic_file_vm_displacement_proven_for_this_snapshot"] is True
        assert ledger["executable_regions"][0]["name"] == ".text"
        assert 0 not in ledger["dynamic_tag_values"][:-1]
        assert ledger["dynamic_tag_values"][-1] == 0
        assert 1 not in ledger["dynamic_tag_values"]
        assert 12 not in ledger["dynamic_tag_values"]
        assert 25 not in ledger["dynamic_tag_values"]
    else:
        assert summary["platform"] == "Darwin"
        assert ledger["format"] == "MACHO_ARM64_STATIC_PARTIAL"
        assert ledger["load_command_count"] == 14
        assert ledger["segment_count"] == 2
        assert ledger["chained_import_count"] == 0
        assert ledger["executable_regions"][0]["name"] == "__TEXT/__text"


def _elf_exec_ph(raw: bytearray) -> int:
    phoff = struct.unpack_from("<Q", raw, 32)[0]
    count = struct.unpack_from("<H", raw, 56)[0]
    for i in range(count):
        pos = phoff + i * 56
        typ, mode = struct.unpack_from("<II", raw, pos)
        if typ == 1 and mode & 1:
            return pos
    raise AssertionError("no executable PT_LOAD in original fixture")


def _elf_text_sh(raw: bytearray) -> int:
    shoff = struct.unpack_from("<Q", raw, 40)[0]
    count = struct.unpack_from("<H", raw, 60)[0]
    for i in range(count):
        pos = shoff + i * 64
        flags = struct.unpack_from("<Q", raw, pos + 8)[0]
        if flags & 4:
            return pos
    raise AssertionError("no executable section in original fixture")


def _elf_dynamic_ph(raw: bytearray) -> int:
    phoff = struct.unpack_from("<Q", raw, 32)[0]
    count = struct.unpack_from("<H", raw, 56)[0]
    for i in range(count):
        pos = phoff + i * 56
        if struct.unpack_from("<I", raw, pos)[0] == 2:
            return pos
    raise AssertionError("no dynamic segment in original fixture")


@pytest.mark.parametrize("mutation", (
    "magic", "truncate", "wrong-platform",
    "executable-writable", "executable-section-oob",
    "unexpected-executable-section", "bad-section-alignment",
    "segment-oob", "unexpected-dynamic-import",
    "unexpected-exec-virtual-address", "unapproved-relo-or-undefined",
))
def test_binary_mutant_fails_closed(actual, mutation):
    observed, _summary = actual
    platform = observed["platform"]
    data = bytearray(observed["linked_image_bytes"])

    if mutation == "magic":
        data[0] = 0
    elif mutation == "truncate":
        data = data[:32]
    elif mutation == "wrong-platform":
        other = "Darwin" if platform == "Linux" else "Linux"
        with pytest.raises(ValueError):
            scan.static_executable_ranges(bytes(data), other)
        return
    elif platform == "Linux":
        if mutation == "executable-writable":
            struct.pack_into("<I", data, _elf_exec_ph(data) + 4, 7)
        elif mutation == "executable-section-oob":
            struct.pack_into("<Q", data, _elf_text_sh(data) + 24, len(data) + 1)
        elif mutation == "unexpected-executable-section":
            # This makes a non-exec section appear to contain executable code.
            shoff = struct.unpack_from("<Q", data, 40)[0]
            pos = shoff + 7 * 64  # .eh_frame in this frozen ELF
            struct.pack_into("<Q", data, pos + 8, 0x6)
            struct.pack_into("<Q", data, pos + 32, 8)
        elif mutation == "bad-section-alignment":
            struct.pack_into("<Q", data, _elf_text_sh(data) + 48, 3)
        elif mutation == "segment-oob":
            struct.pack_into("<Q", data, _elf_exec_ph(data) + 32, len(data) + 1)
        elif mutation == "unexpected-dynamic-import":
            dynamic = _elf_dynamic_ph(data)
            off = struct.unpack_from("<Q", data, dynamic + 8)[0]
            struct.pack_into("<q", data, off, 1)  # DT_NEEDED
        elif mutation == "unexpected-exec-virtual-address":
            struct.pack_into("<Q", data, _elf_text_sh(data) + 16, 0xFFFF0000)
        elif mutation == "unapproved-relo-or-undefined":
            shoff = struct.unpack_from("<Q", data, 40)[0]
            pos = shoff + 9 * 64  # .comment, real nonempty byte section
            struct.pack_into("<I", data, pos + 4, 4)  # SHT_RELA, size >0
    else:
        textpos = 32  # First LC_SEGMENT_64
        sectionpos = textpos + 72
        linkeditpos = textpos + 152
        if mutation == "executable-writable":
            struct.pack_into("<I", data, textpos + 60, 7)
        elif mutation == "executable-section-oob":
            struct.pack_into("<I", data, sectionpos + 48, len(data) + 1)
        elif mutation == "unexpected-executable-section":
            struct.pack_into("<I", data, textpos + 64, 2)
        elif mutation == "bad-section-alignment":
            struct.pack_into("<I", data, sectionpos + 52, 31)
        elif mutation == "segment-oob":
            struct.pack_into("<Q", data, linkeditpos + 48, len(data) + 1)
        elif mutation == "unexpected-dynamic-import":
            chainedcmd = textpos + 152 + 72 + 64
            off = struct.unpack_from("<I", data, chainedcmd + 8)[0]
            struct.pack_into("<I", data, off + 16, 1)
        elif mutation == "unexpected-exec-virtual-address":
            struct.pack_into("<Q", data, sectionpos + 32, 0xFFFF0000)
        elif mutation == "unapproved-relo-or-undefined":
            dysymcmd = textpos + sum(sz for _, sz in scan.s3._DARWIN_CMDS[:6])
            struct.pack_into("<I", data, dysymcmd + 28, 1)
    with pytest.raises(ValueError):
        scan.static_executable_ranges(bytes(data), platform)



def _elf_writable_load_ph(raw: bytearray) -> int:
    phoff = struct.unpack_from("<Q", raw, 32)[0]
    count = struct.unpack_from("<H", raw, 56)[0]
    matches = [
        phoff + i * 56 for i in range(count)
        if struct.unpack_from("<II", raw, phoff + i * 56) == (1, 6)
    ]
    assert len(matches) == 1, "expected one real writable PT_LOAD"
    return matches[0]


@pytest.mark.parametrize("mutation", (
    "overlap-rw-with-rx-vm",
    "rw-rx-alias-on-single-page-without-byte-overlap",
    "dynamic-vaddr-unmapped",
    "dynamic-vaddr-mapped-to-wrong-load",
    "writable-load-virtual-address-wraparound",
))
def test_actual_elf_virtual_load_and_dynamic_mapping_denies_mutants(
        actual, mutation):
    """P2-01 RED first, then GREEN. Mutate observed inert ELF bytes only.

    Under the OLD parser every one of these variations is accepted. The
    first two expose PT_LOAD VM/page aliases, the next two show PT_DYNAMIC
    file bytes not mapping at the declared virtual address, and the last
    lacks virtual end-overflow validation. No candidate ELF is loaded.
    """
    observed, _summary = actual
    if observed["platform"] != "Linux":
        pytest.skip("ELF-specific binary negatives; macOS positive unchanged")
    raw = bytearray(observed["linked_image_bytes"])
    rx = _elf_exec_ph(raw)
    rw = _elf_writable_load_ph(raw)
    dy = _elf_dynamic_ph(raw)
    rx_vaddr = struct.unpack_from("<Q", raw, rx + 16)[0]
    assert rx_vaddr == 0x1000
    assert struct.unpack_from("<Q", raw, rw + 16)[0] == 0x2f20
    if mutation == "overlap-rw-with-rx-vm":
        struct.pack_into("<Q", raw, rw + 16, rx_vaddr)
        struct.pack_into("<Q", raw, rw + 48, 1)
    elif mutation == "rw-rx-alias-on-single-page-without-byte-overlap":
        assert struct.unpack_from("<Q", raw, rx + 40)[0] < 0x900
        struct.pack_into("<Q", raw, rw + 16, rx_vaddr + 0x900)
        struct.pack_into("<Q", raw, rw + 48, 1)
    elif mutation == "dynamic-vaddr-unmapped":
        before = struct.unpack_from("<Q", raw, dy + 16)[0]
        struct.pack_into("<Q", raw, dy + 16, before + 0x8000)
    elif mutation == "dynamic-vaddr-mapped-to-wrong-load":
        struct.pack_into("<Q", raw, dy + 16, rx_vaddr)
    elif mutation == "writable-load-virtual-address-wraparound":
        struct.pack_into("<Q", raw, rw + 16, 0xFFFFFFFFFFFFFFD0)
        struct.pack_into("<Q", raw, rw + 48, 1)
    else:
        raise AssertionError("unhandled P2-01 mutation")
    expected_errors = {
        "overlap-rw-with-rx-vm": "ELF_LOAD_VIRTUAL_INTERVAL_OVERLAP",
        "rw-rx-alias-on-single-page-without-byte-overlap": (
            "ELF_LOAD_VIRTUAL_PAGE_ALIAS"),
        "dynamic-vaddr-unmapped": "ELF_DYNAMIC_VIRTUAL_LOAD_MISMATCH",
        "dynamic-vaddr-mapped-to-wrong-load": (
            "ELF_DYNAMIC_VIRTUAL_LOAD_MISMATCH"),
        "writable-load-virtual-address-wraparound": (
            "ELF_LOAD_VIRTUAL_ADDRESS_OVERFLOW"),
    }
    with pytest.raises(ValueError, match=expected_errors[mutation]):
        scan.static_executable_ranges(bytes(raw), "Linux")


@pytest.mark.parametrize("source", (None, [], "not bytes", b"", b"x" * 1048577))
def test_non_binary_or_unbounded_input_is_rejected(source):
    with pytest.raises(ValueError):
        scan.static_executable_ranges(source, "Linux")


def test_misleading_metadata_cannot_replace_raw_executable_ranges(actual):
    image, _summary = actual
    raw = image["linked_image_bytes"]
    # The parser must not depend on readelf/otool metadata copied from text.
    # It sees only the true bounded bytes, which remain a limited observation.
    a = scan.static_executable_ranges(raw, image["platform"])
    assert a["executable_regions"][0]["actual_bytes_sha256"]
    changed = bytearray(raw)
    # Changing section text without moving headers alters the region digest;
    # this is NOT a proof of instruction reachability or safety.
    offset = a["executable_regions"][0]["file_offset"]
    changed[offset] ^= 0xFF
    b = scan.static_executable_ranges(bytes(changed), image["platform"])
    assert a["executable_regions"][0]["actual_bytes_sha256"] != (
        b["executable_regions"][0]["actual_bytes_sha256"]
    )


def test_workflow_and_manifest_preserve_permanent_stop():
    doc = DOC.read_text(encoding="utf-8")
    wf = WF.read_text(encoding="utf-8")
    for token in (
        "NO LOAD", "NO C EXEC", "PARTIAL", "P3-01", "P3-02",
        "P3-03", "191 expected RED", "NOT_RUN/BLOCK",
        "REVIEW_REQUIRED_NO_LOAD", "group_kill_authorized=false",
        "reuse_proven=false", "g2_qualified=false",
        "first_c_load_authorized=false", "S5", "S6",
        "ExecSupervisor", "REST/MCP Multi-Workspace Exec",
    ):
        assert token.lower() in doc.lower(), token
    for token in (
        "contents: read", "persist-credentials: false",
        "macos-15", "ubuntu-latest", '"3.13"', '"3.14"',
        "MANIFEST.sha256", "C3B03_S3S6_GROUP_SIGNAL_AUTHORIZED",
        "tests/test_c3_candidate_b_t01_s3s6_exec_region_proof.py",
        "test ! -e tools/research/c3_candidate_b_kill.c",
    ):
        assert token in wf, token
    for forbidden in (
        "workflow_dispatch", "continue-on-error:", "|| true",
        "ctypes.CDLL(", "dlopen(", "os.kill(", "killpg(",
        "test_c3_candidate_b_t01_r2b_contract_red.py",
    ):
        assert forbidden not in wf, forbidden
    assert not (ROOT / "tools/research/c3_candidate_b_kill.c").exists()
    manifest = scan.s6.s0.checked_manifest()
    for path in (DOC, WF, Path(__file__), Path(scan.__file__)):
        name = "./" + path.relative_to(ROOT).as_posix()
        assert manifest[name] == hashlib.sha256(path.read_bytes()).hexdigest()
