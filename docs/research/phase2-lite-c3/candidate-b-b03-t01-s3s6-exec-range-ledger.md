# C3 B03-T01 — S3/S6 Bounded Executable Range and Static Loader-Field Ledger

**Status: AUTHOR PARTIAL NO LOAD / NO C EXEC RESEARCH — independent Standards / Spec CODE Review PENDING.** This new file adds a narrow byte-level executable-range ledger; it is **NOT** complete final-image CFG, loader/ABI provenance, code signing, independent D1 S6, or first Native C load approval.

**Independently reviewed base:** [PR #54 Review #5613963741](https://github.com/chinanjjohn2012/mac-file-gateway/pull/54#pullrequestreview-5613963741), fixed Head `27f959e305cec18e36bbc75126b602d78b9fd7f9`, Git Tree `161da4d379f772359a7c03671c333c744991daec`: Standards PASS / Spec PASS **only for the existing S3/S6 bounded static object/linked byte→SHA PARTIAL**. Parent PR stays Draft/unmerged. P3-01 and P3-02 remain OPEN, P3-03 CLOSED.

## Actual data sources and exact limits

This stage reuses the already-reviewed existing S3 real inert Candidate C compile/object/static-link collector, the S6 OFFLINE DENY-ONLY checker, the S4 static C11 ABI/SourceOnlyAdapter AST and S5 separate **non-executable DATA** FD observations. It does not add or change the compiler's frozen flags, linked artifact bytes or S3→S6 security authority. It reads the **same bounded ≤1 MiB in-memory linked image bytes** retained by the reviewed S3 collector; the prior S6 byte-to-SHA binding is checked first, and the new independent parser calculates an actual SHA256 for exactly one executable section's bounded bytes.

The parser uses **Python `struct.unpack_from` only**. It does NOT import/load the candidate `.so/.dylib` with `ctypes.CDLL`, `dlopen` or any FFI; does not call candidate C, invoke host processes/PID/PGID, or send group signals. It makes no new binary dynamic-library search or OS loader requests. `native_loader_invoked=false`, `candidate_c_executed=false`, `native_dispatches=0`.

### Linux x86_64 / ELF64 limited observations

Based on actual preceding three-platform S3 Job logs, the observed inert ELF has **10 program headers and 13 section headers**, one executable `.text`, four PT_LOAD segments (three with nonempty file intervals), exactly one executable PT_LOAD, and one PT_DYNAMIC. The pure byte reader:

- Requires little-endian ELF64 `ET_DYN`, machine x86_64, zero entry point, bounded conventional ELF header and section/program header counts and sizes. Every parsed file offset/size is checked against the actual linked-byte array.
- Rejects PT_INTERP, unknown segment kinds, writable-and-executable memory permissions, executable PT_GNU_STACK, impossible alignment/size, overlapping nonempty LOAD file intervals or missing/unrecognized executable LOAD.
- Reads the actual section name string table; rejects duplicated/invalid section names, unknown executable sections, missing/empty `.text`, ELF `SHT_REL/SHT_RELA/SHT_RELR` **with nonempty size**, executable section marked writable or mapped outside its observed executable LOAD. The single identified `.text` region must have real file-offset and virtual-address agreement with PT_LOAD.
- Reads the bounded `PT_DYNAMIC` records directly from bytes, allowing only this previously observed finite tag set: `NULL, SONAME, GNU_HASH, STRTAB, SYMTAB, STRSZ, SYMENT, FLAGS, FLAGS_1`. Unknown tags such as `NEEDED`, `INIT`, `INIT_ARRAY`, `JMPREL`, `RUNPATH` reject. GNU ld may pad the real dynamic table with null records; nonzero data after the first DT_NULL fails.

This is a *limited scanner*, not a complete ELF parser, symbol/linker verification, memory page permission proof, CFG, or full enumeration of exotic relocation surfaces.

### macOS ARM64 / Mach-O limited observations

The previous real macOS Job shows a `MH_DYLIB`, **14 reviewed load command IDs/sizes**, `__TEXT` with one `__text` section and `__LINKEDIT` with none. The new byte reader first invokes the already reviewed narrow `_linked_header_gate` on the actual byte prefix, then:

- Parses the actual two `LC_SEGMENT_64` commands with bounded file/VM sizes and segment protections. Rejects W+X, unexpected `__TEXT`/ `__LINKEDIT` names, extra sections, wrong/prohibited protection, segment file overlap or out-of-bounds data.
- Parses the actual single `section_64 __TEXT,__text`; rejects wrong section flags, extra relocation counts, unknown reserved values, invalid alignment, malformed file bounds or section address inconsistent with its executable segment. Records an actual SHA256 of only this section's in-memory bytes.
- Bounds-checks `LC_SYMTAB`, selected `LC_DYLD_CHAINED_FIXUPS`/ `LC_DYLD_EXPORTS_TRIE` and linkedit-data byte ranges; rejects nonzero reported chained import count and nonzero `LC_DYSYMTAB` undefined-symbol count. This is **not** full dyld fixup decoding, exports-trie validation or loader dependency authentication.

### Output, negatives and exact security meaning

The final ledger returns only `REVIEW_REQUIRED_NO_LOAD`. Each actual per-platform log records the current Git Head+Tree/Manifest SHA, platform, actual object/linked SHA from S3, final linked length, finite header/section count, **one observed executable byte interval with actual section SHA256**, and explicit `complete_final_cfg_proven=false`, `full_s6_independent_approval_granted=false`, `future_loader_same_inode_proven=false`.

Deterministic **in-memory byte mutations** test malformed magic/short content/wrong platform, W+X segment flags, out-of-range code offset, an additional executable section, bad alignment, segment range overflow, unexpected dynamic import, unmapped executable virtual address, relocation/undefined-symbol mutation, and unsupported length or type. Negative fixtures alter only existing transient candidate bytes **after** collection, never load them. The section SHA responds to a changed instruction-area byte, without pretending to determine whether that changed byte is executable instruction or a valid branch target.

**Unknown or changed format on any runner MUST fail CI and require review**, never bypass gate or promote a new toolchain layout automatically. A verified binary-region data ledger cannot by itself establish all reachable instruction edges, disassembly completeness, indirect branch targets, initializers, on-load side effects, full dependency closure or safety of function calls. No real process-group signal safety is inferred.

## Open obligations and scope control

**P3-01 OPEN:** compiler/driver/backend/linker/SDK/sysroot recursive identity, atomic source→object→final→actual loader same-inode custody and same-UID/TOCTOU protection remain unproven. **P3-02 OPEN:** actual full executable CFG, indirect branches, import/relocation/fixup/initializer completeness, future FFI Adapter transitive import graph, call convention and pointer lifetime remain unproven. **P3-03 CLOSED** remains unchanged. The old S5 checks a **different inert DATA file**, not the linked Candidate C image. Each collector uses a different temporary session, so there is no atomic build-to-loader provenance chain. Full D1 S6 `INDEPENDENT_PRELOAD_DECISION` and Native first load remain **NOT_RUN/BLOCK**.

The **191 expected RED** Native contract cases (19 B03 missing Helper/Runner plus 172 R2b missing Native Helper/Adapter) remain untouched. Linux Full must be represented as FAILURE, never full GREEN; any unexpected regression is blocking.

**Hard STOP:** `group_kill_authorized=false`, `reuse_proven=false`, `g2_qualified=false`, `first_c_load_authorized=false`. T04/T08b/T10 `NOT_RUN/BLOCK`, R2b-R2b-R3/R2b-R3/T01-R3, first candidate C load/call, Native Owner/Controller/Worker, real process-group TERM/SIGKILL, G2/G3/G4/G5, production Gateway ExecSupervisor / REST/MCP Multi-Workspace Exec, merge/deploy **BLOCK**. Stacked PR stays Draft/unmerged.

Independent reviewer must read the fixed PR Head+Tree and actual implementation/tests/workflow/Manifest, parent fixed Review #5613963741 and **original current-Head Actions Job logs**; a PASS could only close this **static executable-region/finite loader-tag ledger PARTIAL** stage, not P3-01/P3-02 or Native load permission.
