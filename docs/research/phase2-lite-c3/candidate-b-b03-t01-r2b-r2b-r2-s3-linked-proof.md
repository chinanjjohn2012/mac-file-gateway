# C3 Candidate B / B03-T01 R2b-R2b-R2-S3 — SAME-SESSION Linked Image Provenance (NO LOAD / NO C EXEC)

**Status: AUTHOR PARTIAL S3 EVIDENCE; independent CODE Review PENDING.** This branch is stacked on independently reviewed [PR #48](https://github.com/chinanjjohn2012/mac-file-gateway/pull/48#pullrequestreview-5611546056), frozen Head `21d0f6b00e21f154d41703d1f1910080b066c884`, Tree `8610fa21b8bd7470e8d3d155be5a2453c8d1d90b`. Its Standards PASS / Spec PASS covers only S2 OBJECT NO LOAD PARTIAL.

## Strict S3 boundary
This research-only change obtains **fresh**, same-session evidence for frozen inert C source + header SHA, observed compiler-entry SHA (before compile), exact compile argv, real relocatable object bytes, exact link argv, and real final linked `.so` / `.dylib` bytes. It only observes file type, exports, undefined symbols, raw Mach-O load commands or Linux ELF header, relocations, imports/dependencies, sections and disassembly. The object and library are in a temporary owned `0700` directory, read via nofollow hashing and removed without load or call. No Python FFI, `ctypes.CDLL`, `dlopen`, native Adapter, actual C invocation, or group signal.

Same-session SHA digests provide an **ordered observational association**, not immutable or atomic provenance. The compiled and linked artifacts are real, not copied historical R1 hashes. The pre/post compiler-entry SHA does **not** prove the actual executed driver inode, nested frontend, assembler, linker or transitive SDK/sysroot closure. The S3 final image check is **PARTIAL** and does not prove complete CFG, unreachable initializer analysis, every indirect branch target or loader lookup path. The loaded image is never tested.

## Actual evidence, negatives, and admission
- S0: complete ordered Manifest with exact Head+Git Tree, immutable reviewed C/header input digests, exact two includes.
- S1 PARTIAL: fixed sanitized environment and compile/link argv, real compiler-entry SHA observed before compile and re-read after link, but full toolchain/SDK closure **unproven**.
- S2: actual candidate C `-c` to `.o`, real byte SHA, expected platform-only strong-T export and zero undefined; original disassembly is printed by CI and linked by stage digest.
- S3 PARTIAL: fresh `cc` link from that **same object** to transient library; no other object accepted as an input. SHA256, ownership, nlink, format, symbols, dynamic surfaces, fixed Mach-O command layout / ELF sections+relocations and original disassembly recorded. No file is loaded.
- Negative coverage: wrong executable header, Mach-O extra command, linked metadata added symbol, undefined import, wrong type, unknown syscall, constructor, relocation and dependency mutations. These **in-memory metadata and header mutants** are not substitutes for true malicious linked binary variants or complete CFG. Unknown result is STOP.
- S4 Adapter, S5 atomic loader-custody and S6 independent authority: **NOT_RUN/BLOCK**. Return `REVIEW_REQUIRED_NO_LOAD` only, with all complete gate booleans false.

**P3-01 OPEN** — full toolchain/SDK closure, exact child exec identity, source-to-object-to-final atomic chain and loader inode custody remain absent.
**P3-02 OPEN** — full final binary reachable CFG, all indirect edges, imports/relocations/initializers and actual Python FFI binding remain absent.
P3-03 CLOSED remains unchanged.

The unimplemented Native contracts remain **191 expected RED** (19 B03-R1 absent Helper/Runner + 172 R2b-R1 absent C Helper/Adapter), so Linux Full workflow is **FAILURE**, not GREEN. Unexpected failures are not excused.

**Hard BLOCK:** `group_kill_authorized=false`, `reuse_proven=false`, `g2_qualified=false`; T04/T08b/T10 NOT_RUN/BLOCK; R2b-R2b-R3 first Native C load, Native Owner/Controller/Worker, real TERM/SIGKILL, G2/G3/G4/G5, product Gateway ExecSupervisor/REST/MCP Multi Exec, merge and deploy. PR remains Draft, unmerged.

Independent reviewer must read exact Base/Head/Tree, all changed files and **original GitHub Actions jobs** and publish Standards / Spec on the fixed Head. Passing S3 PARTIAL never grants Native permission.
