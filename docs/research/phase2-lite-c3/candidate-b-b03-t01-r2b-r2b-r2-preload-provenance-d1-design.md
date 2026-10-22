# C3 B03-T01 / R2b-R2b-R2-D1 — PRE-LOAD Provenance and Adapter Binding DESIGN ONLY

**Status:** AUTHOR DESIGN, independent Standards/Spec review PENDING. **DESIGN_ONLY=true · NO_LOAD=true · C_EXECUTED=false · NATIVE_DISPATCHES=0 · group_kill_authorized=false**.

**Fixed independent parent:** [PR #45](https://github.com/chinanjjohn2012/mac-file-gateway/pull/45), Head `d8e011fb538d9638f67e5c0d928340d374677a1b` / Git Tree `cce4d65bdd64dac4d7fa6604abaca6925d04102c`, [Review #5610072946](https://github.com/chinanjjohn2012/mac-file-gateway/pull/45#pullrequestreview-5610072946): **Standards PASS / Spec PASS for SOURCE-ONLY**, P3-03 CLOSED; **P3-01/P3-02 OPEN**. PR #45 remains Draft, frozen and unmerged.

## 1. Exactly what this independent DESIGN stage may do

This PR includes only this document, pure synthetic evidence-fixture tests, a branch-guarded design-only three-platform Actions workflow and `MANIFEST.sha256`. It must **not** compile/link candidate C in this D1 workflow, import a dynamic Python Adapter, load/execute a shared library, issue a native signal or change product runtime.

The parent `tools/research/c3_candidate_b_t01_r2_source_only_adapter.py` still produces only immutable review data: `native_dispatches=0` and `native_execution_allowed=False`; `native_call()` unconditionally raises `SOURCE_ONLY_NO_C_LOAD`. It is NOT a Python-to-C Adapter, permission token or 19-field Native result. The test-owned C candidate (`tools/research/c3_candidate_b_t01_no_signal_candidate.c`) and header (`tests/native/c3_b03_t01_no_signal_contract.h`) remain unchanged. The following files must be ABSENT: `tools/research/c3_candidate_b_kill.c`, `tools/research/c3_candidate_b_kill_t01_no_signal_probe.py` and `tools/research/run_c3_candidate_b_kill.py`. No host PID/PGID input or dynamic library lookup is permitted.

The 172 frozen R2b-R1 Native behavior tests plus 19 B03-R1 Native tests remain **191 expected RED**. Linux Full must remain explicitly reported as FAILURE; any additional failure is a separate problem. No `xfail`, `skip`, `|| true`, `continue-on-error` or artificial Native GREEN.

## 2. P3-01 — ordered source-to-final-to-Adapter evidence chain

The **future** independent PRE-LOAD implementation (not part of this D1 PR) must produce *actual independently observed* checkpoints in this precise dependency order. Hashes copied from old Job logs, mutable self-reports, or synthetically complete dictionaries are not authoritative.

| Stage | Mandatory evidence, bound to one build_session_sha | Fail-closed examples |
| --- | --- | --- |
| **S0 REVIEWED_SOURCE_LOCK** | Same-repository fixed reviewed Git Head + Git Tree, complete byte-verified `MANIFEST.sha256`, actual byte digests of reviewed C source (`5a1292787584632fac20c86bbe62e50153e82b0ecb36ad190446bf4b7b714195`), test header (`7c9bd037ecf65da8de91605846c4ac4fc7ceaebbd0ca2fe983ecfef630c9958e`), future Adapter, *all transitive imports*, build script, linker script and every build input. | Dirty checkout, untracked code, omitted input, wrong parent tree, changed import → STOP |
| **S1 PRE_COMPILE_TOOLCHAIN_LOCK** | **Before launching compiler**, resolve/hash the actual compiler executable, driver subprocesses `cc1` and linker `ld`, versions, realpaths, platform arch/target, Darwin Xcode/CLT build and SDK/sysroot, or Linux binutils/sysroot; record complete transitive tool/runtime file closure, sanitized environment, working dir and exactly ordered compile/link argv. | Hash printed only after `cc` ran; mutable symlink/wrapper, `xcrun` or toolchain fallback, stale SDK, `CC`/`LDFLAGS`/`CPATH`/`SDKROOT`/`LIBRARY_PATH`/`LD_*`/`DYLD_*`/`PATH` injection, unknown tool closure → STOP |
| **S2 COMPILED_OBJECT_LOCK** | Only the exact C test source and approved C11 header, compile-time `C3B03_TEST_NO_SIGNAL_STUB=1` in every translation unit, no fallback object; actual object SHA, arch, symbols, relocations and machine-code edges, linked to S0 and S1 identities. | Macro absent/0/2; alternate object, extra symbol, unresolved dependency or OS signal path → STOP |
| **S3 FINAL_LINKED_IMAGE_LOCK** | Fresh final Mach-O `.dylib` / ELF `.so` bytes with descriptor-hashed SHA256, exact object+ordered link flags+linker SDK association, architecture, ABI, all symbols/imports/relocations/constructors/dependencies and executable reachability. Historical PR #44 linked hashes are reference observations, **not new PRE-LOAD authorization**. | Different same-named binary, stale object digest, extra constructor, unreviewed dependency or unknown code edge → STOP |
| **S4 ADAPTER_ABI_IMPORT_GRAPH_LOCK** | Before importing future Adapter, review exact Adapter source SHA and all transitive imports/side effects; independently freeze C `sizeof`/`alignof`/`offsetof` for input/output/deadline structs and enum widths, Python future FFI layout, padding, all fields, step slots, pointer ownership/lifetime and call convention. Exact strong-T export binding and real Python→C call path must be reviewed, not mimicked by Python counters. | Wrong struct offset, FFI default padding, unrecognized import-time loader, alternate exported symbol, fake `c_adapter_dispatches=1` → STOP |
| **S5 PRE_LOAD_PATH_CUSTODY_LOCK** | Private owned 0700 root, safe ancestors, regular immutable final file with `st_nlink==1`, exact owner/dev/inode/size, no symlink/hardlink/outside writer, `O_NOFOLLOW`/`fstat`-bound SHA and canonical loader path/dependency resolution. **Prove future loader opens those exact reviewed bytes without path replacement race.** | Rename, hardlink, writable parent, TOCTOU, library-search fallback, `DYLD_INSERT_LIBRARIES`/`LD_PRELOAD`, fd-to-loader identity unproven → STOP |
| **S6 INDEPENDENT_PRELOAD_DECISION** | S0–S5 observed evidence and immutable chained build_session_sha, independent Standards PASS / Spec PASS on exact Head+Tree, separately granted **first no-signal Native C load** authorization. | Any missing evidence, unknown control-flow target, self-reported approval or mere D1 PASS → **NO_LOAD / BLOCK** |

**None of S0–S6 evidence collection or approval occurs in THIS PR.** Future PRE-COMPILE must record compiler identity *before* spawning it, not after. A compiler-driver file digest alone is not proof about a dynamically chosen subprocess linker, compiler resource directory, SDK, tool-injected flags or code generation. If transitive toolchain identity cannot be pinned on the runner, future load remains BLOCK. No generic system-wrapper exemption.

The evidence record must bind a single build_session_sha and previous-stage digest across S0→S1→S2→S3→S4→S5→S6, review Head/Tree, full Manifest byte digest, compiler/ld/SDK resource SHA, ordered argv/environment, output object SHA, final linked SHA, Adapter+import closure SHA, ABI layout SHA, unique filename/dev/inode and loader-path custody. **A synthetic hash chain is not proof of its claimed observations**. Independent original GitHub Jobs and physical byte identity are necessary.

## 3. Exact future ABI and real Adapter-to-C call chain

The only reviewed inert test candidate C symbol is `int c3b03_t01_no_signal_candidate(const c3b03_t01_mock_input_t *, c3b03_t01_mock_output_t *)`. Its exported symbol must be *exactly* `_c3b03_t01_no_signal_candidate` on Darwin ARM64 and `c3b03_t01_no_signal_candidate` on Linux x86_64, strong defined TEXT, with no aliases or additional exports. No dynamic symbol substring matching.

The proposed, **currently unimplemented** binding chain is:

`fixed 12-key request → reviewed SourceBindingPlan with 67 finite IDs (MODE id=66 denied), exact 8-field original and attempt deadline copies, fresh uint64 nonce and ≤3 steps → independently reviewed field-by-field C ABI serialization and mock fact masks → PRE-LOAD checked fixed loader identity → exact strong TEXT entry pointer → two reviewed typed in/out pointers → checked real C return/result → constrained 19-field Python response`.

The last four edges DO NOT EXIST today. A Python simulation returning `c_adapter_dispatches=1`, matching nonce or counters is *not* C invocation proof. The future Adapter must be separately reviewed for import hooks, transitive imports, eager loads, dynamic module aliases, unchecked library search, fake result synthesis, FFI object lifetime and any data-driven target/path. No path, PID, PGID, command or mutation mode may be promoted to OS authority.

For each platform, verify compiled C ABI metadata using future **compile-only** `_Static_assert` checks for `offsetof`, `sizeof` and `alignof` and the exact C11 layout, including nested deadline struct, enum storage, padding, reserved unused attempt slots and output fields. Compare independently with the proposed FFI definition **before any import/load**. C ABI agreement may not be inferred from Python field names alone. Failure → STOP, not guessed default alignment.

## 4. P3-02 — exact final image and complete control flow

A future linked binary's **actual final bytes**, not earlier R1 screenshots, source greps or synthetic test fixtures, must pass platform-specific exact byte inspection **before first load**:

- **Darwin ARM64:** exact architecture/`MH_DYLIB`, 14 reviewed Mach-O load command IDs/order/sizes/payloads as R1's *historical* no-load baseline (any toolchain variation needs fresh review), only exact `/usr/lib/libSystem.B.dylib` system dependency under a separately reviewed exception, no other `LC_LOAD_DYLIB`, no weak/reexport/upward/RPATH, chained-fixups `imports_count=0`, no `LC_ROUTINES`/`LC_ROUTINES_64`, `__mod_init_func`, linked `__init_offsets` or other initializer/interposer. Exact strong-T export, `nm -u=0` and byte-bound import/reloc evidence.
- **Linux x86_64:** exact ELF64 `ET_DYN`, strong text export and zero undefined; zero `DT_NEEDED`, `DT_INIT`, `INIT_ARRAY`, `PREINIT_ARRAY`, `FINI_ARRAY`, `RPATH`/`RUNPATH`, `PLT/GOT` loader surface, executable interpreter or runtime relocation; architecture and program headers independently checked.
- **Both:** enumerate **every executable section and reachable edge** (direct/indirect call/branch targets, disassembly/CFG, foreign code, compiler runtime). An unknown branch target, unknown opcode, link-time added code, trap/system-call, OS group signal entry, inline assembly or dynamic lookup is STOP. R1's old deny-string instruction scan **is not a full CFG**. Import/relocation/initializer/constructor allowlists are finite and versioned, not wildcard. Any final linked byte drift → new evidence and independent fixed-SHA review.

The R1 Mach-O `LC_ROUTINES_64` mutated linked image and constructor `__init_offsets` negatives, wrong/weak/extra export, and Linux ELF invalid imports are necessary tests, **not a substitute for actual PRE-LOAD binding**. Do not claim R1's historically observed linked SHA is what the future loader would open. Unknown can never default to allow.

## 5. Custody: the crucial check/use gap cannot be waived

A dynamic library may execute initialization **as it loads**, before a post-load hash can run. Checking a pathname, read-only `0400` bit, `st_nlink==1`, private root or holding a source descriptor alone does not bind the future `ctypes.CDLL(path)` to the same inode: an untrusted writer or mutable ancestor could replace the path between review and load. A future design must independently demonstrate an OS-specific atomic check/use binding or uncontested custody across loader lookup; otherwise **NO_LOAD remains mandatory**.

No assumed universal solution based on Linux `/proc/self/fd` may be applied to macOS dyld by analogy. The exact loader's lookup of declared dependencies (including Darwin's system library) requires separately reviewed identities and environment. Do not rely on a post-load SHA to compensate for missing pre-load initializer/path controls.

**Pre-load sequence:** S0 source lock → S1 precompile toolchain lock → S2 actual object → S3 actual final linked bytes + entire reachable CFG → S4 Adapter import/ABI/source lock → S5 path/inode custody → S6 independent review **and explicit separate Native no-signal permission** → *future* first C load. A D1 design PASS can approve **only the design**, not S6 or any function invocation.

## 6. Design-only test fixtures and exact CI scope

Pure Python offline tests may validate synthetic evidence **schema** and stage linkage, but every structurally plausible fake must return `REVIEW_REQUIRED_NO_LOAD`, NEVER `ALLOW`/`AUTHORIZED`/`NATIVE_PASS`. Changed keys, fake self-approved flag, malformed digest, reversed S1/S2 order, tool hash collected after compilation, changed session/parent digest, missing ABI or loader-path proof, unknown final CFG or dependency must yield `REJECT`. A linter's acceptance is **not proof that the original compiler, binary or loader was ever observed**.

No D1 workflow compiler, linker, executable C, `ctypes.CDLL`, `dlopen`, Native Helper/Probe/Runner, host PID/PGID or group signal. 3-platform same-repository guarded Actions uses precise Head checkout, complete Manifest SHA, read-only `contents: read`, `persist-credentials: false`; pure source-only and new design pytest only. No `workflow_dispatch`, `continue-on-error` or disguised `|| true`. Legacy research workflows skipped by branch guards are not proof of R1 or new native behavior on this Head.

Linux Full still reports **191 expected RED** (19 B03-R1 + 172 R2b-R1 missing Native Helper/Adapter), overall **FAILURE**, not full PASS. Any other failure is unexpected and must be investigated.

## 7. Review gate and permanent blocked permissions

Independent reviewer must check fixed Base/Head/Git Tree, PR diff, original three-platform job logs, synthetic falsifications, source-only/no C import boundary, and publish Standards PASS/FAIL, Spec PASS/FAIL with P0/P1/P2/P3 and stage-specific permission conclusion. The D1 DESIGN may close only with that independent design verdict. **P3-01 and P3-02 remain OPEN** for future actual precompile/linked/Adapter/loader implementation evidence, even after design PASS. P3-03 is already independently CLOSED on PR #45.

Next permitted work after an independent D1 PASS is **another separate no-load static provenance implementation/review**, not R2b-R2b-R3 execution. Until the actual pre-load gate has a separate independently approved implementation and an explicit first no-signal C load grant, **R2b-R2b-R3 is BLOCK**.

**Hard BLOCK:** `group_kill_authorized=false`, `reuse_proven=false`, `g2_qualified=false`, T04/T08b/T10 `NOT_RUN/BLOCK`; Native Owner/Controller/Worker; R2b-R3/T01-R3; real group TERM/SIGKILL; G2/G3/G4/G5; Gateway production ExecSupervisor/REST/MCP Multi Exec; merge and deployment. This D1 PR authorizes none of those.
