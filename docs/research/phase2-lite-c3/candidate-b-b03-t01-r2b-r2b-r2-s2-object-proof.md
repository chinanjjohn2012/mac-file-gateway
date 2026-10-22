# C3 B03-T01 R2b-R2b-R2-S2 — Actual Candidate C Object Provenance (NO LOAD / NO C EXEC)

**Status:** AUTHOR PARTIAL S2 EVIDENCE, independent Standards / Spec CODE review PENDING.
**SOURCE_ONLY_NO_LOAD=true · C_EXECUTED=false · NATIVE_DISPATCHES=0 · group_kill_authorized=false.**

**Frozen reviewed Base:** [PR #47](https://github.com/chinanjjohn2012/mac-file-gateway/pull/47), Head `045542b8825279dd416ca2e9a7325b4529f952ef` / Git Tree `19fb259dacf4ff592f0063077ba833c55aa10bba`; [independent Review #5610700612](https://github.com/chinanjjohn2012/mac-file-gateway/pull/47#pullrequestreview-5610700612) = **Standards PASS / Spec PASS only for S0/ABI compile-only PARTIAL**; P3-01/P3-02 remain OPEN and P3-03 was already CLOSED. The parent PR is frozen, Draft and unmerged.

## 1. Stage boundary: S2 object observations, not final linked authority

This child creates a **separate S2 candidate-object evidence substage**, using the immutable, previously reviewed synthetic C source `tools/research/c3_candidate_b_t01_no_signal_candidate.c` SHA256 `5a1292787584632fac20c86bbe62e50153e82b0ecb36ad190446bf4b7b714195` and frozen header SHA256 `7c9bd037ecf65da8de91605846c4ac4fc7ceaebbd0ca2fe983ecfef630c9958e`. The source contains an **inert TEST MODEL** (no POSIX signal/Owner/Controller/Worker/syscalls). It is never called by this stage. These are the same C bytes reviewed in upstream source/object/link-inspect-only studies.

Exactly 5 research-only file changes: new stdlib-only object proof module, tests including negative compiler macro and in-memory object metadata mutants, S2 scope document, strictly branch-limited three-platform Actions, and `MANIFEST.sha256`. The existing S0/ABI proof, C model, test header, SourceOnlyAdapter, existing 172 Native RED contracts, product gateway code and all reviewed upstream PR Heads are unchanged.

Allowed process actions only: `git rev-parse`, fixed compiler `cc -c` of the **single approved inert candidate C translation unit**, and fixed read-only `nm`, `file`, `otool -tv` or `objdump -dr` **on its ephemeral .o bytes**. A private 0700 directory holds the object and is deleted upon test completion. These object inspections do NOT run any candidate C instruction, do not link a shared image, do not invoke dyld/ld.so, and never send TERM/SIGKILL. Negative macro tests intentionally run `cc -c` but must produce **no .o**, only fail-closed diagnostics.

No `ctypes.CDLL`, `dlopen`, C/native Adapter, Python FFI, dynamic linker, executable Runner, Native Helper or kernel signal transport. All full Native calls remain unavailable; no fake 19-key Native outputs.

## 2. Actual evidence chain with exact bounds

**S0 reviewed input lock:** Call the separately independently reviewed `s0.checked_manifest()` and `s0.current_revision()` on the same child checkout, verify full sorted  SHA256 Manifest and current Git Head/Tree. Reject source/header SHA drift before compilation; verify SHA remains equal after compilation. C source text must have precisely the reviewed two includes — `"c3_b03_t01_no_signal_contract.h"` and `<stdint.h>` — with no new include; the source and header are fixed to the upstream frozen byte hashes. This is **non-atomic source-path hygiene** (symlinks denied by parent), not proof against concurrent-write races or loader check/use identity.

**S1 PARTIAL compiler entry:** Restricted PATH, exact resolved compiler-entry FD SHA256 before the `cc -c` call, fixed ordered C11 flags and environment, with post-compile compiler-entry byte SHA validation. This proves only pre-call **entry** observation, not identity of the exact executed driver, compiler frontend, assembler, Xcode/CLT, SDK/sysroot and transitive resource closure. The compiler may spawn unexamined tools; a driver sha alone is not a trusted complete PRE-COMPILE toolchain. `complete_toolchain_sdk_closure_proven=false` is hardcoded; any future real gate without a fully enumerated independently verified S1 closure remains STOP. Observed timestamps are diagnostic ordering indicators, **not OS fexecve proof**.

**S2 actual temporary object:** With exactly `C3B03_TEST_NO_SIGNAL_STUB=1`, `-std=c11 -O0 -fPIC -fno-stack-protector -fno-builtin -fno-asynchronous-unwind-tables -fno-unwind-tables -c` and fixed warnings, compile only to a private ephemeral `candidate-inert.o`. Observe object SHA using a nofollow regular FD and `fstat`, with owner/nlink checks. On **macOS ARM64**, `file` must identify Mach-O 64-bit arm64 object, `nm -u` must be empty, and `nm -g` must contain exactly one strong T `_c3b03_t01_no_signal_candidate` export. On **Linux x86_64**, `file` must identify ELF64 relocatable x86-64, `nm -u` empty, and `nm -g` exactly one strong T `c3b03_t01_no_signal_candidate`. No extra/weak/alias/undefined symbol may pass. The disassembler's actual text is SHA256-hashed, included verbatim in original CI and screened for obvious `syscall` / `sysenter` / `svc #` / trap markers.

**Important P3-02 scope limit:** The source instruction deny-string/object-symbol checks and raw disassembly hash are **NOT complete CFG** or full relocation/branch target proof. They can only produce `OBJECT_INSPECTION_PARTIAL_NO_LOAD`; unknown indirect control-flow targets, binary instrumentation/injection, final linked machine code and new runtime dependencies still require a separate strict platform-specific allowlist and independent review of the *final* bytes. `complete_object_cfg_proven=false`, `final_linked_image_proven=false` and `preload_custody_proven=false` always. The original parent R1 linked-image hashes are historical and cannot be substituted for this object or a future loader-path result.

**S3–S6 NOT_RUN/BLOCK:** No final shared-image linking, imports/relocations/constructors at final address, OS loader path/TOCTOU, Python Adapter import/ABI pointer layout, final strong-T address binding, first Native C call, real legally reaped subprocess/wait evidence, or independently approved Native load. Every positive case returns **`REVIEW_REQUIRED_NO_LOAD`** and `first_c_load_authorized=false`; no action to turn these fields true exists.

## 3. Falsifiable negative evidence

Three actually executed C11 **compile-only** macro negatives `missing`, `zero`, `two` must fail with the original frozen C/header `test C candidate requires exact no-signal stub 1` diagnostic and create no object. This prevents an innocently omitted or mistyped no-signal macro from entering the object-stage provenance graph.

Additional in-memory (never executed/linked) metadata mutants must be rejected before approval: wrong arch, unknown platform, wrong symbol name, extra/weak symbol, missing strong-T, undefined import (`killpg`), injected `syscall`/`svc #`/trap instructions, empty disassembly and unexpected source includes. These synthetic text mutations test the **narrow object metadata gate**, and are clearly distinguished from real alternate linked Mach-O/ELF bytes, a true CFG or future S5 loader-custody negatives.

Document/CI enforce: source+header SHA and complete Manifest, exact fixed Head, no helpers/probe/runner, \`SOURCE_ONLY_NO_LOAD\` and hard group authorization false; branch guards, read-only contents, disabled credentials and no workflow_dispatch/continue-on-error/`|| true`. The dedicated job may run previous S0/ABI compile-only tests and the frozen R2a object-only test, but must **never run first Native C**, invoke a host group signal, generate a loadable library, or accidentally promote the 172 contracts to green.

## 4. Actual status remains RED for Native behavior

There are **191 expected RED** Native contract failures in the Linux Full workflow until later independent implementation: B03-R1 missing Native Helper/Runner **19** and R2b-R1 missing Native C Helper/Adapter **172**. The Full Job must remain described as **FAILURE**, not full GREEN. All unrelated failure classes (if any) are unexpected and must be repaired.

The positive object test is allowed to prove an **actual** frozen C translation unit compiles into a single platform-scoped .o, but this is **not** a linkable C function execution or complete end-to-end provenance gate. **P3-01/P3-02 remain OPEN**, because compiler/SDK closure, an independently reviewed S1 source→compiler backend chain, final linked C machine code CFG, S4 Python FFI, S5 TOCTOU-safe actual loader binding and S6 first-load permission remain missing.

## 5. Independent review and hard safety gates

Independently read the new code and original GitHub CI Job logs (not just copied report hashes), and check fixed Base/Head/Git Tree, actual object SHA and disassembly on three platforms, observed compiler-source timestamps, exact global/undefined symbols, and **real macro** compile negatives. Confirm no native load, startup initializer, dynamic Python FFI, native C call or real group signal. An independent Standards PASS / Spec PASS can only CLOSE this **S2 OBJECT PARTIAL / NO C EXEC** stage, not P3-01/P3-02 or any load/execute right.

**Hard BLOCK:** `group_kill_authorized=false`, `reuse_proven=false`, `g2_qualified=false`; T04/T08b/T10 `NOT_RUN/BLOCK`; R2b-R2b-R3 first native C load, Native Owner/Controller/Worker, real group TERM/SIGKILL, R2b-R3/T01-R3, G2/G3/G4/G5 and production Gateway ExecSupervisor/REST/MCP Multi Exec; merge and deployment BLOCK. This stage does not grant them.
