# C3 B03-T01 R2b-R2b-R2-S0 — Actual source + C11 ABI compile-only evidence (NO LOAD)

**Status: AUTHOR PARTIAL STATIC IMPLEMENTATION; INDEPENDENT CODE REVIEW PENDING.**
**SOURCE_ONLY_NO_LOAD=true · C_EXECUTED=false · group_kill_authorized=false · P3-01/P3-02 remain OPEN.**

**Frozen authority:** [PR #46](https://github.com/chinanjjohn2012/mac-file-gateway/pull/46) Head `37bd517932b6b99952fa19e091b5b8d94d45939a` / Tree `ed661fe5ea2297b89c9ba96bd312e01a5a4f8778`, [independent Review #5610375979](https://github.com/chinanjjohn2012/mac-file-gateway/pull/46#pullrequestreview-5610375979): Standards PASS / Spec PASS for **D1 DESIGN ONLY**, P0/P1/P2=0, P3-01/P3-02 OPEN and P3-03 already CLOSED. The parent PR Head remains frozen. This child cannot inherit permission to run Native C.

## 1. Narrow increment: S0 partial + S1 compiler-entry snapshot + C11 ABI compile-only

Four new files and a complete SHA256 Manifest entry update:

- `tools/research/c3_candidate_b_t01_s0_abi_proof.py`: stdlib-only **actual source and compiler-entry evidence**. Verifies the full on-disk Manifest against the real checkout, Git Head/Tree object ID shapes, frozen reviewed C/header bytes, new ABI-assert translation-unit bytes and existing SOURCE-ONLY Adapter bytes. Before invoking `cc -c`, resolves the compiler entry executable, SHA256-hashes its actual bytes from a nofollow regular-file FD, records monotonic ordering and exactly ordered compiler argv, compiles only the C11 ABI assert TU to a fresh private `0700` temp .o, hashes its bytes from a nofollow FD, rehashes the compiler entry afterward and deletes the .o/temp files. Never compiles/links the executable candidate's functions, and never builds a shared library or dynamically loads/executes any C.
- `tests/native/c3_b03_t01_abi_compile_only.c`: test-owned fixed C11 `_Static_assert` checks for all three types' `sizeof`, `_Alignof`, and `offsetof` **plus field widths**; ABI v1, enum widths/values, max 3 attempts, max 67 scenario IDs, 64-byte deadline, 208-byte input and 48-byte output on the two reviewed 64-bit architectures. It includes the frozen test-only C header, not a native helper or signal function. No C function is compiled.
- `tests/test_c3_candidate_b_t01_s0_abi_proof.py`: positive actual compiler/.o evidence plus independently compiled **invalid layout mutants** (wrong nonce width, missing attempt slot, changed deadline width, output type, enum/macro drift), all of which must fail with explicit `ABI_` static-assert evidence. Every successful static compilation remains `REVIEW_REQUIRED_NO_LOAD`; negative is `REJECT`.
- A dedicated read-only macOS ARM64 Python 3.13/3.14 + Linux x86_64 Python 3.13 Actions workflow; source/ABI proof CI only. No first C load, no Native Helper/Probe/Runner; no production code.

**Stage truth:** This child proves selected **S0 actual on-runner source bytes** and **S4 partial compile-only C ABI layout**. It does **not** prove S0 complete transitive input closure, S1 complete toolchain/SDK, S2 candidate C object, S3 final image, S4 future Python FFI layout/import-call graph, S5 loader path identity or S6 independent PRE-LOAD approval.

## 2. Exact 64-bit ABI contract, never inferred by a Python Native call

The frozen `tests/native/c3_b03_t01_no_signal_contract.h` SHA256 is `7c9bd037ecf65da8de91605846c4ac4fc7ceaebbd0ca2fe983ecfef630c9958e`. Actual `cc -std=c11 -c` must prove these sizes/alignments on **both** macOS ARM64 and Linux x86_64:

| C11 struct | sizeof | _Alignof | Important byte offsets |
| --- | --- | --- | --- |
| `c3b03_t01_deadline_t` | **64** | **8** | eight int64 fields at 0,8,16,24,32,40,48,56 |
| `c3b03_t01_mock_input_t` | **208** | **8** | abi 0, mode 4, phase 8, nonce 16, fault_id 24, len 28, steps 32 (12 bytes), TERM/KILL masks 48/56, times 64/72, policies 80/144 |
| `c3b03_t01_mock_output_t` | **48** | **8** | abi 0, decision 4, nonce 8, fake calls 16/20, real_group_signal_syscalls 24, attempts 28/32, closed 36, after-close 40 |

Every field also has a `CHECK_FIELD_SIZE` assertion, preventing same-offset but incorrect-width regressions. The test compiles altered headers in isolated directories and **requires C11 static-assert failures**, never running those mutants. This is not yet a checked Python `ctypes.Structure` comparison: no ctypes, cffi, Python FFI or dynamic shared-library interface is created.

## 3. PRE-COMPILE fingerprint is real but S1 is explicitly INCOMPLETE

**Pinned identifiers and field names:** the observed Git Head and **Git Tree** are 40-hex object IDs, distinct from 64-hex byte SHA256. The complete verified `MANIFEST.sha256` covers the current child source, compiler/proof code and ABI asserts. The C ABI fields **`scenario_nonce`** (uint64) and **`attempt_sequence`** (3 C enums) are checked by value/offset; no host PID/PGID enters either. The entry SHA must be collected **before compiler** execution, never justified by after-the-fact hashes. With missing S1 tool closure, **first C load remains BLOCK**.

The proof uses a tightly restricted executable search path and records the **real compiler-entry binary SHA** from an FD **before** `subprocess.run(cc -c)`. It records exact ordered argv digest, SHA of the resulting object and a second compiler-entry byte SHA. Any missing input, wrong Manifest/C fingerprint, changed entry hash, failed compile, non-regular object or altered ABI fails closed. **Manifest source paths are checked for file and directory symlink components before realpath resolution**, and unsafe `..`/empty components are rejected; offline negatives cover internal symlinks as well as path traversal. This is S0 path hygiene only, **not an atomic check/use guarantee** against a concurrent writer or any future loader.

**Critical limitation:** On Darwin `/usr/bin/cc` may be a compiler-driver shim, and on Linux `cc` may resolve through symlinks. A hash of that resolved entry alone **cannot** pin which secondary compiler program, `ld`/assembler, SDK/sysroot, transitive resource file or environment wrapper was used. Nor is hashing a pathname a general atomic executable-fd identity guarantee. No linker is invoked for this ABI-only TU, but S1's nested tool and SDK closure are still unknown. The proof therefore **always** reports:

- `compiler_sdk_linker_closure_complete=false`
- `real_preload_chain_proven=false` and `ffi_binding_proven=false`
- `first_c_load_authorized=false`, `native_loader_invoked=false`, `candidate_c_executed=false`, `group_signal_authorized=false`
- `native_dispatches=0`, best non-reject decision `REVIEW_REQUIRED_NO_LOAD`.

An altered compiler entry, nested tool-selection drift, malicious compile wrapper or mismatch between claimed tool hash and actual executed binary still requires future stricter tests and independent S1 proof. This limited probe **must not be reused as S1 admission code**. Compiler output and output object SHA are real ephemeral CI evidence, not the candidate C function's compiled object or future linked-library SHA.

## 4. Immutable Native RED / review and hard STOP conditions

The 172 frozen R2b-R1 Native Helper/Adapter contract tests and 19 B03-R1 Native Owner/Runner contract tests remain **191 expected RED**. The Linux full workflow is expected **FAILURE** until independently approved Native implementation; no xfail, skip masking, false overall GREEN or fake C counters. The existing SourceOnlyAdapter still rejects `native_call()` with `SOURCE_ONLY_NO_C_LOAD`, and no `tools/research/c3_candidate_b_kill.c`, `tools/research/c3_candidate_b_kill_t01_no_signal_probe.py` or `tools/research/run_c3_candidate_b_kill.py` may appear.

**P3-01/P3-02 remain OPEN.** The D1-approved S0–S6 prerequisites continue to demand a **different, independently reviewed** true PRE-COMPILE driver/secondary tool/SDK lock, candidate source→object→final-linked byte SHA, full disassembly/CFG/import/relocation/constructor and dependency validation, ABI match to a reviewed Python Adapter with real transitive-import analysis, and proof that a loader will open exactly the byte-attested inode/path without TOCTOU. **No first C load is authorized** unless all required checks, an independent fixed-SHA PASS and a separate first-load permission are present. Neither holding an ABI .o nor today's historical R1 shared-library hashes establish those facts.

The branch-limited Actions workflow must check exact Git Head and complete Manifest, use read-only `contents: read`, `persist-credentials: false`, the explicit test-only stub macro, no unrelated build flags or Native helper, and run only ABI compile-only regression and source-only pure Python tests. No `workflow_dispatch`, `continue-on-error`, `|| true`, `cc -shared`, `cc -dynamiclib`, `dlopen`, C function invocation, process group signal, merge or deployment.

**Stage review request:** Independently read the real test-only C source and frozen header, ABI assertions/negative mutants, real C compiler and .o SHA from original three-platform Jobs, current Head/Tree/Manifest, and verify that the reported provenance is **partial** and no native load/call can occur. Standards/Spec PASS on this S0/ABI partial stage cannot close P3-01/P3-02 or authorize next Native C operation.

**Persistent BLOCK:** `group_kill_authorized=false`, `reuse_proven=false`, `g2_qualified=false`; T04/T08b/T10 `NOT_RUN/BLOCK`; R2b-R2b-R3 first C load, Native Owner/Controller/Worker, real group TERM/SIGKILL, R2b-R3/T01-R3, G2/G3/G4/G5, production Gateway ExecSupervisor/REST/MCP Multi Exec; PR remains Draft/unmerged. Never execute native C in this stage.
