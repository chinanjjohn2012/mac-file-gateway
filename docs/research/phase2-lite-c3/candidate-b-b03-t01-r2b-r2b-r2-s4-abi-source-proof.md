# C3 B03-T01 R2b-R2b-R2-S4 — Static Python/C ABI and Source-only Import Graph (NO LOAD / NO C EXEC)

**Status:** AUTHOR S4 ABI/AST PARTIAL EVIDENCE; independent Standards / Spec CODE review PENDING. NO LOAD / NO C EXEC means no Candidate C binary is loaded or executed. The only C compiler action is on the previously frozen C11 _Static_assert-only ABI translation unit, not the candidate C; no candidate shared library is linked or opened.

**Parent:** [PR #49 independent Review #5611861773](https://github.com/chinanjjohn2012/mac-file-gateway/pull/49#pullrequestreview-5611861773), fixed Head 9c0bb5b0e83a3d5e57bacd2d55eaff174cb9c8fc, Tree ad13b6a5a362874f50dc7ad70778b55c48f7f5c8, Standards PASS / Spec PASS strictly for S3 same-session linked-image STATIC OBSERVATION PARTIAL / NO LOAD. Parent Draft/unmerged. Prior #48 S2 and #47 S0 remain independently reviewed partial stages. P3-03 CLOSED and P3-01/P3-02 OPEN.

## Exact scope and actual evidence

The S4 research-only implementation:

1. Revalidates current Head/Tree and complete MANIFEST.sha256 using frozen S0 checks, including frozen inert C source/header SHA, existing reviewed ABI assertion translation unit, and reviewed Source-only Adapter. The C source and header are unchanged.
2. Statically parses existing SourceOnlyAdapter Python source using ast.parse; it does not import or instantiate that Adapter. Direct import roots must remain exactly __future__ and dataclasses, SourceBindingPlan field order and eight-field policy order must match the static ABI model, twelve-key request schema is frozen, and native_call must unconditionally raise SOURCE_ONLY_NO_C_LOAD. An unreviewed import, dynamic import, changed authority flag, unexpected field order or omitted denial is rejected. This is source-level direct import graph only, NOT complete transitive stdlib import closure.
3. Constructs Python ctypes.Structure DATA-ONLY layout descriptions for the reviewed 64-byte deadline, 208-byte mock input and 48-byte mock output. ctypes only computes sizeof, alignment and field offsets; no CDLL, PyDLL, dlopen, symbol lookup, function binding or candidate native invocation occurs. The frozen C header is parsed for exact three struct field names, data types and array length; Python declarations must match. Importing the Python ctypes support module is not Candidate C library loading.
4. Reuses frozen tests/native/c3_b03_t01_abi_compile_only.c with actual C11 cc -c: every frozen C11 _Static_assert for C size, alignment, field offset and field size must compile. Only a temporary ABI assertion object is hashed and discarded. Independently parses **all 77 existing C assertions** and compares their expected values to Python ctypes measurements: 9 size checks, 6 alignment checks, 31 offsets and 31 field sizes. macOS ARM64 and Linux x86_64 must agree on this reviewed test ABI. Enum storage WIDTH of four bytes is checked; enum signedness, future FFI pointer lifetime and call convention are not.
5. Outputs exact Head/Tree, real source/header/ABI/Adapter SHA256, compiler-entry SHA before/after, real ABI assertion object SHA, Python static layout, Adapter AST roots and hashes. No historical S3 image hash is substituted for an actual current S4 observation.

Negative fixture mutations include changed Python import/authorization/field order/no-load denial, changed C field type/array/ordering, and mismatched or missing C layout assertions. These mutations are in-memory header, C assertion or Python source tests, not hostile linked binaries or future loader tests. Original GitHub Actions Job logs, not author self-report, are needed for review.

**Best result is always REVIEW_REQUIRED_NO_LOAD.** native_dispatches=0, first_c_load_authorized=false, native_candidate_library_loaded=false, candidate_c_executed=false and actual_python_to_c_call_binding_proven=false. No Native Helper/Owner/Controller/Worker/Runner, real PID/PGID, process-group TERM/SIGKILL, or Gateway product code. No existing Native RED contract change, skip, xfail or fake GREEN.

## Open obligations and hard gates

- **P3-01 OPEN:** compiler-entry digest does not prove actual spawned frontend, assembler, linker, SDK/sysroot recursive closure; complete S1/S3 atomic source→final binding and S5 loader check/use same-inode custody absent.
- **P3-02 OPEN:** final linked binary complete CFG, imports, relocations, initializers and unknown indirect targets not proved; the future Python FFI Adapter, transitive import-time side effects and real call chain are absent. This source-only AST and ctypes DATA-ONLY layout evidence does not close the full S4 import/ABI gate.
- **P3-03 CLOSED:** remains closed. S5/S6 NOT_RUN/BLOCK; first Native C load, function call and permission BLOCK.
- **191 expected RED:** Linux Full intentionally FAILURE from 19 B03 Native Helper/Runner and 172 R2b Native C Helper/Adapter tests. Unexpected new failures must be zero.

**Hard BLOCK:** group_kill_authorized=false, reuse_proven=false, g2_qualified=false; T04/T08b/T10 NOT_RUN/BLOCK; R2b-R2b-R3 first C load, R2b-R3/T01-R3, G2/G3/G4/G5, real group TERM/SIGKILL, Native Owner/Controller/Worker, product Gateway ExecSupervisor / REST / MCP Multi-Workspace Exec, merge and deploy. All PRs Draft/unmerged.

Independent reviewer must inspect source/tests/workflow/Manifest, the fixed Head/Tree, historical Reviews and every original current-Head CI Job. A PASS may close only S4 SOURCE-ONLY STATIC ABI/AST PARTIAL, not full S4/S5/S6 or any first-load authorization.
