# C3 B03-T01 / R2b-R2b-R2 — Adapter SOURCE-ONLY validation and PRE-LOAD evidence boundary

**Status:** AUTHOR SOURCE-ONLY IMPLEMENTATION / INDEPENDENT STANDARDS & SPEC REVIEW PENDING.

**Immutable parent:** [PR #44](https://github.com/chinanjjohn2012/mac-file-gateway/pull/44) exact Head `a39124235c89a92794eb973a0c718e766eb4f64d` / Git Tree `db8a87d883711bd0be11eae3d5b4de3b3000b098`, [independent Review #5609405609](https://github.com/chinanjjohn2012/mac-file-gateway/pull/44#pullrequestreview-5609405609) **Standards PASS / Spec PASS, P2-01 and P2-02 CLOSED** for **compile/link/inspect-only, no dynamic load**. Parent PR stays immutable Draft/unmerged.

## 1. Precisely scoped source stage (NOT a native Adapter or load gate)

This incremental R2 source-only candidate adds `tools/research/c3_candidate_b_t01_r2_source_only_adapter.py`, pure-Python input/binding tests, a branch-guarded three-platform workflow and updated `MANIFEST.sha256`. It also repairs the inherited **P3-03** Mach-O `nsects` unbounded iteration **only on this NEW child branch**, together with a fast bounded malformed-header test. The parent PR #44 reviewed Head remains unchanged.

**NO_LOAD=true · C_EXECUTED=false · NATIVE_DISPATCHES=0 · group_kill_authorized=false**. This source file deliberately has NO Python→C dynamic loader/call path. It may be imported as plain Python but cannot import, dynamically load, invoke or dispatch to C; `native_call` fails unconditionally with `SOURCE_ONLY_NO_C_LOAD`. It does not create a native helper or native probe, and does not reproduce the frozen 19-field C response.

**This stage does NOT close P3-01 or P3-02.** Its Python binding plan is only a reviewable *candidate*, NOT evidence of an actual Adapter→linked C call chain, checked final loader-path custody, approved linked SHA, real C behavior or native lawful wait. The next independent PRE-LOAD stage must actually approve verified ABI/struct layout, compiled source/toolchain/SDK, final bytes, loader call path and TOCTOU controls **before any C load**. The 172 R2b-R1 behavior cases and 19 B03-R1 Native cases remain genuine RED, never modified or suppressed.

The future standard test-probe path `tools/research/c3_candidate_b_kill_t01_no_signal_probe.py`, Native Helper `tools/research/c3_candidate_b_kill.c` and Runner `tools/research/run_c3_candidate_b_kill.py` remain ABSENT. The new module has a distinct `source_only_adapter.py` name and cannot make any of the frozen 172 behavior cases spuriously GREEN.

## 2. Immutable request → C ABI DATA mapping (not an invocation)

[PR #41](https://github.com/chinanjjohn2012/mac-file-gateway/pull/41) froze the exact 12-field Python request, 67 case catalog and eight-field C11 deadline struct in `tests/native/c3_b03_t01_no_signal_contract.h`. This source candidate independently copies the 67 fixed phase/fault IDs and validates them against the frozen contract **in tests**, never reading a dynamic ID from caller input. It rejects scenario 66 (`MODE/different-mode`), all other 10 non-T01 modes, unknown phases/faults and all host numeric PID/PGID targets.

`SourceOnlyAdapter.plan` strictly requires exactly 12 keys: `abi_version=1` (non-Boolean int), `mode="escalate-positive"`, the one fixed synthetic string target, `mock_only=True` (identity check), a fresh nonzero uint64 `nonce`, one of the 66 reviewed test scenarios, two exactly eight-key independently consistent signed-int64 deadline snapshots, nonnegative signed-int64 time samples, and a frozen tuple of 1–3 synthetic TERM/KILL steps for the selected scenario. Bad schemas, booleans, extra/missing keys, strings posing as ints, overflow, wrong or surplus steps, mismatched deadline math are BLOCK. **Any valid nonce is consumed before subsequent validation, even for malformed requests**; repair or replay with the same nonce on the same Adapter instance is BLOCK.

A valid request returns a frozen data-only `SourceBindingPlan` with the scenario ID, phase enum, per-step test enum and **by-value** policy tuples in C ABI field order. It always records `native_dispatches=0` and `native_execution_allowed=False`. Changed yet internally consistent attempt policies may yield a *type-valid* plan: **whether this rebase must fail the Native C Gate remains for actual future C behavior tests**; the source-only checker must not pretend a Python result was a C verdict.

**Not yet implemented or authorized:** mapping real mock fact masks and native output fields, Python `ctypes.Structure` layout, exact C symbol binding and actual call, pointer/lifetime ownership, Native C mock transport; no POSIX process groups, no `kill`, `killpg`, `waitpid`, `dlopen`, `ctypes.CDLL` or final-library execution.

## 3. P3-03 correction: bounded RAW Mach-O section counts

Independent [PR #44 Review #5609405609](https://github.com/chinanjjohn2012/mac-file-gateway/pull/44#pullrequestreview-5609405609) added nonblocking **P3-03**: the prior byte parser iterated `range(nsects)` before proving `nsects` fit the reviewed `LC_SEGMENT_64`. In this child branch it must check `nsects == 1` for the frozen `__TEXT,__text` section, or `nsects == 0` for `__LINKEDIT`; then check `cmdsize == 72 + 80 * expected_count` and data bounds, and **only then** iterate. Any `0xffffffff`, changed count or malformed bytes must BLOCK in bounded time before allocating a tuple, even on the synthetic test file. The actual constructor and `LC_ROUTINES_64`/unknown-command rejection tests from R1 remain and are rerun.

This is an author repair with targeted regression, **P3-03 cannot be independently marked CLOSED until the new fixed Head receives its own review**. The new source-only module does NOT reuse the parser as a runtime loader admission path.

## 4. Frozen bytes, original CI and missing PRE-LOAD guarantees

The existing reviewed C source `tools/research/c3_candidate_b_t01_no_signal_candidate.c` SHA256 is `5a1292787584632fac20c86bbe62e50153e82b0ecb36ad190446bf4b7b714195`. Header `tests/native/c3_b03_t01_no_signal_contract.h` SHA256 is `7c9bd037ecf65da8de91605846c4ac4fc7ceaebbd0ca2fe983ecfef630c9958e`. Historical PR #44 tested (not packaged/installed) Darwin arm64 linked SHA256 `87d87fd11bc2a38f066e41b1c51d8282eafe2d174f35a87354fdd728a01c5c9a` and Linux x86_64 linked SHA256 `9bbf2acd784cebb363fb9fb1bc6a2b71781b84d76c38262e44cc60bbe56d8918`. These are **historical source/object/linked-image evidence, not valid self-reported tickets to load a newly produced binary**.

In particular **P3-01 remains OPEN**: the prior `cc`/linker executable hash was printed after compilation, not locked at PRE-COMPILE; SDK/sysroot and ordered flags need exact independent commitment; source SHA must be tied to actual target bytes, load commands, relocations, indirect call graph, custom loader path and no-TOCTOU custody. The future independent gate must freeze a **real final linked binary SHA before loading** and prove a real Python→reviewed C call binding; a forged `c_adapter_dispatches=1` field, matching scenario ID, familiar basename or echoed nonce proves nothing. **P3-02 remains OPEN** for final full-CFG/relocation/initializer/architecture-specific preload binding on the actual binary.

The present source-only module neither loads nor constructs a final C library, even if its tests rerun the parent **compile/link/inspect-only** suite. It never supplies a runtime authorization token. PR/push Actions use a fixed head-branch, `permissions: contents: read`, exact checkout, `persist-credentials: false`, full Manifest SHA256, original C+header SHA and absence of three Native Helper/Probe/Runner paths. No `workflow_dispatch`, `continue-on-error`, `|| true` or hidden `xfail`.

## 5. Independent Standards / Spec review request

1. Verify exactly all 67 frozen scenario IDs, exact 12 Python input types/schema, one-use nonce across malformed/replay, 8-key signed-int64 policy, no privileged caller-target path and bounded 1–3 synthetic attempts. Check that `SourceBindingPlan` is never a fake native dispatch/permission token.
2. Verify **P3-03** no longer iterates over raw `nsects` before checking count/size/bounds. Target giant-count malformed Mach-O header on macOS and Linux; ensure genuine R1 source/object/linked safety tests stay GREEN without loading C.
3. Verify no C native Adapter/probe/helper/runner was added or imported, and no false positive C ABI behavior/19-field response. AST/code inspection and actual 3-platform original CI must independently establish no dynamic load.
4. Verify **P3-01/P3-02 remain OPEN**, with compiler PRE-COMPILE custody, ABI struct layout, true Adapter→C call path, exact final-image SHA, relocations/initializers/control flow/loader path and TOCTOU checks reserved for another independent pre-load permission decision.
5. Confirm original Linux Full CI still has only 19 + 172 expected RED Native contract tests, **no unexpected failures**. No PR is merged/deployed and no true group signal sent.

**Hard BLOCK:** `group_kill_authorized=false` · `reuse_proven=false` · `g2_qualified=false` · T04/T08b/T10 `NOT_RUN/BLOCK` · R2b-R2b-R3 first no-signal Native C run, R2b-R3/T01-R3 real signal studies, G2/G3/G4/G5 and Gateway ExecSupervisor/REST/MCP Multi-Exec all BLOCK. An independent PASS for this **source-only substage** cannot authorize a first dynamic C load, even with historical linked-image SHA evidence.
