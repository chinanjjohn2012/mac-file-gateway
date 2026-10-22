# C3 Candidate B / B03-T01 R2b-R2b-R2-S6 — Offline Cross-stage Denial Evidence (NO LOAD / NO C EXEC)

**Status: AUTHOR S6 DENY-ONLY OFFLINE PARTIAL; independent Standards / Spec CODE Review PENDING.** This is not the full D1 `S6_INDEPENDENT_PRELOAD_DECISION` nor Native first-load approval.

**Fixed independently reviewed parent:** [PR #51 Review #5613071390](https://github.com/chinanjjohn2012/mac-file-gateway/pull/51#pullrequestreview-5613071390), frozen Head `499574be48ad14d2473f73342cc2c7708fb81b8f` / Git Tree `7d7393ee645d9c9bcfbf54f755a03ccc4aee02af`, Standards PASS / Spec PASS **only for S5 inert DATA path/FD observation PARTIAL**. All stacked PRs remain Draft/unmerged. P3-01 and P3-02 are OPEN, P3-03 CLOSED.

## 1. Exact evidence collection, and what does not occur

This implementation composes **previously reviewed static collectors** within one read-only GitHub Actions Job:
- **S0**: actual current Git Head/Tree, complete byte-verified sorted MANIFEST.sha256, frozen Candidate C/header source SHA.
- **S1 PARTIAL**: compiler entry SHA and fixed flags from the existing S3 collector, without actual nested driver/linker/SDK closure.
- **S2 / S3 PARTIAL**: existing S3 code compiles the same inert C candidate into a disposable `.o` and links an ephemeral `.dylib/.so`, hashes real object and linked bytes and reads actual symbols/sections/relocations/loader metadata/disassembly. The linked image is **never loaded or called**, exactly as independently reviewed in PR #49. The final linked artifact is deleted before the collector returns.
- **S4 PARTIAL**: already-reviewed S4 code compiles only the C11 `_Static_assert` ABI translation unit (`cc -c`) and inspects Python `ctypes.Structure` **data layout only**; the existing SourceOnlyAdapter is parsed as AST but is **not imported**. No actual FFI function binding is made.
- **S5 PARTIAL**: already-reviewed S5 code creates and reads an **inert non-Mach-O/non-ELF DATA** file in a fresh `0700` temp directory, uses nofollow descriptor/path identity checks, then destroys it. This inert file is **not** the actual S3 linked image or a candidate loader target.
- **S6 OFFLINE DENY-ONLY**: reject missing/spliced/different Head+Tree/Manifest, out-of-order stages, malformed digest, false authorization booleans and incompatible static S3/S4/S5 observations. Consistent PARTIAL results can only return `REVIEW_REQUIRED_NO_LOAD`. Any contradictory/unknown record returns `REJECT`. **There is NO ALLOW/APPROVED/NATIVE_PASS branch or token.**

**Crucial distinction:** these are *three separate, ephemeral collectors executed sequentially within one CI test*, not one atomic build-to-Adapter-to-loader session. The S3 .so/.dylib no longer exists when S5's unrelated DATA-file custody check starts. The aggregate SHA256 is merely a digest of reported partial observations, **not** a security-authenticated unbroken chain, proof of toolchain identity, or protection from TOCTOU/same-UID writers.

The new S6 code does **not** create/open a native loader, call `ctypes.CDLL`, import a C-binding Adapter, invoke any Candidate C function, inspect a host PID/PGID, or send a process-group signal. It invokes the prior permitted S3 compiler/linker tools for static **NO LOAD** evidence only, and the permitted S4 C11 compile-only proof. No product Gateway code, Native Helper/Owner/Controller/Worker/Runner, or frozen Native contract RED behavior is altered.

## 2. Deny-only cross-stage validator and negative tests

A fixed ordered three-entry bundle `S3_LINKED_STATIC_PARTIAL → S4_SOURCE_ABI_STATIC_PARTIAL → S5_INERT_DATA_PATH_STATIC_PARTIAL` must have exact stage keys, fixed historic independently reviewed parent Head/Tree identities, matching **current** 40-hex Git Head/Tree, shared current 64-hex Manifest digest and frozen C/header source hashes, correct 64-hex object/link/layout/data digest shape and consistent stage-local forbidden-authority flags. Existing reviewed raw linked-header and static metadata validation is run on **in-memory** S3 output; S4 stored layout/AST digests are recomputed, and S5 inert file identity must have expected private mode, expected DATA SHA and an explicitly non-loader dual observation. Everything remains partial.

Dedicated negative test cases mutate:
- Missing/reordered stage, wrong Git identifier type, mixed HEAD/TREE, changed Manifest/source/hash, unknown extra approval key;
- S3 claimed Native execution/full CFG, tampered linked-header bytes or additional export;
- S4 fake call authorization, bad layout/AST digest or changed SourceOnly denial;
- S5 changed inert SHA, zero inode, hardlink, invented loader custody and drifted reviewed parent tree;
- Fake `admission=AUTHORIZED`, nonexistent evidence and copied yet structurally valid dictionaries.

This linter **does not independently authenticate arbitrary dictionaries**. It cannot turn a copied or even perfectly formatted synthetic record into proof of C invocation or future safe loading. A fabricated complete-looking record may at most receive `REVIEW_REQUIRED_NO_LOAD` if it satisfies the intentionally limited checks; unknown or contradictory values yield `REJECT`. It is not a security approval service.

The actual original CI Job prints current Head/Tree and real per-platform object, linked image, ABI assertion and inert DATA SHA digests, plus six **missing full gate** reasons. No output labels S1, S3, S4, S5 or **S6 full** PASS.

## 3. Explicit outstanding security controls (not waived)

- **P3-01 OPEN:** complete PRE-COMPILE compiler/assembler/linker/SDK/sysroot closure and executable inode binding, atomic source→object→final→loader custody, S5 same-inode actual loader check/use, dependency resolution and exclusion of same-UID/TOCTOU replacement still **NOT PROVEN**.
- **P3-02 OPEN:** full reachable C machine-code CFG, all imports/fixups/relocations/initializers, real Python FFI Adapter transitive graph and true Python-to-C call/ABI lifetime are **NOT PROVEN**. Partial metadata scans cannot substitute for these.
- **P3-03 CLOSED** remains unchanged. Full `S6_INDEPENDENT_PRELOAD_DECISION` **NOT_RUN/BLOCK**; an independent Standards / Spec review of this PR cannot substitute for a separate explicit first no-signal C load grant.
- **191 expected RED** Native contracts remain untouched: 19 B03 missing Native Helper/Runner plus 172 R2b missing native Helper/Adapter. Linux Full remains **FAILURE**, NOT GREEN; all unexpected failures must be treated as blocking.

**Permanent hard STOP:** `group_kill_authorized=false`, `reuse_proven=false`, `g2_qualified=false`, `first_c_load_authorized=false`; T04/T08b/T10 `NOT_RUN/BLOCK`; R2b-R2b-R3 first Native C load/call, real process-group TERM/SIGKILL, Native Owner/Controller/Worker, R2b-R3/T01-R3, G2/G3/G4/G5, Gateway ExecSupervisor / REST/MCP Multi-Workspace Exec, merge and deploy are all **BLOCK**.

## 4. Independent review handoff

Read current PR's **exact Head/Tree**, all five research-only files, prior approved S3/S4/S5 proofs, the D1 design, the historical fixed-SHA independent Reviews and **original GitHub Actions Jobs**. Check actual compile/link behavior remains NO LOAD; test all fail-closed mutants and distinguish truly collected observations from dictionary-shape lints. Publish Standards PASS/FAIL, Spec PASS/FAIL, P0/P1/P2/P3 and a conclusion **restricted to S6 offline deny-only PARTIAL**. Even PASS closes only this narrow negative-decision research, not D1 S6 completion or any Native load authority.