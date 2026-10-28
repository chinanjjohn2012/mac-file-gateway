# PR #95 r004 — N3-M complete effective Workspace scope/Runner order repair (T0 only)

**DEVELOPER FIX CANDIDATE / INDEPENDENT B AND C REVIEWS REQUIRED.** No operative D0 change, no new Native rights, no real FS/owner.lock/fsync, no Git/SDK T1, no Native processes/signals/T2, no user Mac/Tunnel/shared/prod T3, no integration/merge/deploy.

REPO: chinanjjohn2012/mac-file-gateway
PR: #95
TASK_ID: MULTI-EXEC-R2N-N3M-MEMORY-20261028
REVIEW_ROUND: r004
REVIEW_TARGET: FULL BOUNDED N3-M pure memory authority-binding model, strict typed contracts, Fake PREPARED/STARTING/retirement/decision, source-static F1/Git/File adjacency; 42 original + 17 r002 + 9 r003 + 11 r004 declarative Python unittest methods = 79 available T0 methods.
REVIEW_SCOPE: FULL (bounded N3-M T0 ONLY; not full Gateway, real Native or N3-F0/F1/A).
BASE_SHA: bf11211f06c8f8c3ac21deba64b8508489281a98
PREVIOUS_R003_HEAD_SHA: 027059cb3fdc3f8ec90b8576b0a4be22c0e3aae5
PREVIOUS_R003_HEAD_TREE: 79d80d61e5de34ccd9612aa372a5aef103712fe2
R003_HANDOFF: https://github.com/chinanjjohn2012/mac-file-gateway/pull/95#issuecomment-6474933027
B_R003_FAIL: https://github.com/chinanjjohn2012/mac-file-gateway/pull/95#pullrequestreview-5686644866
C_R003_FAIL: https://github.com/chinanjjohn2012/mac-file-gateway/pull/95#pullrequestreview-5686633299
RULESET_ID: ICR-V2.0
HANDOFF_PROTOCOL_ID: GHRH-2.0
EVIDENCE_PROFILE_ID: ETP-V2.0
CONTRACT_SCOPE: CURRENT operative D0/F1/Phase1/G05/R004 security, explicitly user-approved PR94 r001 N3-D future-only design, unchanged actual gateway/workspaces_config.py::_bounded_tuple and gateway/executor.py CommandRunner. PR94 B/C targeted DESIGN acceptance is not N3-M code PASS. PR90–PR94 reviewed PR Heads must remain unchanged.
USER_AUTHORIZATION: A restricted to N3-M pure memory Schema, effective selected policy/Runner identity and response decision FK, safe T0 testing and independent B/C code review, including P2 repairs. No true private N3 state, real authorization or process operations, no T1/T2/T3, integration, merge or deploy.

## Source-level finding and explicit closure hypothesis (not signed)

B95-R003-P2-01 and P2-C95-R003-01 are the same independent material violation: previous N3MBinding.__post_init__ wrongly required lexicographically pre-sorted distinct `workspace_exec_paths` and `workspace_exec_runners`. Current operative gateway/workspaces_config.py _bounded_tuple validates bounded, nonempty, exact-string-unique arrays but **does NOT require sorted input**; CommandRunner takes runner entries in declared order, chooses longest matching cwd ancestor, and when the same PATH has different mapping strings it uses dict assignment so **last mapping for that PATH wins**. This is an effective-policy contract fact, not a new product behavior implemented by N3-M.

**r004 candidate behavior in gateway/r2n_n3m_offline.py:**
- Accept existing eligible, unsorted but unique Workspace Exec paths, rejecting exact duplicate scope strings, traversal, noncanonical/malformed values. Retain the original caller tuple for transparent review; do not add new operative config constraints.
- Accept valid arbitrary-order unique complete `PATH=direct|pipenv` strings. Reject exact duplicate string, malformed paths/modes and external scope; compute the effective runner map in original order with the same last-write-wins behavior for different strings mapping the same PATH, then choose the longest matching configured ancestor for runner_cwd. Inaccurate runner_id/runner_project claims remain rejected.
- Only for canonical deterministic equality/digest, `encoded_binding` normalizes unordered paths and the FINAL effective runner map by sorted path. Equivalent raw ordering -> identical effective authority fingerprint; reordering conflicting same-PATH values with a different effective last mode -> changed digest, stale prepared ticket invalidation when evaluated. This SHA256 equality digest is NOT a trusted operator authorization, durable state witness or same-UID antirollback defense.
- `digest` now hashes the same normalized `encoded_binding` output. The existing grant, root, profile, trust_scope, backend, risk ACK, owner/consent and temporal identity fields remain present. No runtime import of this model is introduced and current F1 nonpreview exec_cleanup_proof_required is unchanged.

**test-first r004 source:** tests/test_r2n_n3m_review_r004.py includes exactly 11 T0 methods covering both raw array orderings, canonical digest equality, nearest child pipenv/direct, root-dot, invalid duplicate strings, malformed map, last-wins same-PATH mode, effective equivalent duplicates, changed effective mapping fencing, F1 no-positive mock; all distinct from the previous 42+17+9 existing tests. In particular the original r003 test `test_c95_r002_nearest_override_pipenv_and_mutation_fence` is intentionally NOT weakened or rewritten. Original r003 B/C exact SOURCE RED: each observed 68 actual tests -> 67 pass and 1 ERROR on this legal input, both native SHA-bound reviews separately reported. That is valid old-Head RED evidence (not A-run and not the new Head's result).

## Actual A verification status (do NOT inflate)

A independently ran an isolated **reconstructed minimal binder** in Linux x86_64 Python 3.13.5 under `PYTHONDONTWRITEBYTECODE=1 python3 -B -I -S`; raw harness/source and final stdout are committed under:
- docs/evidence/R2N_N3M_R004_REDUCED_RUNNER_T0_20261029.py
- docs/evidence/R2N_N3M_R004_REDUCED_RUNNER_T0_20261029.log

Observed final REDUCED GREEN: 17 tests executed, 17 pass, 0 errors/fail/skips, process exit 0. Initial harness run had one test fixture error from mistakenly naming a Pipenv project outside its nearest granted scope; A adjusted the **reduced test fixture**, not the product code, and reran. This is only a **semantically reconstructed B/C finding probe**, NOT byte-identical full source execution, NOT an original GitHub Actions workflow, and NOT current r004 full source success. No actual private-state operation, OS process, signal, shell/third-party Git, network or service operation is inside the Python harness.

**CURRENT EXACT-SOURCE COMPLETE 79-TEST EXECUTION BY A: NOT_RUN.** Raw Github current source and the FOUR real test modules were fetched/checked as Git Blob text but cannot be materialized to A's standalone Linux model-test container by authenticated GitHub connector network in this session. Prior r003 B/C exact 68-run FAIL is historical RED for OLD Head only; prior r001 42 GREEN, r002 8+10 REDUCED GREEN, and r003 source-only static checks do NOT become r004 PASS. No original current-Head hosted G05 or full Gateway CI job exists unless separately observed at final handoff. B/C must independently run CURRENT HEAD exact source 42+17+9+11 tests under authorized T0, author own negative counterexamples, report actual exit code and raw evidence. Missing current full-source regression may lead to evidence insufficiency/BLOCKED; no role-level code PASS is assumed.

## Future P3, platform and authorization hard stops

B94 P3: N3-private-only strict UID/mode/owner.lock must not break Phase1 legal ordinary loose Workspace/config/Preview/Git/File, future Git T1 must bind disposable HOME/git configs/filters/fsmonitor/hooks/credential helpers/SSH before any separate user approval. C94 and C95 P3: actual trusted lineage/complete namespace loss/rollback, response as-of marker and true FK transaction/ACK, prearmed boot-deny fsync and post-unlink dir-fsync, physical byte limits/ENOSPC, owner.lock split-brain, worker limits/HTTP/official MCP/SDK/Git/File, macOS at-signal target ownership and whole descendants remain NOT_RUN/UNPROVEN. No fake proof extends to Native or Strict F3. Reviewers preserve all old Review objects and no A unilateral finding closure.

**NOT_AUTHORIZED/NOT_RUN:** real N3 private FS, owner.lock/flock/rename/fsync/ENOSPC; Native Exec process/PGID/signal/killpg/forced crash; full Gateway installed G05/36-wheel RECORD source identity; actual local Mac/Tunnel/shared/prod T3; actual REST/MCP/Git/File/SDK T1; user production config/migration/consent enable, UNKNOWN reset, integration, merge, release, tag or deploy. Valid Preview and independently legal File/Git remain governed by their existing allowances; no global subprocess blocking or runner activation was added.

**A STATUS:** FIX_CANDIDATE; current r004 source and tests are NOT independently reviewed; new HEAD SHA/Tree and Manifest must be recorded from raw GitHub objects in GH_HANDOFF_V2 FIX_READY after final verification. B and C each issue their own native COMMENT Review bound to the SAME r004 Base/Head/Tree under FULL bounded N3-M T0. FULL_CODE_REVIEW_PASS, INTEGRATION_PASS and whole product R10 are not signed by this note.
