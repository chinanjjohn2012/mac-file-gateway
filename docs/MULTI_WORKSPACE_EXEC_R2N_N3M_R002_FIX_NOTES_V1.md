# PR #95 r002 — A bounded N3-M pure-memory code repair notes

**STATUS: DEVELOPER FIX CANDIDATE; independent B/C new-Head r002 reviews REQUIRED.** This document is not a new operative D0 contract, reviewer signoff, positive Exec permission, complete CI or physical-durability proof.

REPO: chinanjjohn2012/mac-file-gateway
PR: #95
TASK_ID: MULTI-EXEC-R2N-N3M-MEMORY-20261028
REVIEW_ROUND: r002
REVIEW_TARGET: COMPLETE BOUNDED N3-M strict pure-memory schema/consent/owner lifecycle, nonspawning STARTING and server decision, adapted 42 original T0 tests plus 17 new direct-reviewer-finding T0 tests, source-static nonwiring and F1 adjacency.
REVIEW_SCOPE: FULL (bounded N3-M T0 only; NOT full Gateway, real N3-F0/F1/A, CI, integration, Native)
RULESET_ID: ICR-V2.0
HANDOFF_PROTOCOL_ID: GHRH-2.0
EVIDENCE_PROFILE_ID: ETP-V2.0
FIXED_BASE_SHA: bf11211f06c8f8c3ac21deba64b8508489281a98
PREVIOUS_FROZEN_R001_HEAD_SHA: 1204f5b11c6d6c4f682884c0b56d35b7e573d428
PREVIOUS_FROZEN_R001_HEAD_TREE: 044a929caf56b4347fc6ffdfaa04257cb7374170
PREVIOUS_A_HANDOFF: https://github.com/chinanjjohn2012/mac-file-gateway/pull/95#issuecomment-6471938579
B_R001_FAIL: https://github.com/chinanjjohn2012/mac-file-gateway/pull/95#pullrequestreview-5684805307
C_R001_FAIL: https://github.com/chinanjjohn2012/mac-file-gateway/pull/95#pullrequestreview-5684830202
USER_AUTHORIZATION: User expressly allowed A N3-M pure-memory Schema, complete effective identity/decision FK, and safe T0 only, including correcting r001 B/C P2 within that original boundary. Keep PR #90–#94 reviewed snapshots frozen, F1 default deny. No actual private FS/owner.lock/fsync, Git/SDK/HTTP/MCP T1, Native actual process/signals/PGID/T2, user Mac/shared/prod T3, integration/merge/release/deploy.

## 1. Consolidated B/C blocking findings and code changes

| Original finding | r002 fix proposal (NOT independently closed yet) | New regression cases |
| --- | --- | --- |
| B95-R001-P2-01 | retire_limited_fake(now, binding) is now mandatory, validates latest monotonic fake clock and same current consent, owner, epoch, root/backend/runner binding and quarantine before RETIRED_LIMITED; expired/changed/revoked => UNKNOWN+quarantine, preserve already possible fake dispatch count, no clean later decision | new test_b95_* expiry strictly between dispatch/retirement, exact expiry boundary, valid-before-expiry limited as-of, changed backend, revoked after dispatch, mutable legal script |
| C95-R001-P2-01 | frozen N3MBinding now requires typed exact profile=native_limited and trust_scope=mutable_workspace; both enter canonical asdict SHA256 digest. Invalid strict_f3/preview_only/unknown trust rejected (other profiles are not alternate valid Native permissions). | new test_c95_security_profile_and_trust_scope_are_typed_exact |
| C95-R001-P2-02 | removed nonexistent global server path allowlist (real server.exec is Boolean). Exact Workspace .exec.paths supports root '.', valid canonical nested POSIX paths, with Workspace per-path PATH=direct/pipenv explicit map. Digest includes selected direct/pipenv mode, selected runner project, map, explicit runner fallback and backend fingerprint; wrong/missing/ambiguous maps denied; changing effective runner/path map changes digest. This T0 model still does NOT physically inspect Pipfile or installed runner. | new legal root/nested, direct-pipenv map change, invalid traversal/wildcards, server-only Boolean and contradictory mode cases |
| C95-R001-P2-03 | explicit independent fake_starting_commit() barrier changes PREPARED->STARTING only after modeled commit; fake_first_dispatch requires STARTING then one modeled dispatch step with 'dispatch' fault injection. Failed starting or dispatch fake commits quarantine, set UNKNOWN and ensure integer dispatch count=0. Explicit revoke/late-event at STARTING blocks later fake first dispatch. | new starting commit fail, dispatch fail, revoke-after-STARTING, late event-after-STARTING and pre-existing 42 event order regressions |
| B95-R001-P3-01 | typed N3MControl now rejects contradictory global_quarantined=False + reason!=none and global_quarantined=True + reason=none. This is *only typed in-memory consistency*, not a real owner lock, provenance, boot scan or persistent-store proof. | new test_b95_control_reason_conflict_fails_closed_in_memory |

Actual N3-M model type checks only Python stdlib and has zero OS/socket/signal/subprocess/file operations. N3-M remains unimported by existing Gateway runtime. Current operative WorkspaceService.invoke_exec valid nonpreview dry_run=false still exec_cleanup_proof_required before Worker/PREPARED/Runner/Popen; separately authorized Preview/Git/File remain under their old gates. No runtime code, tests, config, CI workflows, deps, native backend, existing v1/S2/N2 state, or operative D0 changed.

## 2. Developer T0 evidence and exact limitations

**Original r001 r002 behavior repro:**
- B supplied an independently originated frozen old-Head P2 report and source-extracted expiry RED; A separately executed an isolated _reduced_ Python method-excerpt reproduction of the old retirement/clock path with fake time reaching exact expiry: observed RETIRED_LIMITED, quarantined=false, expected fail-closed UNKNOWN; exit 1 and raw output in docs/evidence/R2N_N3M_R002_REDUCED_T0_RED_GREEN_20261028.log.
- In the same isolated Linux Python 3.13.5 with -B -I -S and PYTHONDONTWRITEBYTECODE=1, A executed TWO separately authored _reduced_ mock method models of the proposed finalization/STARTING transitions (8/8 PASS exit0) and canonical binding/map rules (10/10 PASS exit0). Their full original stdout and source mode are named in the same evidence log.
- These are NOT executions of the actual current GitHub N3-M full source module, original complete 42 unittest suite, or added 17 new unittest cases; **all 59 full-suite current-r002 cases are NOT_RUN by A**. The original r001 developer 42-GREEN log was on OLD Git Blob/model schema and is historical, not new Head PASS. The import-only r001 test-first RED does not prove the new P2s. No original r002 GitHub Workflow Job/Log or G05/36-Wheel installed RECORD provenance exists until independently observed.

**T0 review source:** tests/test_r2n_n3m_review_r002.py adds exactly 17 new executable declarative Python stdlib unittest methods targeting B/C findings. tests/test_r2n_n3m_offline.py retains the prior 42 method names but updates fixture to real server-Boolean, Workspace paths and runner map, and changes 14 retirement calls to require current binding+time. Model has explicit warning it never creates real tokens or can signal/qualify Native cleanup.

**Source execution identity limitation:** Reduced tests are not byte-identical complete-module runs; never infer their GREEN proves the current committed GitHub full suite. Source-static identity is direct GitHub committed Git Blobs and SHA256 of each r002 changed file/Manifest as fixed in the subsequent r002 handoff. B/C must independently verify/correct model behavior using the exact new Head, in addition to their own legal/illegal/boundary/abnormal counterexamples. Missing execution and possible test failures are NOT_RUN/BLOCKED for full product claims, not auto PASS.

## 3. Carried P3 / future tests NOT authorized

B94-R001-P3-01 N3-private 0700/0600 and owner.lock must never globally reject Phase1 valid loose-mode Workspace/config, Preview, legal independent Git/File; no actual private FS implementation here. B94-R001-P3-02 future real Git T1 requires disposable HOME, pinned effective config/include/hooks/fsmonitor/filter/credential helpers/SSH and exact child/host grant, separate owner approval; no Git subprocess run.

C94-R001-P3-01 independent trusted lineage/provision anchor, both-roots absence/consistent rollback and same-UID adversary still unqualified. C94-R001-P3-02 T0 identity linkage/clock is modeled but trusted clock, persisted FK and physical response ACK NOT_RUN. C94-R001-P3-03 real final-fence unlink BEFORE directory fsync remains T1; no Fake proof substitutes. C94-R001-P3-04 real quota 4096/4096/16MiB, owner.lock/FD/restart/fsync/ENOSPC, Worker slots, official MCP/REST, Git/File and Mac process-signal identity NOT_RUN. C95-R001-P3-04 persisted attempt phase/status/cleanup/ref and decision as-of marker fields are future schema proof, not a hidden Native grant. C95-R001-P3-05 true source/installed CI and physical/adjacent evidence unavailable. No P3 is independently closed by an A developer-only statement.

## 4. Requested independent new-round qualification

B and C each reread the current V2.0 source rules, the fixed PR94 design and operative D0/F1 contract, independently fetch PR95 Base/Head/Head Tree/full diff/entire current model and BOTH test modules, original old fail and new limited GREEN log, any actual new Head/merge CI Jobs if run, and the exact new Manifest. Run actual safe exact-source T0 59 tests if independently feasible, invent new fault/clock/Runner/response sequence counterexamples, and independently decide whether each P2 closes. Two new native GitHub COMMENT Reviews must both bind the same new r002 Base/Head/Tree; neither may inherit old C/B conclusion or treat A's reduced-green as a current exact-source full PASS.

**Strict hard STOP:** no T1 private FS/owner.lock/fsync/ENOSPC/Git/official SDK, real Native Exec/signals/killpg/crash/VM, T2/T3, user Mac/Tunnel/shared/prod, local operator consent activation, migration, UNKNOWN clearing, integration, merger, deploy, release, strict_f3 fallback, or full descendant cleanup claim. R10/integration remain INCOMPLETE/NOT_TESTED pending independent code review and later distinct authorization.
