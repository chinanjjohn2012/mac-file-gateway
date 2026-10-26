# R1 stage integration — nonspawning Runner decision boundary

**STATUS: R1 DEVELOPMENT CANDIDATE; NO REAL MULTI EXEC; STAGE B/C REVIEW NOT YET ISSUED.**

- **TASK_ID**: `MULTI-EXEC-R1-NONSPAWNING-STAGE-20261026`
- **REVIEW_TARGET**: entire R1 limited nonspawning Runner protocol, inert admission decision, integration with current F1 shared synchronous Worker, T0 and hosted T1 regressions.
- **CONTRACT_SCOPE**: current D0 §0.1, §0.3, §0.4; approved F1 production-first implementation plan; Phase1 local OS trust boundary; G05 source/wheel/RECORD identity; unchanged independent File Write/Git apply and REST/official MCP routing.
- **BASE**: frozen PR #79 exact Head `b95414ae0287b66def3fb25853a0a553a9849aca`. The PR #79 fix is an ancestor and its new code results cannot be inherited as R1 full PASS.
- **STAGE INPUT**: frozen PR #80 exact Head `bf0cf4bb463f6c28a5987a11b74eca157638f381` is a development ancestor with one R1-A0 READY_FOR_REVIEW comment and no role Reviews as checked at stage start. PR #80 remains unchanged. This stage PR must review **all** effective source changes from PR #79 Base to final R1 stage Head, including everything originally added in PR #80.
- **R0 DESIGN**: separate frozen PR #78 r002 Head `d502254934961ebe53720fb0708def85db6cd202`; its B/C targeted design PASS does not modify operative D0 §0.4, approve the Native Limited trust-risk contract, or substitute for R1 code review.
- **GOVERNANCE**: original ICR-V1.0/GHRH-1.0 remains operative pending independently approved V2 activation and same-version A/B/C Project sources. The user has approved stage-based review scheduling for subsequent R1 development, *not* any safety exception or real Exec.

## 1. Completed scoped code work — stage effective source

1. `gateway/runner_seam.py`: R1 immutable AttemptIdentity (Workspace name/dev/ino/attempt+generation tokens), ProposedCommand, BoundReference, BackendQualification (only none), descriptive command/cleanup/delivery records, future RunnerBackend Protocol. It has **no** process spawn, signalling, network, filesystem I/O or VM implementation.
2. `RunnerCoordinator.evaluate`: a fake-compatible, no-backend-call **denial-only** API. `deny_unqualified_apply()` returns an immutable denial; this code does not allocate attempts or produce authorization.
3. `gateway/workspaces.py:WorkspaceService.invoke_exec`: creates an inert Coordinator once per service and invokes `deny_unqualified_apply()` ONLY when both Exec opt-ins and healthy state have been validated and `dry_run=False`. It then **unconditionally raises** the unchanged hard-coded `GatewayError(exec_cleanup_proof_required)` before setting Worker occupancy, calling `gateway.run_command`, Runner/Popen or writing PREPARED. The return from Coordinator is deliberately not capable of enabling Exec.
4. `tests/test_runner_seam_r1.py` and a new actual-service/REST/Git/File/UNKNOWN test in `tests/test_multi_exec_f1.py`: malformed inputs, fake forged "proven" evidence, no process/network implementation, immutable identity, no delayed-reply replay grant, unchanged v1 state, direct and HTTP denial, legal preview, actual same-service authorized Git subprocess and File Write, denied Workspace and Exec UNKNOWN precedence.
5. Hosted macOS 15 ARM64 R1-stage job (no real Exec) runs G05 tracked source audit **before** Python imports, source-locked 36-wheel SHA256 check, offline install and installed RECORD file hashes, then selected safe tests and final Manifest. Its PR guard requires the exact stage base branch and frozen #79 Base SHA. Existing Linux workflow runs all full pytest and REST/official MCP/Git smokes. Both checkout and verify **actual PR Head**, not merely a green synthetic Merge commit.
6. `MANIFEST.sha256` must include every new/changed tracked file hash and match actual final Head Git Tree. Do not infer a developer-local uncommitted worktree from the GitHub Tree.

**No different API, public profile selector, operator grant, schema v2, Runner backend, Exec activation or post-proof Worker admission has been implemented.** The existing v1 durable ownership/UNKNOWN/quarantine and G05 dependency verification remain unchanged.

## 2. R1 stage safety contract and negative counterexamples

| Contract | Legitimate outcome | Prohibited / boundary / exception outcome | Evidence level |
| --- | --- | --- | --- |
| F1 default deny | Both grants enabled + healthy state + real Apply -> `exec_cleanup_proof_required` | Backend forged proof, request headers/JSON, busy slot or future mode fields cannot get Popen/PREPARED or allow | Real direct/REST/MCP F1, T0 fake |
| F1 preview | Valid scoped `dry_run=true` produces bounded nonexecuting preview | Malformed argv/cwd/Workspace/timeout/boolean, missing grant, quarantined state rejects | Real service/REST/MCP |
| Adjacent legal | Real authorized Git `dry_run=false` + physical File Write works on same disposable service | Unauthorized Git/File denied; after UNKNOWN Exec quarantines but Git/File lawful path remains | Existing F1 real T1 and expanded test |
| Ownership/UNKNOWN | Private state health and locks precede no-proof decision | Lost owner, unreadable state, UNKNOWN, copied test-only group marker, schema/boot ambiguity cannot auto-clear or bypass | Existing private-FS tests, not new native process proof |
| Coordinator no authority | Fake arbitrary Backend, forged descriptive cleanup data, zero exit cannot grant real admission | Missing/invalid tokens and stale owner data reject structure; unauthorized user-supplied profile/proof/reset unknown | Pure T0 + in-service deny-only hook |
| Result honesty | Cleanup result is distinct from command success and transport delivery | Observed survivor cannot report clean group/full-domain; group-only never full descendant proof | Pure T0 only, no real OS observation |
| Native T2 and F3 | NONE, unsupported in R1 | No real positive Exec, no `start_once`, no group signals/VM, no automatic UNKNOWN reset | NOT_RUN/NOT_AUTHORIZED |

## 3. Stage tests and review criteria

- GitHub-hosted Linux exact Head: G05 222+ current tracked blobs and matching per-file Manifest, 36 pinned wheels and RECORD, full pytest, true REST/SDK MCP/Git smoke, after-test byte recheck, Bash and compileall. Do not copy historical totals to this new source.
- GitHub-hosted macOS 15 ARM64 exact Head: selected native Darwin/F1/Runner/G05 tests, immutable source/wheel/RECORD before/after, explicit macOS platform identity. This does not claim full Mac suite, real Exec, or actual user Mac.
- B and C must independently review the **combined stage cumulative diff**, source/contract test matrix, actual original jobs and executed Head vs synthetic Merge identity, and build their own positive/negative/boundary/exception counterexamples. Their reviews must be SHA-bound to the **same stage PR** Head/Base/Tree and applicable current rules.
- All P0–P2 and any true material safety evidence gaps must close in a new snapshot/review round. A may coordinate and repair but never sign B/C outcomes. Do not confuse TARGETED or REVIEW_COMPLETE with full R10/INTEGRATION_PASS.
- No production integration is claimed. True Native positive cleanup/identity-safe PGID signals and Strict F3 OS proof are **separate later safety contracts** requiring both independent reviews and separate user authorization, including high-risk Mac T2 resources.
- Do not merge, deploy, release, create tags, modify user Mac/Tunnel or production configuration, load Native C/C3, or expand any privileged experiment.

## 4. Stage completion gate

Only after R1 combined exact-Head CI and A source check have completed may A publish **one stage `READY_FOR_REVIEW`** and freeze its Head/Base. This handoff must enumerate BOTH #80 R1-A0 + the stage Worker hook, original Linux/macOS Run/Job/logs including SKIP/NOT_RUN, security gaps, full Head Tree and inherited authoritative contract versions. No per-intermediate-PR role review is claimed or required under the approved phase-gate scheduling, but the stage's full source must be reviewed. Review is complete only when B/C independently publish sufficient scope reviews and A verifies R10 and additional constraints.
