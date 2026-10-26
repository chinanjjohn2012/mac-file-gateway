# Multi-Workspace Exec R1-A0: non-spawning Runner seam and T0 contracts

**Historical scope note:** This document describes the original R1-A0 inert
snapshot on PR #80 only, where the coordinator was not wired into
WorkspaceService. The later cumulative R1-stage integration on the distinct
stage PR adds a **denial-only** synchronous Worker hook; the F1 public
response remains hard-coded to reject, before any Worker slot or PREPARED.
For the actual stage review target and combined source scope, see
`docs/MULTI_WORKSPACE_EXEC_R1_STAGE_GATE.md`. This historical A0
description is NOT a claim that the current integrated stage has no
WorkspaceService import.

**Status: R1-A0 CODE CANDIDATE ONLY / NO POSITIVE EXEC / NO INTEGRATION OR ACTIVATION APPROVAL.**
**Task:** MULTI-EXEC-R1-A0-NONSPAWNING-SEAM-20261026.
**Source ancestry:** PR #79 exact reviewed CI/dev resolver Head
`b95414ae0287b66def3fb25853a0a553a9849aca` and Tree
`b5931b1c61dc5af0bf07e1fe657008d0f56f0854`.
**Design reference (NOT a parent, current authority amendment or runtime grant):**
PR #78 r002 fixed Head `d502254934961ebe53720fb0708def85db6cd202`,
Tree `b54fb1e875264aa4d046410533f1998d07052359`;
four reviewed proposed RUNNER_*_V1 design documents, each reviewed by
independent B and C with TARGETED_REVIEW_PASS for T0 design clarity only.
**Current operative authority** remains D0 section 0 and the production-first
F1 deny-only plan from PR #76 / PR #79 source.

## 1. Deliberately limited deliverable

- New `gateway/runner_seam.py` provides immutable typed identifiers and
  distinct command, cleanup and response-delivery results, a descriptive
  `RunnerBackend` Protocol, plus `RunnerCoordinator.evaluate()`.
- The coordinator **always returns** the denied decision:
  `allowed=false`, `error_code=exec_cleanup_proof_required`,
  `completion_capability=none`, even when given a fake backend that claims
  a complete domain proof.
- The coordinator **never calls** a backend method or process API. No
  `allocate/start_once/observe/terminate_and_prove/reconcile` implementation
  exists in the Gateway runtime. The Protocol is descriptive only.
- The reference and outcome data classes are NOT signed qualifications or
  authority. A forged `CleanupEvidence(full_bound_domain, proven)` object
  cannot change the coordinator decision.
- Identifiers are structural fields, not authenticated owner-lock, persistent
  generation, OS process identity or a target for a host signal.
- `tests/test_runner_seam_r1.py` adds pure T0 success/denial/boundary/invalid
  data tests. These do NOT prove real cleanup, durable PREPARED, crash
  reconciliation, owner revocation or an authentic backend.
- No existing `WorkspaceService.invoke_exec`, REST, MCP, CommandRunner,
  ExecStateStore, config schema, Git/File policy, user Mac or installation
  is changed. Existing unchanged product F1 tests and original CI provide
  the real transport/Preview/denied Exec/authorized Git/File regression path.

## 2. Security invariants and negative counterexamples

1. Forged backend qualification, secret token, cleanup evidence, mode selector
   or caller-supplied proof cannot enable the seam.
2. A claimed full-tree marker in plain data is never trusted as a cleanup
   certificate. Group-only plus proven full-tree is structurally invalid.
3. Positively observed detached survivor cannot be represented as clean
   group-only or proven domain completion. Future runtime must quarantine.
4. Command exit code, cleanup observation, and HTTP/MCP delivery are separate;
   an exit code of zero or lost response ACK cannot imply safe cleanup/retry.
5. Attempt and generation identifiers are immutable syntactic tokens, not
   durable identity evidence. Stale PID/PGID, group signal TOCTOU and any
   operator reset remain NO-GO; no native OS calls are added.
6. The source has no process/network/signal imports, and its coordinator has
   no start/stop method. This is **nonoperative** code, not a positive runner.
7. Existing F1 retains `dry_run=false` denial before any Worker slot,
   Runner/Popen or PREPARED. Real same-service File Write/Git grants and
   official REST/MCP routing stay subject to the existing tests and authority.

## 3. What this R1-A0 does NOT do

- No actual Runner allocation, process launch, VM, native process-group signal,
  real cancellation, T2 descendant test or T3 user-host work.
- No schema v2, operator consent record, configuration profile flag,
  qualified Native Limited, Strict F3, automatic UNKNOWN repair or
  versioned recovery. Any candidate mutable Workspace trust remains
  unapproved until explicit product-owner decision and independent D0 amendment.
- No live `RunnerCoordinator` wiring into `WorkspaceService` or real
  transport. Current ExecStateStore schema v1 remains untouched.
- The T0 Mock/test outcomes are NOT substitute evidence for real R1+ durability,
  macOS live group identity, strict OS domain termination or integration.
- No assumption that PR #79 CI or PR #78 R0 role reviews applies to this new
  code Head; it requires its own exact-Head CI, both independent roles,
  and a new round before any stronger claim.

## 4. R1-A0 tests and evidence scope

- T0: immutable attempt/owner-generation/dev-inode fields; malformed/bool
  cases; structurally invalid cleanup claims; zero exit vs cleanup result;
  lost ACK vs replay; fake backend accessed zero times; no profile/reset fields.
- T0 static adjacency: preserve F1 proof-before-busy source order, assert no
  import/wiring into WorkspaceService, and retain original v1 state phases.
- Linux T1: existing exact-Head G05 checkout admission, source-controlled
  wheel lock, offline install/RECORD and full pytest + REST/MCP/Git smokes,
  if the GitHub workflow runs. Record actual counts, skips and failures.
- macOS T1: supported disposable GitHub-hosted macOS 15 ARM64 verification
  requires an independently scoped same-Head workflow/job and cannot be
  inferred from Linux successes or historical #76/#79 jobs.
- T2/T3: NOT_AUTHORIZED / NOT_RUN for native child, SIGTERM/killpg, VM,
  forced crash and user Mac/Tunnel. Even T1 tests must not enable real Multi
  Exec Apply.

The PR must record real Head and synthetic Merge identities separately,
actual original Job logs, SHA256 Manifest and exact changed file set.
Incomplete CI evidence means an incomplete/full blocked review, not a
retrospective test pass. Preserve the PR #79 3.5.1 dependency constraint
and the two source-locked wheel SHA256 files without modifications.

## 5. Follow-on gates (not implemented here)

R1-A1, if separately approved, may integrate a real **nonspawning**
Coordinator decision seam with the F1 Worker only if proof-denial remains
before any lease or PREPARED, with real ingress and File/Git regressions.
A live backend interface and durable schema evolution require separate
design/code reviews and explicit authorization. Actual Native profile
requires owner acceptance of the mutable Workspace and detached-daemon
residual risk, independently approved D0 contract change, macOS
race-resistant live target identity, T2 authorization and full
positive/negative tests. Strict F3 requires separate D1-D6 OS proof.
No fail-open or Native fallback is ever permitted.

**Prohibited:** merge, deploy, publish, tag, production config, real
Multi Exec apply, private proof-grant enablement, unknown process signals,
Native C/C3, unquarantine, unsafe native experiments and user Gateway/Tunnel
changes without separately scoped authorization.
