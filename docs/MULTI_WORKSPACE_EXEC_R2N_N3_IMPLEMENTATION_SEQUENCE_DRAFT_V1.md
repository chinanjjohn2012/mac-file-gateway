# R2-N N3 — conditional implementation sequence and interface sketch V1.0

**DOCUMENT-ONLY DESIGN. No new product source, private-state directory, real FD, owner lock, filesystem fault, SDK/Git/File integration or Native process work in this round.**

REPO: chinanjjohn2012/mac-file-gateway
TASK_ID: MULTI-EXEC-R2N-N3-PRIVATE-STATE-DESIGN-20261028
REVIEW_ROUND: r001
REVIEW_TARGET: staged future N3 private persistence implementation, code responsibility boundaries, source-level fail-closed interfaces, test-first checkpoints, rollback gates and independent review criteria.
AUTHORITIES: ICR-V2.0 / GHRH-2.0 / ETP-V2.0; operative D0/F1; approved PR #92 r001 future-N2 D0 draft and N0–N6 plan; user-accepted PR #93 r002 N2 bounded code. PR #90–#93 remain frozen.
AUTHORIZATION: THIS round is N3 design and pure T0 preparation only. User has NOT authorized N3 real implementation source/FS, any T1/T2/T3, integration, merge or deployment.

## 1. Why N3 is not a direct copy of S2/v1

Actual inherited source at PR #93 r002 Head 162b5f697ec5bfdb228b6aff351b8ac5cc540e3c:

| File | Git Blob | Existing truth | Future N3 work item, NOT a change now |
| --- | --- | --- | --- |
| gateway/private_fs.py | 3425c06ab543e5fb57c5f73fc667e3a5231d1eeb | FD-pinned strict private file loading | Build separate vetted private N3 namespace adapter; no hidden cross-workspace authority |
| gateway/exec_state.py | d3dc2c0ec9dec0a571f768eb6aa15edf5d0153b0 | v1 owner-locked ExecStateStore, PREPARED/RUNNING/UNKNOWN/RETIRED | NEVER reinterpret v1 RETIRED or issue local consent; keep independent |
| gateway/r2s_state_s2.py | 89632a1bb4ed1623a87b49e6926fa7f84fcac5e2 | offline nonspawning S2 schema=2, real disposable FS with owner.lock and fault markers | Review algorithms as prior evidence, not an automatic schema migration, runtime grant or independently accepted physical proof |
| gateway/r2n_n2_offline.py | 50f646c7b81b51aa6a3542ba5da07062bc5629ee | standalone single-threaded pure-memory N2 Fake; no production wiring | Reuse N2 RED/GREEN *concepts* only; do not import Fake tickets as prod authority |
| gateway/runner_seam.py | 1518efccb8e089856defc4a06c39d2dff08610b4 | NO-QUALIFIED-BACKEND inert seam | Must remain unable to launch Native absent future new code and separately proven backend |
| gateway/workspaces.py | 6d2c0b4087f17bcc543b467b04e405f0e994369d | installed F1 real WorkspaceService rejects ordinary Exec Apply before Worker/PREPARED/Runner | Keep exact default deny; any new N3 status must be no positive route |
| gateway/workspaces_config.py | 4ffd1bea9464732266e85d6cee32611317270f49 | strict schema_version=1, unknown fields reject | Do not accept native_limited profile under current schema; no implicit v2/3 migration |
| gateway/http_multi.py | 665e2f1956b4626f6ad73e9452e9e5d16706c720 | REST invokes shared service for Exec/Git/File | No new consent or reset endpoint; maintain sanitized status |
| gateway/mcp_multi.py | 7f457f2da17cd76ddae015c6a01dab4f06f64933 | official MCP routes shared service | No second hidden Native path; no client-supplied profile/grant |
| tests/test_r2s_s2_private_fs.py | 43dfaea1d70745c47b1e73070f2975ca1cbecde2 | existing real disposable-FS test suite; DIFFERENT SNAPSHOT | Reference for failure windows only; rerun as T1 only when separately authorized |
| tests/test_r2n_n2_offline.py | 05a25d2dab1ce8748484a30c4fee5550c672746a | 27 bounded pure-memory T0 tests | Older independently reviewed N2 T0 evidence, NOT automatic N3 persistence PASS |

Existing D0 requires the N3 code/FS/Runner gates to be separately reviewed; previous B/C N2 role PASS is not N3 code approval or physical testing evidence. A may NOT modify existing runtime modules, tests or workflows under the current N3 design-only authorization.

## 2. Proposed future internal interfaces (types and responsibilities only)

~~~text
# Interface sketch. NOT implemented, imported, run, or considered a capability.
N3ReadOnlySnapshot:
  schema_id: "native-n3-v1"
  namespace_id: OpaqueID
  lineage_generation: NonNegativeInt
  owner_generation: OpaqueID
  consent_epoch: NonNegativeInt
  durability: "unavailable" | "quarantined" | "healthy_metadata_only"
  execution_capability: "none"      # unconditionally for all N3 stages
  quarantine_reason: BoundedCode
  outstanding_uncertainties: NonNegativeInt

N3LocalAuthorityWitness:
  # exclusively offline operator-provisioned, separately pinned and owned
  validate_against_namespace(namespace_id, generation) -> DENY | METADATA_OK
  reject_if_absent_or_rolled_back() -> ALWAYS_DENY_UNLESS_SEPARATE_OFFLINE_RECOVERY
  # no create_from_request, reset, promote_v1 or live execution permission

N3OwnerLease:
  pin_private_namespace_and_witness() -> VERIFIED | UNAVAILABLE
  acquire_lifetime_owner_lock() -> FENCED_OWNER | UNAVAILABLE
  boot_scan_before_admission() -> DENY | METADATA_OK
  # no authoritative PID/group signal operations

N3StateJournal:
  propose_nonspawning_prepared_intent(...) -> PROPOSED_RECORD | BLOCKED
  commit_fence_then_record(...) -> METADATA_ONLY | QUARANTINED | UNAVAILABLE
  record_late_event_and_quarantine(...) -> QUARANTINED | UNAVAILABLE
  commit_server_response_decision(...) -> HISTORICAL_OR_UNKNOWN | UNAVAILABLE
  # no start, run, start_once, spawn, signal, killpg, PID-based cleanup or clear UNKNOWN

N3NoApplyAdapter:
  deny_apply(...) -> exec_cleanup_proof_required
~~~

These sketches are not contracts to expose new methods under current runtime. Future source must strictly separate owner/admission vs client identity, read-only status vs internal metadata, and response-decision fsync vs transport ACK. A metadata status labelled healthy_metadata_only NEVER means Exec available. Existing error precedence for valid requests remains exec_disabled -> exec_quarantined -> exec_state_unavailable -> exec_cleanup_proof_required -> busy.

## 3. Execution order after NEW user approvals (NO steps 2–5 authorized now)

| Gate | Proposed separately reviewable increment | Required evidence and STOP |
| --- | --- | --- |
| N3-D (THIS PR) | Design docs, truth tables, static T0 scenario cases, test resource and recovery proposal, Manifest only | GitHub exact Base/Head/Tree and documentation source identity; two independent B/C TARGETED design reviews; no real resource operations |
| N3-M (future) | Pure in-memory strict field schema + canonical binding digest model and authority/epoch/owner/attempt lifecycle, no process/FD ops | Separate explicit user authorization for N3 source T0; independent B/C source review; test-first negative/edge/exception including tampered consent and old N2 Fake provenance; current F1 unchanged |
| N3-F0 (future) | Private-FS adapter isolated from live Gateway and S2/v1: explicit provision witness, own root/lock/pin, read-only fail-closed scan, no positive adapter | Separate product implementation scope AND disposable T1 resource authorization before any real file opens/writes/locks/FS tests. T0 static/fake phase first |
| N3-F1 (future) | Atomic pending + final fence + replacement, durable boot-deny and journal/quotas/late-event record/response decision | Real T1 fault injection, ENOSPC/missing namespace/lock ABA/full quota/restart/split owner; exact raw logs/cleanup. On failed fsync never claim success, never let stale consent revive |
| N3-A (future) | Nonspawning status/official MCP/REST adjacency; legal separate Git/File regression with real SDK in SAME disposable service | Separately explicitly authorized safe T1, exact fixtures and test identity; must not disable legal Git subprocess; native Exec still always rejects |
| N3-Q (future) | B/C complete bounded N3 code review, independent evidence check, source and policy gate for further N4 | New Head/Tree, actual reviewed current T1/CI/G05 where required, R10 narrow only; no automatic N4/T2 or merge/production |

The user may choose to approve **only N3-M pure T0** in a later message. That would still NOT authorize an OS file open, owner.lock, Git, SDK, local Mac, CI run containing T1, or any Native signal. N3-F0/F1/A require exact independent resource inventory and owner consent for T1. N4/N5/R3 actual Native process identity and termination tests remain wholly separate T2/T3 authorization.

## 4. Proposed test-first closure sequencing

1. Build a static contract matrix from the approved N3-D design, actual N2/operative F1 code paths and B/C new objections. Start every new code stage by binding Base/Head/Tree, actual changed-file set, external inputs and contract version.
2. N3-M RED negative cases (within separately approved T0): unknown schema/field, duplicate JSON key, wrong root dev+ino, changed one of server/Workspace grants, runner selection, backend config, expired/revoked consent, owner-generation replay, foreign namespace/lineage, lost entire namespace/witness, missing boot-deny, malformed immutable outcome, fake response before terminal, late event before decision, byte/count quota. No real FS, just strict-memory models.
3. N3-M GREEN only for newly committed source with test identities, relevant old N2 regression and new adversarial permutations executed; cannot inherit N2 B/C PASS and cannot call it product Native qualification.
4. N3-F0/F1 RED/GREEN only **after** separately authorized disposable private-FS T1. Set complete failure injection windows before pending, after pending, after temp fsync, after atomic replace/before dir fsync, after directory fsync/before pending unlink, after pending unlink/before final marker unlink, after marker unlink and on reboot. Must prove conservatism from original bytes and journal before/after; no real process.
5. N3-A legal same-instance real File Write, independently granted real Git apply (may spawn Git, not Native), REST/official MCP status and deny-before-Worker plus owner-lock corruption/second owner; fresh exact-Head SDK and integration evidence only if separately granted.
6. No N3 test may create live Native local operator consent, call RunnerBackend.start_once, touch PID/PGID, send signals, kill processes, stress a shared Mac, run destructive crash/VM, or auto-clear UNKNOWN.

**Specific future RED expected examples:** if record is PREPARED and "response_commit" occurs first, Fake must enter UNKNOWN+global quarantine and emit NO clean success; if a late survivor event wins before a response, no new clean result; if fsync fails after journal replacement, prearmed marker must make next boot DENY; if the whole namespace is deleted while old consent survives, next boot NEVER grants new Native admission. A negative from static scenario rules is only a T0 model conclusion, never physical persistence/OS proof.

## 5. Concrete failure and recovery responsibilities

| Failure boundary | Responsible proposed component | Minimum safe observable outcome |
| --- | --- | --- |
| Owner.lock inode replaced or duplicate owner | N3OwnerLease | Source identity invalid/unavailable; no new grant or record; forensic retention |
| Prior consent/old Git HEAD | N3LocalAuthorityWitness | Only mutable Workspace content may change without epoch; scope/backend/runner change fences |
| Total namespace lost or rollback | Independent lineage authority | If proof missing or inconsistent: no first-install autodetection, fail closed; offline operator decision |
| PREPARED fsync incomplete | N3StateJournal | NO child/Worker; durable uncertainty marker if proven; future boot denies |
| ENOSPC during late event | N3StateJournal | Stop new admission in memory, retain already armed durable restart-deny; report durability of new observation unknown |
| quota/count/byte exhaustion | N3StateJournal | Deny before new intent; no evict UNKNOWN or RETIRED_LIMITED forensic tombstones |
| Response decision vs late event race | N3 short admission gate | Event-first => nonclean; decision-first => immutable historical/as-of only, never transport ACK |
| Cancel/lost response | Worker's future delivery protocol | No replay, no release solely due to client loss; N3 does not implement delivery |
| Incomplete termination/unknown owned group | N4/N5 Native backend (future only) | NO SIGNAL without live authenticated identity, UNKNOWN+quarantine and Native positive NO-GO |
| Unknown production state recovered | Offline operator only | No network reset, no automatic deletion, no "PID absent" shortcut; keep original data |

A mere list of interface names does not show that these operations are implementable, atomic or resilient to an adversarial same-UID process. B/C must critically assess the proof plan and resource design before any code authorization.

## 6. Provenance, regression boundaries and stage-to-stage governance

N3-D source mode COMMITTED_REPOSITORY. GitHub HEAD Tree/Blob/Manifest prove the committed design content only. No current user Mac uncommitted worktree is observed; no actual Python import, SDK, CI worker or filesystem source artifact can be assumed clean. A HEAD vs a synthetic Merge commit must be separately verified even if their Trees match. The N2 B/C source-equal model-copy GREEN can be quoted as historical bounded N2 T0 background but is **NOT** the new N3 source, fsync or T1 PASS.

Additional code must be submitted on a newly authorized branch/Head, with new rNNN review round for every drift. Never extend N3 work by rewriting frozen PR #90–#93. No user approval of this design document confers a test grant, local operator consent, positive Native backend qualification, full descendant cleanup, integration, user Mac/Tunnel, merge/release/deploy or Strict fallback.

## 7. B/C review prompts and stop condition

**B Standards:** independently verify current N3 design against operative D0 §0.1/0.4/3/4/6, actual private_fs.py/exec_state.py/S2/N2 source and immutable Base; attack missing-both-roots rollback, owner.lock ABA, write-ahead marker ordering, directory fsync/ENOSPC, immutable historical response, quota and Git exception. Verify stages do not accidentally authorize physical T1 or Native signals, and every P3 has a future proof/closing gate.

**C Spec:** independently verify typed API authority and record contracts, server/Workspace grant/runner/version changes vs mutable scripts, three identities, owner restart, PREPARED vs revoke vs first dispatch, response decision/late event ordering, v1 and S2 fake migration denial, status/error precedence, legitimate Preview/Git/File, full test cases, recovery and transport ACK semantics. Supply own legal/illegal/boundary/exception counterexamples; do not inherit B's verdict.

**Stop:** Until current new PR's fixed Base/Head/Tree obtains both independent TARGETED DESIGN reviews and a subsequent explicit owner decision, no N3-FS source implementation, no T1/T2/T3, no Native process/PGID/signal, integration, merge/deploy, auto UNKNOWN reset or live Native activation.
