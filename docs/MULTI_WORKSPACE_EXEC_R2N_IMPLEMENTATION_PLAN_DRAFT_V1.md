# R2-N Native Limited - conditional product implementation plan V1.0 (DESIGN ONLY)

**STATUS: PROPOSED FUTURE WORK PLAN. NO PRODUCT IMPLEMENTATION IS AUTHORIZED BY THIS PR. NO LIVE NATIVE EXEC, SIGNALS OR T1/T2/T3.**

- TASK_ID: MULTI-EXEC-R2N-D0-PLAN-DESIGN-20261028
- REVIEW_ROUND: r001 in a new Draft docs-only PR based on PR #91's frozen approved Design Head.
- REVIEW_TARGET: TARGETED D0 Native Limited future amendment wording + detailed staged R2-N product implementation/test plan, including two prior B Standards P3 future implementation gates. No current code or full code review.
- REVIEW_SCOPE: TARGETED DESIGN; companion MULTI_WORKSPACE_EXEC_R2N_D0_AMENDMENT_DRAFT_V1.md; Manifest only.
- GOVERNANCE: ICR-V2.0, GHRH-2.0, ETP-V2.0 E1-E8/T0-T3.
- FROZEN_DESIGN: PR #91 r001 Base 27e675b8f745abc0fb2b1f75f1147d59c876534a / Head b981c6b175fdd4dd467db1c3a9bee45ddc4b31c1 / Head Tree b154aec79c77fddb20478e78fb021ac1b72e035f, B native Review 5678775898, C native Review 5678771116. Both independent TARGETED_REVIEW_PASS for nonoperative contract only.
- OWNER_DECISION_2026_10_28: user approved the precise PR91 design contract and authorized A to WRITE THIS D0 DRAFT and FUTURE IMPLEMENTATION PLAN and request separate B/C design review. They explicitly prohibited positive Native Exec, process signalling, T1/T2/T3, integration, merging and deploying. This approval is NOT source-code authorization, per-instance operator consent or approval to enact the D0 amendment.
- OPERATIVE_CURRENT_D0: docs/MULTI_WORKSPACE_EXEC_RECOVERY_D0_DESIGN.md Blob 6e25904aed9a62bb0f472b732021c2a7ca3b3bb0; F1 plan 76baeb820c6f8a9b067e45e2dcc42e76453fe5b1; Phase1 b3f2383f292a59fd234269389e5338cd50e334a2; G05 76c1c2b8a7947e0b305d55c5f550ab59c638b6d1; R004 bounded Wheel/RECORD 2ffe5341288e428be5ee5d0fa8d52aea3e9efc93.
- REFERENCE_R2S: PR #90 r010 Nonspawning bounded code Head 27e675b8f745abc0fb2b1f75f1147d59c876534a, Tree 2c9fa57e9514ca0146c3fd8b501e14b6f74f9cce. No B/C FULL or integration qualification transfers automatically to future code.

## 0. Product goal, trust promise and explicit exclusions

A future separately approved native_limited profile would let a **locally consenting operator** run trusted, intentionally mutable host-Workspace Direct/Pipenv/Go tools, using only authenticated directly owned child and original process-group limited cleanup, with no claim of full descendant absence or OS sandboxing. The local consent can continue across legal in-root Git/File/script/dependency edits; this is the Candidate A risk model, not revision-pinned source signing.

An unknown survivor, unsafe signal target, lost owner/start ACK, fsync failure or observed detached descendant must fail closed with durable UNKNOWN/global Exec quarantine. An old response, test-grant, old state RETIRED or external caller cannot authorize a retry, false cleanup proof, Native fallback from Strict or reset.

**Actual product behavior remains F1:** shared WorkspaceService.invoke_exec denies all normal dry_run=false absent whole-descendant proof before any Worker/PREPARED/Runner/Popen; safe preview, separately granted Git/File and Legacy path remain unchanged. No schema v2 Native opt-in, live local consent or Native process backend exists in currently authorized production code.

The target is a **plan**, not permission to implement it. T0, T1 and T2 stages listed below are future conditions requiring new explicit user authorization for code and any non-T0 experiment. Status of all new proposed test cases: NOT_RUN.

## 1. Exact current code inventory and dependency boundaries

| Existing source at PR91 Head / Git Blob | Directly observed role | Proposed future dependency (NOT yet approved) |
| --- | --- | --- |
| gateway/workspaces.py / 6d2c0b4087f17bcc543b467b04e405f0e994369d | WorkspaceService.invoke_exec common Worker denies before Runner/PREPARED; info available=false; separately invoke_git | Preserve gate and error precedence. Later add source-reviewed local mode/qualification admission only under effective D0. MUST NOT modify now |
| gateway/runner_seam.py / 1518efccb8e089856defc4a06c39d2dff08610b4 | RunnerCoordinator inert NONE-only; immutable structures; no process backend | Future typed internal Native capability reference and no-spawn Fake must be separate from production proof |
| gateway/r2s_state_s2.py / 89632a1bb4ed1623a87b49e6926fa7f84fcac5e2 | Nonspawning isolated private-FS schema-v2 Fake; consent/owner tokens, offline journals; NOT a product Exec grant | Existing S2 tests are an aid for new state design, NOT a migration-ready or live-authorized state engine |
| gateway/exec_state.py / d3dc2c0ec9dec0a571f768eb6aa15edf5d0153b0 | v1 group-only state, private ownership lock, quarantine and conservative restart | Explicit separately versioned new state namespace and fail-closed downgrade/upgrade; NEVER reinterpret v1 RETIRED |
| gateway/workspaces_config.py / 4ffd1bea9464732266e85d6cee32611317270f49 | Validates only schema_version=1 and rejects unknown config keys | Future locally reviewed mode parser and NO remote grant path; default preview_only and operator consent absent/invalid |
| gateway/executor.py / e578c72f0133bb74e64d03a1cca2c70e133da0a3 | Legacy CommandRunner uses start_new_session and killpg on timeout, no authenticated live group safety proof | Do NOT turn this into a qualified Native backend by reuse, flag or test patch |
| gateway/http_multi.py / 665e2f1956b4626f6ad73e9452e9e5d16706c720 | REST /run calls shared Worker from threadpool | Future separate command/cleanup/delivery serialization AFTER state qualification; must retain actual REST error mapping |
| gateway/mcp_multi.py / 7f457f2da17cd76ddae015c6a01dab4f06f64933 | Official MCP run_command calls shared Worker | Future same bounded decision/response ID without fake client delivery ACK; no second backdoor gate |
| tools/g05_ci_admission.py, tools/ci_dependency_provenance.py, tools/r01_external_source_evidence.py | Current source-admission and scoped CI provenance tools | Re-evaluate exact current Head/Tree and true execution inputs for any new code; R004 verifies 36 locked Wheels and RECORD-listed files only, extra R01 source evidence is an independent named scope |

Exact future code file list is **proposed**, not a promise to edit all these modules or a loophole to expand scope. Interface extraction should be minimal. Git/File subprocess behavior must remain reachable solely by their own grants even while Exec quarantined.

## 2. Stage-gated plan; explicit decision after every stage

| Stage | Proposed deliverable | Future evidence | Before the stage may start |
| --- | --- | --- | --- |
| N0 - THIS PR | Nonoperative D0 exception draft + this plan, two new Markdown files and complete Manifest only | GitHub immutable objects, exact Base/Head/Tree, T0 static source/doc checks; CI original NOT_RUN if [skip ci] | Current user already authorized only these docs/T0 |
| N1 - Authority activation decision | Independent B/C TARGETED design verdicts on N0; user exact-version acceptance and operative D0 source amendment *designated as effective* for a specific next code round | Two native SHA-bound B/C design Reviews plus distinct owner approval and version identity | N0 double review and another explicit user decision; N1 itself does not authorize runtime |
| N2 - Pure source/fake seam | Proposed source-only nonspawning typed consent/epoch/fence/response-decision interfaces and deterministic fault/interleaving T0 tests | New code Head, test-first RED and post-fix GREEN, independent appropriate code B/C reviews | Separate explicit PRODUCT CODE authorization and effective accepted D0; no positive real Exec route |
| N3 - Private-FS state + status | Future isolated versioned state journal, durable prearmed boot fence, resource retention, explicit migration rejection and current fail-closed REST/MCP status, keeping normal dry_run=false denied | New Head T0 + separately authorized non-destructive T1 disposable private-FS/owner.lock/real SDK/Git/File evidence; no Native starts | Additional scoped T1 permission, written fixture inventory and no product/production state migration |
| N4 - Native feasibility/source candidate | Exact macOS ARM64 at-signal identity primitive analysis, independent no-collateral design, future NativeRunner kept unreachable from normal requests until qualified | Source-level architecture/T0; separate T2 exact-resource/native proof cannot be inferred from T0 | New independent design/security/code approval; real Native/process tests remain NO-GO until explicit T2 approval |
| N5 - R3 bounded disposable native acceptance | Bounded Direct/Pipenv/Go, group/survivor/timeout/cancel/crash/restart/identity/race and transport tests, with independent watchdog and recovery | Original macOS 15 ARM64 actual Head+Tree, positive/negative/edge/failure, externally supervised T2 raw Jobs and no collateral signal | User's new exact disposable Mac T2 authorization, owner consent limited to fixture, preapproved signals/termination/rollback and B/C scope |
| N6 - Activation / rollout | Separate mode-specific ordinary product profile, true local owner UI/consent, rollback/observability/unknown recovery and safe release plan | Independently sufficient B/C FULL code review, R10, relevant real integration, user Mac/Tunnel only after T3 approval | Explicit production activation, separate integration/merge/deploy approvals; Strict F3 remains separate NO-GO |

Nothing in N0 or B/C N0 design PASS automatically advances to N1–N6. N2/N3 must not add an externally callable positive path just because there is a Fake. N4 source must not signal or claim a qualification while macOS at-signal ownership is unproven. No two-stage "test consent" may be promoted to product consent. A new code Head/Base and effective contract always starts a new review round.

## 3. Core internal contracts for future source review (not current code)

### 3.1 Consent, authority and scope

- Private local operator consent: explicit profile native_limited, mutable_workspace trust, canonical Workspace and pinned root dev+ino, effective Exec paths/runners and server+Workspace grants fingerprint, reviewed backend identity/config/version, exact risk acknowledgment and supported consent_format_version.
- Persistent consent_epoch increments on issue/revoke/reissue or scope/backend/risk contract changes. It does **not** rotate on legal Workspace source/Git HEAD/Pipenv content changes, deliberately. service_owner_generation rotates with new exclusive owner.lock/restart. attempt_generation/attempt_id are single-use, never authorizations for a different owner.
- A valid persisted consent can survive a clean restart as a record, **but** an armed NATIVE_UNRESOLVED_ON_RESTART fence or old UNKNOWN still denies Native admission until independently authorized offline recovery. Persisted consent is not live execution permission.
- REST/MCP/headers/config v1/env/test-only grants/client fields cannot create, transfer, switch, renew or reset any of these operator authorities. Unsupported configuration or backend version fails closed.

### 3.2 Last prestart and stop/revoke

- Exact qualification, no global quarantine, pinned private state, real owner lock and PREPARED fsync MUST precede any potential first irreversible start. STARTING is durable before dispatch, and actual dispatch-vs-revoke shares a verified, owner-controlled serialization mechanism; simply checking under a mutex then launching later without a race-free guarantee is inadequate.
- Revoke after PREPARED but before first dispatch => exact backend starts=0, fence token, UNKNOWN/quarantine pending reviewed no-start proof. Start dispatch first => at most once and effects possible; revoke blocks new admissions and leads to bounded same-attempt reconciliation or UNKNOWN. Lost ACK, client cancel/retry, worker shutdown/restart never rerun.
- No real OS process call in N2/N3. The live macOS lifetime-bound group signalling and process-ownership mechanism is **unproven** and MUST remain an N4/N5 hard blocker; no old bare PID/PGID plus killpg assumption.

### 3.3 Response decision versus transport delivery (B91-R001-P3-01)

A proposed future **durably recorded response-decision ID** must linearize under the SAME short trusted owner/admission/late-survivor lock as the global quarantine event. Ordering is between (a) durable server decision based on last known bounded cleanup evidence and (b) durable positive late-survivor quarantine latch; the boundary is **not** an SDK response future, socket-write start, queueing event or client ACK.

- Event-first: after RETIRED_LIMITED, quarantine latch durably commits before pending server decision -> NEVER issue a new apparently clean-limited success. Persist a quarantined/cleanup-unknown decision, retaining any historical command outcome separately.
- Response-decision-first: one immutable bounded historical result (attempt/generation/outcome ID, limited scope and as-of sequence) may already be committed before a later event. The event durably supersedes current capability; delayed network delivery cannot claim present health or descendant completeness. Cannot retract an already sent response, and a lost HTTP/MCP response never retries Exec.
- Failures: no durable decision confirmation => no clean success; client cancellation/disconnect is not ACK; slow socket/queue cannot hold the security state mutex for unbounded time. Future code must define committed-vs-enqueued-vs-written-vs-acknowledged provenance and demonstrate the no-stale-success ordering under actual allowed ingress. If it cannot implement this serialized boundary with state durability, Native positive stays NO-GO.

### 3.4 ENOSPC, fsync and restart fail-closed (B91-R001-P3-02)

A proposed **precommitted armed restart-deny fence** is mandatory before first possibly irreversible Native dispatch and must remain durable across every limited retirement, late-event arrival, owner close/crash and next boot unless a separately authorized offline recovery process proves a stronger independent condition.

- N2 Fake verifies last known healthy consent cannot resurrect Native eligibility on restart after failed final fsync or a late event whose journal write could not commit.
- N3 private-FS versioned journal would reserve and fsync a fixed boot-deny marker and bounded emergency-event capacity in a pinned private directory BEFORE launch. If not possible, NO START. Missing/invalid versioned initialized state/marker fails closed, never auto-creates an empty healthy Native namespace.
- A real late-event write fails under ENOSPC: close admission immediately in memory and preserve the already armed on-disk boot-deny marker as next-boot witness; mark event durability unknown; never claim the failed fsync stored the new forensic observation.
- On 4096 record, 4096 bytes/record or 16MiB state budget pressure, stop admitting; never silently evict unresolved or limited-retired attempt attribution just to make capacity. A missed post-archive attribution leads to orphan global quarantine.
- A clean service restart may preserve operator consent as data but requalifies **no** past attempt or new Native Exec while the armed boot fence remains; an operator offline recovery workflow must be separately reviewed and authorized. This conservative user-experience cost is an explicit future design choice for B/C to assess, not a proved current implementation.

Never state "survived disk full and rebooted safely" based only on Python Fake or a mock fsync. Real private-FS crash/durability claims need a distinct T1 resource authorization; power-loss and native signal race proofs remain absent.

### 3.5 Result/status, capacity and cleanup

- Durable phases FUTURE ONLY: IDLE -> PREPARED -> STARTING -> RUNNING -> CLEANUP_PENDING -> RETIRED_LIMITED; any uncertain -> UNKNOWN + global QUARANTINED. Strict-only RETIRED_PROVEN needs whole bounded-domain OS and anti-restore proof; cannot share Native.
- Cleanup evidence is original_group_only plus full_descendant_tree_clean=not_proven; a returned exit code, output EOF, group absence and non-observation of escaped descendants are not complete cleanup evidence. A positively observed detached survivor even AFTER RETIRED_LIMITED fsync/client response/slot release/restart supersedes it and globally stops new Exec.
- Maintain 1 managed Worker per Workspace, 4 per instance (admission concurrency only, **not OS descendant limits**); unresolved potential live-resource reservation and immutable forensic tombstones remain after Worker release.
- /info /health/direct REST/official MCP must agree about current profile, capability and quarantine; disabled -> quarantined -> state unavailable -> missing proof -> busy ordering preserved for valid requests. Until genuine approved Native qualification, available=false, completion_capability=none.
- Valid Preview and independently authorized File Write and Git apply remain intact when Exec missing proof or UNKNOWN; no global subprocess interceptor; Legacy and Local Skills are not re-scoped.

## 4. Prospective falsifiable test matrix; every new row is NOT_RUN

| ID | Future positive/legal assertion | Negative, boundary or exception | Stage and evidence |
| --- | --- | --- | --- |
| R2N-T01 F1 unchanged | Valid preview; /info and /health consistently unavailable/no proof | Both opt-ins + dry_run=false fail before PREPARED/Runner; unexpected busy precedence, client profile spoof or foreign test grant rejected | N2 static/T0, later authorized N3 real T1 ingress |
| R2N-T02 mutable scope | Authorized same-root legal File/Git/Pipenv edit leaves operator consent_epoch stable | Changed root dev+ino, new exec_paths/backend/risk version, revoke/reissue rotates and blocks old attempt | N2 deterministic T0; T1 actual Git/File separately authorized |
| R2N-T03 start/revoke | Prestart revoke (before PREPARED; after PREPARED) => 0 start calls | Start-first then revoke+ACK loss => at most 1 start, never replay; stale owner+token after restart cannot borrow approval | N2 T0 fake only, not host processes |
| R2N-T04 P3-01 event-first | A RETIRED_LIMITED committed, survivor quarantine durably latches BEFORE response decision => non-clean decision | If code computes success before latch and enqueues after latch, detect as invalid NEW success; include waiter cancellation and failed decision fsync | N2 T0 RED->GREEN with controlled event order |
| R2N-T05 P3-01 response-first | Historical limited decision durably commits BEFORE later event; delivery may retain bounded as-of decision ID | Delayed send cannot newly assert healthy current state, full-tree or transport ACK, even if client retries | N2 T0 both-order scheduling; N3 real REST/MCP requires T1 consent |
| R2N-T06 P3-02 owner boot | Armed marker durably precedes all first dispatches; on restart with marker deny despite persisted consent | Failed PREPARED/STARTING/fsync, torn marker, owner epoch ABA, attempted auto-clear -> no positive admit | N2 T0, N3 private-FS T1 if authorized |
| R2N-T07 P3-02 ENOSPC | Prearmed boot marker retained when event journal/fsync fails, new admission stops | Quota full 4096/16MiB, orphan late event, missing reserved marker, crash after partial write -> no healthy reboot | N2 T0; N3 private-FS T1 after approval |
| R2N-T08 late positive | Known positive survivor after A delivered/released => A UNKNOWN, global quarantine, B PREPARED cannot start | B dispatch won BEFORE late latch => already in-flight; no invented prevention, no stale PID signal | N2 T0 fake, real observation T2 not authorized |
| R2N-T09 no-signal | Unknown/stale PID/PGID yields ZERO real signal in code; refuse retired proof | At-signal owner lost, numeric PGID reuse after precheck -> NO SIGNAL/UNKNOWN | N2 T0 signal-trap Fake, N5 T2 only after explicit approval |
| R2N-T10 migration | Existing v1 and offline v2 Fake remain separate/inert; correct absent consent blocks | v1 RETIRED/test grant, foreign lock, corrupt file, mixed schema, downgrade cannot qualify | N2 T0; N3 T1 later authorized |
| R2N-T11 API adjacency | Real authorized Git and File Write work in SAME service even when Exec denied/quarantined | Unauthorized Git/File denied independently; client profile/reset cannot bypass | N3 T1 separately authorized, NO CURRENT RUN |
| R2N-T12 provenance | Frozen Git Head/Tree/Manifest and actual execution inputs precisely verified | Ignored/untracked/import shadow, synthetic Merge mistaken for Head, wheel drift or R004 RECORD-unlisted input declared global proof -> reject unsupported claim | N0 GitHub T0 now; N2/N3 future exact-head original CI |
| R2N-T13 macOS acceptance | Hypothetical proven lifetime-owned Native original-group only under separately approved disposable fixture | Detached/sids/reparented survivors, launch lost ACK, timeout/cancel, check-to-signal race and wrong-owner collateral -> UNKNOWN/no signal | N5 T2 NOT_AUTHORIZED, no fake equivalent |
| R2N-T14 Strict separate | Strict whole-domain domain, terminate, anti-restore evidence if ever separately qualified | Native, group-only, limited consent or lost strict proof cannot fallback to Native | Strict R4/R5 independent NO-GO |

For each actually authorized future code stage: first record exact tested commit, Head Tree, Base and effective diff; test-first RED for new defects when safe, real GREEN/FAIL/SKIP/NOT_RUN per original job logs; independently B/C review adequate scope, user authorization and actual platform identity. An unsafe/native T2 RED is NOT to be rerun for review convenience. No test count targets. Historical PR #90 nonspawning GREEN is background on its own Head, NOT success for any new product Head.

## 5. Independent future safety and platform qualification prerequisites

The existing Python CommandRunner session/group signalling is NOT a safe macOS target identity proof. Before any real Native test or positive route:
- Identify exact macOS 15 ARM64 API/OS primitive (or rigorously equivalent mechanism) providing current, race-resistant signal-target ownership at the instant of a termination request, including PGID reuse/ABA, leader loss, group membership ambiguity and helper generation fencing. If unavailable, NO SIGNAL and Native positive NO-GO.
- Provide a planned T2 fixture inventory: disposable Mac account/host, isolated Workspace+dependencies, bounded executables/argv, process/time/CPU/memory/disk budgets, external independent watchdog, exact stop/cleanup identities, non-collateral verification, rollback and evidence preservation. The user must approve this exact plan and target separately. No user Mac/Tunnel/shared/production inference.
- Distinguish direct-child/original group limited observation from detached reparented setsid/double-fork survivors; positive known survivor at ANY time supersedes limited retirement and globally quarantines. Operator risk acceptance of unobserved residual daemons never proves their absence.
- Direct/Pipenv/Go parity, filesystem side effects, network and credentials are actual host-user effects; they cannot be undone by completing a command. Strict F3 whole-domain closure is a separate D1-D6 feasibility investigation and never has an automatic Native fallback.
- Real REST/MCP and Tunnel integration, production enablement, merge and rollback each require independent user approval and independent B/C code/integration evidence; this design plan has neither.

## 6. Proposed review checklist for THIS design-only PR

**B Standards, independently:** verify exact fixed Base/Head/Tree/new 2-doc diff and Manifest; compare proposed D0 section-specific replacement against currently operative D0/F1; challenge mutable trust and residual survivors; independently construct a revoke-vs-first-start or late-survivor/response-commit counterexample; assess armed persistent boot-fence ENOSPC durability, long-lived forensic tombstones/quotas and no macOS signal primitive. Explain whether future N2-N6 code/resource approval gates adequately prevent accidental positive Exec. Report any P0-P3, ETP E1-E8 and NOT_RUN.

**C Spec, independently:** re-derive shared direct/REST/MCP Worker/error/status invariants, consent/owner/attempt epoch semantics, no-grant and legal mutable edits, v1/v2 migration, three outcomes and as-of response ID; explicitly test policy with event-first and response-first T0 text schedules and failure-window/ENOSPC/restart, pending B start and quota/owner ABA. Check Preview/Git/File/Legacy adjacency and Strict nonfallback; no inherited B verdict. No actual T1/T2/T3 tests.

**Evidence for this Draft:** only new exact GitHub committed text/Manifest/Tree, independently inspectable source code and B/C historical PR #91 approved design (as previous-contract authority, not this round's PASS). Current new Head CI is expected NOT_RUN because [skip ci] prevents auto-running repo workflows requiring T1, and actual GitHub runs must be checked. Neither A nor the two reviewers may describe design-only T0 as current runtime, macOS native, R10, integration or activation PASS.

**After independent B/C TARGETED design reviews:** preserve this precise snapshot. If either finds P0-P2, A may only fix within separately allowed docs/T0 and create a NEW Head and review round with FIX_READY; do not rewrite either role's Review. If both pass, user must approve the fixed amendment and plan and separately authorize any product-code stage. No automatic merge or D0 authority adoption.

## 7. Explicit NOT_RUN and STOP

This round has **no executable behavior change**, no new runnable test or CI Workflow change, no use of host process APIs, no local user/Gateway/Tunnel changes, no production config, no executable schema migration, no new privileged grant or backend, and no release path.

- T0 currently authorized: GitHub source/Tree/file/Manifest identity, static design/contract diff, no host processes or real filesystem mutation beyond GitHub documentation commits.
- T1 NOT_AUTHORIZED and NOT_RUN: even disposable real REST/MCP/Git/File/private-FS and native library integrations.
- T2 NOT_AUTHORIZED and NOT_RUN: macOS process spawn/termination/killpg/PGID probes, forced crash, survivor, watchdog, VM or actual NativeRunner.
- T3 NOT_AUTHORIZED and NOT_RUN: user Mac, Tunnel, shared or production/remote resources.
- Product code implementation, original Head runtime pytest, CI installation/runtime checks, source migration/UNKNOWN clearing, merger, tagging, release, deployment, production profile activation and Strict F3 remain outside user authorization.

**HARD STOP:** the user approved a prior design risk model and permitted only this NEW D0 amendment draft and implementation PLAN. Independent B/C review and another exact-version user authorization are needed before any operative D0/code step. Until then, keep the frozen PR #90 and #91 unchanged and preserve current F1 deny-only installed behavior.
