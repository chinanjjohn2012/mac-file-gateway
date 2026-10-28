# R2-N Native Limited - Candidate A product contract for independent DESIGN review (V1.0)

**STATUS: NONOPERATIVE DESIGN CANDIDATE. No D0 amendment is effective; no Native positive Exec, process signalling, T1/T2/T3 experiment, product implementation, integration, merge or deployment is authorized by this document.**

- TASK_ID: MULTI-EXEC-R2N-NATIVE-LIMITED-DESIGN-20261028
- REVIEW_TARGET: exact R2-N native_limited + mutable_workspace DESIGN contract; D0 exception text, local owner consent, macOS process identity, state/response/recovery and T0-only acceptance predicates.
- REVIEW_SCOPE: TARGETED DESIGN (this document, the companion R2-N design/test matrix and Manifest). Not a code FULL, R10, F3 feasibility, Native activation or integration.
- RULESET_ID: ICR-V2.0; HANDOFF: GHRH-2.0; EVIDENCE_PROFILE_ID: ETP-V2.0. V2 first formally effective for PR #90 r010, not retroactively for older design reviews.
- SOURCE_BASELINE: frozen PR #90 r010 Head 27e675b8f745abc0fb2b1f75f1147d59c876534a, Tree 2c9fa57e9514ca0146c3fd8b501e14b6f74f9cce. PR #90 remains untouched and unmerged. The new PR must independently record its own Base/Head/Tree.
- OWNER_AUTHORIZATION_2026_10_28: A may finalize R2-N DESIGN documents and perform non-dangerous T0 static design checks ONLY. The owner explicitly prohibited positive Native Exec, process signals, T2/T3, integration, merge and deploy, and requires independent B/C DESIGN reviews plus a further explicit owner approval before product implementation.

## 1. Authority, provenance and precedence

**Current operative product authority is unchanged:**
1. docs/MULTI_WORKSPACE_EXEC_RECOVERY_D0_DESIGN.md, Git Blob 6e25904aed9a62bb0f472b732021c2a7ca3b3bb0; especially D0 sections 0.1, 0.4, 2.1, 3-7J and 8.
2. docs/MULTI_WORKSPACE_EXEC_PRODUCTION_FIRST_IMPLEMENTATION_PLAN.md, Blob 76baeb820c6f8a9b067e45e2dcc42e76453fe5b1.
3. docs/PHASE1_LOCAL_TRUST_BOUNDARY.md, Blob b3f2383f292a59fd234269389e5338cd50e334a2.
4. docs/GITHUB_G05_CI_ADMISSION.md, Blob 76c1c2b8a7947e0b305d55c5f550ab59c638b6d1; docs/MULTI_WORKSPACE_EXEC_F1_G05_INTEGRATED_RC.md, Blob 2ffe5341288e428be5ee5d0fa8d52aea3e9efc93. R004 remains 36 source-locked Wheels plus installed RECORD-listed bytes ONLY, with CI_UNLISTED_IMPORTABLE_FILES=NOT_ASSESSED.

**Fixed historical PROPOSALS, NOT operative D0 amendments:**
- PR #78 r002 Head d502254934961ebe53720fb0708def85db6cd202, four Runner R0 design docs; B/C independent TARGETED design PASS, not implementation/activation. Candidate A future-mutable Workspace owner choice recorded at PR #78 issuecomment-6414363063.
- PR #84 r002 Head 638f7723f523f6d38bf0737ce61d1971abec4e76, three S0/D0-exception design texts; B/C independent TARGETED design PASS for proposal only. The proposed exception Blob f4153acfdbf2d59a20c0241f9d37c39416e14a49 is not current D0.
- PR #90 r010 B/C ROLE_FULL_SCOPE_PASS and A R10_STATUS=ELIGIBLE apply ONLY to S1 pure-memory and S2 disposable private-FS NONSPAWNING bounded M1-M4, inherited F1 default-deny and R01/G05 evidence. No positive Native/F3 scope.
- PR #77 F3-D0 independent Standards feasibility BLOCKED; C targeted design PASS is not Strict containment proof.

This text resolves/extends the R0/S0 proposals as a NEW contract for independent review, but is not a silent replacement of their original source or reviews. Until a separate owner-approved operative D0 amendment, F1 section 0.4 wins every conflict. In particular, user approval to start this DESIGN round is not owner acceptance of an executable runtime exception.

## 2. Proposed exact D0 exception wording (future amendment; not active)

**Proposed D0 section 0.1 exception addendum**: Ordinary Multi-Workspace Exec remains preview_only, with valid dry_run=true Preview and unconditional dry_run=false denial without full-descendant proof before any Worker slot, PREPARED, Runner, Popen or backend allocation. Existing server and Workspace Exec opt-ins grant request eligibility, never proof. A future, independently authorized profile named native_limited MAY be offered only by separately qualified code, a supported reviewed local profile/schema version and a fresh local operator consent bound to that Workspace and backend. A request cannot select or mint the profile or consent. Merely adding a profile field, setting both opt-ins, or loading a test grant NEVER unlocks positive execution. Existing error precedence and Git/File independence remain.

**Proposed D0 section 0.4 bounded exception**: The full-descendant cleanup requirement remains mandatory for strict_f3. A separate native_limited profile for trusted operator-approved mutable host Workspace code MAY, after its own product-code and native evidence/authorization gates, use the narrower guarantee of an authenticated direct-child reap plus authenticated original-process-group absence, and explicitly records full_descendant_tree_clean=not_proven. It does NOT guarantee no escaped/daemonized/reparented descendant, isolation, rollback or host credential safety. A POSITIVELY OBSERVED detached survivor, including a late observation after a limited completion, ALWAYS causes durable UNKNOWN and global QUARANTINED and prevents new Exec. Merely not observing a survivor never proves its absence. If safe live ownership/group identity and at-signal safety cannot be demonstrated on supported macOS, there is NO qualified Native positive path and F1 denial remains.

**Proposed D0 sections 2.1/3-7J/8 preservation**: The existing test-only original-group grant NEVER becomes a production capability; no client can grant/renew/revoke Native consent or remotely reset. Preserve pinned private FD/owner.lock, exact durable intent and fsync sequencing, fail-closed boot, no replay, global UNKNOWN, state quotas and File/Git independence. Introduce separate versioned Native evidence and forensic records only in separately reviewed future code. Old v1 RETIRED or test-grant evidence is never promoted to Native/F3. R2-N code, R3 macOS T2 tests and release each need separate authorization; this DESIGN document authorizes none.

The eventual D0 amendment must cite its exact accepted source/owner approval and be independently reviewed as a NEW fixed snapshot. No modification to the currently operative D0 file is part of this PR.

## 3. Trust model and user-visible risk disclosure

The chosen design is **native_limited + mutable_workspace** (Candidate A), not revision-pinned Candidate B. It intentionally trusts future changes to the whole approved Workspace and the actual host Direct/Pipenv/Go runner and reachable local dependencies. Otherwise authorized File Write, Git changes, script/Pipenv and source revisions can change bytes run later and DO NOT automatically revoke consent while the approved root, effective Exec scope, backend and risk version stay unchanged. This is a conscious trust choice, never source signing, per-person attribution or an OS sandbox.

Required readable owner acknowledgment before any future local consent:
- Commands execute with ordinary Gateway OS-user privileges. Allowlisted entry commands do not sandbox child filesystem, credentials, network or further process creation.
- Independently authorized File/Git writers and same-user code writers can indirectly change later executable behavior within the mutable scope; individual humans are not authenticated by a Workspace name.
- Leader exit, process-group absence, signal success, exit status, stdout EOF or Gateway restart never prove complete descendants absent. Detached processes may persist and accumulate across repeated limited retirements. A known survivor forces a global Exec shutdown.
- Timeout, cancellation and Gateway crash cannot undo already-issued file, database, Git or network effects. Result delivery loss never permits command replay.
- No promise of arbitrary code isolation, enforced total OS-descendant cap, or automatic reset/recovery. Strict F3 requires its own OS-enforced domain proof.

No broadening of Phase1 local OS user threat model is implied. Risk acceptance by the project owner for design exploration is NOT a per-Workspace, instance-local operator consent.

## 4. Future local-only consent and identity contract

A future consent record is *conceptual only*, not accepted by current schema v1 and not executable configuration. Mandatory immutable/bound fields:
- consent_format_version; profile exactly native_limited; trust_scope exactly mutable_workspace; displayed risk-contract version/hash and explicit operator acknowledgment.
- canonical Workspace identity and pinned root (dev,ino); effective server+Workspace Exec grants, allowed exec_paths/runners/permission fingerprint; installed reviewed backend implementation identity/version/config fingerprint; operator issue/revoke state and optional expiry.
- persistent, monotonically fenced consent_epoch; **separate** ephemeral service_owner_generation for each new owner.lock acquisition/restart; fresh unique attempt_generation and attempt_id for each attempt.
- persistent consent cannot derive from a client request, REST/MCP message, CLI argument, environment variable, test factory, mutable local Workspace file, Git HEAD or an inferred PID/PGID.

**Authority transitions**: approved local grant issue/revoke/re-issue and relevant root/exec-scope/backend/risk-version changes advance consent_epoch under held owner-controlled serialization and durable fsync. Legal source/Git/Pipenv content edits do not change it. A clean Gateway restart may preserve still-valid operator consent, but MUST rotate service_owner_generation and reject all prior-owner callbacks and attempts. At any mismatched/unsupported record/identity/scope/backend/epoch, reject and conservatively fence. A stale callback may never adopt newly reissued consent.

**No remote consent**: no REST, MCP, public config override, request field, header, command-line flag, test grant or untrusted environment can create, upgrade, bypass, reset or remotely recover consent. Private operator file/record changes outside the reviewed local mechanism do not count as valid linearized approval; detected mutation invalidates authority and can quarantine unresolved attempts. Any future operator editing procedure and secure persistence permissions need their own reviewed implementation design, not invented in the present v1 config.

## 5. Admission, durable lifecycle and revoke-before-start

Future transitions: IDLE -> PREPARED -> STARTING -> RUNNING -> CLEANUP_PENDING -> RETIRED_LIMITED; on uncertainty -> UNKNOWN with globally latched QUARANTINED. RETIRED_PROVEN belongs ONLY to independently qualified strict_f3, and cannot be reached through a Native backend. Every transition must be durable and linked to its attempt, consent epoch, owner generation, backend and pinned root. Existing S2 offline-fake state is NOT a live start authority.

Proposed positive-branch predicates (not implemented):
1. Existing direct/REST/official MCP shared WorkspaceService.invoke_exec applies normal Workspace, command, cwd, runner and grant checks, and rejects disabled/quarantined/unavailable before any future proof or slot. With no separately qualified Native backend+effective local consent, it returns exec_cleanup_proof_required before slot or transient PREPARED.
2. For a future qualified backend only: acquire the bounded lease (one Workspace / four instance managed Workers), verify owner.lock and pinned private state, consent/root/scope/backend/risk version; atomically commit+fsync PREPARED BEFORE backend allocation or any potentially irreversible launch.
3. Record and fsync STARTING and re-check exact consent_epoch, service_owner_generation, attempt_generation, Workspace root/Exec scope/backend and global quarantine immediately before first irreversible start. Local consent revocation, the last pre-start gate and the actual start-dispatch linearization MUST share a proven serialization/ownership mechanism. A userspace check followed by an independently scheduled spawn is NOT an atomic proof. Until such mechanism exists, NO START.
4. **Revoke wins before PREPARED**: no new intent or launch. **Revoke wins after PREPARED but before first dispatch**: zero starts, fence old token, durably UNKNOWN/global QUARANTINED pending separately reviewed no-start reconciliation. PREPARED is not grandfathered approval.
5. **Start wins before revoke**: acknowledge irrevocable possible side effects; revoke closes further starts/admissions, reconcile only the exact owned in-flight attempt or conservatively UNKNOWN; lost ACK/timeout/cancel cannot send a second start.
6. Observe command, owned leader and group cleanup separately, hold the Worker lease to durable RETIRED_LIMITED or UNKNOWN; release in-memory slot only after durable finalization. An unresolved potential external resource persists in separate accounting even after slot release.

Never use numeric PID/PGID, timestamps, mutable Workspace Git SHA or a stale test-grant identity as a live launch, signal or cleanup authority. If storage commit, owner identity, serialization or backend qualification is uncertain, fail closed without launching.

## 6. macOS ownership, group proof and signal safety: unresolved HARD NO-GO

The existing gateway/executor.py start_new_session + leader.wait + killpg logic is NOT accepted as a reviewed Native target identity or descendant proof. Historical process-group observations do not establish live ownership at signal time: check-to-kill races can target an unrelated reused PGID.

Before *any* separate Native positive code activation, identify a supported **macOS ARM64 platform primitive or rigorously equivalent mechanism** that binds the correct group/leader target to an authenticated owned execution lifetime at the actual attempted signal. Specify the OS API, lifetime semantics, reuse/ABA prevention, owner-generation fencing, signal target and teardown observation; then independently validate the no-collateral-signal property under a separately authorized T2 disposable host setup. No such mechanism is claimed proven in this DESIGN document. If it is unavailable or loses identity, send NO SIGNAL, persist UNKNOWN/global quarantine, and keep positive Native mode NO-GO. Never run killpg or a process probe as a T0 test.

A qualified Native outcome may prove only directly reaped leader and original process-group absence at an authenticated bounded observation. It CANNOT prove absence of setsid, double-fork, daemonized or reparented descendants, cannot turn a detached survivor observation into success, and cannot establish strict_f3 D1-D6 containment. Native Limited is not a secure default for arbitrary or untrusted projects.

## 7. Known/unknown survivors, late events, forensic retention

**Limited retirement qualification (future)** requires: correct locally approved Native consent, same durable owned attempt and live target identity, directly reaped leader, authenticated original group absence, no POSITIVELY OBSERVED detached survivor, bounded cleanup/drain and successful final persistence. It stores phase=RETIRED_LIMITED, cleanup_scope=original_group_only, full_descendant_tree_clean=not_proven. Lack of an observed survivor is not evidence no survivor exists.

A later *independently authenticated positive* attributable survivor observation **at any time** (including after fsync, HTTP/MCP response and Worker release, or after restart) supersedes the earlier limited claim. Serialize the global latch against other attempts' LAST pre-start gates: durably latch global QUARANTINED, append bounded observation without secrets, reclassify attempt to UNKNOWN and link the prior completed result. Do not fake retraction of a previously delivered response. If B has PREPARED and survivor event wins, B cannot start; if B already dispatched first, do not claim its effects were prevented, reconcile it or UNKNOWN. Insufficient attribution means conservative orphan/uncertain quarantine, NEVER a guessed PID signal.

**Critical result race (B84-P3-01)**: after A fsyncs RETIRED_LIMITED but BEFORE its result is committed to REST/MCP transport, if a positive survivor has already latched global quarantine, do not send a newly minted clean/current limited-success response. Report current quarantine/cleanup uncertainty and retain the prior command outcome. If response commitment occurred first and the event arrives later, keep the historical delivered limited outcome, link its supersession and correct future global status; it cannot be recalled. A pending transport waiter never owns or weakens the durable state gate.

Retain minimal attempt+consent+owner/backend/root attribution tombstone even after limited response/slot release. No TTL or quota-driven eviction of unresolved or limited-retired forensic identity solely to admit more work. At 4096 records, 4096 bytes/record, 16 MiB state budget exhaustion, stop admitting and durably quarantine rather than sacrifice linkage. If later separately approved archival removes attribution, positive uncertain late evidence still latches orphan quarantine. If the latch cannot fsync, Exec state becomes unavailable/quarantined across restart; no silent healthy boot.

## 8. Schema/migration/recovery and adjacent paths

The current on-disk ExecStateStore is v1 PREPARED/RUNNING/UNKNOWN/RETIRED and the separate gateway/r2s_state_s2.py is offline/nonspawning v2-fake evidence only. Neither is authority to upgrade existing v1 RETIRED, group-only marker or copied state into Native consent. Future v2 production schema, explicit downgrade/upgrade, late tombstone behavior and local offline recovery need separate code review and safe migration contract. Unknown/mixed schema, unsupported backend/state version, copy/old owner, unresolved journal or missing lock => Exec denied and forensic evidence preserved. Never auto-unquarantine, delete UNKNOWN, replay commands or reset over REST/MCP.

Report command result, cleanup result and delivery result independently. An exit code of zero and an ACK are neither cleanup proof nor evidence of no detached survivor. Native may someday report completion_capability=native_original_group_limited and full_descendant_tree_clean=not_proven; default current F1 MUST report available=false / completion_capability=none. No Strict fallback to Native, test-grant promotion, client-selected profile or public reset.

Keep status/error precedence for applicable valid requests: exec_disabled -> exec_quarantined -> exec_state_unavailable -> exec_cleanup_proof_required -> busy. Preserve true malformed-argument validation semantics, bounded preview and independent legally authorized real Git/File operations even under Exec denial/UNKNOWN. No global subprocess interception; Legacy Exec and Local Skills are out of change scope.

## 9. Required next gates (none supplied by this design alone)

1. New fixed Base/Head/Tree docs-only TARGETED B Standards and C Spec reviews under effective ICR-V2.0/GHRH-2.0/ETP-V2.0. Each must independently challenge the D0 exception, mutable trust, consent/revoke race, post-retirement response race, OS signal identity, fake-vs-native evidence, recovery and strict nonfallback. A does not author either Review.
2. Owner explicitly accepts or rejects THIS fixed Native Limited contract after B/C targeted design results. Design review and the owner's current permission to WRITE DOCS do not constitute runtime activation.
3. If separately approved, propose a separately reviewed operative D0 amendment and implementation plan, with exact version, future code task, off-by-default migration and tests. No runtime or config/schema changes before that approval. Any unresolved old review applicability must be re-evaluated rather than inherited.
4. Only after further approval may a future R2-N product implementation candidate be written, retaining no externally reachable positive path pending backend evidence and new B/C code reviews. A fake or T0 design does not prove macOS process safety.
5. R3 native macOS actual start/terminate/signal/crash/daemon cases require separate precise disposable resource inventory, watchdog, no-collateral termination proof, budgets, recovery, owner T2 authorization and independently assessed implementation. T3 current user Mac/Tunnel/shared/production is separately NO-GO.
6. Full code R10, integration, merge/release/deploy and enabling positive Exec each have independent scope and authorization. No stage automatically grants the next.

**NOT_RUN / NOT_AUTHORIZED this round**: any new runtime pytest, REST/MCP/Git/File integration, Native positive Exec, actual child/PID/PGID/signal/killpg, crash/VM, T1/T2/T3, user Mac/Tunnel, shared/production migration, UNKNOWN reset, production config and release. Only non-dangerous T0 static design validation and document/Manifest identity checks may be performed.
