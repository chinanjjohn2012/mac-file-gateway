# Multi-Workspace Exec — R2-S nonspawning state and coordination plan V1

**STATUS: DESIGN PROPOSAL ONLY; NO R2 CODE AUTHORIZATION, NO POSITIVE EXEC OR NATIVE TESTS.**

- TASK_ID: \`MULTI-EXEC-R2S-NONSPAWNING-DESIGN-20261026\`
- REVIEW_TARGET: R2-S nonspawning state/coordination and migration plan, with explicit Candidate-A Native contract dependency
- CONTRACT_SCOPE: approved D0/F1/Phase1/G05 + R0 design proposal, frozen R1 nonspawning behavior
- RULES: original ICR-V1.0 / GHRH-1.0; V2.0 candidate not formally activated

## 0. Frozen authority and history

- **R1 source**: PR [#82](https://github.com/chinanjjohn2012/mac-file-gateway/pull/82) Head \`0af04817f61e2e45d702daecf9c7a1b1cf310cd0\`, Head Tree \`397de0543d277727a7c20ce180fa1b67d02bc98e\`, Base \`b95414ae0287b66def3fb25853a0a553a9849aca\`. R1 B r002 = \`BLOCKED\`, C r002 = \`ROLE_FULL_SCOPE_PASS\` for bounded nonspawning R1. User excluded B's two general governance/evidence issues from A's product task list; **this does not clear B's verdict or R10**.
- **R0 proposed contracts**: PR [#78](https://github.com/chinanjjohn2012/mac-file-gateway/pull/78) Head \`d502254934961ebe53720fb0708def85db6cd202\`, Head Tree \`b54fb1e875264aa4d046410533f1998d07052359\`. Independent B/C r002 \`TARGETED_REVIEW_PASS\` applies to design documents only, not new product authority. Sources: \`docs/MULTI_WORKSPACE_EXEC_RUNNER_CONTRACT_V1.md\` Blob \`5d9d4d899bea0f921fe731e2ece0eb24e6c9d343\`; architecture Blob \`f83bf9efb87d1cb5698554a427db1af8b0afefe5\`; recovery Blob \`644017dd873bccd3f0671b99a2a9afc8bad9c605\`; test matrix Blob \`21a73076364786be5a1f68aa9624a8dd112778e6\`.
- **Owner direction**: the exact user answer “选择候选 A” is recorded in [PR #78](https://github.com/chinanjjohn2012/mac-file-gateway/pull/78#issuecomment-6414363063). It selects \`native_limited + mutable_workspace\` rather than revision-pinned Candidate B for **future contract design**; it does not create a local Workspace consent record, enact a D0 amendment, authorize actual Native Exec, or permit T2/T3.
- **Current operative sources**: \`docs/MULTI_WORKSPACE_EXEC_RECOVERY_D0_DESIGN.md\` Blob \`6e25904aed9a62bb0f472b732021c2a7ca3b3bb0\`; F1 plan Blob \`76baeb820c6f8a9b067e45e2dcc42e76453fe5b1\`; Phase1 trust Blob \`b3f2383f292a59fd234269389e5338cd50e334a2\`; R004 verifier scope Blob \`2ffe5341288e428be5ee5d0fa8d52aea3e9efc93\`. Current D0 §0.4 remains in force. R004 limited 36 locked Wheel SHA256 + installed RECORD-listed bytes remains unchanged; Candidate A does not waive independent executable-source evidence requirements.

## 1. Disambiguate the two old "R2" labels

| Source | Original meaning | Proposed stage label |
| --- | --- | --- |
| D0 §8 | Private durable intent/admission and restart quarantine, after R1 review | **R2-S** state/coordination; design-only today |
| R0 Runner Contract §6 | Candidate Native Runner code, positive path remains unreachable pending approvals | **R2-N** separate later candidate |
| R0 §6 R3 | Real bounded Native acceptance | **R3** separately authorized macOS experiments |
| R0 §6 R4/R5 | Strict F3 OS-domain qualification / implementation | R4/R5 unchanged NO-GO |

These labels are planning aids, not replacements for D0 or its prerequisites.

## 2. Actual source inventory at R1 Head

| File | Already exists | Proposed, not implemented |
| --- | --- | --- |
| \`gateway/runner_seam.py\` Blob \`1518efccb8e089856defc4a06c39d2dff08610b4\` | Immutable structural Attempt/Command/Evidence; \`RunnerCoordinator.deny_unqualified_apply\` always denies, no real backend | Deterministic offline fake lifecycle and fencing only |
| \`gateway/exec_state.py\` Blob \`d3dc2c0ec9dec0a571f768eb6aa15edf5d0153b0\` | v1 states PREPARED/RUNNING/UNKNOWN/RETIRED; pinned private FD, owner lock, fsync and bounded quota | Separate versioned v2 state/migration contract; do not reinterpret v1 RETIRED |
| \`gateway/workspaces.py\` Blob \`6d2c0b4087f17bcc543b467b04e405f0e994369d\` | No-proof Apply unconditionally raises \`exec_cleanup_proof_required\` before slot/PREPARED/Popen | Keep unchanged until independent product contract and positive backend gate |
| \`gateway/workspaces_config.py\` Blob \`4ffd1bea9464732266e85d6cee32611317270f49\` | schema v1 only; no Native profile or consent | Separate local-only v2 configuration proposal, never implicitly enabled |
| \`gateway/executor.py\` Blob \`e578c72f0133bb74e64d03a1cca2c70e133da0a3\` | Legacy runner validates Direct/Pipenv, original group cleanup not descendant proof | Do not reuse historical Popen/killpg as Native safe-identity proof |

## 3. Proposed R2-S state contract, offline only

1. **Attempt identity and three distinct epochs:** a durable operator **consent_epoch** is incremented only on local approval/revoke/re-approval or binding changes; an ephemeral **service_owner_generation** rotates whenever owner.lock ownership is newly acquired/restarted; a unique **attempt_generation/fencing token** belongs to each attempt and its callbacks. The operator's consent may persist across a safe service restart without inheriting stale owner/attempt authority. Every callback must match the pinned Workspace/root (dev,ino), backend identity, approved consent epoch, current owner generation and exact attempt token. Numeric PID/PGID, timestamps and mutable Workspace source SHA never serve as execution authority.
2. **Ordering and revocation:** a future qualified positive flow needs a held admission lease and fully fsynced PREPARED before any hypothetical allocation/start. Admission, last pre-start validation and locally applied consent/revocation use the same serialized owner-controlled authority; revoke wins before the irreversible start boundary => **NO START**, fence the queued attempt, durably UNKNOWN/global quarantine until independently reviewed no-start closure. Failed fsync/rename, missing lock, unknown ordering, unsupported backend atomicity or changed root/grant/backend => **NO START**; never accept stale consent after PREPARED. R2-S fake is incapable of real host launch.
3. **Single launch:** Fake allocate/start_once/observe/terminate_and_prove/reconcile must bind the same attempt, consent epoch and owner/attempt generations. A durable STARTING record and last local consent/root/backend/owner revalidation must precede the irreversible start_once dispatch; the authorization lock orders start dispatch against local revocation acknowledgement. If start linearizes first, a later revoke cannot undo an already issued irreversible command: deny new admissions, conservatively clean up/reconcile this in-flight attempt or mark UNKNOWN, never misrepresent it as never started. Lost ACK => authenticated observation or UNKNOWN, **never retry** non-idempotent start.
4. **Conceptual future v2 phases (not current code):** IDLE -> PREPARED -> STARTING -> RUNNING -> CLEANUP_PENDING -> RETIRED_LIMITED | RETIRED_PROVEN. Any uncertain persistence/identity/cleanup goes UNKNOWN + globally QUARANTINED. RETIRED_LIMITED is Native-only, full_descendant_tree_clean=not_proven and is **not an absorbing terminal state**: later positively attributed survivor evidence must reopen its forensic attempt as UNKNOWN and latch global Exec quarantine (see §3.2), even after delivery and slot release. RETIRED_PROVEN is Strict-only with separate OS domain proof. No v1 RETIRED auto-migration, automatic UNKNOWN deletion or client-directed reset.
5. **Independent outcomes:** command execution/exit, cleanup observation/proof, response delivery/ack separately. Exit 0, group absence, EOF or HTTP timeout is not full-tree cleanup nor authority to repeat a command.
6. **Capacity and shutdown:** preserve D0 4096 records, 4096 bytes per record and 16 MiB total, one managed Worker per Workspace/four per instance. UNKNOWN is unresolved possible external state even after Worker slot release; 1/4 slots do not bound detached descendants. Retain RETIRED_LIMITED attempt identity + minimal immutable attribution/tombstone for potential late positive observation; **no TTL/quota eviction of unresolved or limited-retired forensic linkage solely to admit more work**. At quota or storage exhaustion stop admission, retain evidence and quarantine rather than silently GC or invent clean proof; any future bounded archival needs separately approved offline procedure.
7. **Real entrypoint invariant:** REST \`POST /run\` and official MCP \`run_command\` share \`WorkspaceService.invoke_exec\`, with stable deny before Worker/PREPARED. Valid Preview, independently authorized real Git apply/File Write remain legal. Legacy Exec/Local Skills are not modified.

**No R2-S mock or any proposed admission predicate may turn ordinary current F1 \`dry_run=false\` into positive Exec.**

### 3.1 Proposed revocation/start linearization (B83-P2-02)

**Chosen policy: no grandfathering for a PREPARED-but-NOT-started attempt.** Future local operator consent issuance/revocation and the backend's first irreversible start dispatch must share a reviewed, same-owner serialized decision point, with local durable consent_epoch and fenced attempt+owner generations. **Before PREPARED:** revoke first means no PREPARED or launch. **After PREPARED, before STARTING/first start dispatch:** the coordinator must reacquire and revalidate the exact local record/root dev+ino, Exec scope, backend identity, consent_epoch, owner lock and attempt generation *at the last pre-start gate*. If revocation or root/scope/backend drift is ordered first, prohibit allocate/start, fence the attempt, record a conservative UNKNOWN/quarantine pending offline no-start evidence; no automatic replay or clean RETIRED.

**Start-first race:** only if the authorized irreversible start dispatch has already linearized before the durable local revocation may a command already be in-flight; revocation must wait/serialize, then deny subsequent dispatch and admission, conservatively reconcile/cleanup the in-flight attempt, and quarantine it on lost ACK or uncertain results. A revocation acknowledgement cannot recall an already issued OS side effect. Do not claim that a userspace check and separate platform process spawn are inherently atomic; a backend lacking a supported ownership/serialization/identity guarantee stays NO-GO. If storage/lock fails during this ordering, never choose a positive path. An out-of-band file mutation that bypasses the reviewed local consent mechanism cannot count as a safe linearized authorization change; reject/fence on detection and require operator review.

**T0 future cases, NOT_RUN:** (a) revoke wins before prepare => 0 starts; (b) revoke after fsynced PREPARED before dispatch => 0 starts, UNKNOWN/quarantine with fixed token; (c) start dispatch wins first then revoke/ACK lost => at most one attempted start, admission closed, reconcile or UNKNOWN, never double start; (d) old consent_epoch, owner generation or attempt token after restart/ABA => cannot start/finalize; (e) legal mutable Workspace revision change without scope/backend change preserves consent.

### 3.2 Late positive survivor after RETIRED_LIMITED (B83-P2-01)

A future limited retirement records **only original-group-limited evidence** and an immutable attempt+consent+owner/backend/root attribution key. It must retain a forensic minimal tombstone even after response delivery, slot release and otherwise clean limited retirement. A later independently authenticated **positive observation** of an attributable surviving detached child — minutes or restarts later — **supersedes** the old limited claim: immediately close new Exec admission; under the same serialized owner/admission authority durably latch **global QUARANTINED**, append bounded late-survivor evidence, and reclassify the old attempt from RETIRED_LIMITED to UNKNOWN with provenance to the earlier completion. A late event does not magically retract an already delivered response, erase the original evidence, promote to Strict, or authorize a stale-PID/PGID signal.

If admission for attempt B races this observation, the durable latch and B's **last pre-start gate** use the same serialization: observation first => B must NOT start (even if B has PREPARED); start-first B is already in-flight and must be conservatively reconciled/quarantined, not falsely counted as prevented. Future request admission is denied until independent operator-approved offline resolution. Known surviving descendant is a hard block whether the original group was present or long absent.

**Retention/GC:** retain retired-limited attempt identity and minimal attribution/tombstone subject to the existing finite private state quotas, without silent TTL deletion or re-use of the attempt ID. At cap, **fail closed/quarantine rather than evict attribution to make capacity**. If a historic record was pruned under an independently approved later policy, or identity is insufficient to safely attribute the new observation, persist an orphan/uncertain late-evidence marker plus global quarantine; **do not** claim a specific process can be signalled or a clean attempt can remain accepted by default. If the latch/event cannot be durably written or checked, mark Exec state unavailable/quarantined and prohibit all new admission across restart; no optimistic recovery. No host process observation, signal or T2 test is claimed by this design.

**T0 future cases, NOT_RUN:** late attributed positive survivor after limited retirement+delivered result+released slot; late callback after restart; orphan evidence after independently approved record archival; 4096-record quota pressure; B PREPARED but not started versus B already dispatched; fsync failure during quarantine latch; known survivor with group absent. Assert zero **new** start after the quarantine latch, preserved earlier completion audit and no automatic clean reset.

## 4. Candidate A consent dependence and hard Native stop

Future local-only consent binds profile=native_limited, trust_scope=mutable_workspace, Workspace/root dev/ino, effective Exec command/path/runner grant fingerprint, backend identity/version, exact risk acknowledgement and **persistent consent_epoch**. The current service owner generation and per-attempt generation are distinct ephemeral credentials, never stored as a long-lived local approval. Local consent changes increment/fence consent_epoch; operator approval can outlive a clean service restart but stale callbacks cannot. Verify consent at admission, **immediately before irreversible start**, and finalization, not solely after command execution. Authorized Workspace byte, Git HEAD and Pipenv changes do not auto-revoke; expanded grants, changed root/backend, missing approval, revocation or incompatible state/backend implementation version deny. No REST/MCP grant or reset.

An observed detached child ALWAYS => \`UNKNOWN\`/global quarantine, even if original group is absent; not observing a child never proves it does not exist. No clean Native retirement unless the directly owned leader and original group are authenticated absent and no detached survivor was positively seen **under the separately approved Native limited contract**. No group signal if target is not race-resistently bound at signal time; a PID/PGID check followed by \`killpg\` is insufficient. No signal experiment or positive Exec until exact approval and T2 evidence.

## 5. Future batches and approval gates

| Batch | Candidate deliverable | Testing | Hard stop |
| --- | --- | --- | --- |
| **S0 — this PR** | Propose D0 exception wording, R2-S FSM, traceability and tests | Read-only docs/Manifest and CI if run | No runtime/config/schema change or positive Exec |
| **S1 — later** | Pure offline mock state/evidence/fencing and consent model | T0, no subprocess | Requires accepted R2-S scoped design and applicable R1 disposition |
| **S2 — later** | Disposable private FS state/migration and nonspawning coordinator tests | T0 + non-destructive authorized T1 | Real REST/MCP remain hard-deny, no live state migration |
| **R2-N** | Native Runner candidate with independently qualified live target identity | Separate authorization and code reviews | No positive route without effective D0 amendment and owner consent |
| **R3** | Real Native Direct/Pipenv/Go, cleanup/crash/watchdog acceptance on disposable macOS ARM64 | T2 only if independently authorized | No user Mac, Tunnel, shared/production T3 |

R0 design B/C TARGETED PASS, current R1 C ROLE_FULL_SCOPE_PASS, CI GREEN and user's Candidate-A direction do not jointly provide R1 R10 or positive-mode activation. For new R2 code, freeze a different Head/Base/Tree and request independent full-scope B/C code reviews. Stage-based grouping reduces intermediate review events, never scope or evidence.

**This PR is DOCUMENTS + Manifest ONLY. NOT_RUN:** new R2 T0/T1 code (not implemented), real Native Runner/process/group signal/VM, T2/T3, current user Mac/Tunnel, release/integration. No merge/deploy/tag/config or UNKNOWN reset.
