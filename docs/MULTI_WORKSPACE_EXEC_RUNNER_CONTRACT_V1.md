# Multi-Workspace Exec — Runner Dual-Contract Proposal V1.0 (R0)

**STATUS: DESIGN PROPOSAL ONLY / NOT CURRENT PRODUCT AUTHORITY / NO POSITIVE EXEC AUTHORIZATION.**
**TASK_ID:** MULTI-EXEC-RUNNER-CONTRACT-20261026.
**REVIEW_ROUND:** r002 proposed after completed r001 B/C BLOCKED. The old r001 Head/Reviews remain unchanged. This revision is a fresh code snapshot, NOT yet independently approved.
**SOURCE:** PR #76 fixed Head 0fc1ae245de7cb582a69162c79c201d15bfaa258, Tree e05777c0bc6eea0b375a6347602b99c68024b3b6; PR #77 independent research Head c9b625e322697175887a4cedf23bc191dd8a91c3 is background evidence, **not** this branch's ancestor or inherited PASS.
**AUTHORITY:** At source Head, docs/MULTI_WORKSPACE_EXEC_RECOVERY_D0_DESIGN.md (Blob 6e25904aed9a62bb0f472b732021c2a7ca3b3bb0), docs/MULTI_WORKSPACE_EXEC_PRODUCTION_FIRST_IMPLEMENTATION_PLAN.md (Blob 76baeb820c6f8a9b067e45e2dcc42e76453fe5b1), docs/PHASE1_LOCAL_TRUST_BOUNDARY.md (Blob b3f2383f292a59fd234269389e5338cd50e334a2), docs/MULTI_WORKSPACE_EXEC_PRODUCT.md (Blob a86ee5e36a30f7d731e7f33a70602210a465f5c8), docs/MULTI_WORKSPACE_EXEC_F1_G05_INTEGRATED_RC.md (Blob 2ffe5341288e428be5ee5d0fa8d52aea3e9efc93).
**RULES:** Current governing original Independent Code Review Rules V1.0 / GitHub Review Handoff V1.0 and applicable previously approved project security rules. ICR-V2.0 / GHRH-2.0 / ETP-V2.0 may be added as candidate review discipline but are NOT formally effective without independent rule approval, exact-version user approval and three-Project source synchronization.

## 0. Explicit proposed contract change; conflicts and non-authority

The current approved F1 contract in D0 section 0.1 and its future-positive section 0.4 require complete-descendant cleanup evidence before **any ordinary non-preview Multi Exec**. The present product in gateway/workspaces.py denies all dry_run=false requests with exec_cleanup_proof_required before Worker/Runner/PREPARED, even if both switches are enabled. This behavior MUST remain unchanged in this R0 PR, R1 interface refactor, and until a separately reviewed NEW product contract plus explicit user activation authorization exists.

This proposal requests a **bounded change to the future product requirements**, not a reinterpretation of the existing D0 or historical verdicts:
- Continue full descendant proof as a mandatory requirement for a new mode named strict_f3.
- Consider a separately named native_limited mode that can execute only *trusted locally approved project code* while explicitly providing **limited** process-group cleanup, no complete-descendant guarantee, and conservative durable lifecycle.
- Product owner must explicitly accept the narrower risk contract. B Standards and C Spec must independently assess it against the existing D0, system trust model, practical failure modes and user-facing terminology. A design PASS alone is NOT permission to enable native_limited.
- If this bounded contract change is not approved, native_limited remains an unimplemented design and the existing entire positive Exec gate stays NO-GO. No authorization to bypass the old D0 section 0.4 can be inferred from this proposal.

No security contract change is made by merely adding these docs. No implementation, config parser changes, test grant, production flag, host signal, Native C, VM allocation or actual apply is included in R0.

### 0.1 Explicit D0 amendment map — no automatic override

The left-hand rules below are **current inherited authority**, not silently superseded. The right-hand Native column is a **proposed future, separately approved exception**; until written user approval, independent same-Head B/C review and a separate implementation/activation authorization, existing F1/default-deny wins.

| Inherited D0 location | Existing mandatory guarantee | Proposed future Native Limited disposition (not effective) |
| --- | --- | --- |
| §0.1 and F1 plan §§1/4 | Ordinary dry_run=false without full-tree proof rejects before slot/Runner/PREPARED | Preserve entirely in R0/R1 and current product. Only an explicitly selected and approved new mode could later use different admission |
| §0.4 | Positive ordinary Multi Exec requires complete descendants cleanup proof | Propose a named **native_limited** exception ONLY for trusted mutable host Workspace with no F3 claim; strict_f3 retains full-tree requirement |
| §2.1 | Private test-only group grant never becomes production authorization | Preserve; proposed Native would require an independent reviewed operator grant/backend identity, never reuse, serialize or expose test grant |
| §3 | fsynced intent, private pinned FD, owner.lock, finite quotas, fail-closed boot scan | Preserve; versioned schema-2 profile/evidence migration requires separate review; v1 group-only RETIRED never proves full tree or authorizes Native |
| §4 | qualification + lease + PREPARED before Popen; no replay | Preserve all ordering. A Native limited admission would also require explicit operator risk consent and live identity-safe cleanup qualification |
| §5 | **positively observed detached survivor => UNKNOWN + global quarantine**, even under test grant | **Preserve unconditionally.** No Native RETIRED_LIMITED for a known surviving detached process. Only *not positively observed*, with leader+original group proven absent under authenticated observation, may become future RETIRED_LIMITED, still NOT F3 |
| §6 | honest status, error priority, no remote unquarantine | Preserve through R0/R1; propose new distinct capability name native_original_group_limited only for reviewed future backend; NEVER label full_tree_qualified |
| §7J | known detach/failed group evidence/uncertain state cannot retire or clear quarantine | Preserve for Native. The proposed exception never weakens the known-survivor prohibition, even if user accepts mutable Workspace and unknown background-child risk |

A new D0 amendment PR and exact-version owner decision are mandatory **before** changing the operative safety contract in product code. A design-only verdict may approve investigating or implementing a non-runnable seam, not real Exec.

## 1. Three product profiles (separate proof and release criteria)

| Profile | Purpose | Execution guarantee | Admission |
| --- | --- | --- | --- |
| preview_only | Existing F1 Preview | Validated dry_run=true is safe; all ordinary dry_run=false denied | Existing approved behavior, default |
| native_limited | Host-native direct / Pipenv / Go for trusted operator-selected projects | Confirmed direct child and original process group management only, with complete tree explicitly **not proven** | Future independent product-contract approval, implementation/code review, scoped macOS acceptance and explicit activation approval |
| strict_f3 | Whole OS-enforced execution-domain closure | Every member within a bounded domain cannot outlive authenticated completed teardown, with recovery and anti-restore protection | D1-D6 qualified backend, T2 native proof, separate full independent reviews and activation approval; **NO-GO currently** |

A profile identifies the **security contract**, not a client-selectable backend. Strict failure NEVER falls back to Native. A public request cannot set profile, cleanup qualification, evidence level, test grant, reset, or an internal backend identifier.

### 1.1 Native Limited product warning (mandatory, prominent)

- Only project code trusted by the local operator; this is NOT a sandbox for untrusted scripts.
- Commands inherit the Gateway OS user's ordinary privileges. Exec-path allowlists constrain API-initiated path/command selection; they do NOT confine child filesystem access, shell-less process creation through scripts, network effects, local services, credential access or other already-existing host resources.
- The Runner attempts to manage the directly owned leader and its original process group; a setsid/double-fork/daemonized/reparented descendant can survive and cannot be certified absent by leader wait, killpg, PGID scan, heartbeat silence or output EOF.
- Execution may have irreversible side effects even if timeout, cancellation or a crash occurs. A successful exit_code does NOT establish cleanup. A complete group-scoped observation does NOT establish complete-descendant cleanup.
- The user must use appropriately limited trust and credentials. Real Home, shared services, production tokens and arbitrary scripts are not appropriate default test targets.
- On ambiguous state durability, group identity or group cleanup: UNKNOWN/global Exec quarantine, evidence retained, no response replay, no remote reset, no stale-PID signal after crash.

**Do not name this mode safe sandbox, isolated, full_cleanup, F3, descendant_proven or equivalent in API, help, docs or telemetry.**

### 1.1.1 Proposed code-trust scope: explicit mutable Workspace (OWNER DECISION PENDING)

**Chosen R0 design candidate A (not user-approved):** The operator deliberately trusts an **entire changing Workspace and its effective host-side runner/dependencies** for future Native commands, rather than a fixed Git SHA or source-byte digest. This preserves the practical Direct/Pipenv/Go development workflow. It is a deliberate trust/risk choice, not a content-integrity or code-signing promise. An alternative B is to pin source revision, Python/Pipenv environment and executable inputs and deny on material change; that alternative is safer against evolving code, but is *not* selected for this feasibility proposal and would need a different contract and compatibility budget.

**Operator consent is mandatory and remains UNAPPROVED in this round.** Future local-only configuration must explicitly acknowledge: `native_limited`, `mutable_workspace` trust, no full-descendant cleanup, irreversible side effects, any authorized File Write/Git changes, and all future mutable scripts/dependencies reachable from the selected runner. The operator must be told that all actors with Write/Git and Exec grants, and any same-OS-user processes able to edit/import code, can indirectly influence what code later runs as the Gateway OS user. The gateway cannot truthfully claim to authenticate individual human users merely from a Workspace ID; the existing local-operator trust boundary remains. Remote callers must never grant/refresh this consent.

**Machine-checkable, future implementation contract (not code today):** Trust approval is a private operator-controlled versioned record bound to `profile=native_limited`, canonical Workspace ID, pinned root `(dev,ino)`, the effective Exec path/runner grant configuration fingerprint and the installed native backend identity. Verify before admission and at finalization. Unknown config versions, workspace/root identity changes, changes to grant scope/backend identity, missing acknowledgement, expiry *if later configured*, or operator revocation fail closed and require new local operator acknowledgement. **Source file bytes, Git HEAD, Pipfile lock or venv bytes are intentionally NOT pinned by this candidate**: approved File Write, approved Git changes and locally modified Pipenv dependencies do **not** automatically revoke the mutable-root consent. This lack of per-change revocation must be visible and explicitly risk-accepted, not disguised as source verification or automatic alerting.

Approval scope persists across restarts only while the exact reviewed local approval record, configuration fingerprint, root identity, supported version and backend remain valid; no implicit upgrade of an old/no-consent configuration. Operator revocation disables new admission immediately under a separately implemented local control path; any already admitted attempt must complete bounded lifecycle or remain UNKNOWN before shutdown/reconfiguration. No REST/MCP profile enable or revoke endpoint. Until explicit owner decision and implementation/review, profile admission remains fail-closed even if a user edits illustrative future JSON.

**Required distinct T0/T1 cases:** (A) legal, same-root File Write or Git edit of an executable, changed Git HEAD, and updated Pipenv dependency retain future Native mutable trust **only after explicit consent** (with visible warnings); (B) prior to consent or after revocation, the same calls do not allow Native execution; (C) wrong root dev/ino, new exec_paths/runners, changed backend identity or unsupported config version require a new approval; (D) Strict never uses Native consent, and current F1 still rejects non-preview before spawn. These are future predicates, not executed tests or a claim that changed code is benign.

**Risk acceptance still required from the product owner:** Approve this mutable Workspace model *instead of* source-revision pinning, including code alteration through otherwise allowed Git/File capabilities and cumulative unobserved detached descendants. A's choice of a candidate does not constitute that approval.

### 1.2 Strict F3 security contract

- Domain identity and ownership bound **before any user command can run**. Domain membership must be enforced and include fork/exec, setsid, daemonization, double-fork, orphan/reparent and concurrent spawn within the reviewed bounded process domain.
- All guest-to-host process-launch brokers, SSH/Docker sockets, IPC triggers, file watchers and network-based indirect execution must be blocked, included in proof, or explicitly excluded from the precisely stated boundary. A mere network/filesystem authorization limit is not an OS process-domain guarantee.
- terminate_and_prove must authenticate the domain and verify all domain execution terminated, not merely observe requestStop or an empty original PGID. Retired attempt cannot be resumed or restored via saved guest state, replay, stale callback or untrusted artifact.
- Domain creation/stop acknowledgement loss and Gateway/Runner manager crash must be covered by a verifiable lookup/reconciliation and fail-closed recovery protocol. Never blindly signal an old PID/PGID.
- Even proven whole-domain shutdown does not roll back prior network, database, Git or filesystem side effects.
- Candidate macOS VM per attempt is only a feasibility hypothesis, **not a selected shipping backend**. Linux cgroup v2 is a distinct Linux execution-environment contract and not native macOS Pipenv parity.

## 2. Preserve existing F1 legal and illegal behavior

- Global server.exec.enabled and Workspace exec.enabled remain independent opt-ins; valid dry_run=true preview, configured relative cwd, argv allowlist, script path checks, Direct/Pipenv selection and bounded output remain.
- No qualified positive backend in the current code. For valid non-preview requests with opt-ins enabled, return exec_cleanup_proof_required **before** Worker slot, Exec Runner/Popen or even transient PREPARED write; proof-denial precedes busy.
- Failure precedence must remain: disabled -> persisted quarantine -> state unavailable/owner lock -> missing required backend proof -> busy (only if positive route separately qualified). Invalid argument validation must retain the currently reviewed semantics; no new client fields are accepted here.
- REST POST /run and official MCP run_command reach the same synchronous WorkspaceService.invoke_exec decision; /info and /health must truthfully report current available=false and completion_capability=none for ordinary F1, even if route/tool registered.
- Independent File Write and Git apply must remain available per their own grants when Exec is denied or UNKNOWN. Do not use a global subprocess ban; do not change Legacy Exec or Local Skills in this design.

## 3. Future operator configuration — illustrative ONLY, unsupported by current schema v1

A future separately reviewed config-schema version would bind an operator-selected profile to a Workspace, default preview_only. The runtime could expose native_limited or strict_f3 only after qualified code and approval. Example *shape only*, **not accepted gateway.json today**:

    schema_version: 2
    server.exec.enabled: false
    server.exec.native_limited_enabled: false
    server.exec.strict_f3_enabled: false
    workspaces.project_a.exec.enabled: false
    workspaces.project_a.exec.profile: preview_only

The two existing opt-ins alone never override the selected mode gate. Unknown keys, unknown profile, unsupported backend, absent signed/qualified external components or incompatible state version must fail closed; no silent downgrade or implicit upgrade. Future /info and /health may report profile and distinct completion_capability values, but **must not** claim full_bound_domain from config or from a Native group-only observation.

### 3.1 Future operator scope (illustrative, not accepted by schema v1)

A future separately reviewed local-only consent record would carry canonical Workspace name, `root_dev` / `root_ino`, effective Exec scope fingerprint, `profile=native_limited`, `trust_scope=mutable_workspace`, backend identity/version, explicit risk acknowledgement and revocation state. No caller-supplied `profile`, `proof`, `trust_scope` or `acknowledge_risk` can set any of these. The operator must re-acknowledge on scope/back-end changes; **file/commit/Pipenv changes do not cause revocation under candidate A by design**. Preserve fail-closed owner.lock and version upgrades; operator-only disabling does not delete unresolved attempt evidence.

Current `gateway/workspaces_config.py` accepts only schema v1 and does not implement this record; neither the example above nor this clause enables execution.

## 4. Three distinct execution outcomes

Store/report command outcome, cleanup outcome and delivery outcome independently:
- command: executed, requested/effective runner, exit_code, timed_out, capped stdout/stderr and truncation; zero exit code is not a cleanup proof.
- cleanup: attempted, verified identity, bounded result, cleanup_scope=none|original_group_only|full_bound_domain, full_descendant_tree_clean=not_proven|proven, evidence reference; only a separately qualified Strict backend can ever write proven.
- delivery: result response attempted and confirmed receipt only if the transport truly supplies acknowledgement; lost HTTP/MCP response is never a reason to retry non-idempotent Exec.

Native may durably retire under a **new** explicitly reviewed limited evidence contract, never under the old v1 full-tree interpretation. Ambiguous cleanup/durability must UNKNOWN/quarantine. A normal completion with fully verified original group evidence can still have full_descendant_tree_clean=not_proven. Historical group-only RETIRED in v1 does not authorize any new execution or become a full-tree proof.

### 4.1 Normative proposed Native termination/retirement table (before any implementation)

These rows clarify but do not activate the proposed limited contract. `result` is **command result**, `cleanup` is separate evidence, and `response` cannot assert a clean execution when cleanup is unknown. Each terminal record must be durably fsynced while the Worker owns its lease. Never claim full-descendant proof for Native.

| Observation after launch | Future durable phase and evidence | Response / new Exec admission / lease and quota |
| --- | --- | --- |
| Command leader reaped; authenticated original group absent; **no detached survivor positively observed**, but transitive absence not proven | `RETIRED_LIMITED`; `cleanup_scope=original_group_only`; `full_descendant_tree_clean=not_proven`; evidence describes exactly what was checked | May return completed *limited* command outcome ONLY under separately approved Native consent and race-resistant original-group verification; release in-memory lease after retirement fsync; future requests may admit within consent and budgets. **Residual unobserved background-process risk accepted only by separately approved product owner** |
| Detached grandchild is **positively observed still running** (whether group absent or not) | `UNKNOWN` with `observed_detached_survivor=true`, `cleanup_scope=none` for full-result qualification, `full_descendant_tree_clean=not_proven`; durable global `QUARANTINED` | No clean success; deliver structured cleanup-unknown failure with any command outcome marked partial only. New Exec blocked across all Workspaces. Once UNKNOWN/quarantine is durably latched, in-memory Worker lease may release but an unresolved potentially-live-resource reservation remains for operator cleanup; no automatic restart/unlock |
| Leader/PGID membership, signal target ownership, group-absence evidence, output drain, cleanup deadline or fsync uncertain | `UNKNOWN` + global quarantine; record bounded specific reason without credentials/PID authority | No clean response or further Exec; unknown resource retained until separately authorized offline resolution. Never signal stale/unbound identity |
| Known surviving child AND original group also present/unknown | `UNKNOWN` + quarantine, regardless of exit code or status of original leader | Same as known detached; timeout/cancellation cannot silently retire |
| Gateway/Runner manager crash, lost spawn ACK, stale PID/group/generation or missing authenticated live handle | Persist or recover to `UNKNOWN`/quarantine; do not fabricate absence | No retry, no stale signal, no new Exec, offline reconciliation required |
| Proven no-spawn after durably prepared but before any user command/side effect | Versioned terminal no-spawn outcome only after original intent and reliable absence proof were durably reconciled; otherwise `UNKNOWN` | Failure response with `executed=false`; never represent as successful execution |
| Qualified Strict backend authenticates complete domain stop and anti-restore, with clean persistence | `RETIRED_PROVEN`; `full_descendant_tree_clean=proven` with backend/domain evidence | Strict-only outcome; cannot reuse Native or old test-group marker |

**Known versus unobserved is an epistemic distinction:** "not positively observed" NEVER proves absence. Current D0 §5/§7J known-survivor => UNKNOWN is preserved and has priority over hypothetical Native limited retirement. Post-cleanup capture, process observation and identity-validation method themselves require native T2 evidence. There is no authorization to signal groups merely from PID/PGID polling.

**Future status vocabulary:** For an independently qualified Native mode only, propose `completion_capability=native_original_group_limited`; existing `test_original_group_only` remains test-only and `full_tree_qualified` remains Strict-only. Default/current F1 is `completion_capability=none` and `available=false`. `cleanup_scope` alone cannot confer capability. Distinguish disabled, quarantined and unavailable, preserve existing request error priority, and report profile+evidence consistently via direct/REST/MCP/info/health.

## 5. Resource and compatibility requirements

Before authorizing Native: confirm actual host Direct/Pipenv/Pipfile/virtualenv discovery, Homebrew PATH, Python ABI/extensions, Go, cwd, generated outputs, output cap, sanitized environment, existing 1-per-Workspace/4-per-instance lease and 1–300 second timeout. This is host-native compatibility, not permission to share all credentials.

Before qualifying Strict: independently document host macOS version, guest OS, signed/verified image, required entitlements, guest tool install, shared-root semantics and conflict handling, guest-to-host broker closure, VM cold-start and teardown latency, CPU/memory/disk pressure, resource cleanup and capacity including STARTING/CLEANUP_PENDING/UNKNOWN. Do not promise host existing venvs can be reused in guest. Count every unretired domain against a bounded budget.

Both profiles must preserve privacy boundaries: do not persist raw argv, environment, stdout/stderr, secrets or tokens in lifecycle state. Filesystem writes, network calls and Git modifications cannot be assumed rollback-safe.

### 5.1 Native bounded resources cannot mean complete host-process bounds

The existing 1-per-Workspace/4-per-instance slots count admitted managed Worker attempts, not every OS descendant. After a limited retirement, **unobserved detached background processes may accumulate** while the in-memory slots appear empty; this is a disclosed, separately accepted Native risk, NOT bounded complete cleanup. A positively observed survivor forces UNKNOWN/global Exec denial and remains in unresolved resource accounting. Before Native approval, define conservative per-attempt and per-operator limits for concurrently running/admitted attempts, startup/cleanup deadlines, output and record storage, and any independently verifiable surviving-process budget. If the host's actual detached process count cannot be proven, do not advertise a hard total-process cap. Host-side resource ceilings and separate OS account may mitigate but are not equivalent to F3.

**Live signal identity gate:** Any group signalling in a future NativeRunner requires supported macOS evidence of a **race-resistant current ownership binding at the instant of signalling**, not just a pre-signal PID/PGID lookup or a stored generation. On lost identity/leader ownership, unverified target or a check-to-kill TOCTOU, **do not send the signal**, enter UNKNOWN/quarantine and invoke operator recovery. Implementation must document the OS primitive or safe equivalent with independently authorized disposable T2 no-collateral-signal tests. Absent such a mechanism, Native positive cleanup qualification is NO-GO, not something to simulate with Mock PASS.

For v2 records, owner generation, profile and evidence level must be version-bound. A v1 original_group_only `RETIRED` is not Native consent or proof and never auto-migrates. Conservative default on restart, profile switch or downgrade with old/unrecognized limited evidence is Exec denied pending separately reviewed boot compatibility rules; no auto-unquarantine/record deletion. Current v1 quarantine remains unchanged.

## 6. Explicit decision and review gates

**R0 (this proposal):** B/C independent TARGETED review of both the narrower Native risk contract and the unchanged Strict F3 goal, F1 compatibility, migration, recovery, test privileges, rejection behavior and operator warnings. They may accept a design for bounded implementation but cannot approve real Exec automatically.

**R1:** separate new code PR adding Runner interface and deterministic fake path while F1 still denies ordinary apply before launch/state intent. Original exact-Head CI, full applicable code review and existing File/Git/REST/MCP evidence required.

**R2:** separately reviewed Native implementation candidate with no externally reachable positive path until new contract, real macOS disposable T2 permission and B/C code reviews. Real execution requires a **separate explicit user authorization**, never just a config flag.

**R3:** Native product acceptance on supported Mac with bounded direct/Pipenv/Go fixtures and crash/cleanup/transport proofs, operator recovery runbook and independent security signoff; no automatic merge/release/deploy.

**R4:** independent Strict F3 mechanism research; must prove D1-D5 (domain, termination, crash, parity, environment) or conclude NO-GO. No T2/VM experiments in this R0.

**R5:** Strict implementation only after R4 qualification, new Head/CI and B/C full reviews, applicable integration, rollback and separate activation approval.

**R0 r001 independent findings (not approvals):** B Standards BLOCKED on B-P2-01 (known detached survivor disposition); C Spec BLOCKED on C-P2-NATIVE-TRUST-01 and C-P2-NATIVE-RETIRE-02. This r002 proposal addresses the design ambiguities without asserting independent closure. B-P3-01 race-safe live group signal and B-P3-02 detached resource accumulation are explicit future qualification gates. External CI wheel-lock drift is independent and must be fixed in a separately reviewed scope before code/full validation.

## 7. R0 decision questions for independent reviewers

1. Does the product owner explicitly accept proposed candidate A trusting the **entire future-mutable Workspace + actual host runner/dependencies**, including authorized Git/File code changes and undetected detached-survivor accumulation, rather than revision-locked candidate B? If not, retain Native NO-GO and choose a new review contract. D0 §0.4 continues to govern until separately approved.
2. Is the distinction between an authenticated native group observation and an authenticated Strict domain termination sufficient and impossible to conflate through API/result/storage?
3. Does a native limited retirement leave ambiguous detached children as an accepted risk, and what operator recovery and warning are necessary?
4. Can source/runtime/REST/MCP/file/Git identity and error precedence remain unchanged until a new separately reviewed product PR?
5. Are the proposed compatibility, resource and native T2 experiment gates complete, and which additional counterexamples should be required?

**Non-goals and prohibited:** R0 does NOT write gateway/**, tests/**, tools/**, workflows, requirements or config; does not merge/tag/release/deploy, alter production config, enable real apply, signal any host process/group, experiment with VM, change frozen PR #76/#77, auto-reset UNKNOWN, or inherit historic B/C PASS.

**Related design artifacts in this PR:** MULTI_WORKSPACE_EXEC_RUNNER_ARCHITECTURE_V1.md, MULTI_WORKSPACE_EXEC_RUNNER_RECOVERY_RUNBOOK_V1.md, MULTI_WORKSPACE_EXEC_RUNNER_TEST_MATRIX_V1.md.
