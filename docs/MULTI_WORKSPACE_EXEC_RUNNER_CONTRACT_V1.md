# Multi-Workspace Exec — Runner Dual-Contract Proposal V1.0 (R0)

**STATUS: DESIGN PROPOSAL ONLY / NOT CURRENT PRODUCT AUTHORITY / NO POSITIVE EXEC AUTHORIZATION.**
**TASK_ID:** MULTI-EXEC-RUNNER-CONTRACT-20261026.
**REVIEW_ROUND:** r001 (new independent design review requested).
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

## 4. Three distinct execution outcomes

Store/report command outcome, cleanup outcome and delivery outcome independently:
- command: executed, requested/effective runner, exit_code, timed_out, capped stdout/stderr and truncation; zero exit code is not a cleanup proof.
- cleanup: attempted, verified identity, bounded result, cleanup_scope=none|original_group_only|full_bound_domain, full_descendant_tree_clean=not_proven|proven, evidence reference; only a separately qualified Strict backend can ever write proven.
- delivery: result response attempted and confirmed receipt only if the transport truly supplies acknowledgement; lost HTTP/MCP response is never a reason to retry non-idempotent Exec.

Native may durably retire under a **new** explicitly reviewed limited evidence contract, never under the old v1 full-tree interpretation. Ambiguous cleanup/durability must UNKNOWN/quarantine. A normal completion with fully verified original group evidence can still have full_descendant_tree_clean=not_proven. Historical group-only RETIRED in v1 does not authorize any new execution or become a full-tree proof.

## 5. Resource and compatibility requirements

Before authorizing Native: confirm actual host Direct/Pipenv/Pipfile/virtualenv discovery, Homebrew PATH, Python ABI/extensions, Go, cwd, generated outputs, output cap, sanitized environment, existing 1-per-Workspace/4-per-instance lease and 1–300 second timeout. This is host-native compatibility, not permission to share all credentials.

Before qualifying Strict: independently document host macOS version, guest OS, signed/verified image, required entitlements, guest tool install, shared-root semantics and conflict handling, guest-to-host broker closure, VM cold-start and teardown latency, CPU/memory/disk pressure, resource cleanup and capacity including STARTING/CLEANUP_PENDING/UNKNOWN. Do not promise host existing venvs can be reused in guest. Count every unretired domain against a bounded budget.

Both profiles must preserve privacy boundaries: do not persist raw argv, environment, stdout/stderr, secrets or tokens in lifecycle state. Filesystem writes, network calls and Git modifications cannot be assumed rollback-safe.

## 6. Explicit decision and review gates

**R0 (this proposal):** B/C independent TARGETED review of both the narrower Native risk contract and the unchanged Strict F3 goal, F1 compatibility, migration, recovery, test privileges, rejection behavior and operator warnings. They may accept a design for bounded implementation but cannot approve real Exec automatically.

**R1:** separate new code PR adding Runner interface and deterministic fake path while F1 still denies ordinary apply before launch/state intent. Original exact-Head CI, full applicable code review and existing File/Git/REST/MCP evidence required.

**R2:** separately reviewed Native implementation candidate with no externally reachable positive path until new contract, real macOS disposable T2 permission and B/C code reviews. Real execution requires a **separate explicit user authorization**, never just a config flag.

**R3:** Native product acceptance on supported Mac with bounded direct/Pipenv/Go fixtures and crash/cleanup/transport proofs, operator recovery runbook and independent security signoff; no automatic merge/release/deploy.

**R4:** independent Strict F3 mechanism research; must prove D1-D5 (domain, termination, crash, parity, environment) or conclude NO-GO. No T2/VM experiments in this R0.

**R5:** Strict implementation only after R4 qualification, new Head/CI and B/C full reviews, applicable integration, rollback and separate activation approval.

## 7. R0 decision questions for independent reviewers

1. Is modifying the future D0 section 0.4 to permit explicitly limited Native trusted-code execution acceptable, given its known detached-descendant residual risk? If not, block Native without weakening Strict.
2. Is the distinction between an authenticated native group observation and an authenticated Strict domain termination sufficient and impossible to conflate through API/result/storage?
3. Does a native limited retirement leave ambiguous detached children as an accepted risk, and what operator recovery and warning are necessary?
4. Can source/runtime/REST/MCP/file/Git identity and error precedence remain unchanged until a new separately reviewed product PR?
5. Are the proposed compatibility, resource and native T2 experiment gates complete, and which additional counterexamples should be required?

**Non-goals and prohibited:** R0 does NOT write gateway/**, tests/**, tools/**, workflows, requirements or config; does not merge/tag/release/deploy, alter production config, enable real apply, signal any host process/group, experiment with VM, change frozen PR #76/#77, auto-reset UNKNOWN, or inherit historic B/C PASS.

**Related design artifacts in this PR:** MULTI_WORKSPACE_EXEC_RUNNER_ARCHITECTURE_V1.md, MULTI_WORKSPACE_EXEC_RUNNER_RECOVERY_RUNBOOK_V1.md, MULTI_WORKSPACE_EXEC_RUNNER_TEST_MATRIX_V1.md.
