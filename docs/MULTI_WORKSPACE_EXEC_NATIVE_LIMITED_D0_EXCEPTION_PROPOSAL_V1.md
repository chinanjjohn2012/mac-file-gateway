# Native Limited Candidate A — proposed D0 exception and owner-consent contract V1

**STATUS: PROPOSED TEXT ONLY / NOT CURRENT D0 / NO NATIVE POSITIVE EXEC AUTHORIZATION.**
**TASK_ID:** MULTI-EXEC-R2S-NONSPAWNING-DESIGN-20261026.
**REVIEW_TARGET:** precise future \`native_limited + mutable_workspace\` security-contract exception, not live implementation or activation.
**APPLICABLE RULES:** current original ICR-V1.0 / GHRH-1.0 and approved D0/F1/Phase1/G05. V2.0 is unactivated candidate.
**AUTHORITATIVE D0:** \`docs/MULTI_WORKSPACE_EXEC_RECOVERY_D0_DESIGN.md\` Git Blob \`6e25904aed9a62bb0f472b732021c2a7ca3b3bb0\` at R1 frozen PR #82 Head \`0af04817f61e2e45d702daecf9c7a1b1cf310cd0\`.

## 0. What the owner did and did not approve

The user replied **“选择候选 A”** to the explicit product choice described in R0, recorded on [PR #78](https://github.com/chinanjjohn2012/mac-file-gateway/pull/78#issuecomment-6414363063). This selects a **future-mutable Workspace**, actual host Direct/Pipenv/Go runner and local dependencies, not a fixed source/Git/Pipfile digest. Authorized File Write, Git changes and local Pipenv updates may change the code later executed **without automatic per-content revocation**.

The corresponding risk tradeoff is acknowledged **for future product-contract development**:
- Native commands execute with the Gateway **OS user's normal privileges**, and command allowlists are not a code sandbox or per-human identity guarantee.
- Native manages directly owned leader and original process group only; setsid/double-fork/daemonized/reparented descendants may remain outside that group and **may survive**.
- A successful command, successful group cleanup, timeout/cancellation or Gateway restart cannot roll back filesystem/Git/database/network effects or certify all descendants absent.
- Already observed surviving detached child remains a **hard no-success/UNKNOWN** signal; unobserved possible survivors are an accepted residual risk only in an independently approved Native Limited contract and per-Workspace operator opt-in.

This **does not** grant an instance-specific local consent, authorize changes to the operative D0/F1 configuration, provide the required macOS group identity proof, allow signalling/T2, turn on positive \`dry_run=false\`, or clear the R1 B BLOCKED verdict. The D0 text itself is deliberately **not edited** in this proposal.

## 1. Explicit normative amendment map — proposal only

| Inherited operative D0 / plan | Mandatory rule today | Proposed precise future \`native_limited\` exception, contingent on separate effective amendment |
| --- | --- | --- |
| D0 §0.1 and F1 | All ordinary non-preview apply without full-descendant proof rejects before Worker/Runner/PREPARED | Keep default \`preview_only\`; a *separately named*, local-operator-selected Native profile may use distinct **limited original-group** evidence after its own complete qualification; never silently reinterpret ordinary F1 no-proof |
| D0 §0.4 | Positive general Multi Exec requires independently proven complete descendants cleanup | Strict F3 continues that guarantee. Native exception explicitly **cannot** claim full descendants, F3, sandbox or nonescaped descendants |
| D0 §2.1 | Test-only group grant cannot become production qualification | Preserve fully; Native must use different, private versioned operator consent + independently reviewed backend/evidence qualification, never test grant or remote request |
| D0 §3 | Private pinned-FD state, exact schema, owner.lock, fsync, boot scan, quotas; unresolved state blocks | Keep all principles; propose separate schema v2 with profile, attempt/generation, backend, scope and evidence. Unknown/old/mixed/migrated v1 group-only RETIRED never upgrades to Native or full proof |
| D0 §4 | Qualification, lease and fsynced PREPARED **before** any possible launch, one start and no replay | Preserve order; operator grant/revocation must serialize against the **last pre-STARTING/irreversible-start gate**, in addition to admission and finalization. Revocation after PREPARED **before** dispatch => NO START, conservative UNKNOWN/quarantine; start-first may already have effects, so no replay and no false rollback. See §2.1. |
| D0 §5 and §7J | Known detached survivor or uncertain group evidence => UNKNOWN and global Exec quarantine | **Preserve regardless of time:** even a late positively attributable survivor observed **after** RETIRED_LIMITED/response/slot release reopens UNKNOWN and durably latches global quarantine. Do not GC attribution under quota pressure. Group-only/absence is never full descendants proof. See §3.1. |
| D0 §6 | Honest error priority/status; no remote unquarantine/reset, no unearned capability | Future Native reports \`completion_capability=native_original_group_limited\`; never \`full_tree_qualified\`. Strict and Native results must not be confused |
| D0 §8 | R1 required before R2, real native acceptance and merge separate | R2-S design and fake tests only now; R2-N implementation and R3 T2 require later separate gates. Design approval never turns on production |

**No line in this table is currently effective.** Activation needs an exact new operative D0 version, independent B/C review and explicit owner scope/activation decision. A cannot amend active rules by referencing this document.

## 2. Proposed Native local trust and consent record

A future review may approve a **local-only**, versioned, non-client-mintable consent record with the following *conceptual* fields. This is NOT accepted by present \`gateway/workspaces_config.py\` schema v1 and is not runnable JSON:

| Property | Binding and meaning |
| --- | --- |
| \`version\`, \`profile\` | Supported exact version and \`native_limited\` only; no default implicit upgrade |
| \`trust_scope\` | Must explicitly equal \`mutable_workspace\`; no claim of source-hash pinning |
| \`workspace\`, \`root_dev\`, \`root_ino\` | Operator-selected canonical Workspace and pinned filesystem identity |
| \`exec_scope_fingerprint\` | Effective local Exec permissions, approved \`exec_paths\` and runner selection, not mutable request data |
| \`backend_identity\` | Exact reviewed Native backend implementation/config/version; not a mere PID/PGID |
| \`risk_acknowledgements\` | Explicit readable notice of host user privilege, future code/dependency changes, limited group cleanup, residual daemon risk and irreversible side effects |
| \`revoked\`, optional expiry | Local operator revocation or unsupported/expired version denies new admission; record never grants remote recovery |
| `consent_epoch` | Persistent local approval-generation fencing: increment on explicit revoke/re-consent or binding change, not on ordinary service restart or mutable Workspace Git/File/Pipenv edit |
| `service_owner_generation` | Ephemeral owner.lock service session/lease epoch, rotates after restart/new ownership; not durable consent authority |
| `attempt_generation` | Fresh unique per-attempt token fencing callbacks/start_once and retained forensic evidence; not operator consent |

At admission, **immediately before irreversible start dispatch**, and before durable finalization, all relevant identity/consent checks must pass. Approval lifetime `consent_epoch`, service owner generation and attempt token are **distinct**: a consent can remain valid across a clean service restart if its reviewed backend/root/grants/risk scope remains unchanged, but stale owner or attempt callbacks cannot. If root, approved Exec scope/backend, supported state/backend implementation version or consent epoch changes, local revoke is committed, or attempt owner identity mismatches, **deny new admission** and any pending pre-start dispatch. The unlaunched PREPARED attempt must not be grandfathered; conservatively move it to UNKNOWN/global quarantine pending offline verification. After an irreversible launch has already linearized, revocation cannot undo its side effects: stop future starts, conservatively reconcile/cleanup in-flight work, and mark UNKNOWN if result, identity or durable closure is uncertain. Do **not** revoke merely because lawful Workspace scripts/Git HEAD/Pipenv dependencies changed under unchanged mutable scope; Workspace code SHA is NOT a version pin. Other actors with Git/File and same-user access may change that code; this is the accepted Candidate-A risk, not proof of harmlessness.

No public REST/MCP/CLI/environment \`profile\`, \`proof\`, \`acknowledge_risk\`, test factory or opaque backend marker may create, copy, renew or reset consent. Application startup without consent remains F1 deny-only. \`server.exec.enabled\` and Workspace \`exec.enabled\` alone never qualify a Native backend.

### 2.1 Future authorization and revoke/launch linearization — explicit P2 closure proposal

**Policy selected for future contract review:** a PREPARED-but-not-yet-started attempt has **no grandfathered launch permission** after local consent is revoked. Local consent creation/revoke/reapproval is versioned, durably fsynced and serialized with the same owner-controlled admission/last-prestart authorization authority. Revocation's **linearization point** is the committed local consent_epoch transition under that authority; the first irreversible backend start dispatch's point is its successful fenced/owned transition from prepared intent through durable STARTING to the backend invocation under that same serialized gate. All identity checks (Workspace pinned root dev/ino, effective Exec scope, backend binary/config/version, consent epoch, owner generation and attempt token) run immediately **before** dispatch. A mere earlier admission/PREPARED or PID/PGID lookup cannot authorize later start.

- **Revocation wins before PREPARED:** no durable new PREPARED and no backend allocation/launch. **Revocation wins after PREPARED but before first start dispatch:** no start, fence the attempt, durably record UNKNOWN/global QUARANTINED until reviewed no-start closure (do not invent an auto-cleared safe retirement). Never re-run under refreshed consent or substitute a test grant.
- **Start dispatch wins the ordering:** the command may already have irreversible host effects before the later revocation is acknowledged. The revocation closes further starts/admissions and requires conservative in-flight reconciliation/cleanup; if ACK, owner, startup or proof is uncertain, durable UNKNOWN/global QUARANTINED. No second start, blind signal, optimistic clean result or rollback claim.
- **Failure to serialize safely:** if supported local durability, lock ownership, backend identity, last pre-start recheck or at-start target lifetime cannot be established across the relevant concurrency, the future Native positive backend is **NOT QUALIFIED**. Fail closed; do not claim a userspace preflight check and unrelated OS spawn form a race-free atomic operation. Out-of-band edits bypassing the reviewed consent mechanism are not valid operator approval; detection fences and quarantines.
- **Generations:** persistent \`consent_epoch\` (rotates on local consent issue/revoke/re-issue/binding change), ephemeral \`service_owner_generation\` (rotates on new owner.lock lease/restart), unique \`attempt_generation\` (never reused, checked by callbacks, ACK, cleanup and retirement). Compare each against its correct persisted/live authority; a restart alone need not revoke valid mutable consent but must invalidate old callbacks. Old backend/schema implementation versions never silently qualify, while legal mutable Workspace Git/Pipfile/script revisions do not trigger consent-epoch rotation.

These are *future normative proposals*, not an implemented atomic start primitive. T0 fake interleavings are NOT_RUN. No actual positive Native or macOS signal experiment is authorized.

## 3. Proposed identity, status and result invariants

1. **Separate profiles**: \`preview_only\` (current default), \`native_limited\` (future conditional), \`strict_f3\` (separately qualified full domain). Strict cannot fallback to Native; Native consent cannot grant Strict or \`full_bound_domain\`.
2. **Three outcomes**: command (executed, exit, timeout, capped stdout/stderr), cleanup (scope, evidence ID, known-survivor flag, \`full_descendant_tree_clean=not_proven\` for Native), delivery (attempted/actual receipt acknowledgement if known). \`exit_code=0\` is not a cleanup proof.
3. **Future `RETIRED_LIMITED`**: only on independently reviewed limited evidence, owned leader reaped, original group demonstrably and race-resistently absent, no currently known live detached process, with all final records fsynced. It is *not* an absorbing final state against **later positive survivor evidence**; see §3.1. It permits only limited completion, not RETIRED_PROVEN or whole-tree clearance.
4. **Known or uncertain external state**: positively identified survivor at any time (including after limited retirement/response/slot release), lost ownership, group identity, cleanup/drain/final fsync/ACK uncertainty => globally QUARANTINED and durable UNKNOWN plus evidence attribution; new admission stopped. A Worker release is not clearance of external state. Preserve limited-retired provenance/tombstone and uncertain markers, never quota-evict them solely to admit new Exec.
5. **No blind group signals**: a successful preflight PID/PGID lookup cannot protect against PID reuse between check and \`killpg\`. A supported macOS *at-signal* race-resistant ownership mechanism, independently reviewed and tested in specifically authorized disposable T2, is mandatory. If unavailable: **no signal**, mark UNKNOWN/quarantine, Native positive mode stays NO-GO.
6. **Boot/upgrade/downgrade**: current schema v1 RETIRED group-only is never Native consent. Unsupported reviewed Gateway state/backend/schema implementation version, mode, owner or record => deny Exec and preserve evidence; no auto recovery. **Version is Gateway state/backend implementation version, not mutable Workspace Git/source/dependency revision**; legal Candidate-A source changes do not auto-expire consent. Reboot alone cannot establish detached process termination.
7. **Resource accounting**: one Worker per Workspace/four per instance is admission concurrency, not a total host descendant bound. Retain limited-retired forensic attempt/generation/tombstones subject to finite 4096-record/4096-byte/16MiB state quotas; exhausted budget => stop admission/quarantine, no silent TTL/GC of unresolved or late-evidence attribution. An independent later approved archival procedure may redefine retention only if late evidence still forces conservative global quarantine. Repeated unseen descendants may accumulate, never advertise their absence.
8. **Status and error precedence**: preserve \`exec_disabled\` -> \`exec_quarantined\` -> \`exec_state_unavailable\` -> \`exec_cleanup_proof_required\` -> \`busy\` for the actually applicable mode and validated request. Current \`/info\`, \`/health\`, direct/REST/MCP remain truthful (\`available=false\`, \`completion_capability=none\` without a reviewed qualified backend). No client-selected downgrade, fake proof, offline reset or production-grant bypass.

### 3.1 Future post-retirement positive observation and concurrent admission (B83-P2-01)

**Temporal rule is unlimited by prior status or response:** only an **authenticated, positively observed** living detached descendant attributed by the reviewed attempt/generation/backend/Workspace identity triggers this specific known-survivor rule. A past RETIRED_LIMITED does **not** prove absence of escaped descendants. Later detection after fsync, Worker release, message delivery or service restart must **supersede** that limited evidence: synchronously close new Exec admission, serialize against admission's last pre-start gate, durably latch global QUARANTINED, preserve/append bounded late-survivor evidence, and reclassify the original limited-retired attempt to UNKNOWN with an auditable link to its prior limited result. Do not silently rewrite an already delivered success or forge a new Strict cleanup proof; an already delivered limited receipt is irreversible historical evidence, not an active authorization to continue Exec.

If attempt B was only PREPARED when A's late observation wins, B must not start and conservatively becomes UNKNOWN/quarantined. If B's first irreversible start wins the serialization earlier, B may be in-flight; account for it, deny further admission and reconcile B independently, UNKNOWN if uncertain. No late event may cause automatic signalling on a stale PID/PGID, remote recovery or opportunistic kill of another owner's process. Late evidence without sufficient attribution still requires an **orphan/uncertain global quarantine** and preserved evidence, not a guessed process kill.

**Forensic retention and finite quotas:** retain minimal limited-retired tombstone+attempt mapping after response, without TTL or capacity-driven eviction of unresolved evidence. Stop admitting when 4096 records/4096 bytes each/16MiB budget cannot retain attribution. If a future *separately approved* archival policy has legitimately pruned historical linkage, or a late observer cannot authenticate the attribution, latch global quarantine with an orphan evidence marker; never trust a now-missing record as proof of safety. If the required durable latch/event fsync fails, mark Exec unavailable and fail closed on the current and next boot. A specific past result cannot be revoked from a client's memory; correct current public capability/status and audit history instead.

This is future design text only. T0 sequences for late callback, already delivered result, record pruning/overflow, B pre-start/start-first races and latch fsync failure must be implemented and independently reviewed before any positive backend work; Mac process observation remains T2 NOT_AUTHORIZED.

## 4. Explicit negative/positive counterexamples for independent design review

| Contract | Future legal path after separate approval | Forbidden / boundary / failure path |
| --- | --- | --- |
| Mutable trust | Same-root legal Git/File/Pipenv edit stays within *locally acknowledged mutable scope* | No owner consent, revoked record, wrong dev/ino, broadened exec_paths or switched backend => no positive admission |
| Cleanup | Future owned leader reaped + authenticated original group absent and no positive detached survivor => limited (not full) evidence only | Positively observed detached survivor **before or after** RETIRED_LIMITED/response/slot release => durable global QUARANTINED and forensic UNKNOWN; never trust absence of observation or stale PID |
| Signalling | Independently authenticated live owned signal target under a safe supported macOS mechanism | PID reuse/check-to-kill race/old process group => **no signal** and UNKNOWN; never collateral kill |
| Durable identity | Fsynced intent, serialized fresh local consent pre-start gate, same consent/owner/attempt generations, exactly-one attempted dispatch | Revocation after PREPARED but before start => NO START/UNKNOWN; start-before-revoke => only one in-flight launch plus conservative reconciliation; lost ACK never retries |
| Mode separation | Strict gets independently proven entire-domain shutdown | Native group cleanup, client proof or limited result can never upgrade to Strict |
| Adjacent operations | Authorized Git/File remain usable while Exec disabled/quarantined | Git/File do not grant Exec consent; unhealthy Exec state does not indiscriminately kill separate Git subprocesses |

B/C must independently derive additional counterexamples and decide whether the exact D0 §0.4 replacement scope is acceptable. The user's Candidate A selection resolves the **model choice** only, not macOS group-signal feasibility, real backend cleanup, operator grant design qualification, R1 overall R10 or release.

## 5. Non-negotiable staging and NO-GO conditions

**This PR may request only TARGETED design review** of proposed wording. It makes no production or test code/config changes.

- Current R1 hard denial remains unchanged on every normal \`dry_run=false\` path, including both opt-ins enabled, even if an external request for profile is forged.
- No \`RETIRED_LIMITED\` record is written by current v1 product. No Native positive backend is implemented or invoked.
- Actual T2 macOS process-group signalling, forced Gateway crashes, detached-process probes, VM, Native C/C3, T3 user Mac/Tunnel/shared/production remain **NOT_RUN / NOT_AUTHORIZED**.
- A later D0 amendment must be independently reviewed and specifically activated before executable product behavior can diverge. A separately reviewed version-2 schema/consent, code approval, identity-safe backend qualification, and **separate exact-resource operator/owner T2/activation authorization** remain mandatory.
- No merges, releases, tags, deployments, production configuration, automatic UNKNOWN reset or workspace privilege expansion are authorized by this document.
