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
| D0 §4 | Qualification, lease, fsynced PREPARED **before** any possible launch; one start, no replay | Preserve order; add consent and verified backend identity/revocation at admission **and finalization**; lost launch ACK cannot trigger a second start |
| D0 §5 and §7J | Known detached-survivor or uncertain group evidence => UNKNOWN and global Exec quarantine | **Preserve without exception.** Only leader reaped + race-resistently authenticated original group absent + *no positively observed* detached survivor may qualify future \`RETIRED_LIMITED\` (NOT absence proof) |
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
| \`owner_generation\` | Bound attempt lifetime/fencing, checked alongside state and backend |

At admission **and before durable finalization**, all relevant identity/consent checks must pass. If root, approved Exec scope/backend, owner generation, record version or revocation state mismatch: **deny further admission**, quarantine an uncertain already admitted attempt, and require distinct local operator re-acknowledgement. Do **not** revoke merely because legal Workspace scripts/Git HEAD/Pipenv dependencies changed under unchanged approved mutable scope. Other actors with Git/File and same-user local access can influence that future code; this is the accepted tradeoff, not proof of harmlessness.

No public REST/MCP/CLI/environment \`profile\`, \`proof\`, \`acknowledge_risk\`, test factory or opaque backend marker may create, copy, renew or reset consent. Application startup without consent remains F1 deny-only. \`server.exec.enabled\` and Workspace \`exec.enabled\` alone never qualify a Native backend.

## 3. Proposed identity, status and result invariants

1. **Separate profiles**: \`preview_only\` (current default), \`native_limited\` (future conditional), \`strict_f3\` (separately qualified full domain). Strict cannot fallback to Native; Native consent cannot grant Strict or \`full_bound_domain\`.
2. **Three outcomes**: command (executed, exit, timeout, capped stdout/stderr), cleanup (scope, evidence ID, known-survivor flag, \`full_descendant_tree_clean=not_proven\` for Native), delivery (attempted/actual receipt acknowledgement if known). \`exit_code=0\` is not a cleanup proof.
3. **Future \`RETIRED_LIMITED\`**: only on independently reviewed limited evidence, owned leader reaped, **original group demonstrably and race-resistently absent**, no known surviving detached process, all final records durably fsynced. It permits only a specifically scoped *limited* completion, not \`RETIRED_PROVEN\` or whole-tree clearance.
4. **Known or uncertain external state**: positively seen survivor, lost ownership, lost group identity, cleanup timeout, broken output drain, state failure, lost execute ACK or post-crash identity uncertainty => durable \`UNKNOWN\` and global Exec QUARANTINED. An in-memory Worker may be released only after appropriate conservative durable accounting; possible external process remains unresolved and must not be quota-evicted.
5. **No blind group signals**: a successful preflight PID/PGID lookup cannot protect against PID reuse between check and \`killpg\`. A supported macOS *at-signal* race-resistant ownership mechanism, independently reviewed and tested in specifically authorized disposable T2, is mandatory. If unavailable: **no signal**, mark UNKNOWN/quarantine, Native positive mode stays NO-GO.
6. **Boot/upgrade/downgrade**: current schema v1 \`RETIRED\` group-only is never Native consent; incompatible schema/mode/backend/owner or unknown record => global Exec denied and evidence preserved. No automatic recovery or REST/MCP reset. Reboot alone never establishes old detached process termination.
7. **Resource accounting**: existing one managed Worker per Workspace/four per instance are **admission concurrency**, not total OS child limits. Repeated unobserved detached processes may accumulate even with available Worker slots. Define finite startup/cleanup/time/output and unresolved resource budget; never advertise host-wide process containment absent OS evidence.
8. **Status and error precedence**: preserve \`exec_disabled\` -> \`exec_quarantined\` -> \`exec_state_unavailable\` -> \`exec_cleanup_proof_required\` -> \`busy\` for the actually applicable mode and validated request. Current \`/info\`, \`/health\`, direct/REST/MCP remain truthful (\`available=false\`, \`completion_capability=none\` without a reviewed qualified backend). No client-selected downgrade, fake proof, offline reset or production-grant bypass.

## 4. Explicit negative/positive counterexamples for independent design review

| Contract | Future legal path after separate approval | Forbidden / boundary / failure path |
| --- | --- | --- |
| Mutable trust | Same-root legal Git/File/Pipenv edit stays within *locally acknowledged mutable scope* | No owner consent, revoked record, wrong dev/ino, broadened exec_paths or switched backend => no positive admission |
| Cleanup | Reaped leader + authenticated original group absent + no positive detached-survivor observation => limited non-full evidence only | Positively observed detached child => UNKNOWN regardless of group disappearance; absence of observation is not \`proven\` |
| Signalling | Independently authenticated live owned signal target under a safe supported macOS mechanism | PID reuse/check-to-kill race/old process group => **no signal** and UNKNOWN; never collateral kill |
| Durable identity | fsynced intent, same attempt/generation/owner and exactly-once start | Crash or lost create/start ACK, stale generation/replay => authenticated reconcile or quarantine; never double start |
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
