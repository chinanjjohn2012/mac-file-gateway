# Multi-Workspace Exec: durable lifecycle and unknown-cleanup design (D0)

**Status: PROPOSED PRODUCTION-FIRST D0 AMENDMENT / INDEPENDENT DESIGN REVIEW REQUIRED / NO IMPLEMENTATION AUTHORITY.**
**Track: Python product only.** Stacked on the fixed macOS partial-acceptance
PR #57 Head `bb636febe00099be2d15ca6621c1ee2dd892e6e8`, whose base is
PR #56 reviewed product Head `e528ddb809df897b4f81802e0ae5f4f95ff5d2c7`.
The accepted evidence is `PARTIAL_NATIVE_ACCEPTANCE_PASS` only.
Do not merge, deploy, enable production Exec, restart a user's Gateway,
load Native C, or restart Candidate C/B03 research under this design.

## 0. Proposed production-first D0 amendment (2026-10-25)

**Status: PROPOSAL ONLY / not yet an approved replacement contract.**
This proposal follows an explicit product-direction change: finish the
ordinary Multi-Workspace Gateway's **production fail-closed behavior**
before pursuing test-specific facilities. The historical D0 sections
below and frozen PR #67/#68 contracts/CI/independent Reviews remain
valid evidence on *their own* Head/Base/Tree; no prior FAIL is turned
into PASS. This new amendment requires independent Standards and
Spec **design review** on its new Draft-PR snapshot before it
changes implementation requirements.

### 0.1 Decision and boundary

The immediate product target is an **ordinary deny-only** Gateway.
Instance `server.exec.enabled=true` plus selected Workspace
`exec.enabled=true` is permission to request Exec, never cleanup
proof. With no separately approved full-descendant cleanup proof,
every `dry_run=false` request MUST reject at the shared synchronous
`WorkspaceService.invoke_exec` boundary with
`exec_cleanup_proof_required` (REST 503, MCP structured isError),
**before Exec Popen/Runner invocation AND before any newly written
PREPARED record**, including write-then-unlink. Missing proof
precedes `busy` and cannot be bypassed via client fields, CLI,
configuration, environment, headers, selected paths or names.

A legal `dry_run=true` request must still perform the existing
workspace/path/allowlist validation and produce a useful preview
without starting a child or writing Exec attempt intent. The
`/info` and `/health` Exec policy remains sanitized and consistent:
`adapter_exposed` and `enabled` may be true, but
`available=false`, `completion_capability="none"`. Quarantined,
unavailable and disabled cases keep the stricter existing error
priority. File Read/Write and Git permissions, including the
separately authorized Git subprocess path, remain independent.

### 0.2 Explicit amendment to historical D0 scopes

For the **immediate deny-only phase only**, this `0 supersedes the
historic positive-disposable-test *development prerequisite* found
in `2.1 (group-only positive factory), `4 (post-gate positive
launch sequence), `5 (group-only RETIRED evidence), `7 I/J
(positive private-grant fixtures), and `8 (mandatory R1
positive Bridge sequence). Those clauses are retained below for
historical provenance and for consideration in a **future**
separately approved real-execution design, not as gates that must
be implemented or green merely to ship safe default-DENY.
The ordinary default-DENY security requirement and every
existing fail-closed/quarantine property remain mandatory.
This is **not** a permission to use a mock/legacy grant as
production execution qualification.

No new `create_private_exec_acceptance_bridge()` or elaborate
SDK internal mutable-method audit is a deny-only product
prerequisite. The existing B1-A/B0 test grants/Listeners remain
inert, not externally mintable, and must not be wired to a
normal Worker. Their eventual retention/removal requires
reviewed dependency analysis. PR #68's frozen 24 expected
RED / 34 GREEN counts and all existing reviewer conclusions
remain tied to that old R0 contract; they do not become
metrics for this revised contract. No test-count quota.

### 0.3 Minimum verification; Mock vs real evidence

Only test material product risks and both legal/illegal
paths. For the deny-only Worker: check direct service, real
REST and official MCP ingress; valid preview; error precedence;
status parity; no real Exec Runner call or newly written
PREPARED intent (including physical write-then-unlink); no
client-minted authority; and File/Git independence.
Use real private-FS/owner-lock evidence where filesystem
identity and durability are security claims, and a small
number of disposable real REST/MCP requests to prove the
network path reaches the same Worker gate.

Use deterministic Mock/fakes for fault, cancelled waiter,
slot/lease, timeout and state-machine transition behavior
**when no real child needs to run**. Refactor, combine or
replace obsolete real-subprocess tests only with an explicit
old/new contract traceability matrix and independent
review, not by silently deleting a safety property.
A mocked Runner or synthetic heartbeat is NEVER evidence
of real OS group/descendant cleanup. Purely hypothetical
Python object monkeypatches inside a trusted process are
not automatically network-reachable P2 vulnerabilities;
require an identified untrusted request/real production
reachability and actual Worker bypass before making them
mandatory tests.

The deny-only stage stops once the required safe failure
and legal preview/File/Git paths pass, there is no
in-scope P0/P1/P2, the relevant CI and independent B/C
reviews are complete on one fixed snapshot, and no
unaccounted integration/security gap remains. Do not
optimize for the total number of tests.

### 0.4 Future positive Exec remains a separate safety gate

No production real Exec becomes permitted as a result
of approving `0. If positive real command execution is
later requested, its independent contract MUST provide
durable fsynced PREPARED-before-Popen, safe ownership,
complete descendant cleanup rather than leader/group-only
observation, UNKNOWN/quarantine and no replay, correct
timeout/cancel/shutdown/restart lifecycle and identity-safe
signalling. It needs separate bounded **real native macOS
ARM64** process-tree evidence and real transport/Tunnel
integration when applicable; Mock alone is insufficient.
No Native C/C3 research or host signal experiments are
authorized by the deny-only roadmap.

### 0.5 Implementation/review gate

The companion document
`docs/MULTI_WORKSPACE_EXEC_PRODUCTION_FIRST_IMPLEMENTATION_PLAN.md`
is a **proposed** implementation plan, not implementation
approval. First review this design and plan independently.
Only after approval may a separate product Draft PR
implement the proof gate and **explicitly migrate** obsolete
tests; it must receive fresh independent code reviews and
original CI on its own Head/Base/Tree. Freeze PR #68's r002
Head while it is reviewed; do not silently rewrite its tests
or assign it a PASS. Do not merge, release, deploy, enable
production Exec, restart the user Gateway/Tunnel or relax
quarantine/cleanup permissions.


## 1. Observed gaps and safety targets

At the referenced base, `gateway/workspaces.py` holds in-memory synchronous
Worker slots and closes pinned roots after waiting for those slots.
`gateway/executor.py` starts a new session, signals its original PGID on
timeout, and waits for the directly launched process. It has **no durable
Exec attempt state** and no proof that a detached descendant is gone.
The macOS PR #57 proves linked-child heartbeat cessation, real loopback TCP
REST/MCP disconnect and ordinary shutdown ordering; it does **not** prove
arbitrary detached descendants, failed-cleanup quarantine, abrupt restart, or
private Tunnel behavior.

Design goals:
1. Never launch a non-preview Exec command without durable, fsynced intent.
2. Retain evidence of an uncertain attempt across process crashes/restarts.
3. Refuse further Exec after unknown cleanup or corrupt/unavailable state.
4. Do not signal a possibly reused PID/PGID or auto-retry after lost response.
5. Keep File/Git permissions separate; no reflected routing or new general shell.
6. Explain exactly which cleanup evidence was observed, without claiming
   complete OS-level process-tree cleanup.

## 2. Terms: observation is not authorization

- `PREPARED`: fsynced intent exists before any attempted `Popen`.
- `RUNNING`: a spawn may have occurred; durable admission token is held.
- `LEADER_REAPED`: direct child was waited; not proof of group/tree absence.
- `GROUP_ABSENT_OBSERVED`: original process group absent at a bounded check.
  This cannot prove an independently detached descendant exited.
- `UNKNOWN`: observation or cleanup evidence is incomplete, contradictory,
  timed out, or failed. This is a **persisted uncertain attempt**, not success.
- `QUARANTINED`: global Exec admission has been disabled because an
  `UNKNOWN` or untrusted persisted state exists.
- `RETIRED`: an intent was durably closed with direct-leader and original-group
  evidence. This is an explicitly **group-only** completion for trusted,
  disposable product tests, not proof that every detached child was reaped.

Two separate facts must never be conflated: `original_group_clean` (bounded
leader/group evidence) and `full_descendant_tree_clean` (not established
by the existing Python CommandRunner). A returned exit code, EOF, heartbeat
silence, or `killpg` success alone must never set the second fact.
A future full-tree qualification requires a separately reviewed mechanism.
This D0 is a **contract**, not a claim that Python can discover all descendants.

### 2.1. Machine-checkable, test-only group-retirement qualification (P2-01)

**Default: DENY.** The ordinary installed Gateway, including a process with
both `server.exec.enabled=true` and Workspace `exec.enabled=true`, has
`group_only_test_grant=None`. Those two configuration grants allow choosing
*whether to request* Exec, but are **not** cleanup-evidence qualification.
No `gateway.json` field, CLI flag, environment variable, REST/MCP body,
header, metadata, Workspace path/name, test-named command, CI flag or
`PYTEST_CURRENT_TEST` value can create or activate this qualification.

For R1, only a **separately maintained, trusted disposable acceptance
harness** may construct a private, in-memory, nonserializable, instance-bound
`TestOnlyGroupRetirementGrant` via an **internal acceptance-only factory**.
The normal CLI / server factory MUST NOT call that factory or accept a grant
from any external input. The factory must first verify ownership of a newly
created private temporary fixture root and Exec state root, pin both by FD
identity, restrict the listener to loopback, identify the exact Gateway
service instance and the explicitly enumerated disposable Workspace
identities (name plus pinned root dev/ino), and refuse production/user roots
or an already-used state root. It returns a single service-scoped grant
valid only for this fixture lifetime; it is invalidated by service close,
process exit, fork or restart and cannot be transferred to a different
service, state root or unlisted Workspace. The harness, **not a client**,
injects it once while creating the disposable service. Each admitted
attempt captures the grant's matching fixture identity and rechecks it
at finalization. Sequential attempts within the same authorized disposable
scope may use the grant **only while the service remains healthy**; one
attempt's failure or quarantine invalidates further admission. A REST
or MCP caller can only use its predetermined scope, never alter it. This is
an application admission boundary under the existing trusted-local-user
model, **not** a cryptographic secret or an OS sandbox against code already
running with the Gateway user's privileges.

The Worker must evaluate the following **non-client-controllable**
predicate both at admission and immediately before durable finalization:

```text
group_only_test_qualified =
    service.has_internal_test_grant
    AND grant.identity_is(service.instance, state_root.dev_ino)
    AND grant.is_live_in_same_process
    AND workspace.name_and_pinned_dev_ino IN grant.disposable_scopes
    AND fixture_is_private_and_loopback
    AND server_exec_granted AND workspace_exec_granted
    AND state_owner_lock_held AND state_is_healthy AND NOT quarantined
```

A positive result selects only the **test-scoped original-group** evidence
policy for the identified attempt. It does not skip the original Exec
allowlist, durable `PREPARED`, checks for observed detached descendants,
or any quarantine. A late grant, injected client parameter or previously
quarantined attempt can **never** change `UNKNOWN` back to `RETIRED`.
R1 must provide a narrow internal test seam to construct this condition
without exporting it via the normal Gateway product API. If the harness
cannot prove any required identity/fixture property, the predicate is false.

The separate future **full-descendant-cleanup qualified** path is NOT
implemented or assumed in D0/R1. In ordinary Gateways without that future
reviewed proof mechanism, non-preview apply MUST be rejected **before**
`Popen` with `exec_cleanup_proof_required`; an attempt already RUNNING
that produces only original-group evidence MUST end `UNKNOWN` and global
quarantine, not `RETIRED`. A disposable test with the exact internal grant
may retire only after direct-leader reap, verified original-group absence,
and no positively observed detached descendant, using the limited
evidence marker defined in §5.

## 3. Durable state and fail-closed boot scan

State root: a Gateway-owned `<private-config-dir>/exec-state` outside **all**
Workspace roots, independent of `git-state`. Use pinned directory FDs,
no-follow opens, regular single-link bounded records, exact schema, bounded
file count and record size. Reject symlink/hardlink, unknown entry, invalid
metadata, ambiguous identity, unreadable file, and unsafe ancestry. Protect
state from Gateway File API grants. Match local-OS trust assumptions already
defined in `docs/PHASE1_LOCAL_TRUST_BOUNDARY.md`; no cross-user sandbox claim.

Atomic state change: unique temp in the pinned state dir, write-all, fsync
file, atomic rename, fsync directory. On all durability errors, latch
`QUARANTINED` immediately; never return an apparently clean Exec result.
Record a version, random per-attempt ID, Workspace ID, pinned root dev/ino,
phase, attempt timestamp (diagnostic only), and bounded cleanup observations.
Do not persist arbitrary argv, stdout/stderr, environment, tokens or content.
Never use timestamps or PIDs as sole authority. If an intent fsync fails
**before** any spawn, launching is prohibited, so a later boot cannot
inherit an unrecorded child. If finalization fails **after** a spawn,
the earlier fsynced PREPARED/RUNNING record must remain as a restart hazard.

Boot ordering: open and scan the private state **before** any Exec-enabled
API can accept requests. Every surviving `PREPARED`, `RUNNING` or
`UNKNOWN` marker, invalid schema, incomplete atomic update, corrupt entry,
unexpected filename, or untrusted directory results in **global Exec
quarantine**. Healthy empty/retired state can be admitted only under matching evidence
qualification: a normal Gateway MUST quarantine on seeing any test-only
`RETIRED` record copied into or left inside a normal state root, rather
than treating its group-only evidence as full-tree proof. Each test fixture
uses an exclusive disposable state root; its grant does not survive restart.
No automatic "the old PID is gone, so recover" shortcut. A new Gateway process must
not signal a previously recorded PID/PGID merely because it exists.

Only one owner may modify the same state root: require an interprocess
ownership lock for the whole Gateway Exec state lifetime, and fail closed
if it cannot be taken. File API and separately authorized Git must not
inherit Exec permission or silently bypass the lock.

**P3-01 — finite capacity and retired-only reclamation.** R1 must enforce
at most **4096 durable attempt records**, **4096 bytes per record** and
**16 MiB total attempt-record payload** per Exec state root (plus one
fixed owner-lock object and one in-flight atomic temp entry). Validate the
limits before admitting a new `PREPARED` record. At capacity, prune only
records already durably marked `RETIRED`, whose attempt is not referenced
by any unresolved marker; select candidates by bounded
`(retired_at, attempt_id)` ordering (timestamps affect reclamation
order **only**, never process identity, grant, or recovery authority).
Prune via pinned-FD unlink and directory fsync, never by wildcard cleanup,
TTL-based deletion of unresolved records, or a client-accessible endpoint.
A crash while deleting an already retired record may leave that safe
retired record present or absent; a leftover ambiguous temp entry must
fail closed at boot. `PREPARED`, `RUNNING`, `UNKNOWN`, quarantined,
corrupt and unexplained entries are **never** quota-evicted. If no safely
reclaimable `RETIRED` entries remain or a prune/write/fsync fails, deny
the request **before spawn**, report `exec_state_unavailable`, latch
global Exec admission closed, and preserve any surviving unresolved intent
for offline review. No optimistic empty-state reset or automatic replay.

## 4. Exact launch ordering and Worker ownership

On `dry_run=true`, perform ordinary read-only validation without spawning
or writing a RUNNING intent; quarantined Exec must still be visibly denied
(rather than presenting a misleading READY preview).

On `dry_run=false`:
1. In the actual synchronous Worker, check global and Workspace grants,
   state health, Workspace slot and four-instance admission limit.
   Resolve the internal proof qualification of §2.1 before any spawn:
   without a full-tree proof implementation, a normal (non-test) apply
   fails `exec_cleanup_proof_required` before writing `PREPARED`.
   Do not derive test qualification from the request or config.
2. Reserve the slot **before** any possible child launch; keep it through
   durable finalization, including if REST/MCP waiter disconnects.
3. Persist+fsync `PREPARED` before trying `Popen`.
4. Under the same short state admission gate, recheck closing/quarantine,
   then attempt spawn. If a deadline expires before calling `Popen`,
   classify as **proven no-spawn**; remove intent durably. If a spawn might
   have occurred or an exception is ambiguous, persist `UNKNOWN` and
   quarantine, never optimistically retire.
5. If a leader exists, record `RUNNING` observations, independently
   handle bounded streams and cleanup without holding the global state
   gate during potentially blocking IO.
6. Under the held Worker ownership, **recheck the same internal proof
   qualification from §2.1**, then durably retire only if the selected
   evidence contract is satisfied. With only original-group evidence and
   no valid test grant, mark `UNKNOWN` and quarantine globally instead.
   A proven full-tree contract is a future separate review gate. Only
   after durable retirement or conservative `UNKNOWN` finalization may
   the in-memory Worker slot be released and a response sent.
7. A lost or cancelled response never starts a replacement Worker.
   The caller must not treat absent response as an unsuccessful apply.

Never overwrite or delete an unresolved attempt record as part of a new
request. On an exception in persistence, spawn, drain, signal, wait, or
finalization, bias to retained `UNKNOWN` and closed Exec admission.

## 5. Cleanup evidence and escalation boundaries

Review implementation of the existing Python executor separately; D0
does not approve changes to signal semantics. Require bounded monotonic
deadlines for normal wait, TERM/KILL escalation **only when target
identity is still verified**, stream drain, and reap of directly owned
children. Do not wait forever for descendants or emit success on an
unbounded join. A group presence probe is merely group-scoped evidence.

If any leader/group cleanup is unconfirmed, explicitly persist `UNKNOWN`
and quarantine **all Exec across the instance**, not just the named
Workspace: authorized project code shares the Gateway OS user's privileges
and may operate beyond its Workspace. Keep unrelated File read and
separately granted File Write/Git gates independent, unless their existing
policies independently deny the operation. Never auto-retry or silently
restart the same command.

**D0 decision (P2-01):** the directly owned leader must be reaped, the
original group must be verified absent under a bounded policy, and the
**same live internal §2.1 group-only test grant must be valid at admission
and finalization**. Only then may a disposable fixture attempt become
durably `RETIRED` with `cleanup_scope=original_group_only` and
`full_descendant_tree_clean=not_proven`; a later test request within the
same healthy fixture may be admitted. A normal Gateway with both Exec
opt-ins but **no separate full-tree proof** never qualifies for this
`RETIRED` transition: reject unsupported new apply before spawn, or
persist `UNKNOWN` and global quarantine if an already-running attempt
has only original-group evidence. A grant never clears an earlier
quarantine. Positive evidence of a detached descendant, any uncertain
leader/group cleanup, lost state ownership, invalidated test qualification,
or failed persistence forces `UNKNOWN` and global quarantine even inside
the harness. This is **not** a full-tree clean result, and production
activation remains blocked until a separately reviewed full-descendant
contract is proven. Heartbeat silence or PGID disappearance alone cannot
satisfy the future full-tree gate.

Crash windows are conservative: after intent fsync/before Popen; after
Popen/before PID metadata; after leader exit/before cleanup verification;
after verification/before durable retirement; and after retirement/before
HTTP/MCP response. After a restart, all unresolved earlier windows
quarantine, while a durably retired call is **never replayed**.

## 6. External reporting, recovery and authorization

Retain the existing separate `server.exec.enabled` and Workspace
`exec.enabled` opt-ins, Workspace selection, command allowlist, and
`dry_run=true` default. **P3-02 — precise status contract:** report
the same sanitized `exec_policy` snapshot from `/info` and `/health`:

- `adapter_exposed` means the REST/MCP route/tool was configured and
  registered for at least one eligible Workspace; it is **not** an
  assertion of safe runnable status and may remain `true` during
  quarantine to expose a consistent denial.
- `available=true` requires effective instance + Workspace permission,
  healthy/private durable state and ownership lock, **no quarantine**,
  and a live permitted cleanup qualification (the private disposable
  test grant or a future independently approved full-tree mechanism).
  It represents **safe eligibility**, not an empty concurrency slot;
  slot exhaustion still reports `busy`. `available=false` whenever
  quarantined, uninitialized/unavailable, permission-disabled or missing
  the required proof mechanism, even if `adapter_exposed=true`.
- `quarantined=true` means Exec admission has latched closed on
  `UNKNOWN`, corrupt/foreign records or lost state trust; it cannot
  be cleared remotely. `durability_state` is exactly one of
  `disabled | healthy | quarantined | unavailable`. `unavailable`
  covers unreadable/unwritable state or missing exclusive ownership;
  both `quarantined` and `unavailable` cause `available=false`.
  In an unavailable case admission is latched closed as well, even
  where a quarantine marker itself cannot be persisted.
- `quarantine_reason_code` is `null` for healthy/disabled, otherwise
  one stable sanitized code such as `cleanup_unknown`,
  `corrupt_record`, `owner_lock_unavailable` or
  `state_io_unavailable`. No PID, argv, environment, root or state
  path appears in status. `completion_capability` is exactly
  `none | test_original_group_only | full_tree_qualified`, with
  `full_tree_qualified` forbidden to R1; do not confuse it with
  the user-requested execution policy.

Error precedence for requests: missing global/Workspace permission ->
`exec_disabled` (HTTP 403); durable `UNKNOWN` / corrupt recovered
state -> `exec_quarantined` (HTTP 503); unavailable storage/owner lock ->
`exec_state_unavailable` (HTTP 503); both opt-ins but no qualifying
cleanup mechanism -> `exec_cleanup_proof_required` (HTTP 503);
healthy but all Worker slots occupied -> `busy` (HTTP 409).
Use identical stable codes in MCP `isError=true` structured responses,
with no lost-response replay. Even a `dry_run` cannot report readiness
while quarantined or state-unavailable. No REST/MCP input can create
the internal §2.1 acceptance grant. File/Git policy and their
readiness indicators remain independent.

There is **no REST/MCP reset/unquarantine endpoint**. Recovery is an
explicit, separately approved offline operator procedure performed
while the Gateway is stopped. It must retain forensic evidence and
independently establish safe process cleanup; merely observing a missing
PID, waiting, deleting marker files, or restarting is insufficient.
When reliable proof is unavailable, leave Exec disabled/quarantined and
escalate for manual containment. Avoid sending signals to unknown process
identities after restart. Document any OS reboot/isolation conditions
explicitly before proposing an unlock, and independently review them.

## 7. Required RED contracts before implementation

A. State admission: no state/dir fsync -> no spawn; fail-close on changed
   state inode, symlink, hardlink, corrupt, unknown, oversized or missing
   records; duplicate Gateway owner cannot admit a second process.
B. Spawn ambiguity: forced failures immediately before/after `Popen`,
   killed Worker after durable intent, leader exits early, errors during
   capture/drain/signal/wait; every ambiguous state quarantines.
C. Restart: crash before spawn, crash after child start, crash after leader
   reaped but before retirement, stale marker after restart, repeated
   restart while quarantined, and no blind PID/PGID signal.
D. Boundaries: one Workspace / four-instance slots, concurrent unrelated
   reads, shutdown drain, HTTP/MCP waiter cancel, no automatic replay,
   disabled Exec defaults and fully independent Git grants.
E. Status and recovery: stable error codes, sanitized metadata and
   offline-only recovery; no remotely available reset.
F. Disposable macOS ARM64 negative fixtures: original-group child,
   **separately detached** descendant (prove the limitation without
   treating a heartbeat as reaping), a fault-injected cleanup failure,
   and an abrupt kill/restart of the *temporary* Gateway. No real user
   workspace, uncontrolled external signal, or private Tunnel in D0.
G. Both GitHub CI and macOS runs pin the same Head+Git Tree and verify the
   full Manifest. Original Job logs, not developer summaries, are evidence.
H. **P2-01 default DENY:** normal Gateway with global and Workspace Exec
   enabled, but no internal grant/full-tree mechanism, cannot start a
   new non-preview apply (`exec_cleanup_proof_required`, zero `Popen`).
   Fault-inject a preexisting normal `RUNNING` attempt with leader
   reaped and only original group absent: it MUST NOT `RETIRED`;
   record `UNKNOWN`, globally quarantine, and refuse another apply
   after restart (`exec_quarantined`). Adding config, env var, CLI
   flag, REST/MCP `test_mode` or synthetic metadata cannot change this.
I. **P2-01 positive test:** the internal trusted harness creates a
   private temporary root/state, pins identities, restricts loopback,
   injects one correctly bound nonserializable test grant, and enables
   both normal Exec permissions. Leader reap + original-group absence,
   no observed detached child and healthy state permit `RETIRED`
   with `cleanup_scope=original_group_only` and
   `full_descendant_tree_clean=not_proven`; a subsequent healthy test
   request can run. Alter the Workspace identity, state FD, service,
   bound process, listener, grant lifetime or attempt identity: all
   mismatch cases DENY, never silently RETIRE. A restart loses the
   grant; importing an old test-only `RETIRED` into a normal state
   root quarantines, never becomes proof of full-tree absence.
J. **P2-01 no exception to quarantine:** even with a valid test grant,
   a positively observed detached child, leader/group uncertainty,
   state write fault or preexisting `UNKNOWN` must quarantine globally.
   Test qualification must not clear an existing quarantine; test-only
   `RETIRED` can never mean full-tree cleanup or production PASS.
K. **P3-01 quota:** test retired-only bounded reclamation, no deletion
   of unresolved markers, quota exhausted with no retired record
   (`exec_state_unavailable` / zero spawn), fsync/unlink failure,
   torn temp entry after simulated crash, and exact 4096-record/16 MiB
   boundary. No test reset or eviction of `UNKNOWN` may pass.
L. **P3-02 reporting:** exercise `/info`, `/health`, REST and MCP in
   disabled, healthy-but-no-proof, internal-test-qualified, quarantined,
   state-unavailable and busy-slot cases. Assert exposed-tool state
   can remain true while `available=false`, sanitized consistent
   fields, stable errors/HTTP codes, and no request-origin qualification.

## 8. Staged implementation and hard stops

- **D0 now:** review this contract only. No runtime, test or workflow
  modifications in this design PR.
- **R1 next, only after independent D0 PASS:** add deterministic RED
  state-machine/fault-injection tests, with no privileged process operations.
- **R2, after R1 review:** implement private durable Exec intent/admission
  and restart quarantine in Python; keep old PR #56/#57 fixed.
- **R3, separately reviewed:** bounded cleanup observation and macOS
  temporary subprocess failure tests; allow only claims that are directly
  proven by source and original CI.
- **R4:** independent Standards/Spec code reviews and separately approved
  product-grade E2E/Tunnel verification. No production merge/activation
  until every required process-cleanup gate and recovery guarantee passes.

**STOP:** Unknown cleanup remains quarantined. No Native C / Candidate C
load or group-signal research, external production commands, PR merge,
deployment, tag, uncontrolled host signals, or automatic unlock.
