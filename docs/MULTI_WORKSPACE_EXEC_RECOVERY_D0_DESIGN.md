# Multi-Workspace Exec: durable lifecycle and unknown-cleanup design (D0)

**Status: DRAFT / DESIGN REVIEW REQUIRED / NO IMPLEMENTATION AUTHORITY.**
**Track: Python product only.** Stacked on the fixed macOS partial-acceptance
PR #57 Head `bb636febe00099be2d15ca6621c1ee2dd892e6e8`, whose base is
PR #56 reviewed product Head `e528ddb809df897b4f81802e0ae5f4f95ff5d2c7`.
The accepted evidence is `PARTIAL_NATIVE_ACCEPTANCE_PASS` only.
Do not merge, deploy, enable production Exec, restart a user's Gateway,
load Native C, or restart Candidate C/B03 research under this design.

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
- `RETIRED`: an intent was durably closed under its explicitly documented,
  bounded evidence contract. This does not mean every detached child was reaped.

Two separate facts must never be conflated: `original_group_clean` (bounded
leader/group evidence) and `full_descendant_tree_clean` (not established
by the existing Python CommandRunner). A returned exit code, EOF, heartbeat
silence, or `killpg` success alone must never set the second fact.
A future full-tree qualification requires a separately reviewed mechanism.
This D0 is a **contract**, not a claim that Python can discover all descendants.

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
Never use timestamps or PIDs as sole authority.

Boot ordering: open and scan the private state **before** any Exec-enabled
API can accept requests. Every surviving `PREPARED`, `RUNNING` or
`UNKNOWN` marker, invalid schema, incomplete atomic update, corrupt entry,
unexpected filename, or untrusted directory results in **global Exec
quarantine**. Healthy empty/retired state can be admitted. No automatic
"the old PID is gone, so recover" shortcut. A new Gateway process must
not signal a previously recorded PID/PGID merely because it exists.

Only one owner may modify the same state root: require an interprocess
ownership lock for the whole Gateway Exec state lifetime, and fail closed
if it cannot be taken. File API and separately authorized Git must not
inherit Exec permission or silently bypass the lock.

## 4. Exact launch ordering and Worker ownership

On `dry_run=true`, perform ordinary read-only validation without spawning
or writing a RUNNING intent; quarantined Exec must still be visibly denied
(rather than presenting a misleading READY preview).

On `dry_run=false`:
1. In the actual synchronous Worker, check global and Workspace grants,
   state health, Workspace slot and four-instance admission limit.
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
6. Under the held Worker ownership, either durably retire according to
   the **bounded** evidence contract, or durably mark `UNKNOWN` and
   quarantine; only then free the in-memory slot and reply.
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

If a command exits and only the bounded original-group contract can be
confirmed, report `cleanup_scope=original_group_only` and
`full_descendant_tree_clean=false/not_proven`; do **not** label this
"all descendants clean." If detached descendants are observed or cleanup
fails, quarantine even if the direct leader has already exited. Design
review must decide whether any ordinary-success attempt can retire with
this explicitly limited guarantee; until that decision, production
activation remains blocked. No progress- or heartbeat-only test can
satisfy the unresolved full-tree gate.

Crash windows are conservative: after intent fsync/before Popen; after
Popen/before PID metadata; after leader exit/before cleanup verification;
after verification/before durable retirement; and after retirement/before
HTTP/MCP response. After a restart, all unresolved earlier windows
quarantine, while a durably retired call is **never replayed**.

## 6. External reporting, recovery and authorization

Retain the existing separate `server.exec.enabled` and Workspace
`exec.enabled` opt-ins, Workspace selection, command allowlist, and
`dry_run=true` default. Expose sanitized `exec_policy` fields:
`available`, `quarantined`, `quarantine_reason_code` and
`durability_state`, without leaking local paths/PIDs or sensitive
command arguments. `run_command` rejects quarantined attempts with a
stable `exec_quarantined` or `exec_state_unavailable` code.
The API may remain discoverable for an operator to diagnose the denial,
but must never spawn while blocked. Other capabilities retain their
independent policies.

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
