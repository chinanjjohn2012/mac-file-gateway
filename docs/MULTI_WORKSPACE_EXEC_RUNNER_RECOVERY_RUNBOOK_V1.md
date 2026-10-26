# Multi-Workspace Runner UNKNOWN recovery runbook V1 — R0 proposal only

Status: UNEXECUTED DESIGN / NO RESET AUTHORIZATION. Inherited D0 private state, owner.lock, fsync ordering and quarantined boot behavior remain effective. No executable recovery code or operator command is created by this document.

## 1. Safety goals and exclusions

- Any uncertainty about start identity, domain identity, runtime ownership, cleanup, retention or final durability means UNKNOWN and global Exec QUARANTINED.
- Never automatically replay commands, erase uncertain records, use a stale PID/PGID for signalling, trust a missing PID as whole-descendant cleanup or promote native group-only evidence to full F3.
- File and independently authorized Git paths continue only under their own policy; Exec quarantine must not globally block those paths.
- Recovery by an operator is NOT automatically approval to enable real Exec or edit production state. No remote reset/unquarantine endpoint.

## 2. Proposed state semantics

IDLE -> PREPARED (atomic fsync intent) -> STARTING (allocation initiated) -> RUNNING (may have executed) -> CLEANUP_PENDING (cleanup in progress) -> RETIRED_LIMITED (Native limited evidence) or RETIRED_PROVEN (qualified Strict full-domain evidence). Any uncertain phase or corrupt record goes to UNKNOWN/QUARANTINED.

All names beyond existing v1 PREPARED/RUNNING/UNKNOWN/RETIRED are proposed future schema, not current executable transitions. Existing v1 RETIRED is original_group_only only and must never be treated as RETIRED_PROVEN.

## 3. Crash-window decision matrix

| Failure window | Required conservative handling |
| --- | --- |
| before durable PREPARED | do not launch; unresolved temp/uncertainty quarantines |
| after PREPARED, before allocate | authenticated backend absence proof needed for safe closure; otherwise UNKNOWN |
| create request succeeded but ACK lost | query authenticated backend by attempt/generation; no duplicate domain allocation |
| domain allocated, launch not acknowledged | Strict requires non-runnable execution barrier until durable identity bound; uncertain remains UNKNOWN |
| launch sent but execution ACK lost | query same attempt, never retry spawn |
| command completed but group/domain cleanup pending | do not send clean response or release lease |
| termination request/stop callback lost | re-observe authenticated same domain, not a guessed pid |
| verified stop but RETIRED fsync lost | preserve UNKNOWN/last durable state; never advertise clean retirement |
| Gateway or Manager abrupt failure | boot scans private state before any Exec; quarantines unresolved; no old PID group signalling |
| stale callback, PID reuse, wrong Workspace dev/ino | generation/fencing rejection, no retirement or unrelated termination |
| operator upgrade/downgrade | unknown schema or missing backend qualification means Exec disabled and evidence retained |

## 4. Operator-only procedure (to be reviewed; not yet runnable)

1. Stop positive Exec admission. Preserve original state root, lock and all forensic bytes; record evidence hash, software version, source Head/Tree, backend binary/image/config, attempt and root dev/ino. Do not modify user project or private credentials.
2. Gather bounded server logs and backend authenticated execution-domain inventory using reviewed backend tooling. Exclude raw secrets, argv/environment, stdout/stderr from durable state.
3. For Strict, verify the old bound domain with attempt ID + owner generation + backend opaque identity, determine whether it is still executable/restorable, and use independently authorized whole-domain shutdown protocol. Verify terminal domain state and anti-restore/no-guest-to-host-broker before considering closure.
4. For Native, **do not infer whole-descendant termination** from group absence. Propose a risk-specific operator containment decision only under the new limited contract; absence of direct old identity/reliable evidence means remaining quarantined. No blind kill, reset or deleting a marker.
5. Verify no stale callback, other Gateway instance, alternate owner or active previously allocated resource can revive the same attempt. Record observations and uncertainty honestly.
6. Submit offline recovery evidence and proposed transition to B/C for independently reviewed procedure where necessary; only an explicitly approved, separately implemented recovery tool may alter evidence. Any failure or uncertainty leaves Exec unavailable.
7. Re-open admission only after correct contract-level recovery qualification, explicit operator authorization and safe state upgrade. A successful clean reboot is **not** by itself an unquarantine proof.

## 5. Operational constraints and budgets

Use finite deadlines and quotas for state records (historical D0 references 4096 records, 4096 bytes/record, 16MiB payload), cleanup attempts and backend resources. UNKNOWN domains count as occupied, not evicted by TTL. Require a verified owner lock; no GC of PREPARED/RUNNING/UNKNOWN/corrupt records. Keep a separate finite budget for guest startup, disks, memory, helper processes and cleanup. Unknown domains cannot consume unlimited resources silently; stop new Exec admission and require safe operator action.

## 6. Acceptance tests (separate from this R0)

T0 Mock: fsync/rename fail, ambiguous create ACK, stale generation, fake PID reuse, stop callback drop, final fsync fail, multiple owner scans, schema migration and attempted reset; all must fail closed. T1 disposable local: owner.lock/private FS and legal Git/File remain independent. T2 later only with separate exact Mac ARM64 disposable environment, process identity constraints, external watchdog, bounded processes/memory/disk/time, approved host shutdown and evidence preservation. T3 user Mac/Tunnel/shared resources prohibited absent separate authorization.

No native termination, VM shutdown or user-host recovery tests performed in R0.
