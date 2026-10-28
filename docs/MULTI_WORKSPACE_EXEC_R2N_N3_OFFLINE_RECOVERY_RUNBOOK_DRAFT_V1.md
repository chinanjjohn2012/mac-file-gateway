# R2-N N3 — proposed offline forensic recovery and rollback runbook V1.0

**DRAFT PLAYBOOK FOR FUTURE AUTHORIZATION ONLY. Do NOT follow this document to alter a real Gateway or clear its state now.**

TASK_ID: MULTI-EXEC-R2N-N3-PRIVATE-STATE-DESIGN-20261028
REVIEW_ROUND: r001
REVIEW_TARGET: no-replay, evidence-preserving, offline-only Native state and failure recovery procedure suitable for independent B/C design challenge; not a runnable automatic reset.
DESIGN_INPUTS: operative D0 §§0.1/0.4/3/4/5/6; approved PR #92 future-N2 D0 proposal, N0–N6 plan; PR #93 r002 approved bounded N2 Fake. Current installed F1 deny-only remains intact.
AUTHORIZATION: this is only documentation, source-static T0 and review; NOT permitted to stop/restart a service, send a signal, unlink state, run real private-FS/Git/SDK T1, perform a crash/T2, touch a user Mac/Tunnel/T3, merge, deploy or modify production config.

## 1. Incident triggers and immediate response principle

Stop new Native **admission by design** upon missing/foreign owner.lock, unexpected state/lineage identity, malformed schema, unknown pending/final fence, incomplete fsync, ENOSPC, full forensic quota, prestart revoke ambiguity, stale generation, late-positive survivor, lost response with uncertain attempt, physically unqualified cleanup or absent trusted Mac signal identity. Default F1 nonpreview apply remains denied regardless.

A state marked UNKNOWN, QUARANTINED or UNAVAILABLE is not a cleanup certificate. **Never try to "repair" by retrying a command**, deleting a marker or response, trusting a PID/PGID snapshot, or running killpg after restart. Safe File/Git capabilities must remain governed by their independent grants and any separate incident restrictions, not a global Exec-subprocess ban.

Status visible to remote clients must be sanitized: report only stable reason and available=false/completion_capability=none under current F1; do not expose private root, persisted IDs, command, environment, tokens, stdout or process identity. No REST/MCP reset or consent-issuance endpoint is proposed.

## 2. Operator decision tree (design, NO actions executed)

| Condition | Immediate policy | Evidence to preserve | Decision owner / future gate |
| --- | --- | --- | --- |
| Prior N3 lineage and namespace both present with consistent versions, no current runs, but boot-deny armed | Always refuse Native after restart | Both pinned-root identity records, owner generation, marker/attempt tombstones | Separate offline recovery authority; no automatic healthy boot |
| Namespace missing but witness/consent survives | Quarantine/deny; NEVER first-init automatically | Witness, old consent record hashes, directory history and absence | Local owner investigation; separate independent replacement anchor design |
| Both namespace and lineage missing | Deny; provenance unprovable | Best available original installation/provision approval and system backups | Do not automatically first-provision; explicit separately authorized offline decision only |
| Owner lock busy/replaced/foreign | Deny/unavailable | Current lock FD identity when safely observable, original stored inode and ownership facts | Independent safe-owner verification; no replacing lock while in use |
| Failed fsync/rename/final-fence unlink | Deny/unavailable | All surviving pending/final/temp marker bytes and generations | Actual disposable FS tests T1 later; treat finalization unconfirmed |
| Unknown PREPARED/STARTING/RUNNING at boot | Quarantine + retain | Old attempt owner/epoch/reference, boot-deny | No replay, no PID/PGID signal based on disk |
| RETIRED_LIMITED with late observed survivor | Global quarantine, supersede current status | Immutable historical decision, positive observation and attribution tombstone | No response retraction; no new clean decision; unrelated attempt B reconciled separately |
| ENOSPC/quota during late-event evidence | Stop admission synchronously even if event cannot fsync | Already precommitted boot-deny marker plus explicit unknown durability of new event | Never present failed persistence as completed |
| Old v1 RETIRED or S2 offline Fake import | Deny migration to Native | Original source type/snapshot, immutable state files | No automatic schema upgrade or test grant promotion |
| Missing actual macOS at-signal safe ownership | NO SIGNAL + Native positive NO-GO | Any trusted non-signal observation (if independently authorized) | Requires distinct Native safety design and T2 resource approval |

If a state cannot be safely inspected without disturbing it, preserve what can be observed read-only and **do not perform speculative cleanup**. A policy document is not itself a cleanup procedure credential.

## 3. Future authorized offline recovery phases (currently STOP at phase 0)

**Phase 0 — now:** only read this draft and design cases; do NOT open or mutate a real state directory.

**Phase 1 — explicit incident/fixture authorization, not yet granted:** identify exact affected disposable instance, operator, separate physical host and current trusted control-plane root. Obtain exclusive planned maintenance, approved safe stop/start strategy, immutable Base/Head and code identities, independent incident scope, known allowed and forbidden operations. For production/shared or user Mac this requires a new T3 consent and incident runbook; this N3 draft cannot supply it.

**Phase 2 — evidence capture before any repair:** under the separately approved safe read-only scope, preserve forensic copies/hashes of relevant lineage witness, owner-lock identity, root inode attributes, control, boot-deny and pending/final marker, all bounded attempts and response decisions, original program/OS versions and exact timestamps *only as diagnostics*. Encrypt/restrict evidence as needed; never publish raw secret paths or executable arguments to PR. Verify the snapshot copy is from stable pinned ownership, and distinguish failed-to-sync observations from proven stored bytes. If an active owner still exists, stop here until its ownership is safely resolved without signal guesswork.

**Phase 3 — independent absence and identity qualification:** do not infer all descendants absent from reaped leader, missing PID, PGID probe, elapsed time or clean restart. For future native_limited, separately establish the qualified owner/group cleanup and explicit acceptance of possible unobserved detached survivors. If no macOS lifetime-safe mechanism exists or a known positive survivor appears, keep Native locked and escalate; no signal is permitted by this N3 runbook. True full-tree cleanup remains strict_f3's separate D1–D6 task.

**Phase 4 — separately approved record/namespace disposition:** an owner-signed and independently reviewed decision may authorize a new namespace_id/lineage_generation or an offline recovery procedure on a **disposable instance** only after all resource/state ownership and rollback concerns are resolved. Do not delete historical evidence; preserve old immutable records/tombstones and link superseded attempts. Never resurrect v1/S2 test grant, convert limited into proven, or make an old local consent valid by copying it. A previously lost entire namespace/lineage cannot be authenticated through a mere fresh file creation.

**Phase 5 — independent re-verification, before any future enablement:** verify exact accepted code Head/Tree/Manifest, owner/lineage/namespace identity, all prior unresolved attempts accounted, new control-plane authority, private FS durability and byte limits, independent test evidence and the still-separate process-signal qualification. Even after successful offline source recovery, current installed F1 ordinary Exec Apply remains denied; any future profile enablement is a distinct user/operation decision.

No phase above should be mistaken for an actual command list. This PR does not implement or execute any of them.

## 4. Restoration is not equivalent to resurrection

**Permitted future choices after proper authorization:** (a) leave the disposable instance in deny-only quarantine while retaining all evidence; (b) abandon disposable test fixture after securely recording evidence and resource cleanup authorization; (c) open a separate review/authorization for a new fresh local operator provenance chain. Under no circumstance does "restore last backup" automatically restore Native admission.

**Forbidden shortcuts:** replacing/unlinking owner.lock while stale owner might be live; deleting boot-deny/final-fence/UNKNOWN to get a healthy status; reissuing a previous consent epoch; reusing owner_generation or attempt_id; retrying a command after lost ACK; mutating another Workspace to fix Exec; invoking a signal to an untrusted numeric PGID; assuming same-UID filesystem trust provides cryptographic rollback resistance; silently merging old v1 or S2 Fake states.

**State backup with changed inode:** record the mismatch, deny and require separate operator disposition; do not rewrite dev+ino metadata to match a stale grant. When both lineage and state disappear, a cryptographic or independently protected provenance anchor would need to exist to prove history; absent such a capability, the conservative policy is no Native admission, not automatic initialization.

## 5. Proposed rollback of FUTURE test-only code/config

If a separately authorized disposable N3 test later discovers unsafe filesystem behavior:
1. Stop the testing workflow by its approved harness/fixture stop mechanism, **not** by blind process signals, and preserve raw sanitized log, Head/Tree/test bundle and test-only state.
2. Confirm production and user Mac/Tunnel were never targeted and that current F1 is still default deny. Do not recover by enabling Native or loosening group cleanup proof.
3. Identify all test-created private roots by the original fixture manifest and pinned identity; do not run wildcard deletion outside those named roots. If any root identity or potential external process is unknown, do NOT remove it; escalate for a separate safe cleanup authorization.
4. Verify the candidate code and registry were not imported by runtime routes, schema v1 remains strict and legal File/Git scope is unchanged. Retain forensic IDs/hashes before eventually cleaning up a confirmed disposable fixture.
5. Revert only by a future reviewed new commit/branch and fresh B/C reviews, never by silently force-updating the old reviewed N2 or N3 Head. No auto merge/deploy/release.

For the CURRENT design PR, none of these operations occurs; a rollback consists of retaining the Draft PR as review evidence or proposing a separate new design revision, not moving frozen Heads.

## 6. T0/T1/T2 delineation in recovery claims

- T0 may reason about boot/restart/interleaving schedules in memory and validate the JSON test-case table; it cannot prove file durability, actual lock ownership, rollback resistance, OS descendants or real transport.
- T1 later may test an independently authorized disposable private-FS lock/fsync/rename/owner reacquisition and real local-only Git/official SDK, with safe failure injection, but no deliberate disk-fill, process kill, destructive crash or real Native start.
- T2 later would be needed for destructive real OS failure/identity/signal, requiring exact disposable resource, watchdog, rollback and independent safety gate. No T2 can be inferred from T1 or this design.
- T3 user Mac/Tunnel/shared/production remains forbidden without direct separate authorization. No successful N3 result authorizes Strict F3 or production Native positive.

## 7. Required review, forensic integrity and closure

Reviewers must independently challenge at least: missing-both-roots reboot; copy of old consent into a new namespace; old v1 RETIRED or S2 fake witness; lock inode ABA; crash/final fsync ambiguity; ENOSPC after late-positive observation; event-before-response and response-before-event; old pending B; output/command secrets leaking into journal; status race; legal Git subprocess under Exec quarantine. Report which can be checked via static T0, which need separately authorized physical T1, and which require Native T2.

Before accepting any future recovery implementation the owner must specify which exact offline interventions are authorized and which evidence sources establish current owned processes/forensic continuity. If unknown, the only permitted safe answer is **keep Exec disabled/quarantined**.

**FINAL HARD STOP:** This is a proposed procedure, not an instruction or approval to run commands on a real host. Current N3 design-only source/Manifest and scenario syntax checks may proceed; real state mutation, T1/T2/T3, Native process/signals, local operator consent/reset, integration, merge and deployment remain NOT_RUN/NOT_AUTHORIZED.
