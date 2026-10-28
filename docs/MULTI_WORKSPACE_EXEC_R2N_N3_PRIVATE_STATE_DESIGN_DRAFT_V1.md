# R2-N N3 — private state and fail-closed durability DESIGN DRAFT V1.0

**STATUS: PROPOSED / NONOPERATIVE / DESIGN + STATIC T0 ONLY. No code, real filesystem testing, Native process, signaling, integration or activation is authorized by this document.**

TASK_ID: MULTI-EXEC-R2N-N3-PRIVATE-STATE-DESIGN-20261028
REVIEW_ROUND: r001 (new Draft PR; independent of PR #93 r002)
REVIEW_TARGET: N3 private-state namespace, external provisioning witness, local owner/consent and attempt identity, write-ahead failure fences, bounded audit/journal, boot scan, status/adjacency, and failure/recovery obligations.
CONTRACT_SCOPE: user-approved PR #92 r001 proposed Native Limited D0 amendment and N0–N6 plan; user-accepted PR #93 r002 fully bounded N2 T0 source and B/C role-specific reviews. Operative D0/F1 remains unchanged.
GOVERNANCE: ICR-V2.0 / GHRH-2.0 / ETP-V2.0.
FIXED_SOURCE_PARENT: chinanjjohn2012/mac-file-gateway PR #93 r002 Head 162b5f697ec5bfdb228b6aff351b8ac5cc540e3c / Tree e13c2685b9e8762935b818132c8403e31bec3937, B Review 5681296448, C latest Review 5681856989.
USER_AUTHORIZATION: only A N3 design and pure T0 development preparation in a new Draft PR, including detailed implementation/resource/recovery proposal and independent B/C review. NO real private-FS/Git/File/SDK/REST/MCP T1, NO process/signals/T2/T3, NO integration, merging or deployment. Preserve PR #90–#93 exact frozen Head.
STATUS_OF_OLDER_DESIGN: docs/MULTI_WORKSPACE_EXEC_R2N_D0_AMENDMENT_DRAFT_V1.md is an approved future-N2 design input but NOT a modification of current operative D0. Neither this document nor B/C design PASS will itself make D0 Native exceptions effective.

## 1. Explicit threat model, trust and non-goals

The Gateway operates for a trusted local OS user. Workspace contents and scripts are intentionally mutable and execute, if ever separately enabled, with that user's host privileges; N3 is not a same-UID tamper-proof enclave, namespace isolation, anti-rollback cryptographic ledger, or complete descendant cleanup proof. Even a perfect state journal does not turn killpg/PID/PGID checks into safe macOS at-signal group ownership.

Every installed ordinary Multi-Workspace non-preview Exec request keeps existing F1 synchronous exec_cleanup_proof_required denial BEFORE a Worker, PREPARED record, Runner or child. Valid preview and separately granted Git/File continue under their own policies; do not globally intercept subprocess or prohibit legal Git. The schema_version=1 config parser and existing ExecStateStore v1 state are unchanged. Nonspawning S2 v2-fake state and N2 pure-memory tickets are test evidence, never a migration source for Native consent, limited retirement or runtime qualification.

N3 must be off by default even if the new private state is present, well-formed or operator consent metadata exists. No N3 state is a true OS-process/Native start authority; only a future reviewed qualified backend plus approved effective D0, separate local owner consent, safe prestart serialization and macOS identity proof could eventually enable it.

## 2. Proposed storage boundaries and authority hierarchy — NOT created in this round

**Candidate layout (relative to a separately approved and pinned Gateway-private control root, NEVER under a Workspace, backup-visible File API root, v1 exec-state, or S2 offline fixture):**

~~~text
<private-gateway-control>/
  native-n3-lineage/
    provision-witness.v1       # separate pinned parent/inode, private, authenticated boot-history witness
    owner-authority.v1         # local operator-authorized initialization/recovery gate; NOT an API grant
  native-n3-state/
    owner.lock                 # persistent pinned single-link inode, acquired for entire store lifetime
    control.v1                 # schema, namespace ID, lineage ID, owner generation, consent epoch, quarantine
    boot-deny.v1               # independent prearmed NATIVE_UNRESOLVED_ON_RESTART witness
    last-commit.v1             # bounded monotonic state epoch/checkpoint candidate, NOT antirollback crypto
    attempts/
      r-<opaque-attempt-id>.json  # never store argv/output/environment/credentials
    responses/
      d-<opaque-decision-id>.json # immutable as-of-decision evidence, not transport ACK
    pending-* / final-fence-* / tmp-*  # bounded mutation-only names, unresolved on boot => deny
~~~

These are **names and content-contract candidates, not validated OS paths or a request to create them**. File layout must be independently reviewed against actual pinned-FD APIs, macOS metadata/rename/fsync semantics, concurrent owner registration, quota exhaustion and cleanup. No named file may be client-controlled or automatically removed as a way to resume Exec. Separate lineage state must not live inside the delete-able N3 state directory; a root deletion may still take both. If every possible evidence root disappears, the system cannot infer "first-ever install" from absence. Therefore **NO automatic first init at Gateway boot or after missing/rolled-back namespace**, even if old consent appears healthy elsewhere.

**Provisioning identity choices to be separately reviewed:**
- namespace_id: high-entropy, immutable identity minted only by a trusted **offline operator action**, not REST/MCP/Workspace/CLI request data or a startup auto-create; record it in separately pinned lineage and namespace state.
- lineage_generation: monotonically fenced on an operator-approved offline provisioning/recovery; a matching old consent epoch is insufficient if namespace disappears or lineage differs.
- owner.lock identity: pinned dev+ino/mode/UID/regular single-link; on acquisition generate new service_owner_generation. No lock rename/unlink/recreate to clear a bad owner; rejected second/split owner.
- Operator-only first installation must be explicit and separately authorized, with no currently live uncertain attempts and a documented forensic baseline. A witness missing in an otherwise unknown historical setup means NO NEW NATIVE ADMISSION, not a new clean installation.
- A same-UID adversary with arbitrary access who can roll back all state AND the separate witness defeats local-only monotonic rollback detection. This remains a **known limitation**; future positivity requires a reviewed trusted anchor or unconditional deny under uncertainty. Never advertise cryptographic antirollback from timestamps or checksum.

## 3. Versioned bounded data contracts (proposals, no parser/runtime code)

Proposed Native namespace schema_id=native-n3-v1, **not** old ExecStateStore.schema_version=1 or S2 offline-fake schema_version=2. Treat unknown fields, duplicates, wrong types, nonfinite numbers, inconsistent epochs, unsupported previous versions, malformed/ambiguous filenames or symlinks/hardlinks as quarantine/unavailable. Do not deserialize Python objects, pickle or execute stored content.

**control.v1 minimum fields:** schema_id, namespace_id, lineage_generation, state_generation, consent_epoch, consent_record_id, consent_active, consent_expiry_or_null, consent_binding_digest, owner_generation, owner_lock_dev, owner_lock_ino, global_quarantined, global_quarantine_reason, max_attempts, max_attempt_bytes, max_total_attempt_payload, unresolved_retired_tombstone_count. No field by itself unlocks Native.

**Local operator consent record (future only):** profile=native_limited, trust_scope=mutable_workspace, canonical selected Workspace ID, pinned Workspace root dev+ino, effective server AND Workspace Exec grants, normalized exec_paths/runner selection, backend implementation+version+config digest, reviewed risk-contract identity, explicit acknowledgment of host-user access/irreversible effects/possible detached survivors, operator issuer identity, expiry/revocation if provided and consent format version. The effective binding digest covers all of these with an unambiguous canonical encoding; source Git HEAD and in-root mutable scripts intentionally do NOT rotate consent_epoch. A root/permission/backend/runner/risk-contract change MUST fence consent and invalidate stale tickets. B93-R001-P3-01 is **not closed by existing N2 FakeScope**; closure requires new reviewed type and independent per-field T0 negatives, then a separately authorized real-source T1 check.

**Attempt minimum fields:** opaque non-reusable ID, attempt_generation, service_owner_generation, consent_epoch, namespace_id, lineage_generation, pinned root identity, effective binding digest, phase PREPARED|STARTING|RUNNING|CLEANUP_PENDING|RETIRED_LIMITED|UNKNOWN, status/cleanup scope, full_descendant_tree_clean=not_proven, evidence references, monotonic model decision sequence. The mere presence of an attempt ID does NOT grant start/terminate/signal.

**Server response decision (future only):** separate decision_id, attempt_id, attempt_generation, owner_generation, decision_sequence, phase_at_decision, decided_at_as_of_marker, decision_kind=LIMITED_HISTORICAL_COMPLETION_COMMITTED|QUARANTINED_OR_CLEANUP_UNKNOWN, cleanup_scope=original_group_only|none and full_descendant_tree_clean=not_proven. No ack=true by default. Actual client delivery, queue insertion, bytes written and ACK are separate, independently provable facts not part of a state fsync claim.

**Quota proposal:** max 4096 total attempt records, max 4096 encoded bytes per attempt record, max 16 MiB for attempt-record payload. Separately budget lineage, control, response records, directory entries, bounded pending/final safety fences and reserve for late-positive/orphan quarantine evidence; the fixed reservation must be accounted and proven prior to the first possible start. At limit reject new PREPARED and preserve unresolved and RETIRED_LIMITED forensic linkage; no age/TTL or quota-driven removal of those records to reopen capacity. If metadata reservation is insufficient, fail closed without evicting attribution. Count cap alone in N2 is NOT the byte/durability proof (B93-R001-P3-02).

## 4. Candidate atomicity and owner protocols, each requiring future T1 proof

**N3 boot:** open only vetted private parent(s) with O_DIRECTORY/O_NOFOLLOW/O_CLOEXEC, verify FD identity and permissions; acquire one lifetime exclusive pinned owner.lock and verify original inode continuously; read separately pinned lineage and N3 namespace BEFORE permitting any future admission. A newly started Gateway must deny if either root missing, namespace/lineage mismatch, preexisting foreign marker, dangling temp, invalid schema, failed prior commit, earlier live PREPARED/STARTING/RUNNING/CLEANUP_PENDING/UNKNOWN, or armed boot-deny. Rotate owner generation only with durable ownership and scan; no resurrection of old ACK or old consent. **Default F1 remains deny even when all the future metadata checks would succeed.**

**Mutation transaction (proposed order, not an assertion of actual fsync success):**
1. Validate owner identity, consent/attempt generations and capacity. Under one reviewed short admission/forensics gate, close future Native admission on any uncertainty.
2. Ensure a separately pinned, initialized lineage witness exists; before the *first potentially irreversible* start in a generation, create + fsync + directory-fsync independent boot-deny witness, with an advance-reserved bounded late-event forensic slot. The boot-deny marker remains **armed across any RETIRED_LIMITED and all restarts** until a separate offline-authorized recovery with actual independent evidence. A healthy operator consent record does not erase it.
3. Create a random pending mutation marker and durable independent final-fence marker; fsync each and parent directory. Validate intended record size/count/total and write temp completely; fsync temp, atomic rename, fsync parent. Remove pending, fsync, validate inode identity, then remove final-fence last. The precise no-window guarantee, especially directory fsync AFTER final-fence removal, is a **T1 obligation**; if its outcome is unconfirmed, deny on boot rather than announce clean commit.
4. PREPARED with durable fence must precede any backend allocation/STARTING. Future STARTING fsync must precede last irreversible dispatch, with revoke and late-survivor global latch serialized against that dispatch under an independently proven owner authority. N3 has **no real dispatch** and may only model a counter in T0; userspace lock + later os.spawn is not a proof.
5. For synthetic late-positive evidence, close new admission immediately in memory even if the journal cannot allocate/fsync. Preserve the previously fsynced boot-deny witness as reboot hazard; mark the newly observed evidence durability UNKNOWN, not "persisted". Unknown attribution => global orphan quarantine, no guessed PID signal.
6. Once any durability, owner, inode, quota, ancestry, rollback/witness or serialization step fails, no positive result, no new PREPARED/STARTING or Worker claim may be issued; mark unavailable/quarantined with a sanitized reason. Preserve all available forensic bytes for authorized offline inspection.

**Design caveat:** POSIX rename and fsync alone do not automatically guarantee power-loss durability on every filesystem/platform or defeat an adversary modifying same-UID directories concurrently. Actual API sequence, FD ownership, root pinning, crash behavior and macOS directory semantics must be independently validated on a specified disposable platform. T0 static schedule alone is not such evidence.

## 5. Lifecycle and stop/restart truth table

| Observed/candidate state | Initial or restarted admission | Minimum safe decision |
| --- | --- | --- |
| No independent lineage witness; unknown history | DENY | Never auto-create an empty healthy N3 namespace; explicit separately approved offline first install/recovery only |
| N3 namespace missing with old consent/witness retained | DENY/QUARANTINE | Reopen not permitted; retain lineage evidence, require offline investigation |
| Lineage missing but native state looks valid | DENY/UNAVAILABLE | Treat as unknown provenance, not fresh provisioning |
| Lineage + namespace both missing | DENY | Cannot distinguish deletion/rollback from first install; no automatic positive Native |
| Lock in use or same-name replaced inode | DENY/UNAVAILABLE | No split owner, no new lock O_CREAT on previously provisioned namespace |
| Unknown/corrupt schema/temp/final-fence | DENY/QUARANTINE | Preserve bytes for forensic examination, no client reset |
| Valid consent but PREPARED/STARTING/RUNNING/CLEANUP_PENDING after restart | DENY/QUARANTINE | Reclassify uncertain earlier attempt UNKNOWN only via reviewed durable operation; never retry/start |
| RETIRED_LIMITED + armed boot-deny after restart | DENY/QUARANTINE | Original group absence did not prove escaped descendants absent; consent may remain as data only |
| ENOSPC at late-positive journal write | DENY immediately | Existing precommitted boot-deny must survive reboot; do not report failed write as durable |
| Decision committed before late event | Historical as-of only | Later event quarantines current capability; cannot retract a delivered result |
| Late event committed before decision | No new apparently clean result | Nonclean/UNKNOWN decision only; no client ACK invented |
| Completely valid theoretical state, no Native platform identity proof | STILL F1 DENY | N3 state does not override exec_cleanup_proof_required or supply BackendQualification |

No offline procedure may simply delete a marker, unlink UNKNOWN, recreate owner.lock, restore an old consent file, infer PID absence from elapsed time, or replay an attempt.

## 6. External API and adjacent product boundaries

N3 must be internal-only and independently versioned. No new REST/MCP endpoint, external flag, schema v1 fallback, response token or arbitrary caller is allowed to create local operator consent, change security profile, clear quarantine, restore the namespace, import v1 RETIRED or issue a Native signal. Existing status must continue F1 available=false/completion_capability=none; proposed separate status fields, if introduced only in a subsequent approved code round, must be sanitized and consistent across /info and /health.

Existing gateway/workspaces.py WorkspaceService.invoke_exec must continue to reject ordinary valid dry_run=false before Worker/PREPARED/Runner/Popen; gateway/http_multi.py and gateway/mcp_multi.py still share that gate. Existing authorized Git can legitimately invoke a Git-specific subprocess and File Write remains separately scoped when Exec is denied/quarantined; N3 does not globally intercept Python subprocess, block Git based solely on Exec quota, or modify Legacy/Local Skills. The N2 Fake, S2 real-FS offline candidate and current ExecStateStore v1 remain isolated, with no source import or state reinterpretation into a live Exec authority.

## 7. Required challenge questions and closure criteria

- B92-R001-P3-01: clarify that a separately authorized future N3 T1 may exercise real legal Git subprocess even though Native Exec launch/PGID/signal is forbidden; NEVER perform that test now.
- B92-R001-P3-02: counterexample delete the **entire** N3 namespace while retaining outside consent; also delete BOTH local namespace and witness. Absence cannot become automatic new install. Require an independent trusted provenance anchor OR unconditional deny and separately approved offline provenance restoration.
- B93-R001-P3-01: changed effective server/Workspace grants, runner/backend config/expiry must change canonical authority binding even if Workspace scripts remain mutable.
- B93-R001-P3-02: enforce record count, per-record byte and 16 MiB attempt payload independently; accounting and reserved forensic markers cannot create a false healthy state under ENOSPC.
- B91-R001-P3-01: response decision durable linearization and late-survivor quarantine event must share an authority boundary; transport ACK is never implied.
- B91-R001-P3-02: "boot-deny witness" needs exact reservation, fsync order and restart failure evidence, especially after ENOSPC at finalization, not merely Mock memory.
- C93 R002 P3: managed Worker 1/Workspace and 4/instance is not an OS descendant bound; no real leader/group cleanup identity, response transport, local operator consent or macOS signal proof can be inferred from N3.

**Present round review:** two independent B/C TARGETED DESIGN reviews on this new fixed docs/Manifest/T0 scenario content, including independently authored counterexamples and exact ETP E1–E8 evidence qualifiers. A's work does not close their P3 or sign their verdicts.

## 8. Hard safety stop and evidence scope

N3 T0 now: read only fixed GitHub source, write docs/Manifest in a separate design branch, statically check complete Git Tree/paths/new file hashes, and optionally validate *scenario data syntax* in an isolated stdlib context. This checks no actual persisted state, native metadata, owner.lock, filesystem fault/ENOSPC, Git/File/SDK, REST/MCP, background process or transport.

FUTURE T1 requires a **new explicit resource-by-resource owner authorization** and fresh Head identity; FUTURE T2 process/signal experiments require separate macOS disposable safety, watchdog and rollback approval. T3 real user Mac/Tunnel/shared/production, merge, deployment, effective D0 amendment, native_limited positive admission, cleanup proof, real state schema migration and UNKNOWN clearing all remain NOT_AUTHORIZED / NOT_RUN / NO-GO.
