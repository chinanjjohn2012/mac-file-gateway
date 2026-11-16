# Multi-Workspace Exec LBE R009 - Job-Global Envelope and Positive-Success Repair

TASK_ID: MULTI-EXEC-LBE-FIVE-DAY-CANDIDATE-20261105
MILESTONE_ID: LBE-FIVE-DAY-CORE-PRODUCT-CANDIDATE
DESIGN_ID: MWE-LBE-R009-T1-JOB-GLOBAL-DESIGN-008-CANDIDATE
STATUS: PROPOSED_NOT_EFFECTIVE
PARENT_R008_DESIGN_BLOB: a9d78a1e07b345a3ec69cb93ac9d5cca8246c3fe
PARENT_R007_DESIGN_BLOB: e9094844bb21517d8ca585560003ba4c5cd16dfe
PARENT_R006_DESIGN_BLOB: b8d8a1cb32fb7130dfa6d00b37831dfddfaad11c
RULESET_ID: ICR-V2.0
HANDOFF_PROTOCOL_ID: GHRH-2.0
EVIDENCE_PROFILE_ID: ETP-V2.0
HOST_OPTION: UNDECIDED
REVIEW_SEQUENCE_OPTION: UNDECIDED
PRODUCT_T1: DENY
INTEGRATION_STATUS: NOT_TESTED

This is a design-only repair. It does NOT select A1 or B1, does NOT weaken the
current strict R006 host gate and does NOT authorize PRODUCT_T1. R008 remains
the parent contract except where this file explicitly replaces or tightens it.

## 1. Review findings repaired by R009

R008 Standards independently issued TARGETED_REVIEW_PASS with P2=0 and two P3
precision items. R008 Spec independently issued FAIL with one P2 and one P3.

This R009 candidate repairs all of them:

1. C114-R008-DESIGN-007-SPEC-01:
   a GitHub Job ID alone cannot serialize two legitimate WorkspaceService
   instances that use different config/journal roots inside the SAME Job.
2. C114-R008-DESIGN-007-SPEC-02:
   six observed child completions are not six positive successes unless each
   exact benign command exits zero and satisfies its output/filesystem policy.
3. B114-R008-ST-D007-P3-01:
   public Job API identity plus environment strings are not cryptographic proof
   that the local process belongs to the approved Job.
4. B114-R008-ST-D007-P3-02:
   NO_EXPLICIT_CREDENTIAL_INJECTION must state exactly which preproduct process
   sees SSH_AUTH_SOCK and must prove it never migrates to product helpers/child.

No prior PASS/FAIL/BLOCKED is inherited as a R009 verdict.

## 2. Normative precedence

All R008 sections not changed below remain proposed and non-effective.
R009 replaces R008:
- section 6 Job-envelope uniqueness and local-to-Job continuity;
- section 7 one-Job/six-command success semantics;
- the relevant future owner execution-grant fields in section 9;
- the matching safe-T0 requirements in section 10;
- credential-selector process-boundary precision in sections 3.1/11.

A0/B0 retain strict deny semantics unchanged.
A1/B1 remain UNDECIDED and cannot be implemented until this exact R009 design
receives independent B/C design PASS and the owner later makes the required
option/risk decision.

## 3. One canonical durable Job envelope, not one ledger per config root

### 3.1 Deterministic Job envelope key

For a future B1 PREEXEC_HOLD, the tracked trusted bootstrap derives:

JOB_ENVELOPE_KEY = SHA256(canonical ASCII fields):
r009-job-envelope-v1
repo
pr
workflow_id
workflow_path
workflow_ref
github_run_id
github_run_attempt
github_job_id
github_job_name
head_sha

No REST/MCP/client/config field can override any component.

The envelope pathname is derived only from that key under a fixed platform
anchor:

/private/tmp/mfg-r009-job-<64-hex JOB_ENVELOPE_KEY>

The bootstrap must first open and verify /private/tmp itself as:
- a real directory, no symlink;
- uid=0;
- mode exactly 01777;
- stable dev/inode/uid/mode across creation;
- parent ancestry root-owned and not group/other writable except this sticky
  anchor.

An unavailable, replaced or differently permissioned anchor => DENY.

### 3.2 Create-once root and irreversible service lease

The PREEXEC_HOLD creator performs mkdir of the deterministic envelope root with
mode 0700. Existing root => DENY, never adopt/reopen it for positive execution.
This makes restart/duplicate startup conservative: a previous or uncertain
creator permanently consumes this Job envelope.

Inside the new root, before any WorkspaceService positive authority exists, the
creator atomically creates and fsyncs:
- job-lease.json, mode 0600, O_CREAT|O_EXCL|O_NOFOLLOW;
- service-config/, mode 0700;
- exec-state/, mode 0700;
- command-journal/, mode 0700.

job-lease.json contains canonical runtime identity plus:
- one random 256-bit JOB_LOCAL_SECRET;
- one random 256-bit SERVICE_INSTANCE_NONCE;
- exact root dev/inode/uid/mode;
- exact subdirectory dev/inode/uid/mode;
- created timestamp and bounded expiry;
- normalized future service-config SHA256.

The raw secret and service nonce are NEVER logged or placed in owner comments.
Only their SHA256 values are published.

The creator retains pinned directory FDs for the envelope root, exec-state and
command-journal. The positive in-process JobEnvelopeAuthority capability can be
minted ONLY as the direct result of successful create-once lease creation in
that same process. Reading an existing lease file, knowing its fields, or
restarting a process can never reconstruct this capability.

If the creator crashes, closes, loses a pinned FD, sees an identity change or
cannot prove exclusive lease continuity, PRODUCT_T1 for that Job is DENY. The
root/lease is never removed to permit retry.

### 3.3 Exactly one positive service/config root

The future positive PRODUCT_T1 path MUST NOT accept a caller-selected config
root. PREEXEC_HOLD materializes the reviewed schema-v2 service config under the
canonical service-config/ directory and binds its normalized bytes.

Exactly one WorkspaceService may receive the in-process JobEnvelopeAuthority.
That service must use:
- the canonical service-config directory;
- the canonical exec-state directory and owner.lock;
- the canonical command-journal directory.

Any WorkspaceService opened from another otherwise-valid private config root
has NO positive R009 authority and remains ordinary preview/deny only.

The owner execution grant binds:
- JOB_ENVELOPE_KEY;
- envelope pathname SHA256;
- envelope root identity fingerprint;
- exec-state identity fingerprint;
- owner.lock identity fingerprint;
- command-journal identity fingerprint;
- job-lease immutable digest;
- JOB_LOCAL_SECRET_SHA256;
- SERVICE_INSTANCE_NONCE_SHA256;
- normalized service-config SHA256.

The final admission gate rechecks every identity before nonce consumption and
again immediately before Popen where applicable.

### 3.4 Global one-use rows inside one Job

All six command nonce tombstones are O_EXCL+fsync records in the ONE canonical
command-journal. No config-root-local d4-journal may authorize R009 positive
execution.

Each row burn occurs before Workspace/Worker/DirectChildOwner/Popen reservation.
A duplicate nonce or any preexisting/uncertain tombstone => DENY.

Same-Job concurrency therefore serializes through:
1. the create-once Job envelope lease;
2. one in-process positive service authority;
3. one canonical durable command-journal.

The ordinary Workspace concurrency limits remain additional constraints, not
the global replay mechanism.

### 3.5 Required same-Job duplicate-service negative

Safe T0 MUST construct two otherwise legitimate service startups with:
- SAME verified repo/Head/Tree/G05;
- SAME GitHub run/attempt/Job identity;
- SAME owner decision/grant/source/recipe/nonce;
- DIFFERENT requested private config roots.

Both target the same fixed platform anchor.

Exactly one creator may atomically create the deterministic Job envelope and
obtain a fake-positive JobEnvelopeAuthority. The second must be rejected before
any fake product Popen, even though its own requested config root is healthy.

After closing/crashing/restarting the first creator, the second still MUST NOT
adopt the existing envelope or obtain a positive authority. Lost ACK and an
alternate clean config root do not reset the Job.

This test is required in addition to the existing different-Job negative.
If this global envelope cannot be implemented and attested, PRODUCT_T1 remains
DENY.

## 4. Local-to-Job continuity without claiming GitHub cryptographic attestation

R009 does not claim that the public GitHub Jobs API cryptographically attests
the local process.

PREEXEC_HOLD uses three independent classes of evidence:
1. public unauthenticated GitHub API facts for the exact in-progress
   run/attempt/job/workflow/Head;
2. fresh local G05 checkout and host/source/socket/mount observations;
3. possession of the non-public JOB_LOCAL_SECRET created only inside the
   deterministic local Job envelope before the owner execution grant exists.

The owner-visible host snapshot includes JOB_LOCAL_SECRET_SHA256 only.
The later final gate proves continuity by reading the raw secret from the pinned
lease FD and matching the grant hash. A sibling Job that copies environment
strings, API responses and owner comments cannot derive the preimage from the
hash and has a different deterministic Job key/root.

This is runner-local continuity evidence, NOT signed GitHub hardware/OS
attestation and NOT protection from an already-compromised same-UID process.
R006 same-UID residual risk remains.

Safe T0 must include:
- sibling Job with copied env/API/comment but different local secret => DENY;
- same Job but alternate config root => DENY by global lease;
- changed/missing secret, changed lease/root identity, completed/stale Job or
  changed run_attempt => DENY;
- correct unchanged Job-local secret and API/local identities => only a
  fake-Popen-eligible positive, never real T1 authority.

## 5. Exact credential-selector process boundary

R009 narrows the phrase NO_EXPLICIT_CREDENTIAL_INJECTION.

The tracked workflow launches the tiny stdlib-only PREEXEC_HOLD entry through
absolute /usr/bin/env -i with the exact R008 bootstrap allowlist. That one
preproduct process may receive SSH_AUTH_SOCK solely as a path selector.

Before importing gateway product modules or creating WorkspaceService, the hold
entry:
1. records only the path string needed for the metadata-only socket witness;
2. performs the R008 no-connect socket/ancestor metadata checks;
3. removes SSH_AUTH_SOCK;
4. constructs the sanitized product-helper environment;
5. verifies exact-key equality against that sanitized allowlist.

All subsequent product helpers, source qualification, WorkspaceService, Worker,
NativeRunner and final PRODUCT child MUST have SSH_AUTH_SOCK absent.

Operator-visible state must report:
BOOTSTRAP_SSH_AUTH_SOCK_SELECTOR_PRESENT=true
PRODUCT_HELPER_SSH_AUTH_SOCK_PRESENT=false
PRODUCT_CHILD_SSH_AUTH_SOCK_PRESENT=false
NO_PRODUCTION_CREDENTIALS_PROVEN=false
NO_AMBIENT_SSH_AGENT_PROVEN=false

No status may claim "no ambient credential selector" for the bootstrap stage.

Safe T0 must intercept the actual env mapping at every future helper/launcher
boundary and fail if SSH_AUTH_SOCK or any unapproved key reaches a product
helper or child. It must also prove zero socket connect/send/recv/list-identity
operations. RISK_10 remains fully accepted if A1 is later selected.

## 6. Six rows: observed completion is not positive success

One PRODUCT_T1 Job still contains exactly the six R008 command rows, each with
its own unique durable nonce. R009 adds a required row outcome state:

ROW_NOT_RUN
ROW_OBSERVED_NONZERO
ROW_POSITIVE_SUCCESS
ROW_AMBIGUOUS
ROW_VOID

ROW_POSITIVE_SUCCESS requires ALL of:
- exact owner-bound command row consumed before Popen;
- exact reviewed Workspace/cwd/runner/requested/effective argv/recipe;
- final host/source/Job/envelope identity unchanged;
- original direct child existence and ownership unambiguous;
- original direct child exit witnessed;
- real exit_code == 0;
- stdout_eof == true and stderr_eof == true;
- stdout_truncated == false and stderr_truncated == false;
- output remained within the existing 48000 raw-byte / redacted-char bounds;
- process_may_be_running == false for the original direct child only;
- no claim of full descendant cleanup/rollback;
- command-specific filesystem policy below passes.

A witnessed exit_code != 0 is ROW_OBSERVED_NONZERO. It is truthful process
evidence but NEVER positive T1 command qualification.

ROW_OBSERVED_NONZERO or ROW_AMBIGUOUS latches the Job envelope FAILED, makes all
remaining unused rows ROW_VOID and prohibits same-Job retry/regrant.

### 6.1 Command-specific positive filesystem policy

All six use disposable private staged fixtures. First-party source bytes and
reviewed manifests must remain unchanged.

1. py-direct pytest:
   exit 0; source bytes unchanged; writes, if any, confined to the private
   workspace and only reviewed pytest/python cache paths.
2. py-direct compileall ./src:
   exit 0; source bytes unchanged; generated files only
   src/**/__pycache__/*.pyc inside the private workspace.
3. py-pipenv pytest:
   exit 0; source and pinned private venv bytes unchanged; writes, if any,
   confined to reviewed workspace pytest/python cache paths and approved
   private cache root.
4. go test ./...:
   exit 0; source bytes unchanged; writes only to the reviewed private Go cache
   and approved private temp root.
5. go vet ./...:
   exit 0; same source/cache constraints as go test.
6. go build -o bin/app ./cmd/app:
   exit 0; source bytes unchanged; writes only to reviewed private Go cache/temp
   plus exactly bin/app. bin/app must be a new owner-owned regular single-link
   non-symlink file under the private workspace, executable, bounded size and
   recorded SHA256.

Unexpected path creation/mutation, source mutation or output-artifact mismatch
makes the row failed/incomplete and the Job cannot become six-command PASS.

Safe fake-child T0 MUST include exit_code=1 for at least go vet and one Python
row and prove the result is ROW_OBSERVED_NONZERO, remaining rows are VOID and no
integration eligibility is emitted.

## 7. Six-command Job PASS and integration eligibility

SIX_COMMAND_PRODUCT_T1_PASS exists only when all six rows are
ROW_POSITIVE_SUCCESS in the exact owner-bound order and the Job envelope never
latched FAILED/AMBIGUOUS.

One to five successes plus NOT_RUN/VOID rows are incomplete.
Six observed exits with one nonzero are FAIL, not PASS.
Output truncation/EOF uncertainty or filesystem-policy failure is incomplete or
fail according to the directly observed result, never PASS.

Only SIX_COMMAND_PRODUCT_T1_PASS may make the code eligible for a later,
SEPARATE owner integration decision. It does not itself authorize integration.

R008 separate integration grant, later independent B/C FULL reviews and R10
remain unchanged.

## 8. Future owner execution grant additions

In addition to all R008 fields, a future R009 executable grant MUST bind:
r009_design_blob
job_envelope_key
job_envelope_path_sha256
job_envelope_root_identity_fingerprint
exec_state_identity_fingerprint
owner_lock_identity_fingerprint
command_journal_identity_fingerprint
job_lease_digest
job_local_secret_sha256
service_instance_nonce_sha256
service_config_sha256
credential_stage_contract=R009_BOOTSTRAP_SELECTOR_ONLY_V1
six_row_success_contract=R009_EXIT0_EOF_NOTRUNC_FS_POLICY_V1

Old R008/R007/R006-only execution grants cannot authorize R009 code.

The parser/bootstrap/shared service gate/final runner must reject any mismatch
before Popen.

## 9. Required safe T0 before any real PRODUCT_T1

A later selected implementation must prove, with zero real product Popen:
- same Job + two different config roots race: only one envelope creator; second
  zero fake-Popen;
- first creator restart/lost ACK + alternate clean root: no reacquire;
- sibling Job copied env/API/comment: local-secret mismatch DENY;
- missing/changed lease/root/subdir/owner.lock/journal/config identities DENY;
- duplicate command nonce across process/service instances DENY;
- exact valid unchanged fake-positive path uses canonical global journal;
- helper/child env interception proves SSH_AUTH_SOCK absent after bootstrap;
- no SSH agent connect/send/recv/list operation;
- nonzero Python/Go fake child => ROW_OBSERVED_NONZERO and envelope failure;
- truncated/no-EOF fake output => not positive success;
- unexpected filesystem mutation/build artifact mismatch => not positive success;
- six exact fake successes => only T0 six-row state, not PRODUCT_T1 evidence;
- old R006/R007/R008 grant/design/review/option identity => DENY;
- current strict public F1/ordinary v2, old UNKNOWN/owner.lock, PR102 isolation and
  lawful File/Git behavior remain unchanged.

## 10. Current authority and claims

At R009 proposal creation:
- R008 Standards: TARGETED DESIGN PASS only, P2=0, P3=2.
- R008 Spec: TARGETED DESIGN FAIL, P2=1, P3=1.
- current product code remains strict R006;
- A1/B1 implementation remains NOT_IMPLEMENTED;
- PRODUCT_T1 remains NOT_RUN / NOT_AUTHORIZED;
- integration remains NOT_TESTED.

Even if R009 later passes design review, these remain false until separately
proved:
FULL_BOOT_IMAGE_ATTESTED
ACTUAL_LOADED_GRAPH_PROVEN
PHYSICAL_WHOLE_TREE_CPU_MEMORY_ENFORCEMENT_PROVEN
NO_PRODUCTION_CREDENTIALS_PROVEN
NO_AMBIENT_SSH_AGENT_PROVEN
NO_SHARED_WRITABLE_MOUNTS_PROVEN
OFFLINE_ONLY

R006 risks 1-9 remain. RISK_10/RISK_11 apply only if owner later selects A1.

Until independent B/C PASS of this exact design and a later explicit owner
option/risk decision:
R009_DESIGN_STATUS=PROPOSED_NOT_EFFECTIVE
HOST_OPTION=UNDECIDED
REVIEW_SEQUENCE_OPTION=UNDECIDED
PRODUCT_T1=DENY
NEXT_ROLE=B/C_TARGETED_DESIGN_REVIEW_AFTER_A_FREEZE
