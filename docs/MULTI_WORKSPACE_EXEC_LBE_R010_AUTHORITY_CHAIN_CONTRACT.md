# Multi-Workspace Exec LBE R010 - Unified Authority Chain Contract

TASK_ID: MULTI-EXEC-LBE-FIVE-DAY-CANDIDATE-20261105
MILESTONE_ID: LBE-FIVE-DAY-CORE-PRODUCT-CANDIDATE
DESIGN_ID: MWE-LBE-R010-AUTHORITY-CHAIN-DESIGN-009-CANDIDATE
STATUS: PROPOSED_NOT_EFFECTIVE
PARENT_R009_DESIGN_BLOB: c6ed1388a868e01b51d10722195ea4b9e8ff9af9
PARENT_R008_DESIGN_BLOB: a9d78a1e07b345a3ec69cb93ac9d5cca8246c3fe
PARENT_R006_DESIGN_BLOB: b8d8a1cb32fb7130dfa6d00b37831dfddfaad11c
RULESET_ID: ICR-V2.0
HANDOFF_PROTOCOL_ID: GHRH-2.0
EVIDENCE_PROFILE_ID: ETP-V2.0
PRODUCT_T1: DENY
INTEGRATION_STATUS: NOT_TESTED
HOST_OPTION: UNDECIDED
REVIEW_SEQUENCE_OPTION: UNDECIDED

R010 is the single normative authority root for any future R010 positive path.
It preserves the substantive safety properties explicitly listed below, but no
version-bound Review, Owner Choice or execution Grant from R006/R007/R008/R009
is automatically upgraded into R010 authority.

This file is design-only. It does NOT authorize A1/B1 implementation, OIDC
requests, SSH-agent access, autofs activation, native Python/Pipenv/Go execution,
T2/T3, user/shared/production Mac/Tunnel, merge, tag, release or deploy.

## 1. Review findings closed by this design

R010 is intended to close the current R009 review findings in one versioned
contract rather than another partial overlay:

- C114-R009-DESIGN-008-SPEC-01: old R008 design-choice and grant predicates
  conflict with the newer R009 design version.
- C114-R009-DESIGN-008-SPEC-02: exit 0 with truncated output or invalid
  filesystem/artifact result lacks a named fail state and mandatory latch.
- B114-R009-ST-D008-P2-01: local secret continuity does not prove the first
  PREEXEC_HOLD is the provider-identified GitHub Job targeted by the owner.
- B114-R009-ST-D008-P2-02: a newly initialized state root could hide inherited
  UNKNOWN/owner.lock history unless state provenance is explicit.
- B114-R009-ST-D008-P2-03: whole-host "writes only" cannot be proven under the
  accepted no-sandbox same-UID trusted-host model.
- B114-R009-ST-D008-P3-01: the six rows need an explicit global serial
  transition so a later Workspace cannot start before the earlier row succeeds.

R009_JOB_GLOBAL_LEASE_RETAINED: the create-once deterministic per-Job envelope,
canonical service root and one durable command journal remain the foundation.
R010 strengthens attribution, state provenance and row semantics around it.

## 2. Normative retain / replace / supersede matrix

The following table is authoritative for R010. A parent clause has no R010
version authority unless this table says RETAINED_SAFETY_ONLY.

| Parent item | R010 status | R010 rule |
| --- | --- | --- |
| R006 residual risks 1-9 | RETAINED_SAFETY_ONLY | Must be explicitly re-affirmed in the new R010 Owner Design Choice. No old comment auto-upgrades. |
| R006 default F1 / unqualified positive DENY | RETAINED | Ordinary v1/F1 and unqualified v2 positive Exec continue to deny. |
| R008 A0/A1 host behavior | RETAINED_SAFETY_ONLY | Substantive host predicates and RISK_10/RISK_11 are re-stated in section 5, but exact-R008 design PASS and Review IDs are SUPERSEDED_DENY. |
| R008 B0/B1 sequencing | RETAINED_SAFETY_ONLY | Two-stage TARGETED then FULL semantics are re-stated in section 6; exact-R008 PASS predicates are SUPERSEDED_DENY. |
| R008 section 5 R008_OWNER_DESIGN_CHOICE_V1 | SUPERSEDED_DENY | Replaced only by R010_OWNER_DESIGN_CHOICE_V1. |
| R008 section 9 R008_OWNER_PRODUCT_T1_GRANT_V1 | SUPERSEDED_DENY | Replaced only by R010_OWNER_PRODUCT_T1_GRANT_V1. |
| R009 section 3 Job-global lease | RETAINED_AND_TIGHTENED | R010 keeps deterministic create-once envelope and canonical journal, adds provider Job attestation and explicit state-domain provenance. |
| R009 section 4 local secret continuity | REPLACED | Replaced by provider-signed OIDC check_run_id plus local-secret challenge continuity in section 7. |
| R009 section 5 SSH selector boundary | RETAINED_AND_TIGHTENED | PREEXEC_HOLD only; stripped before gateway/product helpers; exact status semantics remain. |
| R009 sections 6-7 row success | REPLACED | Replaced by the explicit serial state machine and finite observed acceptance matrix in sections 9-11. |
| R009 section 8 grant additions | SUPERSEDED_DENY | R010 defines one complete execution grant schema; additive legacy schemas are invalid. |
| PR98 persistent owner.lock/UNKNOWN behavior | RETAINED for ordinary gateway | R010 PRODUCT_T1 uses a separately reviewed ephemeral Job state domain only under section 8; no persistent state is silently cleared or migrated. |
| PR102 SOURCE_TOOLCHAIN_T1 | RETAINED_SEPARATE | No inheritance or widening; its Gate B remains separate. |

Any old marker, old Blob or old Review identity can be evidence history only.
It is never executable R010 authority.

## 3. R010 authorization chain - exact order

No layer can be skipped or backfilled from an older version.

1. FIXED R010 DESIGN
   - exact R010 design Blob;
   - exact Base/Head/Tree/Manifest;
   - current V2 rule identifiers and security gates.
2. INDEPENDENT R010 DESIGN REVIEWS
   - B and C each review the same R010 design Blob;
   - both must be TARGETED design PASS with no in-scope P0/P1/P2.
3. R010 OWNER DESIGN CHOICE
   - exact R010 Blob;
   - exact B/C R010 design Review node IDs;
   - A0/A1, B0/B1 and exact risk re-affirmation;
   - state_domain=R010_EPHEMERAL_JOB_STATE_V1.
4. R010 IMPLEMENTATION SNAPSHOT
   - A implements only the selected options on a new fixed Head;
   - safe T0 first; PRODUCT_T1 remains NOT_RUN.
5. INDEPENDENT R010 T1 EXECUTION QUALIFICATION
   - B/C independently review the exact implementation Head;
   - complete pre-T1 critical path, not a label-only review;
   - TARGETED_REVIEW_PASS only; FULL remains NOT_ISSUED.
6. R010 PROVIDER-ATTESTED PREEXEC_HOLD
   - one separately user-authorized GitHub-hosted macOS Job starts;
   - safe qualification only; zero PRODUCT Popen before execution grant;
   - creates global Job envelope, state provenance and provider OIDC witness.
7. R010 OWNER PRODUCT_T1 GRANT
   - binds exact current R010 design, owner choice, implementation Reviews,
     provider Job witness, global envelope and six row nonces.
8. SIX SERIAL PRODUCT_T1 ROWS
   - each row independently one-use and globally serialized;
   - any failure/ambiguity latches the Job and voids remaining rows.
9. OPTIONAL SEPARATE INTEGRATION GRANT
   - only after SIX_COMMAND_PRODUCT_T1_PASS;
   - distinct owner decision and nonce set.
10. NEW INDEPENDENT FULL REVIEWS
   - use original native/integration evidence;
   - no TARGETED result auto-promotes to FULL.
11. A evaluates R10 only after both current ROLE_FULL_SCOPE_PASS reviews.

## 4. R010 Owner Design Choice - one exact version

The only valid design-choice marker is:

R010_OWNER_DESIGN_CHOICE_V1

Required canonical fields:
- repo, pr;
- r010_design_blob;
- b_r010_design_review_id;
- c_r010_design_review_id;
- host_option exactly A0 or A1;
- review_sequence_option exactly B0 or B1;
- state_domain exactly R010_EPHEMERAL_JOB_STATE_V1;
- risk_marker:
  - A0 => R010_REAFFIRM_R006_RISK1_9_NO_NEW_HOST_WEAKENING
  - A1 => R010_REAFFIRM_R006_RISK1_9_PLUS_RISK10_11
- created_at == updated_at;
- direct OWNER human identity.

The new comment is a fresh R010 re-affirmation. Prior R006 risk acceptance may
be cited as history but does not substitute for this R010 risk_marker.

R006/R007/R008/R009 design-choice/grant markers are SUPERSEDED_DENY for R010.
An edited comment, wrong Blob, old Review IDs, mismatched A/B option or missing
risk marker => DENY.

## 5. Host options under R010

### A0 - strict host deny

A0 preserves current R006: ambient SSH_AUTH_SOCK and any writable non-local
mount keep PRODUCT_T1 in DENY on the currently observed standard macOS host.

### A1 - explicit reduced host guarantees

A1 may be implemented only after exact R010 design PASS plus the R010 Owner
Design Choice above.

The host rules are the R008/R009 safety rules, with these R010 truth claims:
- NO_PRODUCTION_CREDENTIALS_PROVEN=false;
- NO_AMBIENT_SSH_AGENT_PROVEN=false;
- NO_SHARED_WRITABLE_MOUNTS_PROVEN=false;
- FULL_BOOT_IMAGE_ATTESTED=false;
- ACTUAL_LOADED_GRAPH_PROVEN=false;
- OFFLINE_ONLY=false.

RISK_10 and RISK_11 remain additive to R006 risks 1-9.

The bootstrap selector contract remains exact:
- only tiny stdlib PREEXEC_HOLD may initially see SSH_AUTH_SOCK;
- it may perform metadata-only no-connect socket checks;
- it strips SSH_AUTH_SOCK before importing gateway/product modules;
- all product helpers, WorkspaceService, Worker, NativeRunner and PRODUCT child
  must see SSH_AUTH_SOCK absent;
- no agent connect/send/recv/list identity operation is permitted.

The autofs exception, if A1 is chosen, remains exactly the previously observed
single row and full-table recheck:
- type=autofs;
- target=/System/Volumes/Data/home;
- source_sha256=6713f2a70c72b6c412839ad247f7605db53105c3e624c0a9cd778eb7fdeef5ad;
- flags=72351744;
- qualification mount_count=11;
- no second/nested writable non-local row;
- same full sorted mount-table fingerprint immediately before each Popen.

## 6. Review sequencing under R010

### B0 - FULL-before-T1

B0 keeps native PRODUCT_T1 denied until the current full gate is satisfiable.

### B1 - TARGETED execution qualification, then evidence, then new FULL

If B1 is selected, B and C independently review the exact runnable R010 Head.
Each pre-T1 Review must state:
- REVIEW_SCOPE: TARGETED
- REVIEW_LEVEL: TARGETED_REVIEW_PASS
- VERDICT: PASS
- EVIDENCE_STATUS: SUFFICIENT
- EVIDENCE_SCOPE_QUALIFIER: SUFFICIENT_FOR_T1_EXECUTION_QUALIFICATION_ONLY
- INTEGRATION_STATUS: NOT_TESTED
- T1_EXECUTION_QUALIFICATION: PASS
- ROLE_FULL_SCOPE_PASS: NOT_ISSUED
- FULL_CODE_REVIEW_PASS: NOT_ISSUED
- PRODUCT_T1: NOT_RUN

The REVIEW_TARGET must cover the complete reachable pre-Popen critical path,
including version parser, provider witness, state provenance, global lease,
WorkspaceService shared gate, source/host checks, runner, worker, output/state
machine and adjacent File/Git behavior.

## 7. Provider-attested pre-grant Job binding

R010 replaces R009 self-attribution with:

R010_GITHUB_OIDC_CHECK_RUN_V1

The future tracked R010 workflow gives id-token: write ONLY to the dedicated
PREEXEC_HOLD Job. No other Job in that workflow receives that permission.

Before Owner PRODUCT_T1 grant:
1. PREEXEC_HOLD creates JOB_LOCAL_SECRET (256 random bits) in the create-once
   Job lease, never logs it, and computes JOB_LOCAL_SECRET_SHA256.
2. It requests a GitHub OIDC token with custom audience:
   mfg-r010:<R010_DESIGN_BLOB>:<HEAD_SHA>:<JOB_LOCAL_SECRET_SHA256>
3. A future verifier must validate the provider signature and require exact:
   iss=https://token.actions.githubusercontent.com
   repository=chinanjjohn2012/mac-file-gateway
   run_id, run_attempt
   check_run_id (provider claim for the current Job)
   workflow_ref, workflow_sha
   head/source identity as defined by the reviewed implementation
   runner_environment=github-hosted
   custom audience above.
4. The exact provider-signed check_run_id, OIDC token SHA256/claims digest and
   local secret hash enter the sanitized PREEXEC snapshot that the owner later
   binds.
5. The raw OIDC JWT, ACTIONS_ID_TOKEN_REQUEST_TOKEN and request URL are
   credential material for PREEXEC only, mode-0600/pinned if stored, never
   logged, and scrubbed before gateway/product imports.
6. Final admission re-verifies current Job/check-run status, exact grant and
   possession of the same raw JOB_LOCAL_SECRET through the pinned lease.

This is provider-signed Job attribution plus runner-local continuity. It is not
hardware attestation and does not remove R006 same-UID risk.

A sibling Job with copied env/public API/Owner comment but a different signed
check_run_id or different local-secret challenge MUST fail before Popen.
A self-signed/mock JWT is valid only in SAFE T0 and never runtime authority.

## 8. Ephemeral R010 state provenance and old UNKNOWN semantics

R010 PRODUCT_T1 defines a separate reviewed state domain:

R010_EPHEMERAL_JOB_STATE_V1

This is an explicit R010 exception for one disposable provider-attested
GitHub-hosted Job; it does not change persistent gateway semantics.

Positive admission requires ALL:
- provider-signed current check_run_id and github-hosted runner witness;
- tracked workflow proves no cache/artifact restore into the R010 state anchor;
- PREEXEC_HOLD is before any earlier positive gateway/service step;
- deterministic canonical Job-envelope root is absent before create;
- no conflicting prior R010 envelope or state record exists for this Job;
- no discovered legacy/conflicting state root named by the exact workflow,
  service config or fixed legacy defaults contains UNKNOWN/corrupt state;
- owner.lock is provisioned OFFLINE by trusted PREEXEC setup before service
  admission;
- WorkspaceService then opens the canonical state with existing_only semantics;
- any missing/replaced owner.lock, corrupt state or conflicting historic root
  => DENY.

A new empty state root must never be used to "clear" a persistent gateway
UNKNOWN. Ordinary persistent gateway/PR98 old-state behavior remains unchanged.
If the future implementation cannot prove a fresh ephemeral R010 state domain,
PRODUCT_T1 remains DENY.

## 9. R009 Job-global lease retained and global serial row state machine

The R009 create-once deterministic Job envelope remains mandatory:
- fixed platform anchor;
- one create-once 0700 envelope root;
- one job-lease;
- one canonical service-config, exec-state/owner.lock and command-journal;
- one in-process positive JobEnvelopeAuthority only for the creating process;
- alternate config roots never gain positive authority;
- existing root after crash/restart/lost ACK is permanent DENY, never adopted;
- each row nonce burns O_EXCL+fsync in the one canonical command-journal before
  any Worker/Popen reservation.

R010 adds one atomic global sequence index to the same durable envelope.

Job states:
JOB_PREEXEC_HOLD
JOB_READY_FOR_ROW_1 ... JOB_READY_FOR_ROW_6
JOB_ROW_RUNNING_1 ... JOB_ROW_RUNNING_6
JOB_FAILED_LATCHED
JOB_SIX_COMMAND_COMPLETE

Row states:
ROW_NOT_RUN
ROW_RUNNING
ROW_OBSERVED_NONZERO
ROW_OBSERVED_ZERO_INVALID_OUTPUT_OR_FS
ROW_AMBIGUOUS
ROW_POSITIVE_SUCCESS
ROW_VOID

Only expected row i may consume its nonce and enter RUNNING_i.
Row i+1 cannot burn a nonce or start until row i is fully classified
ROW_POSITIVE_SUCCESS and the durable expected-row index advances atomically.

Any OBSERVED_NONZERO, OBSERVED_ZERO_INVALID_OUTPUT_OR_FS or AMBIGUOUS transition:
- latches JOB_FAILED_LATCHED;
- writes the observed result truthfully;
- marks every remaining NOT_RUN row ROW_VOID durably;
- makes every later command zero-Popen;
- forbids same-Job retry/regrant.

This serialization is global across all Workspaces, not the existing per-
Workspace concurrency limit.

## 10. Row acceptance matrix - finite observable claims only

R010 removes R009 whole-host "writes only" wording.

UNOBSERVED_HOST_SIDE_EFFECTS_NOT_PROVEN_ABSENT=true
TRANSIENT_SOURCE_MUTATION_NOT_PROVEN_ABSENT=true

These are accepted limitations under the trusted disposable-host model and
R006 residual risk 9. R010 never claims a complete write-event monitor or
whole-host filesystem confinement.

ROW_POSITIVE_SUCCESS requires:
- exact command row/nonce/argv/cwd/runner/recipe;
- exact provider Job, global lease, host/source identities at final recheck;
- a trusted DirectChildOwner reservation-bound original-child reap observation:
  the private reaper's wait() returned a real integer exit code, and its
  DirectObservation is status="exited" for that SAME original and attempt;
- the trusted Worker reports status="exited", executed=true, timed_out=false
  consistent with the owner observation (not merely a client-supplied status);
- witnessed real exit_code == 0;
- stdout_eof=true and stderr_eof=true;
- stdout_truncated=false and stderr_truncated=false;
- each stream remains within existing 48000 raw-byte and redacted-char bounds;
- finite pre/post observed integrity predicates below pass.

Original-child completion and descendant-tree cleanup are distinct facts.
The owner-only observation above is the future internal
`original_child_reaped=true` witness; it MUST originate from the trusted
DirectChildOwner wait()/reap path bound to the same reservation/attempt, NEVER
from a client, REST/MCP field, normal config or independently editable Worker
response. A public Worker result of `status="exited"` and `exit_code=0` is
consistent with that witness, but is not a stand-alone client-grantable proof.

Current Worker truthfully returns `process_may_be_running=true` even after
confirmed original exit. This is aggregate potential descendant survival,
NOT a claim that the original direct child is still alive. It MUST NOT
independently select ROW_AMBIGUOUS when the trusted original reap exists.
The existing `cleanup_proven=false` and
`full_descendant_tree_clean="not_proven"` remain unchanged; neither original
exit nor ROW_POSITIVE_SUCCESS proves descendant cleanup or zero delayed host
side effects. The finite observed filesystem contract and accepted residual
risk remain in force. No further row may begin unless the previous row
satisfies every other positive acceptance predicate.

ROW_CLASSIFICATION_TRUST_BOUNDARY:
- trusted original reap + nonzero integer exit => ROW_OBSERVED_NONZERO;
- trusted original reap + zero exit + both EOF/no truncation, bounded output,
  healthy reader and finite filesystem/artifact acceptance => ROW_POSITIVE_SUCCESS;
- trusted original reap + zero exit + missing EOF, truncated/excess output,
  failed reader or observed filesystem/artifact predicate =>
  ROW_OBSERVED_ZERO_INVALID_OUTPUT_OR_FS;
- no trusted original reap, lost wait/owner/ACK, cancelled or timed-out waiter,
  or unqualified original identity/exit => ROW_AMBIGUOUS irrespective of a
  guessed exit code, response metadata or aggregate process risk.
All failed rows latch JOB_FAILED_LATCHED, VOID remaining rows and forbid
subsequent Popen/retry. Cancellation/timeout is never retrospectively upgraded
by a detached later wait or replayed public response.

If exit_code != 0 => ROW_OBSERVED_NONZERO.
If exit_code == 0 but EOF/truncation/output bound/observed-integrity/artifact
predicate fails => ROW_OBSERVED_ZERO_INVALID_OUTPUT_OR_FS.
If original ownership/exit is uncertain => ROW_AMBIGUOUS.
All three failure classes latch/void as section 9 requires.

Finite observed integrity means only:
- exact pre/post digest+metadata snapshots of the reviewed selected source set;
- exact pre/post snapshot of the reviewed private output/cache roots;
- expected allowed deltas for that row;
- exact artifact checks where applicable.

A transient outside-root write+delete or source mutate+restore that escapes the
finite snapshots is NOT proven absent and must never be used as an absolute
safety claim. Safe T0 must explicitly demonstrate this limitation.

### Six-command acceptance matrix

| Row | Positive observed predicate | Zero-exit invalid examples |
| --- | --- | --- |
| 1 py-direct pytest | exit 0, EOF/no truncation, selected source pre/post snapshot equal, reviewed private pytest/python cache deltas only | truncated output; unexpected observed private-root mutation |
| 2 py-direct compileall ./src | same stream rules; selected source text pre/post digest equal; only reviewed __pycache__/*.pyc deltas inside selected private src tree | missing/unexpected pyc form; unexpected observed mutation |
| 3 py-pipenv pytest | exit 0; selected source and pinned venv pre/post digest equal; reviewed private pytest/cache deltas only | venv/source observed change; truncated/no EOF |
| 4 go test ./... | exit 0; selected source pre/post digest equal; reviewed private Go cache/temp observed deltas | unexpected observed selected/private delta |
| 5 go vet ./... | same as Go test | exit 0 but observed integrity/output invalid |
| 6 go build -o bin/app ./cmd/app | exit 0; selected source pre/post digest equal; reviewed cache/temp deltas; exactly new bin/app artifact | bin/app missing/symlink/nlink!=1/wrong owner/not executable/size invalid |

Go bin/app exact positive form:
- regular non-symlink file;
- st_nlink == 1;
- owner uid == current runner uid;
- owner executable bit set;
- group/other write bits absent;
- 1 <= st_size <= 67108864 bytes;
- SHA256 recorded in original evidence.

SIX_COMMAND_PRODUCT_T1_PASS requires all six rows in order as
ROW_POSITIVE_SUCCESS and no FAILED/AMBIGUOUS latch.

## 11. Complete R010 execution Grant schema

The only valid execution marker is:

R010_OWNER_PRODUCT_T1_GRANT_V1

It is a fresh direct OWNER comment and must bind at minimum:
- repo, pr;
- r010_design_blob;
- R010_OWNER_DESIGN_CHOICE_V1 comment id + canonical digest;
- host_option, review_sequence_option, exact R010 risk_marker;
- b_r010_design_review_id, c_r010_design_review_id;
- implementation base_sha, head_sha, head_tree, manifest_sha256;
- b_r010_t1_qualification_review_id, c_r010_t1_qualification_review_id;
- review_target_id=R010_COMPLETE_PRE_T1_CRITICAL_PATH_V1;
- contract_scope_id=R010_IMPLEMENTATION_CONTRACT_V1;
- provider_contract=R010_GITHUB_OIDC_CHECK_RUN_V1;
- OIDC issuer/audience/claims digest/token SHA256;
- github run_id, run_attempt, provider-signed check_run_id;
- workflow_ref, workflow_sha;
- runner/image/source/host snapshot identities;
- state_domain=R010_EPHEMERAL_JOB_STATE_V1 and state-provenance digest;
- job_envelope_key/root identities/lease digest;
- job_local_secret_sha256 and service-instance nonce hash;
- canonical owner.lock/exec-state/command-journal/config identities;
- row_contract=R010_SERIAL_EXIT0_FINITE_OBSERVED_DELTA_V1;
- six exact command rows + six unique nonces;
- bounded expiry.

Old R006/R007/R008/R009 choice/grant marker or old design Blob/Review ID is
SUPERSEDED_DENY. Wrong option/risk/state/provider/version/Head/Job/workflow/
source/nonce => zero Popen.

## 12. Pre-review SAFE T0 / Mock / static selfcheck matrix

Before R010 design is handed to B/C, A must produce source-only T0 evidence for:

1. VERSION CONFLICT
   - R008/R009 Owner Choice or Grant presented to R010 => DENY;
   - synthetic exact R010 choice/grant only passes the non-runtime model.
2. PROVIDER JOB ATTRIBUTION
   - mocked verified GitHub OIDC current check_run_id + exact custom audience =>
     model pass;
   - wrong check_run_id, unsigned/self-signed token or sibling-job witness => DENY.
3. JOB-GLOBAL UNIQUENESS
   - SAME Job, two services, two requested private roots => only canonical root
     can claim one envelope; second zero fake-Popen;
   - restart/lost ACK/existing envelope => no reacquire.
4. STATE PROVENANCE
   - restored state, prior positive service, preexisting root, historic UNKNOWN,
     missing owner.lock or failed existing_only open => DENY.
5. SERIAL SIX ROWS
   - row 5 cannot start while row 1 is running;
   - only completed positive row i advances expected index.
6. FAILURE CLASSIFICATION
   - a real SAFE T0 FakeChild through existing DirectChildOwner/LbeWorker
     must show status="exited", process_may_be_running=true,
     cleanup_proven=false and full_descendant_tree_clean="not_proven";
     trusted fake wait/reap + exit 0 + complete streams/valid finite FS
     => ROW_POSITIVE_SUCCESS (without changing the public Worker fields);
   - exit 1 with trusted original reap => ROW_OBSERVED_NONZERO + FAILED + remaining VOID;
   - exit 0 + stdout truncation/no EOF => ROW_OBSERVED_ZERO_INVALID_OUTPUT_OR_FS;
   - exit 0 + invalid Go artifact/observed filesystem predicate => same invalid
     state and no later row;
   - ambiguous/unreaped original, timeout or cancelled waiter =>
     ROW_AMBIGUOUS + no later row, even if process_may_be_running=true.
   - a caller-supplied `original_child_reaped` flag without private owner
     wait/reap provenance is NOT trusted evidence and cannot authorize Popen.
7. FINITE-OBSERVATION HONESTY
   - outside-root write+delete and source mutate+restore are explicitly modeled
     as NOT_PROVEN_ABSENT, not falsely claimed prevented.
8. OLD SECURITY BOUNDARIES
   - F1/unqualified positive, UNKNOWN, missing owner.lock, wrong source identity,
     unapproved runner => DENY;
   - separately lawful Git/File remain available despite Exec denial.

These T0 models do NOT implement runtime authority and do NOT prove PRODUCT_T1.
Real OIDC request/signature verification and native child evidence remain
NOT_RUN until later reviewed implementation and explicit authorization.

## 13. Owner choice and future implementation gates

Even if B/C independently PASS this exact R010 design, A must not implement A1
or B1 until the owner publishes the exact R010_OWNER_DESIGN_CHOICE_V1.

If the owner selects A0 or B0, the corresponding deny path remains operative.
If the owner selects A1/B1, A may then implement only the reviewed R010 contract
on a NEW Head, run safe T0 and freeze an exact implementation snapshot for new
independent TARGETED T1 qualification.

No design PASS is a native execution grant.

Until then:
R010_DESIGN_STATUS=PROPOSED_NOT_EFFECTIVE
HOST_OPTION=UNDECIDED
REVIEW_SEQUENCE_OPTION=UNDECIDED
PRODUCT_T1=DENY
INTEGRATION_STATUS=NOT_TESTED
FULL_CODE_REVIEW_PASS=NOT_ISSUED
R10_STATUS=BLOCKED
