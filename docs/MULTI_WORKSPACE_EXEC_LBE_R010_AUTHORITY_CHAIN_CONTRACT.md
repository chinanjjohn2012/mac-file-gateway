# Multi-Workspace Exec LBE R010 - Unified Authority Chain Contract

TASK_ID: MULTI-EXEC-LBE-FIVE-DAY-CANDIDATE-20261105
MILESTONE_ID: LBE-FIVE-DAY-CORE-PRODUCT-CANDIDATE
DESIGN_ID: MWE-LBE-R010-AUTHORITY-CHAIN-DESIGN-013-CANDIDATE
REVIEW_ROUND: D4-R014-AUTHORITY-CHAIN-DESIGN-013
CURRENT_DESIGN_ID: MWE-LBE-R010-AUTHORITY-CHAIN-DESIGN-013-CANDIDATE
CURRENT_DESIGN_BLOB: RESOLVE_FROM_THIS_FROZEN_FILE_GIT_OBJECT_AFTER_COMMIT
PREVIOUS_R013_FROZEN_HEAD_SHA: 7fe777768b35c2182f028e786dba5b568296176d
PREVIOUS_R013_FROZEN_TREE_SHA: 61f137415f2be84a660d764dc006b914c556e406
PREVIOUS_R013_DESIGN_BLOB: fa3f756f5876e67ff9434747c855a68fd01e7654
PREVIOUS_R013_B_REVIEW: PRR_kwDOU5v3IM8AAAABWs2i6Q (TARGETED PASS, historical)
PREVIOUS_R013_C_REVIEW: PRR_kwDOU5v3IM8AAAABWs3Ieg (FAIL P2 C114-R013-DESIGN-012-SPEC-01, historical)
PREVIOUS_R012_FROZEN_HEAD_SHA: a2c28bee8c92b59ecd280597205038bb152586fd
PREVIOUS_R012_FROZEN_TREE_SHA: 3a3ad1b2d5e93594927322644dcadd466bbd65f6
PREVIOUS_R012_DESIGN_BLOB: 1dddfdaa5f610c6c02ba9b81d4d11296d2b36eb3
PREVIOUS_R012_B_REVIEW: PRR_kwDOU5v3IM8AAAABWsvTtA (BLOCKED, two P2)
PREVIOUS_R012_C_REVIEW: PRR_kwDOU5v3IM8AAAABWsvbsQ (TARGETED_PASS only, no migration)
PREVIOUS_R011_FIXED_HEAD_SHA: 7cd6be407737be8e0b4f943bf6ac2ffb022f3f08
PREVIOUS_R011_DESIGN_BLOB: 6b0d9e6f1248f075d927b04c0585f44357e4652c
PREVIOUS_R011_B_REVIEW: PRR_kwDOU5v3IM8AAAABWsnx5A (BLOCKED, two P2 + one P3)
PREVIOUS_R011_C_REVIEW: PRR_kwDOU5v3IM8AAAABWsoUvQ (TARGETED PASS, one P3)
PREVIOUS_R010_REVIEWED_DESIGN_BLOB: f0cdeac6887c570e759f549587dcb9980e410253
PREVIOUS_INTERIM_R010_DESIGN_BLOB: 410dc9d80b2f1d407c0752a9a6d70966fac527ab
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
is automatically upgraded into R010 authority. The sole new current design
candidate is DESIGN-013 (CURRENT_DESIGN_ID above), whose actual Git Blob is
resolved ONLY after this entire document is frozen. Historical DESIGN-009,
DESIGN-010, DESIGN-011 and DESIGN-012 Blobs, corresponding B/C Review IDs,
Choices, Qualifications, OIDC audiences and Grants have NO current authority.
A new B/C pair must independently review this exact new frozen Blob/Head/Tree;
old successes or failures remain historical, not authorization.

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
| R009 section 5 SSH selector boundary | REPLACED_FOR_OIDC_PREEXEC_ENV_ONLY | Section 14 explicitly replaces exact R008/R009 PREEXEC bootstrap allowlist with an exact two-selector OIDC exception; strict no-agent-protocol and all downstream no-selector/closed-child requirements remain. |
| R009 sections 6-7 row success | REPLACED | Replaced by the explicit serial state machine and finite observed acceptance matrix in sections 9-11. |
| R009 section 8 grant additions | SUPERSEDED_DENY | R010 defines one complete execution grant schema; additive legacy schemas are invalid. |
| PR98 persistent owner.lock/UNKNOWN behavior | RETAINED for ordinary gateway | R010 PRODUCT_T1 uses a separately reviewed ephemeral Job state domain only under section 8; no persistent state is silently cleared or migrated. |
| PR102 SOURCE_TOOLCHAIN_T1 | RETAINED_SEPARATE | No inheritance or widening; its Gate B remains separate. |

Any old marker, old Blob or old Review identity can be evidence history only.
It is never executable R010 authority.

## 3. R010 authorization chain - exact order

CURRENT_VERSION_AUTHORITY_RULE (normative for R014): CURRENT_DESIGN_ID is
MWE-LBE-R010-AUTHORITY-CHAIN-DESIGN-013-CANDIDATE. CURRENT_DESIGN_BLOB
means the complete frozen Git blob SHA of THIS document, independently
obtained from the fixed reviewed Git Head/Tree AFTER source editing, NOT a
self-referential hash written in this file. It must be identical at every
authorization layer. CURRENT_DESIGN_REVIEW_B_ID and
CURRENT_DESIGN_REVIEW_C_ID mean DISTINCT, freshly issued B/C native
GitHub Review nodes independently bound to the exact CURRENT_DESIGN_ID,
CURRENT_DESIGN_BLOB, current design Base/Head/Tree and R014 review target.
They are NOT the historical R012 or R013 review IDs. All are currently
NOT_ISSUED; this design alone confers no real authority.

No layer can be skipped or backfilled from an older version.

1. FIXED R010 DESIGN
   - exact CURRENT_DESIGN_ID and CURRENT_DESIGN_BLOB;
   - exact design Base/Head/Tree/Manifest (from frozen Git source);
   - reject every old DESIGN-009 through DESIGN-012 Blob for this round;
   - current V2 rule identifiers and security gates.
2. INDEPENDENT R010 DESIGN REVIEWS
   - B and C each independently review CURRENT_DESIGN_BLOB on the
     same frozen Base/Head/Tree and declare CURRENT_DESIGN_ID;
   - bind their two distinct current Review IDs; each must be TARGETED
     design PASS with no in-scope P0/P1/P2, old rounds not inherited.
3. R010 OWNER DESIGN CHOICE
   - exact CURRENT_DESIGN_ID and CURRENT_DESIGN_BLOB;
   - exact CURRENT_DESIGN_REVIEW_B_ID and CURRENT_DESIGN_REVIEW_C_ID;
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
   - binds exact CURRENT_DESIGN_ID/CURRENT_DESIGN_BLOB, current owner Choice
     and its canonical digest, separate current implementation Reviews,
     provider Job witness, global envelope and six distinct one-use row nonces;
   - old or mixed design/review/Choice/audience/Grant is DENY.
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
- r010_design_id exactly CURRENT_DESIGN_ID;
- r010_design_blob exactly CURRENT_DESIGN_BLOB;
- b_r010_design_review_id exactly CURRENT_DESIGN_REVIEW_B_ID;
- c_r010_design_review_id exactly CURRENT_DESIGN_REVIEW_C_ID;
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
The existing R010_OWNER_DESIGN_CHOICE_V1 marker remains structurally valid,
but a DESIGN-009/010/011/012 payload under this same marker is ALWAYS DENY;
no rehash, editing, copying fields or newer Review can promote that payload.
An edited comment, wrong current ID/Blob, historical Review IDs, mismatched
A/B option or missing risk marker => DENY.

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

The future OIDC-capable PREEXEC selector contract is exactly the versioned
section 14 exception, which supersedes the old R008/R009 exact PREEXEC
environment list ONLY at that stage. After PREEXEC all older no-credential,
no-SSH-agent-protocol and closed-child requirements remain:
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
PREEXEC_HOLD Job. This is a JOB-LEVEL permission (not PREEXEC process-only
isolation): same-UID code could steal runner request selectors. Other Jobs
must have no such permission. No live permission or request is authorized now.
Section 14 defines the only proposed compliant PREEXEC process boundary.

Before Owner PRODUCT_T1 grant:
1. PREEXEC_HOLD creates JOB_LOCAL_SECRET (256 random bits) in the create-once
   Job lease, never logs it, and computes JOB_LOCAL_SECRET_SHA256.
2. It requests a GitHub OIDC token with custom audience:
   mfg-r010:<CURRENT_DESIGN_BLOB>:<IMPLEMENTATION_HEAD_SHA>:<JOB_LOCAL_SECRET_SHA256>
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
- a single immutable internal Owner+Worker observation bound to the same
  active one-use row nonce, SAME DirectChildOwner reservation object and
  SAME original child wait/reap result, with matching integer exit codes;
  no independent user-fed booleans, alternate attempts, lost ACK or
  cancellation can create ROW_POSITIVE_SUCCESS;
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
- JWT verification transcript SHA256, issuer metadata/JWKS digest, algorithm/kid,
  signed subject/check_run and verified exp/nbf/iat freshness at grant;
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
9. R011 REQUIRED COMPOSED P2 NEGATIVES
   - exact OIDC PREEXEC-only env is allowed in the synthetic model;
     extra GIT_ASKPASS/proxy, missing OIDC request selector, URL spoofing,
     token/SSH leak into a helper/child, agent protocol use or foreign Popen
     => DENY.
   - synthetic verified original JWT receipt with exp/iat/nbf and JOSE/JWKS
     metadata; expired, stale, future, unknown kid, wrong alg, wrong signed
     check_run/sub, forged digest, unavailable raw bytes => DENY.
   - invalid R008 Choice + recomputed R010 Grant digest, mismatched current
     qualification design ID/Blob and B0+TARGETED-only => DENY.
   - in-memory SharedJobRegistry is NOT native atomic O_EXCL/fsync evidence.

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

## 14. R011 targeted normative correction: PREEXEC, JWT and composed grant

The following three corrections resolve the PREVIOUS R010 B-targeted design
P2s only as a NEW design candidate. They do not rewrite the Worker, alter
R010 original-child-reaped versus descendant-survival results, create
operative native code, authorize PRODUCT_T1 or infer any B/C PASS.

### 14.1 B114-R010-ST-D009-P2-01: R010_OIDC_PREEXEC_SELECTOR_V2

PRECEDENCE AND EXACT ALLOWLIST:
- R008 section 3.1 and R009 section 5 exact /usr/bin/env -i PREEXEC
  environment requirements are SUPERSEDED *for a future OIDC-enabled
  PREEXEC_HOLD entrypoint only*, never for ordinary legacy/product
  helpers/Worker/NativeRunner/PRODUCT children.
- The trusted tracked workflow starts a tiny stdlib-only PREEXEC process
  under absolute /usr/bin/env -i with EXACTLY the 18 R008 nonempty
  bootstrap keys and their pre-reviewed exact identities PLUS EXACTLY:
  ACTIONS_ID_TOKEN_REQUEST_URL=<runner-provided bounded HTTPS endpoint>
  ACTIONS_ID_TOKEN_REQUEST_TOKEN=<runner-provided nonempty bearer>
  No other key, token/cloud selector, GIT_ASKPASS, SSH_ASKPASS, KRB5CCNAME,
  proxy variable, user-provided environment key or config-based selector
  is allowed. The two added credentials are valid for PREEXEC only.
- The two OIDC values MUST originate from the current GitHub runner job
  context; a copied env value or caller assertion is not a provider
  identity proof, so the independently signed JWT verification below is
  mandatory. The reviewed custom audience binds exact CURRENT_DESIGN_BLOB
  (the R014 DESIGN-013 Git object resolved after freeze),
  exact current implementation Head and job-local-secret digest; URL, bearer and
  audience must NOT be influenced by REST/MCP/client, Workspace config,
  untrusted source files or public API input.
- Require HTTPS + authenticated hostname and certificate, a reviewed
  *.actions.githubusercontent.com request endpoint, exact request path
  shape and size, no arbitrary URL/redirect/proxy, no custom CA and
  bounded response. Missing/changed/unavailable endpoint or bearer
  => hard DENY, no fallback to old R008 exact env or untrusted URL.
- Only this PREEXEC process may receive SSH_AUTH_SOCK and the OIDC
  request selectors. SSH_AUTH_SOCK is a metadata-only path; zero
  SSH agent connect/send/recv/list-identity or autofs target activation.
  No unreviewed helper/process launch, no PRODUCT Popen before the
  independently authorized Owner execution grant.
- Before importing gateway/product modules or constructing service,
  remove SSH_AUTH_SOCK, both ACTIONS_ID_TOKEN_REQUEST_* names, raw JWT
  and any other credential selector from env, arguments and subprocess
  inheritance. Keep private source-verified 0600 original evidence
  under pinned 0700 disposable state only if a later review permits.
  The post-scrub product-helper nonempty env is EXACTLY:
  PATH=/usr/bin:/bin, HOME=<reviewed private>, TMPDIR=<reviewed private>,
  LANG=C, LC_ALL=C. The six future command children have separate exact
  reviewed recipe environments, never any SSH_AUTH_SOCK, GITHUB_*, RUNNER_*,
  Image*, ACTIONS_ID_TOKEN_* or unreviewed credential variable.
  No child may receive the raw selector values under renamed keys.
  If a safe Go/Pipenv-specific variable is necessary it needs a future
  explicit, reviewed child recipe; no ambient inheritance fallback.
- Future implementation must capture actual env construction at each
  PREEXEC/Helper/WorkspaceService/Worker/Runner/child boundary, ensure
  all foreign Popen/agent operations are absent and handle scrub failures
  by DENY. Source-only T0 merely tests synthetic maps and process-call
  counters and is not runtime evidence.
- The workflow grants id-token: write at JOB scope only, not per process.
  Same-UID credential theft and other host secrets remain accepted
  residual risk, NOT PROVEN ABSENT. No live token is fetched in this round.

### 14.2 B114-R010-ST-D009-P2-02:
R010_PROVIDER_JWT_TEMPORAL_VERIFICATION_V1

A future separately reviewed verifier MUST validate cryptographic ORIGINAL
JWT bytes, not a decoded-claims digest, self-reported "signature_verified"
boolean, public run status or Mock. Before ANY Owner execution grant:

1. Authenticate exact issuer discovery via trusted TLS from
   https://token.actions.githubusercontent.com/.well-known/openid-configuration .
   Obtain its issuer-controlled JWKS URI by authenticated metadata, never
   from attacker-provided JOSE header URLs. Limit response sizes, host,
   redirects/proxies, time and unknown key rotation. Preserve exact
   discovery/JWKS hashes for independent replay.
2. Require JOSE typ=JWT, alg=RS256, a unique known kid matching exactly one
   RSA issuer JWKS key. Verify RSA PKCS#1 v1.5 SHA-256 signature over the
   ORIGINAL base64url(header).base64url(payload) bytes. alg=none, HS256,
   invalid signature, unknown kid, wrong key type, duplicate kid, bad
   encoding/oversize or untrusted JWKS => DENY.
3. From the SIGNED payload, verify exact iss, custom aud, reviewed sub
   (from actual provider/workflow format, never a client guess), repo,
   run_id, run_attempt, signed check_run_id, workflow_ref, workflow_sha,
   github-hosted runner, verified Head/source/workflow Job linkage and
   JOB_LOCAL_SECRET_SHA256 audience binding. Independently check
   GitHub's actual CURRENT in-progress Job/check-run identity; no
   self-attributed job ID or public env string is sufficient.
4. Validate signed integer iat/nbf/exp with trusted wall clock:
   exp > iat, exp-iat <=600s; at first signature verification require
   iat <= now+30s and now-iat <=120s, nbf <= now+30s,
   exp > now. At Owner grant decision reverify the same Job is running,
   grant_now >= verified_at, grant_now-verified_at <=120s, and
   grant_now STRICTLY < exp. The <=30s skew is ONLY for iat/nbf,
   never acceptance of an already expired JWT. Missing/skewed clock,
   absent claim, expired/not-yet-valid token, stale grant or changed Job
   => DENY before Popen; new token requires new bound grant evidence.
5. Retain token SHA256, exact signed-input SHA256, selected JWKS/issuer
   metadata SHA256, alg/kid/verified signature result, full expected vs
   observed signed claim fields, verification and owner-check times,
   provider Job identity, verifier source version and verified transcript
   digest in one original source-bound sanitized transcript.
   Raw bearer/JWT bytes must NEVER go in PR comments, CI logs or public
   artifacts. A digest of a caller-authored transcript is not proof.
   Independent B/C qualification must be able to replay signature
   verification on actual ORIGINAL JWT bytes/JWKS via separately approved
   protected access during a live authorized Job; if no secure,
   independently inspectable original-byte path is available, STOP and
   report EVIDENCE_INSUFFICIENT rather than accepting a summary.
6. Bind original JWT digest and validated transcript digest to exact
   immutable Owner Choice, implementation/role Reviews, Job/lease,
   local secret and finite execution grant. Recheck freshness before
   product Popen. A different source, signed Job claim, clock, key
   version, transcript or grant is a different attempt and requires
   a new authorization.

Authoritative external claim reference:
https://docs.github.com/en/actions/reference/security/oidc
https://github.blog/changelog/2025-11-13-github-actions-oidc-token-claims-now-include-check_run_id/
The current model tests no real OIDC network calls or cryptographic JWT.

### 14.3 B114-R010-ST-D009-P2-03: atomic authority composition

1. An independently fetched immutable exact CURRENT_DESIGN_BLOB together
   with exact CURRENT_DESIGN_ID and both DISTINCT current R014 B/C design
   Review IDs on the SAME frozen Base/Head/Tree define EXPECTED authority
   values. Caller supplied Choice/Grant fields CANNOT define expectations.
2. Validate real direct OWNER authorship, immutable comment and current
   R010_OWNER_DESIGN_CHOICE_V1 marker, exact CURRENT_DESIGN_ID and
   CURRENT_DESIGN_BLOB, CURRENT_DESIGN_REVIEW_B_ID/C_ID, A0/A1+B0/B1,
   fresh R010 risk marker and ephemeral
   Job state BEFORE inspecting any execution grant digest. A legacy
   R008/R009 or superseded R010 DESIGN-009 Choice is DENY even with
   a recomputed matching digest.
3. Independently verify implementation code review objects and require
   qualification.design_id/blob EXACTLY CURRENT_DESIGN_ID /
   CURRENT_DESIGN_BLOB, separate current implementation Head/Tree/Manifest
   and independently verified B+C current code Review IDs, matching
   role/scope/verdict/evidence. For option B0, BOTH current reviews must
   be ROLE_FULL_SCOPE_PASS BEFORE T1; B1 must have BOTH current
   TARGETED_REVIEW_PASS for the complete pre-T1 critical path and later
   new FULL. Current B0/B1 choices remain UNDECIDED.
4. ONLY THEN validate fresh owner-authored immutable
   R010_OWNER_PRODUCT_T1_GRANT_V1 with CURRENT_DESIGN_ID/BLOB,
   exact selected options/risk,
   B/C design and implementation identity, canonical Choice digest,
   signed and fresh JWT original-byte transcript, current Job/lease/
   state/source/nonce. Invalid legacy choice+new grant, wrong qual
   design/blob, B0 paired with merely TARGETED, changed token digest,
   wrong risk/host or stale Reviewer ID => pre-Popen DENY.
5. No T0 caller-created dataclass, faked review metadata, self-asserted
   verification flag or digest grants production authority. The pure
   model tests field consistency only; actual GitHub/owner/provider
   provenance and persistent atomic Journal are NOT_IMPLEMENTED.

### 14.4 B R010 P3 and remaining non-runtime proof limits

SharedJobRegistry's process-local set does NOT prove interprocess atomicity:
two independent registries can claim identical keys in SAFE T0. Later
true O_EXCL/fsync, two-process contention, crash/lost ACK, no-state-adoption
and same-UID credential handling need original authorized evidence and
independent B/C review. The job-level id-token permission is not
PREEXEC-only OS isolation. Product host/sandbox guarantees, loaded graph,
positive native T1, integration, FULL and R10 remain not established.

HISTORICAL_R011_REVISION_STATUS=PROPOSED_NOT_EFFECTIVE
HISTORICAL_R011_REVISION_ROUND=D4-R012-AUTHORITY-CHAIN-DESIGN-011
HISTORICAL_R011_B_C_REVIEWS_AT_THAT_TIME=NOT_ISSUED
A0_B0_DEFAULT_DENY_RETAINED=true
REAL_PROVIDER_OIDC=NOT_RUN
PRODUCT_T1=NOT_RUN_NOT_AUTHORIZED
INTEGRATION_STATUS=NOT_TESTED
R10_STATUS=BLOCKED

### 14.5 R011 independently expected identities and retry boundary

The expected signed OIDC subject is pinned from the independently reviewed
current workflow/provider subject policy and exact Job; it cannot come from
a JWTVerificationReceipt.expected_subject field, a caller-provided claim
summary or a value copied from the token itself. A signed subject matching
a forged caller-authored expectation is DENY. The R011 SAFE T0 model requires
expected_provider_subject as a SEPARATE trusted comparison input.

Similarly, a valid GitHub re-run has its OWN positive decimal
GITHUB_RUN_ATTEMPT and a fresh separately authorized Job/Owner binding; a
literal attempt "1" is not a permanent allowlist. A new run_attempt=2
may qualify only when the trusted expected attempt is ALSO 2 and the
reviewed current exact Job/Head/secret/nonce match. A stale attempt=1
grant or environment copied into attempt=2 is DENY, and leading-zero
or missing attempt identities are rejected. No attempt is replayable.

These rules change only the NON_RUNTIME source-backed model and proposed
design; actual Job witness/Owner verification remains NOT_IMPLEMENTED.


## 15. R012 minimal targeted correction of R011 B P2-01/P2-02/P3-01

R011 B's independent REVIEW_COMPLETE / INSUFFICIENT / BLOCKED verdict on
the frozen R011 Head identified two model false positives and a canonical
identity precision defect. R011 C independently issued TARGETED DESIGN PASS
with endpoint path precision P3. Neither role verdict carries to R012.
This section is normative for fresh DESIGN-011, supersedes the incomplete
R011 section 14.1 URL example and strengthens section 10 row classification. It adds
NO new runtime authority, network test permission or change to F1/R006.

### 15.1 OIDC URL: R012_GITHUB_RUNNER_PIPELINES_OIDC_BASE_V1

GITHUB DOCUMENTATION FACT: The GitHub Runner provides the complete
ACTIONS_ID_TOKEN_REQUEST_URL and a separate Bearer selector and the Actions
toolkit appends an URL-encoded &audience=<...> query. Official documentation
does NOT promise a permanent provider request path. No T0 test here has a
live Runner URL or an actual OIDC request. Our existing R011 Fake Runner T0
fixture uses this candidate backend profile:

  https://<exact-lowercase-single-label>.actions.githubusercontent.com/_apis/oidc/token?api-version=2.0

For this REVIEWED PROFILE V1 ONLY, before any Bearer request or foreign
subprocess, check strict raw-byte canonical equality after parsing:
- HTTPS scheme exactly lowercase and a single nonempty ASCII DNS subdomain
  label [a-z0-9][-a-z0-9]* with no leading/trailing hyphen; exact suffix
  .actions.githubusercontent.com; no userinfo, unexpected port, IP literal,
  alternate scheme, host case variation, repeated/doubled dot, backslash
  or CR/LF/space/control.
- Path EXACTLY /_apis/oidc/token (case-sensitive, no percent encoding, dot
  segment, trailing slash, semicolon, extra prefix/suffix or normalization).
- Original Runner base query EXACTLY api-version=2.0; no original audience,
  no repeated or unexpected parameters, empty values, alternate order,
  encoded '=' or '&', overlong/unbounded URL or trailing # / fragments.
- Construct the **only** outgoing URL from the validated BASE plus
  "&audience=" and RFC3986 percent-encode every reserved byte of the exact
  OWNER-bound mfg-r010:<design GitBlob>:<Head>:<JOB_LOCAL_SECRET_SHA256>.
  Accept only the fixed lower-hex 40/40/64 digest audience shape; do not
  copy caller-provided audience or append a second audience parameter.
- In a future independently reviewed network implementation, reject any
  3xx/Location/redirect, proxy env, custom CA, unreviewed destination,
  differing TLS certificate hostname or reinterpreted URL **before
  forwarding the Bearer** to an unapproved endpoint. Redirect handling must
  be explicitly disabled, not followed and checked only afterward.
  The current T0 models an oidc_redirect_count=0 assertion and zero real
  network/credential operations; it does NOT demonstrate live HTTP behavior.

A legitimate provider-side path/shape drift is a deny requiring a NEW
independent provider observation, reviewed endpoint profile and owner/role
approval. It is NOT a reason to silently widen a suffix allowlist. The
candidate is grounded in the fixed R011 Fake Runner fixture and public
toolkit request-form examples, NOT an assertion that the GitHub production
service promises this path forever. Inability to establish the exact live
source URL in the future means PRODUCT_T1=DENY and REAL_PROVIDER_OIDC=NOT_RUN.

Public references for behavior only (not authoritative path guarantees):
https://docs.github.com/en/actions/reference/security/oidc
https://github.com/actions/toolkit/tree/main/packages/core

### 15.2 One same-attempt private OriginalChild/Worker outcome

No separate scalar trusted-success flags may be passed to the R012 T0 row
classifier. Use ONE frozen OwnedRowObservationT0 that models internal
DirectChildOwner and Worker observations for exactly the in-flight
JobEnvelope active row nonce. In the *future real implementation* this
immutable record MUST be minted only inside the trusted owner/Worker
adapter from the same private DirectChildOwner reservation object; not
from REST/MCP, config, caller attributes, returned Worker dictionaries
or a synthetic test dataclass.

The adapter's accepted positive original-child proof requires ALL:
- owner_attempt_nonce == worker_attempt_nonce == active row nonce;
- owner_reservation IS worker_reservation (private reference identity,
  not equivalent caller-supplied string/digest);
- the DirectChildOwner wait()/reap observation status is exactly "exited",
  with a non-bool integer exit_code 0 and proven original_child_reaped;
- Worker outcome status exactly "exited", executed=true, timed_out=false,
  cancelled=false, ack_lost=false; integer Worker exit_code exactly equals
  private owner exit_code 0; no stale/different attempt result;
- BOTH streams actually EOF, no truncation, within bound and reviewed
  finite filesystem/artifact integrity predicates all pass;
- original public process_may_be_running may remain true as possible
  descendant risk. Preserve cleanup_proven=false and
  full_descendant_tree_clean=not_proven, with no false tree-clean claim.

If two same-reservation original exit results agree but are nonzero,
ROW_OBSERVED_NONZERO. If true exit0 but EOF, truncation, byte/output bound
or FS/Go artifact predicate is invalid, ROW_OBSERVED_ZERO_INVALID_OUTPUT_OR_FS.
If Worker status/timed_out/executed contradicts the owner, a reservation/
nonce differs, original wait fails, ACK is lost, a request is cancelled, or
timeout occurs, return ROW_AMBIGUOUS regardless of echoed exit0/EOF;
latch JOB_FAILED_LATCHED, burn that nonce, VOID all remaining rows, deny
every later Popen or replay. A subsequent detached/later wait cannot
retroactively turn a timed-out row positive.

R012 FakeChild T0 now spies on the ACTUAL library
DirectChildOwner.observe(reservation) and actual LbeWorker.run result for
one injected FakeChild, then builds the frozen test-only observation from
that recorded private reservation object plus the Worker result. Poison
the Worker result (exited->timed_out, executed=false, timed_out=true,
exit mismatch), owner/worker attempt IDs or private object identity to
prove fail-closed. Synthetic T0 does NOT implement a truly
unforgeable production receipt or authorize a real native child.

### 15.3 ASCII run_attempt canonical identity

Use the canonical ASCII-only fullmatch [1-9][0-9]* with existing
12-character ceiling in this reviewed model. Reject Unicode decimal
digits, Arabic-Indic digits, fullwidth numerals, leading zeros, empty
string, signed values, whitespace, float/exponent/hex forms and booleans.
Then require exact match to the separately verified current GitHub
Run Attempt numeric identity; a valid retry attempt 2 is not permanently
forbidden, but old attempt 1 authority never transfers to it. Matching
two untrusted strings alone remains T0 and cannot authenticate a Job.

### 15.4 T0/CI evidence limits and fresh freeze conditions

The new RED matrix first shows same-approved-host wrong path/query and
double/encoded params falsely accepted, Unicode decimal attempt falsely
accepted, and the absence of a combined owner/worker outcome boundary.
GREEN must prove legitimate profile+audience passes, all wrong same-host
path/query/encoding/redirect cases fail **before** fake Bearer send, the
real Worker/Owner injected FakeChild original status and exit0 still pass
with descendants unproven, and status/nonce/reservation/exit/cancel/lost
ACK/timeout conflicts latch FAILED and VOID later rows. Existing
nonzero/zero-invalid, six serial rows and F1/File/Git/REST/MCP regressions
must remain safe. Only current Head G05+Manifest and original CI count;
a synthetic GREEN is never real OIDC or native integration.

SECURITY_BOUNDARIES_UNCHANGED:
- Current operative F1/R006 strict positive Exec DENY.
- No live OIDC request, id-token:write workflow change, bearer or JWKS
  network operation, SSH-agent socket access, autofs activation, network
  canary, real Python/Pipenv/Go PRODUCT_T1, T2/T3 or production action.
- Owner A0/A1 and B0/B1 choice UNDECIDED; no approved direct R012 owner
  choice/execution grant, no native T1 qualification, no FULL role review,
  integration or R10 release authority.
- HISTORICAL R012-only requirement: reviewers at the time had to fix
  HEAD/BASE/TREE/new DESIGN-011 Git Blob and independently verify old
  R012 evidence. DESIGN-011 never becomes the CURRENT_DESIGN_BLOB for
  R014, and its old role verdicts never transfer.

HISTORICAL_R012_DESIGN_STATUS=PROPOSED_NOT_EFFECTIVE
HISTORICAL_R012_REVIEW_ROUND=D4-R012-AUTHORITY-CHAIN-DESIGN-011
HISTORICAL_R012_REAL_OIDC_REQUEST=NOT_RUN
ORIGINAL_MACOS_PRODUCT_T1=NOT_RUN
INTEGRATION_STATUS=NOT_TESTED
FULL_CODE_REVIEW_PASS=NOT_ISSUED
R10_STATUS=BLOCKED


## 16. R013 targeted P2 repair: reader/Owner health and irrevocable child deny

R013 applies only to the PREVIOUS frozen R012 Standards findings
B114-R012-ST-D011-P2-01 and B114-R012-ST-D011-P2-02, plus the directly
necessary R012 C-scope adjacency. R012 B published REVIEW_COMPLETE,
EVIDENCE_STATUS=INSUFFICIENT, VERDICT=BLOCKED with two in-scope P2.
R012 C independently published TARGETED_REVIEW_PASS for DESIGN-011,
NOT a PASS for DESIGN-012 or any runnable product.

This section takes precedence over earlier sections 10/14/15 wherever
they leave reader fault or child env override validation incomplete.
Its historical R013 version predicates have NO R014 authority; section
17 now takes precedence over ALL earlier current-design identity predicates
(including this section) without weakening reader/child-env safety.
It creates NO executable authority and does NOT change F1/R006, native
launcher, Worker/DirectChildOwner source, GitHub workflow permissions,
OIDC token acquisition, or real PRODUCT_T1 safety eligibility.

### 16.1 B P2-01: reader/owner state is part of the ONE private row receipt

A genuinely reaped original child, Worker.status="exited",
Worker.executed=true, Worker.timed_out=false, matching integer exit=0
and both stdout/stderr EOF do NOT suffice if reader resource cleanup
fails. A real selector.close() or pipe.close() error AFTER both EOFs
may produce output_complete=true AND pipe_reader_failed=true; the
actual BoundedPipeDrain._release_resources sets _fault=true, signals
the owner, and the Worker may return status="exited" after calling
DirectChildOwner.latch_unavailable(reservation). This is a reader/owner
uncertainty, never a positive next-row admission.

For DESIGN-012 SAFE T0, the ONE frozen OwnedRowObservationT0 already
binds identical active nonce, owner/Worker attempt, private reservation
identity and witnessed original-child exit. Extend it to require ALL:
- Worker-produced pipe_reader_failed is exactly False, not silently
  omitted when output_complete=True.
- The *same private reservation's* BoundedPipeDrain.snapshot reports
  pipe_reader_failed exactly False AND pipe_reader_finished exactly True.
- The actual DirectChildOwner.snapshot for the same owner is healthy:
  unavailable exactly False AND closing exactly False, sampled after
  the reader completion and immediately before row classification.
- The original Owner DirectObservation and Worker result remain
  consistent, no canceled/timed-out/ACK-lost or other invalid attempt.
- Both actual streams EOF, no truncation, bounded bytes/redacted chars,
  valid finite FS and Go artifact predicates.

If ANY reader fault, missing reader-finalization proof, Owner-unavailable
latch, Owner-close drift or contradictory Worker/Owner health exists,
classify ROW_AMBIGUOUS (even when original exit=0 and EOF=true).
This specifically overrides the broader earlier wording "failed reader
=> ROW_OBSERVED_ZERO_INVALID_OUTPUT_OR_FS" for *owner/reader health
faults* where the trusted completion authority is unavailable.
ROW_OBSERVED_ZERO_INVALID_OUTPUT_OR_FS continues to apply to a
HEALTHY completed reader with missing EOF, output truncated/over-bound
or finite filesystem/artifact mismatch. Known nonzero only qualifies
as ROW_OBSERVED_NONZERO when the same private observation and reader
health are valid. Missing/false proof NEVER means allow subsequent
Popen. Every nonpositive row latches JOB_FAILED_LATCHED, burns the
nonce, VOID remaining rows, forbids retry/replay/later Popen.

SAFE T0 tests must use ACTUAL LbeWorker/DirectChildOwner/BoundedPipeDrain
source with an INJECTED FakeChild, explicitly produce TWO real fake
zero-byte EOF events and then a selector.close() failure, and inspect
Worker.pipe_reader_failed=True and Owner.unavailable=True. The row
oracle MUST remain AMBIGUOUS/FAILED/VOID. Also test that a healthy
status-exited original and completed no-fault reader still produces
ROW_POSITIVE_SUCCESS even when public process_may_be_running=True
describes unproven descendants, cleanup_proven=False and
full_descendant_tree_clean="not_proven". More synthetic negatives must
poison worker/owner reader health and finished flags independently.

The receipt is NON_RUNTIME and source-only: test code reads the
private owner reservation and reader snapshot. No client may mint
this as evidence; the production pinned same-attempt adapter and
atomic durable Job status/nonce journal do NOT exist yet and need
separate implementation qualification. Current runtime Worker itself
is NOT changed in this repair.

### 16.2 B P2-02: hard-block forbidden child environment variable names

An optional approved_child_keys argument is NEVER authority to expand
the security boundary of the separate PRODUCT child. Do not merely
compare a set of keys to a caller-provided frozenset or compare child
values to the original PREEXEC Bearer. Hard DENY protected NAMES in
the requested recipe and the actual child, independently of any
caller-selected extension:

- All ACTIONS_ID_TOKEN_*, GITHUB_*, RUNNER_*, SSH_*, GIT_*,
  OIDC_*, AWS_*, AZURE_*, GOOGLE_*, GH_*, KRB5_* and Image*/IMAGE_*
  selector families, plus exact SSH_AUTH_SOCK, GIT_ASKPASS,
  SSH_ASKPASS and KRB5CCNAME.
- All HTTP(S)_PROXY, ALL_PROXY, NO_PROXY and any other proxy selector,
  including case changes and embedded PROXY; PIP_INDEX_URL,
  PIP_EXTRA_INDEX_URL, PIP_TRUSTED_HOST, PIP_CONFIG_FILE,
  PIPENV_* and other unapproved package/mirror selectors.
- Names with token/password/secret/key/credential/auth suffixes or
  embedded TOKEN/SECRET/PASSWORD; names outside canonical uppercase
  ASCII env identifier syntax are denied.
- Literal original OIDC Bearer, runner URL or SSH socket path forwarded
  as ANY child/helper VALUE, including a renamed key or a prefixed/
  suffixed copy; this is a conservative static value check, not proof
  against transformed/encoded secret exfiltration.

The safe child BASE is the closed five-key product-helper environment
PATH, HOME, TMPDIR, LANG and LC_ALL. Only a separately source-reviewed
SAFE T0 addition may join its closed recipe. This proposed R013
immutable source-reviewed extra key/value profile is exactly:

  PYTHONUNBUFFERED=1
  PYTHONDONTWRITEBYTECODE=1
  PIP_NO_INDEX=1
  PIP_DISABLE_PIP_VERSION_CHECK=1

Any selected combination of those four safe names is permitted solely
with its EXACT value, plus all five base keys inherited exactly from
the sanitized helper. An unknown Go/Pipenv/runtime env variable, a
different value or an arbitrary approved_child_keys extension is
DENY; review and VERSION a future new safe recipe explicitly rather
than mutating this list or inheriting bootstrap env. These T0 candidate
recipe options do not activate Go/Pipenv product execution.

The PREEXEC stage still may receive exactly its separate reviewed two
runner OIDC selectors, but the product helper remains the exact five
noncredential keys and the product child must never receive the
forbidden selector NAMES or values. No network/token request, HTTP
redirect or foreign process is performed to evaluate this model.

### 16.3 Original safe T0 / RED->GREEN and freeze

For B P2-01, original RED MUST show FakeChild success status exit0 with
both fake EOFs but a selector close-after-EOF resource fault; Worker
returns pipe_reader_failed=true and owner unavailable=true, yet the
old row model falsely advances. GREEN must produce ROW_AMBIGUOUS,
JOB_FAILED_LATCHED, remaining ROW_VOID and zero future Popen; original
no-fault exit0/nonzero/zero-invalid and cancel/timeout must regress.

For B P2-02, original RED MUST show that approved_child_keys
frozenset({base five} | {"ACTIONS_ID_TOKEN_REQUEST_TOKEN"}) can
whitelist a *different fake token value* under that forbidden name;
also test SSH/GITHUB/Runner/proxy/package selectors. GREEN must
hard-deny irrespective of the override, retain safe exact-value extra
recipe positives, reject renamed/embedded bearer, and preserve the
existing signed OIDC Job-identity and canonical URL/ASCII-attempt T0.

Retest the exact Head original Linux SAFE T0 and appropriate HTTP/MCP,
Git/File regressions, current G05, Blob modes, Manifest and expected
macOS R006 host FAIL_CLOSED. No exact positive native Worker, live
OIDC, signature/JWKS, actual durable cross-process lease or integration
is authorized. If new source/contract/Head drift occurs, B/C must
review the fresh immutable Head/Tree and cannot inherit R012 PASS.

HISTORICAL_R013_DESIGN_ID=MWE-LBE-R010-AUTHORITY-CHAIN-DESIGN-012-CANDIDATE
HISTORICAL_R013_DESIGN_STATUS=PROPOSED_NOT_EFFECTIVE
HISTORICAL_R013_REVIEW_ROUND=D4-R013-AUTHORITY-CHAIN-DESIGN-012
R012_B_VERDICT=BLOCKED_HISTORICAL_ONLY
R012_C_VERDICT=TARGETED_PASS_HISTORICAL_ONLY
OWNER_A0_A1_B0_B1=UNDECIDED
ACTUAL_OIDC_AND_JWT=NOT_RUN_NOT_AUTHORIZED
NATIVE_PRODUCT_T1=NOT_RUN_NOT_AUTHORIZED
INTEGRATION_STATUS=NOT_TESTED
FULL_CODE_REVIEW_PASS=NOT_ISSUED
R10_STATUS=BLOCKED


## 17. R014 unique CURRENT DESIGN authority and irreversible revocation

This section is normative for R014, DESIGN-013 and all later steps that
claim to derive authority from THIS fixed source contract. It resolves
C114-R013-DESIGN-012-SPEC-01 by superseding ALL inconsistent earlier
current-version predicates, specifically the original section 1
"DESIGN-011 fresh", section 14.1 audience, section 14.3 expected ID/Blob
and qualification, section 15.4 old "new review" direction, and the
section 16 former DESIGN-012 current-instance scope. Earlier technical
safety requirements (F1/R006 refusal, closed PREEXEC, original reaper,
healthy pipe drain, owner/reader latch, serial six nonces, state/host/
source guards, no descendant cleanup claim) are RETAINED unchanged.

### 17.1 One current source object; no self-hash

CURRENT_DESIGN_ID = MWE-LBE-R010-AUTHORITY-CHAIN-DESIGN-013-CANDIDATE.
CURRENT_DESIGN_BLOB = the exact SHA1 Git blob object holding the entire
frozen bytes of THIS file, independently resolved by GitHub content API
and crosschecked against the identical path at the frozen design
HEAD_TREE. It is NOT the R013 DESIGN-012 Blob fa3f756f5876e67ff9434747c855a68fd01e7654,
the R012 DESIGN-011 Blob 1dddfdaa5f610c6c02ba9b81d4d11296d2b36eb3,
or a synthetic constant like "a"*40. The final current Blob must be
calculated AFTER editing this file; the hash is NOT embedded into this
same file. A separately versioned tools/r010_authority_chain_t0.py
source-only model may pin the exact resulting final Blob and tests MUST
recalculate git_hash(b"blob "+size+b"\0"+bytes) of this exact document.
The frozen Head/Base/Tree and final Git Blob must match the current
GitHub API contents before any B/C review or Owner Choice exists.

The only current external expected authority includes ALL of:
- this exact CURRENT_DESIGN_ID and final CURRENT_DESIGN_BLOB;
- the same immutable R014 design BASE_SHA, HEAD_SHA and HEAD_TREE;
- separately independently issued, nonempty, DISTINCT, current B/C
  R014 design Review node IDs both on that exact target and snapshot;
- a new direct, unedited human OWNER choice on those precise IDs,
  options A0/A1 + B0/B1, reviewed risk acceptance and state domain;
- a separate, later current implementation HEAD_SHA/HEAD_TREE/Manifest,
  appropriate B/C independent pre-T1 implementation code Reviews;
- provider-signed original-byte OIDC evidence for the current run/job/
  attempt/Head, audience exactly mfg-r010:<CURRENT_DESIGN_BLOB>:
  <IMPLEMENTATION_HEAD_SHA>:<JOB_LOCAL_SECRET_SHA256>;
- a fresh owner-authored R010_OWNER_PRODUCT_T1_GRANT_V1 binding all the
  above together with one Job-global lease and exactly six one-use
  command nonces. No state row runs until actual owner qualification.

The old message TYPES R010_OWNER_DESIGN_CHOICE_V1 and
R010_OWNER_PRODUCT_T1_GRANT_V1 remain structurally valid. But types
alone confer NO authority. A payload using an earlier design ID,
earlier Blob, stale B/C IDs, old signed audience, old implementation
Head/Job/nonce, stale risk choice or old grant is forever INVALID
for this R014 contract even if someone recomputes its canonical digest
under a new type marker or forges a consistent expected field set.

### 17.2 Precedence and history versus required present

All occurrences of DESIGN-009, DESIGN-010, DESIGN-011 and DESIGN-012
in sections 1/14/15/16, parent tables, historic audit trails, old review
references, previous snapshots or superseded footers are HISTORICAL
identifiers only. They DO NOT provide alternative current-required IDs,
valid expected Blob, Review IDs, Choice, Qualification, audience or Grant.
The operative identity of the CURRENT contract is section 3 plus THIS
section 17; in any conflict these supersede ALL earlier version
predicates. In particular, no OLD id/blob survives as an alias of the
current DESIGN-013 and no C/B Review can be inherited after a new Blob.

Valid R014 B/C design Reviews, if independently issued later, cannot
be assumed to exist at source freeze. A (Developer) never fabricates
their IDs or an Owner choice. The current status remains PROPOSED and
the only executable decision remains DENY.

### 17.3 Required current-snapshot T0 cross-version adversarial matrix

A synthetically correct current DESIGN-013 + its EXACT, independently
pinned final contract Git Blob + distinct synthetic current-role IDs,
mock fresh direct Choice, qualification, matching mock signed audience
and matching synthetic Grant MUST pass PURE FIELD-CONSISTENCY checks.
This is a legitimate model-success path, not an actual JWT signature,
two actual human approvals, or permission to launch a child.

All of the following MUST be denied in pure T0 before any possible
Popen: old DESIGN-011 and old DESIGN-012 Choices, either historical
Blob disguised by a current DESIGN_ID and recomputed digest, current
Blob with R013 old B/C Review node IDs, an old OIDC audience in a
new Choice, a stale owner Grant rehashed to resemble current fields,
foreign/stale Job or run_attempt, changed implementation HEAD,
missing/disparate review IDs, missing state/nonce or unrelated
target. Matching self-declared fields do not prove GitHub provenance.
The external trusted expected design Blob and expected Review IDs
cannot be copied from caller-supplied Choice/Grant.

### 17.4 Freeze / evidence / safety status

A-only SHA-bound original RED->GREEN on full current Git Head, G05,
source Blob and tracked MANIFEST.sha256, and adjacent SAFE T0 are
required for R014 targeted design handoff. New B and C reviews MUST
both bind the identical BASE/HEAD/TREE/CURRENT_DESIGN_BLOB. Historical
R013 B TARGETED_PASS and C FAIL are not R014 B/C conclusions.

No live OIDC token request or JWT verification, mutable field and
actual Owner-authorship proof, real crossprocess O_EXCL/fsync/owner.lock
recovery, native Python/Go/Pipenv PRODUCT_T1, same-instance positive
integration, FULL/R10, shared or production, merge/tag/deploy is
authorized by this design revision. F1/R006 and PR102 source/host Gate
B OFFLINE_ONLY remain fail-closed.

R014_DESIGN_ID=MWE-LBE-R010-AUTHORITY-CHAIN-DESIGN-013-CANDIDATE
R014_DESIGN_STATUS=PROPOSED_NOT_EFFECTIVE
REVIEW_ROUND=D4-R014-AUTHORITY-CHAIN-DESIGN-013
CURRENT_DESIGN_BLOB_VALUE=POST_FREEZE_GIT_OBJECT_NOT_EMBEDDED
R014_B_REVIEW=NOT_ISSUED
R014_C_REVIEW=NOT_ISSUED
OWNER_A0_A1_B0_B1=UNDECIDED
REAL_PROVIDER_OIDC=NOT_RUN_NOT_AUTHORIZED
PRODUCT_T1=NOT_RUN_NOT_AUTHORIZED
INTEGRATION_STATUS=NOT_TESTED
FULL_CODE_REVIEW_PASS=NOT_ISSUED
R10_STATUS=BLOCKED
