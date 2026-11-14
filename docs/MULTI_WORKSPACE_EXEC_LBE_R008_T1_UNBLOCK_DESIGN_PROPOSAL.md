# Multi-Workspace Exec LBE R008 - PRODUCT_T1 Host and Review-Sequence Repair

TASK_ID: MULTI-EXEC-LBE-FIVE-DAY-CANDIDATE-20261105
MILESTONE_ID: LBE-FIVE-DAY-CORE-PRODUCT-CANDIDATE
DESIGN_ID: MWE-LBE-R008-T1-UNBLOCK-DESIGN-007-CANDIDATE
STATUS: PROPOSED_NOT_EFFECTIVE
PARENT_R007_DESIGN_BLOB: e9094844bb21517d8ca585560003ba4c5cd16dfe
PARENT_R006_DESIGN_BLOB: b8d8a1cb32fb7130dfa6d00b37831dfddfaad11c
RULESET_ID: ICR-V2.0
HANDOFF_PROTOCOL_ID: GHRH-2.0
EVIDENCE_PROFILE_ID: ETP-V2.0
HOST_OPTION: UNDECIDED
REVIEW_SEQUENCE_OPTION: UNDECIDED
PRODUCT_T1: DENY
INTEGRATION_STATUS: NOT_TESTED

This file repairs the R007 design findings only. It is not runtime authority.
Current code remains strict R006 fail-closed. No A1/B1 implementation, PRODUCT_T1,
agent query, autofs activation, T2/T3, user Mac/Tunnel, merge, tag, release or
production action is authorized by this proposal.

## 1. R007 review findings being repaired

This R008 candidate is written to close, at design level:

- C114-R007-DESIGN-006-SPEC-01 and B114-R007-DESIGN006-P2-01:
  A1 contradicted itself by allowing an unknown SSH agent while retaining a
  no-production-credential assurance and lacked a deterministic selector/socket
  oracle.
- C114-R007-DESIGN-006-SPEC-02 and B114-R007-DESIGN006-P2-03:
  future owner authority did not bind the new design/selected options/new risks
  and complete T1 qualification scope.
- C114-R007-DESIGN-006-SPEC-03:
  one-use authority was not bound to one immutable GitHub Job across separate
  hosted-runner filesystems.
- B114-R007-DESIGN006-P2-02:
  autofs allowance was not bound to source/flags/count/full same-job snapshot.
- C114-R007-DESIGN-006-SPEC-04 and B114-R007-DESIGN006-P3-01:
  pre-T1 critical-path review coverage and the difference between one Job and
  six original command attempts were underspecified.

No prior FAIL/BLOCKED is converted to PASS by this text.

## 2. Fixed real host evidence that motivates A0/A1

Pre-design source Head:
958bd9350ca8b651c173006ead39ed0662ced766

Real GitHub-hosted macOS 15 ARM64 safe T0:
Run 42469201680 / Job 128695758515.

Observed without connecting to SSH agent or activating/walking the autofs target:
- kernel=Darwin, machine=arm64, macOS=15.8.2;
- proxy_variable_names=[];
- credential_variable_names=["SSH_AUTH_SOCK"];
- mount_count=11;
- exactly one writable non-local row was reported:
  fstype=autofs
  target=/System/Volumes/Data/home
  source_sha256=6713f2a70c72b6c412839ad247f7605db53105c3e624c0a9cd778eb7fdeef5ad
  flags=72351744.
- native_launch_allowed=false and current strict R006 verifier denied before
  PRODUCT_T1.

The raw f_mntfromname is intentionally not printed in public CI. Its SHA256 is
an identity witness, not proof that future activated backing storage is safe.

## 3. Host decision

### A0 - retain strict R006

A0 changes nothing. SSH_AUTH_SOCK remains unknown credential exposure and every
writable non-local mount remains DENY. Current standard macOS route is not
PRODUCT_T1 eligible.

### A1 - explicit, owner-signable weakening

A1 is allowed to become effective only after:
1. B and C independently PASS this exact R008 design Blob;
2. the repository owner explicitly selects A1 and accepts RISK_10 and RISK_11;
3. A implements a separately versioned code Head with safe T0;
4. B/C independently qualify that exact runnable Head under B1 if B1 is chosen;
5. a later exact Job grant is issued.

A1 REPLACES the R006 "no production secrets" claim with this narrower truthful
claim:

NO_EXPLICIT_CREDENTIAL_INJECTION is the only retained credential guarantee.
The product bootstrap and child do NOT intentionally inject production
credential material, checkout credentials, cloud credentials, askpass helpers,
Kerberos selectors or token variables. A1 DOES NOT guarantee that production or
otherwise sensitive credentials are absent from same-UID host resources.

RISK_10:
The GitHub-hosted runner may expose a live SSH agent or other same-UID host
credential channel whose contents can include production or otherwise sensitive
credentials. The product does not query or intentionally use it, but R008 does
not provide an OS sandbox preventing reviewed/foreign same-UID code from
discovering or accessing such host resources. Selecting A1 explicitly accepts
this possibility. NO_PRODUCTION_CREDENTIALS_PROVEN=false and
NO_AMBIENT_SSH_AGENT_PROVEN=false.

### 3.1 Closed bootstrap and child environment oracle

A1 implementation MUST launch the PRODUCT_T1 harness under a service-owned
environment constructed from scratch, not inherited wholesale.

The only allowed non-empty bootstrap keys are:
PATH=/usr/bin:/bin
HOME=<private reviewed runner home>
TMPDIR=<private reviewed runner temp>
LANG=C
LC_ALL=C
GITHUB_ACTIONS=true
GITHUB_EVENT_NAME=pull_request
GITHUB_REPOSITORY=chinanjjohn2012/mac-file-gateway
GITHUB_RUN_ID=<exact decimal>
GITHUB_RUN_ATTEMPT=<exact decimal>
GITHUB_JOB=<exact reviewed logical job name>
G05_EXPECTED_HEAD=<exact frozen Head>
RUNNER_ENVIRONMENT=github-hosted
RUNNER_OS=macOS
RUNNER_ARCH=ARM64
ImageOS=macos15
ImageVersion=<reviewed image version>
SSH_AUTH_SOCK=<exact observed absolute Unix-socket path>

Any additional environment key is DENY for this PRODUCT_T1 bootstrap. This
closed allowlist prevents GIT_ASKPASS, SSH_ASKPASS, KRB5CCNAME, token/cloud
selectors and unknown inherited environment selectors from entering the service
process by omission, rather than attempting an incomplete secret-name blacklist.

The exact child environment remains the existing recipe-owned closed
environment and MUST NOT contain SSH_AUTH_SOCK or any GITHUB_/RUNNER_/Image*
identity variable.

### 3.2 SSH_AUTH_SOCK metadata-only witness

No design/review/T0 step may connect to the agent, list identities, read keys or
send an agent protocol request.

Before owner grant and again immediately before Popen, the trusted bootstrap
MUST:
- require SSH_AUTH_SOCK to be one absolute canonical path, no NUL and bounded
  length;
- lstat the socket path without following a symlink and require S_ISSOCK;
- require socket uid == current runner uid, no group/other permission bits and
  stable dev/inode/mode/uid/gid/nlink;
- resolve from a pinned parent directory with nofollow/fstatat-style metadata
  checks; no component may be a symlink;
- require the immediate socket directory and every descendant directory below
  the platform temp anchor to be runner-owned and not group/other writable;
- permit a platform temp anchor only when it is the exact pinned root-owned
  sticky directory mode 01777 (for example /private/tmp) with stable
  dev/inode/uid/mode; ancestors above that anchor must be root-owned and not
  group/other writable;
- bind every ancestor dev/inode/uid/mode identity into the same-Job snapshot
  and reject replacement or permission drift at the final recheck;
- hash the path string for the owner-visible host snapshot rather than publish
  the raw path;
- bind socket path hash plus socket/ancestor metadata into the exact Job host
  snapshot and owner execution grant;
- require the final pre-Popen metadata recheck to be identical.

A missing/replaced/symlinked/wrong-owner/permissive/drifted socket is DENY with
zero Popen. Passing this metadata oracle DOES NOT prove agent contents safe and
does not reduce RISK_10.

### 3.3 Autofs exact-row and same-job snapshot oracle

A1 permits exactly ONE writable non-local mount row and only if its observed
identity equals all of:
- fstype=autofs
- target=/System/Volumes/Data/home
- source_sha256=6713f2a70c72b6c412839ad247f7605db53105c3e624c0a9cd778eb7fdeef5ad
- flags=72351744
- current qualification mount_count=11.

The verifier MUST hash the complete sorted getmntinfo table including
fstype,target,raw-source bytes and flags. The exact full-table fingerprint is
created inside the exact T1 Job before owner execution grant and is included in
that grant. The raw source need not be published.

Immediately before every Popen:
- reread getmntinfo;
- require exactly one writable non-local row;
- require the exact row identity above;
- require no additional/nested writable non-local entry;
- require the complete mount table fingerprint and count to equal the
  owner-bound same-Job snapshot.

Changed source hash, flags, target, type, count, table fingerprint, an
unavailable/ambiguous table or a second writable non-local entry => zero Popen.

The implementation MUST NOT stat, walk, read from or intentionally activate the
autofs target merely to prove safety.

RISK_11:
Even with the exact pre-Popen row/table binding, autofs may activate remote or
shared writable storage after launch. That storage can contain production or
shared data and R008 provides no after-launch mount namespace or write
isolation. Selecting A1 explicitly accepts that risk.
NO_SHARED_WRITABLE_MOUNTS_PROVEN=false.

## 4. Review-sequence decision

### B0 - retain FULL-before-T1

B0 leaves the current FULL gate unchanged. Given current Standards closure
requirements, the route remains blocked. PRODUCT_T1 stays DENY.

### B1 - exact TARGETED execution qualification, then T1, then fresh FULL

B1 changes sequencing only. It does not weaken the meaning of FULL.

After R008 design PASS, explicit owner option/risk selection and a separate A
implementation Head, B and C must independently review the same exact frozen
runnable snapshot.

Each pre-T1 Review MUST be a native COMMENT Review bound to exact commit_id and
must state all of:
REVIEW_SCOPE: TARGETED
REVIEW_LEVEL: TARGETED_REVIEW_PASS
VERDICT: PASS
EVIDENCE_STATUS: SUFFICIENT
EVIDENCE_SCOPE_QUALIFIER: SUFFICIENT_FOR_T1_EXECUTION_QUALIFICATION_ONLY
INTEGRATION_STATUS: NOT_TESTED
T1_EXECUTION_QUALIFICATION: PASS
ROLE_FULL_SCOPE_PASS: NOT_ISSUED
FULL_CODE_REVIEW_PASS: NOT_ISSUED
PRODUCT_T1: NOT_RUN

No in-scope P0/P1/P2 may remain.

### 4.1 Fixed pre-T1 REVIEW_TARGET

T1_EXECUTION_QUALIFICATION MUST cover the complete reachable admission and
original-child critical path on the exact implementation Head, not an unrelated
module or label. At minimum it includes:
- tracked workflow/T1 entry and source bundle loader;
- G05 receipt and fresh checkout re-admission;
- exact GitHub Run AND Job runtime identity;
- R008 design-choice parser, targeted-review parser and owner execution grant;
- durable job/envelope and per-command nonce state plus old owner.lock/UNKNOWN;
- WorkspaceService shared invoke_exec permission path;
- host OS/image/source, closed bootstrap env, SSH socket metadata and mount
  oracle;
- Go/Pipenv/CPython selected source, loader/import closure and recipe binding;
- NativeRunner final fresh rechecks and Popen boundary;
- Worker/DirectChildOwner timeout/cancel/output/ambiguous-spawn semantics;
- Direct/REST/official MCP status/permission path needed by later integration;
- adjacent lawful File/Git behavior;
- every reachable helper/import used by the path above.

Reviewers must apply R03-R08 to this target: legal positive, illegal rejection,
boundary/expiry/replay, cancellation/ambiguous failure, independent negative
counterexamples, exact source identity and original Job evidence. This is
complete pre-T1 critical-path TARGETED review, not unrelated whole-repository
FULL review.

## 5. Owner design choice is a separate immutable decision

After B/C PASS this exact R008 design, the owner must publish one direct,
unedited GitHub PR comment:

R008_OWNER_DESIGN_CHOICE_V1

Its canonical payload MUST bind:
- repo/pr;
- exact R008_DESIGN_BLOB;
- exact B and C R008 design Review node IDs;
- host_option exactly A0 or A1;
- review_sequence_option exactly B0 or B1;
- risk_acceptance:
  - A0 => R008_A0_NO_NEW_HOST_RISK_ACCEPTANCE;
  - A1 => R008_A1_R006_RISK1_9_PLUS_RISK10_RISK11_ACCEPTED;
- created_at == updated_at, direct OWNER human identity.

If later executable authority still depends on the previously accepted R006
risk 1-9, that acceptance must be independently bound by the executable grant;
the A0 marker above must never be misread as creating or replacing it.

This design-choice comment is NOT executable authority. A may implement only
the selected options on a new Head. Any option/risk mismatch is DENY.

## 6. Exact single-Job PRODUCT_T1 envelope

If and only if B1 is selected and both exact-Head TARGETED code Reviews PASS,
a separately user-authorized disposable GitHub-hosted macOS 15 ARM64 Job may
enter PREEXEC_HOLD. Starting this hold Job authorizes only reviewed safe
qualification and exact identity publication; it does not authorize a product
child.

The hold Job obtains its immutable GitHub Job ID from the GitHub Actions Jobs
API over direct TLS with no ambient proxy or credential header, publishes only
sanitized run/job/host fingerprints, and remains before the product Popen
boundary. The later direct OWNER execution comment is created only after this
Job ID and host snapshot exist. A bounded service-owned GitHub API fetch may
retrieve that exact comment while the same Job is still in_progress. Timeout,
Job completion, rerun or changed run_attempt before grant => DENY; there is no
automatic rerun or grant carry-forward.

The trusted runtime MUST independently authenticate and bind:
- repo/pr/base/head/tree/Manifest;
- workflow id/path/ref and event;
- run_id and run_attempt;
- immutable GitHub Job ID;
- logical job name;
- Job status=in_progress and exact Head;
- image/version/build and reviewed selected-source identity;
- full same-Job host snapshot including SSH socket metadata hash and full mount
  table fingerprint;
- R008 design Blob;
- R008 design-choice comment id/digest and selected A/B options;
- B/C R008 design Review node IDs;
- B/C exact implementation TARGETED T1 qualification Review node IDs.

The Job ID is mandatory execution identity. A sibling Job, different job name,
different workflow, rerun/new attempt, cloned private ledger or stale Job ID
must fail before any Popen even if it possesses the same nonce/comment.

A safe T0 multi-job simulation MUST use two different verified Job identities
and two independent private journals against the same candidate grant and show:
exactly the owner-bound Job may proceed to a fake-Popen boundary; the sibling
has zero Popen. Local O_EXCL is not used as cross-Job uniqueness proof.

## 7. One Job means six separately one-use original command grants

"One PRODUCT_T1 attempt" now means ONE exact disposable GitHub Job envelope,
not one child and not an unlimited session.

The owner execution comment may contain one canonical six-row command manifest.
Each row MUST have its own unique 64-hex nonce and exact:
workspace,cwd,runner,requested_argv_sha256,effective_argv_sha256,
product_recipe_fingerprint,timeout_seconds.

The six rows are exactly:
1. py-direct/direct: python -m pytest -q
2. py-direct/direct: python -m compileall -q ./src
3. py-pipenv/pipenv: requested python -m pytest -q;
   effective pipenv run python -m pytest -q
4. go-project/direct: go test ./...
5. go-project/direct: go vet ./...
6. go-project/direct: go build -o bin/app ./cmd/app

Every row is independently consumed BEFORE reservation/Worker/Popen and cannot
be reused. The job-envelope identity and all common bindings from section 6 are
included in every durable row.

If any invocation has:
- pre-Popen identity/source/host drift;
- ambiguous Popen/child ownership;
- timeout/cancel/lost ACK with uncertain child;
- old-state UNKNOWN/quarantine/reaper fault;
then the job envelope is latched unavailable and all remaining unused command
rows are VOID. Restart/rerun cannot redeem them. A fresh review/grant is needed.

Completion of only one or five rows never proves six-command PRODUCT_T1 PASS.
All unexecuted rows remain NOT_RUN.

## 8. Separate integration grant after clean six-command evidence

Six-command PRODUCT_T1 success does not authorize or prove integration.

If all six complete with original exit/output evidence and no ambiguous state,
the owner may later issue a distinct R008_INTEGRATION_T1_GRANT for the same
frozen implementation snapshot and an independently qualified same-instance
integration envelope.

That later grant must explicitly bind each native execution request used by
Direct/REST/official MCP with its own nonce/command row, plus the lawful File/Git
checks. It is outside the six-command grant and remains NOT_AUTHORIZED until
explicitly issued.

B/C FULL reviews occur only after the separately authorized native command and
integration evidence that their FULL contract requires. TARGETED T1
qualification never inherits or promotes to FULL. A evaluates R10 only after
both independent ROLE_FULL_SCOPE_PASS reviews on the then-applicable snapshot.

## 9. Future owner execution grant fields

R008_OWNER_PRODUCT_T1_GRANT_V1 must be a direct unedited OWNER GitHub comment
and MUST include, at minimum:

authorization=R008_PRODUCT_T1_SIX_COMMAND_JOB
repo,pr,base_sha,head_sha,head_tree,manifest_sha256
r008_design_blob
r008_design_choice_comment_id and digest
host_option,review_sequence_option,risk_acceptance
b_r008_design_review_id,c_r008_design_review_id
b_t1_qualification_review_id,c_t1_qualification_review_id
t1_review_target_id,t1_contract_scope_id
workflow_id,workflow_path,workflow_ref
github_run_id,github_run_attempt,github_job_id,github_job_name
image_os,image_version,os_build
selected_host_source_fingerprint,runner_profile_fingerprint
ssh_socket_path_hash,ssh_socket_metadata_fingerprint
mount_table_fingerprint,mount_count
six exact command rows and six unique nonces
expires_at

The canonical parser, durable attempt identity, trusted bootstrap,
WorkspaceService shared gate and final native boundary must all reject:
- old R006-only grant/risk marker;
- old R007 design Blob;
- missing/wrong R008 design choice;
- A0 grant under A1 code or B0 grant under B1 code;
- missing RISK_10/RISK_11 acceptance when A1 is selected;
- unrelated/missing/old role Review IDs, wrong REVIEW_SCOPE/REVIEW_LEVEL,
  wrong t1_review_target_id or t1_contract_scope_id;
- Base/Head/Tree/Manifest/source/recipe drift;
- wrong run/attempt/Job/workflow;
- SSH socket or mount snapshot drift;
- duplicate nonce, expired/edited owner comment or lost-ACK replay;
with zero Popen.

## 10. Required safe T0 before any real T1

Implementation of selected A1/B1, if ever authorized, must first produce safe
T0/RED-to-GREEN evidence for:
- closed bootstrap env: GIT_ASKPASS, SSH_ASKPASS, KRB5CCNAME, token/cloud
  selector or any extra key => deny;
- SSH socket missing/symlink/wrong uid/permissive mode/ancestor drift/path hash
  drift => deny; metadata-only valid unchanged case; never connect/query;
- autofs source hash/flags/type/target/count/full-table drift, nested/second
  writable non-local mount and unavailable table => deny;
- R006-only grant, R007 Blob, wrong option, missing RISK_10/11, edited owner
  decision, wrong design/code Review IDs => deny;
- sibling Job with separate private journal, wrong Job name/id/workflow,
  run_attempt replay => deny;
- six command rows: wrong argv/cwd/runner/recipe, duplicate nonce, partial job,
  ambiguous child => deny/void remaining rows;
- old owner.lock/UNKNOWN/quarantine/corrupt state, cancellation before/after
  consume, lost ACK and service restart;
- Direct/REST/MCP competing callers and truthful status;
- adjacent lawful Git/File;
- zero real Popen for every negative.

No T0 fake-Popen result is real PRODUCT_T1 or integration.

## 11. Truthful claims under A1/B1

Even after future approval/implementation, the following remain FALSE:
FULL_BOOT_IMAGE_ATTESTED
ACTUAL_LOADED_GRAPH_PROVEN
PHYSICAL_WHOLE_TREE_CPU_MEMORY_ENFORCEMENT_PROVEN
NO_PRODUCTION_CREDENTIALS_PROVEN
NO_AMBIENT_SSH_AGENT_PROVEN
NO_SHARED_WRITABLE_MOUNTS_PROVEN
OFFLINE_ONLY

R006 risks 1-9 remain. If A1 is selected, RISK_10 and RISK_11 are additive.
PR102 standalone SOURCE_TOOLCHAIN_T1 remains separate and unchanged.

## 12. Current evidence and gates

At creation of this R008 proposal:
- parent reviewed R007 Head 2c193630c2282536df4987d6da7996de31917536:
  C TARGETED design FAIL, B TARGETED design BLOCKED;
- pre-design source Head 958bd9350ca8b651c173006ead39ed0662ced766
  adds only sanitized mount source-hash/flags T0 evidence;
- macOS Run 42469201680 / Job 128695758515 confirms the exact row identity in
  section 2 and remains FAIL-CLOSED under strict R006;
- PRODUCT_T1=NOT_RUN;
- positive A1/B1 implementation=NOT_IMPLEMENTED;
- integration=NOT_TESTED;
- merge/deploy/release=NOT_AUTHORIZED.

B/C must independently decide whether this design closes their prior design
findings. Only after two PASS results may the owner be asked to select A0/A1
and B0/B1 and, if A1, explicitly accept RISK_10/RISK_11.

Until then:
R008_DESIGN_STATUS=PROPOSED_NOT_EFFECTIVE
HOST_OPTION=UNDECIDED
REVIEW_SEQUENCE_OPTION=UNDECIDED
PRODUCT_T1=DENY
NEXT_ROLE=B/C_TARGETED_DESIGN_REVIEW_AFTER_A_FREEZE
