# D4 R003 - trusted-host PRODUCT_T1 executable-design contract (PROPOSED; fail-closed)

TASK_ID: MULTI-EXEC-LBE-FIVE-DAY-CANDIDATE-20261105
MILESTONE_ID: LBE-FIVE-DAY-CORE-PRODUCT-CANDIDATE
CONTRACT_ID: MWE-LBE-TRUSTED-PRODUCT-T1-PROFILE-R003
DESIGN_ROUND: D4-DESIGN-002 (new design review required)
STATUS: PROPOSED_NOT_EFFECTIVE / NO_EXECUTION_AUTHORITY / SAFE_SOURCE_AND_T0_ONLY
REVIEW_SCOPE: TARGETED DESIGN, not the unfrozen PR114 r006 product/code FULL
RULESET_ID: ICR-V2.0
HANDOFF_PROTOCOL_ID: GHRH-2.0
EVIDENCE_PROFILE_ID: ETP-V2.0

## 1. Fixed authority, change record and precedence (normative proposal)

This document is a NEW proposed test contract, NOT an operative amendment to D0/F1 or
PR102. It addresses D4-DESIGN-001 B114-D4-P2-01..04/P3-01 and C-SPEC-01..04
on PR114 prior Head b3d828d683ac6c1faa62ab25c033e8887f7ea597.
It does not edit the historical R002 GitBlob a31e4517bbd4d2c3d2d0f4370619e3043cd973bb
or old B/C verdicts. Current PR114 r006 stays DEVELOPING until independently frozen.

Authority inputs (read the immutable original versions, not summaries):
- PR98 product design r002, GitBlob 9e6622401b198138039c692efe91fba1a8d06891;
- PR102 SOURCE_TOOLCHAIN_T1 Gate B r002, GitBlob 7db3b77aadca8b0c284e28fa5ee64e315e9275d2;
- PR113 D1 trusted product proposal r001, GitBlob 3b9aa056f67008aa825da5c95b6ca71b0b25a84d;
- operative D0 6e25904aed9a62bb0f472b732021c2a7ca3b3bb0,
  F1 76baeb820c6f8a9b067e45e2dcc42e76453fe5b1,
  Phase1 b3f2383f292a59fd234269389e5338cd50e334a2,
  G05 76c1c2b8a7947e0b305d55c5f550ab59c638b6d1,
  R004 2ffe5341288e428be5ee5d0fa8d52aea3e9efc93 (limited 36 Wheel+RECORD).
- ICR-V2.0/GHRH-2.0/ETP-V2.0 apply only to eligible new rounds after
  their separate activation criteria; A does not assert cross-Project activation.

The DEFAULT remains the existing PR102 Gate B and operative F1 denial. Merely
renaming a source-toolchain T1 job or obtaining a syntactically valid D4 T0
packet does NOT waive any existing requirement. The following is the ONLY
proposed future narrow exception, requiring new independent B/C design review,
exact owner approval and separately reviewed runnable code BEFORE becoming
effective:

| Target | Precontact egress obligation | Source/loader and authority | Current result |
| --- | --- | --- | --- |
| Standalone SOURCE_TOOLCHAIN_T1 / PR102 | Strict OFFLINE_ONLY deny-all attached to child and descendants, with independently observed precontact denial canary, or separately newly owner-authorized enforced BOUNDED_EGRESS | PR102 source, loaded-source, Gate A/B and test identity | NOT_RUN; R003 does not change it |
| Ordinary schema-v1 / Legacy or old F1 | Existing F1 / old state safety; no implicit v2 migration | No D4 exception | DENY |
| schema-v2 dry_run preview | Current canonical scope/argv/source checks only | Nonoperative; no positive grant | Preview possible, apply DENY |
| PRODUCT_T1 without fully effective R003 exception | Existing PR102 product-origin extended Gate B + public F1/Go-Pipenv native deny | No owner consent or complete actual identity | DENY before Popen |
| PRODUCT_T1 with newly B/C-reviewed and owner-approved exact trusted-host R003 exception AND separately reviewed real launch code | Deliberately EGRESS_POSSIBLE; NOT OFFLINE_ONLY; no egress guarantee. This changes only the named PRODUCT test requirement AFTER approval, never the SOURCE claim. | All R003 actual runner/source/credential/resource/first-party gates and exact owner risk consent still mandatory | Eligible only after ALL gates, otherwise DENY |
| Public product positive apply outside the separately approved test fixture | No D4 implicit elevation | Separate operative F1/D0 exception, independently reviewed production code/authorization | DENY |

A D4 design PASS alone would NOT enact the exception, allow real Mac T1,
extend PR102 standalone permission, release code or approve a user Mac/Tunnel,
T2/T3, merge or deployment. Any conflict with currently operative F1 or
PR102 MUST resolve to DENY until the separate exact amendment is approved.

## 2. Owner-signable, exact bounded decision (not yet given)

The future owner must explicitly approve ALL of:
(a) this exact R003 GitBlob and B/C-reviewed design round;
(b) a particular new runnable REPO, BASE_SHA, HEAD_SHA, HEAD_TREE, manifest,
    complete diff and effective contract/implementation versions;
(c) the one specific disposable GitHub-hosted macOS 15 ARM64 job and immutable
    image/provider identity, real G05 record, checked fixtures and source closure;
(d) the exact runner-bound commands, selected Workspace/cwd/runner and budget
    in sections 3 and 6, including a resource-domain failure rule;
(e) accepting outbound network/same-UID filesystem/process exposure even when
    all selected fixtures INTEND no fetch, possible surviving original children
    and descendants after timeout/crash, lost-ACK/manual-retry duplicate effects,
    pathname last-moment TOCTOU race, and no F3/rollback/descendant cleanup;
(f) no production secrets, user Mac/Tunnel or shared writable mounts,
    no automatic retry, unknown PID/PGID signals, killpg or unsafe process killing.

Acceptance of the PR98 lighter product *direction* or prior PR102 Gate A risk
record is NOT this new network-capable D4 PRODUCT_T1 authorization.
Owner approval must be associated with a concrete exact reviewed version;
a developer PR comment is at most a labeled transcription, not a native
GitHub-owner signature, independent reviewer conclusion or runtime grant.
If any tuple element changes, stop and obtain a new decision.

## 3. First-party fixture and command-contract matrix (exact proposed T0)

Only first-party disposable, privately staged, no-follow, owner-controlled
Workspace directories may be selected. Paths below are WORKSPACE-RELATIVE
inside a fresh predeclared private runner root, NEVER host paths:
py-direct (Direct), py-pipenv (Pipenv with exact Pipfile and private .venv),
go-project (Direct). The py-direct/src directory must be precreated and
contain only pinned project .py inputs, owner-controlled 0700/0755 directories
and no symlink/hardlink/pointer/source-shadow path components. The only
compileall output is private py-direct/src/__pycache__ within that tree;
verify no outside-fixture writes and no other selected sys.path directory
is walked. Reject missing/unsafe src or redirection. Do not rely on
compileall's default selection of sys.path.

| Workspace / runner | Public requested_argv (exact) | Internal effective_argv (exact) | Required cwd / output |
| --- | --- | --- | --- |
| py-direct / direct | python -m pytest -q | same | py-direct |
| py-direct / direct | python -m compileall -q ./src | same | py-direct; checked ./src only |
| py-pipenv / pipenv | python -m pytest -q | pipenv run python -m pytest -q | py-pipenv, exact Pipfile/lock/.venv |
| go-project / direct | go test ./... | same | go-project |
| go-project / direct | go vet ./... | same | go-project |
| go-project / direct | go build -o bin/app ./cmd/app | same | go-project; precreated safe bin output parent |

The T0 proposed_commands field contains only these SIX internal effective
vectors, in the table order, and never confers request/runner selection.
The ACTUAL future shared service must independently compare the requested
argv, selected runner, effective argv, canonical workspace/cwd, source
inventory, output parent and policy; a client may NOT request pipenv as
the direct entrypoint and may NOT select runner by env/header/REST/MCP
bypass. Go -o=bin/app may be separately tested only after an exact
reviewed allowlist fixture; it is not an additional command in this packet.
No go run, shell, python -c, pipenv install, arbitrary script, -toolexec,
-exec, -vettool, GOFLAGS/GOCACHEPROG hook, symlink output escape, or hidden
compileall extra flag/path. py-direct/src must be the only compileall path
operand, no unspecified zero-operand compileall. Default Python site
startup may load pre-pinned inputs, but cannot expand the compileall walk.
A no-fetch test-input selection is NOT an OS no-egress control.

## 4. Non-client-mintable trusted authorization and exact pre-Popen order

Before the FIRST nonapproved interpreter, Pipenv, Go compiler or child
process/import, a trusted bootstrap (not the REST/MCP payload, a config
field, env flag, public header, forged dataclass, or a stand-alone CLI)
must prove this approved first-party job/run identity and assemble an
immutable, single-use, run-bound authorization in a reviewable internal
service construction path. It must carry immutable identifiers:
- reviewer/owner-approved R003 GitBlob, design Review URLs and approval
  artifact identity; run/job ID; immutable REPO/Base/Head/Tree/Manifest;
- exact runner OS/arch/image and provisioner identity; no checkout
  credential persistence/tokens/secret env or writable shared mounts;
- every selected first-party fixture byte/mode/owner/cwd and executable
  path plus Go toolchain/compiler/linker/stdlib/module/loader graph,
  Pipenv executable/shebang/CPython/.venv/site/seed/.pth/RECORD-unlisted
  import closure and generated/runtime inputs, all actual loaded sources;
- the selected request->effective vector, closed environment, Workspace
  scope, output parent and exact resources/network risk decision.

The bootstrap must be independently inspectable and must deny, not mint a
grant, when any runtime/image/source identity is absent or untestable.
An immutable token stored in an untrusted client request, T0 packet or
Python env is NOT authority. The actual positive permission is only
evaluated inside WorkspaceService.invoke_exec after prior v1 private
owner.lock/ExecStateStore existing-only healthy scan and v2 scope checks.
After validation but immediately before Popen, NativeLauncher re-checks
source/loader/environment/approval/runner/budget/fixture identity. If any
identity/mode/mtime/loader resolution drifts between prep and launch,
fail closed. Trust in the local same-UID operator means pathname
Popen TOCTOU cannot be claimed race-free without an independently
reviewed FD-exec or protected immutable-mount mechanism. Missing an
acceptable mechanism or explicit owner acceptance of residual race:
STOP. No separate public REST/MCP positive or test-only bypass.

Mandatory zero-Popen denials: missing/forged grant, wrong Head/Tree,
unapproved owner risk, wrong/shared runner, persisted credentials,
unsafe mount/proxy, missing source or .pth, GOFLAGS=-toolexec=untrusted,
GOCACHEPROG/toolhook, alternate PATH/GOROOT, .venv redirect-file or
symlink/PIPENV_PYTHON, missing old root/owner.lock, UNKNOWN/quarantine,
unsafe -o or compileall src, changed input, incorrect runner/effective
argv, unknown admission/lost owner. Preserve old v1/Git/File semantics.

## 5. Identity and runner observation, not declarations

Before foreign code, record exact G05 checkout Head AND Git Tree, complete
Manifest/hash/mode, Base/effective PR diff, synthetic Merge separately if
different, and all generated/ignored/untracked participating inputs.
Observe actual job image ID/digest/host provider/OS=macOS 15/arch=ARM64,
runner provisioning and root/permission facts independently of a claimed
JSON image_sha256. GitHub-hosted label macos-15 alone is NOT a verified
image digest or proof of no secrets. Require checked-out source with
persist-credentials:false; inspect effective token exposure, PATH,
credential helpers, environment, proxies and writable mounts BEFORE
third-party import/Go/Pipenv. No GITHUB_TOKEN or production secret passed
to untrusted child. If an actual image digest or non-shared credential/
mount boundary cannot be verified, stop BEFORE foreign Popen.

Do not treat archival SHA of Go/Pipenv, selected go/bin/go/compile/link
bytes, pip RECORD-only checks or a synthetic D4 T0 declaration as the
actual loaded/compiler/stdlib/module/venv/site import closure.
Require a trusted stdlib-only preflight nofollow walk and original
loaded-source-selection evidence, current absolute executable/shebang/
interpreter selection, fully pinned Go stdlib/toolchain/modules incl
generated source, Pipenv virtualenv seed/.pth/site and import shadow.
Construct a fresh closed Go/Pipenv effective child env (not os.environ
copy), rejecting inherited or resulting selector injection; assert
GOPROXY=off / PIP_NO_INDEX=1 only as hints, never as egress security.
Do not run unqualified code to discover its identity retroactively.
When pre-exec loader identity cannot be established, stop. A full
semantics proof of arbitrary trusted code is NOT claimed.

## 6. Exact limits and failure/uncertainty policy

The ONLY proposed numeric tuple for a future owner decision is:
- job wall <=1200s, one PRODUCT_T1 job concurrently;
- original child requested timeout <=120s, bounded public Worker
  timeout <=300s; 1 active ORIGINAL per Workspace / 4 per service;
- CPU budget <=2000 millicores and RAM <=4096 MiB;
- raw stdout/stderr capture <=48000 BYTES per stream, returned redacted
  text <=48000 CHARACTERS per stream; bounded drainer and EOF grace.

The T0 packet MUST require this exact tuple, not a maximum allowing
8000m CPU or 16384MiB RAM. These NUMBERS do not create OS enforcement.
Before native execution the job must show an actually attached, auditable
CPU/memory limit for all relevant child/descendant resource consumption
in the disposable execution domain; verified cgroup/VM/equivalent
container policy and its actual association, not env vars, CI timeouts,
Go -p, process niceness or after-the-fact sampling. If no such verified
macOS resource policy is technically available, STOP and report
PRODUCT_T1=NOT_RUN / EVIDENCE_STATUS=INSUFFICIENT; a weaker future
profile requires NEW reviewed contract and separate owner risk approval.
A macOS runner's teardown is NOT proof that a process tree was cleaned.

Time and process semantics are independent of CPU/memory caps:
original child exit observed => actual exit_code, cleanup_not_proven;
timeout with no observed exit => timed_out=true, exit_code=null,
process_may_be_running=true, output_complete=false unless final EOF
was observed, keep original-child slot and owner/reaper as appropriate;
disconnect => NO assured ACK, no retry or unquarantine; lost ACK,
ambiguous Popen, reader/owner failure or crash => stop NEW admission
and report uncertainty, never retry, signal unknown PID/PGID, killpg
or assert rollback/full descendant cleanup. An original 120s timeout
is an observation deadline, NOT proof of process death; descendants
can survive beyond it and affect host/network. Whole-tree resource
enforcer may bound consumptions only when independently proven; it
does not make process state/recovery certain.
On budget overflow or missing enforcer witness: refuse new launches,
classify failure truthfully, do not invent a safe kill; if OS domain
reclamation cannot be proven, retain uncertainty/latch and let
disposable runner disposal be a separate observed event.
Restart does not prove prior best-effort children gone; manual
resubmission can duplicate effects and this risk needs owner approval.

## 7. Independent verification matrix and release boundary

Each role must independently review current fixed R003 GitBlob and new
Base/Head/Tree, PR98/PR102/operative constraints, actual affected code,
original CI/Job/Log and denial call chain. At minimum independently
design/run safe T0 where applicable:
1. positive six exact nonspawning fixtures plus explicit compileall
   scoped operand, pipenv requested/effective mapping, real shared
   Direct/REST/official MCP dry_run parity and no Popen;
2. negative no-arg compileall, absolute/path-traversal/src symlink,
   ignored sources/output write escape, direct-client pipenv invocation,
   stale/forged packet/contract/runner/owner/Head/source;
3. exact proposed CPU/RAM and every bound's over/under/bad-type,
   no enforcer, ambiguous child/timeout/cancel/lost ACK/status;
4. injected GOFLAGS/toolhook, .venv redirect/symlink/.pth and
   wrong interpreter/runner, old UNKNOWN, no owner.lock, v1/legacy
   no escalation and independent File/Git regression.

No real native T1 or unapproved network, Seatbelt canary, T2 process
termination or T3 shared/production experiment is authorized by these
tests. Later authorized T1 must record the real image, actual loaded
source, stdout/stderr/exit/original child state, budget enforcement and
exact actual executable same-instance Direct/REST/MCP+File/Git evidence.
A syntactic packet, T0 GREEN or B/C design PASS is not a product FULL
code review, integration PASS, R10, release or deployment.

## 8. Explicit closure and next decision

D4-DESIGN-001 B P2-01..04/C P2-01..02 and associated P3 are
candidate-remediated by this proposed normative R003 and narrowed T0
packet ONLY if both independent B/C reviewers confirm on the NEW fixed
snapshot. Implementation of actual physical Runner/resource/source
witness and a reviewed non-client-mintable NativeLauncher authorization
remains NOT_DONE; zero native authority is granted. Owner acceptance of
this exact nonisolated host/network/crash/retry risk + resource/fixture
decision is NOT_OBSERVED and must be requested separately after review.
Any failure or missing proof: NO_GO, T1 NOT_RUN. PR114 r006 code FULL,
real integration and R10 remain separate and incomplete.

INTEGRATION_STATUS: NOT_TESTED
R10_STATUS: BLOCKED
FULL_CODE_REVIEW_PASS: NOT_ISSUED
PRODUCT_T1_AUTHORIZATION_STATUS: NOT_GRANTED
F1_AND_GO_PIPENV_NATIVE_LAUNCH: DENY
NEXT_ROLE: B Standards and C Spec independent R003 DESIGN review;
then A consolidation and exact user risk/fixture decision; no T1.
