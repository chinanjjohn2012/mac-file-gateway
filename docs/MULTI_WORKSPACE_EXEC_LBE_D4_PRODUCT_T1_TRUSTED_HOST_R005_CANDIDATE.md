# D4 R005 — GitHub-hosted trusted-host PRODUCT_T1, weaker resource contract (CANDIDATE)

TASK_ID: MULTI-EXEC-LBE-FIVE-DAY-CANDIDATE-20261105
MILESTONE_ID: LBE-FIVE-DAY-CORE-PRODUCT-CANDIDATE
DESIGN_REVIEW_ROUND: D4-TRUSTED-HOST-DESIGN-004
CONTRACT_ID: MWE-LBE-D4-PRODUCT-T1-TRUSTED-HOST-R005-CANDIDATE
CONTRACT_STATUS: PROPOSED_NOT_EFFECTIVE
REVIEW_SCOPE: TARGETED_DESIGN_ONLY; NOT PR114 r006 FULL product code review
OWNER_ROUTE_SELECTION: B_GITHUB_HOSTED_WEAKER_RESOURCE_PROFILE_SELECTED_IN_CHAT_2026-11-08
OWNER_R005_EXACT_RISK_CONSENT: NOT_YET_GIVEN
OWNER_EXACT_NATIVE_JOB_APPROVAL: NOT_ATTESTED
B_R005_DESIGN: NOT_ISSUED
C_R005_DESIGN: NOT_ISSUED
AUTHORIZATION: NO_REAL_NATIVE_T1; NO_PUBLIC_POSITIVE_EXEC; NO_T2_T3
RULESET_ID: ICR-V2.0
HANDOFF_PROTOCOL_ID: GHRH-2.0
EVIDENCE_PROFILE_ID: ETP-V2.0

## 1. Decision identity, authority and non-activation

The owner replied **"B"** on 2026-11-08 to A's explicit choice between
(A) dedicated bare-metal Apple-silicon host plus strict domain and
(B) GitHub-hosted macOS trusted-host with weaker process-tree limits.
This settles **the proposed architecture direction**, NOT approval of this
as-yet-unreviewed R005 GitBlob, its precise residual-risk language, a
specific runner/image/job/source version, or a positive NativeLauncher/F1
code change. No new externally mintable execution permission exists.

Fixed sources, to be read as separate immutable authorities:
- Parent D4 R003, Blob f8556b48ab5f4af7390fb015092862a8a87768fb,
  MWE-LBE-TRUSTED-PRODUCT-T1-PROFILE-R003; targeted B/C D4-DESIGN-002
  PASS was DESIGN ONLY and did not make the contract operative.
- D4 R004 two-path decision, Blob
  4b0b50c847c0a6a2bcc7069a284d59f4fd986942, independently
  reviewed under D4-DOMAIN-DESIGN-003 on PR114 Head
  51a68840cafd2996005016ccb3600cf179f17308, Tree
  c9d1f187a794c7c63672650673c431df39e35e22.
  B Standards TARGETED_DESIGN_PASS (no runnable qualification);
  C Spec BLOCKED (two P2 qualification blockers).
- PR98 lightweight product r002 Blob 9e6622401b198138039c692efe91fba1a8d06891
  remains product DESIGN, NOT a current operative F1 exception.
- PR102 SOURCE_TOOLCHAIN_T1 Gate B r002 Blob
  7db3b77aadca8b0c284e28fa5ee64e315e9275d2 remains distinct:
  standalone SOURCE_TOOLCHAIN_T1 **OFFLINE_ONLY** precontact deny-all
  or separately approved enforceable BOUNDED_EGRESS requirement is not
  relaxed, inherited, or certified by PRODUCT_T1 R005.
- Operative D0 6e25904aed9a62bb0f472b732021c2a7ca3b3bb0,
  F1 76baeb820c6f8a9b067e45e2dcc42e76453fe5b1,
  Phase1 b3f2383f292a59fd234269389e5338cd50e334a2,
  G05 76c1c2b8a7947e0b305d55c5f550ab59c638b6d1
  and limited 36 locked Wheels / installed RECORD-listed source R004
  2ffe5341288e428be5ee5d0fa8d52aea3e9efc93 are unchanged.
  (The last R004 is the dependency-evidence profile, NOT D4 R004.)
- ICR-V2.0, GHRH-2.0 and ETP-V2.0 apply as conservative, named
  review criteria; global three-Project formal activation is
  NOT_INDEPENDENTLY_ATTESTED.

The current PR114 r006 **unfrozen** product has real source/Worker
preflight implementation, but `WorkspaceService.invoke_exec(dry_run=False)`
still fails closed with `exec_cleanup_proof_required` and
`D4MacOSRunnerLaunchBoundary.launch` cannot start a native child.
This document changes no runtime code or accepted Test Profile today.

## 2. Precisely changed R003 fields — no silent waiver

| R003 clause / requirement | Proposed R005 PRODUCT_T1-only change | State |
| --- | --- | --- |
| §2(c), §5 provider | RETAIN GitHub-hosted **macOS 15 ARM64**; request exact `runs-on: macos-15` and directly observe `arm64`, OS build, provider/runner image identity in one disposable job | Still must verify real evidence |
| §6 **original + all descendants CPU <=2000m** | REMOVE this mandatory hard OS-domain CPU cap **for prospective R005 PRODUCT_T1 only**. No alternate number is claimed; any process or descendant may consume CPU up to host capacity | Explicitly WEAKER, not R003 compliant |
| §6 **original + all descendants RAM <=4096 MiB** | REMOVE this mandatory hard OS-domain RAM cap **for prospective R005 PRODUCT_T1 only**. Host runner RAM is NOT a memory-controller promise; original/descendants may exhaust host RAM | Explicitly WEAKER, not R003 compliant |
| §6 mandatory physically attached whole-tree OS resource domain | NOT REQUIRED under proposed R005 PRODUCT_T1. CPU/RAM observation, process rlimits, `ulimit`, watchdog, Go `-p` and GitHub job timeout are diagnostics/operational limits only, NEVER independent containment evidence | Requires new B/C + owner approval |
| §2(c), §6 job/child/Worker time | RETAIN one job <=1200 seconds; original child requested timeout <=120 seconds, Worker timeout <=300 seconds | No forced kill/cleanup claim |
| §6 concurrency | RETAIN one original child per Workspace, <=4 originals per service, one PRODUCT_T1 job at a time. Detached descendants are NOT included in these original-child counters | Parent/descendant risk explicit |
| §6 output | RETAIN raw stdout and stderr capture <=48000 BYTES EACH, returned redacted text <=48000 CHARACTERS EACH, bounded drainer/EOF grace | No unlimited pipes |
| §3 six vectors | RETAIN exactly the six fixed Python Direct/Pipenv and Go test/vet/build vectors and cwd/runner/output path constraints | No arbitrary shell/Go invocation |
| §4 trust and PRE-Popen | RETAIN actual same-WorkspaceService permission gate, owner.lock/old ExecStateStore, one-use source & runner checks, closed environment, no client-mintable capability | Missing proof => DENY |
| §5 actual loaded sources/image | RETAIN need to demonstrate exact actual Go compiler/linker/stdlib/module and CPython/Pipenv/venv/site/seed/.pth/generated inputs and trusted OS/image identity BEFORE foreign code | No exemption granted here |
| §6 uncertainty/cleanup | RETAIN truthful original-child status, no automatic retry/UNKNOWN reset, no unqualified process kill/killpg, no rollback/full-tree cleanup claim | Strong negative gate |
| §7 verification and R10 | RETAIN independent B/C product-code reviews, exact-head native evidence, same-instance Direct/REST/official MCP + Git/File integration, separate R10 | No implied PASS |

**Strong separation:** This proposal cannot be used to certify R003-STRICT
physical limits, PR102 SOURCE_TOOLCHAIN_T1 OFFLINE_ONLY, F3 complete
containment, third-party source provenance, whole-tree cleanup, any T2/T3,
or production deployment. If code or tests label the new profile as
"R003 resource compliant", "cpu_millis_enforced" or "ram_mib_enforced",
B and C must reject the claim. Do not silently reinterpret an older
R003 packet or resource receipt as R005 evidence.

## 3. Explicit operator-facing residual risks for exact R005 consent

The proposed weaker test grants the inspected first-party Go/Pipenv/Python
process ordinary **same-UID host privileges on a GitHub-hosted ephemeral
macOS runner**; it is NOT an application sandbox or network boundary.
Owner acceptance MUST cover all of the following, attached to this exact
future reviewed R005 Blob and runnable job:

1. **CPU/memory exhaustion**: no R005 hard process-tree CPU/RAM cap;
   child or detached descendant can exhaust the allocated host VM,
   stall the runner, and affect job availability. GitHub runner's
   advertised vCPU/RAM figures are host specifications only.
2. **Network**: arbitrary code and descendants may attempt outbound
   traffic; `GOPROXY=off` and `PIP_NO_INDEX=1` are config hints
   and do NOT make the test OFFLINE_ONLY or bounded-egress. No actual
   exfiltration proof/guarantee is inferred from no-fetch fixture intent.
3. **Same-UID files/processes**: code may access any runner-local
   files/processes that the job's user could access, even beyond the
   selected Workspace, unless separately enforced by the host. Exclude
   all production secrets, checkout credentials and writable shared mounts.
4. **Surviving original and descendants**: a 120-second request timeout,
   cancelled HTTP/MCP waiter, direct-child exit or runner termination
   is not proof of descendant cleanup or command rollback. No F3 or
   process-tree lifetime guarantee is given.
5. **Lost response / duplicate effects**: missing ACK, Gateway crash,
   owner failure or manual restart/resubmission can produce duplicate
   non-idempotent side effects. No automatic replay or unknown PID/PGID
   signals. Old v1 UNKNOWN/quarantine cannot be cleared.
6. **Pathname TOCTOU**: validated files and hashed interpreters can be
   changed by the trusted local user before OS pathname spawn. Unless
   an independently reviewed FD-exec/immutable-mount mechanism exists,
   disclose residual race; do not assert race-free executable selection.
7. **Image/supply-chain gaps**: a GitHub-hosted image label/runner metadata
   is NOT a cryptographic digest of a complete booted image. Go and Pipenv
   installed RECORD-only or synthetic Mach-O headers are NOT the entire
   actual import/build/load source closure. No unreviewed fallback.

The absence of whole-tree CPU/RAM caps is the **sole immediately proposed
security weakening** selected by Route B. If actual GitHub-hosted image
content digest, source closure, credential controls or required loader
identity cannot be proven, they remain a **separate blocker**, NOT
implicitly waived by this route selection. B/C may propose a specific
additional image-provenance fallback for owner consideration, but R005
does not approve it. No high-risk load/exhaustion/probe is requested.

## 4. Exact intended disposable host, source and command contract

Candidate provider: standard `macos-15` GitHub-hosted public-repository
arm64 runner only. `macos-latest`, Intel, self-hosted, user Mac,
Mac File Gateway Tunnel, EC2 Mac, Docker/VM on an unrelated host and
macOS 26 are NOT equivalent. The actual job must verify:
- GitHub Actions `repository`, `run_id`, `run_attempt`, trigger,
  `head_sha`, Base, Git HEAD and Tree, synthetic Merge Head/Tree and
  applicable base diff, G05 original admission before code/import;
- `uname -m=arm64`, actual `sw_vers` macOS major=15, `ImageOS`,
  `ImageVersion`, current immutable GitHub image release ref where
  available, exact action SHAs/steps, runner-name metadata and
  platform image content provenance. A mutable label alone fails;
- scoped `actions/checkout` with `persist-credentials:false`,
  no production tokens/SSH keys/proxies/cloud credentials, no
  unreviewed hidden/untracked/ignored importable inputs, no shared
  writable mounts; actual clean env and no forged selectors;
- all source blobs and selected launcher/compiled/imported source
  identities and source-shadow risk independently inspected before
  child entry and immediately before Popen; if only source archive
  hashes or limited RECORD hashes are available, fail closed;
- an **explicitly reviewed** single-use trusted bootstrap-bound grant
  containing current approval version, run identity, code identity,
  host/image/source/cwd/argv/scope/limits; no REST header, MCP
  attribute, environment flag, client dataclass or test monkeypatch
  may grant it.

Exactly six requested/effective commands, in order:

| Workspace | Runner | Requested argv | Effective argv |
| --- | --- | --- | --- |
| `py-direct` | Direct | `python -m pytest -q` | same |
| `py-direct` | Direct | `python -m compileall -q ./src` | same, ./src only |
| `py-pipenv` | Pipenv | `python -m pytest -q` | `pipenv run python -m pytest -q` |
| `go-project` | Direct | `go test ./...` | same |
| `go-project` | Direct | `go vet ./...` | same |
| `go-project` | Direct | `go build -o bin/app ./cmd/app` | same, prequalified private bin |

Reject extra flags, `go run`, direct client-selected Pipenv,
Go toolhook/alternate compiler/CGO, stale `go.mod`, dangerous `-o`,
unqualified `src`, redirect-file/symlink `.venv`, external
interpreter, inherited `DYLD_*` or Go/Python selector env, unexpected
`.pth`/site, missing private root or changed original file/inode/mode.
Positive fixture scripts must be bounded and first-party only; no
hostile resource load, spawn tree, real network/canary, or destructive
process termination is necessary to demonstrate ordinary success.

## 5. Approval order, operative gate and truthful results

Before A implements/enables the **actual** NativeLauncher/F1 exception:
- independent B **and** C TARGETED design review of this exact immutable
  R005 GitBlob/contract against R003/PR98/PR102/D0/F1 and the full
  application/security test contract; independently resolve all
  P0-P2 and decide whether a native-implementable proposal exists;
- owner approves **the reviewed R005 exact version**, explicitly the
  seven residual risks in §3 and the limited PRODUCT_T1 exception,
  not only architecture Route B. If B/C requires any revised wording
  or further weakened image/source guarantee, create R006 and
  obtain new independent review and owner acceptance;
- implement approved narrow code only under a new development Head,
  preserve original F1 DENY until an **independently reviewed** exact
  positive gate in `WorkspaceService.invoke_exec` (direct/REST/MCP
  share one method). V1/Legacy, Git/File and PR102 standalone T1
  remain unchanged. No public wrapper bypass;
- only then select exact GitHub-hosted macOS 15 ARM64 Job, image,
  source/owner/run ID and one-job fixture, perform pre-T1 qualification
  before third-party imports or any Go/Pipenv/Python native child,
  and obtain user-specific native T1 execution authorization tied
  to those observed identities. A general earlier "approve native T1"
  intent never overrides missing code/image/source or gate evidence.

Before *any* prospective positive Popen: require exact registered
and currently permitted v2 Workspace/cwd/argv, existing-only private
old-state root + original `owner.lock`, healthy complete
ExecStateStore boot scan, no PREPARED/RUNNING/UNKNOWN/RETIRED/corrupt
or quarantine, no busy slot, live trusted owner/reaper/pipe workers,
complete actual source image / compiled interpreter / closed env and
authorization identity, and a fresh one-use source/Runner recheck.
No owner.lock fallback, auto-reset or new PREPARED write. If any
predicate is unknown, ambiguous, changed or non-reviewable: DENY,
zero child and sanitized error. Lack of the R003 physical
whole-tree CPU/RAM controller alone is no longer a **future R005**
rejection reason only *if* R005 is later made effective.

After a future authorized spawn:
- witnessed direct child exit -> report actual `exit_code`,
  `executed=true`, `cleanup_proven=false`,
  `full_descendant_tree_clean=not_proven`; descendants may live;
- timeout without witnessed exit -> `timed_out=true`,
  `exit_code=null`, `process_may_be_running=true`,
  `output_complete=false` unless EOF witnessed; retain original
  child slot and asynchronous direct-child reaper;
- waiter cancel/transport disconnect -> no fictitious response/ACK,
  no child cancellation guarantee, no auto retry; retain owner;
- ambiguous Popen, owner/reaper loss, crash, torn state or lost ACK
  -> fail new admission in current service lifetime, retain
  uncertainty; never kill an unknown PID/PGID or `killpg`.
- never claim physical OS CPU/RAM quarantine, process-tree cleanup,
  strict rollback or complete source semantics from this profile.

## 6. Test matrix and real evidence thresholds

| Level | Required legal success | Required negative / boundary / exception | Evidence |
| --- | --- | --- | --- |
| SAFE SOURCE/T0 | Six exact preview and internally pinned source+Worker candidates; lawful independent Git/File | Scope/wrong env/argv, forged grant/Head, old UNKNOWN, stale source/image, altered `.venv`/Go toolhook, no native child | Original exact-Head Linux G05, tests, HTTP/MCP/Git smokes |
| T0 R005 profile | Explicit `whole_tree_cpu_enforced=false` and `whole_tree_ram_enforced=false` if test diagnostics introduce these fields; no forged R003 PASS | Contract/version mix-up, wrong platform/limits/type, stray credential, missing source/approval -> ZERO Popen | Original test logs; non-operating |
| Future disposable PRODUCT_T1 | First-party actual Python Direct/Pipenv and Go original direct-child completion for six approved vectors | Wrong source or code, old UNKNOWN, Busy, timeout/cancel/lost ACK, prelaunch identity drift, fake cleanup, unintended output, invalid modes | New exact macOS 15 ARM64 job; original preflight+exec logs and source identities, no unsafe T2 |
| Future same-instance integration | Shared Direct/REST/official MCP positive/negative status plus independently lawful real Git and File Write | No transport-only or test-bypass grant; same original-child slot and error mapping; v1 remains DENY | Actual run/Head/Merge identity+original raw logs |
| T2/T3/high-impact canary | NONE authorized by this profile | No kill, resource exhaustion, VM probe, network exfiltration or shared/user/production Mac | NOT_RUN, separately authorize if needed |

Native T1's operating-risk model accepts that a trusted program may
spawn descendants or use network; **do not turn this into permission to
perform a load test, fork bomb, real egress probe, OS process termination,
or secret access**. A future safety-qualified positive test should use
only deterministic short benign first-party fixtures and full original
logs; test timeout as an injected state-machine fault unless a separate
actual timeout trial is explicitly authorized with disposable recovery.

Source-only Linux CI green, R004 B targeted design PASS, an R005 B/C
design PASS or a future macOS synthetic receipt do NOT imply real T1,
merged-result integration, FULL_CODE_REVIEW_PASS, R10 or deployment.
The r006 PR Body may contain historical SHA; always bind the actual
Git objects when publishing a new review.

## 7. Required independent R005 DESIGN verdicts and owner closure

B Standards: determine whether the R003 §6 downgrade is **the only**
permitted semantic weakening; inspect F1/D0 v1/UNKNOWN/cancellation,
the original-child reaper and one-service admission; challenge credential,
network, import shadow, host ImageVersion spoofing and misleading
resource/cleanup/egress fields; supply independent P0-P3.
C Spec: independently establish legal six-command PRODUCT_T1 success
oracles, precise negative/error/timeout/EOF/slot/REST/MCP/Git/File
behavior, full actual-source witness and Mac provider identity;
decide if the proposed weaker route is genuinely testable without
claiming image-byte or full resource enforcement; supply P0-P3.

Both reviewers must bind **this R005 GitBlob**, its exact A-chosen
Base/Head/Tree and `D4-TRUSTED-HOST-DESIGN-004`. A will not synthesize
a joint PASS or substitute B for C. This design-only review does not
freeze the unfrozen PR114 r006 product source, which must have its
own complete later milestone review.

R004_SPEC_P2_01_OPTION_A: NOT_SELECTED, NOT_CLOSED_BY_TECHNICAL_PROOF
R004_SPEC_P2_02_OPTION_B: PROPOSED_CONTRACT_WRITTEN, STILL_OPEN
OWNER_ROUTE_B: SELECTED
OWNER_R005_FINAL_RISK_CONSENT: PENDING_REVIEWED_VERSION
PRODUCT_F1_D0_POSITIVE_EXEC: DENY
PRODUCT_T1: NOT_RUN
SOURCE_TOOLCHAIN_T1_PR102: UNCHANGED_OFFLINE_ONLY_GATE
INTEGRATION_STATUS: NOT_TESTED
FULL_CODE_REVIEW_PASS: NOT_ISSUED
R10_STATUS: BLOCKED
MILESTONE_STATUS: DEVELOPING
FREEZE_READY: NO
NEXT_ROLE: B STANDARDS + C SPEC FOR THIS FIXED R005 DESIGN ONLY
NEXT_COMMAND: Independently review R005 normative PROFILE and publish
             separate SHA-bound TARGETED DESIGN-004 verdicts. After both,
             A consolidates P0-P2, obtains exact revised-version owner
             acceptance, then begins positive Runner/product code and
             separately qualified macOS PRODUCT_T1.
