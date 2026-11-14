# D4 R006 — selected-source trusted-host PRODUCT_T1 qualification (DESIGN PROPOSAL ONLY)

TASK_ID: MULTI-EXEC-LBE-FIVE-DAY-CANDIDATE-20261105
MILESTONE_ID: LBE-FIVE-DAY-CORE-PRODUCT-CANDIDATE
DESIGN_REVIEW_ROUND: D4-TRUSTED-HOST-DESIGN-005
CONTRACT_ID: MWE-LBE-D4-PRODUCT-T1-TRUSTED-HOST-R006-CANDIDATE
STATUS: PROPOSED_NOT_EFFECTIVE / B_C_INDEPENDENT_REVIEW_REQUIRED
REVIEW_SCOPE: TARGETED_DESIGN_REPAIR_FOR_R005_STANDARDS_P2
OWNER_ROUTE_B: SELECTED_ON_2026-11-08
OWNER_R006_NEW_IMAGE_AND_RUNTIME_SOURCE_RISK_ACCEPTANCE: NOT_GRANTED
OWNER_EXACT_T1_JOB_AND_RUN_ATTEMPT_APPROVAL: NOT_ATTESTED
B_DESIGN_R006: NOT_ISSUED
C_DESIGN_R006: NOT_ISSUED
F1_D0_NATIVE_POSITIVE_EXEC: DENY
MACOS_PRODUCT_T1: NOT_RUN
RULESET_ID: ICR-V2.0
HANDOFF_PROTOCOL_ID: GHRH-2.0
EVIDENCE_PROFILE_ID: ETP-V2.0

## 1. Original fixed authority and why this must be a distinct version

R003 proposed executable design GitBlob f8556b48ab5f4af7390fb015092862a8a87768fb
required a verified original+descendant whole OS CPU <=2000m and memory
<=4096MiB enforcement domain, full booted macOS image provenance and complete
*actual selected* Go/Pipenv/Python loaded-code pre-Popen qualification. R004
decision GitBlob 4b0b50c847c0a6a2bcc7069a284d59f4fd986942 split strict
dedicated-host Option A and weaker Github-hosted Option B. User selected
Option B as the architecture direction, not approval for a specific test.

The exact R005 weaker CPU/RAM-only proposal GitBlob
a3b7f6e573bd6678f570e38fffbba1e73d797518 (reviewed Head
fd6f911dcb0016aace295cee94fb1e645f470100, Tree
4d977925852604d0f15ab79d86ef72682b402164) was independently reviewed
in D4-TRUSTED-HOST-DESIGN-004:
- B STANDARDS: REVIEW_COMPLETE / EVIDENCE_INSUFFICIENT / BLOCKED,
  B114-TH-004-P2-01 (full booted hosted-image provenance has no testable
  witness), B114-TH-004-P2-02 (full actually loaded code graph *before*
  first unqualified foreign instruction has no specified positive oracle),
  plus B114-TH-004-P3-01 (atomic, run-attempt-scoped grant replay).
- C SPEC: REVIEW_COMPLETE / SUFFICIENT / TARGETED_REVIEW_PASS for the
  *R005 normative delta only*. C explicitly retains R005 full-image/source
  FAIL-CLOSED prerequisites and does not qualify native execution.
B and C are distinct, neither review may be inherited as an R006 PASS.

PR98 candidate GitBlob 9e6622401b198138039c692efe91fba1a8d06891
and PR102 standalone SOURCE_TOOLCHAIN_T1 Gate B GitBlob
7db3b77aadca8b0c284e28fa5ee64e315e9275d2 remain separate and
unmodified. Operative D0 6e25904aed9a62bb0f472b732021c2a7ca3b3bb0,
F1 76baeb820c6f8a9b067e45e2dcc42e76453fe5b1,
Phase1 b3f2383f292a59fd234269389e5338cd50e334a2 and
G05 76c1c2b8a7947e0b305d55c5f550ab59c638b6d1 remain binding.
The separate 36-Wheel/RECORD evidence R004 GitBlob
2ffe5341288e428be5ee5d0fa8d52aea3e9efc93 remains LIMITED.

This is a prospective **additional safety guarantee downgrade** beyond
the user's Route B choice. The owner has NOT accepted it. The frozen R005
text, its old B/C reviews and ordinary F1/NativeLauncher denials are NOT
modified by this proposal. No text here is runtime authority.

## 2. Exact R006 differences and claims that must never be made

| Prior R003/R005 requirement | PROPOSED R006 PRODUCT_T1-only replacement | Current authority |
| --- | --- | --- |
| R003 physical whole-tree CPU <=2000m, RAM <=4096MiB | Retain R005's honest NO hard whole-tree CPU/RAM isolation. Operating host can exhaust resources | NONE; previously Route B selected only |
| R003/R005 full byte-level booted image identity before any code | TRUST a specific GitHub-hosted `macos-15` ARM64 *provider/job identity*, first-party checked-out HEAD/Tree/G05, actual `uname` and macOS build, `ImageVersion` + pinned runner-images release metadata, and SHA256+inode nofollow measurement of an explicitly enumerated **subset** of selected OS/system loader files. Declare FULL_BOOT_IMAGE_ATTESTED=false and accept residual unmeasured macOS image components | P2-01 proposed risk alternative, NOT approved |
| R003/R005 full actually loaded Go/CPython/Pipenv/dyld/import/stdlib/module graph proven **before** first foreign instruction | PIN finite known-source selection and exact toolchain binaries, Go P007 complete stage where applicable, first-party Workspace files, Pipfile/Pipfile.lock/.venv interpreter/site/seed and expected locked Wheels/RECORD, source-shadow/startup hook denials and closed env; recheck immediately pre-Popen. Explicitly accept that **arbitrary dynamic and post-launch source/loader selection cannot be fully proven in advance**. Declare ACTUAL_LOADED_GRAPH_PROVEN=false; after-launch source audit is not retrospective authorization | P2-02 proposed risk alternative, NOT approved |
| R005 exact six/limits/old-state | UNCHANGED: six vectors, 1200s job, 120s original, 300s Worker, original concurrency 1/Workspace and <=4/service, 48000 raw BYTES and redacted CHARS per stream, old owner.lock/UNKNOWN/cancel/no replay | Still requires separate operative F1/D0 |
| PR102 SOURCE_TOOLCHAIN_T1 standalone OFFLINE_ONLY | UNCHANGED; this weaker PRODUCT test cannot be relabeled as PR102/source precontact no-egress qualification | DENY unless its own approvals/proofs |
| T2/T3 / production / user Mac/Tunnel / merge | UNCHANGED and NOT AUTHORIZED | DENY |

The host provider/release and sampled selected source bytes are a
**finite observation of parts of the execution system**, not a cryptographic
image attestation or OS sandbox. The risk is not negligible: a future
Go/Pipenv/CPython/dyld dependency may load as-yet unlisted code from the
runner image or expanded runtime graph. This risk must be reviewed and
signed separately, even for benign trusted first-party fixtures.

## 3. Concrete, independently testable positive/negative admission oracle

The candidate actual test is restricted to **GitHub-hosted standard macOS
15 ARM64 in a newly bound, disposable pull-request job** and the same
six fixed first-party paths and requested/effective vectors from R005:
- py-direct / direct: python -m pytest -q
- py-direct / direct: python -m compileall -q ./src
- py-pipenv / pipenv: requested python -m pytest -q,
  internal effective pipenv run python -m pytest -q
- go-project / direct: go test ./...
- go-project / direct: go vet ./...
- go-project / direct: go build -o bin/app ./cmd/app

Preflight MUST run G05 before any unqualified dependency, with checkout
`persist-credentials: false`, original HEAD and native Tree, exact source
Manifest and no untracked/ignored executable inputs. The GitHub job log
must independently show: repository, PR/Base, Head, synthetic Merge
separately, `run_id`, `run_attempt`, `runner.environment=github-hosted`,
`runs-on=macos-15`, actual Darwin kernel, ARM64, macOS 15 OS build,
`ImageOS`, `ImageVersion` and the selected runner-images release
metadata. Values obtained from environment variables or local JSON
remain CLAIMS about GitHub-run context; they are not signed OS image
digests. An unknown release or unreviewable mismatch is DENY.

For sampled selected OS/runtime source, a trusted **review-bound
allowlist** with independently established expected SHA256s MUST be
verified by bounded nofollow FD stream, inode/mode/uid and all pinned
ancestor drift checks immediately before launch; a self-supplied digest
computed by the same untrusted client from current bytes cannot qualify
source. Prefer exact observed selected loader/stdlib/venv/Go paths plus
their approved origin when available. Unsupported or unknown paths,
pointer-file/symlink, writable/multi-link source, tampered bytes, stale
inode, missing expected source, or changed selected file/ancestor => DENY.
A checked source subset cannot establish that the OS loader selected no
other source.

Current A source-only candidate:
`gateway/lbe_hosted_source_probe.py` provides a real, bounded, nofollow
selected file-byte/metadata reader and an atomic consume-before-recheck
helper with **ALL** host-provider/image/loaded-source/native booleans FALSE.
It is not wired into a positive Worker, not a full boot-image witness,
and not itself approval of source digests. Tests in
`tests/test_lbe_hosted_source_probe.py` use disposable files and
forbid subprocess/signal execution. Existing `gateway/lbe_runtime_tree.py`
rejects unlisted sources, dangerous `.pth`, `sitecustomize` and
unqualified symlink paths, but its installed RECORD scope is limited;
`gateway/lbe_go_import_sources.py` and
`gateway/lbe_python_import_sources.py` remain static first-party
import candidates, not true dynamic load testimony.

The actual reviewer-approved positive native code (NOT implemented or
authorized by this document) must additionally retain:
- independently pinned exact source archives, Go compiler/linker/P007
  source stage, selected CPython interpreter and Pipenv wheel/seed/site,
  private Workspace/cwd/Go output paths, closed child environment with
  no alternate `GOFLAGS=-toolexec`, `GOCACHEPROG`, `PIPENV_PYTHON`,
  injected `DYLD_*`, `.venv` pointer-file or unknown startup `.pth`;
- no production secrets, no checkout-credential persistence, no shared
  writable mounts, unknown proxy/credential exposure => DENY;
- old exact owner.lock/private ExecStateStore healthy boot scan, no
  PREPARED/RUNNING/UNKNOWN/RETIRED/corrupt or quarantine and no
  missing-root fallback, no public schema-v1 escalation;
- one service-owned `WorkspaceService.invoke_exec` permission decision,
  not a second REST/MCP/CLI path, no ability for a client or plain
  dataclass to mint owner approval, no hidden environment boolean grant;
- one original child/Workspace, four/service, witnessed original exit
  or retained owner/reaper slot on timeout/cancel/disconnect, bounded
  output/EOF, no unsafe PID/PGID signal/killpg and no automatic replay.

## 4. Explicit per-run atomic approval and replay negative cases (B P3)

A **future** independently reviewed trusted bootstrap (not R005/R006
declaration data, REST/MCP client, ordinary env or test monkeypatch)
MUST bind a typed owner-signed/approved authorization to:
`REPO, PR, BASE_SHA, HEAD_SHA, HEAD_TREE, MANIFEST_SHA256,
R006_DESIGN_BLOB, review IDs, GITHUB_RUN_ID, GITHUB_RUN_ATTEMPT,
OS/image-release/source snapshot identity, Workspace/cwd/runner,
requested_argv/effective_argv, timeout, nonce and expiry`.

Each per-attempt nonce is bound to an exact original-child/Workspace
request. Within the **shared** WorkspaceService authorization gate,
atomically check eligibility + mark the one-use nonce CONSUMED **before**
reservation, Worker/Runner/Popen and before any cancellation-sensitive
IO. The already implemented SOURCE/T0 `D4OneUseAttemptMarker` burns
a memory-local marker under lock, but does **not** prevent replay after
process restart or across two different GitHub run attempts: do not
promote it to a durable owner grant. Require a fresh owner decision
for every new run ID/attempt. Crash/restart with any uncertain
outstanding original must latch/deny; no deleted/rewound nonce,
automatic clean slate or replay. Any inability to prove cross-process
uniqueness => no positive launch.

T0 must cover competing Direct/REST/official MCP callers; same nonce
competing across two workspaces; old run_id/run_attempt replay; wrong
Head/Tree/Blob/source; cancellation after consume; repeated submit
after lost ACK; state UNKNOWN/owner.lock missing; missing or malformed
approval. Require zero original Popen in every negative and no
mocking of actual owner-lock filesystem identity.

## 5. Future owner acceptance requires nine explicit risk categories

A's earlier recorded Route B selection did NOT approve these additional
weakening terms. A final owner action must cite the exact **new R006
GitBlob**, reviewed B and C verdict URLs, exact runnable Head/Base/Tree,
run_attempt, host image-source identity and command manifest. The owner
must accept ALL of:
1. original + descendants may consume CPU/RAM up to the runner's
   host capacity; job scheduling/timeouts are not process-tree cgroups;
2. arbitrary network egress may be possible; no OFFLINE_ONLY promise;
3. same-UID host files and processes may be accessible outside Workspace;
4. direct process or descendants may survive timeout, cancellation or
   process crash; no full-tree cleanup or rollback;
5. lost ACK, manual rerun and restart may duplicate effects;
6. pathname Popen TOCTOU remains under local trusted-user threat model;
7. future GitHub-hosted OS image can contain unmeasured/unversioned bytes
   beyond release metadata and finite selected-source checks;
8. Go/Pipenv/Python dynamic code/import/dyld/generated source may be
   selected beyond preflight's complete provable static subset;
9. non-idempotent first-party build/test/file side effects inside the
   disposable runner may occur; no production secret and no user Mac.

Approval does NOT permit resource-exhaustion, real network canary,
kill/signal/Seatbelt resource experiment, user Mac/Tunnel, shared host,
production, merge/tag/release/deploy, or a separate standalone
SOURCE_TOOLCHAIN_T1 without PR102 Gate B.

## 6. Test and evidence milestones

**Now — authorized SAFE SOURCE/T0 only**:
original Linux G05 Head/Tree/Manifest, source-only private staging,
actual selected host-file FD measurement against independently supplied
hashes, one-use atomic recheck, negative source/parent drift, malformed
runner/replay/unknown-state and adjacent preview/Git/File checks.
No positive Go/Pipenv/Python original T1, no macOS load or OS-domain
claims. The existing new source probe is not connected to public
positive code.

**Next, only after R006 exact B/C design PASS and owner approval**:
A implements the new typed run-bound server-side authorization,
selected native Runner/launcher positive path and proper status
semantics, with reviewed code and suite of safe T0/RED→GREEN. DO NOT
weaken native refusal while draft R006 is under review.

**Then, only when exact T1 job/runner/source/credentials are independently
qualified and separately authorized**: one benign disposable
macOS 15 arm64 PRODUCT_T1 job with six exact legitimate positive cases,
negative paths, actual original direct-child completion and output
evidence; original GitHub Job Log/HEAD/Tree, installed source and
image/version evidence; same-instance Direct/REST/MCP+Git/File
integration as separately qualified. No T2/T3 or high-impact canary
without another authorization.

Every unexecuted stage reports `NOT_RUN`, not `PASS`. A Linux GREEN,
a fixed design PASS or an unbound image metadata claim never proves
native execution. Merge commit/tree and Head must be independently
recorded even if Trees currently match. R10 full code+integration
remain distinct.

## 7. B/C independent design questions and closure threshold

B Standards and C Spec each independently determine whether the
weaker image and loaded-source assertions are sufficiently honest,
testable, precisely scoped and acceptable to the owner, and whether
the retained old-state/PR102/credential/no replay/unknown-failure
security obligations can be implemented without false attestations.
B must re-evaluate its own prior P2-01, P2-02 and P3-01 with independent
counterexamples; C must independently verify legal six-command
success and negative/error/timeout/transport boundary coverage.
Any new unqualified source selection or infeasible acceptance oracle
is a new P2 BLOCKER; no one may inherit the old C targeted PASS.

Current A finding status:
B114-TH-004-P2-01: PROPOSED_NARROWER_HOST_IMAGE_RISK_CONTRACT; NOT_CLOSED
B114-TH-004-P2-02: PROPOSED_NARROWER_DYNAMIC_SOURCE_RISK_CONTRACT; NOT_CLOSED
B114-TH-004-P3-01: ATOMIC_RUN_ATTEMPT_CONTRACT_SPECIFIED;
                  TRUE_CROSS_PROCESS_APPROVAL_NOT_IMPLEMENTED
C_R005: TARGETED_DESIGN_PASS_ON_OLD_BLOB_ONLY
R006_B_REVIEW: NOT_ISSUED
R006_C_REVIEW: NOT_ISSUED
EXACT_OWNER_R006_FINAL_ACCEPTANCE: NOT_GRANTED
R006_CONTRACT_STATUS: PROPOSED_NOT_EFFECTIVE
F1_D0_POSITIVE_EXEC: DENY
NATIVE_PRODUCT_T1: NOT_RUN
INTEGRATION_STATUS: NOT_TESTED
FULL_CODE_REVIEW_PASS: NOT_ISSUED
R10_STATUS: BLOCKED
MILESTONE_STATUS: DEVELOPING
FREEZE_READY: NO
NEXT_ROLE: B/C only for this R006 design repair after A fixes and
           freezes this fixed design Blob; A retains r006 product code.
