# M2 macOS Seatbelt Runner Security Gate (T0-only)

TASK_ID: MULTI-EXEC-LBE-M2-SEATBELT-RUNNER-SAFETY-T0-20261104
REVIEW_ROUND: r002
REVIEW_SCOPE: TARGETED
STATUS: NONOPERATIVE_T0_ONLY / NATIVE_MACOS_CANARY_NOT_RUN / GO_PIPENV_NOT_RUN
USER_AUTHORIZATION: Independent Draft PR; design and run only safe T0; submit B/C independently. No live macOS canary or Go/Pipenv.
PARENT: PR #111 r002 Head bc25207ed4d8b6e74c23af4d8939e7f4f544a518 / Tree 7d8cfffb70a62171d64b6a411bba4698adb175db.
AUTHORITY: PR102 r002 Gate B design GitBlob 7db3b77aadca8b0c284e28fa5ee64e315e9275d2; PR98 local_best_effort design GitBlob 9e6622401b198138039c692efe91fba1a8d06891; PR110 r002 offline canary design GitBlob 2a5e89df6a08accb5fbb781a949be483e1574e60; PR111 r002 original canary prep GitBlob 748127744b06de9cbeaaa7f1c43c47071cd5dfaf; current effective ICR-V2.0, GHRH-2.0, ETP-V2.0, A role; operative D0/F1/Phase1/G05/R004 unchanged.

## 1. Scope and invariants

This PR adds a descriptive Python T0 source gate, deterministic synthetic tests and this runbook. It does NOT change a production code path, Apple C helper, workflow, Seatbelt profile or existing hard-stop. Earlier PR109 SOURCE_T1, PR110 Seatbelt backend and PR111 native-canary execution entrypoints remain unconditional DENY.

The only success condition in T0 is structural validity of a proposed future runner profile. It is NEVER a real admission, executable OS attestation, test authorization or guarantee that the named external hash was observed. No physical fork/wait/kill/signal, network probe, socket, sandbox_init, OS setrlimit, compilation of macOS helper, native Go/Pipenv, macOS hosted job, firewall, production, merge or deploy.

## 2. Four future mandatory runner safety gates (none is attested in T0)

**R1 First-party and runner source identity.** Before any external native instruction a separately authorized trusted preflight MUST observe real GitHub Head, Tree, complete effective diff, G05 source and actual index/ignored/untracked files; exact immutable C helper + fd scrub + bounded wait headers; true runner image version/digest and workflow code identity; absolute compiler/SDK/linker and full Mach-O binary SHA, code sign/loader and dynamic source closure. A runner label, proposed SHA or forged image/compiler digest is only caller text. Compiler/SDK and runner image need a source chain, not the OS label. A changed Head/Base/Tree/image/toolchain/build artifact voids prior proof. Actual Mac provenance NOT_ATTESTED.

**R2 OS resource limits and external owner.** The T0 ceiling proposal is one disposable GitHub-hosted macos-15 arm64 runner, one original and at most one naturally forked child, one concurrent canary, job wall <=1200s, helper wall <=10s, CPU <=10s, RAM <=128MiB, internal selected-child wait <10s and <=2000ms, stdout/stderr each <=4096 raw bytes, proposed soft nofile <=64. These are ceilings, NOT measurements or applied limits. A trusted outer supervisor MUST enforce and observe wall, aggregate CPU, process-tree memory, descendant ownership, bounded output and active process count BEFORE attachment. RLIMIT_CPU (per-process), RLIMIT_RSS/AS (macOS limitations), RLIMIT_NPROC (per-UID), RLIMIT_FSIZE (file not streams), runner YAML timeout, posthoc metrics or environment flags alone DO NOT satisfy the contract. If effective OS enforcement or privileged control is unavailable, STOP before any native canary.

**R3 Timeout and descendant survivor quarantine.** The selected child WNOHANG 2-second bounded source probe from PR111 is not a reaper/supervisor. TIMED_OUT, ECHILD, unknown owner/child, lost ACK, retry request or unverified timeout => possible-live descendant and an irreversible admission latch in the current observation model. A later success string, process-name match, recycled PID, fake cleanup, changed parent, restart or direct-child exit0 cannot clear it. The future supervisor must bind original PID + birth identity and all descendants to its owned isolated domain, keep the stop/quarantine state across runner/job lifecycle and prove disposal/containment WITHOUT unapproved signals. T0 model is in-memory only; it does not persist or retire native processes. An uncontained survivor forbids real test/retry.

**R4 Pre-exec isolation admission.** Required order before any foreign executable code: G05 source snapshot, hosted runner image/workflow identity, compiled Mach-O/compiler/SDK source lock, safe two-pass FD scrub, enforceable resource+survivor supervisor, actual fail-closed Seatbelt policy attached, approved same-domain negative network/IPC/DNS/proxy probes and bounded natural descendant observation. No Go/Pipenv or product Exec occurs in this PR. Any missing, out-of-order, failed or unverifiable step blocks. Precontact means BEFORE foreign/native instructions; a later network failure observation cannot retroactively guarantee no prior leak. Actual sandbox_init, TCP/UDP/remote/DNS/proxy/AF_UNIX, descendant inheritance and loader are NOT_RUN/NOT_ATTESTED.

## 3. Safe T0 tests and expected results

tests/test_lbe_m2_seatbelt_runner_gate_t0.py uses original first-party byte locks through the PR111 source-only plan. It covers ordinary syntactically valid proposed identity/budgets/order, altered C/header bytes, bad Head/Tree coupling, fake Runner OS/image/toolchain digests, digest collisions, limit overrun/underflow, boolean/float confusion, conflicting CPU/wall/child deadlines, nofile/children/concurrency ceiling, precontact ordering and injection, direct-child exit not proving descendant retirement, timeout/ECHILD/owner loss latch with fake later success, mutation of frozen receipt and fake all-green OS claims. No import of subprocess/socket/ctypes/resource/os and no process/native/network operations. Existing Linux T0 source, helper FD scrub callback tests, full Python regressions and smoke run only under existing controlled-exec-tests GitHub workflow.

Execution identity must be checked in the original GitHub CI Job log: exact Head SHA, Tree, G05 before imports, locked first-party Manifest, 36 wheel inputs and limited installed RECORD provenance, pytest pass/fail/skip, final manifest, smoke exits. A synthetic Merge checkout is a different possible test object; do not claim it was run if it was not. CI green for Python T0 CANNOT count as macOS OS gate, source T1, product integration, R10/FULL.

## 4. Test risk and future stage authorization

T0 allowed: static review, pure Python T0, existing safe isolated Linux bounded C callback regressions and ordinary offline smoke. T1 actual disposable-hosted macOS helper compilation/Seatbelt canary, OS resource probing or native Go/Pipenv: NOT_AUTHORIZED THIS ROUND and NOT_RUN. T2 process termination/cleanup or destructive tests: NOT_AUTHORIZED. T3 user/shared/production machine: NOT_AUTHORIZED. Do not add a workflow that could bypass this. No global pf/firewall, sandbox-exec, child-signal cleanup, Go/Pipenv or exact product F1 denial removal.

User may consider a later new, independently reviewed exact runnable Head only after a separate explicit T1 decision and OS/runner/limits/source identity evidence. B and C must independently review this NEW Base/Head/Tree T0 code and original test evidence. Prior #111 targeted PASS cannot be inherited. Both targeted PASS would still NOT grant native or product execution. INTEGRATION_STATUS: NOT_TESTED; FULL_CODE_REVIEW_PASS: NOT_ISSUED; R10_STATUS: BLOCKED.

## 5. B/C counterexample prompts

B Standards: independently verify source/Runner SHA cannot be inferred from string checks, monotonic survivor latch after TIMEOUT+fake EXIT_ZERO, boundaries and effective nofile/CPU/memory/output caps; challenge forged all-green dataclass and accidental changes in existing native hard stops; inspect full Base..Head diff and original source-bound T0 Job log.

C Spec: independently challenge true precontact sequencing (before *first* foreign instruction), same Seatbelt domain and descendant policy, all egress/IPC channels, OS-enforceable limits vs static budget syntax, restarted unknown child cleanup/never retry, Head and Merge execution identity and actual Mac NOT_RUN; verify no product positive Exec, no native canary or Go/Pipenv was invoked. Both reviews target this T0 code only, not future OS evidence.

## 6. r002 grouped security-preflight P2 repair and test-first original RED

Current PR112 r001 exact Base bc25207ed4d8b6e74c23af4d8939e7f4f544a518,
old reviewed HEAD 68296277cee47457630070908c056dc4b82a35c7,
Tree bf3662fe6e643d46608346db3265f3be0b566e10:
- B Standards independent native r001 FAIL:
  https://github.com/chinanjjohn2012/mac-file-gateway/pull/112#pullrequestreview-5761154460
  P2-112-01: untyped five runner identity fields accept hostile __eq__/__ne__.
  P2-112-02: nine precontact tuple elements accept hostile __eq__.
- C Spec independent native r001 FAIL:
  https://github.com/chinanjjohn2012/mac-file-gateway/pull/112#pullrequestreview-5761162968
  C112-R001-SPEC-01: non-string element injection accepted by tuple equality.
  Both old Reviews remain immutable. No live macOS launch was evidenced.

A added FIRST-PARTY TEST-FIRST RED on distinct intermediate commit
aee1b818d04ec228b3a43c897d1d842a042e58b8,
Tree 69064cc650ba34be1cfb66b1882c9087f3aef5a3.
Original Linux x86_64 Python3.13 hosted GitHub Run
https://github.com/chinanjjohn2012/mac-file-gateway/actions/runs/41744752274
original Job
https://github.com/chinanjjohn2012/mac-file-gateway/actions/runs/41744752274/job/126294830559
G05 correct HEAD/Tree, Blob/mode 309 PASS, Manifest 308 PASS,
no ignored/untracked source-shadow inputs, but pytest intentionally FAILED:
42 failed, 2624 passed, 19 skipped, 1 warning, 52 subtests passed;
smoke/final manifest NOT_RUN due to pytest RED. These are safe Python T0
in-source negative cases, NOT Apple C helper or process/OS experiments.

The grouped r002 source repair has exactly two validator changes:
1. Before equality, require exact primitive str for all five runner identity
   fields. Do not allow custom objects, bool or str subclasses to run user
   comparison logic or masquerade as canonical runner identity.
2. Before tuple equality, require exact tuple AND type(step) is str for EVERY
   precontact element. A crafted __eq__/__ne__ object must be rejected before
   any method callback; no "ORDERED" receipt is created for injected steps.

First-party direct tests cover all 5 identity slots and all 9 ordered steps
across always-equal, throwing-comparison and custom str-subclass variations;
any comparison callback MUST remain uncalled, and clean literal-only source,
budget, lifecycle and unconditional native-deny cases must still work.

r002 current original HEAD GREEN CI must be obtained and independently read
before A publishes GH_HANDOFF_V2 FIX_READY; neither old RED nor old r001
GREEN is a new-HEAD PASS. Synthetic Merge and developer Mac worktree are
not independently tested/observed. Still NONOPERATIVE T0: actual macOS
runner/compiler/SDK/MachO/OS Seatbelt network/process isolation and real
resource limits/survivor retirement NOT_ATTESTED; Go/Pipenv and product
Exec NOT_RUN; no global firewall, OS signals, merge, release or deployment.
TARGETED r002 B and C independently review the new Head/Base/Tree, entire
four-file effective diff and both fixed P2 counterexamples; R10 BLOCKED.
