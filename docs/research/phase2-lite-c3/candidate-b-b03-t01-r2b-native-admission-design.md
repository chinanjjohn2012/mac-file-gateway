# C3 Candidate B / B03-T01-R2b-D0 — Native run-admission package DESIGN ONLY

**Status:** DESIGN FOR INDEPENDENT STANDARDS / SPEC REVIEW · NO NATIVE GROUP TERM OR SIGKILL EXECUTION · NO NATIVE KILL HELPER/DRIVER/WORKFLOW IMPLEMENTATION · no merge or deploy.

**Prepared:** 2026-10-22. **Scope:** T01 `escalate-positive` only, in a freshly constructed synthetic Darwin ARM64 group. This document elaborates already-reviewed [B03-D0](candidate-b-b03-kill-design.md) and [T01-D1](candidate-b-b03-t01-gate-design.md); it **does not replace, expand, or relax** either upstream design.

## 1. Frozen upstream authority and negative decisions

| Source | Frozen Head | Gate it passed |
| --- | --- | --- |
| B03-D0 PR #33 | `829a8e12ec8583a07a0f854c5a4f2479635e072b` | Standards/Spec design PASS |
| B03-R1 PR #34 | `d460052c68bbb723b6dd7597e950c66aab8cbf21` | 11-mode / 10-group contract RED only |
| B03-R2 pre-signal PR #36 | `ecbb5790edf75458f9e30ec4e507ca4906d383fe` | Native pre-signal safety preflight, no group signal |
| T01-D1 PR #37 | `30c74b50d12e9d5763054da48be1d612b4b9fc02` | Strict T01 staged design PASS |
| T01-R1 PR #38 | `d6ca7afa15642c82da263ffa6bb75063bbe0ac29` | Pure signal-free contracts RED, Standards/Spec PASS |
| T01-R2a PR #39 | `50400831bb10483c8ce67a9a0cb66ea29173e3c7` | Pure Python simulated Gate GREEN, independent Standards/Spec PASS (Review #5607469692) |

**This R2b-D0 artifact requests DESIGN approval only.** Passing this design cannot start the native group SIGTERM/SIGKILL experiment. T01-R2b contract RED, native no-signal C implementation and adversarial tests, native-run admission review, operator authorization, then narrowly scoped real T01-R3 evidence are **different gates**. A `READY_FOR_REVIEW` comment for this document is not an operator authorization.

The T01-R2a `_Ledger`, `TERM_FACTS`, `KILL_FACTS`, `classify_t01` and `POSITIVE_EXPERIMENT` are synthetic-data tools. They **must not be imported or accepted as authorization** to call a native signal syscall. The native Owner obtains independent kernel/IPC observations and holds its own serial signal ledger. `reuse_proven=false`, `g2_qualified=false` and `group_kill_authorized=false` remain mandatory throughout this design review.

## 2. Exact synthetic process ownership, creation and trust

`Research Driver [no signals, outside target group]
└── Native Owner [sole serialized signal authority; outside Anchor PGID]
    ├── Anchor [Owner direct child, PID=PGID, unreaped group leader, SIGTERM=SIG_IGN]
    └── Controller [Owner direct child, self-led PGID!=Anchor PGID; same session]
        └── Worker [Controller direct child, joins Anchor PGID before ARMED]`

- Only a newly created, single-use, private `0700` owned test root. Validate `lstat` identity and owner, no symlink/hardlink aliases, exact executable identity and private marker, before native child creation. **No host-selected PID, PGID, command, shell, general binary/path, Gateway Workspace, user-provided target or network connection** is accepted. Process role/mode are finite fixed enums; only T01 admitted. Worker, Anchor and Controller executable roles are from the same reviewed artifact.
- Native Owner creates/records and exclusively maintains Anchor and Controller identities and their lawful `waitpid` rights; Controller alone creates and `waitpid`-reaps Worker. Driver may wait only its own immediate Owner. No thread, signal handler, `SIGCHLD` watcher, `SA_NOCLDWAIT` or external cleanup routine competes for a child's legal wait status. Owner and Controller never join the Anchor target PGID.
- Owner verifies Anchor remains alive, non-zombie and **unreaped** with live native PID=PGID, Owner PPID, original SID and exact returned spawn identity before *each* signal entry. A `waitpid(anchor,WNOHANG)==0` is evidence only while the exact child is still held; positive child PID return consumes status and permanently invalidates KILL eligibility. `ECHILD`/`ESRCH`/ambiguous state reject. Recheck the Controller's direct-child identity, self-group, SID and lawful Worker parent/PGID, plus a trusted Controller state witness. User-space `proc_pidinfo`/`getpgid`/`getsid` then `kill` checks are **not kernel-atomic PGID reuse capabilities**.
- Anchor actively installs and reads back `sigaction(SIGTERM, SIG_IGN)` before trusted READY. The same Anchor checks it **again after actual TERM** with a new monotonically advancing sequence and unique trusted IPC writer. Controller verifies Worker's TERM-resistant state with native `sigaction`/`sigprocmask`, direct PPID/PGID/SID, native ARMED sequence and post-grace liveness. The Owner must not treat a pre-signal marker, inherited disposition, or PR #36 `NOTE_EXIT` as a post-TERM witness or a lawful Worker `waitpid`.
- All controlled pipes and finite binary IPC frames identify role, PID, phase and sequence; verify `CLOEXEC`, `posix_spawn` file actions and exactly one trusted Controller FINAL writer. No Worker, Anchor, Driver or inherited FD may forge Controller's FINAL or Anchor post-TERM witness. Truncated, reordered, repeated, stale or wrong-role frames are fail-closed.
- Synthetic descendants and Canary do **not** participate in T01. T02/T03/T05/T06/T07/T08a/T09 are separate future native mode qualifications. T04/T08b/T10 have additional orphan/descendant prerequisites and remain NOT_RUN/BLOCK.

## 3. Only one native Owner signal lane; admission is not string evidence

**Owner-only serial state:** `CREATED → ROOT_VERIFIED → ANCHOR_HELD → CONTROLLER_SELF_GROUP → WORKER_JOINED/ARMED → NATIVE_TERM_GATE → TERM_ATTEMPTED → TERM_SENT → GRACE/WITNESSES → NATIVE_KILL_GATE → KILL_ATTEMPTED/SIGNALS_CLOSED → LAWFUL_WAITS → FD_CLOSED → VERIFIED_OR_UNRESOLVED`.

Every native signal-path action is in a **single serialized Owner lane**. A helper for role dispatch, Driver, Controller or cleanup path cannot call group TERM/KILL. No independent signal lane or system PID fallback is permitted. Failure of any Gate, expired cutoff, lost waiter, unexpectedly reaped Anchor, untrusted IPC, changed TERM disposition, Worker exit, or Controller loss closes signal authority irreversibly. All later stages must observe that closure.

### Admission evidence immediately before TERM

Owner must have a current, same-task, exact, live and unreaped Anchor leader; a live external Controller/parent; Worker direct-parent/group/TERM disposition + authenticated ARMED; unique IPC source; native deadline still strictly within TERM cutoff; and no earlier group signal attempt. Gate check is **inside** the sole native send entry, not just a Python predicate. Then increment TERM count exactly once before the syscall. Any TERM syscall error (`EINTR`, `ESRCH`, `EPERM` or other) means `term_attempts=1,term_succeeded=0,kill_attempts=0,SIGNALS_CLOSED`, no retry/fallback.

### Admission evidence immediately before KILL

Owner must prove a successful native TERM attempt from the same original task, identical immutable seven-field deadline vector and original `term_sent_at`, monotonic elapsed grace, a fresh **post-TERM** Anchor native `SIG_IGN` witness/sequence, live unreaped Anchor at the original PID/PGID, live external Controller, genuine live Worker Controller-parented in the Anchor group, immutable trusted IPC origin, and strict KILL deadline eligibility. A claimed flag in the R2a Python Ledger or a copied `READY` message is **not sufficient**.

The *only* potential real KILL entry is the reviewed native Owner helper method `send_kill_to_owned_group`. It revalidates all gate evidence and, if still eligible, increments `kill_attempts` before the call and irreversibly sets `SIGNALS_CLOSED` **at the first attempt**, regardless of success/failure, errno, timeout or later evidence. Never try a second KILL, another TERM, individual-PID fallback, reverse escalation or Runner-administered signal. A successful syscall is **not** Worker/Anchor wait evidence.

### C-level no-signal Mutation **must precede** any real signal path

At R2b no-signal implementation, every candidate signal branch is compiled with a mandatory `C3B03_TEST_NO_SIGNAL_STUB` interception. The stub takes an **opaque synthetic token**, not an actual user/host PGID, counts attempted TERM/KILL calls and errors, and cannot delegate to `kill`, `killpg` or any other signal-capable OS API. Each negative mutant gets a **fresh synthetic lifetime**, and mutated missing safety gates must be rejected before even reaching the fake transport. A mutation that reaches the no-signal transport is a test failure, never authorization to run against a numeric PID.

The test matrix must include: omitted Anchor first TERM-ignore, omitted Anchor post-TERM disposition readback and new sequence; Anchor exited/reaped before KILL; Controller lost/self-group invalid; Worker not owned/not group member/not live; forged trusted FINAL; missed FD closure, false cleanup; TERM/KILL deadline equality/late; stale/changed policy; insufficient grace; syscall error `EINTR/ESRCH/EPERM` without retry; second TERM/KILL after signal close. The macro set must be explicit, finite and reviewed, with no privileged runtime mutation flags from CLI or environment.

**Absolute STOP** if a dangerous mutant can bypass the stub or if a negative test could invoke `kill(-stale_pgid,SIGKILL)`, even briefly. Negative C builds must have no linkable live negative-PGID signal path. A static no-signal assertion alone cannot establish this: disassembly / symbol and executable-path examination plus actual fault-injection tests are required at implementation review.

## 4. Frozen clock math, native timing calibration, self-expiry

All timestamps use one `CLOCK_MONOTONIC` Owner task epoch `t0`. No stage can reset the task clock.

`outer_deadline = t0 + outer_budget_ms
kill_cutoff   = outer_deadline - cleanup_reserve_ms
term_cutoff   = kill_cutoff - term_grace_ms - kill_entry_margin_ms
grace_end     = native_term_sent_at + term_grace_ms`

Strictly positive `outer_budget_ms`, `cleanup_reserve_ms`, `term_grace_ms`, `kill_entry_margin_ms` and startup/ARMED admission budget. Validate no overflow or equality collapse. Admission `now_term < term_cutoff`; `now_kill >= grace_end`, `grace_end < kill_cutoff` and `now_kill < kill_cutoff`, with both calls before original `outer_deadline`. The Gate must compare the current full frozen original policy at the actual native entry and not accept a self-consistent replacement.

**No numeric production/native timing vector is approved by R2a.** At R2b implement *no-group-signal native calibration* on real macOS ARM64 Python 3.13 and 3.14: capture raw monotonic durations and tail samples for (a) root validation and enrollment/ARM, (b) native identity/witness checks, (c) fresh Controller IPC round trip and FD close, (d) legal Worker/Anchor/Controller `waitpid` cleanup with cooperative child exits, (e) Runner exact-Owner wait and self-expiry behavior. Document actual host/macOS build, compiler, binary SHA, sample count, worst observed time and conservative margins; **do not use a made-up percentile as evidence**.

Freeze a single candidate outer budget and vector only *after* measurements show strict headroom for all of the following: launch/ARM before `term_cutoff`; post-grace checks and KILL entry before `kill_cutoff`; Controller remains lawful Worker waiter while its child exits; held Anchor/Controller reaped, all FDs closed and Final verified before `outer_deadline`. Child self-expiry deadlines for Anchor, Worker and Controller must be proven **after the latest admissible signal entry** and leave measured legal-wait/FD cleanup margin before outer deadline; Owner self-watchdog is self-only and cannot kill a group. If no feasible complete bounded vector exists, report `BLOCK/UNRESOLVED`, never extend deadline or signal to force cleanup.

The previously illustrated `outer_budget=12000,reserve=3000,grace=200,margin=300` is arithmetic test data only. It is **not** a measured/reviewed Darwin run setting. For a failed native Owner, Runner waits only its directly created Owner (no arbitrary PID signal); if wait times out, return `UNRESOLVED` and preserve a private forensic root when parentage/reap status is uncertain. Even reaping Owner does not establish that a former grandchild was legally waited by its original parent.

## 5. Proof of Worker/Anchor outcomes and cleanup is a separate axis

| Required evidence | Legitimate writer / observer | Non-evidence that must never upgrade status |
| --- | --- | --- |
| `worker_result=OBSERVED_SIGNAL_SIGKILL` | Live Controller's **own** `waitpid(worker_pid)` and `WIFSIGNALED && WTERMSIG==SIGKILL`; trusted FINAL delivered to Owner | Owner group KILL return 0, `NOTE_EXIT`, EOF, stdout, exit code 137, Worker IPC assertion |
| `anchor_result=OBSERVED_SIGNAL_SIGKILL` | Owner's exact `waitpid(anchor_pid)` with native `WIFSIGNALED && WTERMSIG==SIGKILL` | Numerically equal PGID, previous Anchor READY, stale status |
| `owner_children_reaped=1` | Owner's legitimate wait of Anchor and Controller with verified child identity | Merely observing `SIGCHLD`, Owner process exit |
| `controller_final_trusted=1` | Exact versioned Controller FINAL after lawful Worker wait, single trusted IPC writer and valid sequence | Replayed frame, Worker/Anchor writer, partial frame, post-wait audit note |
| `controller_worker_fds_closed=1` / `owner_fds_closed=1` | Checked close result on all enrolled FDs, original deadline | Implicit process exit, partial close or successful signal |
| `cleanup=VERIFIED` | All legal wait + trusted FINAL + FD + original deadline facts individually proven | `kill_succeeded=1` alone |

If any Worker legal wait, Anchor wait, Controller FINAL, FD closure, deadline or ownership evidence is unavailable, treat cleanup as `UNRESOLVED` and classification `BLOCK`. `SAFE_REFUSAL` is allowed only when **all relevant bounded cooperative cleanup evidence is positively verified**. Worker orphan NOTE_EXIT is always nonchild observation; it never establishes Controller's lawful Worker wait.

The only positive native result possible after separate authorization is `POSITIVE_EXPERIMENT` for **T01's fresh exact enrolled group**, not `G2_QUALIFIED`. Keep the 11-mode frozen typed schema, exact positive/negative integer and enum values, `reuse_proven=0` and `g2_qualified=0`. Fail closed on missing, extra or wrong-typed fields, wrong mode, duplicate final, or type coercion (`True == 1`).

## 6. Staged deliverables and exact CI/trust boundaries

| Stage | Allowed deliverable | Gate to advance |
| --- | --- | --- |
| **R2b-D0 (THIS PR)** | This **design only** + deterministic design-only/no-signal structural tests/workflow + SHA256 Manifest | Independent Standards/Spec **design PASS** at immutable Base/Head/Tree |
| R2b-R1 | Narrow native-helper API contracts / isolated C compile and *test-only* no-signal stub mutation RED with no live group-signal capability | Verified targeted RED; tests cannot invoke real group signal |
| R2b-R2 | Strict C native Owner/Anchor/Controller/Worker research implementation, all test executions forced into **no-signal compilation**; deterministic IPC/waiter/FD/fault checks, independent code review | All contract GREEN, no-signal negative mutation evidence, native timing/self-expiry evidence on Darwin ARM64; independent code review PASS |
| R2b-R3 | Separate **native-run admission package**: exact reviewed source/commit/binary SHA, binary-chain provenance, macOS runner isolation, measured frozen timings, true owner/target lifecycle checks and manual-protected workflow controls | Independent native run-admission **PASS** plus explicit operator authorization to a *single* T01 synthetic mode on an exact SHA |
| T01-R3 | Only if separately authorized: one real-group synthetic TERM then <=1 KILL, native Worker/Anchor wait, FDs, deadlines, trusted FINALS, raw logs | Original evidence verified; ambiguity => BLOCK / UNRESOLVED, never force a green verdict |
| T01-R4 | Independent code and evidence review of the actual run and all mutations | May close *research T01* only; cannot qualify G2 or the other ten modes |

No automatic PR/push-triggered workflow can execute genuine group KILL. The eventual **separate** signal-capable workflow must require a protected GitHub environment with explicit human approval, `workflow_dispatch` (never PR/push), an exact frozen reviewed Head and binary SHA allowlist pinned independently of untrusted branch content, same-repository trusted source, isolated ephemeral macOS ARM64 runner, one hard-coded T01 mode, and explicit watchdog/forensic-stop behavior; **do not create or enable such a workflow in R2b-D0**. The protected environment reviewer gate cannot be satisfied by a JSON or CLI flag. A job status GREEN is never itself operator authorization.

## 7. What this R2b-D0 CI may and may not claim

This document's workflow may only: check that GitHub checkout matches current SHA; verify every `MANIFEST.sha256` entry; ensure forced group-KILL Helper/Runner and signal-capable job remain absent; validate documentation structure, frozen references, mode/result invariants and gate lists; run unmodified R1 and R2a pure Python tests. macOS ARM64 compile of the previously approved **pre-signal** C preflight may occur without group signals. It must not compile, launch, simulate actual group TERM/KILL or claim an approved native timing vector.

The Linux full test workflow is expected to retain the frozen 19 B03-R1 native-helper/runner RED failures; retain original stderr and mark full workflow **FAILURE**, not green. All design test failures are genuine failures, not converted with `xfail`, `skip`, `|| true` or `continue-on-error`. Any unexpected product or old-contract regression blocks the design handoff.

## 8. Independent design review questions (explicit PASS or blocking issue)

1. Is the exact Owner/Anchor/Controller/Worker synthetic lifecycle fully owned and single-use? Could any host PID/PGID, generic command, arbitrary path or user Workspace slip in?
2. Is the sole native signal syscall entry protected by *fresh*, native, non-consuming eligible ownership checks, while first-error/first-KILL attempt irreversibly closes authorization without retry?
3. Are pre/post TERM Anchor SIG_IGN observations genuinely native and event ordered, Controller outside the target PGID, Worker direct child, live and still in group, with no implicit reliance on PR #36 NOTE_EXIT?
4. Can no-signal mutation builds demonstrably capture **every bypass** before a numeric syscall? What exact static/binary/CI evidence will establish this?
5. Is the original monotonic time vector bound at task creation, and does calibration prove both minimum gate margin and maximum legal wait/FD cleanup within the *same* deadline and each child self-expiry?
6. Is Worker `waitpid` sourced only from Controller and Anchor/Controller `waitpid` only from Owner? Does Controller loss force `UNKNOWN/UNRESOLVED` and prevent fabricated VERIFIED?
7. Can old or forged IPC frames/FD inheritance create fake FINAL, post-TERM Anchor witness or deadline proof?
8. Is the eventual actual signal job **impossible** to launch via ordinary PR/push and protected by separately reviewed exact binary SHA, manual human environment approval and one synthetic mode?
9. Are P3 hardening proposals from the previous reviews tracked but not confused with verified native identity or completed orphan containment?
10. Does the plan explicitly leave `group_kill_authorized=false`, `reuse_proven=false`, `g2_qualified=false`, T04/T08b/T10 NOT_RUN/BLOCK, product ExecSupervisor/REST/MCP Multi-Exec and G2/G3/G4/G5 BLOCK until distinct authorization?

**Decision at authorship:** `R2B_NATIVE_ADMISSION_DESIGN_REVIEW_PENDING` · `group_kill_authorized=false` · `reuse_proven=false` · `g2_qualified=false`. No source, test, PR review or CI completion can silently promote these values to true.
