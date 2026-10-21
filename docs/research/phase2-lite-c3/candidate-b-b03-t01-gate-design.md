# Phase 2 Lite C3 Candidate B — B03-T01 原生组 KILL 实验的分阶段准入设计

**Status: T01-D1 DESIGN ONLY / INDEPENDENT STANDARDS + SPEC DESIGN REVIEW REQUIRED / ZERO NATIVE GROUP SIGNALS AUTHORIZED BY THIS PR.**

**Prepared:** 2026-10-21  
**Frozen base:** [PR #36 B03-R2 pre-signal](https://github.com/chinanjjohn2012/mac-file-gateway/pull/36), Head `ecbb5790edf75458f9e30ec4e507ca4906d383fe`, Git Tree `71bac0658875214c3c4a868f9f043c1bee3509bb`; external targeted Standards PASS / Spec PASS, P2-01 and P2-02 closed, research-only.  
**Authoritative B03-D0:** [PR #33](https://github.com/chinanjjohn2012/mac-file-gateway/pull/33), fixed Head `829a8e12ec8583a07a0f854c5a4f2479635e072b`; `docs/research/phase2-lite-c3/candidate-b-b03-kill-design.md`.  
**Frozen R1 contract RED:** [PR #34](https://github.com/chinanjjohn2012/mac-file-gateway/pull/34), Head `d460052c68bbb723b6dd7597e950c66aab8cbf21`, 11 fixed modes / 10 numbered test groups, expected RED because B03 group-KILL C Helper/Runner do not yet exist.  
**Scope:** This *additional* T01 design document + its Manifest entry only. PR #33 / #34 / #36 reviewed content is never rewritten. Do not add B03 C Helper, Runner, signal-capable workflow, Gateway product code, release integration, or deployment in T01-D1.

## 1. Decision being requested and non-decisions

T01 asks exactly one research question: in a fresh test-only Darwin ARM64 process group whose identity is held by its creating Native Owner, after one legitimately authorized group SIGTERM, can the **same Native Owner** send *at most one* genuine group SIGKILL while Anchor and Worker remain alive in the verified target group, and can the distinct lawful parents observe real Worker and Anchor `waitpid` SIGKILL results and close every enrolled resource inside one immutable deadline? A fully evidenced positive is classified `POSITIVE_EXPERIMENT` only for the explicitly enrolled synthetic group, never for G2.

**Passing this design review authorizes only contract-first implementation planning; it does not itself authorize a real SIGKILL.** The first executable phase must be pure gate math, mocked/no-signal admission and safety faults. A later, independently reviewed *native-run admission package* and explicitly enabled isolated GitHub runner are prerequisites to the first genuine `kill(-owned_pgid, SIGKILL)` invocation. The native run remains synthetic research, **not G2 or proof of atomic PGID identity**.

This incremental T01 protocol must **not** silently turn the isolated PR #36 Controller-loss NOTE_EXIT experiment into a general orphan containment proof. T04 (`controller-loss-before-worker-wait`), T08b (`controller-lost-after-term`), and T10 (`known-descendant-observation`) remain **NOT_RUN / BLOCK**, and no experiments involving those modes are included in the T01 native-run envelope.

## 2. Fully test-owned process identity and enrollment

```text
Research Driver [no group signal capability]
└── Native Owner [sole serial signal authority; sole Anchor/Controller waiter]
    ├── Anchor [direct child, unreaped PGID leader; target PGID = Anchor PID]
    └── Controller [direct child, different self-led PGID, same session]
        └── Worker [Controller's direct child; joins Anchor PGID before ARM]
```

T01 deliberately enrolls **exactly these three children**, no Canary, descendant, dynamic command or external service. Owner and Controller themselves **must be outside the target Anchor group**. Owner has sole legal `waitpid(Anchor)` / `waitpid(Controller)`; Controller alone can `waitpid(Worker)`. Group signal authority is unique to Owner; Controller, Worker, Anchor and Driver cannot send group signals.

Driver creates and validates a new `0700` owned private synthetic directory, a fresh purpose-built executable and fixed marker. C Helper role selection and Runner mode selection are **finite enums**. No CLI/env/API parameter can supply a host PID, PGID, binary, command, arbitrary path, real Workspace, or shell. A hardlink, symbolic link, unowned or permissive test root must be rejected. No inherited generic exec tool or Gateway `run_git`/`run_exec` path is involved.

Enrollment requires the actual current task's **native** observations, not PR #36's former PASS:
1. Owner records its own PID, PPID, SID and monotonic launch epoch; records exact child PIDs returned by `posix_spawn` and the sole owned `Child` entries.
2. Anchor actively calls `sigaction(SIGTERM, SIG_IGN)` and reads back `SIG_IGN` *before* a versioned READY. Owner independently confirms a live, unreaped **direct child**, `Anchor PID = PGID`, expected SID and actual PPID using `getpgid`, `getsid`, `proc_pidinfo(PROC_PIDTBSDINFO)` and non-consuming `waitpid(WNOHANG) == 0`. If `waitpid` consumes an exited Anchor, close signal authority.
3. Controller is Owner's still-live direct child, **Controller PID = Controller PGID**, Controller PGID != target PGID, matching SID; it remains the sole direct parent of Worker.
4. Controller deliberately configures Worker to be **TERM resistant**, recording native `sigaction` disposition and `sigprocmask` state. Worker reports its actual dispositions, PID, PPID, PGID, SID and unique ARMED sequence; Owner verifies the same Worker PID really belongs to Controller, is live, and joined the Anchor PGID. Worker must not exit cooperatively after ARMED until Owner explicitly closes or finishes the experiment.
5. Owner verifies the control IPC writers, CLOEXEC and inherited file-actions: a Worker cannot write the trusted Controller FINAL, Anchor's post-TERM witness, or a second terminal record.

**A private marker, string on stdout, numeric PGID value, previously passed preflight, or successful `posix_spawn` is not an independently sufficient signal admission proof.** On any disagreement, close the signal gate; do not attempt TERM/KILL and use the bounded cooperative exit path.

## 3. Native state machine; irreversible group-signal closure

```text
CREATED
  -> PRIVATE_ROOT_VERIFIED
  -> ANCHOR_READY_HELD -> CONTROLLER_SELF_GROUP_VERIFIED
  -> WORKER_JOIN_VERIFIED -> WORKER_ARMED
  -> TERM_GATE_NATIVE_PASS -> TERM_ATTEMPTED -> TERM_SENT
  -> GRACE_STARTED -> GRACE_COMPLETED
  -> ANCHOR_POST_TERM_WITNESS -> WORKER_LIVE_AFTER_GRACE
  -> KILL_GATE_NATIVE_PASS -> KILL_ATTEMPTED -> SIGNALS_CLOSED
  -> CONTROLLER_WORKER_WAIT_OR_UNKNOWN
  -> OWNER_ANCHOR_CONTROLLER_WAIT -> ALL_FDS_CLOSED
  -> OBSERVATIONS_CLASSIFIED -> VERIFIED | UNRESOLVED

Any invalid identity, expired cutoff, failed IPC, unexpected child state,
or untrusted evidence -> SIGNALS_CLOSED immediately -> cooperative cleanup
                             -> SAFE_REFUSAL or BLOCK / UNRESOLVED
```

**Owner serial lane:** one Owner thread/state machine serializes all admission, group syscall attempts, status observations that may reap Anchor, and `SIGNALS_CLOSED` transition. No helper/other waiter competes for Anchor; no reusing Anchor PID after reap.

**Before TERM:** execute a live native TERM gate with held Anchor + Controller + Worker/ARMED and term deadline. Increment `term_attempts` *before* the sole attempted group syscall. A successful `kill(-anchor_pgid, SIGTERM)` makes `term_succeeded=1`; error makes `term_succeeded=0` and immediately closes further group signals. No retry on `EINTR`, `ESRCH`, `EPERM`. TERM itself is research-only and requires the later native-run approval.

**Grace is event-bounded:** actual `term_sent_at` is stored at successful syscall return; test owner waits until `grace_end = term_sent_at + term_grace_ms` without extending the original deadline, while maintaining Controller wait eligibility. No fixed sleep or IPC marker alone substitutes for witnessed elapsed monotonic grace.

**After grace, before KILL:** Owner requests a fresh post-TERM message from the **same owned Anchor's private control channel**; Anchor re-reads `sigaction(SIGTERM) == SIG_IGN` after real TERM, using a new bounded sequence. Owner again establishes Anchor is *live non-zombie, direct, still unreaped, PID=PGID*, expected PPID/SID; Controller is still live, direct Owner child, self-led outside Anchor group; Worker remains live, Controller-owned and a member of target PGID after grace. `waitpid(Anchor, WNOHANG)` returning Anchor's PID (status consumed), `ECHILD`, missing witness, unexpected Controller exit, or missing Worker identity all disqualify KILL. Any native `kqueue / EVFILT_PROC / NOTE_EXIT` observation reused from PR #36 is only non-child exit evidence, not an alternative lawful Worker wait. Failed native identity checks **must not be bypassed by mutant builds**; no-signal stubs intercept before any unsafe numeric PGID syscall.

**At KILL syscall entry:** one actual `send_kill_to_owned_group()` entrypoint must recheck state, held identities, live/non-zombie status, exact deadline and post-grace witnesses; if rejected, `kill_attempts=0`. Otherwise increment `kill_attempts` **immediately before** the sole allowed syscall and irreversibly set `SIGNALS_CLOSED` on that *attempt* regardless of success, error, `EINTR` or perceived Worker state. An error cannot trigger retries, individual-PID fallback, TERM fallback or post-close signals. No such entrypoint is created by this design PR.

### Signals are not wait evidence

- `term_attempts` vs `term_succeeded`, and `kill_attempts` vs `kill_succeeded` vs `kill_errno_class` are distinct, typed ledger observations.
- `kill_succeeded=1` does **not** establish Worker result. Only a trusted Controller `waitpid(worker_pid)` and `WIFSIGNALED && WTERMSIG == SIGKILL` can establish `worker_result=OBSERVED_SIGNAL_SIGKILL`.
- Only the Owner's own legitimate `waitpid(Anchor)` and `WIFSIGNALED && WTERMSIG == SIGKILL` can establish `anchor_result=OBSERVED_SIGNAL_SIGKILL`.
- Lost Controller / partial FINAL / post-wait audit marker / stdout EOF / `128 + signal` / NOTE_EXIT of a nonchild ⇒ `worker_result=UNKNOWN`; do not label it VERIFIED cleanup.

## 4. Deadline arithmetic, positive margin and self-expiry

Freeze once at Owner task creation, all times from `CLOCK_MONOTONIC`; never recompute from a later stage:

- `outer_deadline = t0 + outer_budget_ms`
- `kill_admission_cutoff = outer_deadline - cleanup_reserve_ms`
- `term_admission_cutoff = kill_admission_cutoff - term_grace_ms - kill_entry_margin_ms`
- Both `cleanup_reserve_ms > 0` and `kill_entry_margin_ms > 0` are hard requirements; `term_grace_ms > 0` and positive startup/ARM budget are also required.
- TERM admission: `now < term_admission_cutoff` and `now < outer_deadline` with native identity eligibility.
- KILL admission: `now >= grace_end`, `grace_end < kill_admission_cutoff`, `now < kill_admission_cutoff`, `now < outer_deadline` and all **fresh** kernel + IPC witnesses.
- Equality / late entry is **rejection**; never reset clocks or use a second cleanup window. The strict positive margin must be consumed by genuine native rechecks and signal-entry eligibility.

**Illustrative timing configuration for design review, not an approved native setting:** `outer_budget=12000 ms`, `cleanup_reserve=3000 ms`, `term_grace=200 ms`, `kill_entry_margin=300 ms`, yielding relative `kill_cutoff=9000 ms` and `term_cutoff=8500 ms`. Subsequent implementation must select and benchmark a single frozen timing vector on macOS ARM64 before any real KILL; CI speed assumptions alone cannot justify those numbers.

Anchor, Worker and Controller shall each receive a verified own-process self-expiry fallback. Their effective expiry must occur **after** the maximum lawful TERM→KILL-entry interval but **before** the single outer deadline (with a positive FD/wait reserve). This is an explicit protocol constraint, not proof that the kernel will reap orphaned grandchildren. Owner also has a separate self-only watchdog; Runner's exact-Owner bounded wait/UNRESOLVED classification from PR #36 remains applicable. Pre-signal refusal must send only *private, owned, cooperative control bytes* while the legal Controller still exists.

## 5. T01 positive record and exact expected classification

For the frozen R1 `escalate-positive` mode, retain every current `BOOL_FIELDS`, `ENUM_FIELDS` and fail-closed strict classification; no weakening or defaulting absent evidence:

| Required fact | Exact positive expectation |
| --- | --- |
| Anchor | `anchor_ignore_ready=1`, `anchor_ignore_after_term=1`, `anchor_live_at_kill_gate=1`, `anchor_reaped=1`, `anchor_sigkill_observed=1` |
| Controller | `controller_own_pgid_at_term=1`, `controller_own_pgid_at_kill=1`, `controller_live_at_kill_gate=1` |
| Worker | `worker_spawned=1`, `worker_armed=1`, `worker_term_resistant=1`, `worker_live_after_grace=1` |
| Group signal ledger | `term_gate_checked=1`, `term_attempts=1`, `term_succeeded=1`, `kill_gate_checked=1`, `kill_attempts=1`, `kill_succeeded=1`, `signals_closed=1`, `group_signals_after_close=0` |
| Lawful waits and FD ownership | `controller_waited_worker=1`, `controller_final_trusted=1`, `owner_children_reaped=1`, `owner_fds_closed=1`, `controller_worker_fds_closed=1` |
| Truthful results | `worker_result=OBSERVED_SIGNAL_SIGKILL`, `anchor_result=OBSERVED_SIGNAL_SIGKILL`, `cleanup=VERIFIED`, `kill_errno_class=NONE` |
| Boundary | `positive_kill_margin=1`, `reuse_proven=0`, `g2_qualified=0` |

**VERIFIED is limited to the exact enrolled test-owned Anchor, Controller, Worker and FDs.** It is not a generic process-tree recovery guarantee. If ANY condition is not natively evidenced, return `BLOCK / UNRESOLVED` or `SAFE_REFUSAL` only when real lawful cleanup is independently verified; never invent a positive.

## 6. Fatal vs safe-refusal boundaries

| Fault / observation | Group attempt policy | Lawful cleanup / verdict |
| --- | --- | --- |
| Anchor missing before TERM, invalid Controller self-PGID, Worker not ARMED, Worker group membership/TERM disposition unverified | `term_attempts=0`; `kill_attempts=0` | Close group authorization; cooperative owned-child exit and exact parent waits; VERIFIED only with all status/FD/deadline evidence |
| TERM syscall fails | `term_attempts=1`, `term_succeeded=0`, `kill_attempts=0`, `SIGNALS_CLOSED` | No retries; cooperation while Controller remains lawful parent; `BLOCK` if any evidence missing |
| Anchor `SIGTERM=SIG_IGN` post-witness absent or changed, Anchor exited/reaped, Worker exited during grace | `kill_attempts=0`, no numeric PGID signal | Separate legitimate Worker/Anchor waits; lost source makes `UNKNOWN / UNRESOLVED` |
| KILL cutoff equality/overrun; positive margin absent | `kill_attempts=0` | Single-deadline cooperative cleanup; overdue cleanup ⇒ `BLOCK/UNRESOLVED` |
| Single KILL syscall fails (e.g. ESRCH/EPERM/EINTR) | Exactly one `kill_attempts=1`, `kill_succeeded=0`, `SIGNALS_CLOSED`, **never retry** | Native errno class and surviving children are independently classified; no signal fallback |
| Real group KILL success but legal Worker wait, Anchor wait, Controller final, FD close or deadline proof missing | `kill_attempts=1`, `kill_succeeded=1`, `SIGNALS_CLOSED` | `worker_result=UNKNOWN` unless lawful Worker wait; `cleanup=UNRESOLVED` |
| Unexpected Controller loss; descendant escape; uncertain numeric PID/PGID/identity reuse | **No further real KILL**; do not run orphan-prone modes | `NOT_RUN/BLOCK` when containment was not separately proven; independent NOTE_EXIT is not legal Worker wait |

**Absolute stop:** a code path allowing `kill(-stale_pgid, SIGKILL)`, a second group signal after `SIGNALS_CLOSED`, or a Runner cleanup relying on external forced PID signals is an immediate safety STOP, not a negative-test success.

## 7. Incremental implementation / CI plan

### T01-D1 — This document, design only

- One new T01 research design document and Manifest hash; new Draft stacked PR from the **reviewed** PR #36 exact Head.
- CI may still fail the frozen upstream 19 B03-R1 RED contracts; do not alter them or report full suite green.
- Independent Standards + Spec design review must inspect **real group signal scope**, time reserve, native post-TERM Anchor survival, Kernel waits and two-axis results, all failure/timeout paths. Record findings at an exact fixed Head/Git Tree. **No native group TERM/KILL in this stage.**

### T01-R1 — Contract-first / no group signal

- Separate *new* branch from reviewed T01-D1. Add strict T01-only tests for deadline math (strict equality refusal), Owner/Anchor/Controller/Worker ownership, unique waiter, post-TERM Anchor witness, single KILL attempt and no-signal mutation interceptors.
- The first test result must be honest **RED** for missing T01 native implementation, with no actual signal call. Do not make the existing frozen 11-mode R1 suite pass by supplying hard-coded fake records.
- Negative variants include omitted Anchor initial ignore, omitted Anchor post-TERM observation, premature Anchor reap, absent Worker parent/group identity, missing Controller status, expired cutoff, forged Controller FINAL, missing/failed FD close and retry-after-failure. Every “gate deletion” mutant **intercepts the syscall before real SIGKILL** (compile-time no-signal stub); no stale numeric PGID is ever signaled.
- Add real native Controller EOF and Native Owner stall tests **before** broadening to any orphan-prone mode. The latter must preserve `UNRESOLVED` semantics on unobserved exit.

### T01-R2 — Native admission review, *before* signaling

The reviewer must independently verify all of these on the fixed candidate binary and GitHub workflow:
1. No host-selected PID/PGID/command/path; private root ownership and executable identity verified; isolated only-newly-created target group.
2. No Worker/Controller/Anchor inherited trusted writer leak; exactly one signal lane, unique legitimate parent waits; initial and post-TERM native witnesses are meaningful and event ordered.
3. Own absolute monotonic deadlines and self-expiry fully contained; KILL not eligible on identity/waiter loss, cutoff equality, missing post-TERM witness or unexpected Worker exit.
4. Every unsafe mutation goes to **no-signal stub**, and test evidence demonstrates the attempted bypass would be detected *before* a syscall.
5. Separate gated macOS ARM64 native job with explicit operator authorization and one fixed `escalate-positive` mode; no automatic SIGKILL on untrusted PR/push triggers. Fatal test failures do not cause fallback kill signals or unsafe cleanup.
6. Reviewer records whether Darwin group/PID lifecycle evidence is *only user-space*, not a kernel-atomic reuse proof.

**If any item fails, keep all actual group SIGKILL NOT_RUN / BLOCK.** T01-R2 implementation alone does not waive this review.

### T01-R3 / R4 — Narrow native evidence and independent code review

After T01-R2 is independently authorized, run only a new private synthetic T01 group on macOS ARM64 (Python 3.13 / 3.14), capture native return codes and actual lawful `waitpid`, Manifest, original GitHub logs and orphan cleanup diagnostics. A partial result is `PARTIAL_B03_NATIVE_NOT_G2` at best. Then freeze exact Head/Tree for separate independent Standards / Spec **code** review and mutation verification; do not merge into product or mark G2.

T02/T03/T05/T06/T07/T08a/T09 each require later separately reviewed mode additions. T04/T08b/T10 have stronger independent orphan/descendant lifecycle prerequisites and **remain NOT_RUN / BLOCK throughout T01**.

## 8. Review checklist / decision contract

Independent design reviewer shall explicitly answer each item **PASS / P2 / P1 / P0**:
1. Does T01 accept only a test-created exact owned PGID, with no user-controlled signal target?
2. Does Anchor **actively** set and natively verify `SIGTERM=SIG_IGN` before READY and again after real TERM?
3. Are the Owner's direct-child, group-leader, non-zombie, unconsumed Anchor status and Controller/Worker identities rechecked at both group signal entries?
4. Can missing Worker/Controller lawful wait/Final/FD evidence ever become VERIFIED or OBSERVED_SIGNAL? Must be NO.
5. Can any group signal follow `SIGNALS_CLOSED`, or any ESRCH/EINTR/EPERM cause a group-signal retry? Must be NO.
6. Are cutoff equality and late admission rejected, with a *strictly positive* entry margin and one original cleanup reserve?
7. Does any negative gate bypass send actual group KILL, rather than intercepting before the syscall? Must be NO.
8. Is PR #36's isolated NOTE_EXIT proof distinguished from T04/T08b/T10 target-group-specific containment? Must be YES.
9. Are Darwin XNU PGID reuse guarantees explicitly **not** claimed without exact kernel source verification? Must be YES.
10. Do CI/PR decisions preserve R1 expected RED, Draft status, no product activation and `reuse_proven=false/g2_qualified=false`? Must be YES.

**Decision output:** `T01_D1_REVIEW_PENDING` at this document Head. **No native SIGKILL authorized**; `group_kill_authorized=false`, `reuse_proven=false`, `g2_qualified=false`. T04/T08b/T10 remain `NOT_RUN/BLOCK`. Production ExecSupervisor, REST/MCP Multi exec and G2/G3/G4/G5 are outside this stage.
