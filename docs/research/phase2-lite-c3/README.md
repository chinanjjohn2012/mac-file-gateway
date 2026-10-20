# Phase 2 Lite C3 — 常驻 Leader / Relay 原生安全资格设计（草案）

**Status: REVISED DESIGN / REQUIRES INDEPENDENT STANDARDS + SPEC RE-REVIEW / NOT APPROVED FOR IMPLEMENTATION. G2 BLOCK.**
**Prepared: 2026-10-21. Revised after independent PR #22 design review (P1×2 / P2×3).**
**Parent fixed commit:** `f5e7e6eba40d0987974e4b72df6fd2ccc0f0f42f` (PR #21, C2 isolated research).
**Proposed C3 branch:** `research/phase2-lite-c3-relay-20261021`.
**Product baseline:** `release/ms1` at `ba8634f24cdc26904d1c80951df7173e429240c7`, official MCP SDK 2.3.0.

This file is a **candidate research design**, not code approval, product G2 qualification, or a safe supervisor implementation. The initial independent review of fixed Head `a78d1031fb7c64f310db60337d22d256f50661b5` returned **Standards CONDITIONAL / Spec FAIL** (P1-01, P1-02, P2-01, P2-02, P2-03). This revision defines narrower, falsifiable research contracts without claiming they have been independently accepted. **A fresh independent Standards / Spec design review of the new fixed SHA must PASS before any C3 RED implementation or native Relay prototype.** Read-only Darwin/XNU source analysis may continue. No current Gateway service, REST/MCP tool, real Workspace, Pipfile, app configuration, or production process is modified.

## 1. Evidence boundaries inherited from C1/C2

- PR #18 / C1: synthetic Darwin ARM64 `posix_spawn_file_actions_addfchdir_np` with a pinned directory FD, creation-time PGID, and rename/recreate positive controls. C1 is a narrow OS primitive observation, not generic cwd authorization or G2.
- PR #20 / C2: a single owner of an *original unreaped direct-child group leader* can safely refuse unsafe group signals after leader loss. Its `stale` case deliberately injects an invalid expected identity, **not numeric PID/PGID reuse**.
- PR #21 / C2 review fixes at the fixed parent: third independent review reports **Standards PASS / Spec PASS limited to isolated research**, with bounded signaling deadlines, independent `NOTE_EXIT` for one known synthetic descendant, normal-path false-EOF mutation, and failure cleanup/EINTR negative tests. Hosted macOS 15 ARM64 Python 3.13.15/3.14.7 passed. The recorded outcome is still `PARTIAL_NATIVE_OBSERVATION_NOT_G2` and `g2_qualified=false`.
- C2 proves neither that arbitrary descendants have exited nor that an original workload group leader remains usable after the workload exits. PID and PGID are numeric identifiers, **not durable ownership tokens**. Do not infer an atomic check-and-signal guarantee from `getpgid`.

## 2. C3 question, scope and non-goals

**Question:** Can a *trusted resident group leader / relay* remain an exclusively owned, live, unreaped signal anchor while it supervises Direct/Pipenv-like disposable synthetic work that may exit before its own descendants? Can the external sole owner perform bounded TERM→KILL without signaling an unrelated process group, even when cancellation races relay termination?

C3 may research a C or POSIX-native synthetic relay, a test-only Python workload and a Darwin-only probe in a disposable private directory, with no business data. **Do not** integrate real ExecSupervisor, use production Gateway/Popen, enable Multi `/run`, register MCP `run_command`, change MCP SDK, restart running Gateway, or modify `release/ms1`.

C3 should choose between and explicitly test:
- **Candidate A — Relay as dedicated process-group leader:** one native owner creates and exclusively waits on a directly owned Relay group leader; Relay spawns and alone waits on Worker in that group. Relay stays resident until the permitted termination sequence is complete. **On group SIGKILL the Relay and Worker may both die, so the Relay cannot guarantee reporting the Worker's actual wait status. If not previously observed, Worker exit result is `UNKNOWN`; sending KILL is only an action, not evidence of Worker termination or status.** Relay signal behavior and Worker dispositions must be proven independently.
- **Candidate B — External control relay with separately held group anchor:** the native Owner is the direct parent and sole waiter of both Anchor (group leader) and a group-external Controller. Controller is sole parent and waiter of Worker, which is spawned **into the existing Anchor PGID subject to verified same-session/permission constraints**. The Controller remains outside the Worker group and can attempt `waitpid(Worker)` after group KILL, but Controller failure still makes the result `UNKNOWN`. This has additional ownership/IPC edges and **does not itself eliminate PGID reuse risk**. Keep B for native comparison; do not preselect A as the product architecture.

A relay in the same group **may receive group TERM/KILL itself**. Therefore, Candidate A needs experimental evidence for TERM surviving at the relay without inadvertently making worker/descendants TERM-resistant, and for KILL ending the relay without allowing later numeric group signals. Relay worker and child signal masks/dispositions must be deliberately established. The test must detect unauthorized relay exit, not reclassify it as success.

## 3. Safety invariants to freeze in design review

**Identity and ownership.** There is exactly one **native Owner** for each task's group-signaling capability. In A, Owner is Relay's parent and exclusive waiter; Relay alone reaps Worker. In B, Owner alone reaps Anchor and Controller; Controller alone reaps Worker. All group signal attempts and *final Anchor/Relay reap* are serialized by the same Owner state machine; no other thread, SIGCHLD callback, asyncio child watcher or library may reap that specific direct child. The Owner keeps a task-specific ticket for correlation, **not OS identity**. The held direct-child leader's PID/PGID, ownership and non-reaped state form a **candidate** identity chain requiring explicit XNU evidence. A cached PGID, second waiter, subprocess PID discovered by scanning, or control-message field never authorizes group signaling. If `ECHILD`, another waiter, missing state, actual leader exit, or uncertain kernel retention breaks the qualification => **zero further negative-PGID signals**, `UNRESOLVED/QUARANTINED`. A check and `kill(-pgid,...)` are not POSIX-atomic; C3 must investigate the exact Darwin PID/PGID retention semantics rather than declaring the race solved.

**Termination lifecycle.** Owner's monotonic timer covers spawn/handshake, cancellation, TERM grace, KILL escalation, both-stream drain, direct-child wait, and cleanup; use stage budgets within one bounded outer lifetime. In A, Relay must survive TERM while Worker starts with its explicitly restored default TERM disposition/unblocked TERM mask; in B the group-external Controller must survive Worker-group TERM while Anchor's TERM policy is separately frozen. The last held leader is **never reaped before the last eligible group signal**; if it exits, ownership or identity becomes uncertain, refuse escalation and report BLOCK. KILL is the final permissible group signal; no further group signal afterward, even if cleanup is incomplete. No `killpg(pgid)` or `kill(-pgid,...)` fallback after identity loss; only safely owned *direct child PID* cleanup with independently established eligibility. Deadline checks remain fail-closed user-space guards, not atomic kernel capabilities.

**Truthful result and descendant policy.** A Worker's exit code/signal can be labeled `OBSERVED` only if its *legitimate direct parent* successfully performed `waitpid`, independently from the Relay/Anchor's own status. If group KILL makes that observation unavailable (especially A), report `UNKNOWN`; never turn `KILL_SENT`, EOF or missing IPC into Worker exit code 0 or `WTERMSIG(SIGKILL)`. Use dedicated private owned IPC, exact parsing, bounded messages and a single terminal owner; stdout/stderr are untrusted workload bytes. A grandchild orphan is not generally waitpid-able from Gateway; `NOTE_EXIT` for one known PID and EOF cannot prove exit of every process. Unknown/detached `setsid` descendants require `UNRESOLVED/QUARANTINED` or a documented explicit out-of-scope result, never a fabricated full-tree cleanup. Do not claim general-purpose sandbox containment.

**Directory and workload binding.** Use C1's pinned directory FD and `posix_spawn_file_actions_addfchdir_np` only within synthetic roots. Authorization of ancestor paths, Pipfile binding, allowed runner executable, and mutable config race are **not proved** by this study. Never fall back to a string cwd or global `chdir` / `preexec_fn`.

**Resources.** Every startup/failure/timeout/cancel/stop transition must account for control stdin/stdout, independent stderr, kqueue watchers, directory FD, owned direct children and eventual permits/leases. An observation gap yields `BLOCK` or `NOT_RUN`, never `POSITIVE_EXPERIMENT`. No raw private paths, identifiers, stdout/stderr content or business data in public Actions logs.

## 3A. P1 closure contract — result truthfulness and Owner/reap ordering

### Worker result contract (frozen for **isolated C3**, not a product decision)

| Worker lifecycle observation | Evidence owner | Truthful C3 worker result | Cleanup/task interpretation |
| --- | --- | --- | --- |
| Parent `waitpid` observes normal exit | A: Relay; B: Controller | `OBSERVED_EXIT(code)` (including nonzero) | Only observed code may be reported; cleanup evaluated separately |
| Parent `waitpid` observes signal termination | A: Relay; B: Controller | `OBSERVED_SIGNAL(signum)` | `WTERMSIG` is evidence only when `waitpid` succeeded |
| A: group KILL kills Relay before Worker wait status is sent/committed | No remaining legitimate Worker waiter | `UNKNOWN` | Record `KILL_REQUESTED` / `KILL_SENT` separately; **never** fabricate Worker SIGKILL or successful completion |
| B: group KILL, Controller survives and reaps Worker | Controller | `OBSERVED_SIGNAL` or `OBSERVED_EXIT`, if `waitpid` succeeds | Otherwise `UNKNOWN`; B improves observability but does not guarantee it |
| Relay/Controller dies unexpectedly; IPC is lost, inconsistent, or unauthenticated | No trusted observation | `UNKNOWN` | `BLOCK/UNRESOLVED`; never upgrade a Worker terminal from output text |
| Worker exit observed but descendants/FDs/held Anchor remain unresolved | Direct parent records Worker exit, native Owner accounts for resources | Retain observed Worker result **without** claiming cleanup completed | Task cleanup separately `UNRESOLVED/QUARANTINED` |

**C3 decision:** A may be studied with `UNKNOWN` after forced group KILL; this is an **explicit research limitation**, not user approval of product result semantics. **If future G2 requirements demand an exact Worker status even after forced KILL, reject A as the primary product design and prioritize B/another group-external legitimate Worker reaper.** A prior observed and durably accepted Worker wait status remains valid even if Relay is later killed; `KILL_SENT` by itself is never a Worker observation. This separation preserves “result correct” by distinguishing *known* from *not observable*.

### Native Owner and identity state machine

| State | Authority and invariants | Permitted transition |
| --- | --- | --- |
| `NEW / SPAWNING` | Owner acquires exclusive child-wait ownership; `SIGCHLD=SIG_DFL`, `SA_NOCLDWAIT` absent; no second waiter | Spawn only within synthetic root and per-task permit |
| `ANCHOR_HELD` | Native Owner is verified parent/sole waiter; leader has verified PID=PGID, matching task, expected session, **not reaped** | Controlled handshake to `RUNNING`; no group signal from unverified state |
| `RUNNING / TERM_ELIGIBLE` | Owner serially checks deadline, owned leader state and native identity assumptions | Either lawful TERM, or `UNRESOLVED` on uncertainty |
| `TERM_SENT / KILL_ELIGIBLE` | No other `waitpid(leader)`; TERM grace bounded; verify same identity and deadline immediately before KILL | Final eligible group KILL, or no more group signals and `UNRESOLVED` |
| `SIGNALS_CLOSED` | No further negative-PGID syscall permitted, even if later reap/cleanup fails | Owner may perform final direct-child reap and FD cleanup |
| `REAPED / CLOSED` | Only the sole Owner reaped the held direct child; release resources once | Immutable terminal / separate cleanup outcome |
| `UNRESOLVED / QUARANTINED` | Lost identity, unexpected `ECHILD`/second waiter, impossible status, IPC conflict or unknown cleanup | **Zero further group signal**, preserve failure evidence; only safe direct-owned PID cleanup |

**Signal/reap serialization is a design invariant, not merely a locking suggestion.** The same Owner processes all signal requests and `waitpid(leader)` decisions in a single serialized control lane. Until `SIGNALS_CLOSED`, no other code may reap the leader, including shutdown handlers, independent cancellation tasks, process observers, asyncio watchers or a handler installing `SA_NOCLDWAIT`. Nonblocking `waitpid(...,WNOHANG)` can consume an exited child's status; once it does, identity qualification ends permanently. A relay that exits unexpectedly before a signal must not be treated as a still-live trusted anchor merely because its numeric PID remains visible as a zombie. In a product with uncontrolled competing reapers, research a separate native Owner as true parent instead of assuming a Python-level lock is sufficient.

**Darwin evidence obligation before C3-R2 claims:** Record the target macOS build and corresponding XNU source tag (review cited `xnu-11417.140.69`; confirm actual build), then record source links and relevant checks for PID allocation, occupied process/PGRP/session hashes, zombie retention, group teardown and `waitpid` reap. State the *specific interval* in which an ID is kernel-held and the exact event that ends protection. Use C3-05/06/13 deterministic barriers to seek counterexamples; repeated PID-pressure success alone is not a proof of absence of re-use. If that chain cannot be established, **G2 BLOCK** irrespective of passing isolated tests.

### Candidate B: explicit parenthood and group-join hypothesis

```text
Gateway (may launch one native Owner Helper)
└── Native Owner  [sole Anchor/Controller waiter and group-signal authorizer]
    ├── Anchor    [direct owned child, Worker group leader, held PGID]
    └── Controller Relay [different process group, stays outside Worker group]
        └── Worker  [Controller's direct child, proposed join of Anchor PGID]
            └── known synthetic descendant(s)
```

The **native Owner**, not Gateway unless Gateway itself is the direct parent, alone `waitpid(Anchor)` and `waitpid(Controller)`. The **Controller alone** `waitpid(Worker)`; Worker cannot wait/reap Anchor. Keep Anchor unreaped until `SIGNALS_CLOSED`. Controller remains outside the Worker group during TERM/KILL, so it can *attempt* Worker reap after group KILL. A valid B spawn requires existing Anchor PGID, compatible session and permissions, and Worker joining that PGID **before executing workload code** (candidate `POSIX_SPAWN_SETPGROUP`; success on real Darwin is **not assumed**). The native experiment must verify `getsid`, `getpgid`, parentage, expected group/session, and `posix_spawn` errors; intentionally test incompatible session, non-existent group and Controller premature death. An impossible/failed join -> no Worker execution or group signal and `BLOCK`.

### C3 Worker signal disposition and readiness (P2-01)

For A, Relay may install a defined TERM handler or ignore TERM to survive group TERM (research both if needed), but Worker **must not inherit** that immunity. On Darwin the proposed Worker `posix_spawn` setup explicitly calls `posix_spawnattr_setsigdefault` (include SIGTERM), `posix_spawnattr_setsigmask` (unblock SIGTERM and any undesired inherited masks), and sets `POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK` plus the intended group flag. Relay must use waitable `SIGCHLD` (default, no `SA_NOCLDWAIT`) before Worker spawn. Check all return values. The test-only Worker/Relay READY handshake must complete **before** test TERM or self-expiry timers start; independently verify Relay survives TERM and Worker uses the intended disposition. Negative control: omit each reset flag deliberately, then show the worker improperly ignores/blocks TERM and classify `BLOCK`. In B, Controller remains outside the group and Anchor's TERM behavior is frozen separately, not borrowed from A.

### Control IPC ownership, framing and terminal provenance (P2-02)

- A: the sole trusted writer is Relay; B: Controller is the sole trusted writer. Native Owner receives over a **dedicated private control FD/socketpair**, never parses workload stdout/stderr as control; worker receives no control write endpoint. Close it using `FD_CLOEXEC` **and explicit spawn file-actions close**, with an independent test that intentionally leaks a duplicate write FD and must be detected as `BLOCK`. A file descriptor inherited by an untrusted Worker is not an authenticated message.
- Minimal typed frames (bounded length, versioned, exact field set, no extraneous bytes): `RELAY_READY(version,ticket,seq,anchor_pid)`, `WORKER_SPAWNED(ticket,seq,worker_pid)`, `WORKER_REAPED(ticket,seq,worker_pid,raw_wait_status)`, `FINAL(ticket,seq,worker_result_kind,cleanup_kind)` or `UNRESOLVED(ticket,seq,reason)`. A terminal `FINAL` requires an already accepted `WORKER_REAPED` for an `OBSERVED_*` result; absent that event, only `UNKNOWN` may be emitted. `UNRESOLVED` is never successful.
- `ticket` is a non-reusable *task correlation ID only*, not a kernel identity or authentication capability. Authenticate origin by the Owner's private IPC endpoint ownership, FD non-inheritance and validated process lineage, not by untrusted fields. Sequence numbers strictly increase; duplicate/reordered/cross-task/oversize/corrupt frames fail closed. Exactly one terminal is committed by the Owner; later Relay exit or replay cannot replace it. Contradictory `FINAL`/wait observation, IPC EOF before verified evidence, half-close, Relay loss -> `UNKNOWN / UNRESOLVED` as appropriate, never `SUCCESS`.
- Freeze an explicit **two-axis result model**: `worker_result = OBSERVED_EXIT | OBSERVED_SIGNAL | UNKNOWN`; `cleanup = VERIFIED | UNRESOLVED`. `SIGNAL_REQUESTED/SENT` is a separate event, not a Worker status or terminal. Tests C3-08/09 must cover Worker forging a valid-looking `FINAL` on stdout, intentionally inherited control writer, duplicate/reordered terminal, half-close, Relay death before/after status, and a previous terminal that must remain immutable.

## 4. Mandatory test-first native evidence matrix

Design the following **negative controls first**. A Linux-only static test may prove an interface contract but may not be described as a macOS scheduler/PGID race reproduction.

| ID | Isolation scenario | Required evidence / decision |
| --- | --- | --- |
| C3-01 | Worker exits, one known child remains in original group, relay stays alive | Parent `waitpid` proves Worker exit; known descendant remains live; owned anchor/PGID and session verified. Negative: anchor exits before worker cleanup -> no group signal; unknown descendants never counted as complete |
| C3-02 | Relay receives group TERM while worker must use default TERM disposition | Positive: relay survives group TERM while Worker visibly responds under explicit `SETSIGDEF/SETSIGMASK`; negative: omit disposition/mask reset and detect TERM resistance; waitable SIGCHLD confirmed |
| C3-03 | TERM-resistant Worker and known descendant; compare A/B group KILL | Group KILL is last signal, only while leader identity is held. A: Worker wait status `UNKNOWN` if Relay dies before reap; B: external Controller tries `waitpid(Worker)`. Negative: `KILL_SENT` forged as `OBSERVED_SIGNAL` -> `BLOCK` |
| C3-04 | Relay/Anchor exits unexpectedly before Owner TERM; descendant remains | Control both exited-unreaped and reaped cases; Owner refuses group signal on failed live-identity qualification. Known surviving descendant reported `UNRESOLVED/QUARANTINED`, never finished |
| C3-05 | Relay exits between eligibility check and intended signal | Deterministic two-party event barrier: Owner qualifies → relay exits-but-unreaped → Owner rechecks and safely refuses or proves qualified; compare separate case where an **unauthorized waiter actually reaps** before signal. Record **zero unauthorized group signals**; never equate `sleep` with race proof |
| C3-06 | Competing waiter, premature reap, `ECHILD` or SIGCHLD auto-reap | Barrier forces competing `waitpid` after identity check; record who reaped, owner state and permitted signal count. Any ownership violation or `ECHILD` => `UNRESOLVED` and **zero subsequent group signals** |
| C3-07 | Timeout before/after worker spawn, after TERM and before KILL, cancel/shutdown during drain | One monotonic budget and bounded failure cleanup; no late group signaling |
| C3-08 | Known descendant closes stdout/stderr while alive; output backpressure | No premature completion; independent exit evidence and bounded both-stream drains |
| C3-09 | Control IPC corrupt/duplicated/forged/inherited | Verify FD inheritance and control writer lineage; Worker stdout `FINAL` forgery, leaked control writer, wrong ticket/seq/status, duplicate terminal, premature EOF, Relay death before status => strict reject / `UNKNOWN`; no successful task completion |
| C3-10 | Synthetic tree has an escaping `setsid` / detached child | Explicit out-of-scope report or BLOCK according to frozen policy; never falsely claim complete tree termination |
| C3-11 | Directory rename/recreate after FD pin; runner/Pipfile-like synthetic path swapped | Actual cwd dev/inode remains bound; if executable/Pipfile ownership uncertain, refuse |
| C3-12 | One-shot and sustained `EINTR`, `ECHILD`, `ESRCH`, watcher/pipe open failure | Bounded retries; no unowned PID signals; no false success; resource accounting |
| C3-13 | PID/PGID reuse, zombie retention and owned unrelated-group negative control | Source-level XNU evidence + controlled barriers for held-vs-reaped leader + isolated known unrelated group. No signal to a group after authorization loss; pressure tests can seek counterexamples but **cannot themselves prove immunity**; absent kernel identity chain => `G2 BLOCK` |
| C3-14 | Synthetic Direct and Pipenv-like paths under renamed/recreated root | Actual cwd, runner executable/Pipfile path identity, worker exit code and scope recorded; these do not yet imply production authorization |

Positive controls must include *actual normal execution* (not just a failure-triggered test) on macOS ARM64 Python 3.13 and 3.14. Each negative case needs an observable precondition and an evidence format that cannot be satisfied by TTL self-expiry, stdout EOF alone, or merely an invalid numeric argument. Use dedicated private test processes, never an existing host PID/PGID.

## 4A. Native experiment acceptance/evidence protocol

For each C3-01…C3-14 test, freeze before RED: (1) explicit positive precondition and observable original owner/parentage, (2) **same-path** adversarial counterexample, (3) timeline / barriers (not only `sleep`), (4) independent evidence of group membership and direct-parent `waitpid`, and (5) sanitized strict verdict. Public evidence may report modes, booleans, relative durations, result enums and build identifiers; never private paths, arbitrary live host PIDs, credentials or workload output.

**Typed observations:** `pid_held`, `leader_reaped`, `pgid_matches`, `same_session`, `group_signals_before_identity_loss`, `group_signals_after_identity_loss`, `worker_wait_observed`, `worker_status_kind`, `known_descendant_note_exit`, `stdout_drained`, `stderr_drained`, `ipc_writer_exclusive`, `terminal_count`, `fd_cleanup_complete`, `deadline_exceeded`, `unresolved_resources`, `xnu_identity_assumption_verified`. The experiment records a single owner-driven event order and reason for terminal classification; no forged, missing or duplicate frame may be accepted.

- `POSITIVE_EXPERIMENT`: all scenario-specific preconditions, authentic events and cleanup evidence observed, **without claiming G2**. If a forced KILL makes the Worker status unknown, a positive result can describe *correctly reported UNKNOWN*, never an invented exact exit status; the task must not be called a successful business execution.
- `SAFE_REFUSAL` / `EXPECTED_BLOCK`: expected adversarial path demonstrably rejected and no unauthorized signal sent; `UNRESOLVED` remains visible if known descendants may survive. Safe refusal is not a full cleanup proof.
- `BLOCK`: owner lost, ID kernel argument missing, unexpected group signal, IPC/wait contradiction, out-of-group descendant counted as cleaned, false observed Worker status, missed deadline or evidence gap.
- `NOT_RUN`: target Darwin/arch/toolchain or disposable isolation precondition unavailable. No `NOT_RUN` or Linux static result may become `POSITIVE_EXPERIMENT`.

**Pre-prototype critical path:** C3-03/KILL status semantics, C3-05/06/13 identity/reap ordering, C3-02 worker signal restoration, C3-09 IPC provenance and B's cross-parent PGID-join feasibility must have **falsifiable test design**. Start with a very small Owner + Anchor/Relay + Worker Darwin primitive after design approval, then incrementally add the rest. An A-only isolated pass does not qualify B, and a B fallback must undergo its own native tests. Do not run signal experiments against arbitrary host processes.

**Source checkpoints:** Apple macOS `posix_spawnattr_setsigdefault(3)`, `posix_spawnattr_setsigmask(3)` and `posix_spawnattr_setflags(3)` describe explicit Worker signal setup; see
https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/posix_spawnattr_setsigdefault.3.html ,
https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/posix_spawnattr_setsigmask.3.html , and
https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/posix_spawnattr_setflags.3.html .
The reviewer identified XNU `xnu-11417.140.69` as a potential PID/PGID retention evidence source; **verify exact release and code paths** before treating it as a qualified identity proof.

## 5. Gates and execution order

1. **C3-D0 DESIGN:** incorporate the external review findings (P1×2/P2×3), freeze exact Worker status semantics, native Owner/reap ordering, signal dispositions, IPC/FD ownership and Candidate B genealogy/session constraints. Obtain **new independent Standards/Spec PASS for the revised fixed SHA**. Read-only XNU source analysis is allowed before approval; **no C3 RED implementation or native Relay prototype until the revised design is approved.**
2. **C3-R1 RED:** on a separate research-only implementation commit, write contract and real native negative tests that initially fail because the relay mechanism does not yet exist. Record exact SHA and RED run.
3. **C3-R2 candidate:** implement minimum isolated Darwin relay and test-only runner; no Gateway product changes. Use immutable Git tree/manifest and stable fixed SHA; **never** expose commands capable of selecting arbitrary existing PID/PGID.
4. **C3-R3 native:** macOS 15 ARM64 Python 3.13/3.14, normal and negative controls with bounded synthetic self-expiry and sanitized evidence; Linux full regression, HTTP/MCP smoke, compileall, shell and MANIFEST. Distinguish hosted Mac from user's physical Mac.
5. **C3-R4 review:** independent source + original Actions logs Standards/Spec code review. A candidate native PASS remains **isolated research** until documented product G2 requirements including actual Direct/Pipenv, cwd/Pipfile binding, resource and stop paths, and approved independent qualification are completed.

**Always BLOCK:** G2 real process execution, A4 ExecSupervisor, REST/MCP Multi exec, G3 MCP 2.3.0 independent protocol gate, and G5 release. Keep all stacked research PRs Draft unless the project owner explicitly authorizes another action. Preserve prior failed evidence; do not rewrite history to claim the earlier SDK 1.30.0 contract or C2 original Leader was production qualified.
