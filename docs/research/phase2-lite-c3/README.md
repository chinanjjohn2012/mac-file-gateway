# Phase 2 Lite C3 — 常驻 Leader / Relay 原生安全资格设计（草案）

**Status: DESIGN ONLY / NOT APPROVED FOR IMPLEMENTATION. G2 BLOCK.**
**Prepared: 2026-10-21.**
**Parent fixed commit:** `f5e7e6eba40d0987974e4b72df6fd2ccc0f0f42f` (PR #21, C2 isolated research).
**Proposed C3 branch:** `research/phase2-lite-c3-relay-20261021`.
**Product baseline:** `release/ms1` at `ba8634f24cdc26904d1c80951df7173e429240c7`, official MCP SDK 2.3.0.

This file is a **candidate research design**, not code approval, product G2 qualification, or a safe supervisor implementation. It must undergo independent Standards / Spec design review before creating a native relay prototype. No current Gateway service, REST/MCP tool, real Workspace, Pipfile, app configuration, or production process is modified.

## 1. Evidence boundaries inherited from C1/C2

- PR #18 / C1: synthetic Darwin ARM64 `posix_spawn_file_actions_addfchdir_np` with a pinned directory FD, creation-time PGID, and rename/recreate positive controls. C1 is a narrow OS primitive observation, not generic cwd authorization or G2.
- PR #20 / C2: a single owner of an *original unreaped direct-child group leader* can safely refuse unsafe group signals after leader loss. Its `stale` case deliberately injects an invalid expected identity, **not numeric PID/PGID reuse**.
- PR #21 / C2 review fixes at the fixed parent: third independent review reports **Standards PASS / Spec PASS limited to isolated research**, with bounded signaling deadlines, independent `NOTE_EXIT` for one known synthetic descendant, normal-path false-EOF mutation, and failure cleanup/EINTR negative tests. Hosted macOS 15 ARM64 Python 3.13.15/3.14.7 passed. The recorded outcome is still `PARTIAL_NATIVE_OBSERVATION_NOT_G2` and `g2_qualified=false`.
- C2 proves neither that arbitrary descendants have exited nor that an original workload group leader remains usable after the workload exits. PID and PGID are numeric identifiers, **not durable ownership tokens**. Do not infer an atomic check-and-signal guarantee from `getpgid`.

## 2. C3 question, scope and non-goals

**Question:** Can a *trusted resident group leader / relay* remain an exclusively owned, live, unreaped signal anchor while it supervises Direct/Pipenv-like disposable synthetic work that may exit before its own descendants? Can the external sole owner perform bounded TERM→KILL without signaling an unrelated process group, even when cancellation races relay termination?

C3 may research a C or POSIX-native synthetic relay, a test-only Python workload and a Darwin-only probe in a disposable private directory, with no business data. **Do not** integrate real ExecSupervisor, use production Gateway/Popen, enable Multi `/run`, register MCP `run_command`, change MCP SDK, restart running Gateway, or modify `release/ms1`.

C3 should choose between and explicitly test:
- **Candidate A — Relay as dedicated process-group leader:** parent owns a direct relay child created into a fresh group; relay stays resident and launches a worker in that group, captures worker status, and emits a typed bounded result over a private control channel. Relay must not voluntarily exit before the sole owner completes cancellation/cleanup evidence. Relay's signal behavior and worker default dispositions must be separately proven, not merely assumed.
- **Candidate B — External control relay with separately held group anchor:** a separately owned unreaped group-leader child is kept alive while an out-of-group controller supervises worker/status. This has more identity and IPC edges. Keep as an alternative until native comparative evidence; do not silently label A safe without a B check.

A relay in the same group **may receive group TERM/KILL itself**. Therefore, Candidate A needs experimental evidence for TERM surviving at the relay without inadvertently making worker/descendants TERM-resistant, and for KILL ending the relay without allowing later numeric group signals. Relay worker and child signal masks/dispositions must be deliberately established. The test must detect unauthorized relay exit, not reclassify it as success.

## 3. Safety invariants to freeze in design review

**Identity and ownership.** Only one owning process controls spawn, signal, direct-child wait/reap and permit lifetime. The owner tracks one task-specific relay PID and a non-reusable internal ticket. The relay is a *verified, still-owned, still-unreaped direct child* and original PGID leader. A cached PGID, a second waiter, a subprocess PID discovered by scanning, or a control-message field can never authorize group signaling. At every group signal, the owner checks both its deadline and the currently permitted identity path. Identity lost or relay reaped => **no negative-PGID signal**; fail closed / quarantine the unresolved job. Whether the live owned leader prevents PID reuse until group signaling is complete is a **native kernel-semantics hypothesis to prove**, not a signed-off property.

**Termination lifecycle.** Owner's monotonic timer covers spawn/handshake, cancellation, TERM grace, KILL escalation, pipe drain, direct-child wait, and cleanup; use stage budgets within a single bounded outer lifetime. TERM must not destroy the last owned anchor before KILL can safely be considered; if this guarantee fails, refuse escalation and report BLOCK. No `killpg(pgid)` or `kill(-pgid,...)` fallback after identity loss; no signal to an unknown PID/PGID. KILL is terminal for the relay and worker group; do not send any group signal afterward.

**Truthful result and descendant policy.** Worker exit code must be independently captured by its legitimate parent relay, separately from relay's own exit and the Gateway-side stdout/stderr pipes. A relay-composed status is not itself authenticated merely because it appears on stdout: use dedicated owned IPC, exact parsing, bounded messages and a test-only trust contract. A grandchild orphan is not usually `waitpid`-able from Gateway; `NOTE_EXIT` for one known PID and EOF cannot prove exit of every process. Explicitly specify what counts as success, unresolved descendants, detached `setsid` work, and owner quarantine. Do not claim general-purpose sandbox containment.

**Directory and workload binding.** Use C1's pinned directory FD and `posix_spawn_file_actions_addfchdir_np` only within synthetic roots. Authorization of ancestor paths, Pipfile binding, allowed runner executable, and mutable config race are **not proved** by this study. Never fall back to a string cwd or global `chdir` / `preexec_fn`.

**Resources.** Every startup/failure/timeout/cancel/stop transition must account for control stdin/stdout, independent stderr, kqueue watchers, directory FD, owned direct children and eventual permits/leases. An observation gap yields `BLOCK` or `NOT_RUN`, never `POSITIVE_EXPERIMENT`. No raw private paths, identifiers, stdout/stderr content or business data in public Actions logs.

## 4. Mandatory test-first native evidence matrix

Design the following **negative controls first**. A Linux-only static test may prove an interface contract but may not be described as a macOS scheduler/PGID race reproduction.

| ID | Isolation scenario | Required evidence / decision |
| --- | --- | --- |
| C3-01 | Worker exits, one known child remains in original group, relay stays alive | Owner still has a valid held anchor; cancellation TERM→KILL and observed known descendant exit, direct relay reap; `POSITIVE_EXPERIMENT` only with full evidence |
| C3-02 | Relay receives group TERM while worker must use default TERM disposition | Relay survival before possible KILL; worker/known descendant exit as intended; improper inherited ignore => `BLOCK` |
| C3-03 | TERM-resistant worker and descendant, KILL needed while relay anchor is live | Check identity/deadline immediately before KILL, exactly one allowed group KILL, no further group signal; bounded termination / `POSITIVE_EXPERIMENT` |
| C3-04 | Relay exits unexpectedly before owner TERM, synthetic descendant remains | `SAFE_REFUSAL` for group signal; identify unresolved descendant, never count as completed job |
| C3-05 | Relay exits between owner eligibility check and a scheduled group signal | Negative control must demonstrate *no unauthorized group signal* or label design `BLOCK`; never use an arbitrary integer as a claimed race proof |
| C3-06 | Owner erroneously reaps relay first, sibling waiter calls `waitpid`, or owner loses terminal record | Exclusivity violation yields `BLOCK`/quarantine without PGID fallback |
| C3-07 | Timeout before/after worker spawn, after TERM and before KILL, cancel/shutdown during drain | One monotonic budget and bounded failure cleanup; no late group signaling |
| C3-08 | Known descendant closes stdout/stderr while alive; output backpressure | No premature completion; independent exit evidence and bounded both-stream drains |
| C3-09 | Control IPC corrupted, duplicated, reordered, half-closed or forged by worker | Exact reject; no transition to successful result or leaked signal permission |
| C3-10 | Synthetic tree has an escaping `setsid` / detached child | Explicit out-of-scope report or BLOCK according to frozen policy; never falsely claim complete tree termination |
| C3-11 | Directory rename/recreate after FD pin; runner/Pipfile-like synthetic path swapped | Actual cwd dev/inode remains bound; if executable/Pipfile ownership uncertain, refuse |
| C3-12 | One-shot and sustained `EINTR`, `ECHILD`, `ESRCH`, watcher/pipe open failure | Bounded retries; no unowned PID signals; no false success; resource accounting |
| C3-13 | PID/PGID reuse pressure and negative-control unrelated process group | Credible native identity witness and absence of cross-group signals, or **explicit G2 BLOCK** if unprovable |
| C3-14 | Synthetic Direct and Pipenv-like paths under renamed/recreated root | Actual cwd, runner executable/Pipfile path identity, worker exit code and scope recorded; these do not yet imply production authorization |

Positive controls must include *actual normal execution* (not just a failure-triggered test) on macOS ARM64 Python 3.13 and 3.14. Each negative case needs an observable precondition and an evidence format that cannot be satisfied by TTL self-expiry, stdout EOF alone, or merely an invalid numeric argument. Use dedicated private test processes, never an existing host PID/PGID.

## 5. Gates and execution order

1. **C3-D0 DESIGN:** create this research-only design; independent Standards/Spec review, compare Candidates A/B, freeze signal ownership, IPC, descendant policy and fail-closed evidence. **No C3 native prototype until this design is approved.**
2. **C3-R1 RED:** on a separate research-only implementation commit, write contract and real native negative tests that initially fail because the relay mechanism does not yet exist. Record exact SHA and RED run.
3. **C3-R2 candidate:** implement minimum isolated Darwin relay and test-only runner; no Gateway product changes. Use immutable Git tree/manifest and stable fixed SHA; **never** expose commands capable of selecting arbitrary existing PID/PGID.
4. **C3-R3 native:** macOS 15 ARM64 Python 3.13/3.14, normal and negative controls with bounded synthetic self-expiry and sanitized evidence; Linux full regression, HTTP/MCP smoke, compileall, shell and MANIFEST. Distinguish hosted Mac from user's physical Mac.
5. **C3-R4 review:** independent source + original Actions logs Standards/Spec code review. A candidate native PASS remains **isolated research** until documented product G2 requirements including actual Direct/Pipenv, cwd/Pipfile binding, resource and stop paths, and approved independent qualification are completed.

**Always BLOCK:** G2 real process execution, A4 ExecSupervisor, REST/MCP Multi exec, G3 MCP 2.3.0 independent protocol gate, and G5 release. Keep all stacked research PRs Draft unless the project owner explicitly authorizes another action. Preserve prior failed evidence; do not rewrite history to claim the earlier SDK 1.30.0 contract or C2 original Leader was production qualified.
