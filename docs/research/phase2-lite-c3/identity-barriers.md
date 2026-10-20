# C3-05 / C3-06 / C3-13 — identity barriers, research contract

**State:** contract-first isolated research, **NOT a G2 qualification**.
**Parent:** PR #24 at `e2bfc52fe029c3f0cfd78f622bb6ddaa743ab8ee` (six native A-like cases, first prototype; independent code review remains pending).
**Planned branch:** `research/phase2-lite-c3-identity-20261021`.
**Prior design approval:** PR #22, `a7cd33d2b6f4cbe48b5db41b8f0a3f51a44e109e` Standards/Spec PASS for limited isolated C3 study, **not production**.

## What this increment can and cannot observe

| Mode | Setup barrier / independent evidence | Required result |
| --- | --- | --- |
| `exit-unreaped` (C3-05) | Owner verifies directly owned live group leader, registers kqueue `NOTE_EXIT` first, *then* permits child's synthetic exit, consumes exit event before any final signal eligibility check. No Owner `waitpid` precedes the event. | `SAFE_REFUSAL`; zero group signals, owner finally reaps its own exited child. This is a deterministic check → exit → second check interleaving, **not atomic kernel check-and-signal immunity**. |
| `competing-reap` (C3-06) | Owner first qualifies leader, then explicitly releases a research-only sibling waiter thread to consume **that very child's** `waitpid`; parent must independently observe `ECHILD` on the original child after the thread joins. | `EXPECTED_BLOCK`; no group signal after ownership loss, no PID fallback, final child reaped by test waiter, Owner's `owner_reaped=0`. This simulates a forbidden competing reaper for negative proof; production must forbid it outright. |
| `group-isolation` (C3-13 partial positive) | Owner creates *two* fresh private synthetic group leaders in the test (target and canary), validates their distinct PGID/session identities, signals **only** target group while its leader remains live, reaps target, independently confirms canary remains alive and lets canary exit on its private control byte. | `POSITIVE_EXPERIMENT` scoped to separation of **two owned synthetic groups**, not numeric PGID reuse and not a guarantee under adversarial scheduling. |
| `stale-after-reap` (C3-13 partial negative) | Owner first reaps a separate synthetic leader, retains stale numeric PID strictly as an invalid record, keeps a freshly owned canary group live, checks that no group signal can issue using stale authority. | `EXPECTED_BLOCK`, canary alive, zero group signals, `reuse_proven=0`. **Not** a true reused PID/PGID observation. |

All tests use **processes spawned inside their own private, fresh, marker-verified root**; no business Workspace, arbitrary existing PID/PGID, reusable command string, Gateway runtime or real user process. Only test-owned group signal in the healthy `group-isolation` mode; all other modes prohibit group signals. Failure cleanup may use only a verified directly owned, still-unreaped synthetic PID; any `ECHILD` means no direct PID kill. Child exits on EOF or a bounded self-expiry; the runner uses per-case timeouts. Do not attempt to force kernel numeric PID reuse by increasing pressure or target another process's ID.

## Frozen evidence shape and gate

`C3_ID_RESULT mode=<fixed> exit_observed=<0|1> owner_reaped=<0|1> group_signals=<0|1> after_loss_signals=0 canary_alive=<0|1> refused=<0|1> reuse_proven=0`

The Python driver accepts only one **exact** result line, rejects duplicate/spoofed/truncated lines and extra fields, and publishes sanitized enumerated case labels. `exit_observed` refers to `NOTE_EXIT` in C3-05 and verified direct-child termination in the other modes; a `NOTE_EXIT` event alone does not tell whether a non-child descendant has exited or a worker's exit code. The test must reveal enough source-level ordering to avoid a fabricated precondition passing.

`SAFE_REFUSAL` and `EXPECTED_BLOCK` prove only the *specific refusal*. `POSITIVE_EXPERIMENT` is scoped to two fresh groups created by this helper. `BLOCK` and `NOT_RUN` never qualify G2. The strict result includes `reuse_proven=0` by design. A later TRUE PID/PGID reuse claim requires an independently verified Darwin kernel identity chain across user-space check → kernel group-signal admission; stress alone is not sufficient.

## Darwin source hypothesis (requires independent review)

Apple public [`xnu-11417.140.69`](https://github.com/apple-oss-distributions/xnu/tree/xnu-11417.140.69):
- [`kern_fork.c` lines 962–995](https://github.com/apple-oss-distributions/xnu/blob/xnu-11417.140.69/bsd/kern/kern_fork.c#L962-L995) calls `phash_find_locked`, `pghash_exists_locked`, `session_find_locked` while selecting a new PID.
- [`kern_exit.c` lines 2094–2110 and 2806–2833](https://github.com/apple-oss-distributions/xnu/blob/xnu-11417.140.69/bsd/kern/kern_exit.c#L2094-L2110) distinguish exiting `zombproc` transition from final reap/group removal.
- [`kern_proc.c` lines 2715–2735](https://github.com/apple-oss-distributions/xnu/blob/xnu-11417.140.69/bsd/kern/kern_proc.c#L2715-L2735) destroys an empty pgrp and removes its hash entry.

The observed hosted runner kernel was `xnu-11417.140.69.711.44~1` / Darwin 24.6.0, **not exactly** the public tag above. Matching full release code and proving a non-reusable retained live group identity until syscall admission are NOT_PROVEN. Even the success of all tests leaves **G2 BLOCK**; it does not show true PID/PGID collision resistance under simultaneous exit and unrelated group creation.

## Development and independent review gate

1. Record RED Linux contract failures at a fixed SHA; absence of the helper is expected, not a Darwin bug.
2. Add only the minimal synthetic C/Python identity helper. macOS-15 ARM64 Python 3.13/3.14 must both run the **real C** tests, with explicit exit observation, competing wait, group isolation and stale refusal; Linux pytest, HTTP/MCP smoke, compileall, Manifest must pass.
3. Independently inspect the fixed native source **and raw CI logs** before treating this research increment as closed. No sign-off is inferred from author-generated PASS labels.
4. Candidate B, complete C3-01…14, uncooperative detached descendants, Direct/Pipenv real binding, full IPC and shutdown are separate, not automatically allowed.

**Never enabled:** G2, G3 MCP SDK 2.3.0 protocol gate, ExecSupervisor, REST/MCP Multi exec, deploy or release; all stacked research PRs stay Draft.
