# C3-05/06/13: identity barrier native evidence (NOT G2)

**State:** author-verified isolated Darwin native research; independent Standards / Spec code review REQUIRED.
**Research PR:** [#26](https://github.com/chinanjjohn2012/mac-file-gateway/pull/26), Draft, stacked on [PR #24](https://github.com/chinanjjohn2012/mac-file-gateway/pull/24).
**Experiment source candidate:** `e9178bf95ef0d0e74932bcfb6a72ee1d0a9dd2f9`.
**Design authority:** PR #22 fixed `a7cd33d2b6f4cbe48b5db41b8f0a3f51a44e109e`, independent Standards/Spec design review PASS **only for isolated study**.
**Baseline first C3 A-like prototype:** PR #24 fixed `e2bfc52fe029c3f0cfd78f622bb6ddaa743ab8ee`, already running six synthetic cases, product G2 still BLOCK.

## Test-first RED evidence

- **RED fixed SHA:** `b9b146e866977de47e4deb071ded3648b8c9a7e7`.
- [Linux controlled-exec-tests #39512819674](https://github.com/chinanjjohn2012/mac-file-gateway/actions/runs/39512819674): **5 failed, 870 passed, 8 skipped, 1 warning**. Failures are missing C3 identity driver/native C, not genuine Darwin races or source regressions.
- [Native macOS #39512819695](https://github.com/chinanjjohn2012/mac-file-gateway/actions/runs/39512819695): ARM64 Python 3.13 and 3.14 **each 5 failed / 1 passed** before implementation. No C3 identity native binary existed for these RED jobs.
- Historical RED logs must not be removed or reinterpreted as kernel-signal failures.

## First GREEN candidate native evidence

- **Fixed implementation SHA:** `e9178bf95ef0d0e74932bcfb6a72ee1d0a9dd2f9`.
- [Linux controlled-exec-tests #39513201442](https://github.com/chinanjjohn2012/mac-file-gateway/actions/runs/39513201442): **875 passed, 8 skipped, 1 warning**; HTTP and MCP smoke, Python compileall, shell and Manifest checks completed successfully.
- [macOS ARM64 native matrix #39513201522](https://github.com/chinanjjohn2012/mac-file-gateway/actions/runs/39513201522): Python **3.13 / 3.14 both PASS**. Each native job contains 6 C3 identity contract tests and four real synthetic process cases, with explicit per-mode lines. `PARTIAL_C3_IDENTITY_NOT_G2`, `g2_qualified=false`.
- Runner `uname -v`: Darwin 24.6.0 `xnu-11417.140.69.711.44~1` (hosted macOS-15 ARM64). Public XNU tag `xnu-11417.140.69` is available but is **not byte-for-byte proven equivalent** to this installed kernel; no exact `xnu-11417.140.69.711.44` tag was found during this review.

| Native synthetic mode | Observed per-mode public evidence (each of both versions) | Narrow claim |
| --- | --- | --- |
| `exit-unreaped` | `SAFE_REFUSAL`, `refused=1`, `group_signals=0`, `after_loss_signals=0`, `reuse_proven=0` | kqueue `NOTE_EXIT` was registered before releasing the directly owned leader. An event arrived before its final eligibility check, causing `waitpid(WNOHANG)` to reap and refuse signaling. No atomic check→syscall guarantee. |
| `competing-reap` | `EXPECTED_BLOCK`, `refused=1`, `group_signals=0`, `after_loss_signals=0`, `reuse_proven=0` | A test-only sibling pthread actually `waitpid`-reaped the same direct child. The Owner subsequently observed `ECHILD` and refused; this violation of sole Owner is intentionally **not allowed in production**. |
| `group-isolation` | `POSITIVE_EXPERIMENT`, `refused=0`, `group_signals=1`, `after_loss_signals=0`, `reuse_proven=0` | Helper spawned two *owned synthetic* group leaders; only the target group received TERM while a separate canary was verified alive, then the canary exited cooperatively. |
| `stale-after-reap` | `EXPECTED_BLOCK`, `refused=1`, `group_signals=0`, `after_loss_signals=0`, `reuse_proven=0` | Owner reaped a prior synthetic leader, deliberately retained its invalid numeric ID as a test record, and refused further group signaling; a distinct canary remained live. This does **not** reproduce numerical PGID reuse. |

The C3 identity helper uses a private marker-verified synthetic directory, its own compiled test binary, explicit `POSIX_SPAWN_SETPGROUP`, FD-pinned synthetic cwd, `SIGCHLD` waitable defaults, bounded private handshakes and a research-only competing waiter. The Python runner accepts only strict, sanitized, exact one-line records; no caller-supplied existing PID, PGID, command, business path or production endpoint is accepted.

## Unresolved obligations and precise interpretation

1. **C3-05 remains a controlled *ordered interleaving*, not the same nanosecond window as a kernel `kill(-pgid,...)` admission following a user-space eligibility check.** A process could still exit or be reaped in that interval; an external user-space lock cannot render the syscall atomic with identity checks. The observed safe refusal after NOTE_EXIT does not prove correctness under every scheduling race.
2. **C3-06** shows that an actual second `waitpid` can destroy the Owner's identity qualification. It supports the sole-native-Owner architecture as a testable contract, but does not prove all external library reapers are excluded in a real Gateway.
3. **C3-13 remains partial.** Two fresh, disjoint owned groups and refusal of an intentionally stale value are important positive/negative controls, **not** a real numeric PID/PGID collision or a kernel lifetime proof. Every case has `reuse_proven=0`; any future qualification would need a separately reviewed kernel argument or stronger native primitive.
4. Evidence from one directly owned Leader, one competing waiter and one owned canary does not establish arbitrary descendant management, generic process containment, detached `setsid` behavior or complete stdout/stderr/FD draining.
5. Candidate B (out-of-group Controller with held Anchor), cross-parent Worker PGID-join, versioned private IPC provenance, true Direct/Pipenv authorization, Workspace/permit/shutdown integration, and independent code-review acceptance are **not covered**. They remain separate research or G2 steps.

**Research decision:** `PARTIAL_C3_IDENTITY_NOT_G2`. No `G2 PASS` label, no merge/deploy/real ExecSupervisor or REST/MCP Multi exec, no Gateway restart. The next required gate is an **independent, read-only Standards / Spec code review** of the final PR #26 exact Head, changed native C/driver/contract and original Actions logs. The reviewer may find further blocking issues even though the author's CI is GREEN.
