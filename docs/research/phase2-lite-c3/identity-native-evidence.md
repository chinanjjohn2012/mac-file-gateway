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

## PR #26 independent review P2x3 — targeted fixes (2026-10-21)

The independent reviewer inspected fixed Head `49fd538ec8c8c6e39e958d9f49dc654dde4aa57a` and returned **Standards CONDITIONAL / Spec FAIL, P2×3**. This appendix records *author-side* repairs and native evidence. **The reviewer has not independently re-signed the revised code.**

| Finding | Narrow targeted repair and failure guard |
| --- | --- |
| P2-01: successful `kill(-PGID)` accounting obscured unauthorized attempts returning `ESRCH` | `group_signal_attempt()` increments `group_attempts` and `after_loss_attempts` **before** the syscall. A fault-only test binary compiled with `C3_ID_TEST_KILL_STUB` injects an illegal attempt after losing synthetic ownership; it returns `ESRCH` **without calling Darwin kill(-PGID)**. The strict fault parser requires attempts=1, late attempts=1 and returns `EXPECTED_BLOCK` (failure correctly recognized). A separate deliberately broken compile omits pre-call accounting and must be detected, with `mutation_detected=true`. |
| P2-02: default SIGPIPE could abort Owner before cleanup | The standalone Owner sets a verified `SIGPIPE=SIG_IGN`; synthetic child spawn explicitly restores default SIGPIPE to avoid accidental inherited immunity. The child closes its control-read FD before Owner writes; actual `EPIPE` is observed, converted to `C3_ID_BLOCK`, and its direct child is reaped. |
| P2-03: unbounded `pthread_join`, contested child PID fallback | Owner sets `ownership_contested/lost` **before** creating any second waiter, and never sends a direct PID or PGID signal to that contested child. The research waiter is detached, uses heap-owned arguments and writes a bounded completion record to a separate private pipe. On failed READY or simulated result read, Owner closes the gate first and awaits the known completion within the **original outer monotonic deadline**; a deliberately shortened phase timeout cannot extend this deadline. A known direct child with no competing waiter can be reaped via bounded **waitpid-only** cleanup after gate EOF, with no signal. No unbounded `pthread_join` remains. |

### Additional RED → GREEN evidence

- First targeted **RED** Head `13409d36d4ebd24e4e02d5654a28b5589426f30b`, [Linux #39517235347](https://github.com/chinanjjohn2012/mac-file-gateway/actions/runs/39517235347): **5 failed, 876 passed, 9 skipped**; [macOS #39517235413](https://github.com/chinanjjohn2012/mac-file-gateway/actions/runs/39517235413) confirms the missing C/runner contracts fail on ARM64 3.13/3.14. These RED failures were not real Darwin PGID reuse.
- First repair candidate `2edea570c9d60f1adbe5cc52bbd255a1455da352`: macOS [#39517790489](https://github.com/chinanjjohn2012/mac-file-gateway/actions/runs/39517790489) had green fault contracts and mutation detection, **but runner post-job logs reported termination of orphaned synthetic children**. This intermediate outcome was **not accepted as final cleanup qualification**.
- Cleanup-specific **RED** Head `6cb696b4a34b4b5e2dc0a1761206b02a69ecd611`, [Linux #39518034068](https://github.com/chinanjjohn2012/mac-file-gateway/actions/runs/39518034068): **2 failed, 879 passed, 9 skipped**, targeting the unproven cleanup witness. Native [#39518034012](https://github.com/chinanjjohn2012/mac-file-gateway/actions/runs/39518034012) likewise rejected the stricter contract.
- Repair + updated assertion at `b53f86ca017b3abcb113452a156a950dab083b60`: [Linux #39518320693](https://github.com/chinanjjohn2012/mac-file-gateway/actions/runs/39518320693) **881 passed, 9 skipped, 1 warning**, HTTP/MCP smoke, compileall, shell and Manifest PASS; [macOS ARM64 #39518320723](https://github.com/chinanjjohn2012/mac-file-gateway/actions/runs/39518320723) **both Python 3.13/3.14 PASS, 13 tests per version**. Both original native Job logs show **no `Terminate orphan process:` records** in the Actions cleanup step.

### Native fault-mode evidence at the repaired code tree

| Fixed isolated mode | Expected rejection | Evidence in both native versions |
| --- | --- | --- |
| `fault-unauthorized-esrch` | `EXPECTED_BLOCK` | `attempts=1`, `after_loss_attempts=1`, `pid_signals=0`, `cleanup_complete=1` (simulated ESRCH, never a real stale-PGID syscall) |
| `fault-broken-pipe` | `EXPECTED_BLOCK` | real `epipe=1`, `pid_signals=0`, `cleanup_complete=1` |
| `fault-waiter-ready` | `EXPECTED_BLOCK` | `waiter_done=1`, `pid_signals=0`, `cleanup_complete=1` after broken READY stage |
| `fault-waiter-timeout` | `EXPECTED_BLOCK` | inner timeout injects a failed stage; separate completion is subsequently observed **within the original overall 5s bound**; `waiter_done=1`, `cleanup_complete=1`, no direct PID signal |
| `fault-waiter-result` | `EXPECTED_BLOCK` | a deliberately injected receive-stage `EIO` happens **before consuming** the event; cleanup reuses the private reader, `waiter_done=1`, `cleanup_complete=1`. This is **not** a real lost-FD or kernel `read` error reproduction. |

All five fault results have `after_loss_attempts=0` except the **instrumented** illegal-attempt negative control (where it must equal 1), and all have `pid_signals=0`. Native logs explicitly contain `C3_ID_FAULT_MUTATION_DETECTED=true`. The earlier four C3-05/06/13 scenarios remain unchanged; the only positive group signal occurs in the test-created `group-isolation` case. Both native versions still report `reuse_proven=0`, and `g2_qualified=false`.

**Evidence limits:** The native result flags are test-Helper observations and do not constitute a general independent file-descriptor audit, kernel-atomic signal admission, exact XNU version match, arbitrary process-tree cleanup or Direct/Pipenv/Gateway lifecycle proof. Unexpected future timeout or missing completion remains a **BLOCK**; the bounded cleanup guarantee is for these specific test-owned synthetic child cases. These repairs remain subject to **new independent read-only Standards / Spec code re-review on the next fixed Head**, not self-certified P2 closure. G2/ExecSupervisor/G3/G4/G5 remain BLOCK; keep PR #26 Draft.
