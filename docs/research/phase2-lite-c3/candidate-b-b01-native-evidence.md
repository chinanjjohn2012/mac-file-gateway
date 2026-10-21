# C3 Candidate B B-01 — Darwin cross-parent PGID join: isolated evidence (NOT G2)

**Status: AUTHOR-VALIDATED NATIVE FEASIBILITY ONLY; INDEPENDENT STANDARDS / SPEC CODE REVIEW PENDING.**  
**Base design:** [PR #28](https://github.com/chinanjjohn2012/mac-file-gateway/pull/28), fixed `e5b8093a51a83e9dffd529282f990ad46a8880e5`; independent *design* Standards PASS / Spec PASS, two P3 refinements for the RED contracts.  
**Implementation:** [PR #29](https://github.com/chinanjjohn2012/mac-file-gateway/pull/29), Draft, stacked **on PR #28**, not on PR #24 or PR #26 implementation trees.  
**Native code first candidate:** `496757788d98316ea3d50f4bf1eeac302617e080`. The final documentation-only Head will require its own CI and separate immutable review.  
**Product baseline:** `release/ms1` and MCP SDK 2.3.0 unchanged.

## Test-first RED (genuine negative contract, not Darwin race)

- **RED commit:** `9c0fbf151b3d1a989bd2e168027961a04c5758de`.
- [macOS ARM64 RED #39531632846](https://github.com/chinanjjohn2012/mac-file-gateway/actions/runs/39531632846): **Python 3.13 and 3.14 each 5 failed, 2 passed**, due to deliberately absent C/driver implementation. The separate PR run [#39531670988](https://github.com/chinanjjohn2012/mac-file-gateway/actions/runs/39531670988) preserved the same missing-contract failure class.
- [Linux RED #39531670833](https://github.com/chinanjjohn2012/mac-file-gateway/actions/runs/39531670833): **5 failed, 862 passed, 9 skipped, 1 warning**. This did not reproduce a Darwin kernel race or prove group isolation.

## First actual Darwin native GREEN

- [macOS ARM64 push #39532112789](https://github.com/chinanjjohn2012/mac-file-gateway/actions/runs/39532112789): Python **3.13 and 3.14 both SUCCESS**, each **7 passed**, five native cases executed in the same controlled script. Native runner returned `C3B_NATIVE_RESULT=PARTIAL_B01_NATIVE_NOT_G2`.
- [macOS ARM64 PR #39532117515](https://github.com/chinanjjohn2012/mac-file-gateway/actions/runs/39532117515): both versions SUCCESS on the same implementation commit.
- [Linux #39532117585](https://github.com/chinanjjohn2012/mac-file-gateway/actions/runs/39532117585): **867 passed, 9 skipped, 1 warning**; smoke/compileall/Manifest checks succeeded.
- Native public logs sanitize identifiers, paths and payloads. **No `Terminate orphan process:` line** occurred in the two original successful push Jobs. This is evidence of cleanup in these runs, not a general-purpose leak audit.

| Fresh synthetic B-01 mode | Observed flags in BOTH native versions | Narrow verdict |
| --- | --- | --- |
| `join-positive` | `anchor_held=1`, `sid_distinct=0`, `attempted=1`, `worker_started=1`, `join_verified=1`, `grant=1`, `gate=1`, `workload=1`, `controller_waited=1`, `cleanup=1` | `POSITIVE_EXPERIMENT`: Controller's direct Worker was joined to Owner-held Anchor PGID by `posix_spawnattr_setpgroup` and later reaped by Controller. |
| `owner-reject-missing` | `anchor_held=0`, `attempted=0`, `worker_started=0`, `gate=0`, `cleanup=1` | `EXPECTED_BLOCK`: Owner first reaped its own Anchor, checked that its PID had become unavailable, then explicitly refused Worker spawn before Controller creation. |
| `join-nonexistent` | `anchor_held=0`, `attempted=1`, `worker_started=0`, `gate=0`, `cleanup=1` | `EXPECTED_BLOCK`: unlike Owner pre-rejection, Controller actually called `posix_spawn` for an **already reaped** self-owned Anchor's missing PGID; native spawn refused. |
| `join-cross-session` | `anchor_held=1`, `sid_distinct=1`, `attempted=1`, `worker_started=0`, `gate=0`, `cleanup=1` | `EXPECTED_BLOCK`: Controller genuinely called `setsid()` and changed SID *before* it attempted the native existing-group join; spawn refused. This is not a simulated EPERM. |
| `gate-denied` | `anchor_held=1`, `attempted=1`, `worker_started=1`, `join_verified=1`, `grant=0`, `gate=0`, `workload=0`, `controller_waited=1`, `cleanup=1` | `EXPECTED_BLOCK`: correct kernel join and actual Controller parentage observed, but its intentionally corrupted reported PPID failed independent Owner validation; gate stayed closed and Worker was legitimately reaped. |

## Actual authentication/observation path under study

```text
Fresh Owner -> held Anchor (Anchor PID == PGID, Session == Owner)
            -> external Controller (Owner's other direct child, own PGID)
                -> posix_spawn(Worker, POSIX_SPAWN_SETPGROUP=Anchor PGID)
                    -> Worker READY [still behind read-only execution gate]
                <- Controller checks live getpgid, getsid and Worker self PPID
            <- Controller's dedicated private proposal pipe
            -> Owner independently calls getpgid(worker), getsid(worker),
               proc_pidinfo(PROC_PIDTBSDINFO) for kernel PPID/PGID,
               checks live Anchor and real Controller session
            -> Owner emits only possible G grant on private input pipe
                -> Controller forwards G or rejection N to Worker
                    -> Worker creates C3B_WORK_STARTED marker ONLY after G
                <- Controller alone waitpid(its direct Worker)
            <- Owner receives typed Controller final and waits its own
               direct Controller / Anchor children before recording result
```

**Important distinctions:** Darwin `struct proc_bsdinfo` provides kernel PPID and PGID; this experiment obtains the independent SID via `getsid()`, not via a nonexistent `pbi_sid`. Numeric PID/PGID fields and Controller-sent proposal values are *not durable kernel authorization tokens*. The Owner checks actual kernel parentage at the controlled ready gate before emitting G; this is a held synthetic timing experiment, not an atomic identity handle.

All tested executables are the same compiled C helper under a fresh user-owned 0700 temporary root with test marker. There is **no negative-PGID signal syscall** anywhere in the B-01 helper, no external existing process ID or command argument, no direct Host kill, and no access to a real Workspace, Pipfile, service, database or Gateway. The study does not exercise TERM/KILL, B-02/B-03, real application runtime, generic IPC framing/forgery, detached descendants or full stderr/stdout drain.

**Residual, non-closed obligations:** Cross-parent Join did succeed on the hosted Darwin build observed here, but B-01 does not prove check→signal atomicity, true PID/PGID numerical reuse protection, all path-inheritance safety, the stronger B-05 control-channel trust model, arbitrary Worker/Controller crash recovery, full-process-tree exit, stream drain or independent OS FD auditing. `cleanup=1` covers these specific cooperative synthetic direct-child waits and Controller's one Worker `waitpid`, not universal containment. B-02 and B-03 remain **BLOCK until B-01 exact-Head independent native code review**.

**Decision:** `PARTIAL_B01_NATIVE_NOT_G2`, `reuse_proven=false`, `g2_qualified=false`. No real ExecSupervisor, REST/MCP Multi exec, G2/G3/G4/G5 activation, release branch merge, or Gateway restart. Keep PR #28/#29 Draft. Independent Standards / Spec **code** re-review must inspect the exact new PR #29 Head, Native C spawn/parentage/gate paths, test negative controls, Manifest, original Actions logs and cleanup semantics before formally closing B-01.

## P3-02 pre-spawn mutation audit (separate RED→GREEN)

The first `join-nonexistent` / `join-cross-session` experiment reported `spawn_attempted=1` at the call-site wrapper entry, which could also cover failed FD/file-actions setup **without** actually reaching `posix_spawn()`. That observation was too broad for the independent B-D0 design review's P3-02 “negative precondition versus actual syscall failure” contract. This was repaired **before final sign-off**, not silently counted as Darwin evidence.

- **Additional RED** commit `37db6ad12ce756e609055f198726b1fb44a0a9f3`: [Linux #39532552696](https://github.com/chinanjjohn2012/mac-file-gateway/actions/runs/39532552696) **1 failed / 867 passed / 9 skipped / 1 warning** on the missing direct-syscall marker. [Native ARM64 #39532552644](https://github.com/chinanjjohn2012/mac-file-gateway/actions/runs/39532552644) **2 failed / 6 passed** on each Python version: missing pre-spawn accounting and absent mutation evidence.
- **Repaired candidate** `42ff63cf6df68414ce8990d7c2857bd1ccaa25d0`: C `spawn_role` sets `spawn_invoked` **immediately before** the real Darwin `posix_spawn`, and records the native syscall return code. Controller sends a distinct failure class for a real `posix_spawn` error versus pre-syscall setup failure. The two negative modes only pass as `EXPECTED_BLOCK` when an **actual** native spawn attempt failed.
- **Mutation counterexample:** a separate, test-only binary built with `C3B_FAULT_PRESPAWN` explicitly skips `posix_spawn` for the Worker. It still forms a Controller proposal but reports `spawn_invoked=0`; the Owner must reject the negative control rather than accept it. The process returns `C3B_BLOCK phase=typed_outcome` with one precisely sanitized `C3B_MUTATION ... invoked=0 ...` record. The runner demands that exact pair and records `mutation_detected=true`.
- [Native ARM64 GREEN #39532830939](https://github.com/chinanjjohn2012/mac-file-gateway/actions/runs/39532830939): **Python 3.13 and 3.14 both SUCCESS, 8 passed each**, `C3B_MUTATION_DETECTED=true` and `PARTIAL_B01_NATIVE_NOT_G2`. [PR-native GREEN #39532837800](https://github.com/chinanjjohn2012/mac-file-gateway/actions/runs/39532837800) also SUCCESS for both versions. The five original B-01 modes retain their original outcomes. This does NOT model every possible Darwin kernel error; it specifically blocks pre-spawn test false positives.

The repaired C/runner remains **synthetic, no negative-PGID signals, no production code**. This new targeted evidence is still *author-side research* pending independent Standards / Spec fixed-Head review. G2 BLOCK, B-02/B-03 BLOCK, no real Executor.
