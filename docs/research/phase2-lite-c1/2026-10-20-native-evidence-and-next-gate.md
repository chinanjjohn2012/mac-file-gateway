# C1 native descriptor-cwd experiment: evidence and next gate

**Status: POSITIVE_EXPERIMENT for a narrow OS primitive only; G2 BLOCK.**
Research date: 2026-10-20. This is author-run evidence, NOT an independent security/architecture review.

## Fixed, reproducible evidence

- Repository: `chinanjjohn2012/mac-file-gateway`, PR #18 (Draft).
- Source and workflow commit tested: `e1c936c2197e320ada6e4ec738a8454d574d6506`.
- Base: `release/ms1` at `ba8634f24cdc26904d1c80951df7173e429240c7`, MCP SDK 2.3.0.
- macOS run: https://github.com/chinanjjohn2012/mac-file-gateway/actions/runs/39415289963
- Linux regression run: https://github.com/chinanjjohn2012/mac-file-gateway/actions/runs/39415289945
- Hosted runner: `macos-15` (native Apple Silicon arm64), image `macos-15-arm64/20260907.0337`.
- Python matrix: 3.13.15 and 3.14.7. Both jobs completed successfully.
- Linux: 835 passed, 8 skipped, 1 warning; HTTP, MCP HTTP/stdio/disconnect, compileall, shell syntax and Manifest all passed.

| Host and Python | normal (cwd + initial PGID + owned reap) | race (rename/recreate + pinned inode) | Verdict |
| --- | --- | --- | --- |
| macOS 15 arm64, Python 3.13.15 | POSITIVE_EXPERIMENT | POSITIVE_EXPERIMENT | PARTIAL_NATIVE_OBSERVATION_NOT_G2 |
| macOS 15 arm64, Python 3.14.7 | POSITIVE_EXPERIMENT | POSITIVE_EXPERIMENT | PARTIAL_NATIVE_OBSERVATION_NOT_G2 |

The helper opened a synthetic directory with `O_DIRECTORY|O_NOFOLLOW`, validated an owned test marker,
passed the open FD to `posix_spawn_file_actions_addfchdir_np`, and requested `POSIX_SPAWN_SETPGROUP`.
Before releasing the synthetic child via its stdin handshake, the helper checked `getpgid(child_pid)==child_pid`.
The child then reported its actual cwd dev/inode and PGID; the parent reaped the one owned child with `waitpid`.
In the race case, the old directory was renamed and the original pathname recreated; the child still reported
its original directory identity, not the replacement.

No project/workspace root was accessed by the experiments. Private JSON evidence was ephemeral and not uploaded.
The public CI log includes only sanitized decision and per-case status. These were GitHub-hosted native Mac VMs,
not a run on the user's own Mac, and they do not establish platform equivalence beyond the recorded matrix.

## Explicitly unproved

- Actual authorized Direct and Pipenv runners, real Pipfile/workspace association, and process startup from Gateway.
- Parent-component symlink/path-substitution risks: `O_NOFOLLOW` on one final directory component does not
  by itself prove safe resolution of every ancestor or binding back to the authorized Workspace root.
- Leader exits before descendants, process-group identity after leader exit, and PGID reuse safety.
- Safe TERM then KILL, complete descendant termination, output readers, timeout/cancel/shutdown, and release of FDs,
  directory leases and execution permits.
- Production adapter correctness, G3 MCP SDK 2.3.0 protocol qualification, and independent review.

## Proposed identity/termination experiment (NOT an approved implementation)

1. Do not treat an integer PGID, `killpg(pgid)` or `kill(-pgid, sig)` alone as ownership proof.
   Model an **owned group-anchor capability** with an exclusively owned original leader PID and a single
   waiter/signal owner. Verify its kernel group identity before any possible group signal.
2. Test two designs on disposable synthetic processes: (A) an original leader kept unreaped through group
   termination, using a non-reaping exit notification; (B) a trusted resident leader/relay that stays alive
   while it supervises a worker in the same dedicated group. Neither is accepted merely by design.
3. Prove on macOS that the chosen anchor remains unambiguously owned even if the workload leader exits.
   In particular, check if a not-yet-reaped leader really prevents PID/PGID reuse on this OS, whether
   `getpgid` works for that state, and that no `poll`/`waitpid` elsewhere can consume its status.
   A stored start time or repeated PID lookup alone is NOT an atomic kernel identity handle.
4. For a *synthetic group only*, run a cooperative grandchild that outlives its immediate parent. Check
   leader-first exit, group membership, a bounded TERM grace, bounded KILL escalation, direct-child reap,
   and eventual pipe EOF. Group signals may be considered only under a proved live/held anchor and
   immediately verified invariants; if identity is unknown, STOP without group signaling, not fallback.
5. Inject stale anchors, lost ownership, already-reaped leader, unexpected group/session changes,
   timeouts and cancellation. Assert that no unowned process receives a signal, with a single owner of
   wait/signal/FD/drain/permit operations and no retries of real spawn.
6. Distinguish **termination of in-group descendants** from OS-level `waitpid` reaping: on macOS a Gateway
   process cannot ordinarily `waitpid` arbitrary non-child grandchildren. A child deliberately detaching
   into another session/group is outside plain process-group containment. Do not claim a hostile sandbox.
7. Run on a real Mac as well as a hosted macOS runner. Require negative controls, explicit ownership
   proofs, independent security and architecture review, and a separately approved G2 verdict.

## Gate decision

The descriptor-based cwd and creation-time PGID primitives warrant further controlled research.
**C1 OS primitive = POSITIVE_EXPERIMENT; overall G2 = BLOCK; A4 ExecSupervisor = BLOCK; G3 = independent;
REST/MCP Multi exec activation = BLOCK; G5 release = BLOCK.**
