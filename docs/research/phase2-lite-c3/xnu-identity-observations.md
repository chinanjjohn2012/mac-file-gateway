# C3: Darwin PID / PGID retention — read-only source observations

**Status: RESEARCH NOTES ONLY; not an OS identity qualification. G2 BLOCK.**
**Source reviewed:** Apple public [XNU `xnu-11417.140.69`](https://github.com/apple-oss-distributions/xnu/tree/xnu-11417.140.69), as referenced by the independent PR #22 design review. **The hosted macOS runtime build has not yet been correlated with this exact tag**; no product or non-Apple kernel guarantee is inferred.

## Direct observations from this versioned source

1. [`bsd/kern/kern_fork.c` lines 962–995](https://github.com/apple-oss-distributions/xnu/blob/xnu-11417.140.69/bsd/kern/kern_fork.c#L962-L995) runs the new PID allocator while holding the process-list lock; candidate PID rejection includes `phash_find_locked(pid)`, `pghash_exists_locked(pid)`, and `session_find_locked(pid)` (lines 977–980). This is concrete evidence the allocation path considers existing **PID / PGID / session** IDs, not just whether a process with the same PID is visible.
2. [`bsd/kern/kern_exit.c` lines 2094–2110](https://github.com/apple-oss-distributions/xnu/blob/xnu-11417.140.69/bsd/kern/kern_exit.c#L2094-L2110) moves an exiting process from `allproc` into `zombproc`, which is deliberately not visible via ordinary `proc_find`. Do not equate “not running” with “already reaped” or treat `getpgid` on an exited process as conclusive.
3. The parent-facing `waitpid`/`wait4` reap operation must be traced to the final `reap_child_locked` transition rather than inferred from an observer's `NOTE_EXIT` event. The source-level distinction between zombie and reaped is necessary but not a complete user-space group signal authorization proof.
4. [`bsd/kern/kern_exit.c` lines 2806–2833](https://github.com/apple-oss-distributions/xnu/blob/xnu-11417.140.69/bsd/kern/kern_exit.c#L2806-L2833) shows final `reap_child_locked` removes the child from the process group, calls `phash_remove_locked`, and releases the pgrp. It is a distinct stage from process exit and may alter the group-identity chain.
5. [`bsd/kern/kern_proc.c` lines 2363–2407](https://github.com/apple-oss-distributions/xnu/blob/xnu-11417.140.69/bsd/kern/kern_proc.c#L2363-L2407) maintains per-group membership and marks an empty process group. [Lines 2715–2735](https://github.com/apple-oss-distributions/xnu/blob/xnu-11417.140.69/bsd/kern/kern_proc.c#L2715-L2735) remove a destroyed process group from the group hash only when its members are empty. This must be interpreted together with the exit and reap paths, not extrapolated from the name “zombie”.

## What is not proven

- The exact kernel source/tag running on either hosted `macos-15` ARM64 job, nor equivalence to the user's own macOS system.
- Whether a **live and held**, exclusively owned group leader gives a race-free interval between user-space qualification and group signal across all required exit/reap permutations.
- That exited-but-unreaped leaders are always valid signal targets. **C3 intentionally refuses the group signal after unexpected leader exit**, even if numeric ID retention is suspected.
- That another process never reaps the anchor: the code must enforce one native Owner; a PID allocator check does not enforce user-space exclusivity.
- Generic process-tree containment, unseen descendants, `setsid` escapes, or the exact result of a group SIGKILL sent before worker wait status is observed.
- That a stress loop without observed reuse implies a mathematical proof of no reuse.

## Required falsification before any G2 claim

C3-05, C3-06, and C3-13 must use ordered event barriers to create owner-check → leader exit → no-reap / unauthorized-reap → signal eligibility transitions. Record the sole direct-child waiter, exact signal-authorization state and *zero signals after ownership loss*. Unrelated-group negative controls must use only groups created and owned by the test, never arbitrary host PIDs. A failed identity check yields `BLOCK/UNRESOLVED` and no group signal.

When C3 native CI is available, save sanitized `sw_vers -productVersion`, `uname -v`, `sysctl kern.osrelease` and compiler version. Associate the running kernel with a compatible public source *before* claiming a kernel-level ID retention argument. If the correspondence or race exclusion cannot be shown, **G2 BLOCK** regardless of partial native experiment outcomes.

**Note:** These notes use public source, not a runtime probe. They neither prove C3-R2 execution correctness nor authorize the real ExecSupervisor.
