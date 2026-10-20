# Phase 2 Lite C2 — owned PGID and descendant experiments

**RESEARCH ONLY. G2 BLOCK. NOT A RUNNABLE PRODUCT FEATURE.**
This is a second isolated C1/G2 experiment stacked on [PR #18](https://github.com/chinanjjohn2012/mac-file-gateway/pull/18), in [PR #20](https://github.com/chinanjjohn2012/mac-file-gateway/pull/20).
The original `release/ms1` baseline uses official MCP SDK 2.3.0. No installed SDK, Gateway code, business Workspace, active process or configuration is touched.

## Specific questions and controls

An ephemeral private temporary directory contains a same-UID, mode-0700 synthetic test marker, a copied self-expiring Python child, and a local C helper compiled in place. The helper refuses unmarked directories, foreign-owned roots, symlinks at the final root component and non-regular or multiply-linked children. It uses `posix_spawn_file_actions_addfchdir_np` with a pinned synthetic directory FD, `POSIX_SPAWN_SETPGROUP`, a stdin start barrier, `getpgid`, `waitpid`, and one *exclusively owned* direct-child leader PID.

For **synthetic groups only**, TERM / KILL are sent by negative group PID *only after* the single owner verifies that the directly spawned, still-unreaped group leader is currently live, has the expected PGID, and remains the owned leader. Group signaling is deliberately refused after the leader has been reaped or when the expected identity is incorrect. This is **not** permission to implement generic `killpg(pgid)`. On setup errors or timeouts the only fallback is a bounded, direct PID signal to a still-unreaped owned child. Every synthetic descendant has a bounded self-expiry even if the experiment owner fails.

The helper reads an exact, one-line readiness handshake from its synthetic descendants and then drains the inherited stdout pipe to EOF. It cannot `waitpid` orphaned grandchildren, and pipe EOF alone is not proof of arbitrary descendant cleanup.

| Case | Intended invariant | Expected status |
| --- | --- | --- |
| `term` | Live owned anchor + descendant; TERM group, no KILL, owner reaped, pipe EOF | `POSITIVE_EXPERIMENT` |
| `kill` | TERM-resistant anchor and descendant; verify still live and escalate KILL, reap/drain | `POSITIVE_EXPERIMENT` |
| `worker-first` | Intermediate workload leader exits and is reaped; original group anchor stays live; TERM then drain | `POSITIVE_EXPERIMENT` |
| `leader-exit` | Original group leader exits *and is reaped* while a grandchild remains; refuse all group signals; bounded self-expiry | `SAFE_REFUSAL` |
| `stale` | Still-live anchor supplied with an intentionally invalid expected identity; refuse signals and self-expire | `SAFE_REFUSAL` |
| `close-stdout` | Synthetic TERM-resistant descendant closes stdout while alive; independent witness prevents false positive | `EXPECTED_BLOCK` |

These outcomes are *anticipated contracts*, not proof until native Actions logs are captured. The extra failure controls are designed to fail closed; the experiment deliberately does not attempt to force real PGID reuse or address processes outside the synthetic owned group.

## Test and evidence procedure

The RED commit introduces the contract before implementation. On a fixed source HEAD:

```sh
python3 -m pytest -q tests/test_c2_pgid_probe.py
# Native macOS arm64, Python 3.13+ and a working cc:
PRIVATE_DIR=$(mktemp -d)
chmod 700 "$PRIVATE_DIR"
python3 tools/research/run_c2_pgid_probe.py --evidence-dir "$PRIVATE_DIR"
```

The native workflow `.github/workflows/c2-native-research.yml` tests Python 3.13 and 3.14 on `macos-15` ARM64. It does not upload private JSON or private paths. Exit 0 is **PARTIAL_NATIVE_OBSERVATION_NOT_G2** only if all five statuses match their strict contracts. Exit 2 means `BLOCK_NATIVE_EXPERIMENT`; exit 3 means `NOT_RUN`. Linux contract tests do not count as native acceptance. GitHub-hosted macOS evidence is not the user's own Mac.

## Critical limitations and next gate

Even if all five cases pass, **G2 is still BLOCK**. The test does not prove real PID/PGID reuse, identity behavior under hostile external signals, a kernel-held stable group capability, a detached descendant, Direct/Pipenv and Pipfile binding, permissions of real Workspace ancestors, process ownership after Gateway cancellation/shutdown, full stdout/stderr drain, FD/permit release or OS sandboxing. A process that leaves a group is outside group-based cancellation. The work also does not prove `waitpid` works on grandchildren (it usually does not) or authorize *production* signals based only on an integer PGID.

Require independent source/security review of the exact tested SHA and real Mac failure/positive cases before G2. MCP 2.3.0 G3 stays independent. **ExecSupervisor, REST Multi /run, MCP Multi run_command, merge/deploy/enable remain BLOCK.**

## Independent review finding status (2026-10-20)

The fixed C2 review returned **CONDITIONAL**, NOT G2. A standalone C Helper must explicitly use
a waitable `SIGCHLD` policy: `SIG_DFL` and no `SA_NOCLDWAIT`, with one owner of
`waitpid`; the research process must never change the live Gateway's process signal policy.
The new isolated signal probe synthetically injects `SIG_IGN` and `SA_NOCLDWAIT` *inside its own
test process* before resetting them. This is **not** evidence of inheritance across `exec`
and never proves the group check-to-signal operation atomic.

The existing `stale` case checks an **invalid expected identity** (the caller supplies zero).
It is **not a PGID reuse test**. Thus, successful refusal proves neither reuse protection nor
that an unrelated process group can never receive a signal. Actual reuse and atomic ownership
remain unproved, and C2's intentional fail-closed behavior after the original leader exits
still cannot satisfy real Gateway cancellation.

A separate independent descendant-exit witness and a false-EOF native negative control
are required before the C2 research finding can be closed. Neither the `SIGCHLD` follow-up
nor CI GREEN alone grants G2, G3, ExecSupervisor, merge, deploy or Multi exec activation.

## T02/T03 independent descendant exit and causality research

**New negative-case rule:** stdout EOF and the direct Leader's SIGTERM exit code cannot
establish termination of an orphaned descendant. The native C2 Helper registers
`EVFILT_PROC / NOTE_EXIT` for the **single known synthetic descendant PID**, while that
descendant is still blocked on a second stdin arm byte. Only after successful
registration does the helper send `A`, at which point the synthetic TTL can start.
This avoids the registration-vs-self-expiry race in this particular cooperative test;
the event is a process-exit observation, **not** an atomic PGID identity credential
or reliable exit status for arbitrary non-child processes.

Positive cases require both independent descendant exit notification and stdout
EOF. A single monotonic deadline starts **before sending the arm byte** and caps the
entire signal, drain, witness and direct-Leader reap path (including escalation).
The synthetic positive-case TTL is 5 seconds after the arm is received, while the
positive proof deadline is 2.5 seconds from arm emission. A delayed scheduling
path therefore BLOCKS rather than attributing eventual self-expiry to TERM/KILL.

The adversarial `close-stdout` control has exactly one synthetic descendant
install SIGTERM ignore and close its own stdout after the arm. The independently
owned Leader still receives TERM, its inherited stdout pipe reaches EOF, but a
valid pre-registered NOTE_EXIT witness has **not** fired and the descendant is
still in the group. This is an intentional **`EXPECTED_BLOCK`**, never a success
signal for termination; the test also waits for bounded synthetic self-expiry
after recording the negative evidence.

Only the synthetic PID is monitored. Observation of one descendant's NOTE_EXIT
does not imply all arbitrary descendants exited; a process escaping its group,
closing an inherited descriptor, or executing untrusted Workspace code is not
covered. The `stale` case still checks an invalid expected identity, **not PGID
reuse**. The original Group Leader's premature exit still prevents safe production
group cancellation, and a trusted Relay remains a separate G2 research topic.

**Gate:** C2 T02/T03 native outcomes are limited experimental observations;
independent code review and macOS lifecycle verification remain mandatory.
**G2 BLOCK; G3 separate; ExecSupervisor and REST/MCP Multi exec BLOCK.**

## Round 2 review repairs: six-case primary suite and fault controls

**Review input:** PR #21 fixed `fb28130626d0d0dbec4b3c3316421ddd2ebf05db`
was independently assessed as Standards CONDITIONAL, Spec FAIL: P2-01
user-space deadline before TERM/KILL, P2-02 a shared-success-path false-EOF
negative control with mutation proof, P2-03 bounded failure cleanup and EINTR
faults, and P3-01 obsolete five-case descriptions. This section states the
**research contract**; implementation must be verified against a new exact SHA
and native macOS logs before claiming these findings closed.

The **six-case primary suite** is `term`, `kill`, `worker-first`,
`leader-exit`, `stale`, `close-stdout`. The additional review fault modes
are not silently counted as original primary cases.

- **Deadline before every group signal.** The Helper checks the monotonic arm
  deadline before TERM, before KILL, and within the owned-group signaling
  function immediately before the kernel call. `deadline-before-term` releases
  the synthetic process then injects a 3-second pause against a 2.5-second
  deadline. It may return `EXPECTED_BLOCK` only if **zero group signals** were
  sent, the directly owned Leader was accounted for, and the known synthetic
  descendant's eventual exit was independently witnessed. This is a
  user-space admission gate, **not** an atomic kernel identity guarantee or
  proof of bounded scheduler latency between check and syscall.
- **Same positive branch / mutation.** `term-false-eof` uses the normal TERM
  success path while its single known synthetic descendant ignores TERM,
  closes stdout and remains alive. Missing `NOTE_EXIT` must lead to
  `EXPECTED_BLOCK` after safe synthetic cleanup; it must never produce
  `C2_RESULT`. A throwaway test compilation with
  `C2_TEST_OMIT_POSITIVE_WITNESS` intentionally removes the positive guard.
  `run_mutation_check` requires it to demonstrate the would-be false positive
  **only in this synthetic environment**; the unmodified binary is required
  to reject the same observation. The mutant is never installed in Gateway.
- **Fault cleanups.** `fault-register`, `fault-before-arm`, and
  `fault-after-arm` inject failures around exit watcher ownership and the
  arm barrier. The single owner must not emit a success result; the cleanup
  path may use a *directly owned, still-unreaped child PID* for bounded
  fallback, never an unchecked process group. It must account for each opened
  FD and the single known descendant's `NOTE_EXIT` before issuing the
  strict `EXPECTED_BLOCK` evidence. If registration cannot be established
  or cleanup cannot be observed, the result stays `BLOCK` /
  `cleanup_incomplete`, without upgrading unverified cleanup to success.
  The `fault-waitpid-eintr` and `fault-kevent-eintr` synthetic modes
  require bounded retry rather than unexpected termination; these are
  research-only fault hooks.
- **Boundaries.** `waitpid` cannot reap an arbitrary grandchild; observing
  one known descendant is not proof all descendants have exited. Event
  registration, deadline checks and a retained Leader PID do not establish
  immunity to PGID reuse or atomically protect a later group signal.

The old `c2-native-research.yml` on PR #20 is intentionally branch-scoped
and may be skipped on PR #21. **Only the new `c2-review-native.yml`**
provides PR #21's expanded native review evidence.

**Release gates:** research CI results are not an independent safety review;
G2 remains BLOCK, the Leader/Relay architecture gate remains unresolved,
and G3 MCP SDK 2.3.0 is a separate protocol gate. No ExecSupervisor,
REST/MCP Multi exec, deployment or release activation is permitted.
