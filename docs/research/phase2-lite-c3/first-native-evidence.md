# C3-R1/R2 first native Owner/Relay primitive — evidence and limits

**Status: initial isolated prototype evidence only; G2 BLOCK.**
**Design approval:** PR #22 at `a7cd33d2b6f4cbe48b5db41b8f0a3f51a44e109e`; external targeted Standards/Spec design re-review reported PASS **only for permission to conduct C3 research**.
**Research PR:** [#24](https://github.com/chinanjjohn2012/mac-file-gateway/pull/24) (Draft, stacked on PR #22). Neither PR is authorized for product merge.

## Immutable first-stage checkpoints

- **RED:** `748530efe3dd0053aac0ddfb6001902ad432a179`, [Linux Actions #39508286652](https://github.com/chinanjjohn2012/mac-file-gateway/actions/runs/39508286652): **6 failed / 863 passed / 8 skipped / 1 warning**. Five failures concern as-yet-absent C3 driver/native source; one was the XNU-notes literal `waitpid` omission, corrected rather than misrepresented as a native bug. The dedicated RED macOS jobs failed before a native candidate existed. RED is contract-first, **not proof of an actual Darwin race**.
- **First native candidate:** `558e315a1d01f5b8f30bab4ce1eb0b132e1893cc`, [Linux #39509066218](https://github.com/chinanjjohn2012/mac-file-gateway/actions/runs/39509066218): **869 passed / 8 skipped / 1 warning**, HTTP/MCP smoke, Python compileall, shell and Manifest PASS.
- **Native macOS:** [#39509066205](https://github.com/chinanjjohn2012/mac-file-gateway/actions/runs/39509066205): `macos-15` ARM64 Python 3.13 and 3.14 both PASS, each running eight C3 research contract tests and six *real synthetic native process* cases. These first-stage outcomes are `PARTIAL_NATIVE_C3_ONLY_NOT_G2`, `g2_qualified=false`.
- **Observed runner kernel:** `Darwin Kernel Version 24.6.0`, `xnu-11417.140.69.711.44~1` on the hosted macOS 15 ARM64 runners. This is **more specific** than the published `xnu-11417.140.69` source tag used for the preliminary code reading; treat them as distinct, not proven identical. Exact build-to-source verification remains open.

## What the six native scenarios actually demonstrated

| Mode | Observed research verdict | Narrow property only |
| --- | --- | --- |
| `term-default` | `POSITIVE_EXPERIMENT` / `OBSERVED_SIGNAL` / `VERIFIED` | Owner issued group TERM with retained Relay, a Worker whose SIGTERM default/mask were set via spawn attributes exited by TERM, and its legitimate Relay parent reported `waitpid` |
| `kill-unknown` | `POSITIVE_EXPERIMENT` / `UNKNOWN` / `UNRESOLVED` | Owner issued TERM→final group KILL to a still-owned group; **Relay died too**, so no Worker wait status was fabricated. Known Worker NOTE_EXIT is not arbitrary descendant cleanup |
| `leader-exit` | `SAFE_REFUSAL` / `UNKNOWN` / `UNRESOLVED` | Relay intentionally exited and was reaped before a group signal; Owner refused numeric PGID fallback |
| `competing-reap` | `EXPECTED_BLOCK` / `UNKNOWN` / `UNRESOLVED` | Research-only competing waiter thread consumed direct Relay status; Owner observed `ECHILD` and stopped group signaling |
| `ipc-forgery` | `EXPECTED_BLOCK` / `OBSERVED_EXIT` / `VERIFIED` | Worker printed a forged `FINAL` to stdout; only a private Relay-writer IPC channel carrying a legitimate Worker `waitpid` result influenced the outcome |
| `identity-loss` | `SAFE_REFUSAL` / `UNKNOWN` / `UNRESOLVED` | Explicitly cleared Owner signal admission before any group signal; not a real PID/PGID collision or reuse reproduction |

Native code is limited to private disposable directories with `C3_TEST_MARKER`, a fixed executable compiled inside the same directory, a fixed mode allowlist, child-only group signals, separate Worker readiness/arm handshakes, and a bounded cooperative worker TTL. The compiler-generated C stub returns `C3_NOT_RUN_NON_DARWIN` on Linux; the driver returns `C3_NOT_RUN_NON_DARWIN` without side effects.

All cases are reported independently of product Gateway, and the research protocol forbids passing an arbitrary PID/PGID, business command, Workspace path or existing process. The original control-channel protocol is a deliberately small unversioned candidate for the primitive; it is **not** the complete versioned/ticketed C3 design IPC contract.

## Unclosed C3 / G2 obligations

The six modes are **not** completion of C3-01…C3-14. Explicitly unproven: C3-05 check→exit / reap event-barrier competition, C3-13 real kernel ID retention/reuse identity guarantee, Candidate B group-outside Controller/Anchor and cross-parent PGID joining, fully versioned authenticated IPC, duplicate/reordered terminal controls, descendant `setsid` escapes, robust independent both-stream backpressure/FD-leak audits, native cancellation/shutdown error paths, Direct/Pipenv real workload and pinned cwd authorization (G2 integration), and process-tree-wide termination.

The C3 native Owner continues to use a numeric PGID after a user-space qualification check. Its single-Owner control rule is a **research hypothesis and limited synthetic observation**, not an atomic kernel authorization or a proven absence of PID/PGID reuse. The XNU source/tag correspondence must be checked before any stronger claim.

**Next step:** independent read-only Standards/Spec code review of an updated **fixed Head** and original macOS logs; then targeted RED / deterministic-barrier research for C3-05/06/13 and separate Candidate B feasibility. An independent PASS for this small candidate would still be research-only, not G2.

**Never enabled:** real ExecSupervisor, REST/MCP Multi exec, G3 qualification, release branch merge or running Gateway changes. G2/G3/G4/G5 BLOCK.
