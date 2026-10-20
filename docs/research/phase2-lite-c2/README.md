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
