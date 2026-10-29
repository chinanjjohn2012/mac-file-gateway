# R2-N N3-F0 FD read-only candidate r001 — independent T0-first source

**Status: PROPOSED SOURCE ONLY / NOT_T1_QUALIFIED / NOT FOR PRODUCT IMPORT**

- Repo: `chinanjjohn2012/mac-file-gateway`
- Task: `MULTI-EXEC-R2N-N3F0-PHYSICAL-READONLY-20261029`
- Review round: `r001` (new Draft PR; PR #96 r002 remains frozen)
- Fixed parent: PR #96 Head `f13a4560158b7ea6bb27b1137ab4c2e1d555e319`, Tree `9842a6aef6edd7aed162ca1f73462303415a123a`.
- Rules: `ICR-V2.0`, `GHRH-2.0`, `ETP-V2.0`; operative D0/F1/Phase1/G05/R004, fixed PR #94 r001 N3-D four-doc candidate design and PR #96 T0. Earlier role PASS is background, not current source approval.
- User scope: explicitly authorize an independent N3-F0 physical read-only adapter **source development**; the user has not selected concrete one-time Linux/macOS Runner(s), exact ephemeral paths, budgets, commands and cleanup program. Therefore actual physical T1 remains `NOT_AUTHORIZED / NOT_RUN`. No Native, T2, T3, merge or deploy.

## Source files and negative capability

- `gateway/r2n_n3f0_physical.py`: new, **unwired** physical FD-read-only candidate with `RealFDPort` (an implementation only; no OS operations at import) and `N3F0PinnedReadOnlySession.open_existing(port, trusted_control_fd, state_parent_fd, lineage_parent_fd, workspace_root_fds)`. It takes borrowed, pre-pinned FDs; no remote path, consent, profile, reset, first-install, statically approved positive Exec or subprocess API. It opens only **already existing** literal N3 child names with `O_RDONLY | O_DIRECTORY/O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC`, checks metadata, performs bounded ancestry walks, enumerates bounded entry lists, and acquires a nonblocking exclusive existing `owner.lock` for the **lifetime of the read-only session**. It releases only its owned FDs; borrowed parent/Workspace FDs belong to the caller.
- The real `RealFDPort` must **not be called** before an independently approved resource-scoped T1 with a trusted FD bootstrap. This new module is not imported or wired into `gateway/workspaces.py`, `http_multi.py`, `mcp_multi.py`, `exec_state.py`, `r2s_state_s2.py`, or the installed Runner, and no workflow is modified to invoke it.
- `N3F0PhysicalSnapshot` may only express `durability_state=unavailable`, `quarantine_reason_code=offline_authority_unverified`, `available=false`, `completion_capability=none`. Even a fully well-formed fake or future physical directory does **not** certify an external offline operator authorization chain, native backend or macOS lifetime-safe process identity. No `healthy_metadata_only` or real admission grant is possible from this candidate.
- Strictly deny: missing workspace FD inventory, incomplete/aliased parent lineage, parent/root/workspace overlap, changed inode, insecure state/lineage/owner file type/UID/0700/0600/hardlink, second owner lock, renamed/replaced lock, any boot-deny/pending/final/temp/foreign dir entry or old attempt/response, malformed/duplicate/unknown/oversize control or witness record, stale namespace/generation/owner-lock identity, quarantined or active consent. `owner-authority.v1` is read as an existing private file, but its bytes are **not** accepted as trusted authority or used to mint consent.
- Failure paths release all locally owned FDs and lock; read failures give sanitized code, do not reveal path or record content, never delete/rename/reset or retry to infer healthy state.

## Explicit unresolved design conflict requiring B/C independent adjudication

Approved N3-D **candidate** layout describes sibling directories `<private-control>/native-n3-state` and `<private-control>/native-n3-lineage` (same direct parent). The previously accepted N3-F0 T0 source at PR #96 r002 requires **different pinned state_parent and lineage_parent identities**. This code deliberately requires two distinct validated parent FDs **under a separately trusted common control anchor**, each with one fixed-name N3 root child. If the actual proposed same-parent layout is passed, it must DENY. This is NOT represented as an invisible layout amendment or an already approved T1 filesystem layout. B/C need to resolve the layout/independent witness boundary against the immutable contract before authorizing actual directory creation or claiming physical success. The code does not automatically provision either layout.

## Known physical and provenance gaps (NOT_RUN)

- No actual `RealFDPort` call, pinned FDs from a trusted Gateway bootstrap, `openat/fstat/scandir/flock/owner.lock`, platform-specific `..`/firmlink/mount semantics, concurrent same-UID rename and lock ABA, macOS owner/permission enforcement, crash/reboot/ENOSPC/physical fsync or authentic external operator/witness source has been executed or qualified. Even if tests someday establish FD proof, the same UID threat model is NOT a cryptographic rollback guarantee.
- No physical private files/directories created, modified or deleted. No Live Gateway, Worker, Native, official SDK/REST/MCP, real Git/File, staging/untracked/import-shadow audit, installer/wheel/RECORD, system-wide regression, macOS runner or process signal performed.
- The candidate returns only **unavailable** after structural read; no positive state is reachable. The previous physical T0 fake port `N3F0OfflinePrivateFSAdapter.open_physical_private_store` at PR #96 still always throws `N3F0NotAuthorized`; this is deliberately **not replaced** or wired.

## Actual developer T0 execution

- Exact newly authored source `gateway/r2n_n3f0_physical.py` and test `tests/test_r2n_n3f0_physical_t0.py`; current frozen parent GitHub sources are only fixed Git Blob reference, not imported or tested in this isolated T0 run.
- Linux x86_64 / CPython 3.13.5, `PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 python3 -B -I -S tests/test_r2n_n3f0_physical_t0.py -v`: **40 methods executed, 40 PASS, exit 0**, using the in-memory `FakeFDPort` only. No real `RealFDPort` or N3 private filesystem opened; this does **not** qualify OS behavior.
- Original per-method stdout/stderr and pre/post sha256 + `git hash-object` for the tested files are in `docs/evidence/R2N_N3F0_FD_R001_DEVELOPER_T0_20261029.log`, after the final test source patch. The earliest harness iteration used fake string FD tokens while the API requires integer FDs, producing test-failure noise before the test fixture was repaired; that mismatch does not count as a physical-source failure or as a qualifying RED. No r001 historical PASS is borrowed.

## Proposed, *not yet approved*, concrete T1 one-time Runner resource budget

| Field | Proposed exact authorization value; **not effective until separately accepted** |
| --- | --- |
| Runner | One GitHub-hosted ephemeral Linux x86_64 `ubuntu-24.04` job **first**. A separate macOS 15 ARM64 GitHub-hosted job only after verifying available exact runner label and additional authorization. No user Mac, Tunnel, self-hosted or shared runners. |
| Checkout | Exactly the new Draft PR frozen Head and Tree; compare synthetic Merge separately. G05 source admission **before any external dependency/install/project import**; stdlib-only subset does not silently waive a mandatory full installed R004 claim. |
| Fixture roots | A fresh job-exclusive `${RUNNER_TEMP}/n3f0-t1/<run-id>-<run-attempt>-<random>` under verified non-symlinked job temp. Separate private control/state-parent/lineage-parent+workspace roots whose dev+ino are logged privately. No user paths; no existing N3/v1/S2 state. Actual instance path must be resolved and checked against the exact job-specific approval before creation. |
| Total budget | Max **32 MiB** scratch fixture bytes, **64 open FDs** attributable to tests, **1 service/test instance**, no more than 4,096 records/entries, max 4,096 bytes per control record. Concurrency 1. No actual destructive disk filling. |
| Duration/watchdog | GitHub job `timeout-minutes: 10`, internal harness soft limit 4 minutes with graceful timeout/exit only; external hosted runner/job cancellation authority designated before run. No `kill`, PID/PGID signaling, forced restart, power cut or VM crash. |
| Allowed operations | Newly approved path-identified fixture provision only; `open(O_NOFOLLOW/O_DIRECTORY/O_CLOEXEC)`, `fstat`, bounded `scandir`/`read`, nonblocking `flock` of *existing* `owner.lock`, FD close, read-only boot checks. Negative injection via test substitute only. No N3 journal writes/rename/fsync until separately expanded approval. |
| Executable commands | G05 approved admission command (to be pinned to selected hosted workflow); `python3 -B -I -S tests/test_r2n_n3f0_physical_t0.py -v`; a new explicitly reviewed, resource-bounded `python3 -B -I -S tests/test_r2n_n3f0_physical_t1.py -v` after independent code review. Never invoke real Native or Git subprocess as a proxy. |
| Post-test | Capture bounded sanitized raw logs, executed source SHA256/Blob, exact fixture inode list; close all owned FDs and lock; remove **only** approved nonce fixture after verifying original inode ownership and no unknown file/process. On uncertainty STOP cleanup and allow ephemeral runner retirement, preserve forensic metadata. |

This table is a **request for explicit user confirmation, not a retroactive grant**. Resolve the physical layout conflict and submit a separately reviewed T1 fixture runner, exact test script, version+source identity and user decision before any physical T1 call. A proposed GitHub Actions workflow is **NOT added or launched** in this source-only PR.

## Developer handoff and STOP

Request two independent SHA-bound B/C full-bounded source/T0 reviews for this fixed new PR, including deliberate counterexamples for ancestor renames, lock FD leak, wrong operator authority, direct control vs Workspace overlap, and missing state/witness. Even independent B/C `ROLE_FULL_SCOPE_PASS` would be bounded to this T0-tested source candidate only; physical T1 code and production integration remain separate gates. No automatic merger, deploy, Native Exec, T2/T3, local Mac/Tunnel, quota-based deletion or UNKNOWN clearing.
