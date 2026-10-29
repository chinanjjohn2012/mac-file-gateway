# R2-N N3-F0 r001: isolated read-only private-state adapter scaffold (T0 only)

**Status: candidate source for independent B/C code review, NOT physical private-FS implementation qualification.**

- Task: `MULTI-EXEC-R2N-N3F0-T0-20261029`
- Parent: PR #95 r005 frozen Head `3479f6732c1ac357eac701871d3800adc9ab64c7`, Tree `ef26195e711e936f2ebf4aff224a7bbdcdce270d`.
- Rules: `ICR-V2.0` / `GHRH-2.0` / `ETP-V2.0`.
- Scope: new `gateway/r2n_n3f0_offline.py`, one `tests/test_r2n_n3f0_offline.py`, this note, original T0 evidence and updated Manifest. No edits to live Gateway, v1 state, S2, N2, N3-M, workspaces configuration, executor, native backend, REST/MCP, Git/File, dependencies or CI.
- Authority: approved PR #94 N3-D design fixed blobs `9e8bc0ad24dcee303e3d0a5d34e4abb08f31660d`, N3 sequence `980585e656e8f6f3b4c0dd4a2deb11ec4e5fb909`, resources `be8db259ddb18a5708f9e51bef80232441d68a67`, recovery `930f08510ddc06e1be915996de69f98f606b33a2`; operative D0/F1/Phase1/G05/R004 unchanged.

## Implemented in this FIRST T0-only F0 increment

The adapter accepts an immutable **synthetic** projection of separately pinned control-root metadata, exclusive owner-lock identity, directory entry names, and existing (modeled) N3 control and lineage-witness JSON bytes. It performs deterministic strict bounded parsing and fail-closed boot-scan checks. The only nominal well-shaped outcome is `healthy_metadata_only`, which **always** has `available=False`, `completion_capability=none`, and `t0_model_only=True`. A caller cannot turn it into a positive Native privilege.

The physical FD entrypoint `open_physical_private_store` **always throws `N3F0NotAuthorized`**. There are no `os`, `fcntl`, `subprocess`, `socket`, `signal`, or filesystem imports and no `open`, lock, `fsync`, rename, unlink, process start, signal, network or Git/SDK action. The observation flags and projected inode fields are **test data and are not evidence of real ownership, parent pinning, OS directory modes, root independence, physical durability or independently authorized operator provisioning**. They MUST NOT be populated from REST/MCP or used in production admission.

Positive modeled case: existing separately described state+lineage roots, non-overlapping pinned parents, current single-link `owner.lock` inode identity and fake exclusive claim, exact bounded `native-n3-v1` control and `native-n3-lineage-v1` witness, empty attempt/response lists, no boot-deny; returns only `healthy_metadata_only`, never Exec-ready. All ambiguous state, unknown file names, pending/final/temp or boot-deny marker, stale identity, missing namespace/witness, lock mismatch, corrupt or old v1/S2 fields, retired tombstones and active consent deny or quarantine. Both state and lineage missing are **never** treated as a new install.

This T0 scaffold deliberately has **no real FD implementation, no persistent witness provisioning, no actual lock acquisition/recovery, no fsync/rename/journal/quota mutation, no physical boot scan, no process/descendant ownership proof, no transport ACK, no Live WorkspaceService integration and no N3-F1 or N3-A features**. Reuse of the approved N3-M contract is conceptual; no N3-M source/test file changed and no previous PASS is inherited as current F0.

## Source-static contract / T0 matrix

| Family | Expected modeled decision | Evidence |
| --- | --- | --- |
| Correct bounded metadata | `healthy_metadata_only`, always no Exec | original T0 01/14/32 |
| Missing both roots or separate witness | unavailable, no automatic initialization | T0 04-08 |
| Workspace overlap, no pinned parent, lock ABA, second owner, type/mode/hardlink | unavailable | T0 09-14 |
| Missing/extra/duplicate paths, pending/final/boot-deny, old attempts/response | quarantined | T0 15-18, 30 |
| Strict JSON, old schema, unknown/duplicate, nonfinite, typed mismatch, size/quota | quarantined | T0 19-22, 29 |
| Namespace/generation mismatch, lock identity mismatch, prior quarantine/consent/tombstone | quarantined | T0 23-28 |
| No physical capability escape, static forbidden imports | rejected / no I/O imported | T0 02-03, 31-32 |

## Executed vs prohibited tests

- Developer T0 executed on isolated Linux x86_64 CPython 3.13.5, `PYTHONDONTWRITEBYTECODE=1 python3 -B -I -S ... -v`, 32 actual unit methods, original stdout/stderr and exact source SHA256/Git Blob pre/post in `docs/evidence/R2N_N3F0_R001_T0_20261029.log`.
- All **physical** private-FS tests are `T1 NOT_RUN/NOT_AUTHORIZED` until separately approved exact disposable root/runner, T1 command list, cleanup and raw logs. Hosted GitHub CI and full checkout G05, wheel/RECORD and current N3-M 79-run **NOT_RUN on this new Head** unless later actually executed. Historic #95 tests remain fixed old-Head background only.
- N3-F1 actual durable pending/final fences, `fsync`, ENOSPC and forensic reservations remain `NOT_RUN/NOT_IMPLEMENTED`. N3-A actual REST/official MCP and same-instance Git/File also `NOT_RUN`. Native Exec, real process/signals, T2/T3, merge, deploy, release and production config explicitly **NOT_AUTHORIZED**.
- B/C must independently review this new PR's exact Base/Head/Tree/full effective delta, test implementation/source identities, challenge fake provenance promotion and boundary cases, and publish separate native SHA-bound r001 `ROLE_FULL_SCOPE_PASS` or applicable FAIL/BLOCKED. A's T0 result is not their conclusion.

## Deferred T1 physical port gate

Before enabling any `open_physical_private_store` body or actually invoking private filesystem calls: require a new user decision identifying the disposable runner(s), exact isolated private root and lineage root, filesystem type/OS, resource/memory/disk limits, allowed `openat`/`fstat`/`flock`/read/`fsync` and safe fault-injection list, no real Native processes, exact G05 + locked wheel/RECORD provenance scope, cleanup plan with identity-checked roots, and a fresh B/C reviewed Head. No user Mac/Tunnel or shared/production environment; no implicit grant from a well-shaped fake `N3F0Scan`.
