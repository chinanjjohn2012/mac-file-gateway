# Phase 1: local OS trust boundary amendment

Status: **accepted Phase 1 trust-boundary amendment; merged into `release/ms1` on 2026-10-17**.
The implementation and follow-up review record is [Phase 1 acceptance](./PHASE1_ACCEPTANCE_2026-10-17.md). This amendment does not enable Phase 2 or Phase 3.
This document updates the previously frozen Multi-Workspace Phase 1 design's
local multi-user tampering assumptions. It does not authorize Phase 2 or Phase 3.

## User-directed decision

A Mac File Gateway instance is installed and operated by a trusted local OS
user. Other local accounts and processes with local filesystem access are
**outside the Gateway threat model**. Gateway startup must not judge or repair
ownership, group/other write permissions, or extended ACLs of the paths it
opens. In particular, `0775` Homebrew paths and `0777` Workspace directories
are not refused merely because of their POSIX mode. Control-plane configuration
files are also not rejected because of UID, mode or ACL; restrictive settings
such as `0700` directories and `0600` files remain administrator recommendations.

Operating system permissions still apply: if the Gateway process lacks rights
for an operation, that operation fails normally. This decision does not
provide isolation from other local users (including same-UID processes).

## Rules that remain enforced

- A Web/MCP request must explicitly name an authorized Workspace, and routing
  never falls back to another Workspace. Per-Workspace read/write capabilities
  remain independent.
- Source root, private config and active code/import roots are still pinned by
  FD identity, must not overlap protected control paths or other Workspaces,
  and must not alias by symlinks or noncanonical path components. These checks
  prevent API-based path confusion and Gateway self-modification, **not**
  cross-account filesystem tampering.
- A configuration file must be a regular non-hardlinked file; no symlink
  traversal, FIFO/device input, unbounded reads, duplicate JSON keys or
  inconsistent before/after FD metadata. Root FD identity and per-workspace
  method authorization still apply.
- Existing Gateway file deny rules, source hash guards, redaction, preview,
  scoped writes, and per-Workspace backup separation remain unchanged.
- Multi mode continues to reject command execution and Local Skill activation
  pending the Phase 2/3 safety reviews.

## Explicitly accepted risks

A different local user who can modify the installed code, a Workspace's files
or Gateway configuration may influence this Gateway's behavior, including
between two requests. The Gateway does not try to establish a secure boundary
against this attacker. OS facilities (accounts, directory permissions, disk
access policy) are the system administrator's responsibility. Private
configuration remains outside Workspace roots; file API requests cannot edit
it through the Gateway.

## Required regression evidence

- Private config directories and file modes of `0777` and `0666` are permitted
  when otherwise well-formed and accessible.
- User-owned Homebrew-like `0775` runtime ancestors and `0777` Workspace roots
  pass FD pinning without any UID/mode/ACL admission gate.
- Symlink parents/leaf, hardlinked config, FIFO/device, oversized or mutated
  config, Workspace-root overlap, runtime/import-root overlap, missing Workspace
  and read-only Workspace writes are still rejected.
- Native macOS acceptance, real SDK MCP/REST regression, and full repository
  tests are mandatory before merging into `release/ms1`.
