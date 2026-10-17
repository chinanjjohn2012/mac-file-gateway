# Phase 1 Multi-Workspace: source security / architecture review

> **Historical snapshot only (2026-10-16).** The pending gates and Draft status below describe the repository **at the time of this source review**; they are not the current PR status. Subsequent independent native macOS re-reviews closed the reviewed findings, and PR #3 was merged on 2026-10-17. See [Phase 1 acceptance and residual limits](./PHASE1_ACCEPTANCE_2026-10-17.md). The original assessment is preserved unchanged below.

Review date: 2026-10-16. Scope: `feature/multi-workspace-phase1`.
**Status: pre-merge source review; not an independent second-person approval.**
Do not infer GitHub Actions success or external reviewer approval from this report.

## Confirmed behavior from the implementation

- Config is strict JSON loaded from a pinned file descriptor; symlink and
  hardlink aliases, duplicate keys, missing roots, noncanonical paths and
  read/write policy inconsistencies are rejected
  (`gateway/private_fs.py`, `gateway/workspaces_config.py`).
- All configured roots are pinned and checked for physical overlap with other
  Workspaces, config directory and active Python runtime/import directories
  (`gateway/workspaces.py`). Local UID/mode/ACL restrictions are intentionally
  outside the Phase-1 trust model; see `PHASE1_LOCAL_TRUST_BOUNDARY.md`.
- REST/MCP share `WorkspaceService.invoke`, with mandatory Workspace IDs and
  independent write grants. Phase 1 does not expose exec/Local Skill tools
  (`gateway/http_multi.py`, `gateway/mcp_multi.py`, `gateway/multi_fields.py`).
- File/parent operations use descriptor-relative no-follow access; regular
  file snapshots require `st_nlink == 1`; guarded writes use original
  SHA-256, file backups and per-root locks
  (`gateway/core.py`, `gateway/writer.py`, `gateway/write_storage.py`).
- Raw MCP/REST POST JSON is bounded, validates Content-Type and rejects
  duplicate object keys *before* SDK parsing
  (`gateway/multi_admission.py`). Host, Origin, and optional bearer token
  checks remain in `gateway/http.py`.
- Source redaction and exact-match editing share a sensitive-content policy;
  redacted source lines cannot be matched by the write API
  (`gateway/visibility.py`).

## Acceptance evidence available before this review

- User-provided native macOS output on 2026-10-16:
  `bash verify.sh --require-mcp`: **592 passed, 1 third-party
  deprecation warning**, real HTTP smoke `PASS` (20 checks),
  `Release manifest: OK`.
- User also exercised 10 real MCP protocol checks and 7 additional live
  REST create/read/replace/delete/path-isolation checks, all reported passed.
- These results predate any additional regression cases introduced after
  commit `5e8c3ef563f7aabbbef7b7a613789adf8c89490a`; rerun required
  for any later commit.

## Review disposition and remaining gates

No new source-level P0/P1 blocker was established by this review.
The following must not be presented as completed:

1. Native macOS execution of the newly added negative-test regressions
   (cross-root symlink and hardlink refusal, read-only hash operations,
   hidden-protected names, isolated backup storage, MCP write lifecycle).
2. **GitHub Actions:** no workflow run or check result was visible for
   the PR head when reviewed. This is not a green CI signal. Check repository
   Actions enablement/permissions and get a completed successful run.
3. **Independent review:** this source review is not a separate security
   reviewer/LLM approval. Obtain independent security/architecture review,
   especially on Darwin FD identity, renameatx_np, and descriptor race behavior.

Keep PR #3 Draft and do not merge into `release/ms1` until all gates close.
