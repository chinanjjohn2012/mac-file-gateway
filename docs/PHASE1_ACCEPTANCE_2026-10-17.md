# Multi-Workspace Phase 1: acceptance and merge record

**Status:** Merged into `release/ms1` on 2026-10-17; **file APIs only**.
This is a source and reviewed-test record, not a production deployment or
permission to enable subsequent phases.

## Pinned provenance

- PR: [#3](https://github.com/chinanjjohn2012/mac-file-gateway/pull/3) — merged and closed.
- Original release base: `d3019237e5766f5e7fe4c6b33f8f2c0e78c220e7`.
- Prior reviewed remediation commit: `60fcba819c8d8c1ce7d665c0152a79b58d1c5ff9`.
- Final independently reviewed F3/N1 commit: `8c49bf613af03f3e92500e74d30ec1056b0691bb`.
- Merge commit on `release/ms1`:
  `e32cb5124bbd8b08a79c75b4940799e041dd1295`.
- Final merged Git **tree**:
  `cbd826312cc83300e4a5e85f64c7746d8ac90e7f`.
  This exactly matches the independently re-reviewed F3/N1 candidate tree.
  No additional source changes were introduced by the merge.

## Acceptance evidence and scope

The external independent macOS review reports were supplied to the maintainer
and checked against the pinned source tree; their private local evidence packages
are **not** published in this repository.

- Original independent remediation re-review on macOS: `807 passed`,
  `0 skipped`, plus focused security probes.
- Final F3/N1 independent native macOS acceptance on the exact final tree:
  `830 passed`, `0 skipped`; `233 passed` in the targeted suite
  (23 added regression cases and 210 existing focused cases).
- Negative baseline controls on the old unpatched module:
  `22 failed / 1 passed` as expected, demonstrating the new tests detect
  the original F3/N1 behavior.
- Additional independent live HTTP/MCP and original negative repro probes
  passed within their documented synthetic test boundaries.
- GitHub Actions [run 39008240185](https://github.com/chinanjjohn2012/mac-file-gateway/actions/runs/39008240185)
  completed successfully for the final PR head/merge-checkout:
  `822 passed`, `8 skipped` (Darwin-only), `1 warning`;
  REST smoke 20 checks, compileall, shell parsing, and release manifest
  verification passed. The REST smoke by itself does not verify MCP; separate
  independent native MCP probes did.
- The operator separately confirmed completion of a **local Phase 1 pilot**.
  No pilot logs or deployment version were incorporated here; this statement
  is user-reported, not independently verified production deployment.

The acceptance closed F1, F2, F4, F5, F6, F7 and, on the final exact
tree, F3 and N1 under the findings' respective documented test scopes.
Independent re-review is **not** a GitHub formal review submission or a
general security certification.

## Mandatory operational/security boundaries

- Phase 1 Multi mode supports explicit-Workspace file read/write only.
  It **does not** expose `run_command`, Local Skill Bridge, or Phase 2/3 tools;
  these require separate specifications, security review, and acceptance.
  Legacy single-root execution and Local Skills are unaffected.
- Trusted local OS users/processes remain the accepted threat model.
  No UID/POSIX-mode/ACL startup admission gate is required; the Web/MCP
  authorization boundary, pinned Workspace identities, sensitive-content
  policy, guarded writes, and per-root backups remain mandatory.
- Native SIGINT with the bounded synthetic paused worker was verified.
  The previously observed **SIGTERM graceful-timeout path can terminate
  without entering CLI close**. No claim is made for all stop signals,
  arbitrary slow I/O, SIGKILL, power failure, crash recovery, all volumes,
  or deployment conditions.
- Legacy controlled execution is an opt-in **command launcher, not an OS
  sandbox**. Executed trusted project code may access the host filesystem
  and network with the process account's privileges; do not interpret
  Workspace routing as a subprocess isolation boundary.
- Merging the code does not update a running Gateway or tunnel. Any rollout,
  cutover or restart requires separate operational approval and validation.

## Further work

Before Phase 2 Multi-Workspace Controlled Exec implementation, approve
a separate design that identifies capabilities, command/runner selection,
execution root identity, job lifetime/cancellation/shutdown, cross-Workspace
authorization, negative tests, and the explicit absence or presence of
an OS sandbox. Keep Multi exec disabled until that new phase passes review.
