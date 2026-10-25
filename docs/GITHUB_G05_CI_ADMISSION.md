# G05 — fail-closed GitHub checkout admission, isolated F1 candidate

**Design status:** isolated **CI implementation candidate**, not the adoption of a new R01/R10 verdict and not a release authorization.

**Authoritative approved contract:** [GitHub R01/R10 G01–G08 text](https://github.com/chinanjjohn2012/mac-file-gateway/blob/bf72e23e2cc54a2cd57cc25c400cee321741c13b/docs/GITHUB_PR_R01_R10_REMOTE_COMMITTED_EQUIVALENCE_PROPOSAL.md), specifically G03–G05 and the G04 checkout rule. User approval was recorded on PR #73, Head `bf72e23e2cc54a2cd57cc25c400cee321741c13b`. The original R01 worktree Manifest rule, dual independent R10 review, and local-uncommitted-worktree obligations remain intact. This code does **not** change the approval text.

**Product base:** frozen integrated F1 RC PR #72, Head `ea7989800ba1f1e759739d5bf3a700c1691801a6`, Tree `c45a94a0c288b491bb5c44082f6aab88dfb42bf6`. This separate PR branches **from** that commit and targets its RC branch; it does **not** move the frozen PR #72 Head, alter original B/C Reviews, or modify product Exec/Git/File runtime.

## Before any dependency install, build, test, or project import

Run `python3 -I -S tools/g05_ci_admission.py --expected-head "$G05_EXPECTED_HEAD"` **immediately after `actions/checkout`**. `-I -S` prevents ordinary repository/site import-path hooks from running before the check. All Git queries and hashes are read-only.

1. Verify the actual checkout root, complete Git HEAD against the event's exact PR Head SHA, and read the Git Tree SHA. The workflow must checkout the exact Head rather than implicitly trusting the synthetic Merge SHA. B/C independently verify actual GitHub source Tree, parentage and CI identity.
2. Before running any code from the project, reject tracked changes, untracked paths, **all ignored paths**, and relevant external Python import-path/Git-index overrides. Strict denial of even benign pre-existing caches avoids guessing what could later execute or shadow the reviewed source. The gate runs before test-generated `__pycache__` is created.
3. Independently parse sorted, unique `MANIFEST.sha256` records and verify SHA-256 of every tracked regular file other than Manifest itself, with exact tracked path closure. Symlinks, missing source, altered hashes and incomplete manifests fail closed.
4. Use standard-library `PathFinder` metadata only (no project import) to verify the `gateway` package resolves from the tracked checkout. Recheck checkout status after hashing to detect mutations during the preflight.
5. Emit `G05_REPOSITORY_ADMISSION=PASS` only for the **repository-scoped early checkout condition**, and emit `G05_THIRD_PARTY_DEPENDENCY_PROVENANCE=NOT_ATTESTED`, `G05_DEVELOPER_LOCAL_WORKTREE=NOT_OBSERVED` and `G05_INTEGRATION_STATUS=NOT_TESTED`. On any gap, exit nonzero and emit `G05_R01_GATE=INCOMPLETE`. A PASS is **not** overall R01/R10, dependency provenance, macOS production E2E or release GO.

## Actual admissibility tests

- Positive: a clean disposable Git repository, full Manifest and correctly resolved gateway package succeeds.
- Negative: an ignored `gateway/ignored_shadow.py` is actually discoverable by `PathFinder` and `git diff --quiet HEAD` incorrectly succeeds; G05 refuses the ignored module before execution.
- Negative: ignored directory/bytecode, untracked executable and text file, tracked content drift, incomplete Manifest, wrong or malformed expected SHA and injected `PYTHONPATH` each fail closed.
- Runtime safety: tests use disposable local Git fixtures; they never execute ignored modules, real Exec Apply, Native C, unmanaged PID/PGID signals, user Mac/Tunnel, or non-disposable repos.

## Integration and known limits

- The existing Linux `controlled-exec-tests` workflow now runs the gate before `setup-python`, `pip` or test execution, and pins checkout to the event Head. An isolated new GitHub-hosted macOS ARM64 workflow targets only this PR's frozen F1-base branch and runs the same admission and bounded deny-only F1 tests.
- A CI environment that already contains untracked/ignored build output (even authorized caches) is intentionally rejected; future generated-source allowances must be explicitly approved and cryptographically tied to actual inputs before relaxing this rule.
- Dependencies installed **after** preflight may still be floating or execute installation hooks; their hashes and real installed import roots are **not proven** here. A later dependency-provenance gate / post-install attestation is a separate decision, not silently included in G05. A clean runner is not a sandbox against malicious dependency installers or an adversarial writer racing the checks.
- GitHub-only source evidence does not inspect the developer's local staged/unstaged/untracked worktree; G01–G08 and both B/C role Reviews are still required per applicable review scope. PR #72 cannot inherit full acceptance from this independent PR without separate review and an authorized integration strategy.
- No actual user Mac/Tunnel, old-version upgrade/rollback, F3 positive Exec, descendant cleanup, Native C/C3, production merge or deployment is performed by this change.
