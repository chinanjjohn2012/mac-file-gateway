# Multi-Workspace F1 + G05 integrated source and test candidate

**Status: DRAFT / REVIEW_PENDING / NO_GO.** This is not an authorization to merge, tag, release, deploy, restart a user Gateway or Tunnel, or enable real Exec.

## Fixed lineage and review target

- Repository: `chinanjjohn2012/mac-file-gateway`, proposed target `release/ms1` Base `2f163eeb83fc2f984354dc6d231a614dca5aa9af`.
- Inherit PR #74 exact Head `b957267b4680e8aaf7568a1f2b5ab02755d28756`, Tree `31e56733ebf286178637bf64ccca6039e697e7b7`. Its ancestor PR #72 fixed F1 RC Head is `ea7989800ba1f1e759739d5bf3a700c1691801a6`.
- At the original source snapshot, `release/ms1...PR74` has 74 commits and 53 changed paths. The new candidate adds only this document, one separate hosted macOS workflow and the complete tracked Manifest. Review the ENTIRE final base-to-head source diff, not only this incremental change.
- Source PR #72, #74, all old role Reviews and legacy PRs stay frozen. The old governance proposal PR #75 is not a product dependency or a current rules authority.
- Do not self-infer the candidate Head or Merge Tree from this document: independently read native GitHub Commit/Tree/parents and exact-SHA GitHub A handoff.

## Product and security contracts

- Primary F1 authority: `docs/MULTI_WORKSPACE_EXEC_RECOVERY_D0_DESIGN.md` section 0 and `docs/MULTI_WORKSPACE_EXEC_PRODUCTION_FIRST_IMPLEMENTATION_PLAN.md` at the inherited source.
- Ordinary Multi Exec defaults disabled. Both opt-ins only permit checked `dry_run=true` Preview. Without reviewed full-descendant cleanup proof, `dry_run=false` MUST reject with `exec_cleanup_proof_required` before Exec Runner/Popen or any transient PREPARED.
- Preserve `exec_disabled`, `exec_quarantined`, `exec_state_unavailable` precedence, real private state/owner-lock and UNKNOWN restart denial. No auto-quarantine clearing, PID/PGID signals, or lost-response replay.
- Legitimate separately authorized File Write and real Git Apply must succeed in the SAME disposable service when Exec is denied or quarantined; unauthorized Git/File must refuse. Do not globally intercept subprocess calls.
- G05 authority: `docs/GITHUB_G05_CI_ADMISSION.md` and `tools/g05_ci_admission.py` from PR #74. Verify actual HEAD and Tree, native Blob bytes/executable bits, Manifest, hidden Git index flags, untracked/ignored inputs and import root directly after checkout BEFORE dependencies, imports and build. Fail closed.
- Applicable V1/G01-G08 safety rules stay mandatory until a newer independent V2 governance version is formally approved and A/B/C Project sources synchronized. The separately optimized V2.0 Project rules are additional candidate review criteria, not retroactive review approval.

## Required scoped CI and evidence

- Linux `controlled-exec-tests` on the new PR Head: G05 before setup/install; full offline pytest, real HTTP/MCP/Git smokes, Manifest and Bash/Python checks.
- New `.github/workflows/multi-exec-f1-g05-rc-macos-arm64.yml`: same-repo, exact fixed Base and named review branch, GitHub-hosted macOS 15 ARM64; credential-free Head checkout; G05 early; no post-PR74 product code/test changes; 19-case G05 negative and positive admission suite and F1 deny-only/Preview/File/Git/owner-lock/boot suites. Counts are historical guidance only, not a quota.
- Positive: clean HEAD admission, legitimate Preview, real disposable Git Apply and File Write. Negative: ignored/untracked/import-shadow/index-mask/manifest tampering, invalid Exec Apply, unauthorized Git/File, unsafe state and owner-lock. Boundary and abnormal: cancellation, UNKNOWN/quarantine, boot, lock conflict and adjacent Legacy/Git paths when applicable.
- Historic evidence only: PR #72 Linux 1472 passed / 8 skipped / 1 warning and hosted macOS 4 + 46 passed; PR #74 Linux 1491 passed / 8 skipped / 1 warning and hosted macOS G05 19 passed + F1 4 passed / 1 warning. No historical PASS transfers to the new Head.
- GitHub repository admission is NOT proof of post-install dependency provenance, developer-local worktree, real OS full-descendant cleanup, real user Mac/Tunnel, or any upgrade/rollback compatibility.

## R001 review evidence blockers and R002 bounded CI response

Two independent r001 FULL reviewers reported BLOCKED without proving an in-scope new P0/P1 source defect. Current candidate R002 adds an evidence-only wheel download/installation pipeline and does not alter the production F1/G05 runtime: `tools/ci_dependency_provenance.py` validates that downloaded dependencies are **wheels only**, records each wheel SHA256 before install, installs exclusively from that local wheelhouse with `--no-index`, captures actual installed distribution file content hashes and critical import root locations, then compares those exact installed bytes after all tests. Six isolated positive/negative tests cover legitimate wheels, tampering, non-wheels, symlinks, duplicate distribution names and unsafe evidence overwrite. The early G05 gate remains before Python setup/installation/imports. This addresses traceability of executable dependency bytes **for the specific CI run**; it does NOT assert signed supply chain, a cross-run hash lock or a trusted package index. Reviewers must determine whether further exact artifact lock or formal authorization is required for full R01 acceptance.

Linux changes `pytest -q` to `pytest -q -rs` so the original job logs name and explain the 8 skipped tests; skip reasons must be independently classified against the actual F1/G05 code contract. Historical RED workflows and unapproved positive Exec/Native experiments are NOT rerun. If an original CI job fails at wheel selection, installation, attestation or tests, report FAIL and do not infer a code PASS.

Independent C review also could not read the existing authoritative original V1 R01-R10 and GitHub Handoff V1.0 texts in C Project; B noted the G01-G08 Project source-sync was not verified. These are **separate governance evidence requirements** which a GitHub code commit cannot cure. A has directly found V1 original materials in Library (`05_Original_Independent_Code_Review_Rules_V1.0_UNCHANGED.md`, `GitHub_Review_Handoff_V1.0.md`, `00_Approval_and_sync_status.md`) but cannot truthfully attest they are mounted and full-read in each B/C Project. Formal activation of optimized V2.0 remains separately gated; PR #75 is not its authority.

NO MERGE, NO RELEASE, NO DEPLOY, NO real Exec Apply, NO Native C/C3, NO auto-reset of UNKNOWN, NO user Mac/Tunnel experiment.

## Independent review and hard stops

- B Standards and C Spec must issue separate NEW `FULL` reviews on identical candidate Base/Head/Tree/round, covering all inherited F1 and G05 source, appropriate original CI/Job/logs and negative/positive/boundary/error/adjacent contracts. Previous B/C role results are background only.
- `REVIEW_COMPLETE`, `TARGETED_REVIEW_PASS` and even two `ROLE_FULL_SCOPE_PASS` do not independently establish overall `FULL_CODE_REVIEW_PASS` or `INTEGRATION_PASS`. Record all P0-P3, NOT_RUN and scope/identity limits.
- New Base/Head/Tree, actual diff, contract, external source or rule changes require fresh analysis. Release remains NO_GO until separately approved version, full rollout/rollback evidence and actual environment authorization.
- PROHIBITED: merge, tag, release, deployment, production config changes, real Multi Exec Apply, Native C/C3, unknown process/group signals, private positive Bridge activation, UNKNOWN auto-unquarantine or unapproved destructive tests.
