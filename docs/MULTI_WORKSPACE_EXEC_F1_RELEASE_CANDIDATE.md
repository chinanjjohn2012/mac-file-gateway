# Multi-Workspace Exec F1 — integrated pre-merge candidate

**Status: DRAFT / NO-GO for merge, release, deployment and real Exec activation.** This is a source and integration-review candidate, NOT a new version/tag or an automatic release authorization.

## Fixed provenance and intended delivery

- Repository: `chinanjjohn2012/mac-file-gateway`.
- Target: `release/ms1` at `2f163eeb83fc2f984354dc6d231a614dca5aa9af` (GitHub was read directly).
- Immutable F1 source input: PR #71 Head `f11721765c3f64e3ab18c425fb9b642dc40f6ec7`, based on PR #70 Head `9feb7d8eb71dc6f4ed60b9be2bbc73303a718067`. These two reviewed snapshots are not modified.
- The **new RC Head/Tree must be read from its GitHub PR and GH_HANDOFF_V1 comment**; this file deliberately does not self-pin its own commit.
- The base-to-PR #71 diff contains **71 commits / 45 changed paths**. The final RC adds only docs, README, one isolated test workflow and Manifest; its actual compare must be independently fetched and frozen.
- This is a **single integrated review**, not a request to sequentially merge all 13 Draft PRs. No original PR is merged, closed, rebased or rewritten by preparing this candidate.

## Exact production mainline

`release/ms1` → #56 → #57 → #58 → #59 → #60 → #62 → #63 → #64 → #65 → #67 → #69 → #70 → #71 → **this Draft integrated RC**.

Each intervening PR's Base was checked against the previous fixed Head at RC preparation. All are Draft/unmerged. PR #68 is a frozen **side branch** from #67 for old test-only Private Bridge contracts and is **not** an ancestor or merge prerequisite for this production-first F1 candidate. Its older FAIL/RED/CI facts remain historical evidence, not inherited review approval.

## What F1 actually delivers

1. Ordinary Multi-Workspace Exec defaults globally and per-Workspace to off; opt-ins only expose validated `dry_run=true` preview.
2. Every ordinary `dry_run=false` Exec Apply without reviewed full-descendant cleanup proof refuses with `exec_cleanup_proof_required` **before Exec Popen/Runner and even transient PREPARED**. Effective `exec_policy.available=false`, `completion_capability=none`; REST HTTP 503 and official SDK MCP machine-readable errors.
3. Existing durable Exec-state ownership/UNKNOWN/quarantine denial and error ordering are preserved; no auto-unquarantine or remote reset.
4. Authorized File Write and independently permissioned real Git subprocess Apply remain functional in the **same** Exec-denied or Exec-quarantined instance. This does not make Git safe against its native repository/hook/remote side effects.
5. No F1 positive real Exec, worker full-descendant proof, OS-level sandbox, user Gateway/Tunnel acceptance or Native C/C3 work.

**No runtime/source/test/requirements updates in this integrated RC relative to the fixed PR #71 Head.** The RC documentation status annotations describe already-submitted SHA-bound reviews; they do not retroactively modify PR #69/#70/#71. The existing version labels `2.5.0` are **not** a new release decision: independent version naming, operator notes and rollout approval remain pending.

## Current evidence — not automatically transferable

| Source | Actual evidence | Scope limitation |
| --- | --- | --- |
| PR #69 r002, Head `4110fac4edf2027703f4ce830a4d46718de4804d` | Independent B/C `TARGETED_REVIEW_PASS` | F0 §0 deny-only design, not F3 or whole-PR-stack release |
| PR #70 r002, Head `9feb7d8eb71dc6f4ed60b9be2bbc73303a718067` | Independent B/C `ROLE_FULL_SCOPE_PASS`; Linux `1472 passed / 8 skipped / 1 warning` | F1 product source, not whole stacked release or comprehensive integration |
| PR #71 r001, Head `f11721765c3f64e3ab18c425fb9b642dc40f6ec7` | Independent B/C `TARGETED_REVIEW_PASS`; GitHub-hosted macOS 15 ARM64 `50 passed` across two suites, two warning instances; Linux `1472 passed / 8 skipped / 1 warning` | Isolated disposable F1 deny-only acceptance only; no user Mac/Tunnel or real Exec Apply |
| Historical #56–#67 | SHA-bound staged design/RED/product reviews and successful original CI | Most post-rebase reviews are **TARGETED**; prior FULL PASS does not automatically attach to newer SHA, Base or integrated tree |
| THIS integrated RC | Newly authored docs, safety-gated macOS workflow and final CI pending | **Requires fresh independent B/C FULL scope review against release/ms1** |

GitHub native Git Tree and full tracked SHA-256 Manifest give a precise **remote committed snapshot**, but do NOT prove a developer's local unstaged/untracked worktree. Original R01/R10 remote-equivalence interpretation has not been authorized; therefore no unqualified `FULL_CODE_REVIEW_PASS` may be asserted solely from these facts.

## Release risk gates and closure evidence

| Gate | Why it matters | Release disposition |
| --- | --- | --- |
| RC-01 — full stacked B/C review | 71+ commits, runtime/test/workflow/docs and 45+ files, with historical rebase-only targeted reviews | **BLOCKED** until B/C independently inspect the final integrated RC Head/Base/Tree, contract matrix, original CI and remaining P0–P2; both must explicitly delimit R10/R01 gaps |
| RC-02 — test-only capabilities | `gateway/_exec_test_grant.py` and `gateway/_exec_test_transport.py` exist in distributed source along with historical positive Exec test script | **REVIEW** import reachability, dynamic imports, external REST/MCP/CLI/config bypass and correct no-proof denial; do not erase tests or claim a Python string scan is OS-level proof |
| RC-03 — no positive Exec | Legacy macOS lifecycle workflow contains positive Exec / process-group lifecycle tests | **HARD STOP**: the new RC workflow never invokes that script; no F3/native group-signalling or unmanaged child experiments without new authorization |
| RC-04 — truthful public docs | Historic README described no Multi `run_command`, and F0 docs said PROPOSAL before PR #69 acceptance | This candidate fixes *scoped F1 wording only*; independently review text against actual code, especially `read_only` vs `file_read_only` |
| RC-05 — final exact CI | Old Linux and macOS results were on upstream commits, not the final RC | New Linux full regression plus new hosted macOS F1 focused CI must be green on this exact RC Head and checked-out Tree; keep 8 Linux skips/warnings explicit |
| RC-06 — target drift and approval | `release/ms1` was unprotected, ruleset query empty, PR approvals are GitHub `COMMENTED` | **BLOCKED** until fixed target, merge strategy, approval process and branch protection/manual gates are approved; ANY Base/Head change requires fresh diff analysis/review |
| RC-07 — release/version and recovery | Runtime still reports 2.5.0, production config and rollback of UNKNOWN/owner.lock not exercised | **BLOCKED** until release version decision, controlled rollout/rollback plan, state-file preservation and owner-lock exclusivity are independently authorized/tested |
| RC-08 — production E2E | GitHub-hosted TCP and Git/File proof is not the user's Mac, ChatGPT Tunnel or production ecosystem | NOT_TESTED; requires a separate decision and authorization. Not folded into current RC PASS |
| RC-09 — experimental workflow reproducibility | Old actions versions, dependency drift and staged positive/RED workflow documents remain in tree | Review workflow trigger scoping, authenticated-checkout defaults, pinned dependency strategy and re-run provenance; any changes require new SHA/new reviews |

## Full-review request and subsequent decision

- **B: STANDARDS_REVIEWER; C: SPEC_REVIEWER**. Each independently reviews the entire release/ms1-to-final-Head diff, including upstream code and test-only modules, actual source entry points, prior approved scope, current docs/workflow and full CI evidence. A must not write either review.
- Test both **legal Preview/File/Git success** and **illegal Exec/unauthorized File/Git denial**, error/health priority, owner-lock, UNKNOWN, cancellation/concurrency/recovery and cross-mode side effects; distinguish real TCP/SDK, Python mocks, kernel proofs and historical RED.
- Do not equate `REVIEW_COMPLETE`, targeted PASS, role full PASS, overall `FULL_CODE_REVIEW_PASS`, isolated test green and `INTEGRATION_PASS`.
- If B or C finds P0/P1/P2, A must fix on a **new RC Head and review round**, rerun relevant CI and request two new independent conclusions. Avoid editing frozen #69/#70/#71.
- Even if both reviewers pass their role-level FULL scope, the release remains **NO-GO** until the explicitly unresolved R01/R10, approval, version, rollout/rollback and production integration gates are closed by separate authority.

**Prohibited here:** merge, release, tag, deploy, user Gateway/Tunnel restart, real Multi Exec apply, auto-unquarantine, Native C/C3, private positive Bridge, unmanaged PID/PGID signaling, or changing historical B/C Reviews.
