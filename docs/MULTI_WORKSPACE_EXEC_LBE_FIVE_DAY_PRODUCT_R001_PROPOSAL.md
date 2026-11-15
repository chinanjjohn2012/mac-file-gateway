# Multi-Workspace Exec local_best_effort - five-day product sprint D1 amendment proposal

TASK_ID: MULTI-EXEC-LBE-FIVE-DAY-CANDIDATE-20261105
CONTRACT_ID: MWE-LBE-FIVE-DAY-TRUSTED-CANDIDATE-R001
REVIEW_ROUND: r001
STATUS: PROPOSED_NOT_EFFECTIVE / SOURCE_PLUS_SAFE_T0_ONLY / PRODUCT_DENIED
RULESET_ID: ICR-V2.0
HANDOFF_PROTOCOL_ID: GHRH-2.0
EVIDENCE_PROFILE_ID: ETP-V2.0

## 1. Authority, product boundary and what the owner authorized

The owner has reaffirmed the target of five *development* workdays for a usable local_best_effort product candidate, with concentrated A development and B/C milestone review. That scheduling and product decision is NOT permission to remove operative F1 denial, run new Go/Pipenv, perform unsafe/native T2/T3 experiments, merge or deploy.

Fixed product starting snapshot: PR #101 Head ec25c34492912f3a82175fa9c1060e0632814687, Tree 3a127bf341a0363b9fa77a570d88436a6fd48696, current Base 0fc1ae245de7cb582a69162c79c201d15bfaa258. Do not rewrite the frozen PR101. PR #112 macOS Seatbelt Gate T0 remains a separate research line.

Fixed previously reviewed designs: PR98 r002 local_best_effort source GitBlob 9e6622401b198138039c692efe91fba1a8d06891, B/C TARGETED design PASS; PR102 r002 Go/Pipenv safety test Gate B source GitBlob 7db3b77aadca8b0c284e28fa5ee64e315e9275d2, B/C TARGETED design PASS. PR101 r015 FULL and r016 external code qualification remain BLOCKED; no inherited PASS. Operative D0 GitBlob 6e25904aed9a62bb0f472b732021c2a7ca3b3bb0, F1 GitBlob 76baeb820c6f8a9b067e45e2dcc42e76453fe5b1, Phase1 GitBlob b3f2383f292a59fd234269389e5338cd50e334a2, G05 GitBlob 76c1c2b8a7947e0b305d55c5f550ab59c638b6d1 and original R004 36 Wheel/RECORD scope are unchanged.

Prior Gate A user consent in PR102 #6559619893 is a DEVELOPER transcription of the risk acceptance, not independent signoff or live runtime approval. Prior Gate B user direction in PR102 #6560708487 conditionally approves OFFLINE_ONLY standalone SOURCE_TOOLCHAIN_T1 only after exact runnable source/OS/precontact/evidence gates. These approvals are NOT silently reinterpreted.

## 2. Five-day product functionality and accepted weaker risk model

Use schema_version=2 with explicit per-Workspace nonempty exec.paths as the ONLY public candidate grant; no redundant server.exec.enabled or workspace.exec.enabled. Preserve v1 F1 behavior, no implicit v1 upgrade, old UNKNOWN/quarantine and owner.lock private state fail-closed, Workspace routing, canonical cwd/scope/path and command denylist, no shell and independent Git/File permission.

Required commands: approved Python Direct scripts/pytest/compileall; configured project Pipenv; Go test, vet and build including validated workspace-relative -o. No arbitrary Go run, Python -c, shell, environment toolhook overrides, Pipenv .venv redirect or unchecked runtime selection.

The child-lifetime unit is the witnessed ORIGINAL child, one per Workspace and four per service. On timeout or disconnect do not claim child exit, rollback or descendant cleanup; preserve slot ownership while the direct child may run. Original exit code proves only original exit, not detached grandchildren. Do not signal unknown PID/PGID, retry on lost ACK, recover after crash or fabricate output completeness. The user understands same-UID operator-trusted project code can access user-owned files and network; argv filtering is NOT a sandbox and a pathname Popen has residual same-UID race.

## 3. Explicit proposed change from the stronger native Gate B

Keep the existing PR102 OFFLINE_ONLY standalone source-toolchain T1 as a separate optional stronger security research profile. This D1 proposal requests independent review of a DIFFERENT prospective trusted-code PRODUCT_T1 profile for the simpler product. It would not guarantee Seatbelt, outbound network prohibition, complete dynamic/compiler source semantic safety, full descendant retirement, or strict F3 containment; do not require those claims from a product that does not make them.

IMPORTANT: Existing Gate B mandatory precontact OFFLINE_ONLY proof and Go/Pipenv real-execution hard stop REMAIN operative for now. A new profile is not authorized by a five-day deadline or this source file. It requires B and C independently to approve its exact revised trust/test contract, then explicit user permission acknowledging the non-isolated network/host-code risk and specifying a fixed, disposable execution envelope. Without those, all Go/Pipenv native and product positive T1 remain NOT_RUN and DENIED.

Proposed later bounded real test envelope (not yet approved): one disposable hosted macOS ARM64 runner with no production credentials, shared writable mounts or user Mac/Tunnel; exact newly reviewed Head/Tree, G05 and source/toolchain/venv identity; explicit minimal trusted local test fixtures and allowed commands; closed Go/Pipenv effective environment with prelaunch GOFLAGS/toolhook, Python/virtualenv/.venv/pointer, source-shadows and unknown module denial; defined job and child time/CPU/memory/output limits; direct-child and error handling; original evidence of selected loaded source, outputs and exits. If not actually offline isolated, label residual network ability truthfully and never claim OFFLINE_ONLY or PRECONTACT_DENY_PROVEN. All missing budget/source/runner decisions block native work. T2 signals/kill, T3 and production stay excluded.

## 4. Five concentrated development days and milestone gates

D1: this independent Draft branch, explicit contract change proposal, source/runner input hardening and safe Linux T0 regression. Request B/C design boundary review and explicit owner approval of any new native test profile before activating anything.
D2: after applicable contract authorization, consolidate existing PR101 WorkspaceService/config/single Worker path, private owner.lock/UNKNOWN non-escalation, command output and Go/Pipenv permission tests. Safe synthetic T0 may proceed sooner; operative apply must wait.
D3: implement/test bounded original-child ownership, truthful timeout, cancel, output drain and status, per-Workspace one/four capacity, exception and retry denial. No signals or unknown PID cleanup.
D4: ONLY after separately authorized exact native and integration test envelope, run real Go/Pipenv/Direct/REST/official MCP plus independent Git/File tests and source evidence on disposable resource; otherwise mark NOT_RUN and NO_GO.
D5: group defects and safe regressions, freeze full implementation Head/Base/Tree and submit one B/C independent FULL milestone review with original CI/identity and explicit missing evidence; R10/integration/merge/deploy are separate gates.

## 5. Exact D1 code change and adversarial oracles

This D1 changes only gateway/lbe_worker.py (exact str type of frozen plan.runner BEFORE Python membership calls hostile hash/equality), tests/test_lbe_worker.py (synthetic custom hash/eq, throwing and str subclass negatives; valid Go/Python/Pipenv plan-shape positives) and MANIFEST.sha256, plus this proposed document. The Worker already has no default launcher and ordinary public apply still fails F1. A syntactically approved plan is NOT an execution capability. A green Linux T0 cannot prove actual native toolchain, host confinement or integration.

B Standards: inspect full Base..Head changed files, actual G05/CI and old/native F1 hard stops, adversarial runner object checks and contract version boundary. C Spec: verify correct lower trust meaning, legitimate planned commands and truthful lifecycle/status, explicit separate Gate B alternatives, and remaining authorization. They must independently decide; A cannot sign either.

INTEGRATION_STATUS: NOT_TESTED
R10_STATUS: BLOCKED
FULL_CODE_REVIEW_PASS: NOT_ISSUED
REAL_GO_PIPENV_NATIVE: NOT_RUN / DENIED
FIVE_DAY_DELIVERABLE: CODE_CANDIDATE_OR_NO_GO, NOT AUTOMATIC RELEASE
