# Six-command MVP — Release Candidate 001 source assembly

MILESTONE_ID: LBE-MVP-RELEASE-CANDIDATE-001
ARTIFACT_STATUS: CODE_CANDIDATE_ASSEMBLY; NOT A RELEASE, NOT A TAG, NOT DEPLOYED
REPO: chinanjjohn2012/mac-file-gateway
CONTRACT_ID: MWE-LBE-SIX-COMMAND-MVP-DESIGN-002
CONTRACT_BLOB: d90df6de3bdbd81a314109d5f73959799b5a10a6
REVIEW_RULES: ICR-V2.0 / GHRH-2.0 / ETP-V2.0
AUTHORIZATION: Owner approved concentrating already-developed product into a single RC code candidate. No merge, release, real Mac/Tunnel, production configuration, new native T1 or R006 waiver.
REVIEW_TARGET: cumulative six-only product source plus the later usability/official SDK ClientSession SAFE T0 implementation, exact effective Git diff against PR113's original source Base, and this nonoperative candidate inventory.
SOURCE_COMPOSITION_BASE: ec25c34492912f3a82175fa9c1060e0632814687 (feat/multi-exec-lbe-v2-config-preflight-r001-20261030)
SOURCE_COMPONENT_114_REVIEW_HEAD: 1ef390638a5ba69802d152621544e02d89461788
SOURCE_COMPONENT_114_MERGED_113_HEAD: fc94cc36ce793e32a3fb97d5a500a47608be6781
SOURCE_COMPONENT_113_TREE: fa51d2a7a881f8e4915badcfe0fb088f2fca0ee3
SOURCE_COMPONENT_118_REVIEW_HEAD: 5a5b73a1bacf9f2123eb89152f61c158b42f6564
SOURCE_COMPONENT_118_TREE: 7acd422e8b5f78c14e52ce16a95af93a795988a7
FINAL_RC_HEAD_TREE: Resolve from CURRENT GitHub PR/CI after this file is committed. Never treat these component SHAs as the new RC execution identity.

## 1. What is actually assembled

The RC branch starts DIRECTLY from the frozen, independently reviewed PR118 Head
`5a5b73a1bacf9f2123eb89152f61c158b42f6564`. That commit descends
from merged PR114 through PR113 Head and PR118's five usability commits. The
composite effective Base..source-Head diff before adding this document had
172 paths (151 additions, 21 modifications), 357 commits ahead/0 behind.
The release-document/Manifest commit does not change any runtime Python module,
execution permission, six-command list, worker, launcher, REST/MCP adapter,
test workflow, Git/File grant, or private safety state. RC identity must be
confirmed with the current Git Tree, complete changed path set, original
GitHub CI checkout HEAD and TRACKED SHA256 manifest after this commit.

There is no need to cherry-pick PR114 again, rewrite PR113's frozen Head, or
modify PR118's reviewed Head. #116/#117 are separately reviewed NONOPERATIVE
native test-prequalification control lines, not runtime permissions and not
automatically stacked into this six-command product RC. Any future adoption
of their code needs a separate authority/scope review.

## 2. Exactly the already-approved six commands

These are product request vectors, NOT instructions to execute on a real
user machine or on unqualified GitHub workers.

| ID | Workspace-relative cwd | Selected runner | Requested argv |
| --- | --- | --- | --- |
| S1 py-direct-pytest | `py-direct` | Direct | `python -m pytest -q` |
| S2 py-direct-compileall | `py-direct` | Direct | `python -m compileall -q ./src` |
| S3 py-pipenv-pytest | `py-pipenv` | Pipenv | `python -m pytest -q` (effective `pipenv run python -m pytest -q`) |
| S4 go-test | `go-project` | Direct | `go test ./...` |
| S5 go-vet | `go-project` | Direct | `go vet ./...` |
| S6 go-build | `go-project` | Direct | `go build -o bin/app ./cmd/app` |

The caller supplies one already-configured Workspace ID; none is hardcoded
in the product contract. Schema-v2 requires independent strict server and
Workspace `exec.enabled=true`, matching `exec.paths` for the exact cwd,
correct runner/effective argv, existing-only healthy historical private
state/owner.lock, selected operator-private Python/Pipenv/Go tools, original
child capacity, and final service+launcher rechecks. Schema-v1 and
paths-only preview have NO positive six-command exception. Shell, arbitrary
argv, different Go package/output, alternative scripts, or client-supplied
runner/env never enter the fixed apply allowlist. File/Git grants remain
separate.

Operational behavior is `local_best_effort`, NOT a process-tree
sandbox/journal/cleanup guarantee. A timeout/disconnect may leave descendants
alive; no automatic retry or false cleanup receipt. The accepted residual
risk is only for the exact Owner-approved restricted product scope.

## 3. User-facing usability and safe diagnostic coverage

The cumulative candidate contains `gateway/lbe_mvp_readiness.py` and the
updated `gateway/workspaces.py` status: existing `gateway_info`,
`GET /info`, `GET /health`, `list_workspaces` distinguish
preview-only, both-opted-in, missing selected tools, quarantined/absent old
state, owner/capacity/closing, and **a missing viable exact fixed command
scope/runner**. The status is an aggregate snapshot, NEVER an execution grant
or proof a binary exists at next request time. Path-only/nonmatching scope
must not misleadingly advertise six-command APPLY as eligible.

The official Python MCP SDK `ClientSession` now has nonspawning SAFE T0
coverage in-process and via `streamable_http_client` with in-memory
`httpx2.ASGITransport`. The six previews and legal FakeWorker applies,
invalid/cross-Workspace/disabled requests and REST/MCP read-only parity are
tested. This DOES NOT prove a real TCP ClientSession, ChatGPT Tunnel, local
Mac, Pipenv/Go/Python native child, or deployed integration. The operator
guide `docs/MULTI_WORKSPACE_EXEC_SIX_COMMAND_MVP_RUNTIME.md` supplies a
READ-ONLY `gateway_info` example and consent/troubleshooting cautions.

## 4. Original evidence ledger (component source, not RC verdict)

| Scope | Executed identity / primary evidence | Actual result and limitation |
| --- | --- | --- |
| PR114 native S1–S6 x Direct/REST/MCP | Head 1ef390638a5ba69802d152621544e02d89461788, Tree fa51d2a7a881f8e4915badcfe0fb088f2fca0ee3; Run 43575411697 Job 132388442200 | 18 original-child native macOS 15 ARM64 observations, exit 0; historical approved PR114 scope ONLY |
| PR114 same-service S1 plus actual Git/File | Same earlier PR114 Head/Tree; Run 43575441175 Job 132388535560 | Bounded real mixed observation PASS, no descendant-cleanup proof; historical PR114 scope ONLY |
| PR118 usability and source SAFE T0 | Head 5a5b73a1bacf9f2123eb89152f61c158b42f6564, Tree 7acd422e8b5f78c14e52ce16a95af93a795988a7; Run 43832716339 Job 133181656127 | Linux 4239 PASS /19 SKIP/52 subtests; G05 432 Blob/mode, 431 SHA Manifest PASS, HTTP/MCP/stdio/disconnect/Git smoke; not a native product T1 |
| PR118 strict legacy R006 host diagnostic | Same PR118 Head/Tree; Run 43832716350 Job 133181655615 | ACTUAL FAIL: D4R006HostAllowlistDenied current GitHub/macOS image claim mismatch. Do not mark GREEN or waive |
| This RC branch after metadata commit | See CURRENT RC GitHub PR, its actual HEAD/TREE and original workflow Job logs | NOT_RUN until CI completes; same Git Tree vs composite source MUST be proven, not presumed |

Git Tree `fa51...` of PR114 implementation Head was reproduced by merged PR113
Head `fc94...`, but the PR113 B Standards full review did NOT
unconditionally qualify native dependency, toolchain, environment, and
authorization identity across that different event. PR113 targeted B closed
`P2-EVID-01` (first-hand Owner Design-002 authority) only; **P2-EVID-02
remains OPEN** for unconditional native qualification. No prior PR114,
PR113 or PR118 role PASS may automatically be relabeled a fresh RC full
review/real integration PASS. The current RC must obtain fresh independent
scope-appropriate assessment.

## 5. Code-candidate and release gate checklist

| Gate | Current required decision |
| --- | --- |
| RC composition: exact full Base..Head, no unrelated runtime changes | Verify in new GitHub RC PR |
| RC G05 git commit/tree/blob/modes and all tracked SHA256 Manifest | Original latest-Head CI must PASS |
| RC Linux source/SAFE T0/SDK/adjacent File/Git smoke | Original latest-Head CI must PASS, record all SKIP/FAIL |
| RC bounded full B Standards and C Spec same Base/Head/Tree | NOT_ISSUED at assembly; must independently review entire composite target |
| Historical 18-native evidence reuse PR113 P2-EVID-02 | OPEN, independent qualifier needed, or new separately authorized qualified disposable T1 |
| Current strict macOS R006 | FAIL, separately assess CONTRACT APPLICABILITY; never fake waiver/green |
| Current RC native Mac S1..S6 and mixed real Git/File | NOT_RUN / no new exact-Head Owner execution authorization |
| Official ClientSession via real socket / user Mac / ChatGPT Tunnel | NOT_RUN / not authorized by this assembly |
| R10 FULL_CODE_REVIEW_PASS for the combined candidate | NOT_ISSUED; requires same-snapshot B/C and all applicable gates |
| Actual native INTEGRATION_PASS | NOT_TESTED, separate from code review |
| Merge, version Tag, release, deployment, production Exec switch | FORBIDDEN WITHOUT NEW EXPLICIT OWNER AUTHORIZATION |

For code-candidate assembly, the milestone acceptance is a concrete
self-contained **COMMITTED** RC tree and a complete current-source Manifest,
a source-equivalent assembled feature set, honest raw Linux-safe-test evidence,
a full changed-path inventory and a written blocker ledger. This is not the
same milestone as safe native qualification, true user-device readiness,
production release or external adoption of the inactive T1 controls.

If a new RC Base/Head, Design-002 approval, selected toolchain, native inputs
or workflow execution identity changes, reevaluate affected old reviews and
test applicability. Never change a B/C verdict, historical test or the
frozen PR113/PR118 Head to make the RC appear releasable.
