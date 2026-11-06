# D4 PRODUCT_T1 qualification preparation — declaration-only SAFE T0

TASK_ID: MULTI-EXEC-LBE-FIVE-DAY-CANDIDATE-20261105
MILESTONE_ID: LBE-FIVE-DAY-CORE-PRODUCT-CANDIDATE
SUBSTAGE: D4_PRODUCT_T1_EXECUTION_QUALIFICATION_PREPARATION
REVIEW_ROUND: r006 (DEVELOPING, UNFROZEN)
CONTRACT_ID: MWE-LBE-TRUSTED-PRODUCT-T1-PROFILE-R002
CONTRACT_GIT_BLOB: a31e4517bbd4d2c3d2d0f4370619e3043cd973bb
RULESET_ID: ICR-V2.0
HANDOFF_PROTOCOL_ID: GHRH-2.0
EVIDENCE_PROFILE_ID: ETP-V2.0
STATUS: NONOPERATIVE_PREPARATION / PRODUCT_T1_NOT_AUTHORIZED
T0_ONLY: YES
NATIVE_GO_PIPENV: NOT_RUN
INTEGRATION_STATUS: NOT_TESTED
R10_STATUS: BLOCKED

## 1. Why this code exists

The existing D4 R002 design is a **proposed**, network-capable,
operator-trusted product test distinct from the independently reviewed
PR102 r002 **OFFLINE_ONLY SOURCE_TOOLCHAIN_T1**. The owner accepted the
separately fixed PR98/PR102 Gate A *risk model* (recorded by A in PR102),
but has NOT given an exact-version D4 network-capable PRODUCT_T1 owner
consent or qualified source/runner/CPU/RAM budget. No previous B/C
TARGETED design PASS or Linux T0 CI removes these remaining requirements.

This change adds gateway/lbe_product_t1_profile_t0.py and its standalone
safe synthetic tests. The module validates the **declared shape** of the
proposed D4 execution packet in a strictly nonoperative way. It uses only
built-in pure Python data validation: no syscalls for identity, filesystem,
process, network or security configuration; no shell/Go/Pipenv imports or
execution. No product runtime path imports it as a grant, and there is no
native launcher, workflow_dispatch, external canary or new public flag.

A structurally valid candidate **ALWAYS** yields
NONOPERATIVE_D4_PRODUCT_T1_DECLARATION_T0 and the following booleans
set to FALSE: runner_identity_observed, loaded_source_observed,
os_resource_enforcement_proven, credential_isolation_proven,
risk_acceptance_by_owner_observed, native_launch_allowed,
product_apply_allowed. The dedicated authorize_native_product_t1_from_t0
ALWAYS rejects even if a dataclass is maliciously replaced or supplied
with apparent approval fields. A green declaration is not a Gate B
exception, a Go/Pipenv child authorization, or a Mac/source witness.

## 2. Proposed fixture and budget declaration (NOT owner-approved)

Candidate **test input selection**, restricted to fresh disposable
first-party project fixtures, is precisely:

- python -m pytest -q
- python -m compileall
- pipenv run python -m pytest -q
- go test ./...
- go vet ./...
- go build -o bin/app ./cmd/app

The parser rejects alternate shell, Go run/toolhook, pipenv install,
Python -c, path traversal, missing/duplicate/changed fixture vectors,
unknown fields and custom objects with comparator/hash hooks.
These commands are NOT actually executed by this profile.

Candidate host declaration must name github-hosted, macos-15, arm64,
disposable, a syntactically fixed image ID and SHA256, no credential
persistence, secrets, user Mac, Tunnel, shared mounts or production.
These booleans are merely untrusted declarations, NEVER real
observations of a GitHub Actions job, its GITHUB_TOKEN, or its child
execution environment. A future actual job must independently observe
OS/image/arch, checkout/config/token isolation and boundary before
any untrusted Go/Pipenv import or process.

Candidate bounds (upper limits, not enforcement evidence):

| Proposed field | Candidate value | Actual enforcement |
| --- | ---: | --- |
| One test job wall time | 1200 seconds | NOT_PROVEN |
| Per expected-to-exit original child | 120 seconds | NOT_PROVEN |
| Public Worker upper timeout | 300 seconds | Existing contract, real T1 NOT_RUN |
| CPU quota proposal | 2000 millicores | NOT_PROVEN |
| RAM quota proposal | 4096 MiB | NOT_PROVEN |
| Raw stdout/stderr retention | 48000 bytes per stream | Native NOT_RUN |
| Redacted returned stdout/stderr | 48000 characters per stream | Native NOT_RUN |
| Concurrent product test jobs | 1 | Native NOT_RUN |
| Original children per Workspace | 1 | Native NOT_RUN |
| Original children per service | 4 | Native NOT_RUN |

The CPU/RAM quantities above are **A's proposed T0 input values only**,
not the missing reviewed enforceable macOS quotas, and not additional
permission to run any task. If no verifiable applicable resource
boundary is available, actual PRODUCT_T1 remains BLOCKED. In
particular, elapsed-time CI settings and environment variables alone
do not enforce whole-tree CPU, memory or process cleanup.

The only accepted candidate network-mode declaration is
TRUSTED_HOST_EGRESS_POSSIBLE_NOT_OFFLINE_ONLY. This preserves the
risk disclosure that selected code and its descendants may access
outbound networks and same-UID filesystem/process resources, survive
crash/restart, and duplicate effects after lost ACK/manual retry.
No-fetch fixture **intention** is not egress enforcement. The module
cannot attest owner risk acceptance and never silently changes PR102's
separate OFFLINE_ONLY Gate B.

## 3. Required declared source identities versus physical proof

The packet requires syntactically fixed candidate Git HEAD, Git Tree,
Manifest SHA256, runner-image digest and source digests for go archive,
compiler, linker, stdlib, module graph, Pipenv CLI, CPython interpreter,
venv/site, seed, Pipfile.lock and dynamic/import closure. This list is
a prospective evidence **index**, not a claim those sources were read.
Placeholder-looking test hashes are allowed only in pure T0 tests and
must never be copied into an owner authorization or live runner job.

Before any future T1, a separate *actual* runner-bound procedure must
produce and independently verify: exact NEW runnable first-party
Head/Tree/complete effective diff and G05; controlled execution image
and credential/privilege boundary; real Go compiler and stdlib/module
loaded sources; executable Pipenv CLI/shebang/CPython/venv/installed
RECORD, unlisted importable .pth/site/seed sources; fixture identity;
and pre-Popen rechecks for private state, source paths, command, closed
environment, cwd and -o. A digest declaration or selected nofollow
file snapshot is not proof of actual loaded code or post-close pathname
identity. Prior source-only archives and limited Wheel RECORD proofs
cannot substitute for actual-loader evidence.

## 4. T0 test matrix and execution prohibition

Tests/test_lbe_product_t1_profile_t0.py exercises normal structural
proposal, all time/capacity/output boundaries, missing/extra source
and runner fields, malformed version/digests, wrong macOS/architecture,
credential flags, network-contract confusion, malicious Python objects,
command tampering/duplicates, risk-disclosure loss, post-return input
mutation and forged permission-like dataclass copies. It patches
subprocess, socket and OS signal entrypoints in the structural success
test and verifies no such effects occur. This is a synthetic Python
T0 with no real Go/Pipenv/Mac native test.

Do not add a GitHub Actions native T1 job or invoke one as part of this
source candidate. Do not issue a public F1 exception, modify
WorkspaceService positive authorizer, remove the NativeLauncher Go/
Pipenv pre-Popen refusal, alter v1/Legacy/old UNKNOWN/owner.lock,
or claim full descendant cleanup, sandbox or network isolation.

## 5. Closing conditions for future AUTHORIZATION (still open)

1. Independently review any future changed D4 executable test contract
   and exact implementation Head/Base/Tree (B Standards and C Spec);
   the current r006 source candidate is not a frozen review target.
2. Obtain the owner's **new, explicit, exact** trusted nonisolated
   PRODUCT_T1 approval: external network and same-UID risks, possible
   surviving descendants/crash replay effects, the actual fixed
   first-party command fixtures and a resource-domain failure policy.
3. Fix exact loaded Go/Pipenv/Python source, actual runner job/image,
   enforced CPU/RAM/credential/mount/host limits and failure/timeout
   handling. If any required proof is unavailable, STOP before Popen.
4. After separate authority, run only the explicitly permitted
   disposable macOS T1 profile and capture original command, child
   exit, output, failure and execution-source evidence. Product
   source-only T1, real WorkspaceService T1 and same-instance
   Direct/REST/MCP+File/Git integration are distinct claims.
5. Freeze complete code candidate, gather matching B/C full-scope
   reviews and R10/integration eligibility as independently required.
   Release/merge/deploy/T2/T3 remain separate explicit decisions.

NEXT_ROLE: A DEVELOPER for remaining authorized source qualification;
B/C only at a real applicable freeze or blocking design change.
NEXT_COMMAND: 继续开发 (SAFE_T0_ONLY); real PRODUCT_T1 remains NOT_RUN.
