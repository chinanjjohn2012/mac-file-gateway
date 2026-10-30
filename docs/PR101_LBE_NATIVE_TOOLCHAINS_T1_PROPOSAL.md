# PR #101 — Native Go/Pipenv T1 external-input qualification proposal

PROPOSAL_ID: PR101-LBE-T1-TOOLCHAINS-P001
STATUS: PROPOSED_SOURCE_CANDIDATES_ONLY / NOT_APPROVED_FOR_NEW_NATIVE_EXECUTION
TASK_ID: MULTI-EXEC-LBE-V1-CONSOLIDATED-20261030
TARGET: future source-qualified go test/vet/build/-o and Pipenv positive T1 on disposable GitHub-hosted macOS 15 ARM64
APPLICABLE_DESIGN: PR #98 r002 exact design Head 07b7497e3d100be70a014d6ecdb5b5db018fc708 / Blob 9e6622401b198138039c692efe91fba1a8d06891
DYNAMIC_SNAPSHOT: see current PR #101 Body and original GitHub CI, not this static proposal.

This document is a developer A **proposal**, not an approved security contract,
an operative v1/D0 amendment, a READY_FOR_REVIEW, a source-lock certificate,
an independent B/C conclusion or production release permission. The owner
previously accepted a weaker local_best_effort mode and risk-qualified real
process tests. The **present** native fixture is still explicitly Python-only.
Neither the proposed third-party files nor Go/Pipenv have been downloaded,
installed or executed by this PR's approved native T1 workflow.

## 1. Why the existing green CI is insufficient

- On the current hosted macOS 15 ARM64 T0 runner, after HEAD-bound G05 and
  before dependency setup, pure-Python PATH inventory reported
  LBE_CANDIDATE_GO=NOT_FOUND count=0 and
  LBE_CANDIDATE_PIPENV=NOT_FOUND count=0. This is a finding about that PATH
  snapshot only, not universal absence from the OS or a user Mac.
- The existing 36 original source-locked wheel inputs do not include Pipenv.
  The Go compiler/linker/standard library/module cache/toolchain closure is
  not covered by the existing Python wheel/RECORD attestation.
- Recording or matching the SHA256 of a PATH executable alone is NOT proof
  of its compiler/runtime/dependency closure, absence of path shadowing,
  a sandbox, or an authorization to run project code. The inventory itself
  never invokes the discovered programs.

## 2. Independently published upstream *candidates* (unverified local bytes)

Candidate A — Go compiler/stdlib archive:
- Official source: https://go.dev/dl/?mode=json
- Release: go1.27.3; file: go1.27.3.darwin-arm64.tar.gz
- Officially published archive size: 68196737 bytes
- Officially published archive SHA256:
  dd3908cf20959d798c1e06ebe5b72213f0505ce01373b40ce3110975a6cd99c2
- Status: OFFICIAL_METADATA_SEEN / ARCHIVE_NOT_DOWNLOADED /
  ARCHIVE_BYTES_NOT_HASH_VERIFIED / EXTRACTED_GOROOT_NOT_ATTESTED /
  NATIVE_NOT_RUN.

Candidate B — Pipenv distribution wheel:
- Official source: https://pypi.org/project/pipenv/
- Release: 2026.10.4; file: pipenv-2026.10.4-py3-none-any.whl
- Officially published wheel SHA256:
  308125623e4d08dfe32936f7259a9ed33c5480baa2c9a291a1ff8a9328eeeb1f
- Official PyPI release date: 2026-10-28
- PyPI lists no upload provenance/attestation for this release. This is an
  explicit source-trust gap, not an assertion of maliciousness.
- Status: OFFICIAL_METADATA_SEEN / WHEEL_NOT_DOWNLOADED /
  WHEEL_BYTES_NOT_HASH_VERIFIED / TRANSITIVE_CLOSURE_NOT_PINNED /
  INSTALLED_RECORD_NOT_ATTESTED / NATIVE_NOT_RUN.

These are **candidate version selections**, not accepted inputs. Choosing
them does not replace the original R004 36 locked wheel source identities
or permit online dependency resolution during Gateway-command execution.

## 3. Required deterministic source qualification before any new T1

1. After exact committed HEAD/TREE G05 and fixed Base admission, fetch
   separately approved source archives into a disposable runner-owned
   wheelhouse/toolchain directory. Independently SHA256-check the *actual*
   downloaded bytes against the reviewed exact hashes before extraction
   or installation. If missing/mismatched, fail closed; no Go/Pipenv child.
2. Inspect the Go archive entry types, paths, symlinks/hardlinks, expanded
   sizes and traversal boundaries before extracting to a new RUNNER_TEMP
   prefix, not /usr/local, Homebrew, shared caches or the developer's Mac.
   Record canonical executable and compiler/linker/stdlib byte identities;
   freeze the local-only go.mod and generated project source digest. No
   unreviewed Go toolchain auto-download, module fetch, cgo or arbitrary
   external tool hook.
3. Resolve Pipenv's complete compatible dependency closure (including
   any new wheel *not* present in the original 36), pin every wheel SHA256
   in a **separate explicitly reviewed test-only source lock**, install
   only offline into an ephemeral private Python environment, then
   attest installed RECORD-listed hashes before and after. Freeze the
   Pipfile/Pipfile.lock, local test script bytes and any created venv state.
   An unpinned Pipenv wheel alone is not a runnable source identity.
4. Fix and attest the effective PATH order and executable origins used
   by the real WorkspaceService launcher, not merely by shell tests.
   Reject path shadowing and missing/changed binaries; record allowed
   Go runtime cache/module/script inputs as GENERATED_OR_EXTERNAL.
5. Use only runner-owned disposable Workspace roots and private state,
   distinct from repository/runtime import roots. Repeat original v1
   owner-lock/healthy-state qualification; no state reset or inherited
   UNKNOWN/RETIRED trust grant. Never use a real shared/user Workspace.
6. Before starting any new native command, obtain an **explicit extension
   of the existing Python-only hosted T1 fixture authorization** identifying
   the actual source lock version, effective Head/Tree, Go/Pipenv operations,
   input fixtures and concurrency/timeout budgets. A green T0 candidate
   inventory is not that approval.

## 4. Proposed source-qualified isolated T1 matrix (NOT_RUN)

| Command/route | Required positive result | Negative/boundary result |
| --- | --- | --- |
| Go Direct test ./... | observed original exit 0, bounded output | reject -exec / -toolexec / noncanonical package |
| Go Direct vet ./... | original exit 0 in pinned local module | reject -vettool, -modfile, module/network drift |
| Go Direct build ./cmd/service | original exit 0, no uncontrolled output | reject arbitrary tool hooks/options |
| Go Direct build -o bin/service | original exit 0, output in disposable project | block symlink, hardlink, excluded/secret/output escape |
| Pipenv run python ok.py | observed original exit 0 in qualified private environment | block excluded/hardlinked Pipfile, unsafe runner input |
| REST /run + official SDK MCP | same shared WorkspaceService results and error codes | no double spawn on timeout/disconnect/denied grant |
| Per-Workspace concurrency | one real original/Workspace, four total | busy with unknown live original, no implicit retry |
| Output/lifecycle | 48K per stream; truthful truncation/exit/timeout | cleanup_not_proven, no forced unknown PID/PGID signal |

**Proposed strict budget remains unchanged unless separately approved:**
GitHub-hosted disposable macOS 15 ARM64, original G05 first, job <=12 minutes,
one original child/Workspace and four/service, each request <=5 seconds,
max 48,000 chars per output stream; no shell or additional network after
verified artifact staging, no destructive PID/PGID signals, no T2/T3, no
user Mac/Tunnel. Go cold compilation or Pipenv environment preparation may
exceed 5 seconds: if the observed direct exit cannot be proven within this
contract, report timed_out/NOT_RUN or request a **specific revised resource
authorization**; never infer timeout exit, signal a process or call it PASS.

## 5. Explicit missing decisions and status

- INPUTS: Exact test-only Go archive and Pipenv wheel choices, their actual
  downloaded byte SHA256s, complete Pipenv transitive wheel lock, and
  verified GOROOT/toolchain + local modules are NOT established.
- SOURCE_REVIEW: Separate security qualification of distribution source,
  archives, expanded components and Pipenv's lack of PyPI provenance:
  NOT_APPROVED. This file is developer A planning evidence only.
- AUTHORIZATION: New native Go/Pipenv fixture, any necessary toolchain
  staging/download/install in CI, and any change to timeout/resource bounds:
  NOT_APPROVED for execution in this proposal.
- EXECUTION: Go/Pipenv real positive NOT_RUN; full integration NOT_TESTED.
  Prior exact-Head Python-only T1 and fake-child Go/Pipenv T0 results are
  evidence for their stated scopes only, not this future native matrix.
- R10 / B/C: No developer assertion of ROLE_FULL_SCOPE_PASS, independent
  FULL_CODE_REVIEW_PASS, integration acceptance, or production activation.

NEXT: A may complete nonexecuting source-lock planning; user explicitly
approves the exact expanded isolated fixture and source input list; A then
runs original verified CI on a new committed Head, freezes it and requests
separate B/C FULL reviews only after proper rule-source parity/activation.
