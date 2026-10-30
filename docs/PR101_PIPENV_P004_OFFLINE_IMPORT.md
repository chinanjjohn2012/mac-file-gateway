# PR #101 — P004 six owner-approved Wheel import probes in disposable macOS ARM64 CI

PROPOSAL_ID: PR101-PIPENV-P004-OFFLINE-SIX-IMPORTS-20261030
TASK_ID: MULTI-EXEC-LBE-V1-CONSOLIDATED-20261030
ROLE: A DEVELOPER, test implementation not independent source review
REVIEW_TARGET: exactly six known P002 Wheel inputs plus preapproved packaging 26.3
APPLICABLE_CONTRACT: PR98 r002 user-accepted MWE-LOCAL-BEST-EFFORT-V1.0-CANDIDATE Blob 9e6622401b198138039c692efe91fba1a8d06891
PRIMARY_PROPOSAL: PR101 P001 Blob 96bbd02cd384bd9769cd6af9f5a763442e25d61a
EXTERNAL_INPUT_LOCK: PR101 P002 fixed six Blob c39a83d001512169bf9bb2cc19a0e56b1c0d79c4
ORIGINAL_36_WHEEL_LOCK: ci/wheel-locks/macos-15-arm64-3.13.sha256 Blob f6310fef4596ce20bfa8da35ae8d4883e6b714b5
CURRENT_HEAD: consult authoritative GitHub PR #101, not this static document
RULESET: ICR-V2.0/GHRH-2.0/ETP-V2.0 REFERENCED; effective governance remains not independently proved

## Owner authorization and strict scope

On 2026-10-30 the owner approved downloading six version/SHA256-locked P002
Wheels and then approved their **isolated installation, import or execution**.
This is limited to GitHub-hosted disposable macOS 15 ARM64 CPython 3.13; six
specific PyPI wheels plus a previously source-approved packaging 26.3 wheel
from the original 36 are the ONLY permitted new offline installation inputs.

No Go compiler execution, Pipenv executable, project code, Go native test/vet/
build, user Mac, live Tunnel/REST/MCP, production resource, destructive signal,
T2/T3, merge, tag, deploy, production config or descendant-cleanup claim.

This P004 is a restricted **package import smoke** and source-installed RECORD
check. It is NOT a declaration that the third-party sources are benign, that
all optional dependency markers are satisfied, that a full Pipenv virtualenv
has been qualified, or that real Go/Pipenv Exec contracts were tested.
The owner authorization does not manufacture B/C independent reviews.

## Ordered CI gates

1. Fixed PR Base, real Head/TREE, clean ephemeral macOS-15 ARM64 and G05 before
   package downloads or imports. Original 257+ tracked manifest entries.
2. Pure T0 adversarial tests before network: P002 metadata guard, P003 archive/
   HTTP/RECORD, P004 fake installed RECORD/fail-closed provenance tests.
3. Set up Python 3.13 on approved hosted runner after G05. Fetch exactly six
   release JSON files and verify exactly six pinned real Wheel SHA256/archive
   RECORDs using P003 source checker. No package code is run in this step.
4. Fetch ONLY original-lock packaging==26.3 Wheel; compare its actual SHA256
   to Git Blob f6310f... and inspect archive SHA/RECORD. No resolver of unknown
   third-party packages or other new Wheel downloads is permitted.
5. Offline install seven exact already verified Wheels using pip --no-index,
   --no-deps, --no-compile into a new RUNNER_TEMP private target. Pip performs
   the installation; no unreviewed online dependency auto-resolution.
6. Verify all seven installed METADATA and RECORD SHA256 byte identities BEFORE
   any of the six imported module roots are executed.
7. In one isolated Python 3.13 -I -S interpreter, add ONLY the private target
   ahead of trusted stdlib search locations; import distlib, filelock,
   platformdirs, python_discovery, setuptools, virtualenv, in that order.
   Each import must resolve inside the exact target and the full probe
   must complete within a 5-second observed budget. Python audit hook refuses
   socket connect/bind, subprocess, os.system/fork/exec and ctypes loading.
   This is defense in depth, not a kernel sandbox or general ability to stop
   any malicious native extension; no os.kill/killpg or timeout signal is used.
8. Reverify installed RECORD against observed bytes and all six original Wheel
   download SHA256 values; Git diff and Manifest remain unchanged. Retain
   only ephemeral runner-owned private evidence, no artifact publication
   outside CI logs.

## Explicit independent security and compatibility gaps

- Real source import executes package code by design; SHA, wheel RECORD,
  no-network intent and a Python audit hook alone do not establish trust.
  Independent B/C security source assessment remains NOT_ISSUED and R10
  INCOMPLETE even if P004 tests are successful.
- PyPI publisher provenance for setuptools and distlib is not attested,
  and distlib 0.4.4 does not declare Requires-Python. Metadata alone cannot
  prove Python3.13 compatibility; a real import is a limited observation.
- This is NOT a full wheel marker/extra-resolution proof, Pipenv main wheel
  import/execution, virtualenv environment creation, or any business command
  integration. Only six explicit module imports and installed RECORD are in
  scope. Missing requirements/hashes fail closed; no automatic wheel upgrades.
- An import timeout without observed exit cannot be called success. No signal
  is sent to forcibly terminate an unknown process; GitHub job remains subject
  to its explicit 12-minute outer cap. No protected shared resource.
- If a legitimate installed console-script record escapes the private target,
  the fail-closed checker reports FAIL rather than broadening the target
  or silently accepting an unreviewed path.

NEXT: Inspect P004 raw CI (HEAD/TREE/runner/source wheels/installed RECORD/
exit status), repair any bounded test defect without changing product security
contract; then independent B/C source and full code reviews and approved real
Go/Pipenv T1/REST/MCP remain separate stages.
