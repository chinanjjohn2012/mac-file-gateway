# PR119 six-command MVP: isolated T1 control preparation, design v1

DESIGN_ID: LBE-RC119-T1-CONTROL-PREPARATION-DESIGN-001
TASK_ID: MULTI-EXEC-LBE-RC119-T1-CONTROL-PREP-20261116
MILESTONE_ID: LBE-RC119-T1-CONTROL-PREP-001
ROLE: A DEVELOPER; this is a PROPOSAL for independent B Standards and C Spec design review
DESIGN_STATUS: NONOPERATIVE / STATIC_T0_CANDIDATE / NOT_NATIVE_AUTHORIZED
SOURCE_REVIEW_ROUND: PR119 RC-CODE-FULL-001, B/C both BLOCKED on evidence
SOURCE_RC_BASE_SHA: ec25c34492912f3a82175fa9c1060e0632814687
SOURCE_RC_HEAD_SHA: 33c30b6c2710cac0f8533370c1ca42f31ef6747a
SOURCE_RC_HEAD_TREE: 27e26c423e700cdbad0aeca27efcdf82594507c1
PARENT_PRODUCT_CONTRACT: fixed Owner-approved Design-002 Git Blob d90df6de3bdbd81a314109d5f73959799b5a10a6
RETAINED_SECURITY_CONTRACT: PR102 Gate B/C Git Blob 7db3b77aadca8b0c284e28fa5ee64e315e9275d2
PR113_PREVIOUS_DESIGN_WORKING_BLOB: 4806c2958eebdf14e3e3c02cbc50764d0bc823ed
RULES: ICR-V2.0 / GHRH-2.0 / ETP-V2.0
AUTHORIZATION_SCOPE: Owner approved a separate Draft PR for static test control, identity manifest and SAFE T0 ONLY.
NATIVE_T1_EXECUTION: NOT_RUN / NOT_AUTHORIZED
RELEASE_MERGE_DEPLOY: NOT_AUTHORIZED

## 1. Isolation, topology, and nonoperative guarantees

This branch starts from PR119 frozen HEAD 33c30b6c2710cac0f8533370c1ca42f31ef6747a, but does not modify
that PR branch or any Python/Pipenv/Go launch/product code. The new PR base
is the existing PR119 feature branch, so its direct delta is only these
nonoperative control-preparation files plus MANIFEST.sha256.

The module tools/lbe_rc119_t1_control_static.py is pure data: it imports
only Python re, never reads or modifies the filesystem, opens a socket,
imports foreign project code, invokes GitHub, creates a child or returns a
positive launch grant. The SAFE T0 tests use disposable in-memory dicts,
hard-trap subprocess.Popen and test exact negative conditions. They are NOT
an actual T1 executable workflow, a security boundary, an external
source attestation or a production product change.

No workflow YAML, pull_request labeled native trigger, dispatch endpoint,
permission switch, installation script, testing credential or runtime Exec
feature has been introduced. Control commit SHA/Tree and exact PR number
must be bound from GitHub AFTER the final source/test snapshot is frozen;
those values are not guessed or used as a test permit.

## 2. Frozen six-command and transport contract

This is the future ONE-SERVICE 18 positive T1 observation proposal:
S1 py-direct Direct: python -m pytest -q.
S2 py-direct Direct: python -m compileall -q ./src.
S3 py-pipenv Pipenv: requested python -m pytest -q, effective pipenv run python -m pytest -q.
S4 go-project Direct: go test ./....
S5 go-project Direct: go vet ./....
S6 go-project Direct: go build -o bin/app ./cmd/app.
Each of S1 to S6 has exactly 3 ingress routes: Direct, loopback REST,
official SDK-backed MCP SERVER. A future authenticated official
ClientSession socket client remains separate from the historical
SDK-backed server tested by manual JSON-RPC. All 18 observations must
share one WorkspaceService / owner / state/lock identity. The mixed phase
runs in ONE second dedicated disposable service: one real S1 and real
File/Git before/during/after and under historical UNKNOWN after S1 exit.
No child may be launched by the static control or new tests.

Illegal seventh command (such as go run . or go test ./another), extra
flags, wrong runner/cwd, timeout, client-controlled args, alternate
selected programs and any unqualified source must be denied before
Popen. A future negative T0 control must intercept the reviewed actual
subprocess creation path in a SEPARATE negative-only process with an
independent hard veto, zero launch counter and three ingress outcomes.
If the actual launcher changes, that control must be re-reviewed.
The positive T1 process must not inherit the monkeypatch. Physical
Git/File operations cannot be run under a global Popen hard veto.

## 3. Explicit one-run/two-phase Owner authority requirement

A future nonautomatic test-control workflow, if independently approved,
must bind exact RC HEAD/TREE and independently frozen control HEAD/TREE,
one approved run_id and run_attempt=1, owner actor and Owner's separately
authenticated exact approval, an independently reviewed profile Blob,
the input-lock SHA256, and sequential SIX then MIXED phases. MIXED must
not start without positive/complete SIX and the same unique run identity.

The in-memory inspect_event function checks only synthetic consistency:
wrong actor, PR, SHA/Tree, control identity, phase order, replay attempt,
repeated phase, changed run_id, stale/revoked Owner description and a
missing input/profile digest. It ALWAYS denies actual execution. A GitHub
label, actor name, Owner-shaped dict, local Python set or concurrency key
is NOT an authenticated, atomic, durable one-shot authorization lease.
A future independently reviewed controller needs a real atomic
consume-once design bound to first-hand Owner permission, plus current
GitHub event verification, revocation and job serialization. Until such
an independently reviewed capability exists: T1 NOT_RUN.

## 4. Input identity closure — current template only, no external bytes

See docs/LBE_RC119_T1_INPUT_LOCK_TEMPLATE_V1.json. It lists required
categories: both first-party checkout/control source, pinned GitHub
actions, exact macOS image, selected Python and stdlib, Pipenv entrypoint
and Pipfile/lock/private venv/site, complete wheel and installed RECORD
closure, Go compiler/stdlib/module, generated fixtures, Python fixture,
MCP SDK source and import-precedence shadow checks. All external input
expected/observed SHA256 and provenance fields are NULL with explicit
NOT_ATTESTED. The immutable RC repository Head/Tree in this template
are true CURRENT source metadata only, not local installed-input proof.
This static parser never opens, downloads, hashes or imports external
bytes. A self-filled digest, a matching claimed SHA, GitHub CI GREEN,
or historical PR114 receipt is not a verified native source closure.

Real execution will need separately approved exact acquisition, actual
per-byte independent evidence, no unlisted import/loader/source-shadow,
explicit selected-tool/Pipenv/Go identification and before-Popen
rechecks. The old PR114 macOS ZIP receipts do not preserve a complete
wheelhouse/loaded provenance; do not invent missing bytes or simply
declare the inputs ATTESTED. A later immutable lock update requires
its own reviewed snapshot and first-hand evidence.

## 5. B/C decision: competing network/risk profiles (NOT effective)

PROFILE A = SOURCE_CLOSED_OFFLINE_ONLY, retains stronger PR102 Gate B:
prove actual precontact enforced egress deny attached to each foreign
child and descendants; separately authorized harmless same-domain
verification before any T1; loopback explicitly scoped; authenticated
source acquisition occurs BEFORE isolation. A vanilla GitHub macOS
runner, GOPROXY=off, PIP_NO_INDEX or post-contact logs alone DO NOT
qualify. No concrete approved macOS precontact enforcement mechanism
exists at present. PROFILE A: BLOCKED / NOT IMPLEMENTED.

PROFILE B = DESIGN002_TRUSTED_LOCAL_BOUNDED_HOSTED (NEW VERSION PROPOSAL):
trusted exact-source hash-locked code inside a dedicated disposable
hosted macOS ARM64 runner; no repo credentials, OIDC tokens, SSH agent,
Git write grant, caller-supplied PATH/Go/Pipenv selection, or shared
user mount. Source provision only from separately approved exact
origins/artifact hashes; allow intended runtime network exposure as
explicit NAMED RESIDUAL RISK, without falsely claiming offline or
egress enforcement. No network restriction is silently weakened:
B and C must independently adjudicate exact PR102 Gate B applicability,
contract conflict, which profile is permissible and where a new signed
version is necessary. Owner must expressly approve any weaker bounded
profile and its uncontained network, local same-UID filesystem access
and descendant/duplicate-side-effect risk. If not approved, FAIL CLOSED.
No actual network probe, firewall/pf, sandbox change or native launch
is performed by this design or current PR.

## 6. Future resource and phase budget to approve

Proposed: TWO sequential phases, at most ONE active hosted job at a
time, 20 minutes maximum each, monotonically prelaunch check
remaining time >= command timeout (<=120 s) + dedicated reserve
(>=180 s) or refuse the next child. 18 x 120 seconds does NOT
fit a 20-minute job; missing deadline yields NOT_RUN, not retry.
One original child per Workspace / four per service. 48,000
retained raw BYTES per stdout and stderr stream vs 48,000 redacted
returned CHARACTERS, distinct caps. Never claim descendant cleanup
on waiter timeout/worker exit or hosted-runner teardown.

Hosted 3 CPU/7 GB/14 GB are VM allocations, NOT per-child hard caps.
Filesystem 'only fixture writes' can be asserted only to observed
monitor coverage, not arbitrary code outside the fixture. Owner and
B/C must review this risk; any enforceable OS isolation mechanism is a
separate reviewed design, not implicit permission for T2 force kill,
unknown state reset, source deletion, live egress or user Mac/Tunnel.

## 7. Acceptance and exact next gates

The CURRENT authorized milestone is completed only by (a) isolated
committed Draft control/manifest/design source, (b) static no-spawn
positive-format and denial counterexamples, (c) exact current source
SHA/Tree+Manifest+original CI for SAFE T0, (d) evidence/status ledger,
and (e) B/C independent design review request on ONE frozen Head once
all authorized preparatory work is complete. This is not a product
native T1 or R10 gate closure.

B/C should independently review:
- exact six-command and dual transport phase identity, no seventh
  executable; RED absent native negatives vs static T0-only denial;
- atomic/one-use/replay: current pure matcher is NOT a durable grant;
- complete inputs/real external bytes absent; correctness of schema;
- PROFILE A v PROFILE B contract/risk and PR102 Gate B conflict;
- timeout, host, filesystem, output, old UNKNOWN & File/Git adjacency;
- source identity and static test completeness.

After independent design decisions and if source-control/provenance
remain approved, Owner must SEPARATELY permit an exact test-control
implementation/locked input acquisition. Only once those are frozen
and proven must Owner give an additional exact one-run/native T1
authorization. The current permission does not cover installation,
native execution, actual Mac/Tunnel, production, merge, tag or deploy.

TEST_EVIDENCE_NOW: NOT_RUN before current-Head CI; new tests designed
as pure SAFE T0 only; historical PR114 18/18 and mixed actual T1
belong to a different Head/event and are not inherited.

FREEZE_CONDITIONS: static current-Head Linux SAFE T0/Manifest pass;
the full nonoperative prepared scope and open gates recorded honestly;
then one GH_HANDOFF_V2 READY_FOR_REVIEW for B/C targeted design/static
review, not a T1 clearance. Any code after freeze -> new Head/round.
