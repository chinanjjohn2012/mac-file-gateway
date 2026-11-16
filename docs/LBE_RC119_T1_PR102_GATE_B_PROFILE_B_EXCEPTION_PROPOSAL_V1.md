# PR102 Gate B — narrowly scoped six-command T1 Profile B exception (proposal v1)

DESIGN_ID: LBE-RC119-T1-PR102-GATEB-PROFILEB-EXCEPTION-001-CANDIDATE
TASK_ID: MULTI-EXEC-LBE-RC119-T1-PROFILEB-DESIGN-20261116
MILESTONE_ID: LBE-RC119-T1-PROFILEB-CONTRACT-001
REVIEW_ROUND: PROFILEB-GATEB-DESIGN-001
REVIEW_SCOPE: TARGETED DESIGN, NOT EXECUTABLE CODE/T1/FULL REVIEW
DESIGN_STATUS: PROPOSED_NOT_EFFECTIVE
REPO: chinanjjohn2012/mac-file-gateway
SOURCE_RC_PR: 119 (OPEN/DRAFT/FROZEN)
SOURCE_RC_HEAD_SHA: 33c30b6c2710cac0f8533370c1ca42f31ef6747a
SOURCE_RC_HEAD_TREE: 27e26c423e700cdbad0aeca27efcdf82594507c1
PARENT_STATIC_CONTROL_PR: 120 (OPEN/DRAFT/FROZEN)
PARENT_STATIC_CONTROL_HEAD_SHA: 299bcaff1c075396d205caa450344f7246350d62
PARENT_STATIC_CONTROL_HEAD_TREE: 90e4423f2fd13d5f5f0b9e6c18e393048115d02e
PARENT_PR102_GATE_B_BLOB: 7db3b77aadca8b0c284e28fa5ee64e315e9275d2
PARENT_SIX_COMMAND_DESIGN_002_BLOB: d90df6de3bdbd81a314109d5f73959799b5a10a6
PARENT_PR120_STATIC_DESIGN_BLOB: 52405da8ee867c9abd8c19e3ece71a3058616022
RULESET_ID: ICR-V2.0
HANDOFF_PROTOCOL_ID: GHRH-2.0
EVIDENCE_PROFILE_ID: ETP-V2.0
AUTHORIZATION_FOR_THIS_PROPOSAL: Owner allowed A to DRAFT a new six-command-only
  PR102 Gate B Profile B contract exception and request independent B/C
  design review. This approval is NOT ratification of the proposed exception.
ACTUAL_NATIVE_T1_PERMISSION: NOT_GRANTED
OWNER_EXACT_PROPOSAL_BLOB_RATIFICATION: NOT_ISSUED
B_STANDARDS_INDEPENDENT_DESIGN_VERDICT: NOT_ISSUED
C_SPEC_INDEPENDENT_DESIGN_VERDICT: NOT_ISSUED
EFFECTIVE_GATEB_REPLACEMENT: NONE
NO_NATIVE_OR_NETWORK_TEST: TRUE
NO_MERGE_RELEASE_DEPLOY: TRUE

## 1. Exact decision and legal baseline

This document asks B Standards and C Spec to independently review whether
a NEW, weaker, clearly named *six-command T1-only* test-environment contract
may be offered as an explicit versioned exception to PR102 Gate B
(Blob 7db3..., sections 3, 5 and especially 5.3, 7 and 8).

Existing PR102 Gate B is still the operative authority for claiming its
isolated SOURCE-CLOSED hosted Go/Pipenv T1:
- OFFLINE_ONLY requires enforceable precontact outbound TCP/UDP/DNS denial
  attached to actual foreign children and descendants, with independently
  approved same-context negative verification.
- BOUNDED_EGRESS requires an enforceable, precontact host/IP/port and
  byte/time allowlist plus independently verified per-process attachment.
- GOPROXY=off, PIP_NO_INDEX, sanitized environment, a post-contact network
  log, or a GitHub-hosted macOS runner are NOT substitutes.

PROFILE B below explicitly **does not meet either PR102 network control**.
It is a proposed new *trusted-code residual-network-risk exception*.
Calling it "bounded", "offline", "precontact isolated" or PR102 §5.3
compliant would be inaccurate. Until independent B+C review of this exact
immutable proposal, later first-hand Owner ratification of its exact Blob
and named risks, and separate implementation and one-shot-run permissions,
**PR102 Gate B is unchanged and T1 remains NOT_RUN**.

Approval to write this document is not permission to weaken Gate B,
download/install Go/Pipenv/Python, create a runnable workflow/lease,
probe egress or credentials, change a CI safety check or launch any child.

## 2. Proposed exact replacement/KEEP matrix (NOT operative)

| Parent clause | PROPOSED outcome for exact qualified RC119 six-command native T1 ONLY | Other scope |
| --- | --- | --- |
| PR102 §3 Gate A (operative product approval) | KEEP: same immutable-version B/C + Owner approved product grant; this proposal cannot mint one | unchanged |
| PR102 §3 Gate B enforceable precontact outbound isolation | REPLACE ONLY for an independently approved, exact-Head disposable six-command T1 event with the Profile B residual-network-risk acceptance of §4; no claim SOURCE_CLOSED_OFFLINE_ONLY | all other Go/Pipenv/native tests KEEP old Gate B |
| PR102 §5.1 closed Go/Python/Pipenv environment and hooks | KEEP required before any original child; validate actual selected executable/source and zero unapproved helper | unchanged |
| PR102 §5.2 Pipenv .venv pointers/symlinks/interpreter | KEEP mandatory no-follow pre-Popen denial and exact selected venv/seed/source identity | unchanged |
| PR102 §5.3 OFFLINE_ONLY and BOUNDED_EGRESS | REPLACE ONLY their mandatory precontact egress witness for this named Profile B event, WITH explicit risk instead; neither original category may be claimed as PASS | original §5.3 remains mandatory outside exception |
| PR102 §5.4 source-only vs product-origin T1 | KEEP: only real WorkspaceService/owner original-child may prove six-command product T1; separate source-only success is not product PASS | unchanged |
| PR102 §§6–7 argv, error, result, T1 budgets | KEEP exact six-command scope from Design-002; prior PR102 generic Go/Pipenv command list does NOT broaden this MVP | unchanged |
| PR102 §8 sequence and Gate C | KEEP independently reviewed control, source + native original logs + B/C FULL/R10, no automatic production release | unchanged |
| Design-002 §§1–7, D0/F1 old-state, G05, independent File/Git | KEEP exact six vectors, schema-v2 dual opt-in, owner/UNKNOWN, same-service routes, original-child truth; no runtime gate changes here | unchanged |
| R006 strict macOS host observation | KEEP actual FAIL visible. Independent contract applicability/host qualification decision required; Profile B is NOT an automatic R006 waiver | unchanged |

This proposal does NOT modify the immutable PR102 Blob, retroactively
relabel a prior Review, change existing workflow YAML, or activate any
fallback from Profile A to B. A later operative exception MUST explicitly
cite the final immutable proposal Blob and new Owner approval and state the
narrow, time-bounded scope.

## 3. Absolute scope boundaries: 18 + bounded mixed event

A future authorized original-child product observation consists of exactly
six immutable request rows, each via three ingress routes Direct, loopback
REST and official MCP SERVER attached to the **same** WorkspaceService:

| S | exact workspace-relative cwd | trusted runner | requested argv |
| --- | --- | --- | --- |
| S1 | py-direct | direct | ["python","-m","pytest","-q"] |
| S2 | py-direct | direct | ["python","-m","compileall","-q","./src"] |
| S3 | py-pipenv | pipenv | ["python","-m","pytest","-q"] (effective ["pipenv","run","python","-m","pytest","-q"]) |
| S4 | go-project | direct | ["go","test","./..."] |
| S5 | go-project | direct | ["go","vet","./..."] |
| S6 | go-project | direct | ["go","build","-o","bin/app","./cmd/app"] |

Actual operator-selected Workspace ID is not hardcoded and must remain
service-owned and independently validated. One additional MIXED phase
may observe S1 with independently authorized **real** File/Git operations
in a separate new disposable service, before/during/after S1 and with
historical UNKNOWN safely denied; no unapproved File/Git grant is inferred.
MIXED is contingent on the same approved one-shot identity and successful
complete SIX; it is not 19 extra arbitrary original-child commands.

Never accept S7, shell, Python -c, Go run or altered package/output/flags,
client-supplied effective argv/runner/environment, an alternative Workspace
or bypass of the original WorkspaceService sync gate. The negative-only
Popen veto uses a separate process, with a verified ZERO original-child
counter; positive T1 is NOT permitted merely because that T0 negative passes.

Outside exact RC119 frozen Head/Tree, approved one-use controller Head/Tree
and its one disposable run, this exception automatically has **NO scope**.
It is NOT general product Exec configuration, not a persistent environment
permission, not a source-only generic Go/Pipenv authorization, not user
Mac/Tunnel, not T2/T3, and not a production release grant.

## 4. Proposed Profile B environment and named residual risk (REQUIRES OWNER)

PROFILE_ID: RC119_SIX_T1_TRUSTED_DISPOSABLE_HOSTED_NETWORK_UNRESTRICTED_B1
PROFILE_STATUS: DESIGN_ONLY_NOT_APPROVED

A future version may choose an independently identified **dedicated
disposable hosted macOS ARM64** runner/service account, with prequalified
first-party RC and selected Python/Pipenv/Go/SDK source and private fixture.
There is no guarantee that a standard GitHub runner supplies the required
host or accessible-secret isolation. Its exact image identity and source
qualification must be attested; a current R006 image-claim mismatch is
**not** overridden by naming the machine "trusted".

Before launch, separately approved operator-only preparation must:
- establish a fresh throwaway runner, dedicated non-shared workspace and
  private state/lock; prove no user/shared/production mounts;
- establish that the native child or same-UID project code cannot access
  repository write credentials, SSH agents/keys, OIDC request tokens,
  GitHub Actions/write tokens, sensitive HOME/config/cache files,
  metadata secrets or externally mounted credentials. Scrubbing environment
  keys alone is NOT a no-accessible-secrets proof;
- pin original runner image and toolchain, verify controlled script,
  module, generated fixture, selected Go/Pipenv/Python and SDK identity
  before any future original-child spawn;
- construct a fresh reviewed closed child env/selected absolute programs;
  deny ambient GOFLAGS=-toolexec, GOENV, GOCACHEPROG, GOEXPERIMENT,
  Python/virtualenv import shadow, Pipenv redirect .venv and other hooks;
- require strict Workspace scope/runner/cwd/argv, existing-only healthy
  old-state and owner.lock, no retry or false descendant-cleanup receipt.

**Residual risks requiring separate first-hand explicit Owner acceptance:**
1. **Unrestricted network first contact:** trusted Go/Pipenv/Python source,
   tests or descendants may initiate arbitrary outbound TCP/UDP/DNS/HTTP,
   including contact to unexpected endpoints, before any post-contact
   monitor could detect it. PROFILE B has NO enforceable precontact
   egress deny and NO actual bounded-egress host/IP/byte guarantee.
2. **Same-UID host effects:** source code may read/write other
   user-accessible files, start processes or affect disposable-host state
   beyond fixture paths; workspace allowlist is not an OS sandbox.
3. **Descendant/cancel risk:** waiter timeout, disconnect, observed original
   child exit or hosted shutdown does not prove child-tree cleanup; do
   not auto-kill old/unqualified PID/PGID or claim the descendants stopped.
4. **Ambiguous rerun/restart:** duplicate side effects remain possible if
   an operator reissues a command after missing ACK, crash or UNKNOWN;
   no blanket replay or F3 durability claim.
5. **Residual source race:** independently attested paths and bytes cannot
   automatically rule out pathname-to-exec/loader races under same UID.

The owner must be shown these risks verbatim (or a later accepted exact
version), the exact disposable host, intended network exposure and
scope, and must ratify the specific immutable contract Blob AFTER B and
C independent design reviews. A generic "approved" or earlier
permission to *draft* is not this decision. If the owner declines or
the dedicated host cannot prove absence of accessible secrets: FAIL CLOSED.

## 5. Source lock, identity, authority and no-launch prerequisites (KEEP)

The current #120 lock template contains 22 required input categories and
ALL external expected/observed digests/provenance are NULL/NOT_ATTESTED.
It proves ONLY that categories are enumerated; it is **not** source
qualification. Even perfectly matching self-asserted hashes do not prove
actual selected bytes.

A future separate, authorized source-preparation step must acquire and
independently verify approved upstream archives/hops/size/SHA, installed
wheel RECORD *and unlisted importables*, Python interpreter/stdlib,
Pipenv entrypoint, .venv/bin/python and seed selection (including pointer
files, symlinks and site paths), Go executable/compiler/stdlib/modules,
generated fixtures, official MCP client/server source and import precedence.
The pre-Popen check must fail for runtime-selected source outside the lock,
unsafe ownership/symlink/hardlink or loaded code outside the manifest.
External downloads/staging/tool installation are explicitly NOT allowed
during the current design-PR milestone.

An actual executable controller still requires separately implemented,
independently reviewed authenticated first-hand Owner authorization:
fixed RC119 Head+Tree, fixed control Head+Tree, exact Profile B Blob and
input-lock digest, exact run_id+attempt=1, revocation/expiry and a
durably atomic consume-once claim across concurrent Jobs. The SIX phase
must prove same-run completion before MIXED, not trust a mutable string
"SIX_PASSED"; duplicated/cross-run/replayed/revoked events must deny
before any child. If the controller cannot prove these properties,
native_execution_authorized MUST remain false, and T1 NOT_RUN.
A GitHub label, actor name, passed CI check or matching mock dict is NOT
a signed run permission.

## 6. Proposed time, resource and output envelope (NOT authorized)

Two sequential phases, one active native job/run at a time:
- SIX phase: propose <=45 minutes for six requests x three entrances;
  each selected original child <=120 seconds and an independent
  monotonic prelaunch reserve >=180 seconds. 18 x 120 seconds is
  36 minutes even before preparation and transport overhead; 45 minutes
  may be too short for cold staging. If insufficient, stop and record
  remaining rows NOT_RUN; no hidden retry or extending budget.
- MIXED phase: propose <=20 minutes in a new owned disposable service
  under the SAME one-use approval identity, after SIX is witnessed fully
  successful. No concurrent second native Job; no repeated SIX/MIXED.
- Hard admission: one original-child per Workspace, maximum four
  simultaneously per service, bounded 48,000 retained raw BYTES per
  stdout/stderr stream and separately 48,000 redacted output CHARACTERS.
  No false complete-output receipt or unredacted secrets.
- Hosted runner virtual CPUs/RAM/disk are only host allocation
  observations, NOT per-child CPU/RSS/disk hard limits. A future design
  must explicitly accept that gap or implement independently verified
  limits before making a resource-containment claim. Never T2 kill.
- Record late spawn, partial success, stream/owner failure, cleanup
  uncertainty and original-child exit status. No automatic side-effect
  retry, rollback, old-state reset, killpg or process-tree retirement claim.

All budgets in this section are **new proposals for Owner and B/C**,
not existing test eligibility, and cannot silently extend an older
five-second Python-only or 20-minute candidate authorization.

## 7. Minimum pre-run AND post-run evidence if subsequently approved

PRE-RUN [future, currently NOT_RUN]:
1. B and C independently approve exact revised exception
   (TARGETED DESIGN) and resolve retained PR102 section conflicts;
   then Owner directly ratifies its fixed Git Blob and the five
   network/host/descendant/replay/race risks.
2. B/C independent executable-controller source review; the product
   remains unchanged on frozen #119; source/host/credentials/profile
   and complete selected external byte closure are separately qualified.
3. Owner independently grants exact new run_id/attempt/RC Head+Tree,
   controller Head+Tree, input-lock SHA and physical T1 profile.
   No standing label, wildcard or implied reuse.
4. All prelaunch negatives have zero unauthorized Popen on actual
   reviewed code path; fail before native import/launch on credential,
   source, control, config/old-state, event/replay or host mismatch.

DURING [future, currently NOT_RUN]: original direct child observations for
18 exact commands/routes on one service; later MIXED original S1+File/Git
on separate dedicated service; bounded stdout/stderr, witnessed process
exit and truthful possible descendants. Never perform unapproved egress
probes or intentional crash/kill experiments.

POST-RUN [future, currently NOT_RUN]: independently captured job logs,
source execution identity, actual image/installed/imported inputs,
one-run lifecycle and original child exits; any network audit is
observational ONLY under Profile B, cannot prove denial of first contact.
Missing/ambiguous evidence must remain FAIL/BLOCKED/NOT_RUN, not a passed
T1. Historical PR114 18/18 original native observations belong to
different Head/event and are NOT automatically a current PR119 result.

RC119 independent B/C FULL/R10 and real user Mac/Tunnel
INTEGRATION_PASS are SEPARATE gates. Even successful T1 does NOT
authorize production, merge, version tag, release or deployment.

## 8. Independent design decision matrix and adversarial examples

B Standards and C Spec must each read the original PR102 Gate B full
Blob and this exact proposal (including current nonoperative #120
static review), and independently decide every row below:

| Question | Failing or adversarial case | Minimum decision/proof |
| --- | --- | --- |
| A vs B legality | proposed Profile B first contact without precontact deny | explicitly choose an exact versioned waiver for SIX-only, or reject; NEVER call it PR102 OFFLINE_ONLY/BOUNDED_EGRESS |
| Identity | valid first-party Git Tree but altered Pipenv wheel/venv/go stdlib or .pth loader | reject until selected original bytes/import source locked and qualified |
| Credentials | child env scrubbed but Git/runner/OIDC/SSH accessible via files or metadata | reject if accessible secret remains; no "clean env implies secret-free" |
| Owner | forged run_id/actor/label/approval dict or revoked run | deny; authenticated one-use atomic durable event identity required |
| Replay | two concurrent Jobs consume same run_id or MIXED sees SIX_PASSED of different run | deny; durable same-run phase proof and one active lease |
| Boundary | S7, different Go output/module/hook, wrong Workspace or REST/MCP args | zero Popen; exact six across all routes, no test-only bypass |
| Resources | cold Go build exceeds remaining deadline, stream overflows, child may survive | mark affected row NOT_RUN/uncertain; never auto-repeat or claim cleanup |
| R006 host | current macOS image claim mismatch despite G05 PASS | cannot claim strict R006 PASS; independent choice of compatible qualified host/contract applicability |
| Scope | source-only CLI T1 pass, or same service unavailable for File/Git | not product T1; real service/original-child and mixed provenance necessary |
| Contract drift | Profile B silently applied to all PR102 Go/Pipenv or user Mac | reject; no broad enable, no production |
| Provenance | old PR114 18/18 macOS PASS but new RC119 native inputs unverified | history only, no inherited exact-Head PASS |

For this proposal there is deliberately NO implementation RED/GREEN or
native source acquisition; the only allowed CI is ordinary current-Head
source identity/Manifest/SAFE T0 regression. An independently completed
design review may approve the wording as a conditional future exception,
but MUST NOT grant actual native T1 or close all RC119 proof blockers.

## 9. Explicit stop conditions and future actions

If either B or C finds a P0–P2 scope ambiguity, contradictory retained
PR102 Gate B obligation, insufficient owner risk disclosure, or a
missing indispensable source/host/authorization closure condition,
keep this proposal NONOPERATIVE; A concentrates the design repairs
on a new Head and uses a new review round only after the complete
design milestone is repaired.

This proposal becomes eligible for an *explicit new approved contract*
ONLY after both roles independently PASS the exact design Head/Base/Tree
and Owner later provides first-hand approval referencing the final
immutable Git Blob and accepted named risks. It does not become
effective just because the proposal PR is created, CI GREEN, or B/C
TARGETED_REVIEW_PASS. Current PR102 Gate B remains in force until the
contract activation requirements are independently satisfied. A
separate future authorization is required for external-input acquisition
and controller implementation; another exact one-run authorization is
required for actual T1.

NO_NEW_RUNTIME_PATH: TRUE
NO_NEW_WORKFLOW_TRIGGER: TRUE
CURRENT_NATIVE_T1: NOT_RUN
CURRENT_NETWORK_PROFILE_B: PROPOSED_NOT_EFFECTIVE
CURRENT_INPUT_LOCK: NOT_ATTESTED
CURRENT_R006: FAIL (current PR120 observed image claim mismatch;
  new proposal Head must report its own original result when available)
RC119_FULL_CODE_REVIEW_PASS: NOT_ISSUED
INTEGRATION_STATUS: NOT_TESTED
MERGE_TAG_RELEASE_DEPLOY: NOT_AUTHORIZED
