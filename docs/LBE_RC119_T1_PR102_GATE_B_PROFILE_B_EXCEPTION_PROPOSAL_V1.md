# PR102 Gate B — six-command-only Profile B exception (revised proposal v1.1)

DESIGN_ID: LBE-RC119-T1-PR102-GATEB-PROFILEB-EXCEPTION-002-CANDIDATE
DESIGN_REVISION: 1.1 (current immutable Git Blob; series filename remains V1)
TASK_ID: MULTI-EXEC-LBE-RC119-T1-PROFILEB-DESIGN-20261116
MILESTONE_ID: LBE-RC119-T1-PROFILEB-CONTRACT-001
REVIEW_ROUND: PROFILEB-GATEB-DESIGN-002
PREVIOUS_REVIEW_ROUND: PROFILEB-GATEB-DESIGN-001 (B FAIL P2-01/02/03; C FAIL P2-C121-01/02; no inheritance)
PREVIOUS_B_REVIEW: https://github.com/chinanjjohn2012/mac-file-gateway/pull/121#pullrequestreview-5922878350
PREVIOUS_C_REVIEW: https://github.com/chinanjjohn2012/mac-file-gateway/pull/121#pullrequestreview-5922934045
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
| PR102 §3 Gate B enforceable precontact outbound isolation | CONDITIONALLY REPLACE only the old enforceable egress witness for one separately ratified six-command T1 preparation+product-original-child event using N1-B after a qualified secret-free same-UID domain; initial source/host/Owner requirements KEEP; never SOURCE_CLOSED | all other Go/Pipenv/native tests KEEP old Gate B |
| PR102 §5.1 closed Go/Python/Pipenv environment and hooks | KEEP required before any original child; validate actual selected executable/source and zero unapproved helper | unchanged |
| PR102 §5.2 Pipenv .venv pointers/symlinks/interpreter | KEEP mandatory no-follow pre-Popen denial and exact selected venv/seed/source identity | unchanged |
| PR102 §5.3 OFFLINE_ONLY and BOUNDED_EGRESS | CONDITIONALLY REPLACE this egress witness ONLY for the explicitly approved first-foreign-instruction Profile B domain; substitute N1-B in section 8A, with unrestricted first-contact/dynamic-source risk and no claim of old N1 PASS | original §5.3 remains mandatory outside exception |
| PR102 §5.4 source-only vs product-origin T1 | KEEP: only real WorkspaceService/owner original-child may prove six-command product T1; separate source-only success is not product PASS | unchanged |
| PR102 §6 rejection + §7 host/budget/egress references | KEEP all argv/error/owner/state/closure limits and Design-002 exact six; CONDITIONALLY REPLACE ONLY §6 missing-egress-witness refusal with missing N1-B proof => DENY, and §7 OFFLINE_ONLY witness with N1-B for exact qualified T1; new 45m SIX/20m MIXED and 120s/child are PROPOSALS needing separate approval | original §6/§7 and original budgets unchanged outside event |
| PR102 §8 M2/M3/M4 and Gate C | KEEP independent executable-control/source approval and new code FULL/R10/integration; for exact PRODUCT-origin Profile B only substitute N1-B for old §5.3 egress in M3 while KEEP G1/P1; generic standalone SOURCE-only M2 remains under old Gate B, no source-only PASS promoted; KEEP M4/R10/release gates | original M2/M3 egress requirements operative outside exception |
| Design-002 §§1–7, D0/F1 old-state, G05, independent File/Git | KEEP exact six vectors, schema-v2 dual opt-in, owner/UNKNOWN, same-service routes, original-child truth; no runtime gate changes here | unchanged |
| R006 strict macOS host observation | KEEP SAME-HEAD PR121 actual FAIL on ambient SSH_AUTH_SOCK and writable autofs /System/Volumes/Data/home, notwithstanding G05 PASS; this exception does not waive R006 or attest host | unchanged |

Additional mandatory CROSS-REFERENCE dispositions for any future exact Profile B authority (no omission is a silent KEEP):
- PR102 §5 numbered **item 7**: replace ONLY the old mandatory precontact egress/STOP assertion for this one profile after N1-B; KEEP source acquisition provenance, closed child env, no unsafe unreviewed tool, and original rule for every other event.
- PR102 §5.5 **N1**: for exact Profile B, conditional substitute N1-B same-context first-foreign secret/host/source/Owner admission; old N1 remains mandatory outside scope. Never call N1-B a PR102 N1/OFFLINE_ONLY/BOUNDED_EGRESS PASS. G1/P1/R1/I1 still KEEP.
- PR102 §6 missing **effective precontact egress proof** rejection: replace ONLY that one predicate for approved Profile B with missing N1-B => DENY BEFORE ANY prep hook or original child. All other refusals KEEP.
- PR102 §7 precontact OFFLINE_ONLY witness: replace ONLY with exact N1-B witness for authorized Profile B; other §7 requirements KEEP, 45m SIX/20m MIXED proposed separately (not preapproved).
- PR102 §8 **M2**: general standalone SOURCE_TOOLCHAIN_T1 is NOT covered; original mandatory §5.3 egress continues. Profile B applies only an exact PRODUCT-origin T1 with separately approved prep helpers after first-foreign N1-B; a standalone source-only success never qualifies the product.
- PR102 §8 **M3**: conditionally replace ONLY its N1 egress cross-reference with N1-B for exact approved product-origin Head/control; KEEP G1/P1, private old state, approval and full independent new-Head control source checks. M4 and Gate C KEEP.
- PR102 initial selected-source proof: KEEP witnessed actual source at first foreign instruction. Any purported ALL-runtime-loaded-code/source-closed claim is NOT satisfied by an initial hash under OPEN egress; §8A.3 defines downgraded evidence and a future independent counterexample.
- All original PR102 clauses and fail-closed behavior remain authoritative outside exact one-shot exception; this design has not changed the operative PR102 Git Blob.

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

Before ANY first foreign executable/import/venv-seeder/build-hook instruction, not merely service original-child Popen, independently qualified and separately approved operator-only preparation must:
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
6. **Residual runtime dynamic downloaded-code risk:** with no enforced egress
   and no independently verified complete loader/exec witness, a qualified
   original child may fetch/execute/delete an unlisted helper AFTER initially
   attested hashes; the full executed-code graph remains NOT_ATTESTED.
   This requires separate Owner exact-Blob acceptance and source evidence
   downgrade, not a SOURCE_CLOSED native PASS.

The owner must be shown ALL SIX risks verbatim (or a later accepted exact
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
The PRE-FIRST-FOREIGN-INSTRUCTION check must fail for known UNQUALIFIED
initial selected input or loader, unsafe ownership/symlink/hardlink or
prelaunch imported code outside the manifest. A prelaunch verifier CANNOT
certify bytes downloaded/loaded AFTER an allowed original Popen; use the
runtime source grades and counterexample in section 8A.3.
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
   then Owner directly ratifies its fixed Git Blob and ALL SIX
   network/host/descendant/replay/race/dynamic-source risks.
2. B/C independent executable-controller source review; the product
   remains unchanged on frozen #119; source/host/credentials/profile
   and complete selected external byte closure are separately qualified.
3. Owner independently grants exact new run_id/attempt/RC Head+Tree,
   controller Head+Tree, input-lock SHA and physical T1 profile.
   No standing label, wildcard or implied reuse.
4. All PRE-FIRST-FOREIGN-INSTRUCTION negatives have zero unqualified
   installer/venv-seed/.pth/import/build instruction and original Popen;
   fail on any missing credential, source, host, controller, one-use or
   stage witness BEFORE a preparatory executable, not merely product Popen.
5. Require independently corroborated same UID/mount/FD/socket/metadata
   no-accessible-secret proof (section 8A.2), before the first foreign code.
6. Qualify only initial selected-source evidence, with runtime source
   grade downgrade and future independent oracle in section 8A.3.

DURING [future, currently NOT_RUN]: original direct child observations for
18 exact commands/routes on one service; later MIXED original S1+File/Git
on separate dedicated service; bounded stdout/stderr, witnessed process
exit and truthful possible descendants. Never perform unapproved egress
probes or intentional crash/kill experiments.

POST-RUN [future, currently NOT_RUN]: independently captured job logs,
source execution identity, actual image/installed/imported inputs,
one-run lifecycle and original child exits; explicitly distinguish
PRELAUNCH_INPUTS_ATTESTED_ONLY from RUNTIME_DYNAMIC_EXECUTION_NOT_ATTESTED
and observed out-of-lock dynamic helper => BLOCKED; any network audit is
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
| R006 host | current PR121 G05 PASS but R006 FAIL for SSH_AUTH_SOCK and writable nonlocal autofs; PR120 older image-claim mismatch was a different HEAD | never claim qualified host or R006 PASS |
| Scope | source-only CLI T1 pass, or same service unavailable for File/Git | not product T1; real service/original-child and mixed provenance necessary |
| Contract drift | Profile B silently applied to all PR102 Go/Pipenv or user Mac | reject; no broad enable, no production |
| Provenance | old PR114 18/18 macOS PASS but new RC119 native inputs unverified | history only, no inherited exact-Head PASS |
| Cross-clause legality | PR102 §5 item 7/§5.5 N1/§6/§7/§8 M2/M3 still demand precontact deny | conditional N1-B replacements exact-only; outside scope KEEP old Gate B |
| First preparation contact | pipenv .pth/venv installer starts before service Popen with agent socket present | deny before first foreign instruction, not after Popen |
| Credential context | scrub env but inherited FD, credential helper, shared mount or OIDC metadata still reachable | DENY unless separately corroborated same-UID proof |
| Dynamic source | initial hash matches then transient Go/Python helper fetched/executed/deleted | observed => BLOCKED; not observed => runtime source UNATTESTED, never SOURCE_CLOSED |

For this proposal there is deliberately NO implementation RED/GREEN or
native source acquisition; the only allowed CI is ordinary current-Head
source identity/Manifest/SAFE T0 regression. An independently completed
design review may approve the wording as a conditional future exception,
but MUST NOT grant actual native T1 or close all RC119 proof blockers.

## 8A. Normative R002 correction detail — stage-first N1-B, no-secret proof, dynamic source (NOT OPERATIVE)

This section is part of THIS PROPOSAL ONLY. It supplies explicit
contract and independent negative oracles requested by B/C r001.
It does not create a legal effective exception, control program,
native execution authority, foreign installer permission or secret probe.

### 8A.1 N1-B profile admission, foreign stages and first-contact timing

A future approved N1-B would be a NEW admission vocabulary, not an old
PR102 N1 success:
- PROFILE_B_N1B_PENDING: no proven current host/source/Owner/one-use
  admission; ZERO foreign executable/installer/hook imports or Popen.
- PROFILE_B_N1B_DENIED: any unknown/stale/changed input, UID, mount,
  inherited FD, credential, source, installer, Controller, permit or
  expired/revoked run; ZERO foreign executable starts.
- PROFILE_B_N1B_QUALIFIED_PRE_FOREIGN: possible ONLY with separate
  authenticated one-run Owner approval, full initial selected source,
  independently corroborated same-domain no-accessible-secret witness
  and exact reviewed control/scope BEFORE the FIRST foreign instruction.
  This does NOT assert old N1/OFFLINE_ONLY/BOUNDED_EGRESS PASS.
- PROFILE_B_N1B_UNKNOWN: any lost lease, changed host/identity, late
  source drift or ambiguous original child; stop future admissions,
  no auto kill, retry, old-state reset or cleanup claim.

| Order | Activity and required independently verifiable boundary | Egress status under FUTURE approved exact Profile B |
| --- | --- | --- |
| P-2 | Immutable host/bootstrap/checkout action image and permission identity; unreviewed fetched/bootstrap actions count as executable foreign source, not invisible trusted setup. No inherited privilege into test domain | NO exception for privileged/bootstrap execution |
| P-1 | Before any foreign action, independently qualify the real future child effective UID, FD/socket/mount/HOME/metadata, absence of reachable secret, source+Owner lease, immutable host (8A.2) | No foreign execution until N1-B qualified |
| P0 | Approved exact-origin/archive byte acquisition in separately authorized restricted fetch domain; NO install/import of unknown plugin while checkout/bootstrap credentials reachable. A foreign helper here must instead pass P-1 N1-B in secret-free test domain; current permission grants NO download | No implicit waiver for privileged source fetch |
| P1 | Exact fixed trusted verifier may hash archives, installed candidate paths/RECORD, Go/Pipenv/Python/SDK and fixtures as DATA ONLY; if an installer/import/build hook executes, it is P2, not exempt | No foreign first contact for data-only phase |
| P2 | FIRST foreign installer/venv-seeder/.pth/import/Go helper allowed only AFTER P-1/P1 positive and separately approved control/input contract, rechecked before its first instruction | Possible open network risk only for exact reviewed code/domain; no old egress PASS |
| P3 | Real WorkspaceService S1–S6 x 3 on one owner/state; recheck exact run, N1-B, initial inputs, cwd/runner/argv and old lock just before each original-child Popen | Same qualified exact one-use domain only; runtime source NOT fully attested |
| P4 | Conditional MIXED second disposable service, only after durable authenticated SAME-run SIX_PASSED; one real S1 and independently permitted real File/Git | Exact approved phase only, no second SIX or general grant |
| P5 | Original logs, source and phase grade, witnessed exit, honest survivor uncertainty and durable permit finality | No new executable admission |

FOREIGN means potentially executing third-party Go/Pipenv/Python,
venv seed, Wheel installer, .pth, dynamic import/build helper, or
an unqualified action/plugin, not only original product child.
No post-Popen, postinstall or postcontact observation can ratify
an earlier P2 foreign step. If an actual action is required to
create the host/checkout, it must itself have a distinct approved
provenance/security domain. If that cannot be proven, fail closed.

FUTURE T0 PREP-NEG-01: model a Pipenv .venv seeder/.pth or Go helper
initiating network FIRST during preparation before product original
child. If same-UID credential/host/source N1-B witness is absent
or stale => DENY before its first instruction; no foreign Popen
or import hook, no recovery by a later green original-child preflight.
This is a planned independent negative oracle, not a real network test.

### 8A.2 Same-UID no-accessible-secret compensating control and oracles

N1-B requires an independently corroborated FRESH witness for
credential reachability from the SAME future effective UID/process,
mount, inherited FD, socket and metadata domain as P2/P3/P4.
Do not read, print, transfer or hash actual credential values;
record identities, inaccessible categories, time, exact host
profile, UID/GID, mount table, path, FD and socket metadata and
approved safe sentinel checks only, under a separately approved
safe host-qualification envelope. An environment scrub alone
does not prove secret-free; neither do a GitHub-hosted label,
checkout persist-credentials:false, actor name or static dict.

Must deny when independently identified from that context:
1. Any GitHub Actions/write token, OIDC request token/URL,
   SSH_AUTH_SOCK, cloud key or secret-bearing env/closed-env selector.
2. Any inherited open FD or reachable UNIX-domain SSH-agent,
   credential helper, broker socket (even if env key removed).
3. Any readable .git/config helper, .git-credentials, sensitive HOME,
   .ssh/.config/netrc/cache/checkout file, user/shared/production
   mount, symlink alias or writable nonlocal autofs exposed to
   this UID or descendants.
4. Any accessible cloud metadata identity, runner workload/OIDC
   issuance secret or metadata service credential: with unrestricted
   network a clean env does NOT prove inaccessible metadata.
   Requires independent platform identity evidence, not unapproved
   live outbound probe.
5. Any mismatched or stale host image, environment, UID/mount table,
   root of trust, verifier provenance or postcheck/prelaunch drift.

FUTURE STATIC NEG-SECRET-01: env cleaned but inherited FD4/agent
socket reachable => DENY. NEG-SECRET-02: env empty but checkout
credential.helper/HOME key file readable => DENY. NEG-SECRET-03:
nonlocal writable autofs or shared bind mount accessible => DENY.
NEG-SECRET-04: metadata/OIDC credential still reachable => DENY.
NEG-SECRET-05: identity only attested for a different UID, image
or run => DENY. Qualifying real host probes and independent
same-context safe sentinel/metadata-only negative evidence
require a later explicit Owner approval and B/C safety review.
NONE were executed as part of this documentation PR.

CURRENT PR121 ORIGINAL R006 is a REAL FAIL on old r001 Head
ff07bce1dc498a659298d26c3dec4a4bdb58655b:
D4R006HostAllowlistDenied("ambient credential-bearing environment
is present"), with SSH_AUTH_SOCK and writable nonlocal autofs at
/System/Volumes/Data/home; G05 source checks succeeded first.
This is NOT an observation of credential theft. Parent PR120
failed a different image-claim check on a DIFFERENT Head.
R002 same-HEAD macOS status must be read from its own original Job.

### 8A.3 Source grades, postlaunch transient code and independent T0 oracle

The initial source lock requires actual independently checked Head,
image, external Python/interpreter/stdlib, Pipenv/venv/seed/.pth,
Go/compiler/stdlib/modules, SDK, selected source/fixtures,
real import precedence, installed Wheel RECORD plus unlisted
importables and no unapproved executable selector BEFORE P2.
PR120 22-category template has 0 independently witnessed external
bytes; no current source-qualification PASS.

The *first* selected source is NOT the full future runtime loaded
source graph when open network and arbitrary descendants are allowed.

| Honest grade | Required fact | Forbidden inference |
| --- | --- | --- |
| PRELAUNCH_INPUTS_ATTESTED_ONLY | independently proved selected initial bytes, host and loader before P2 | never all runtime executable inputs |
| RUNTIME_DYNAMIC_EXECUTION_NOT_ATTESTED | no independently proven complete dynamic loader/exec/remote source witness under open network, even if ordinary audit sees no download | NEVER SOURCE_CLOSED_NATIVE_T1_PASS |
| DYNAMIC_FOREIGN_SOURCE_OBSERVED | independently observed additional loaded/executed remote helper outside approved initial source lock | INPUT_DRIFT_OBSERVED/BLOCKED, even if original child exit 0 |
| NATIVE_BEHAVIOR_OBSERVED_WITH_OPEN_EGRESS_RISK | later separately approved Owner risk, qualified initial source, actual witnessed WorkspaceService original child; runtime source graph still unverified | a bounded factual behavior observation only; NOT PR102 fully source-closed T1, not RC119 R10 or integration PASS |

FUTURE T0 NEG-DYNAMIC-01: start from S4 Go test or S1 Python
pytest with unchanged source hashes; simulate post-Popen
download/execute/delete of a transient helper. When witnessed,
source qualification must be BLOCKED; when not witnessed
(not in logs and absent after-run) it MUST remain
RUNTIME_DYNAMIC_EXECUTION_NOT_ATTESTED, not an assertion that
no helper ran. A scanner of only prelaunch files or later filesystem
cannot retrospectively prove absence of a transient helper.
Only a separately reviewed independent runtime exec/import witness
with defensible limitations could support a stronger grade.
No actual helper/network/download/exec was run here.

B/C must decide whether an explicitly Owner-ratified limited
observational native T1 grade could be useful while retaining
RC119 release/R10 source requirements; this document does NOT
unilaterally lower any R10 or mandatory actual native evidence.
If source-closed evidence remains mandatory, report
EVIDENCE_STATUS=INSUFFICIENT/BLOCKED despite exit 0.

### 8A.4 One-run/two-phase atomicity and proposed budgets

A future Controller must consume an independently authenticated
exact Owner one-shot approval bound to RC119 HEAD/TREE, NEW control
HEAD/TREE, final approved contract Blob and input-lock digest,
run_id/attempt=1, expiry/revocation, immutable selected host/UID
and a durable atomic single-active-job lease. Neither actor-shaped
dict, local memory, CI label nor a bare SIX_PASSED string is a
permission. Proposed durable states:
SIX_RESERVED -> SIX_CONSUMED -> SIX_PASSED ->
MIXED_CONSUMED -> MIXED_FINALIZED; FAILED/UNKNOWN
invalidates future admission without replay or force kill.
MIXED may be a separate sequential Job ONLY with independently
verified SAME-run authenticated durable SIX receipt.
One active native job at a time.

Proposed, not approved: SIX <=45 minutes for 18 calls, MIXED
<=20 minutes for separate service, each child <=120s, <=180s
dedicated monotonic remaining-time reserve for startup/finalize
(must have >=180s reserve before each launch), one original
child per workspace/four per service; distinct 48,000 raw
BYTES/stream and 48,000 public redacted CHARACTERS/stream.
18*120s=36min before cold setup; any shortfall => remaining
rows NOT_RUN, never retry/expand original one-shot budget.
Hosted CPU/RAM/disk allocations are NOT per-child hard caps.
No descendant cleanup or T2 signal/physical kill claims.
No budget or implementation approval follows from this draft.

### 8A.5 Concentrated P2 closure mapping (A proposal, NOT B/C signoff)

- B P2-01: §2 expanded PR102 §5(7), §5.5 N1, §6, §7 and §8
  M2/M3 exact conditional KEEP/REPLACE; new N1-B and fail-closed
  outside scope. No general PR102 Gate B change.
- B P2-02: §8A.2 no-accessible-secrets same-UID FD/socket,
  helper/.git/HOME, metadata and mounts; future safe negative
  oracles and explicit missing-proof STOP.
- B P2-03 + C P2-C121-02: §8A.3 split prelaunch attestation
  from downloaded/loaded transient runtime code, explicitly
  downgrade source evidence and require independent counterexample.
- C P2-C121-01: §8A.1 FIRST foreign instruction, including
  early installers/import/venv/Go hooks, before product Popen.
- B P3: §8A.4 authenticated same-run SIX-to-MIXED phase
  and cold-build/time budget clarify, no new permissions.
These are documentation repairs, NOT a claim the defects
are independently CLOSED. Review new fixed r002 Head and
actual raw same-Head CI; previous B/C r001 FAIL remains immutable.

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
