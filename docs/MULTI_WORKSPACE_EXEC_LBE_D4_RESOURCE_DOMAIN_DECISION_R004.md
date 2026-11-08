# D4 R004 — macOS PRODUCT_T1 execution-domain design decision (PROPOSAL ONLY)

TASK_ID: MULTI-EXEC-LBE-FIVE-DAY-CANDIDATE-20261105
MILESTONE_ID: LBE-FIVE-DAY-CORE-PRODUCT-CANDIDATE
DESIGN_ROUND: D4-DOMAIN-DESIGN-003
CONTRACT_ID: MWE-LBE-D4-PRODUCT-T1-RESOURCE-DOMAIN-R004-CANDIDATE
STATUS: PROPOSED_NOT_EFFECTIVE / NEEDS_B_AND_C_INDEPENDENT_DESIGN_REVIEW / OWNER_CHOICE_NOT_RECORDED
REVIEW_SCOPE: TARGETED_DESIGN_DECISION_ONLY
PR: chinanjjohn2012/mac-file-gateway#114
PARENT_DESIGN_GIT_BLOB: f8556b48ab5f4af7390fb015092862a8a87768fb (D4 R003; unchanged)
RULESET_ID: ICR-V2.0
HANDOFF_PROTOCOL_ID: GHRH-2.0
EVIDENCE_PROFILE_ID: ETP-V2.0
EXECUTION_AUTHORITY: NONE
R006_CODE_FULL_REVIEW: NOT_ISSUED

## 1. Decision required before implementing or running native PRODUCT_T1

R003 sec. 2(c), 5, and 6 requires an exact disposable **GitHub-hosted macOS 15
ARM64** job and an *actually attached* enforcement domain for the **original
child plus descendants**, with CPU <=2000 millicores and RAM <=4096 MiB.
It expressly rejects a runner-label string, observed RLIMIT, soft timeouts,
sampling after spawn, and a synthetic T0 packet as proof. An owner statement
of intent to authorize F1/D0 positive Exec or native T1 does not, on its own,
prove an execution domain or amend those operative gates.

The current PR114 r006 service-owned six-command source path is real SOURCE/T0
product code, but the macOS launch adapter `D4MacOSRunnerLaunchBoundary.launch`
unconditionally provides `LbeNoChildStarted` rather than spawning. There is
no attached OS-domain backend that could change this without a newly
independently reviewed executable design and runnable code.

Current verified feasibility blocker:
- GitHub official hosted-runner reference, viewed 2026-11-08:
  https://docs.github.com/en/actions/reference/runners/github-hosted-runners
  says arm64 macOS GitHub-hosted runners do NOT support nested virtualization.
  It does not document a per-job CPU/RAM process-tree resource controller
  satisfying this R003 tuple. Therefore a VZ guest cannot be assumed available
  *inside the prescribed hosted runner*; absence of an identified controller
  is an evidence blocker, not proof that no macOS implementation is possible.
- Apple Virtualization.framework:
  https://developer.apple.com/documentation/virtualization/vzvirtualmachineconfiguration
  describes configurable guest virtual CPUs, memory, devices and entitlement
  requirements; `cpuCount` is a **guest vCPU count**, not an independently
  attested host CPU-millicore quota:
  https://developer.apple.com/documentation/virtualization/vzvirtualmachineconfiguration/cpucount
  and `memorySize` is the **guest-recognized** physical RAM, not a proved
  host-wide process/VM resident-memory cap:
  https://developer.apple.com/documentation/virtualization/vzvirtualmachineconfiguration/memorysize
  These APIs are design primitives, NOT evidence of an actual attached
  enforcement domain for this PR.
- AWS EC2 official Mac Dedicated Hosts reference, viewed 2026-11-08:
  https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-mac-instances.html
  describes bare-metal Mac instances on Dedicated Hosts, with at least
  24-hour host allocation. This is a possible **future provider class**, not
  an already provisioned or owner-approved resource.

## 2. Two mutually exclusive future decisions (neither is approved)

**OPTION A — preserve the strict numeric R003 security objective, change the
test provider (preferred candidate for independent feasibility review).**
A purpose-provisioned, fully disposable, dedicated bare-metal Apple-silicon
macOS 15 host (not user Mac, not shared runner or production system) could
host an Apple Virtualization.framework disposable guest running the exact
first-party product fixture. A proposal may request guest `cpuCount=2` and
`memorySize=4294967296` bytes. However:
  - A two-vCPU VM is not, by itself, an observed 2000m host CPU quota.
    Hypervisor threads and kernel work may consume host resources outside
    guest process accounting. Guest memory size likewise does not bound all
    host VM overhead. B/C must define and independently verify the exact
    required accounting domain, enforcement semantics and failure behavior.
  - The VM guest must actually be compatible with the selected macOS
    restore image and target tests; the platform must prove virtualization
    entitlement, code signature, available guest CPU/memory minimum, image
    bytes/digest, boot/source baseline, guest binaries, network/mount policy.
  - The entire original-child/descendant lifetime must be confined *inside*
    the identified guest, with the original process assigned to that domain
    BEFORE its first unapproved instruction. Host-side debug Popen, native
    process controls, shared folders, guest exec tunneling or test-runner
    credential propagation are not exceptions.
  - A verified VM lifecycle and resource association is necessary, but
    neither VM teardown nor host cleanup proves the original-child exit or
    makes retries safe. Preserve direct-child UNKNOWN/uncertainty protocol.
  - The original R003 "GitHub-hosted" identity and job-shape requirement
    changes. A new contract version, independent B/C design PASS and precise
    user approval for a specific dedicated provider/host/job are mandatory.
    Until approved, **do not substitute** a bare-metal host for R003.

**OPTION B — retain GitHub-hosted macOS 15 ARM64 and explicitly propose a
weaker trusted-host native T1 without a whole-tree OS CPU/RAM limit.**
This may align with PR98's lightweight operator-trusted-code product direction,
but it violates R003's *non-optional* per-domain test qualification. R003,
PR102, and operative F1/D0 remain unchanged unless a separately reviewed
new version expressly removes this invariant and the owner accepts:
  - unbounded original-plus-descendant CPU/RAM consumption within host
    runner capacity, any outbound traffic / same-UID filesystem and
    process exposure, possible descendant survival after timeout, lost ACK
    / manual retry duplicate side effects and last-moment pathname races;
  - exact first-party source, runner identity, no credentials/shared mounts,
    operation limits, actual native-code review, and all old deny conditions;
  - the inability to claim R003 or PR102 SOURCE_TOOLCHAIN_T1 compliance or
    full-tree isolation from a weaker test.
No automatic approval is inferred from the previous user message or from
a GREEN source-only test. A lower-risk or lower-cost intent alone cannot
override the current mandatory gate.

**Decision state:** Neither A nor B is selected. Do not silently blend
GitHub-hosted provider identity from R003 with VM proof from another host.
Neither choice updates the operative product contract in this document.

## 3. Mandatory owner/runner exact tuple before implementation

Before a real executable backend or experimental T1 job can be enabled, a
single explicit future authorization artifact must bind at minimum:

1. Exact chosen resource/provider contract **new GitBlob**, B and C
   independent SHA-bound design results and change list from R003;
2. REPO, PR, TASK_ID, reviewed BASE_SHA, HEAD_SHA, HEAD_TREE,
   synthetic Merge SHA/Tree (separately), complete actual code diff,
   Manifest and all generated/ignored/third-party source identities;
3. exact runner provider, dedicated host identity, actual macOS version
   and ARM64 arch, immutable OS/VM image and guest image identities,
   provisioning/signing/entitlement identities and no-credential proof;
4. exact run/job ID, job/code bootstrapping before third-party imports,
   per-Workspace/cwd/runner and all six fixed public/effective vectors;
5. actual loaded CPython/Pipenv/.venv/.pth/site/seed and Go
   go/compile/link/stdlib/module/build/generated import graph and
   source/loader recheck immediately before first child execution;
6. enforceable resource domain measured *before* native code, the
   association of original and all descendants to the bound domain,
   CPU <=2000m/RAM <=4096MiB if strict Option A, CPU measurement
   semantics, impossible-to-escape device/mount/credential rules, and
   fail-closed on absent or ambiguous evidence;
7. exact one-job limit <=1200 seconds; original child <=120 seconds;
   Worker timeout <=300 seconds; one original per Workspace, four per
   service; stdout/stderr <=48000 raw bytes per stream, <=48000
   redacted output characters per stream;
8. user acceptance of egress/same-UID host impact, timeout/abort
   surviving descendants, no F3/rollback, no unknown PID/PGID signal,
   no automatic replay or auto-clear UNKNOWN.

A future reviewed non-client-mintable capability must be constructed
inside trusted service bootstrap and verified at the *same*
`WorkspaceService.invoke_exec` decision point. REST/MCP payloads, headers,
environment flags, plain dataclasses, test monkeypatches or GitHub
synthetic declarations never authorize production positive Popen.

## 4. Test and evidence matrix, with current status

| Matrix item | Static SOURCE/T0 | Future actual T1 | Today |
| --- | --- | --- | --- |
| R003 chosen six commands + safe source/read-only preflight | Direct/REST/MCP preview and private source candidate tests | Same-instance first-party Python Direct/Pipenv/Go original-child success | T0 only |
| Existing F1/UNKNOWN/owner.lock, v1/legacy and File/Git | Negative regression and lawful File/Git smoke | Same-instance integration with real positive and negative branches | F1 denies |
| Provider identity / checkout / G05 | Exact Head/Tree/Manifest and drift denial | OS/arch/provider/image/run ID observed before imports | Not qualified |
| Original+descendant OS domain | Reject no witness, forged receipt, no backend and ambiguous ownership | Verified attached domain, measurable limits, all child descendants included, loss/restart handling | NOT_IMPLEMENTED |
| Native loaded source identity | Go/Pipenv/Python static candidate/RECORD/dylib closure checks | Dynamic original loader/import/build source resolution and immediate pre-Popen recheck | NOT_ATTESTED |
| Exit, cancel, timeout, crash, retry | Mock/offline fault injection only | Actual original exit/status/pipe EOF, absent ACK/uncertainty and bounded runtime | T1 NOT_RUN |
| T2/T3 / host/network canary | Only safe protocol simulation | Requires further explicit authorization | NOT_AUTHORIZED |

**T1 safe-execution gate:** if ANY actual provider, host, VM/OS-domain,
credential, loaded source, binary/Workspaces, owner and code review evidence
is unavailable, refuse **before** launching Go/Pipenv/Python or signals.
A test returning `LbeNoChildStarted`, Linux CI GREEN or a signed R004
design review is not native T1 evidence.

## 5. Independent DESIGN review request; no automatic product handoff

For this fixed R004 document content, B Standards and C Spec should each
independently decide:
- Is Option A technically credible **without** falsely treating two
  vCPUs/guest RAM as actual host CPU/memory confinement? Which verified
  domain association, source and credential artifacts make it enforceable?
- Is Option B necessarily a *new weaker* contract, and is its full
  residual-risk disclosure sufficient for the owner to decide?
- Can either option meet the F1/D0 old-state, Worker and source rules,
  direct-child uncertainty model, no T2/T3 and PR102 separation?
- Which exact contract fields are changed, which existing requirements
  remain binding, and what is the minimal executable evidence to close
  each P0-P2 blocker?

Only after two independent targeted DESIGN verdicts and the owner's
specific new-version choice should A implement an executable backend
under the then-approved contract. Product r006 is still UNFROZEN;
this is NOT a `GH_HANDOFF_V2 READY_FOR_REVIEW` or `FIX_READY` for
the entire code candidate, not a full-code or integration PASS.

B_STANDARDS_D4_DOMAIN_DESIGN_003: NOT_ISSUED
C_SPEC_D4_DOMAIN_DESIGN_003: NOT_ISSUED
OWNER_RESOURCE_PROFILE_CHOICE: NOT_RECORDED
OWNER_EXACT_JOB_IMAGE_CODE_AUTHORIZATION: NOT_ATTESTED
MILESTONE_STATUS: DEVELOPING
F1_D0_POSITIVE_EXEC: DENY
PRODUCT_T1: NOT_RUN
INTEGRATION_STATUS: NOT_TESTED
R10_STATUS: BLOCKED
FREEZE_READY: NO
NEXT_ROLE: B/C DESIGN ONLY for this exact proposed contract;
           A retains product r006 ownership and must not alter frozen
           design bytes while B/C assess the proposal.
