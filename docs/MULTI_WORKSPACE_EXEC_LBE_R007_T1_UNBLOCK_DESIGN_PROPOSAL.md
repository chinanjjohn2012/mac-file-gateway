# Multi-Workspace Exec LBE R007 - PRODUCT_T1 Unblock Design Proposal

DESIGN_ID: MWE-LBE-R007-T1-UNBLOCK-DESIGN-006-CANDIDATE
STATUS: PROPOSED_NOT_EFFECTIVE
PARENT_CONTRACT: MWE-LBE-D4-PRODUCT-T1-TRUSTED-HOST-R006-CANDIDATE
PARENT_R006_GIT_BLOB: b8d8a1cb32fb7130dfa6d00b37831dfddfaad11c
RULESET_ID: ICR-V2.0
HANDOFF_PROTOCOL_ID: GHRH-2.0
EVIDENCE_PROFILE_ID: ETP-V2.0

This proposal does NOT authorize PRODUCT_T1 and does not change current R006
admission. It becomes relevant only after independent B/C design review and a
later explicit owner decision.

## 1. Blocking facts

A's r007 code work closes the code-addressable r006 findings: current-run G05
receipt plus fresh checkout re-admission, run-bound actual host safety, and
target-specific one-shot status.

Real standard GitHub-hosted macOS 15 ARM64 T0 then repeatedly observed:
- actual Darwin arm64 / macOS 15.8.2;
- no ambient proxy variables;
- SSH_AUTH_SOCK present;
- writable non-local autofs at /System/Volumes/Data/home;
- PRODUCT_T1 NOT_RUN and native launch denied.

R006 requires no production secrets, no checkout-credential persistence, no
shared writable mounts, and DENY on unknown proxy/credential exposure. A may
not special-case the two observed facts as safe without a contract decision.

There is also a review-order cycle: current product code requires B/C FULL
ROLE_FULL_SCOPE_PASS before PRODUCT_T1, while r006 Standards requires actual
PRODUCT_T1/native integration evidence before it can issue that FULL pass.

## 2. Host eligibility decision

### A0 - retain R006 strictly

SSH_AUTH_SOCK remains unknown credential exposure and the observed writable
non-local autofs remains disallowed. The currently observed standard
GitHub-hosted macOS 15 runner is therefore ineligible. PRODUCT_T1 stays DENY.

### A1 - exact two-fact exception, owner-risk weakening

Only after B/C design PASS and a later explicit owner acceptance, a future R007
contract may permit exactly:
1. SSH_AUTH_SOCK may exist in the GitHub-hosted runner process environment,
   but the product child environment MUST omit it and every other credential
   selector. GITHUB_TOKEN, GH_TOKEN, Actions runtime/id-token variables, cloud
   credentials, checkout extraheader/helper, embedded remote credentials and
   all other secret selectors remain DENY.
2. One writable non-local autofs mount at exactly
   /System/Volumes/Data/home may exist. Every other writable non-local mount
   remains DENY.

All current Run/Job/G05, source allowlist, private Workspace/cwd/output, proxy,
checkout-credential, durable nonce and fresh pre-Popen checks remain mandatory.

A1 adds two explicit residual risks:
RISK_10: a same-UID process may discover or use the ambient runner SSH agent;
agent key contents/availability are not proven absent.
RISK_11: the auto-home autofs trigger may activate storage outside the reviewed
Workspace; no no-shared-mount guarantee is claimed for that exact trigger.

A1 does not permit arbitrary SSH selectors, proxy settings, arbitrary writable
network mounts, production credentials, user Mac/Tunnel, shared production
hosts, or T2/T3.

## 3. T1 review sequencing decision

### B0 - retain FULL-before-T1

The current gate remains. Because Standards requires T1 evidence before FULL,
PRODUCT_T1 remains blocked.

### B1 - TARGETED T1 qualification before one T1, FULL after evidence

A future implementation may accept two independent TARGETED reviews on the
same exact frozen Base/Head/Tree only as prerequisites for one separately
owner-authorized PRODUCT_T1 attempt.

Each pre-T1 B/C Review must state:
- REVIEW_SCOPE: TARGETED
- REVIEW_LEVEL: TARGETED_REVIEW_PASS
- VERDICT: PASS
- EVIDENCE_STATUS: SUFFICIENT only for T1 execution qualification
- INTEGRATION_STATUS: NOT_TESTED
- T1_EXECUTION_QUALIFICATION: PASS
- no P0/P1/P2 source/admission blocker in the targeted pre-T1 scope
- PRODUCT_T1 and integration remain NOT_RUN
- NOT ROLE_FULL_SCOPE_PASS and NOT FULL_CODE_REVIEW_PASS

The owner exact-attempt grant then binds the two Review node IDs, frozen
Base/Head/Tree/Manifest, run_id/run_attempt, reviewed source bundle/recipe,
runner/host profile, nonce and expiry. Only one separately authorized benign
PRODUCT_T1 attempt may follow.

After that attempt, B/C independently perform FULL reviews using original
native/integration evidence. TARGETED qualification never inherits or promotes
to FULL. ICR-V2.0 FULL semantics are unchanged.

## 4. Implementation allowed only after approval

If A1 is approved:
- special-case only the exact two host facts above;
- retain final fresh pre-Popen recheck and durable nonce burn/no replay;
- reject any second credential selector, any proxy, any other writable
  non-local mount, platform drift or selected-source drift;
- explicitly report FULL_BOOT_IMAGE_ATTESTED=false,
  ACTUAL_LOADED_GRAPH_PROVEN=false,
  NO_SHARED_WRITABLE_MOUNTS_PROVEN=false,
  NO_AMBIENT_SSH_AGENT_PROVEN=false.

If B1 is approved:
- replace the current FULL-only T1 review gate with an exact
  T1_EXECUTION_QUALIFICATION targeted-review gate;
- require distinct Standards/Spec Review node IDs and exact same snapshot;
- retain direct-owner exact-run approval and all durable replay controls;
- no public client/config/env may mint this witness.

## 5. Current evidence

Pre-proposal code Head: 9edf0772457b68b365d9e9e98ee750b0fadf4909
Linux run 42462019492: SUCCESS; G05 PASS; 3283 passed, 19 skipped,
52 subtests; HTTP/MCP/Git smoke and final checks SUCCESS.
macOS run 42462019544: FAIL-CLOSED before PRODUCT_T1; Darwin arm64,
no proxy, SSH_AUTH_SOCK present, writable non-local autofs at
/System/Volumes/Data/home present.
PRODUCT_T1: NOT_RUN
INTEGRATION_STATUS: NOT_TESTED

No current evidence authorizes A1 or B1. No PRODUCT_T1/T2/T3, credential-agent
query, network canary, kill/signal, user Mac/Tunnel, production, merge, tag,
release or deployment is authorized.

## 6. Independent design questions

B Standards:
1. Is A1 bounded and honest, or must A0 remain?
2. Does B1 preserve independence and prevent TARGETED-to-FULL promotion?
3. Are the negative oracle and owner-grant bindings sufficient?

C Spec:
1. Can A1 yield deterministic legal positive and deterministic credential/mount
   negatives without false no-credential/no-shared-mount claims?
2. Does B1 allow one exact benign T1 while keeping T1/integration NOT_RUN from
   being mislabeled FULL?
3. Are RISK_10 and RISK_11 precise enough for a later owner decision?

Until independent design review and later owner choice:
HOST_OPTION=UNDECIDED
REVIEW_SEQUENCE_OPTION=UNDECIDED
PRODUCT_T1=DENY
R007_DESIGN_STATUS=PROPOSED_NOT_EFFECTIVE
