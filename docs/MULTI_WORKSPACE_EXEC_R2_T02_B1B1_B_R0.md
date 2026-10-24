# R2-T02-B1-B1-B/R0 — internal disposable acceptance bridge expected RED

**Stage: test-contract RED ONLY. NOT a Worker implementation or cleanup PASS.**

## Fixed reviewed parent and scope

Base is PR #67 B1-B1-A Head
c58269c798b62775f8621d69fa037d614c8861da,
Tree f1f50248f5198d9afe2e3f2648f5802efb83f5f8.
Separate independent reviews:
[Spec PASS #5636701611](https://github.com/chinanjjohn2012/mac-file-gateway/pull/67#pullrequestreview-5636701611)
and
[Standards PASS #5636703653](https://github.com/chinanjjohn2012/mac-file-gateway/pull/67#pullrequestreview-5636703653).
These pass only the prior **11 expected RED / 31 GREEN** contract, not
a full-descendant cleanup proof or an ordinary Worker default DENY.

Authority: docs/MULTI_WORKSPACE_EXEC_RECOVERY_D0_DESIGN.md §2.1/3/4/6/7H–J,
and docs/MULTI_WORKSPACE_EXEC_R2_T02_B1B1_A.md §Next.

R0 adds a new *nondefault-collected*, non-spawning RED contract suite,
a strict expected RED verifier and a Linux CI workflow. It does not
modify product Worker/Runner, ExecStateStore, REST/MCP/CLI, existing
B1-A/B0 Grant and Listener, the immutable B1-B1-A contract, or old
real-process acceptance tests.

## Acceptance bridge boundary to implement after independent R0 review

B1-A supplies a self-created disposable private root, single-use,
nonserializable TestOnlyGroupRetirementGrant, pinned service/state/owner-lock
and explicit Workspace identities. B1-B0 supplies a genuinely bound,
wire-ready 127.0.0.1 Uvicorn listener. **Neither grants spawn authority.**

The future private gateway._exec_test_bridge module will expose only a
parameter-free create_private_exec_acceptance_bridge() for a trusted
in-process disposable acceptance harness. The returned context object
owns fixture, service, private grant, bound Listener and a trusted,
**in-process-only** trusted_asgi_app. Only the pre-established, exact
live listener + service + pinned state + enumerated Workspace identity
may qualify. The trusted ASGI app MUST NOT be mounted to the network
Listener; no request body/header, Host value, config/env/CLI flag or
caller-minted scope may select it. Any normal/direct or untrusted network
nonpreview attempt on the private Listener must fail before Runner
and PREPARED with exec_cleanup_proof_required, HTTP 503 or MCP structured
isError=true. Ordinary read-only preview and File/Git remain independent.

On close, revoke before network teardown, do not release pinned FDs
while a real Listener thread is alive; failed join must fail closed.
A token object may not survive close, fork or restart, be serialized,
transferred to another service, Workspace or state inode, nor
become a general-purpose Gateway parameter.

**No real positive child launch is authorized in R0.** Next staged
B1-B1-B implementation must preserve historical real subprocess,
REST/MCP, four Workspace slots, cancellation/disconnect, close-wait
and original owner lock tests; no deletion/skip/mock-only substitution.
B1-B1-C separately implements the actual Worker proof-before-PREPARED,
RUNNING/UNKNOWN/test-only RETIRED, finalization, restart quarantine,
and full required status matrix. No original-group observation proves
complete detached-descendant cleanup.

## Exact R0 RED / GREEN classification

- **6 expected RED**, each with an exact B1B1B_RED_ marker:
  ordinary direct nonpreview on the existing bound test fixture must
  deny before Runner; unauthorized raw TCP REST and real SDK MCP
  apply with forged metadata must deny; the new bridge factory must
  create instance-bound actual loopback proof; its separate trusted
  in-process ASGI preview must work; close must revoke one-way.
  Existing product/bridge absence intentionally fails these.
- **7 required GREEN**: real bound Listener still previews with no
  subprocess or durable attempt; foreign Listener cannot borrow grant;
  both invalid client proof body fields denied; immutable inventory
  of historical real subprocess, REST/MCP, slots and cancel/close tests;
  ordinary product startup does not import bridge; existing private
  grant remains nonserializable and lifetime-revoked.
- **Strict verifier** checks exact 13 expanded NodeIDs once, no skipped
  or unexpected failures, exact six absent-feature markers and seven
  genuinely passing guards, pytest exit=1. It emits
  B1B1B_CONTRACT_STAGE=RED_NOT_IMPLEMENTED only for a matching RED.

CI checks full tracked SHA-256 Manifest, reviewed parent ancestry,
source integrity, unchanged historical product/reviewed blobs, full
real product pytest, frozen B1-B1-A strict RED classifier, and this
new expected RED classifier. It does not spawn any *new* process
from R0 contracts. Existing full product regressions still perform
their preexisting true disposable subprocess acceptance.

## Required next gate

After original CI success, independently review Standards and Spec
against the exact immutable R0 Head, code, negative cases and Job logs.
Only after both pass may the follow-up bridge GREEN implementation begin.
R0 GREEN is not product Worker GREEN. Keep all stacked PRs Draft,
unmerged and undeployed, production Exec OFF, Native C/C3 paused.
No user Gateway/Tunnel restart, unmanaged group signals, automatic
unquarantine, merge, tag or deployment.
