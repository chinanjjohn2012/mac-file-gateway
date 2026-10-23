# Multi-Workspace Exec — R2-T02-A default admission and startup RED

**Stage: deliberate RED contract, not product implementation.**
**Track: Python product only.** Stack this Draft PR on approved
R2-T01 PR #60 fixed Head 10521900e5232ceb7f746f35a73fa811deae20f5.
Accepted T01 independent Review #5625326125: Standards PASS / Spec PASS.
Accepted R1 fixed Head 79cae93e7b4c03293b95dcc8c51e55e97ec2a934
and Review #5624517768. D0 authority: PR #58 independent Review
#5623166343.

## T02-A contract

1. At Multi-Workspace service startup with a globally and per-Workspace
   enabled Exec capability, the product must open a Gateway-private,
   FD-pinned exec-state directory, acquire its lifetime owner lock and
   scan before any Exec API admits work. A normal production service must
   **never** construct/accept a test-only cleanup grant.
2. Both flags true are **necessary but insufficient** to apply. In a
   normal product service, group_only_test_grant is absent and no
   independently approved full-descendant proof mechanism exists. A
   non-preview apply must fail as exec_cleanup_proof_required *before*
   any PREPARED, real runner, Popen or PID/group signal. REST must
   return HTTP 503; MCP tools/call must use isError=true with a stable
   structured error code. No fake result-dict authority.
3. Any physical stale PREPARED, RUNNING or UNKNOWN, corrupt record or
   competing owner must fail closed at construction. Do not replay
   a command, signal a stale PID, delete forensic evidence or infer
   full-tree cleanup. A quarantined Exec must deny previews as well as
   applies, while unrelated File/Git policy stays independent.
4. /info and /health must expose the exact same sanitized exec_policy.
   available=false without cleanup proof, even if adapter_exposed=true;
   completion_capability=none in ordinary product mode. Distinguish
   disabled/healthy/quarantined/unavailable and
   exec_disabled/exec_quarantined/exec_state_unavailable/
   exec_cleanup_proof_required admission precedence.
5. Existing read-only dry_run=true command validation stays available
   when durable state is healthy; it is not a claim that non-preview
   execution can be admitted.

## Evidence discipline

- tests/t02_contracts/contract_multi_exec_admission_t02.py is deliberately
  **non-default-collected**. It operates only on disposable on-disk
  Workspace/state roots and fake command runners; an autouse fixture
  intercepts Python host process/signal entrypoints across creation,
  requests and teardown. This is an application-level test guard,
  not a kernel sandbox. No user's Gateway or Tunnel is started.
- Dedicated workflow checks the fixed Head, Git Tree and exhaustive
  MANIFEST.sha256, runs the existing product suite unchanged, then
  calls tools/verify_multi_exec_r2_t02_admission_red.py. The verifier
  pins **14 fully parameterized RED NodeIDs** with expected exact
  T02_RED markers plus **4 GREEN baseline guards**. Collection/import
  errors, skipped tests, wrong markers, replaced parameter IDs, or
  unexpected current GREEN fail the workflow.
- Workflow SUCCESS proves **expected missing behavior only**.
  It does not mean integrated admission works, stored UNKNOWN is handled
  by the Worker, 28 R1 private-fault cases have run, or process cleanup
  is proven.
- Existing PR #56 product-acceptance tests (including disposable
  subprocess lifecycle) express historical candidate semantics.
  Once normal product Exec is fail-closed, do not delete/skip those
  tests to manufacture passing CI. Preserve their value using a
  separately reviewed internal disposable acceptance factory or
  equivalent test-qualified regression coverage, before integrating
  the final Worker. Configuration, environment, REST/MCP fields or
  PYTEST_CURRENT_TEST may not themselves create any test grant.

## Stages beyond this RED

T02-B: independent review of admission RED, then implement startup
owner/boot scan, truthful status and ordinary DENY without spawning.
T02-C: trusted, identity-bound disposable acceptance qualification
and actual Worker PREPARED/UNKNOWN/RETIRED transitions, fault injection,
cancellation and bounded drain, each with additional RED→GREEN and
independent SHA-bound review. Detached descendants, actual cleanup
failure, capacity pruning and full recovery are separately gated.
R3 macOS ARM64 and R4 final release acceptance do not follow
automatically from R1/T01 PASS.

**Hard STOP:** PR #56–#60 and this PR remain Draft/unmerged.
No production Exec enablement, private Tunnel, real local Gateway
restart, C3 Native C, actual unmanaged group-signal experiments,
tag, deployment or automatic quarantine release. This PR modifies
test/CI/evidence/Manifest only.
