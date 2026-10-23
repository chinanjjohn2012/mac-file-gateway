# Multi-Workspace Exec — R1 deterministic RED contracts (Python product)

**Status: R1 TEST-ONLY, INDEPENDENT REVIEW REQUIRED, NOT R2 IMPLEMENTATION.**
Base: PR #58 D0 DESIGN PASS, independent Review #5623166343,
fixed commit: bec02bbcb7d3bf1b60bd7a27aff1b4b68f0fbab1.
Prior PR #59 independent R1 Review #5623467201, fixed FAIL Head
6710498cfadecb5a569590c31401663cdaec48a7:
Standards PASS / Spec FAIL (P2-01, P2-02) / P3 x3.

This PR modifies only the isolated non-default R1 test, its exact-result
verifier, this document, and MANIFEST.sha256. The existing R1 workflow,
PR #56/#57/#58 implementation and native research remain untouched.

## 1. How the stage is evaluated

- The original controlled-exec-tests workflow must remain GREEN on the
  exact Head (full existing pytest, listener/smoke/stdio/disconnect/Git,
  compile, Shell syntax, Manifest).
- The separate R1 workflow must be GREEN *as a verifier of intentional RED*.
  Its contract test filename does not begin with test_, and is invoked
  explicitly. The verifier requires exact fully parameterized JUnit test
  names (including all 24 distinct scenario IDs), unique nodes, a specific
  controlled R1_RED failure marker for **each** node, no collection or
  fixture errors, and four independently passing legacy guard cases.
  It rejects unrelated HTTP 421, wrong REST/MCP codes, skipped cases,
  swapped parameter IDs, unexpectedly GREEN cases and generic failures.
- This isolated workflow's SUCCESS means only
  RED_CONFIRMED_NOT_IMPLEMENTED. It does **not** prove durable lifecycle
  recovery, a full descendant tree, or R2 implementation GREEN.

## 2. P2-01 — admission and ambiguous cleanup are separate facts

The ordinary Gateway is **not** entitled to test-only group retirement,
even with both global and Workspace Exec opt-ins set to true. The normal
direct/REST/MCP tests require exec_cleanup_proof_required **before** any
Python runner/Popen, no durable PREPARED and no UNKNOWN/quarantine latch.
A definite refusal before spawn must never be treated as uncertain cleanup.

The old ambiguous sync-worker test used an ordinary unqualified Gateway,
which a correct D0 implementation would deny before touching its stub.
It is replaced with a **qualified disposable internal acceptance service**,
using an acceptance-only factory in gateway.exec_recovery_acceptance.
That factory is NOT implemented in R1. It will not be exposed through
gateway.json, environment, CLI, REST/MCP or production Workspaces.
The test-owned subprocess.Popen dummy records a real call and requires
that a parseable, fsynced PREPARED record was visible **at** the attempt.
The dummy then raises an injected ambiguous OSError. For eventual GREEN,
the test checks the actual surviving PREPARED/RUNNING/UNKNOWN record,
global Exec quarantine, and absence of unsafe real OS signals.

The second old ambiguous/restart test now writes a **canonical legal
RUNNING record** through a future private state serializer, independently
validates its schema and exact bytes, calls file+directory fsync, starts a
normal Gateway without a test grant, and rechecks that a second boot
quarantines without modifying/deleting the record. It does not invoke
an unqualified apply or manufacture an ambiguous child. Three additional
parametrized cases cover legal PREPARED, RUNNING and UNKNOWN history.

The future internal factory is permitted solely as a trusted
temporary-fixture construction seam, returning an actual WorkspaceService,
not arbitrary test results. Any failure to create this seam currently
produces R1_RED_PRIVATE_FACTORY_MISSING, explicitly denoting an
**unimplemented prerequisite**, not proof that a spawn fault fired.
Similarly R1_RED_CANONICAL_STATE_CODEC_MISSING denotes no R2 serializer
exists yet. R1 does not downgrade those gaps to existing fault witnesses.

## 3. P2-02 — tests now own evidence (no outcome dictionary)

The old _r1_contract_probe(case)->dict has been removed. A test can no
longer pass simply because an implementation returns a prefilled dict
with outcome_code, spawn_attempts and quarantined. A new test-owned
_ExternalWitness has independently instrumented facts:

1. os.write/fsync on state-file and pinned state-directory file descriptors;
   os.replace for atomic rename; os.unlink for reclamation. The watcher
   targets only the disposable Exec state root.
2. A monkeypatched subprocess.Popen creates an **inert _DummyProcess**,
   never a real OS process. The witness counts attempted launches,
   captures a separate on-disk PREPARED/RUNNING snapshot *at spawn*,
   and verifies that both file and directory fsync preceded it.
3. os.kill and os.killpg are intercepted; a dummy group-absence
   query can never send an actual host process signal.
4. Each durable marker is reread from **real filesystem bytes** in
   the temporary fixture. A valid marker needs an attempt identity,
   Workspace identity and recognized state phase; UNKNOWN/RETIRED
   proof cannot be replaced by an API summary.
5. Private _LifecycleFaultHooks are supplied by the test, invoked only
   from the internal disposable acceptance service at documented
   lifecycle stages. They raise a synthetic exception or block a
   controlled finalization, record the precise invocation, and check
   live Worker-slot ownership while blocked. No REST/MCP caller may
   choose or install these hooks.

For eventual GREEN, key scenario-specific requirements include:

| Scenarios | Independent witness needed |
| --- | --- |
| file/dir fsync, atomic rename before Popen | targeted syscall actually fails, zero dummy-spawn attempts, Exec no longer available |
| ambiguous Popen, failed wait/drain, finalization fsync | one dummy-spawn attempt after fsynced PREPARED; injected failure actually fires; disk retains unresolved attempt; reboot quarantines |
| crash at PREPARED, after Popen, after leader wait, after RETIRED | exact hook is reached, disk bytes survive re-opening; unresolved phases quarantine; retired is never replayed or mistaken for full-tree proof |
| qualified group-only test | actual dummy invocation after durable PREPARED, durable RETIRED marker contains original_group_only and not_proven; no arbitrary descendant-clean claim |
| mismatched, forged, expired grant | a different/nonqualified service cannot inherit capability or spawn; test scope cannot clear earlier quarantine |
| capacity and cleanup | distinct canonical attempt IDs, actual bounded disk records, only RETIRED unlinks, directory fsync strictly after unlink, UNKNOWN never reclaimed; failed prune must close admission |
| cancelled finalization | deterministic pause at real Worker finalization, concurrent apply reports busy until release |
| status and protocol | ordinary missing proof cannot claim available; REST 503 and JSON-RPC tools/call isError=true with stable structured error |

R1 **does not claim** these faults have already fired. The missing
internal factory / private serializer intentionally prevents pretending
R2 functionality exists. The test-side fault machinery, trigger code
and independent assertions are now present; during R2 they must
demonstrate per-scenario events and actual on-disk state. Any R2
implementation that only returns canned values, silently swallows
injection, omits fsync, or launches before PREPARED will fail.

The quota-positive tests require a *live*, same-fixture qualified state
store and a private test-only way to stage RETIRED markers in that active
store. They must never import prior service's test-only RETIRED records
as production evidence, and the real unlink/fsync/size boundaries are
checked by the test after staging. UNKNOWN-at-capacity is tested
separately and must never be evicted to make room.

## 4. P3 improvements

P3-01: verifier now pins fully qualified parametrized JUnit NodeIDs,
including exact env names, foreign-record filename, three historical
phases and all 24 individual fault names. RED markers are specified
*per* NodeID instead of substring detection.

P3-02: full SDK-backed MCP JSON-RPC initialize / tools/call
on loopback verifies isError=true and stable structured
exec_cleanup_proof_required, and checks the fake runner was never
called. An internal SDK ToolError alone is insufficient.

P3-03: legal prior-state records must be serialized by the future
private codec, independently decoded and fsynced by the test,
then scanned by a freshly constructed ordinary Gateway. The old
untrusted-name/corrupt-json tests remain separate and do not
substitute for this schema-valid boot evidence.

## 5. Scope, review criteria, and stop

Independent review must read this PR's new fixed Head and Git Tree,
the updated exact-node RED verifier, actual tests, original normal
GREEN CI and strict RED CI Job logs, D0 accepted fixed-SHA design, and
the earlier Spec FAIL Review. It should distinguish (a) direct live
entrypoint RED, (b) missing private factory/codec RED, (c) independent
future OS/disk fault witness requirements, and (d) guard GREEN.

Only after independent R1 Standards+Spec PASS may R2 implement Python
durable state and test-only fixture construction. Later R3 macOS
fault acceptance and R4 overall acceptance remain separate blockers.
No production Exec enable, no Native C/Candidate B, no real local
Gateway restart, no process-group signal experiment, no private Tunnel,
no code merge, deployment, tag, or automated unquarantine.
