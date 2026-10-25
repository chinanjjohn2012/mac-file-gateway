# Multi-Workspace Exec — Production-First Implementation Plan (F0 accepted for F1 deny-only)

**Current stage (limited):** F0 §0 design has independent B/C r002 `TARGETED_REVIEW_PASS` at PR #69 Head `4110fac4edf2027703f4ce830a4d46718de4804d`. F1 product source PR #70 has B/C r002 `ROLE_FULL_SCOPE_PASS` at Head `9feb7d8eb71dc6f4ed60b9be2bbc73303a718067`; F1 GitHub-hosted macOS ARM64 acceptance PR #71 has B/C r001 `TARGETED_REVIEW_PASS` at Head `f11721765c3f64e3ab18c425fb9b642dc40f6ec7`. All remain Draft/unmerged; this status statement does not transfer those decisions to the integrated RC or authorize merge, deployment, positive Exec or privileged host experiments.

**Scoped authority:** `docs/MULTI_WORKSPACE_EXEC_RECOVERY_D0_DESIGN.md` §0 production-first amendment, independently reviewed at the original PR #69 fixed snapshot for F1 deny-only. Earlier D0 and PR #67/#68 remain valid at their respective fixed historical contract scope; PR #68 is not in this mainline RC. This plan does not supersede historic tests, unmerge any prior approvals, or authorize new positive Exec work.

**Basis:** PR #67 fixed Head
`c58269c798b62775f8621d69fa037d614c8861da`, Git Tree
`f1f50248f5198d9afe2e3f2648f5802efb83f5f8`.
PR #68 r002 fixed Head
`ab3dbda1462f31244f9f4e515c22ba12e7c7fcaa`,
Tree `8f28aa097a13eb444fee12e522833e7dd9d4d6fa`,
remains Draft/frozen and must not be silently rebased or mutated.
Its old 24 RED/34 GREEN are historical contract evidence,
**not production acceptance metrics**.

## 1. Product decision and negative capability

The near-term deliverable is a safe normal Multi-Workspace Gateway that:

- retains independent global and per-Workspace Exec opt-ins;
- provides valid, bounded `dry_run=true` preview with original
  Workspace routing/allowlist/type checks;
- always rejects an ordinary `dry_run=false` invocation when
  an independently reviewed whole-descendant cleanup proof is
  unavailable, **before an Exec Runner/Popen AND before any
  new or transient PREPARED state write**;
- emits stable `exec_cleanup_proof_required`: HTTP 503 from
  REST and structured MCP error; no ambiguous apparent success;
- keeps truthful `/info` / `/health` availability, no
  externally mintable grant/proof field and no remote reset;
- keeps File Read, separately authorized File Write, and Git
  operations independent. Git may invoke its own subprocess
  under Git-specific policy; deny-only Exec must not disable
  or globally intercept Git execution.

**Explicit non-goals:** no new Private Bridge, positive test-only
Worker grant path, new command runner, real native group-signalling
experiment, full-tree cleanup mechanism, C3 Native C research,
transport/Tunnel replacement, or permission to execute real
commands in production. Existing B1-A/B0 private fixture modules
are left inert; any cleanup/removal requires separately reviewed
dependency impact.

## 2. Direct source inventory (historical pre-F1 baseline, NOT current implementation)

| Location | Observed current behavior | Required F1 change |
| --- | --- | --- |
| `gateway/workspaces.py:WorkspaceService.invoke_exec` | Checks permission, state health, busy slot, then calls `ctx.gateway.run_command` with no ordinary cleanup-proof gate | Put proof denial in shared synchronous Worker before slot/Runner/PREPARED |
| `gateway/workspaces.py:WorkspaceService.info` | Marks available on permission+healthy state despite no full-tree proof | Report available=false, completion_capability=none in deny-only phase, stable state/status parity |
| `gateway/http_multi.py` / HTTP error policy | REST adapter calls service | Preserve request validation and map missing proof to HTTP 503 without accidental success |
| `gateway/mcp_multi.py:StrictWorkspaceMCP/build_multi_mcp` | Official MCP tool calls service | Preserve strict typed tool inputs, source stable structured error for missing proof |
| `gateway/exec_state.py` | Existing private durable store, owner lock and restart quarantine primitives | Do not weaken or auto-reset; no new PREPARED in denied apply; retain real private-FS tests |
| `tests/test_multi_exec_product.py` plus REST/MCP smoke | Historical genuine child/slot/disconnect success assumes a test opt-in allows Exec | After design approval, migrate per-contract to focused deny-only and deterministic mocks; preserve historical result provenance |

The exact implementation diff and test migration will be reviewed
on a **separate F1 product PR**, not this design-only PR. Do
not claim that an unchanged CodeRunner can clean detached children.

## 3. F0 — design gate and old PR disposition

1. Open a **documentation-only Draft PR** based on fixed PR #67
   (NOT on bloated PR #68 test contract) with this plan, the D0
   `§0` amendment and updated tracked Manifest.
2. Obtain independent **Standards** and **Spec** design reviews
   on that PR's exact Head/Base/Git Tree, with disclosed original
   CI availability and differences from old D0. Both reviewers
   must explicitly accept/reject the revised threat model,
   deferred Private Bridge, absence of positive execution,
   test migration and release safety boundary. Neither
   reviewer inherits old PR #68 r002 PASS/FAIL.
3. If rejected, revise the design in a new snapshot/round
   before writing product code. If accepted, choose the
   reviewed PR #68 disposition (supersede/close/rework)
   separately; do not erase prior Review history. Closing
   or merging is NOT authorized by this plan alone.
4. No F1 implementation may claim current D0 §0 is
   approved until both role conclusions and safety
   authority are independently validated.

## 4. F1 — minimum product implementation (after F0 approval)

**Single security decision point:** in the actual synchronous
`WorkspaceService.invoke_exec` path (direct/REST/MCP share it),
apply this precedence:

1. Not permitted globally or by Workspace → `exec_disabled`.
2. Persisted UNKNOWN/corrupt/quarantined state →
   `exec_quarantined`.
3. Missing/untrustworthy state root or ownership lock →
   `exec_state_unavailable`.
4. Valid `dry_run=true` → normal safe preview with zero
   Exec spawn/PREPARED; still reject dishonest preview if
   state itself is untrustworthy.
5. Valid `dry_run=false` with no reviewed full-tree proof →
   `exec_cleanup_proof_required` BEFORE Worker slot, Runner,
   any Popen and any Exec PREPARED write.
6. The future `busy` decision is reachable only if a
   separately approved positive-proof path exists. Do
   not return busy in place of missing proof.

Do not authorize production Exec through a different
REST/MCP-only branch, an environment flag, test-internal
private grant, service alias or mock object. Leave Legacy
execution behavior outside the Multi-Workspace scope unless
a later plan independently authorizes changes.

**Status:** both opt-ins can report enabled and adapter_exposed;
as long as full-tree cleanup is not qualified, report
`available=false` and `completion_capability="none"`.
Keep durability_state, quarantined and reason truthful and
sanitized; `/info` and `/health` must agree.

## 5. Minimum test matrix — coverage by risk, not case count

| Risk/contract | Evidence needed | May be mocked? |
| --- | --- | --- |
| Both Exec opt-ins but no proof; zero Popen/PREPARED | Direct Worker plus actual REST/MCP calls, focused physical write-open/rename/unlink observer and Runner spy, correct error on each route | Runner may be spy/mocked; ingress/parsing and at least one state-write witness must be real |
| Disabled/unhealthy/quarantined/error precedence | Direct state/permission negative plus adapter mapping; no Worker admission | Fault-state transitions can be mocked; actual state-root trust stays physically verified |
| Valid preview/invalid arguments/client proof spoof | Legal preview, path/argv/types; representative malicious fields/headers; no real child | Runner execution mocked; real SDK/REST parsing smoke retained |
| File read/write and Git independence | **Mandatory mixed-instance positive:** both Exec opt-ins enabled with no cleanup proof, denied Exec apply, then real authorized Git `dry_run=false` (`status` or `add`) in the **same** disposable WorkspaceService plus authorized File Write apply; repeat real Git apply with Exec UNKNOWN/quarantined; deny unauthorized Git/File Write | Git actual apply and physical File Write must not be mocked; preserve real Git-specific process spawning and independent grants |
| Worker cancellation, timeout, slots, close/drain | Deterministic fake Worker/clock/state machine, no lost-response replay | Yes, for deny-only and abstract transitions; do not claim child cleanup |
| Existing private state owner lock, unsafe path/restart | Existing real private-FS/owner-lock safety checks, quarantine on unresolved records | No for FD/inode/lock truth; mock remaining orchestration |
| SDK ToolManager/Tool.run monkeypatch variants | Only if review shows ordinary untrusted client can actually cause a Worker proof-gate bypass under defined trust boundary | Not required merely to maintain a theoretical Python mutation count |
| Real full-tree process cleanup | NOT part of F1; no positive production execution | Never sufficient alone; future F3 requires native evidence |

**P2-01 required same-instance executable counterexample (F1):**
Use a strictly disposable Workspace/repository with one actual
`WorkspaceService`. Enable both global and Workspace Exec opt-ins,
healthy private Exec state but no approved descendant cleanup proof,
plus separate Git `status` or `add` and File Write grants.

1. On that **same** service, verify direct and at least one genuine
   REST/official SDK MCP Exec `dry_run=false` path yields stable
   `exec_cleanup_proof_required` with zero Exec Runner/Popen and zero
   transient/permanent PREPARED writes; preserve existing direct,
   REST and MCP negative coverage and physical intent observation.
2. Without reconfiguring the instance, invoke an independently
   authorized Git `dry_run=false` (`status` or `add`) against the
   disposable repository. Require a **real Git subprocess** and
   a successful valid Git result, not a dry-run or simulated
   `GitProcessRunner`; perform an allowed File Write apply too.
   Check an unauthorized Git command and unauthorized File Write
   remain denied under their own policy.
3. In a second disposable controlled state on that same service,
   inject persisted Exec UNKNOWN/quarantine (never reset it or
   remove an unresolved record), confirm Exec remains fail-closed,
   and repeat a real authorized Git `dry_run=false` successfully.
   The Exec proof-denial/quarantine implementation must not add a
   process-wide Popen interceptor, bypass Git's separate admission,
   or transfer Exec permissions into Git/File grants.

Only Git's pre-existing independently authorized process is spawned;
these tests do **not** authorize a real Exec command or unmanaged OS
process-group signal. Preserve old Git-only smokes as adjacent
regression, but they are insufficient on their own for this mixed
configuration. This is a risk-based mandatory case, not an arbitrary
minimum test count.

Historical `tests/test_multi_exec_product.py` real-child tests will
not remain mandatory in their old form merely to satisfy a count:
record each existing asserted behavior, classify as still relevant
for deny-only versus future real-Exec, and replace/split/merge
as justified. Previously approved code/files and original
fixed-SHA CI history remain unmodified; a new test rewrite
requires its own new Head and independent Review. No
`pytest.skip`, weakening of a production requirement or
faked GREEN is permitted just to avoid a failing suite.

## 6. Gate for finishing F1; subsequent releases

F1 is complete only if the normal Multi-Workspace product
safely denies unqualified actual Exec before Runner/PREPARED
through all public adapters, valid preview and independent
File/Git paths pass **including the same-instance real authorized
Git apply under missing-proof and UNKNOWN/quarantined Exec**, no
material open P0/P1/P2 remains,
the applicable CI and original fixed-SHA logs have been
verified and both independent B/C code reviews pass the
approved F1 contract. Historical test totals are **not**
an acceptance metric. Preserve known test skips and
platform limits in the handoff; no integration PASS
without actually performing integration.

**F1 is NOT a real command-execution release:** absence of
a proven full-descendant cleanup mechanism means
`dry_run=false` remains prohibited, even if configuration
says Exec enabled or a disposable test passes.

Any later real production execution F3 requires a
separate full-tree/OS containment and cleanup design,
durable PREPARED-before-Popen and identity-safe process
tracking, UNKNOWN/quarantine on uncertain outcomes,
native macOS ARM64 process-tree/restart/timeout/cancel/
disconnect validation, and real Tunnel acceptance where
deployment requires it. Mock-only evidence never
qualifies F3, and separate user authorization to merge,
deploy and enable real Exec is still required.

## 7. Security and handoff invariants

- Never use ordinary REST/MCP, config, CLI or environment
  data to mint internal cleanup qualification.
- Never implement Exec default DENY with a global subprocess/Popen
  interceptor; Git's separately authorized real subprocess path
  must still work in the same instance under Exec missing-proof
  and Exec UNKNOWN/quarantine.
- Do not signal unknown or reused PID/PGID after crash;
  never automatically unquarantine, remove unresolved
  records, or retry non-idempotent Exec after lost response.
- Keep existing D0 private filesystem state ownership,
  fail-closed boot scan, file/Git independence and scope
  isolation; the Exec path grant is not an OS sandbox.
- Do not turn prior `REVIEW_COMPLETE`, targeted PASS, old
  PR #67/68 PASS/FAIL or expected RED into a new
  `FULL_CODE_REVIEW_PASS` or `INTEGRATION_PASS`.
- Freeze each published Head/Tree during independent
  review; Base change invalidates naive inheritance.
- No merge, tag, release, deploy, user Mac Gateway/Tunnel
  restart, production Exec enablement, Native C/C3 scope
  change, unmanaged child/group signal or automatic
  quarantine reset without new explicit authorization.
