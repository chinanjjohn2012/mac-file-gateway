# Multi-Workspace Runner architecture V1 — R0 proposal only

Status: DESIGN ONLY. It does not implement or authorize positive Exec. Source: PR #76 fixed Head 0fc1ae245de7cb582a69162c79c201d15bfaa258; companion contract is MULTI_WORKSPACE_EXEC_RUNNER_CONTRACT_V1.md.

## 1. Current entry points and invariants

REST POST /run and official SDK MCP run_command use WorkspaceService.invoke_exec. The existing F1 checks permission and durable-state health before denying every ordinary dry_run=false with exec_cleanup_proof_required, without allocating a Worker, running CommandRunner or creating PREPARED. Preserve this exact behavior in R0 and R1.

CommandRunner in gateway/executor.py validates command, cwd, script, runner and timeout, but its start_new_session / killpg / leader.wait sequence proves no detached-grandchild shutdown. Treat its command preparation logic as a candidate for extraction, never its Popen path as proof.

Git CLI has its own authorization and subprocess path; File Write is independent. No global subprocess interceptor, no new Local Skills route, no change to Legacy.

## 2. Minimal responsibilities

- WorkspaceService: permission, workspace identity, scope, profile admission, existing 1-per-Workspace / 4-instance lease, closed/closing state. It owns the synchronous Worker lease through durable finalization, independent of the HTTP/MCP waiter.
- CommandSpec: validated command plan, correct direct/Pipenv/Pipfile resolution, relative cwd, effective argv, bounded timeout and output rules. Sensitive command strings/environment are not persisted.
- RunnerCoordinator: monotonic attempt lifecycle, pre-launch fsynced intent, one-time start, output/cancel/timeout accounting, termination, state finalization and reconciliation. No duplicate command after a lost response.
- Runner: narrowly typed internal backend contract, not a configurable plugin-loader. First R1 backend is a non-spawning deterministic fake, **not reachable** from ordinary production requests.
- NativeRunner: proposed R2 trusted-host implementation for direct process/original-group management, never F3 proof.
- IsolatedRunner: contingent R4 research adapter for independently verified OS execution domain, not implemented or selected in R0/R1.
- ExecStateStore: private owner-locked, pinned-FD, atomic write + fsync records, strict finite quotas, conservative boot scan, unknown quarantine. New schema requires separate migration design and review.

## 3. Minimal internal interface — illustrative pseudocode

```python
class Runner(Protocol):
    def qualification(self) -> BackendQualification: ...
    def allocate(self, prepared: PreparedIntent) -> BoundRef | Unknown: ...
    def start_once(self, ref: BoundRef, command: CommandSpec) -> LaunchObservation | Unknown: ...
    def observe(self, ref: BoundRef) -> CommandOutcome | Unknown: ...
    def terminate_and_prove(self, ref: BoundRef, deadline: Deadline) -> CleanupEvidence: ...
    def reconcile(self, attempt_id: str, owner_generation: str) -> ReconcileEvidence: ...
```

Qualification and BoundRef are minted by reviewed trusted backend code only; no network, env, config, CLI or test-grant can promote to full-domain qualification. Include attempt ID, backend/version, generation/fencing token, Workspace root dev/ino, trusted domain handle and backend configuration hash. A bare historical PID/PGID is never identity authority after restart.

## 4. Exact sequencing and crash barriers

1. Reject invalid permission, quarantined/unavailable state or unavailable qualification before any positive Worker admission. Keep existing F1 proof-required-before-busy order.
2. A **future authorized positive** path leases one Workspace and instance slot, validates command, then writes and fsyncs PREPARED before initiating allocation or launch.
3. Strict backend must allocate a non-running domain and durably bind its identity before permitting the first user command. Lost create ACK must be queryable by the same authenticated attempt identity; lack of lookup means UNKNOWN, not blind creation.
4. start_once is single-use and fenced by attempt/generation. A retry must query previous execution or fail closed; it cannot re-run a non-idempotent command.
5. After command completion/cancel/timeout, hold lease during bounded termination and directly validated evidence recording. Do not mark clean from a returned exit code.
6. Only durably complete verified retirement of its own evidence level. Uncertain identity, store health, output/drain or termination => UNKNOWN and instance-wide Exec quarantine. No retry or clean response after a failed final fsync.
7. Lost result delivery does not free domain early or re-execute an attempt. HTTP/MCP must not infer receipt without protocol acknowledgement.

## 5. Outcomes are independent

`command_result`: executed, exit_code, timed_out, stdout/stderr truncation.
`cleanup_result`: status, authenticated_scope, evidence_id, full_descendant_tree_clean.
`delivery_result`: response_attempted, transport_acknowledged_if_known.

Native group-only never sets full_descendant_tree_clean=proven. Strict must independently validate whole-domain stop AND no ability to resume retired attempt. Nonzero exit can have verified cleanup, zero exit can have unknown cleanup.

## 6. Future schema and compatibility constraints

Keep schema_version=1 and the current F1 parser/records unchanged through R0/R1 until a reviewed migration exists. Candidate version 2 separately represents PREPARED, STARTING, RUNNING, CLEANUP_PENDING, UNKNOWN, RETIRED_LIMITED and RETIRED_PROVEN. Quarantine remains a global Exec admission latch, not an alternate completion state. Old version-1 RETIRED (original_group_only) is not automatically usable, migrated to full proof, erased, or considered an old attempt's identity authority. Incompatible downgrade must leave Exec disabled.

Never use a test fake to issue production cleanup qualification. Never allow strict_f3 to silently fallback to native_limited. Runtime status must reflect available=false and completion_capability=none until future reviewed runtime qualification.

## 7. Acceptance gates

R0: complete independent B/C design reviews of changed contracts. R1: source-only no-behavior-change runner interface with current exact-Head CI and safety regressions. R2/R3: Native code, independently authorized isolated macOS ARM64 positive/negative and lifecycle tests, full reviews, explicit activation. R4/R5: Strict platform proof and separate product integration; T2/T3 never automatically authorized.

Not authorized here: real apply, process signalling, VM creation/stop, user Gateway/Tunnel, merge, release, deploy, production config, UNKNOWN reset.
