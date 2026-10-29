# Multi-Workspace Exec — Local Best Effort V1 (five-day product candidate)

**CONTRACT_ID:** `MWE-LOCAL-BEST-EFFORT-V1.0-CANDIDATE`
**STATUS:** R002_DESIGN_FIX / NONOPERATIVE / AWAITING_B_C_NEW_R002_REVIEW / NOT_APPROVED_FOR_POSITIVE_EXEC
**TASK_ID:** `MULTI-EXEC-LBE-V1-DESIGN-20261030`
**REVIEW_ROUND:** `r002` (new Head fixes independent #98 r001 B BLOCKED/C FAIL; earlier reviews immutable)
**REVIEW_TARGET:** TARGETED design decision for a new `local_best_effort` Multi-Workspace Exec mode and its minimal five-day implementation/test plan. NO product runtime modification in this PR.

## 1. Source of authority and user direction

- GitHub repository: `chinanjjohn2012/mac-file-gateway`. Isolated parent: frozen F1/G05 integrated RC PR #76 Head `0fc1ae245de7cb582a69162c79c201d15bfaa258`, native Tree `e05777c0bc6eea0b375a6347602b99c68024b3b6`; target base branch `rc/multi-exec-f1-g05-integrated-ms1-20261025`. No N3/N2/Native research branch is a parent.
- Current **operative** source-based restrictions remain `docs/MULTI_WORKSPACE_EXEC_RECOVERY_D0_DESIGN.md` Blob `6e25904aed9a62bb0f472b732021c2a7ca3b3bb0` §§0.1/0.4; F1 implementation plan Blob `76baeb820c6f8a9b067e45e2dcc42e76453fe5b1`; Phase1 local trust boundary Blob `b3f2383f292a59fd234269389e5338cd50e334a2`; G05 Blob `76c1c2b8a7947e0b305d55c5f550ab59c638b6d1`; R004 user-scoped 36 locked Wheel + RECORD-listed file attestation; existing F1/G05 code and authorizations.
- Review protocol: `ICR-V2.0`, `GHRH-2.0`, `ETP-V2.0`; this is a NEW r002 repair candidate requiring B and C's separate new-Head SHA-bound targeted design reviews, followed by explicit owner acceptance of the **exact reviewed version** before making any D0 exception operative.
- The owner explicitly requested a **five-day usable lightweight product**, accepts that cancel/timeout may leave children or descendants alive, rejects mandatory perfect child-tree cleanup/rollback/recovery, removes both redundant public `server.exec.enabled` and `workspace.exec.enabled` switches in favor of nonempty `exec.paths`, and requires Python Direct, Pipenv, Go `test`, `vet`, **`build`**. Owner said to start on 2026-10-30. That authorizes this bounded design work and independent review, **NOT** existing-F1 gate removal, production activation, Native signals/T2/T3, merge or deployment.

## 2. Intended behavior and trust boundary

This mode is `local_best_effort`, **not** `native_limited`, `strict_f3`, a sandbox, a process jail or a descendant-cleanup qualification. Run only operator-trusted project commands as the Gateway's ordinary OS user. Command allowlists, no-shell argv, Workspace routing, per-Workspace `exec.paths`, denylisted file/path checks and output redaction remain mandatory. The entry-command allowlist cannot constrain arbitrary filesystem, credential, network or further process side effects of trusted Python, Go, project tests and dependencies. The operator bears those host-code risks.

Minimal successful request: an explicitly named Workspace; configured and canonical authorized cwd; validated argv and allowlisted command; `dry_run=false` through a **newly reviewed** shared service gate; return the direct command's actual exit code and bounded redacted stdout/stderr if the direct process completed and those facts were observed. `dry_run=true` remains the default and spawns nothing.

**Best-effort semantics (deliberately accepted limitation):**
- Cancellation means the caller may stop waiting. It does NOT promise a running command, its direct child, process group or grandchildren were stopped. A transport disconnect does not imply process termination.
- At timeout, report `timed_out=true`, `exit_code=null` when a real exit is not known, `process_may_be_running=true`, and **never** describe cleanup as proven. Neither a timeout nor HTTP/MCP cancellation is a command rollback.
- On normal direct-child exit, record the observed exit code; `full_descendant_tree_clean=not_proven` even with exit code zero. Daemonized, detached, reparented and compiler-spawned descendants may survive.
- A Gateway crash or restart loses in-memory attempts; do not recover, signal unknown old PIDs/PGIDs, replay or retry an uncertain command. No durable N3 journal, rollback, forensic tombstone, owner witness or automatic UNKNOWN reset is part of this mode.
- Do **not** invoke the existing `os.killpg(process.pid, SIGKILL)` timeout fallback under this new mode without a separately qualified target identity and explicit destructive test authorization. If no safe direct-child termination can be proven, send **no signal**, report uncertainty and allow the process to survive. Existing Legacy behavior is out of scope and not amended here.
- Do not silently rerun after lost ACK. If a client deliberately submits a new request, it is a new command and might duplicate effects. Limit new admissions to one active original command per Workspace and four per service while the tracked original process remains known active; do not claim this limits already detached survivors or across restarts.
- All user-facing results/status must distinguish `command_exited`, `timed_out`, `cancelled_or_disconnected` and `cleanup_not_proven`. Never report `RETIRED_PROVEN`, `full_descendant_tree_clean=proven`, `INTEGRATION_PASS` or `strict_f3`.

## 3. Configuration: paths are the only public Exec grant

Use an explicitly versioned proposed `schema_version: 2` configuration for the new behavior. In this version, **neither** `server.exec.enabled` **nor** `workspace.exec.enabled` is required or accepted. This is an intentional config contract change, **not** automatic reinterpretation of old v1 configs. A missing/empty `workspaces.<name>.exec.paths` denies Exec for that Workspace. A nonempty list grants only listed *relative* scopes, after canonical validation; `exec.runners` is optional per-path selection, not an additional capability grant. Runners must be within a granted path; all other Workspaces remain denied. Unknown/ambiguous fields reject, not silently ignored.

Illustrative new config fragment (not an accepted current configuration):
```json
{
  "schema_version": 2,
  "workspaces": {
    "a": {
      "root": "/disposable/example/workspace",
      "exec": {
        "paths": ["python-project", "go-project"],
        "runners": ["python-project=pipenv", "go-project=direct"]
      }
    }
  }
}
```
Other mandatory root/transport/config fields and independent Git/File grants remain subject to their existing schema contracts. Old `schema_version: 1` must keep its existing deny-only F1 semantics; a previously disabled v1 configuration with dormant paths must **not** become executable by upgrade without an explicit v2 configuration transition. Do not add a hidden REST/MCP `enable`, token, profile override or client-supplied Exec authorization.

## 4. Minimal command set and argument/output policy

| Entrypoint | Proposed V1 behavior |
| --- | --- |
| `pytest`, `python -m pytest`, `python -m compileall`, `python <project-relative.py>` | Reuse present `CommandRunner` validation/Direct and Pipenv auto/configured runner; disallow `-c`, stdin code, interactive debugger |
| `go test`, `go vet` | Preserve current allowlist and tool-hook restrictions, use Direct Go CLI |
| `go build ./...`, `go build ./cmd/service` | ADD to current whitelist; Go uses Direct (no separate Go Runner), irrespective of an unrelated Pipfile |
| `go build -o bin/service ./cmd/service` and `-o=bin/service` | Allow ONLY a validated workspace-relative output target in an authorized execution subtree; refuse absolute paths, parent traversal, symlink/output-parent escapes, missing/ambiguous values, unsupported tool replacement flags |
| `go run`, generic shell, arbitrary executables | Out of V1 scope; default reject |

Preserve current explicit argv length, output cap, environment allowlist/redaction, cwd path checks, no `shell=True`, and `timeout_seconds` bounds. Preserve blocking `-exec`, `-toolexec`, `-vettool` and any relevant executable/tool injection variants for Go test/vet/build. The `-o` restriction is a **request-level explicit path restriction**, not a claim that compiler/test subprocesses cannot write Go caches, download Go modules, run cgo tools or otherwise affect host state; such actions are accepted within the local trusted-code model.

## 5. Precise exception scope versus operative D0/F1

This contract **proposes** a narrow future D0 exception for operator-chosen `schema_version:2` and allowed `local_best_effort` code only. It is **not currently effective**. Until a fixed reviewed implementation is expressly approved, the actual shared `WorkspaceService.invoke_exec` MUST continue returning `exec_cleanup_proof_required` before real `dry_run=false` execution on F1. `schema_version:1` F1, legacy Gateway, Git/File, private durable state and all other security gates stay unchanged.

The exception, if independently accepted and subsequently activated, would remove full-descendant cleanup proof and durable PREPARED/N3 lifecycle as **requirements for the explicitly weaker local_best_effort mode**, not downgrade their meaning in `strict_f3`, a different Native Limited mode or old F1. No old `RETIRED`/test grant/UNKNOWN may be transformed into a local_best_effort authority. Do not expose a second unguarded HTTP/MCP execution path; the same synchronous WorkspaceService must apply Workspace, cwd, command, time, status, concurrency and mode restrictions to direct, REST and official MCP SDK calls. Keep File/Git independent and do not install a global `Popen` ban.

**r002 resolution of r001 design ambiguity:** The following sections 5.1–5.4 specify the required old-v1-state-to-v2 gate, direct-child lifetime, cross-transport response truth and Go output validation. No reviewer is asked to invent the missing rule. These remain NONOPERATIVE proposed conditions until B/C review and exact-version owner approval.

### 5.1 v1-to-v2 transition and private state — fixed denial oracle

Only an operator-edited `schema_version:2` document with nonempty per-Workspace `exec.paths` proposes a new request grant. Old v1 F1 remains unchanged and denies positive apply. Before ANY proposed v2 positive operation (or preview claiming availability), require the **existing** locked private v1 `exec-state` root and the original `ExecStateStore` boot scan/`require_healthy()`. No new v2 per-command durable PREPARED/JOURNAL records are required. Do not promote any v1 grant, RETIRED record, or quarantine into new authority.

| Observed config or old private state | v2/v1 request behavior |
| --- | --- |
| `schema_version:1` and any v1 flags/state | Existing F1 deny-only and error precedence unchanged; no positive Exec |
| v2 with missing or empty `exec.paths` | `exec_disabled`; no spawn and no implicit former v1 grant |
| v2 nonempty paths, existing private state root locked + healthy, no old attempt records | Only now eligible for proposed v2 validation, capacity and apply; not yet an approval to remove the live F1 gate |
| v2 nonempty paths, old PREPARED/RUNNING/UNKNOWN, test-only RETIRED, corrupt record, unexpected entry or old quarantine | `exec_quarantined` BEFORE spawn; retain all old bytes; never auto-reset, unlink, retry or signal old PID/PGID |
| v2 nonempty paths, private root absent/unsafe, owner.lock unavailable/busy, cannot scan | `exec_state_unavailable` BEFORE spawn; no auto-create-empty fallback and no permission inferred from vanished history |
| v2 unexpected `server.exec.enabled` / `workspace.exec.enabled`, ambiguous paths/runners | Invalid version-2 configuration; no spawn |

Fresh first-time v2 installations must explicitly prepare an empty private `exec-state` root as a trusted **offline/local** setup operation. An existing path MUST NOT be deleted or replaced. Because the inherited `ExecStateStore` constructor currently creates a missing root, v2 implementation MUST add an existing-only preflight/constructor option to avoid clearing evidence of missing history. No new public enable flag, credential or Native authorization is introduced. If an earlier old root vanished, the ordinary v2 paths grant is insufficient to recover; that needs separate deliberate operator safety handling. The trusted-local-user model does not claim resistance to a local owner destructively erasing evidence.

Old v1 historical UNKNOWN stays blocking after changing config versions. **Different risk accepted by operator:** a previously spawned v2 best-effort child may survive v2 Gateway restart; since v2 creates no attempt journal, new requests after a fresh healthy old-state scan cannot prove that v2 child disappeared. State this risk explicitly, do not claim strict cleanup or silently replay lost commands. Existing Git/File grants are unaffected by Exec old-state failures.

### 5.2 Timeout/cancel/slot/reaper/shutdown — direct child is the lifetime unit

The synchronous `WorkspaceService.invoke_exec` is the ONLY authorization path for direct service, REST and official MCP. Proposed child state machine: `VALIDATED` -> `SPAWN_FAILED` (no child; release reservation) OR `DIRECT_CHILD_ACTIVE` -> `DIRECT_CHILD_REAPED` (release slot). `WAITER_DISCONNECTED` and `TIMED_OUT` are **annotations of an active direct child**, never completion. Retain one active direct child per Workspace and at most four per service; a background owner/reaper retains the slot independently of the response waiter and executes `wait()` until the original child actually exits.

On timeout, return `timed_out=true`, `exit_code=null` if exit not observed, `process_may_be_running=true`; do not invoke `killpg`, unsafe PID signals or process.kill. On observed transport cancellation, client gets NO claimed ACK, but the original child/slot/pipe-drain ownership survives. If process A is still live after timeout/disconnect, B in same Workspace MUST get `busy` without spawn, even after A's HTTP response has finished. Other Workspace jobs obey their own grants and total four-slot limit. On witnessed direct-child exit (including nonzero exit), release A slot; detached grandchildren may remain by accepted design.

Bound stdout/stderr collection and reader lifetime. While a direct child remains live after timeout, a bounded/nonblocking drain prevents indefinite pipe backpressure; after observed direct exit, a bounded EOF grace protects against descendants holding inherited pipe FDs. Return `output_complete=false` when final EOF is unobserved, and prevent unlimited daemon reader accumulation. Failure to allocate reaper/reader resources before spawn denies with no child; a lost owner/reaper after spawn latches further v2 admission unavailable in that service lifetime, without signalling unknown OS identities.

Shutdown marks the service closing and denies new admission; active request workers may finish their bounded configured timeout (1..300 seconds), but the service does not await unbounded child/grandchild cleanup after the request returns. Release pinned request resources only after their active synchronous request is finished. Process exit or hard Gateway crash may leave orphans; no restart replay/reap or unknown-state reset. Inherited v1 lifecycle behavior is not rewritten. This does not promise a strict deadline for forcibly killing a wedged Gateway.

### 5.3 Shared direct/REST/MCP return and `/health`/`/info` truth table

| Event | `status` | `executed` | `exit_code` | `timed_out` | `process_may_be_running` |
| --- | --- | --- | --- | --- | --- |
| Preview, no spawn | `preview` | false | null | false | false |
| `Popen` failure, no child | `launch_failed` or sanitized existing GatewayError | false | null | false | false |
| Observed direct child exit | `exited` | true | actual integer | false | true (possible detached grandchild) |
| Timed out, direct exit unobserved | `timed_out` | true | null | true | true |
| Cancelled/disconnected waiter | NO assured response or ACK; active child remains independently tracked | N/A | N/A | N/A | true from later status if live |
| Denied/invalid/quarantined/unavailable/busy | Sanitized existing GatewayError, never success | false | null | false | false for this denied invocation |

Every actual returned v2 result includes `mode=local_best_effort`, `cleanup_proven=false`, `full_descendant_tree_clean=not_proven`, `output_complete` and existing bounded/redacted stdout/stderr/truncation fields. A direct exit code applies only to the original child, never a descendant guarantee. Do not introduce a misleading `cancelled=true` success after dropped transport; no auto-retry on missing ACK. Direct service and REST `/run` return identical Worker data/error codes; official MCP `run_command` returns those fields or the existing structured `isError` mapping, not a synthetic success.

`/info`, `/health` and MCP `gateway_info` expose the same sanitized `exec_policy` keys: `mode` (`preview_only` for v1, `local_best_effort` for v2), `enabled` (v1 existing dual grant, v2 any nonempty paths), `adapter_exposed`, `available` (v1 false; v2 true only with healthy old owner-lock state, at least one eligible path and no closing/unavailable latch), `completion_capability` (`none` for v1, `best_effort` for eligible v2; NEVER `full_tree`), `durability_state`, `quarantined`, `quarantine_reason_code`, `running_direct_children` (count only original tracked children), `max_concurrent_per_workspace=1`, `max_concurrent_total=4`, `dry_run_default=true` and a warning that child exit/timeout/cancel do not prove descendant cleanup. When capacity is full, represent the capacity limitation truthfully with `capacity_exhausted` or `available=false`, consistently across endpoints. Never expose PID/PGID, secrets or nonredacted output. Old v1 F1 still reports `exec_cleanup_proof_required` for eligible apply and keeps legacy error priority.

### 5.4 Go build validation, original CI evidence and r001 defect mapping

Go commands always use Direct, even with unrelated Pipfile. Allow `go test ./...`, `go vet ./...`, `go build ./...`, `go build ./cmd/server`, `go build -o bin/server ./cmd/server` and `go build -o=bin/server ./cmd/server`. Reject `go run`, missing/empty/duplicated `-o`, absolute/tilde/parent-traversing destination, `-o` outside effective authorized cwd subtree, existing symlink or multi-link/nonregular output leaf, symlink/nonexistent output parent, and any replacement/indirection flags such as `-exec`, `-toolexec`, `-vettool`, `-overlay`, `-modfile`, `-ldflags`, `-gcflags`, `-asmflags`, `-pkgdir`, `-buildmode` and their value/equals variants. Initially allow only simple Go package operands and explicitly reviewed safe flags (`-v`, `-trimpath`, one `-o` for build). Validate separated and combined `-o` identically in dry-run/apply, no-follow walk output parent and reject race observed before spawn. This is **not** an OS sandbox against trusted Go compiler/cgo/modules/cache side effects.

Original r001 hosted GitHub Run 40916659575 / Job 123598576883 was **FAIL** at exact Head e13dcb415996334cbb2df0411e20d8fea47fc8fe: G05 source admission PASS (218 Manifest entries), 36 downloaded wheels, wheel SHA source-lock check exit 2 because newer pytest 9.2.0, pydantic 2.14.2, pydantic_core 2.50.2 and sse_starlette 3.6.0 do not match committed versions 9.1.1, 2.14.1, 2.50.1 and 3.5.1. Install, RECORD checks, pytest and REST/MCP/Git smokes were SKIPPED. Original CI job logs are not replaced by B/C interpretations. Before positive code acceptance use a separately reviewed, deterministic resolver of the exact locked 36 wheel files and bytes for Linux/macOS, or independently approve replacement exact locks with downloaded original hashes and regenerate corresponding source checks. Never waive locked wheels or RECORD validation. New r002 design CI outcome must be reported separately.

Independent r001 defect-to-closure trace: B98-P2-01 + C98-P2-01 -> §5.1; C98-P2-02 + B98-P3-01 -> §5.2; C98-P2-03 -> §5.3; B98-P3-02 + C98-P3-01 -> §5.4. These are **proposed** design fixes pending NEW independent B/C r002 review, not an A-issued PASS.

## 6. Five-day staged work and minimum proof

- **D1 design:** This documentation-only PR; B and C independently review the weakened risk contract, v2 opt-in/path-only grant, lack of descendant guarantee, Go build `-o`, old v1 non-escalation, no surprise local privilege or old D0 bypass. A records exact reviewed Head/Base/Tree/authority and owner acceptance for code implementation. If rejected, repair design on a new Head/round before implementing.
- **D2 code:** Separate Draft implementation PR rooted on an explicitly fixed reviewed F1/G05 candidate plus accepted contract, not PR #97. Modify only affected config, shared service, Runner, minimal transport/status and relevant tests. Preserve history and do not rewrite frozen PRs.
- **D3 behavior:** Positive trusted Direct, Pipenv, Go `test`/`vet`/`build` including `-o`; negative cwd/argv/Workspace/output traversal; real output/timeout evidence in an approved disposable runner; no signal/PGID experiments without separate exact T2 approval.
- **D4 integration:** At approved disposable resources, same-instance real REST+official MCP success/denial/preview, legal independent Git/File success, bounded concurrency, cancellation and timeout truthfulness. Execute G05 source admission before imports and actual applicable CI/G05/R004 evidence; record Head vs synthetic Merge identities. No local user Mac/Tunnel/production tests without T3 grant.
- **D5 review:** New B/C independent SHA-bound full code reviews on the implementation PR, focused repair/re-test and honest R10/integration gate evaluation; deliver an explicitly labeled candidate or NO-GO, not automatic deployment.

Review coverage must include real success **and** unauthorized failure, edge cases and non-idempotent side effects; Mock/fake proof does not qualify actual positive Exec. A is Developer only and cannot independently sign B/C reviews or whole `FULL_CODE_REVIEW_PASS`.

## 7. Explicit approvals and exclusions

**Currently permitted:** revise this design and its Manifest following adverse r001 independent reviews, run harmless T0 source/manifest checks and request B/C new r002 independent design re-review. **Not currently permitted:** remove operative F1 denial, run real positive Exec/OS signal/Native T2, run physical private-FS T1, touch user Mac/Tunnel, auto-clear UNKNOWN, merge, tag, release or deploy. Any real disposable subprocess test must specify reviewed code, runner/resources/command/actions/budgets and required T1/T2 permission. Tests do not become authorized merely because they are listed here.

**B Standards review request:** Check explicit scope and D0 exception boundaries, config v1->v2 non-escalation, local OS trust, safe output and `-o` containment, no-unsafe-PID/PGID, non-Exec Git/File, G05/R004 and full lifecycle truthfulness. Provide independent negatives and P0-P3.
**C Spec review request:** Check that legal Python/Pipenv/Go `build/test/vet` runs and that unauthorized requests reject, mode/output/cancellation/timeout responses are truthful, preview matches apply validation, REST and MCP share the Worker, and five-day acceptance is testable. Provide independent counterexamples and P0-P3.

**STOP:** No positive Exec code activation or user Mac/Tunnel experiment until this exact fixed design is independently reviewed by B/C, user accepts the precise operative exception version, and later implementation plus appropriately authorized native/integration evidence meet their own current-snapshot gates.
