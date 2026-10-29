# Multi-Workspace Exec — Local Best Effort V1 (five-day product candidate)

**CONTRACT_ID:** `MWE-LOCAL-BEST-EFFORT-V1.0-CANDIDATE`
**STATUS:** DESIGN_ONLY / NONOPERATIVE / AWAITING_INDEPENDENT_B_AND_C_DESIGN_REVIEW / NOT_APPROVED_FOR_POSITIVE_EXEC
**TASK_ID:** `MULTI-EXEC-LBE-V1-DESIGN-20261030`
**REVIEW_ROUND:** `r001` (new isolated design branch, not PR #97 r001)
**REVIEW_TARGET:** TARGETED design decision for a new `local_best_effort` Multi-Workspace Exec mode and its minimal five-day implementation/test plan. NO product runtime modification in this PR.

## 1. Source of authority and user direction

- GitHub repository: `chinanjjohn2012/mac-file-gateway`. Isolated parent: frozen F1/G05 integrated RC PR #76 Head `0fc1ae245de7cb582a69162c79c201d15bfaa258`, native Tree `e05777c0bc6eea0b375a6347602b99c68024b3b6`; target base branch `rc/multi-exec-f1-g05-integrated-ms1-20261025`. No N3/N2/Native research branch is a parent.
- Current **operative** source-based restrictions remain `docs/MULTI_WORKSPACE_EXEC_RECOVERY_D0_DESIGN.md` Blob `6e25904aed9a62bb0f472b732021c2a7ca3b3bb0` §§0.1/0.4; F1 implementation plan Blob `76baeb820c6f8a9b067e45e2dcc42e76453fe5b1`; Phase1 local trust boundary Blob `b3f2383f292a59fd234269389e5338cd50e334a2`; G05 Blob `76c1c2b8a7947e0b305d55c5f550ab59c638b6d1`; R004 user-scoped 36 locked Wheel + RECORD-listed file attestation; existing F1/G05 code and authorizations.
- Review protocol: `ICR-V2.0`, `GHRH-2.0`, `ETP-V2.0`; this is a NEW r001 design candidate requiring B and C's separate native SHA-bound targeted design reviews, followed by explicit owner acceptance of the **exact reviewed version** before making any D0 exception operative.
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

**Reconciliation required:** B and C must independently decide if v1/v2 private state can remain isolated without the new best-effort mode inheriting stale v1 permission, and whether a no-persisted-intent/restart-unaware mode is acceptable in the explicitly trusted local OS-user model. This is a deliberate security/product contract difference, not a test mock for the old D0.

## 6. Five-day staged work and minimum proof

- **D1 design:** This documentation-only PR; B and C independently review the weakened risk contract, v2 opt-in/path-only grant, lack of descendant guarantee, Go build `-o`, old v1 non-escalation, no surprise local privilege or old D0 bypass. A records exact reviewed Head/Base/Tree/authority and owner acceptance for code implementation. If rejected, repair design on a new Head/round before implementing.
- **D2 code:** Separate Draft implementation PR rooted on an explicitly fixed reviewed F1/G05 candidate plus accepted contract, not PR #97. Modify only affected config, shared service, Runner, minimal transport/status and relevant tests. Preserve history and do not rewrite frozen PRs.
- **D3 behavior:** Positive trusted Direct, Pipenv, Go `test`/`vet`/`build` including `-o`; negative cwd/argv/Workspace/output traversal; real output/timeout evidence in an approved disposable runner; no signal/PGID experiments without separate exact T2 approval.
- **D4 integration:** At approved disposable resources, same-instance real REST+official MCP success/denial/preview, legal independent Git/File success, bounded concurrency, cancellation and timeout truthfulness. Execute G05 source admission before imports and actual applicable CI/G05/R004 evidence; record Head vs synthetic Merge identities. No local user Mac/Tunnel/production tests without T3 grant.
- **D5 review:** New B/C independent SHA-bound full code reviews on the implementation PR, focused repair/re-test and honest R10/integration gate evaluation; deliver an explicitly labeled candidate or NO-GO, not automatic deployment.

Review coverage must include real success **and** unauthorized failure, edge cases and non-idempotent side effects; Mock/fake proof does not qualify actual positive Exec. A is Developer only and cannot independently sign B/C reviews or whole `FULL_CODE_REVIEW_PASS`.

## 7. Explicit approvals and exclusions

**Currently permitted:** document this user-requested new limited design, construct a fresh standalone Draft PR, run harmless T0 source/manifest checks, request B/C design reviews. **Not currently permitted:** remove operative F1 denial, run real positive Exec/OS signal/Native T2, run physical private-FS T1, touch user Mac/Tunnel, auto-clear UNKNOWN, merge, tag, release or deploy. Any real disposable subprocess test must specify reviewed code, runner/resources/command/actions/budgets and required T1/T2 permission. Tests do not become authorized merely because they are listed here.

**B Standards review request:** Check explicit scope and D0 exception boundaries, config v1->v2 non-escalation, local OS trust, safe output and `-o` containment, no-unsafe-PID/PGID, non-Exec Git/File, G05/R004 and full lifecycle truthfulness. Provide independent negatives and P0-P3.
**C Spec review request:** Check that legal Python/Pipenv/Go `build/test/vet` runs and that unauthorized requests reject, mode/output/cancellation/timeout responses are truthful, preview matches apply validation, REST and MCP share the Worker, and five-day acceptance is testable. Provide independent counterexamples and P0-P3.

**STOP:** No positive Exec code activation or user Mac/Tunnel experiment until this exact fixed design is independently reviewed by B/C, user accepts the precise operative exception version, and later implementation plus appropriately authorized native/integration evidence meet their own current-snapshot gates.
