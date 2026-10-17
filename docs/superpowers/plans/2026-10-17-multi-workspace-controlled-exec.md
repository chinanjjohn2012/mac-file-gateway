# Multi-Workspace Phase 2 Controlled Exec Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add explicitly authorized per-Workspace Controlled Exec to Multi mode, without weakening existing Phase 1 file APIs or Legacy exec/Local Skills.

**Architecture:** Reuse the existing `CommandRunner` and add a single-owner `ExecSupervisor` that controls spawn, native process-group identity, cancellation, drain and lifetime leases. `WorkspaceService` alone authorizes Workspace execution; HTTP/MCP only adapt strict arguments. No OS sandbox is claimed.

**Tech Stack:** Python 3.11+ for Legacy/file-only; **macOS Python 3.13+ for Phase 2 Multi exec**, subject to a native `WNOWAIT`/PGID qualification gate. Starlette, MCP SDK, Uvicorn, AnyIO, pytest, Python `subprocess`, native macOS process signals, Pipenv and Go.

**Spec:** `docs/superpowers/specs/2026-10-17-multi-workspace-controlled-exec-design.md` at the approved conditional-freeze design base `a7a3f87772ad13545facff48620db68f12ac8ef3`. Third independent design review: **CONDITIONAL**, zero new P findings; not functional PASS.

## Global Constraints

- **Approved 2026-10-17 product values:** extend `schema_version:1`; `paths:["."]` requires explicit administrator authorization; 1 active exec per Workspace and 4 global; TERM grace 2 seconds, separate drain budget 2 seconds; no public remote cancel API; **at most one `Popen` attempt per admitted request** (`Popen_attempts <= 1`; rejected/dry-run/pre-spawn-cancelled requests have 0), **no dedup between independent requests**.
- **Python version boundary:** existing Legacy and file-only functionality continues to support Python 3.11+. Phase 2 Multi exec on macOS requires Python **3.13+**. This is a capability gate, **not** permission to raise the whole Gateway's minimum version or to execute unsafe fallback `killpg` on unsupported versions. Validate version before listener/exec activation. Document any non-macOS platform support explicitly; do not claim `WNOWAIT` is safe on a platform before native evidence.
- **Review gating:** API and security invariants are conditionally frozen. Exact `WNOWAIT`/unreaped-leader mechanism is *not* qualified. If Task 1 native proof fails, **STOP Task 4 and dependent Multi exec integration/release**, return the OS anchor mechanism to design review; **Task 2 and Task 3 pure parsing/admission work remain independently allowed** when separately authorized. No unchecked numeric PGID signalling.
- **Pre-existing safety defects:** D1/P1 Go hook alias and D2/P2 option-path bypass in shared Legacy `CommandRunner` must be fixed, with pytest R1 indirect argv rejection, *before* Multi exec routes are made runnable.
- Multi mode remains disabled by default. Skills are Phase 3 and stay disabled; Legacy single-root API and behaviour must remain compatible except explicitly prohibited dangerous argv.
- No production policy, real credentials, real project scripts, Tunnel, or running Gateway changes; use synthetic roots and processes only.
- Work on a separate feature branch/worktree; one testable task and security review per change. Never merge or deploy without subsequent explicit authorization.
- On Mac, verify SIGINT and SIGTERM with a live synthetic Gateway listener. Existing CI/Manifest success is not Phase 2 functionality proof.

## Review Focus

The five easy-to-miss scenarios are each owned by the tasks below: (1) pytest short-option clusters, `--`, and `@` indirection (Task 2); (2) native actual-cwd dev/ino changing between validation and spawn, including Pipfile binding (Tasks 3/4); (3) leader exit with original-group descendants still alive or holding pipes (Tasks 1/4); (4) SDK cancellation sent by a second POST or a cancelled worker queued before spawn (Tasks 3/5); (5) lost response and independent retry after side effects (Tasks 4/6).

## Task dependencies and independent STOP boundaries

The task numbers are references, **not an unconditional serial execution order**. The preferred first security task is **Task 2** (shared Legacy D1/P1, D2/P2 and R1 fixes); **Task 1** (test-only PGID proof) may proceed independently. Task 3's static policy/admission tests and actual-cwd *synthetic/native feasibility probe* can also progress independently, without enabling Multi exec. The native Supervisor in Task 4 has hard predecessors **Task 1 qualified + Task 2 reviewed + Task 3 cwd launch contract qualified**. Task 5 integrates the transport, followed by Task 6 lifecycle and Task 7 full verification. No Task 4–7 functional activation is permitted on an unqualified native anchor.

```text
Task 2 (shared Legacy safety fixes) ----\
Task 1 (test-only OS PGID proof) --------+--> Task 4 (Supervisor) --> Task 5 (REST/MCP) --> Task 6 --> Task 7
Task 3 (policy + native cwd seam proof) -/
                  ^
MCP session/request-to-ticket identity contract is decided in this plan
and informs Tasks 3/4 admission even before Task 5 exposes any endpoint.
```

If **Task 1 FAILS**, stop native PGID Supervisor integration and dependent Multi exec release, retain exec fail-closed; **do not stop Task 2** or Task 3's independent static work. If **Task 3 actual cwd handoff FAILS**, stop execution integration until a separately reviewed alternative qualifies; do not fall back to a string-path cwd or unsafe process-global chdir. If the SDK cancellation mode fails, do not claim SDK cancel support or expose exec; revisit the transport decision without introducing a public cancel/job API.

## Pre-implementation contracts resolving IP1–IP3

**IP1: spawn attempts rather than assumed execution.** A unique admitted ticket may make **zero or one** actual `Popen` call. Denied/dry-run/pre-spawn-cancelled: `Popen_attempts=0, marker=0`. Once the apply branch is authorized and enters the actual spawn attempt: `Popen_attempts=1` even when Popen raises; marker stays 0 if it never started. On successful launch followed by response loss/re-entry: ≤1 attempt and ≤1 synthetic marker for that one ticket. An independent later request has a **different ticket** and may execute again. Counting only markers is insufficient; no assertion may require one spawn from every admitted request.

**IP2: actual cwd is a launched directory object, not a re-resolved string.** Task 3 adds `gateway/executor.py` and a `VerifiedCwdLease` (or equivalently named context-managed structure) containing both open, no-follow actual-cwd FD and expected `st_dev/st_ino` plus its root/workspace lease. The **selected first macOS single-Popen launch candidate** is `Popen(cwd=f"/dev/fd/{cwd_fd}", pass_fds=(cwd_fd,), ...)` with `shell=False` and `start_new_session=True`, holding the pinned FD from authorization through child launch; this uses the child-inherited FD namespace instead of `Popen(cwd=str(root.joinpath(...)))`. **Candidate only, not a proven macOS guarantee.** Before production coupling, a native synthetic probe must prove that macOS `/dev/fd/<fd>` resolves to the *same authorized directory object* after validated cwd/ancestor names are renamed/recreated between check and spawn, and that PID, process group, cwd FD/pipe ownership, direct/pipenv/Pipfile selection, and cleanup meet the contract. Measure `(st_dev, st_ino)` of child's `.` and compare it to the pinned actual FD; accept only matching identity **or controlled failure before target code/marker runs**. Repeat with a gate/barrier precisely before spawn, not only preflight `stat()`. If this Popen-based FD path is not provable on supported native macOS, **STOP native exec coupling and return to design review** (a native `posix_spawn` fchdir file action is a possible alternative requiring its own explicit approval, process-handle/at-most-one-spawn contract and qualification; no silent switch). Do **not** use multithreaded process-global `chdir`, `preexec_fn`, an extra unaccounted helper launch, or a stat-only check. The trusted-local-code/no-OS-sandbox model stays unchanged.

**IP3: MCP cancellation has a session and ticket owner.** For a Multi Gateway with **any** exec-enabled Workspace, choose MCP SDK `stateless_http=False` on the existing `/mcp` endpoint and retain `json_response=True` as supported by the tested SDK; require a proper `initialize` and `Mcp-Session-Id` for subsequent POSTs. Pure file-only Multi (`exec.enabled=false` everywhere) retains Phase 1 `stateless_http=True`; Legacy single-root is unchanged. In an exec-enabled Multi process, existing file tools must also work through the **stateful** session; document/test this observable client migration rather than pretending stateless file tool calls still work on that process. If existing required clients cannot negotiate a stateful session, **stop and seek architecture/owner review**, do not silently add a second insecure cancellation mechanism or endpoint.

The SDK identifies requests by the authenticated **session instance + original wire requestId**, never bare requestId; that identity maps to a server-minted **ticket/generation** created **before** submitting the synchronous worker. A cancel notification from another POST with the **same session ID** may cancel only that session's matching in-flight request. Before worker dispatch, register the request-to-ticket mapping and latch cancellation; after task cancellation, notify `ExecSupervisor.cancel(ticket_id, reason)` and **shield the actual cleanup wait** so cancelling the AnyIO waiter does not abandon a running process. Remove the mapping only when the owned worker is truly finished, and use identity-safe compare-and-remove so a late notification or reused requestId cannot cancel a new ticket. An independent retry, including identical MCP request IDs in a new request, creates a new ticket and is **not** deduplicated. REST cancellation is separate; if it is not observable, the command deadline still applies. A notification HTTP **202** is not evidence the owner actually received cancellation. This is standard SDK cancellation, not a new public remote cancel API.

## File map / ownership

- `gateway/executor.py` — shared CLI semantic validation, Legacy entry **and pinned actual-cwd launch handoff (IP2)**; avoid duplicating validators.
- `gateway/exec_supervisor.py` (new) — internal tickets, native PGID identity, owned process signalling, bounded dual-stream drain, permits and teardown.
- `gateway/workspaces_config.py` — optional per-Workspace exec policy and Python capability admission.
- `gateway/workspaces.py` — final Workspace authorization, permit ownership, worker leases, close/drain.
- `gateway/multi_fields.py` — strict Multi exec parameters; do not open Local Skill tools.
- `gateway/http_multi.py` / `gateway/mcp_multi.py` — REST/MCP adapters; when exec enabled MCP uses stateful SDK sessions and request-to-ticket cancellation, pure file-only stays stateless (IP3).
- `gateway/multi_cli.py` — reliable actual SIGINT/SIGTERM shutdown integration.
- `tests/test_phase2_native_pgid.py`, `tests/test_phase2_argv.py`, `tests/test_phase2_config.py`, `tests/test_phase2_supervisor.py`, `tests/test_phase2_admission.py`, `tests/test_phase2_cwd_launch.py`, `tests/test_phase2_http_mcp.py`, `tests/test_phase2_live_shutdown.py` (new) — isolated negative and positive controls; corresponding Legacy tests remain.
- `docs/CONTROLLED_EXEC.md`, `README.md`, `MANIFEST.sha256` — truthful scope, security limits and reproducible verification.

---

### Task 1: Qualify native group identity **before** coding Supervisor

**Files:** Create `tests/test_phase2_native_pgid.py`; no production implementation in this task.

**Interfaces:** Produce a documented executable predicate `native_identity_anchor_qualified()` for platform/version acceptance **only as a test/probe outcome**, not a deployed helper. Record `WNOWAIT` observation, unreaped group leader lifetime, sole reap and signal sequencing. Subsequent work must consult its evidence.

- [ ] **Step 1 — write a native macOS isolated probe**: create own leader and original-group descendants; exercise normal exit, last member exit, ignore-TERM, observing before reaping, final reap, and cancelled timing windows; never send signals to unrelated PIDs. Assert the kernel identity required by the design remains reserved until the final signal permission is exhausted.
- [ ] **Step 2 — demonstrate and capture fail-closed controls**: simulate early reap plus numeric PGID reassignment to a different mock owner; all stale tickets must send **zero** signals to that owner. Measure repeating `WNOWAIT` and `WNOHANG` outcomes; distinguish EPERM/ESRCH from identity proof.
- [ ] **Step 3 — verify primitive Python support**: demonstrate availability/behaviour of native `waitid(WNOWAIT)` and retention of group identity on each qualified macOS Python 3.13+/3.14 platform. The **production startup capability check** (macOS 3.11/3.12 exec rejected while file/Legacy work) belongs to Task 3 and must use an actually enabled config, not the Phase 1 unconditional exec-off policy. Review `Popen.poll/wait/communicate`, `__del__`, SIGCHLD and other reapers; any premature reap path fails qualification.
- [ ] **Step 4 — run**: `python -m pytest tests/test_phase2_native_pgid.py -q` on supported macOS with synthetic processes; expected all tests pass with process identity/cleanup evidence and no unowned signal, not just a mock-only PASS.
- [ ] **Step 5 — decision gate**: independent reviewer signs off OS identity anchor and support matrix. **If the anchor cannot be proved, stop Task 4's native PGID Supervisor and dependent Task 5–7 functional activation, preserve evidence and return the identity mechanism to architecture review; Task 2 may be completed/reviewed independently and Task 3 static parsing/admission/probes may proceed, but nothing may enable Multi exec or unsafe group signalling.** Commit test-only proof on feature branch.

### Task 2: Fix shared CommandRunner CLI validation (D1, D2, R1) — independent/priority security task

**Files:** Modify `gateway/executor.py`, tests `tests/test_phase2_argv.py` and existing Legacy command tests.

**Interfaces:** Preserve `_validate_command(argv: list[str]) -> str | None` plus `_reject_external_path_args(argv: list[str]) -> None`; shared validation must complete before `CommandRunner.run(..., dry_run=false)` calls Popen.

- [ ] **Step 1 — failing tests**: Go `-exec/--exec`, `toolexec`, `vettool` variants (single/double dash, `=`/split, positions) all rejected, `Popen_attempts=0` in dry/apply; native synthetic Go hook marker does not appear. Safe Go flags still work.
- [ ] **Step 2 — failing pytest/path tests**: `-c../outside/pytest.ini`, `--config-file=../outside/pytest.ini`, Go `-modfile=../outside/go.mod` fail; in-scope config works. `@argsfile` (including after `--`) and remote `-o/--override-ini` modifying `addopts` are rejected. Include `-o=addopts=...`, `-qoaddopts=...`, `-qo=addopts=...`; distinguish real option context from plain positional strings/`--` context. Safe non-addopts override, `-q`, legitimate nodeid and marker text remain accepted.
- [ ] **Step 3 — run failing**: `python -m pytest tests/test_phase2_argv.py -q` and relevant pre-existing Legacy test modules; prove the original weakness is detected without actually launching a malicious external command.
- [ ] **Step 4 — implement minimal semantic parser** for Go and pytest under the shared allowlist, without shell, arbitrary argv rewriting, reading `@` files, or running subprocesses during dry-run; no remote `PYTEST_ADDOPTS` environment inheritance.
- [ ] **Step 5 — verify green + Legacy controls**: `python -m pytest tests/test_phase2_argv.py tests/test_exec_cli.py tests/test_mcp_exec.py tests/test_command_runner.py tests/test_command_http.py -q`; output must show 0 failed, and dedicated native synthetic controls pass. Review dangerous-option compatibility as deliberate security tightening.
- [ ] **Step 6 — commit** shared validator + tests; independent security reviewer confirms D1/P1 and D2/P2 parser cases closed before Multi exec exposure.

### Task 3: Workspace config, capability gate and admission

**Files:** Modify `gateway/workspaces_config.py`, `gateway/workspaces.py`, **`gateway/executor.py` for pinned-cwd handoff**; tests `tests/test_phase2_config.py`, `tests/test_phase2_admission.py` and **`tests/test_phase2_cwd_launch.py`**.

**Interfaces:** `parse_workspace_config(config: dict[str, Any]) -> GatewaySettings` keeps old Phase 1 config defaults; add immutable per-workspace exec enabled/scopes/runner policy. `WorkspaceService.require(name: str, operation: str) -> WorkspaceContext` is the final authority; add explicit exec admission/permit interface consumed by Task 4, with 1/Workspace + 4/global slots. **Request ticket is minted and can latch cancellation before handing work to an executor; Task 5's session/request binding uses that same ticket, never generates a second ticket on internal retry.** A context-managed pinned cwd FD/identity lease from `executor.py` remains valid across the real spawn handoff.

- [ ] **Step 1 — failing config tests**: old JSON keeps exec off; enabled with empty/invalid scope, duplicate JSON keys, bad runner or root conflict rejects before listener/Popen; `paths:["."]` only when explicitly present, Python 3.11/3.12 macOS Multi exec denied while file-only and Legacy remain compatible.
- [ ] **Step 2 — failing authorization tests**: A exec on / B exec off, unknown/blank Workspace, out-of-root cwd, symlinks and scope aliases, runner/Pipfile binding; no cross-root fallback. All denied direct Service calls must have `Popen=0`.
- [ ] **Step 3 — implement parser and immutable policy** for Workspace exec; ensure Python macOS 3.11/3.12 rejects an **enabled** Multi exec policy before listener/Popen while file-only and Legacy have positive controls, and 3.13+ capability is still conditional on Task 1 native qualification. Keep existing file policy defaults. Do not treat `write.enabled=false` as OS read-only if exec is enabled.
- [ ] **Step 4 — create actual-cwd FD launch tests (IP2)** in `tests/test_phase2_cwd_launch.py`: use a barrier after path validation before Popen; rename/recreate selected cwd and each ancestor. Compare child `os.stat('.')` dev/ino with expected pinned FD, **or** controlled launch failure with marker=0. Run on native macOS for direct/pipenv and automatic/explicit Pipfile, sibling dir, scope boundary, and exception/cancel cleanup. Do not use an unverified string cwd fallback. A synthetic intercept alone is a failing control, not native PASS.
- [ ] **Step 5 — implement/qualify pinned-cwd launch handoff** in `gateway/executor.py`: hold no-follow `cwd_fd` and Workspace root lease through the single Popen using the explicitly selected `/dev/fd/{cwd_fd}` plus `pass_fds` candidate in the pre-implementation contract. Verify native child identity and Popen/start_new_session semantics before integrating; if not qualified, **STOP native execution integration** and review an alternative. Only one Popen attempt is allowed and the owned FD is cleaned on all paths.
- [ ] **Step 6 — implement atomic nonqueueing exec admission** before dispatch to sync workers; `STARTING/RUNNING/STOPPING` all occupy quota, fifth concurrent exec returns business busy immediately. Separate bounded exec workers/limiter from Phase 1 file worker capacity.
- [ ] **Step 7 — run** `python -m pytest tests/test_phase2_config.py tests/test_phase2_admission.py tests/test_phase2_cwd_launch.py -q` on qualified native macOS for the cwd proof; require no process spawn for denied/dry-run, busy without queued work and no starving B file reads.
- [ ] **Step 8 — commit** configuration/admission/cwd launch work with security review of fail-closed defaults.

### Task 4: Implement the sole-owner ExecSupervisor

**Files:** Create `gateway/exec_supervisor.py`; integrate minimally in `gateway/executor.py` and `gateway/workspaces.py`; test `tests/test_phase2_supervisor.py`.

**Interfaces:** Supervisor owns `ticket_id`, state `STARTING|RUNNING|STOPPING|FINISHED`, group leader, original PGID, *qualified* OS identity anchor, pipes and permits. Consume Task 3 `VerifiedCwdLease` held through actual Popen. Ticket identity is created at admission and later binds to a specific MCP (session, request, generation) without replacing ticket on retry. Implement `cancel(ticket_id, reason)`, `close()` and one synchronous execution entry that returns the existing Legacy fields plus safe Multi additions. Do not introduce persistent job IDs or remote cancel API.

- [ ] **Step 1 — failing cancellation/state tests**: cancel before/after Popen, after handle return but before registration, exception in spawn/reader, concurrent close, duplicate cancel, one-tick delayed TERM/KILL; each ticket has `Popen_attempts <= 1` (denied, dry-run, pre-spawn-cancel = 0; spawn-error = 1 with marker 0; post-start error/reentry ≤1 and marker ≤1); quota/leases released exactly once.
- [ ] **Step 2 — failing original-group tests**: leader exits 0 while descendants remain in original group with inherited and redirected pipes; do not mark `FINISHED` or return while managed group is alive; preserve leader exit code and `timed_out=false` after clean-up.
- [ ] **Step 3 — failing STOPPING PGID identity tests**: last original-group member exits between “check→TERM” and “TERM→2s→KILL”; fake kernel reassigns number to unrelated group, stale ticket's `signal_to_new_owner` must equal 0. One owner performs all signals, revokes/delays timers, drains in-flight signals, then unique `wait/reap`; never `Popen.poll/wait/communicate` behind the owner's back.
- [ ] **Step 4 — implement qualified native anchor** (Task 1 **PASS**, Task 2 security fixes reviewed and Task 3 native cwd launch **PASS** prerequisites), sole owner event queue/lock and TERM→2s→KILL sequencing with strict no-unsafe-fallback behaviour. Keep permissions and FD lease until true worker completion; active operation cancellation is not mere cancellation of ASGI waiter.
- [ ] **Step 5 — failing reader tests + implementation**: define monotonic TERM deadline at first stop/TERM and never reset on repeated cancel; start a **separate** 2s drain deadline at group-cleanup completion (normal output is drained throughout execution). Two streams drained by owner-controlled nonblocking/select or equivalent interruptible bounded polling; independent 2s drain deadline, partial-output flag, no indefinite EOF dependence, no cross-thread `BufferedReader.close`. Escaped `setsid` helper may survive but service reader/FD must be reclaimed. Add single-stream and simultaneous stdout/stderr >48000-character outputs, invalid UTF-8, reader exceptions, stdout/stderr truncation and owned FD/permit release; use a synthetic environment secret sentinel and confirm it is not inherited or leaked in diagnostics.
- [ ] **Step 6 — run** `python -m pytest tests/test_phase2_supervisor.py tests/test_phase2_native_pgid.py -q` and native synthetic process groups; require no owned descendant/FD/permit leaks and exactly one final reap.
- [ ] **Step 7 — commit** Supervisor and integrations; independent lifecycle review before any public endpoint exposure.

### Task 5: Strict REST/MCP adapters and observable cancellation

**Files:** Modify `gateway/multi_fields.py`, `gateway/http_multi.py`, `gateway/mcp_multi.py`, `gateway/workspaces.py`; tests `tests/test_phase2_http_mcp.py`.

**Interfaces:** Multi `POST /run` and MCP `run_command` accept `workspace,cwd,argv,timeout_seconds=60,dry_run=true`. When any Multi Workspace has exec enabled, the SDK MCP transport is **stateful** (`stateless_http=False`, `json_response=True`, initialized session), while file-only mode retains Phase 1 stateless transport; all tools share one `/mcp` endpoint. SDK (session instance, request ID, generation) binds to an already minted admission ticket. Both call the same WorkspaceService authorized execution entry; Skills remain disabled. REST maps business error to HTTP; MCP preserves a machine-readable business code in SDK tool error response.

- [ ] **Step 1 — failing strict negative tests**: wrong Host/Origin/Bearer, MIME, duplicate JSON keys, surrogate/number overflow, wrong types, unknown fields, missing Workspace, **raw and decoded payload over size limits**; assert listener accepted but **business dispatch=0 and `Popen_attempts=0`** for rejected requests (startup config failures assert listener=0); each has legal request positive control. Test REST business vs MCP SDK error mapping. Tools/list includes exec only if some Workspace enabled; B still denied if A enabled.
- [ ] **Step 2 — test stateful cancellation mechanism with real SDK (IP3)** before connecting exec: initialized `Mcp-Session-Id` session, long synthetic tools/call on POST A, `notifications/cancelled` on POST B using same session; confirm actual tool cancellation, **not just HTTP 202**. Two sessions with same requestId must not cancel each other. A stateless SDK probe is retained as expected-failing historical negative control; file-only stateless clients and stateful file tools in exec-enabled Multi both have positive controls. If SDK cannot guarantee session correlation, STOP adapter integration and return to design review.
- [ ] **Step 3 — implement REST route and MCP tool** sharing exact strict input schema and Service method and SDK transport mode, with request-to-ticket identity/compare-remove and early cancel latch. Register ticket before worker submission; cancellation triggers `Supervisor.cancel` and shielded wait for **actual worker** cleanup; late notification/reused ID cannot cancel successor. Return bounded/untrusted result, no raw paths/credentials in errors; never enable Local Skill tools. Document migration of clients to stateful initialize/session when exec is enabled.
- [ ] **Step 4 — cancellation tests**: asyncio Task.cancel, AnyIO CancelScope, **cross-POST SDK** cancellation notification, observable REST disconnect; exercise early cancel **before** ticket/work dispatch, after spawn, and after requestId reuse, with FD/permit recovery. Only the matching MCP session+request+ticket may cancel. Do not equate AnyIO shielded waiter with process cleanup; if network disconnect is unobservable, enforce timeout. Saturated executor pool/pending cancel cannot produce late spawn.
- [ ] **Step 5 — run** `python -m pytest tests/test_phase2_http_mcp.py tests/test_phase2_admission.py -q` plus live HTTP/MCP against synthetic paths; verify positive command in A *and* negative Popen=0 in B.
- [ ] **Step 6 — commit** adapters and independent security review of raw SDK/HTTP admission.

### Task 6: Shutdown, at-most-once and Native macOS lifecycle

**Files:** Modify `gateway/multi_cli.py`, `gateway/workspaces.py`, `gateway/exec_supervisor.py`; test `tests/test_phase2_live_shutdown.py`.

**Interfaces:** `WorkspaceService.close()` first refuses new work, then cancels active execution and waits for actual worker cleanup, finally releases root pins. The CLI/ASGI shutdown path must call it for both SIGINT and SIGTERM, not merely rely on outer `finally`.

- [ ] **Step 1 — write native live signal tests**: idle, Popen STARTING, RUNNING, STOPPING/drain and concurrent close with both SIGINT/SIGTERM on private loopback port; assert termination of managed group, actual worker completed, reader/permit released before root FD.
- [ ] **Step 2 — prove existing SIGTERM issue** on pinned baseline using a synthetic minimal app; then implement minimal reliable signal/lifespan integration without disabling graceful draining or introducing double-close.
- [ ] **Step 3 — request identity tests (IP1/D5)**: rejected/dry-run/pre-spawn cancelled ticket → `Popen_attempts=0`, marker=0; apply that enters spawn but Popen raises → attempts=1, marker=0, permit/lease recover; post-start response failure/internal reentry → attempts≤1, marker≤1; **new** independent request after response loss may spawn once more and add a second marker. Record actual Popen attempt counter separately from markers. Keep `idempotentHint=false`.
- [ ] **Step 4 — test cancellation close ordering**: pending file read and long exec in different Workspaces, concurrent close/cancel and recovered output; ensure worker lease last use precedes pin FD close, no global file lock contention.
- [ ] **Step 5 — run** `python -m pytest tests/test_phase2_live_shutdown.py tests/test_phase2_supervisor.py -q` on native macOS with bounded cleanup of self-created helper processes. If SIGTERM still bypasses cleanup, **BLOCK** and do not merge.
- [ ] **Step 6 — commit** CLI/shutdown and at-most-once coverage; lifecycle independent review.

### Task 7: Full regression, documentation and merge-ready evidence (no merge)

**Files:** Modify `docs/CONTROLLED_EXEC.md` and `README.md`; update `MANIFEST.sha256`; add minimal acceptance report under `docs/` if useful.

**Interfaces:** No public API additions beyond Task 5. Evidence must pin exact final commit/tree; no private root paths or business policies in public documentation.

- [ ] **Step 1 — verify M01–M15** independently, with matrix entries mapped to `tests/test_phase2_*`, Legacy exec and Phase 1 F1–F7/N1 regressions. Report explicit pass/fail/skipped for native macOS and GitHub Linux separately.
- [ ] **Step 2 — run** `bash verify.sh --require-mcp`, `python -m pytest -q`, `python tests/smoke_live.py`, and native SIGINT/SIGTERM tests. Verify no false PASS from original CI; all P0/P1 and unverified PGID/SIGTERM items remain blockers.
- [ ] **Step 3 — docs** state no OS sandbox, `exec=true/write=false` may mutate host, no cross-request retry dedup, no remote cancel API, macOS Multi exec Python 3.13+ while Legacy/file-only 3.11+; explicit per-Workspace scopes, credential/stream redaction limitations and setup examples with synthetic paths.
- [ ] **Step 4 — verify manifest** using the same sorted file set as CI and `diff -u MANIFEST.sha256 /tmp/MANIFEST.sha256`; `git diff --check` must exit 0. Ensure no private paths, hostnames, user files, credentials or test artifacts committed.
- [ ] **Step 5 — independent security + lifecycle code review**, then create a Draft feature PR with commit/tree, exact evidence and known boundaries. **Do not move to Ready, merge, restart, modify real config, enable Skills or deploy** without distinct authorization.

## M01–M15 acceptance case ownership and no-silent-skip rules

Every row names the **owning Task/test file or focused case**, the required **negative / positive control**, the decisive **observable assertion**, and the required **platform**. For startup failures `listener=0`; for authenticated request rejections `dispatch=0, Popen_attempts=0`. Do not count historical file-only smoke as a Multi exec/MCP result. Unrun, skipped, or mocked-only coverage of mandatory native/SDK/live cases is **BLOCK for functional merge**, not PASS.

| ID | Owner / focused test | Negative / positive control → decisive assertion | Platform / skip gate |
| --- | --- | --- | --- |
| M01 | T3 `test_phase2_config.py::test_new_exec_config_fail_closed_on_phase1` | new enabled JSON against pinned old Phase 1: **listener=0, Popen=0**; old JSON under new release: exec=false and listener starts; 3.11/3.12 enabled denied, Legacy/file-only starts | old-vs-new subprocess + macOS supported Python; skip blocks |
| M02 | T3/5 `test_phase2_admission.py::test_cross_workspace_exec_denied` | A valid positive spawn; B/off, absent ID, wrong scope all deny, **Popen=0**; no Skills tools | Service, REST and MCP; skip blocks |
| M03 | T2/5 `test_phase2_argv.py::test_go_pytest_indirection_matrix` | Go hook aliases, path options, pytest `-o` short clusters, `@` incl `--` rejected **Popen=0**, legal Go/pytest positive apply across both forms/runner modes | native Go/pytest + Legacy/Multi HTTP/MCP; skip blocks |
| M04 | T5 `test_phase2_http_mcp.py::test_raw_decoded_payload_limits` | raw/decoded oversized, bad MIME, duplicate JSON, Unicode/fields denied **dispatch=0, Popen=0**; valid small request accepted | REST/MCP SDK real bodies; skip blocks |
| M05 | T2/4/5 `test_phase2_http_mcp.py::test_valid_direct_pipenv_results` | direct/pipenv Python/pytest/Go valid cwd, correct runner/result & exit status; dry-run **Popen=0**, missing runner mapped correctly | native macOS real synthetic commands; skip blocks |
| M06 | T4 `test_phase2_supervisor.py::test_spawn_cancel_barriers` | cancel before Popen=0; failed Popen=1/marker0; post-start errors ≤1; **permit/FD/lease baseline** | model and native spawn; native skip blocks |
| M07 | T3/5 `test_phase2_admission.py::test_busy_does_not_queue` | second same-WS/fifth global 409 immediately, **no delayed start**; independent B file read completes with A long exec | sync workers + live REST; skip blocks |
| M08 | T1/4 `test_phase2_supervisor.py::test_leader_zero_descendants_cleaned` | leader=0 & inherited/redirected pipes; original group cleaned before FINISHED, exit_code=0, FD/permits baseline | native macOS; skip blocks |
| M09 | T4 `test_phase2_supervisor.py::test_escaped_pipe_writer_drain_budget` | escaped child retains stderr or both streams without EOF; 2s drain budget, partial flag and service FD/permit returned | native macOS; skip blocks |
| M10 | T4/5 `test_phase2_http_mcp.py::test_sdk_cross_post_cancel_is_owned` | same-session later POST cancels active; cross-session same requestId does **not**; asyncio/AnyIO/REST cancel tested separately; ignored TERM escalates | real MCP SDK + native process; skip blocks |
| M11 | T1/4 `test_phase2_native_pgid.py::test_stopping_pgid_reuse_has_no_wrong_signal` | STOPPING before TERM/between TERM→KILL mock reuse, wrong group signals=0; real unreaped leader/in-flight drain→reap proof | fake kernel + native macOS; native skip blocks |
| M12 | T6 `test_phase2_live_shutdown.py::test_real_gateway_sigint_sigterm_lifecycle` | real Gateway signal at idle/spawn/active/drain/close; worker finished before root FD close | native macOS loopback REST+MCP; skip blocks |
| M13 | T4/5 `test_phase2_supervisor.py::test_both_output_streams_bounded_and_safe` | stdout, stderr alone & together >48000 chars; invalid UTF-8/reader failure; **each stream ≤48000** + truncation flag, FD/permit return; env/log/error sentinel absent | native process + REST/MCP response/log; skip blocks |
| M14 | T4/6 `test_phase2_live_shutdown.py::test_response_loss_then_new_request` | first marker then lost response, same ticket attempts≤1; next independent request may make second marker; dry-run/denial 0 | live synthetic HTTP/MCP + attempt counter; skip blocks |
| M15 | T7 `test_phase2_full_compatibility` / `bash verify.sh --require-mcp` | pinned Phase 1 F1–F7/N1, Legacy exec/Skill, full native tests, live exec REST/MCP, CI, Manifest each separately report PASS/FAIL/NOT RUN; no skipped mandatory case | macOS + Linux CI, independent review; any missing mandatory => BLOCK |

**Task ownership:** Each test must be written in the owning task **before** implementation; Task 7 aggregates evidence and checks the ledger, not invents the missing test suite. Accepted residual risks (trusted local code, cross-request retries, escaped-session descendants) are documented and not represented by fictitious isolation tests.

## Execution approval boundary

The owner approved **conditional design freeze and creation of this plan**, including the product values above. This is **not approval to implement the plan**. Review the plan before selecting an execution method. Recommended method: **subagent-driven**, because native PGID identity and concurrent signal/reap ownership require isolated reviewers before later tasks depend on them.
