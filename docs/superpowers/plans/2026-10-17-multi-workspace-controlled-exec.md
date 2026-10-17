# Multi-Workspace Phase 2 Controlled Exec Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add explicitly authorized per-Workspace Controlled Exec to Multi mode, without weakening existing Phase 1 file APIs or Legacy exec/Local Skills.

**Architecture:** Reuse the existing `CommandRunner` and add a single-owner `ExecSupervisor` that controls spawn, native process-group identity, cancellation, drain and lifetime leases. `WorkspaceService` alone authorizes Workspace execution; HTTP/MCP only adapt strict arguments. No OS sandbox is claimed.

**Tech Stack:** Python 3.11+ for Legacy/file-only; **macOS Python 3.13+ for Phase 2 Multi exec**, subject to a native `WNOWAIT`/PGID qualification gate. Starlette, MCP SDK, Uvicorn, AnyIO, pytest, Python `subprocess`, native macOS process signals, Pipenv and Go.

**Spec:** `docs/superpowers/specs/2026-10-17-multi-workspace-controlled-exec-design.md` at the approved conditional-freeze design base `a7a3f87772ad13545facff48620db68f12ac8ef3`. Third independent design review: **CONDITIONAL**, zero new P findings; not functional PASS.

## Global Constraints

- **Approved 2026-10-17 product values:** extend `schema_version:1`; `paths:["."]` requires explicit administrator authorization; 1 active exec per Workspace and 4 global; TERM grace 2 seconds, separate drain budget 2 seconds; no public remote cancel API; exactly one `Popen` attempt per admitted request, **no dedup between independent requests**.
- **Python version boundary:** existing Legacy and file-only functionality continues to support Python 3.11+. Phase 2 Multi exec on macOS requires Python **3.13+**. This is a capability gate, **not** permission to raise the whole Gateway's minimum version or to execute unsafe fallback `killpg` on unsupported versions. Validate version before listener/exec activation. Document any non-macOS platform support explicitly; do not claim `WNOWAIT` is safe on a platform before native evidence.
- **Review gating:** API and security invariants are conditionally frozen. Exact `WNOWAIT`/unreaped-leader mechanism is *not* qualified. If Task 1 native proof fails, **STOP** Supervisor work and return to design review; no unchecked numeric PGID signalling.
- **Pre-existing safety defects:** D1/P1 Go hook alias and D2/P2 option-path bypass in shared Legacy `CommandRunner` must be fixed, with pytest R1 indirect argv rejection, *before* Multi exec routes are made runnable.
- Multi mode remains disabled by default. Skills are Phase 3 and stay disabled; Legacy single-root API and behaviour must remain compatible except explicitly prohibited dangerous argv.
- No production policy, real credentials, real project scripts, Tunnel, or running Gateway changes; use synthetic roots and processes only.
- Work on a separate feature branch/worktree; one testable task and security review per change. Never merge or deploy without subsequent explicit authorization.
- On Mac, verify SIGINT and SIGTERM with a live synthetic Gateway listener. Existing CI/Manifest success is not Phase 2 functionality proof.

## Review Focus

The five easy-to-miss scenarios are each owned by the tasks below: (1) pytest short-option clusters, `--`, and `@` indirection (Task 2); (2) externally selected Pipenv/pytest config and Go hook alias paths (Task 2); (3) normal leader exit while descendants still hold original group or pipe (Tasks 1/4); (4) cancelled request waiting on a saturated thread pool still starting later (Tasks 3/5); (5) response lost after a side effect then externally retried (Task 6).

## File map / ownership

- `gateway/executor.py` — shared CLI semantic validation and legacy runner entry; avoid duplicating validators.
- `gateway/exec_supervisor.py` (new) — internal tickets, native PGID identity, owned process signalling, bounded dual-stream drain, permits and teardown.
- `gateway/workspaces_config.py` — optional per-Workspace exec policy and Python capability admission.
- `gateway/workspaces.py` — final Workspace authorization, permit ownership, worker leases, close/drain.
- `gateway/multi_fields.py` — strict Multi exec parameters; do not open Local Skill tools.
- `gateway/http_multi.py` / `gateway/mcp_multi.py` — one REST and one MCP adapter to the same Service path.
- `gateway/multi_cli.py` — reliable actual SIGINT/SIGTERM shutdown integration.
- `tests/test_phase2_native_pgid.py`, `tests/test_phase2_argv.py`, `tests/test_phase2_config.py`, `tests/test_phase2_supervisor.py`, `tests/test_phase2_admission.py`, `tests/test_phase2_http_mcp.py`, `tests/test_phase2_live_shutdown.py` (new) — isolated negative and positive controls; corresponding Legacy tests remain.
- `docs/CONTROLLED_EXEC.md`, `README.md`, `MANIFEST.sha256` — truthful scope, security limits and reproducible verification.

---

### Task 1: Qualify native group identity **before** coding Supervisor

**Files:** Create `tests/test_phase2_native_pgid.py`; no production implementation in this task.

**Interfaces:** Produce a documented executable predicate `native_identity_anchor_qualified()` for platform/version acceptance **only as a test/probe outcome**, not a deployed helper. Record `WNOWAIT` observation, unreaped group leader lifetime, sole reap and signal sequencing. Subsequent work must consult its evidence.

- [ ] **Step 1 — write a native macOS isolated probe**: create own leader and original-group descendants; exercise normal exit, last member exit, ignore-TERM, observing before reaping, final reap, and cancelled timing windows; never send signals to unrelated PIDs. Assert the kernel identity required by the design remains reserved until the final signal permission is exhausted.
- [ ] **Step 2 — demonstrate and capture fail-closed controls**: simulate early reap plus numeric PGID reassignment to a different mock owner; all stale tickets must send **zero** signals to that owner. Measure repeating `WNOWAIT` and `WNOHANG` outcomes; distinguish EPERM/ESRCH from identity proof.
- [ ] **Step 3 — verify Python support**: macOS 3.13+/3.14 supports the chosen mechanism; macOS 3.11/3.12 Multi exec **cannot start** while Legacy/file-only still starts. Review `Popen.poll/wait/communicate`, `__del__`, SIGCHLD and other reapers; any premature reap path fails qualification.
- [ ] **Step 4 — run**: `python -m pytest tests/test_phase2_native_pgid.py -q` on supported macOS with synthetic processes; expected all tests pass with process identity/cleanup evidence and no unowned signal, not just a mock-only PASS.
- [ ] **Step 5 — decision gate**: independent reviewer signs off OS identity anchor and support matrix. **If the anchor cannot be proved, stop here, preserve evidence, return to architecture review; Tasks 3–7 must not enable a fallback.** Commit test-only proof on feature branch.

### Task 2: Fix shared CommandRunner CLI validation (D1, D2, R1)

**Files:** Modify `gateway/executor.py`, tests `tests/test_phase2_argv.py` and existing Legacy command tests.

**Interfaces:** Preserve `_validate_command(argv: list[str]) -> str | None` plus `_reject_external_path_args(argv: list[str]) -> None`; shared validation must complete before `CommandRunner.run(..., dry_run=false)` calls Popen.

- [ ] **Step 1 — failing tests**: Go `-exec/--exec`, `toolexec`, `vettool` variants (single/double dash, `=`/split, positions) all rejected, `Popen_attempts=0` in dry/apply; native synthetic Go hook marker does not appear. Safe Go flags still work.
- [ ] **Step 2 — failing pytest/path tests**: `-c../outside/pytest.ini`, `--config-file=../outside/pytest.ini`, Go `-modfile=../outside/go.mod` fail; in-scope config works. `@argsfile` (including after `--`) and remote `-o/--override-ini` modifying `addopts` are rejected. Include `-o=addopts=...`, `-qoaddopts=...`, `-qo=addopts=...`; distinguish real option context from plain positional strings/`--` context. Safe non-addopts override, `-q`, legitimate nodeid and marker text remain accepted.
- [ ] **Step 3 — run failing**: `python -m pytest tests/test_phase2_argv.py -q` and relevant pre-existing Legacy test modules; prove the original weakness is detected without actually launching a malicious external command.
- [ ] **Step 4 — implement minimal semantic parser** for Go and pytest under the shared allowlist, without shell, arbitrary argv rewriting, reading `@` files, or running subprocesses during dry-run; no remote `PYTEST_ADDOPTS` environment inheritance.
- [ ] **Step 5 — verify green + Legacy controls**: `python -m pytest tests/test_phase2_argv.py tests/test_exec_cli.py tests/test_mcp_exec.py -q`; output must show 0 failed, and dedicated native synthetic controls pass. Review dangerous-option compatibility as deliberate security tightening.
- [ ] **Step 6 — commit** shared validator + tests; independent security reviewer confirms D1/P1 and D2/P2 parser cases closed before Multi exec exposure.

### Task 3: Workspace config, capability gate and admission

**Files:** Modify `gateway/workspaces_config.py`, `gateway/workspaces.py`; tests `tests/test_phase2_config.py` and `tests/test_phase2_admission.py`.

**Interfaces:** `parse_workspace_config(config: dict[str, Any]) -> GatewaySettings` keeps old Phase 1 config defaults; add immutable per-workspace exec enabled/scopes/runner policy. `WorkspaceService.require(name: str, operation: str) -> WorkspaceContext` is the final authority; add explicit exec admission/permit interface consumed by Task 4, with 1/Workspace + 4/global slots.

- [ ] **Step 1 — failing config tests**: old JSON keeps exec off; enabled with empty/invalid scope, duplicate JSON keys, bad runner or root conflict rejects before listener/Popen; `paths:["."]` only when explicitly present, Python 3.11/3.12 macOS Multi exec denied while file-only and Legacy remain compatible.
- [ ] **Step 2 — failing authorization tests**: A exec on / B exec off, unknown/blank Workspace, out-of-root cwd, symlinks and scope aliases, runner/Pipfile binding; no cross-root fallback. All denied direct Service calls must have `Popen=0`.
- [ ] **Step 3 — implement parser and immutable policy**, storing explicit per-Workspace settings; keep Workspace root pin identity through last cwd/start handoff; do not use multithreaded `preexec_fn`. Do not treat `write.enabled=false` as OS read-only if exec is enabled.
- [ ] **Step 4 — implement atomic nonqueueing exec admission** before dispatch to sync workers; `STARTING/RUNNING/STOPPING` all occupy quota, fifth concurrent exec returns business busy immediately. Separate bounded exec workers/limiter from Phase 1 file worker capacity.
- [ ] **Step 5 — run** `python -m pytest tests/test_phase2_config.py tests/test_phase2_admission.py -q`; require no process spawn for denied/dry-run, busy without queued work and no starving B file reads.
- [ ] **Step 6 — commit** configuration/admission change with security review of fail-closed defaults.

### Task 4: Implement the sole-owner ExecSupervisor

**Files:** Create `gateway/exec_supervisor.py`; integrate minimally in `gateway/executor.py` and `gateway/workspaces.py`; test `tests/test_phase2_supervisor.py`.

**Interfaces:** Supervisor owns `ticket_id`, state `STARTING|RUNNING|STOPPING|FINISHED`, group leader, original PGID, *qualified* OS identity anchor, pipes and permits. Implement `cancel(ticket_id, reason)`, `close()` and one synchronous execution entry that returns the existing Legacy fields plus safe Multi additions. Do not introduce persistent job IDs or remote cancel API.

- [ ] **Step 1 — failing cancellation/state tests**: cancel before/after Popen, after handle return but before registration, exception in spawn/reader, concurrent close, duplicate cancel, one-tick delayed TERM/KILL; each ticket attempts `Popen` at most once and releases quota/leases exactly once.
- [ ] **Step 2 — failing original-group tests**: leader exits 0 while descendants remain in original group with inherited and redirected pipes; do not mark `FINISHED` or return while managed group is alive; preserve leader exit code and `timed_out=false` after clean-up.
- [ ] **Step 3 — failing STOPPING PGID identity tests**: last original-group member exits between “check→TERM” and “TERM→2s→KILL”; fake kernel reassigns number to unrelated group, stale ticket's `signal_to_new_owner` must equal 0. One owner performs all signals, revokes/delays timers, drains in-flight signals, then unique `wait/reap`; never `Popen.poll/wait/communicate` behind the owner's back.
- [ ] **Step 4 — implement qualified native anchor** (Task 1 prerequisite), sole owner event queue/lock and TERM→2s→KILL sequencing with strict no-unsafe-fallback behaviour. Keep permissions and FD lease until true worker completion; active operation cancellation is not mere cancellation of ASGI waiter.
- [ ] **Step 5 — failing reader tests + implementation**: two streams drained by owner-controlled nonblocking/select or equivalent interruptible bounded polling; independent 2s drain deadline, partial-output flag, no indefinite EOF dependence, no cross-thread `BufferedReader.close`. Escaped `setsid` helper may survive but service reader/FD must be reclaimed.
- [ ] **Step 6 — run** `python -m pytest tests/test_phase2_supervisor.py tests/test_phase2_native_pgid.py -q` and native synthetic process groups; require no owned descendant/FD/permit leaks and exactly one final reap.
- [ ] **Step 7 — commit** Supervisor and integrations; independent lifecycle review before any public endpoint exposure.

### Task 5: Strict REST/MCP adapters and observable cancellation

**Files:** Modify `gateway/multi_fields.py`, `gateway/http_multi.py`, `gateway/mcp_multi.py`, `gateway/workspaces.py`; tests `tests/test_phase2_http_mcp.py`.

**Interfaces:** Multi `POST /run` and MCP `run_command` accept `workspace,cwd,argv,timeout_seconds=60,dry_run=true`. Both call the same WorkspaceService authorized execution entry; Skills remain disabled. REST maps business error to HTTP; MCP preserves a machine-readable business code in SDK tool error response.

- [ ] **Step 1 — failing strict negative tests**: wrong Host/Origin/Bearer, MIME, duplicate JSON keys, surrogate/number overflow, wrong types, unknown fields, missing Workspace; assert business dispatch and `Popen_attempts` both 0. Tools/list includes exec only if some Workspace enabled; B still denied if A enabled.
- [ ] **Step 2 — implement REST route and MCP tool** sharing exact strict input schema and Service method, return bounded/untrusted result, no raw paths/credentials in errors; never enable Local Skill tools.
- [ ] **Step 3 — cancellation tests**: actual asyncio Task.cancel, AnyIO CancelScope, SDK cancellation notification and observable REST disconnect must reach Supervisor, not just cancel threadpool waiter; if network disconnect not observable, enforce command deadline. Test saturated executor pool and cancel while pending, ensuring no late start.
- [ ] **Step 4 — run** `python -m pytest tests/test_phase2_http_mcp.py tests/test_phase2_admission.py -q` plus live HTTP/MCP against synthetic paths; verify positive command in A *and* negative Popen=0 in B.
- [ ] **Step 5 — commit** adapters and independent security review of raw SDK/HTTP admission.

### Task 6: Shutdown, at-most-once and Native macOS lifecycle

**Files:** Modify `gateway/multi_cli.py`, `gateway/workspaces.py`, `gateway/exec_supervisor.py`; test `tests/test_phase2_live_shutdown.py`.

**Interfaces:** `WorkspaceService.close()` first refuses new work, then cancels active execution and waits for actual worker cleanup, finally releases root pins. The CLI/ASGI shutdown path must call it for both SIGINT and SIGTERM, not merely rely on outer `finally`.

- [ ] **Step 1 — write native live signal tests**: idle, Popen STARTING, RUNNING, STOPPING/drain and concurrent close with both SIGINT/SIGTERM on private loopback port; assert termination of managed group, actual worker completed, reader/permit released before root FD.
- [ ] **Step 2 — prove existing SIGTERM issue** on pinned baseline using a synthetic minimal app; then implement minimal reliable signal/lifespan integration without disabling graceful draining or introducing double-close.
- [ ] **Step 3 — request identity tests**: admitted internal ticket → exactly one `Popen_attempt` including spawn failure/response failure/reentry; discard response after a marker write then send a **new** request and verify a second marker is allowed but not described as deduplicated. Keep `idempotentHint=false`.
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

## Execution approval boundary

The owner approved **conditional design freeze and creation of this plan**, including the product values above. This is **not approval to implement the plan**. Review the plan before selecting an execution method. Recommended method: **subagent-driven**, because native PGID identity and concurrent signal/reap ownership require isolated reviewers before later tasks depend on them.
