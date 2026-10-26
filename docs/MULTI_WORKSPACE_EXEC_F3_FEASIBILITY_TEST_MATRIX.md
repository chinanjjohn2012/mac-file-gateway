# F3-D0 — adversarial review and feasibility evidence matrix

**Status:** review-input proposal only; ZERO real F3 apply or host process-signalling experiments run at this design stage.
**Primary input:** `docs/MULTI_WORKSPACE_EXEC_F3_FEASIBILITY_DESIGN.md`. `TASK_ID=MULTI-EXEC-F3-D0-FEASIBILITY-20261026`.
**Design acceptance** must remain separate from subsequent `F3_CODE_PASS`, `FULL_CODE_REVIEW_PASS`, `INTEGRATION_PASS`, `M1/M2_GO` and permission to execute actual commands.
**Reviewers:** B Standards and C Spec each independently gather original evidence, design own counterexamples, bind same Base/Head/Tree, and publish distinct native GitHub `COMMENT` Reviews. A is not an independent signatory.

## A. Test and evidence ownership

| Class | Permitted now? | Evidence / consequence |
| --- | --- | --- |
| T0 static design/source read, formal negative reasoning, source identity | YES | A static conclusion proves only what the code or platform documents say; not an OS containment mechanism's behavior. |
| T1 isolated, non-destructive mocks/fakes, no spawned monitored group or signals | Can be separately planned within safe authorization | No claim of native cleanup or crash recovery until actual native acceptance. |
| T2 disposable native macOS ARM64 real child trees, forced termination, simulated Gateway kill/restart, VM teardown | **NOT_AUTHORIZED by this design task** | Must separately fix runner identity, exact disposable fixture paths, timeout/watchdog, safe signal destination, recovery and cleanup plan; get explicit risk approval before running. |
| T3 user real Mac/Gateway/Tunnel, shared OS process signalling, production change | **NOT_AUTHORIZED** | Requires separate targeted authorization; not a means of passing a design-only review. |

## B. Full contract checks — B/C should add independently conceived counterexamples

| ID | Type | Case and expected property | Current evidence / gap |
| --- | --- | --- | --- |
| F3-C01 | LEGAL | Both flags enabled; Workspace authorized; valid direct Python/Go command completes with true exit/output and verified whole-domain termination. | `NOT_RUN` / no qualified host backend. |
| F3-C02 | LEGAL | Same valid command through real REST and official SDK MCP; Pipenv real command with correct Pipfile, cwd and env. | `NOT_RUN` for F3; old #57 native linked-child evidence is partial only. |
| F3-C03 | NEGATIVE | Global disabled, Workspace disabled, bad cwd/path/argv, client-supplied `proof`, wrong Workspace and unsafe config are rejected before spawn. | Existing F1 code gives a partial denied-path precedent, not F3 positive proof. |
| F3-C04 | NEGATIVE | No qualified containment/backend means `exec_cleanup_proof_required` with zero `Popen`, `PREPARED`, slot or test grant. | Existing #76 F1 original CI is same-Head negative-only; future F3 must preserve. |
| F3-C05 | BOUNDARY | One Worker/Workspace and four instance-wide; fifth is busy only if backend proved; unrelated workspace read stays available. | State/Worker code exists but positive F3 concurrency `NOT_RUN`. |
| F3-C06 | ADVERSARIAL | Guest child calls `setsid`, `setpgid`, double-fork then parents exit; prove all descendants remain bound and cannot outlive authenticated domain teardown. | **CRITICAL D1** `NOT_RUN`; group-only observation insufficient. |
| F3-C07 | ADVERSARIAL | Fork/exec variants, `posix_spawn`, daemonization, reparenting, fast-exiting intermediates, long-lived grandchildren; no unowned host process. | **CRITICAL D1** `NOT_RUN`. |
| F3-C08 | ADVERSARIAL | Guest attempts host IPC/service launch, access to unreviewed host process spawner, external network-based task launch; containment promise limited/deny. | **CRITICAL D1/D5** `NOT_RUN`; external side effects distinguished. |
| F3-C09 | TIMEOUT | 1–300s deadline: timeout triggers bounded domain stop; all guest descendants gone; exit_code/timed_out honest, bounded logs and readers. | **CRITICAL D2** `NOT_RUN`; existing `killpg` inadequate. |
| F3-C10 | CANCEL | REST/MCP waiter cancellation, disconnect and Gateway graceful shutdown keep lease and durable identity, no re-execution after lost response. | F1/old #57 are supporting partial evidence; positive F3 `NOT_RUN`. |
| F3-C11 | FAULT | PREPARED write, fsync, rename, dir-fsync fault before launch: zero launch; no apparently clean result. | Existing store primitives present; positive backend integration `NOT_RUN`. |
| F3-C12 | CRASH | Gateway crash after PREPARED/before allocation, after domain allocation/before launch, after launch/before recording handle, during cleanup, after cleanup/before final fsync, after retirement/before response. | **CRITICAL D3** `NOT_RUN`; unresolved records quarantine. |
| F3-C13 | IDENTITY | PID/PGID reuse, stale domain ID/VM handle, OS update, missing backend owner, same-name different domain, wrong Workspace dev/ino: never signal unrelated process or retire. | **CRITICAL D2/D3** `NOT_RUN`. |
| F3-C14 | FAULT | Domain-stop API failure, guest refusal to halt, VM crash, watchdog timeout, helper crash, guest escape proof failure: durable `UNKNOWN` and instance-wide Exec quarantine, no clean response. | **CRITICAL D2/D3** `NOT_RUN`. |
| F3-C15 | RESTART | Unresolved PREPARED/RUNNING/UNKNOWN, corrupt/symlink/hardlinked state, owner.lock contention, copied old test-only RETIRED cannot auto-unquarantine. | Existing F1 state negative evidence partial; F3 integration `NOT_RUN`. |
| F3-C16 | ADJACENT | Exec denied/quarantined while same-instance authorized real Git apply and File Write still succeed, unauthorized variants still deny; Legacy unaffected. | #76 negative + Git/File targeted CI is precedent, F3 modification impacts to be retested. |
| F3-C17 | SECURITY | Ability to reset quota, record retention, truncate stdout, fault-induced in-flight serialization and 4 active workers; no state loss or process escape. | Full F3 contract `NOT_RUN`. |
| F3-C18 | PROVENANCE | Native OS/backend source and VM image/entitlements/signed helper identity fixed, executed Head/Base/Tree & external artifacts proved, no unexpected import/source pollution. | G05+wheel/RECORD bounded proof exists for F1 CI only; F3 external backend unverified. |
| F3-C19 | PARITY | Direct/Pipenv selected based on project, same argv allowlist, Python/Go/pytest and native executable behavior, correct cwd and Workspace isolation, no unauthorized host-mount access. | **CRITICAL D4** `NOT_RUN`; Linux VM is not macOS host parity. |
| F3-C20 | INTEGRATION | Real macOS ARM64 REST/MCP/Tunnel after code review, upgrade/rollback, status parity and recovery, exact execution identity. | `NOT_AUTHORIZED` / `NOT_TESTED`. |

## C. Review checkpoints and acceptance levels

1. **F3-D0 design r001:** freeze design-only PR Base/Head/Tree; read D0 + product/OS sources; independently decide whether each candidate H0–H3 has a plausible proof mechanism, whether D1–D6 are falsifiable and whether positive Exec remains disabled. A `READY_FOR_REVIEW` is only a handoff, not B/C signoff.
2. **Feasibility:** reviewers may return design `TARGETED_REVIEW_PASS` for a safe *investigation plan* while `F3_FEASIBILITY=NOT_PROVEN`; do not confuse this with a tested containment design. If D1–D3 cannot be demonstrated, positive-Exec milestone must be `NO_GO`.
3. **Native proof:** only after separate T2 authorization: collect original macOS 15 ARM64/target OS code identity, actual kernel/VM domain boundaries, detached-grandchild cases, real timeout/crash/restart teardown and negative outcomes. Record all `NOT_RUN` exactly.
4. **Product implementation:** new separate Draft PR/review round; new full code/source/CI and independent B/C review; no reuse of F1/G05 targeted PASS for F3. Complete R10 is additional to design PASS.
5. **Integration:** real user Mac/Tunnel and release/rollback only on separate authorization. No automatic merge, deploy, tag, production config, Native C/C3, or UNKNOWN auto-repair.

## D. Remaining research questions that block unconditional M1

- Does the candidate containment backend cryptographically/OS-bind **all** actual descendant processes without allowing any to execute on the host outside the domain?
- What exact public macOS primitive proves *terminated domain* rather than merely `requestStop` accepted, and can that evidence survive host supervisor crash?
- Can a macOS 15 ARM64 supported environment run a compatible macOS guest (or another solution) while keeping native direct/Pipenv/Go functionality, Workspace semantics, installation/runtime footprint and performance?
- What happens if host isolation or helper ownership fails while an attempt's PREPARED exists? How is the evidence retained without blind PID/PGID signalling?
- Which exact T2 disposable native fixtures and watchdog limits are separately approved, and what original CI Job or isolated Mac evidence will independently substantiate the claim?

**Until all blocking questions have documented, separately reviewed answers, `F3_POSITIVE_EXEC=NO_GO`.**
