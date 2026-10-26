# F3-D0 — Ordinary Multi-Workspace Exec: complete-descendant containment feasibility

**STATUS: DESIGN CANDIDATE / FEASIBILITY NOT YET PROVEN / POSITIVE EXEC NO-GO.**
**TASK_ID:** `MULTI-EXEC-F3-D0-FEASIBILITY-20261026`
**REVIEW_ROUND:** `r001` (new independent design review only).
**REVIEW_TARGET:** F3 real `dry_run=false` safety architecture and falsifiable feasibility gates; no product/runtime implementation.
**SOURCE_PR:** `chinanjjohn2012/mac-file-gateway#76`, exact inherited source Head `0fc1ae245de7cb582a69162c79c201d15bfaa258`, Tree `e05777c0bc6eea0b375a6347602b99c68024b3b6`; base this design PR on the **frozen #76 review branch**, not the moving `release/ms1`.
**EFFECTIVE_RULES:** Original Independent Code Review Rules V1.0 / GitHub Review Handoff V1.0. ICR/GHRH/ETP V2.0 have NOT been confirmed effective for new rounds. Historical GH-R01R10 remote-equivalence approval has separate A/B/C Project-source activation criteria.
**ORIGINAL AUTHORITY:** Inherited `docs/MULTI_WORKSPACE_EXEC_RECOVERY_D0_DESIGN.md` (blob `6e25904aed9a62bb0f472b732021c2a7ca3b3bb0`, especially §§0.1, 0.4, 1–7), `docs/MULTI_WORKSPACE_EXEC_PRODUCTION_FIRST_IMPLEMENTATION_PLAN.md` (blob `76baeb820c6f8a9b067e45e2dcc42e76453fe5b1`), `docs/PHASE1_LOCAL_TRUST_BOUNDARY.md` (blob `b3f2383f292a59fd234269389e5338cd50e334a2`), and the #76 F1/G05 integrated RC document (blob `2ffe5341288e428be5ee5d0fa8d52aea3e9efc93`).
**RELATED EVIDENCE:** #76 r004 B/C FULL `BLOCKED`, r005 B/C `TARGETED_REVIEW_PASS` only for source-locked wheel + installed RECORD-listed-file hashes. Neither outcome authorizes F3 positive Exec.
**USER GOAL:** M1 at T+24h seeks true ordinary Multi real direct/Pipenv apply with existing Legacy usability and approved safety guarantees; M2 at T+120h seeks full F3 cleanup/restart verification and independent reviews. These are **decision deadlines**, not authority to lower the F3 security contract. The F3 design feasibility decision is separately targeted for the first day.

## 1. Directly observed baseline and immutable negative gate

- `gateway/workspaces.py:WorkspaceService.invoke_exec` at inherited Head checks global and Workspace authorization, durable state health, and rejects every ordinary `dry_run=false` with `exec_cleanup_proof_required` **before** Worker admission, `CommandRunner.run`, `Popen`, or `ExecStateStore.prepare`. Direct, real REST and official MCP use this same worker decision. Leave this gate unchanged throughout F3 design and until a *new*, independently reviewed positive-proof implementation exists.
- `gateway/executor.py:CommandRunner.run` already contains argv/allowlist/cwd policy, direct/Pipenv selection, 1–300 s timeout, capped/redacted-ish output and a POSIX `start_new_session=True` process. On timeout it tries `killpg(process.pid, SIGKILL)` and waits for **its direct process**. It does NOT prove exit of grandchildren that call `setsid`, reparent, double-fork, or otherwise escape that group.
- `gateway/exec_state.py:ExecStateStore` already has a private owner lock and an atomic/fsynced `PREPARED` record operation plus `UNKNOWN` quarantine; `workspaces.py` provides one-per-Workspace/four-per-instance slots. These are **pieces**, not an integrated F3 positive lifecycle.
- The current documented trust model treats authorized workspace code as executing with the Gateway user's OS privileges and does not claim an OS sandbox, same-UID adversarial tamper prevention, or revocation of past file/network side effects.
- F1/G05 Linux/macOS CI proves deny-only and adjacent File/Git success; it **does not run a normal positive F3 Exec**, any full-descendant cleanup native probe, or real user Mac/Tunnel. Do not reuse those GREEN results as positive-F3 evidence.

## 2. Threat model / required outcome (no weaker Legacy parity shortcut)

F3 should guarantee **for every OS process started within one approved Exec attempt** that no member of that attempt's contained execution domain can continue executing after an authenticated, completed cleanup and durable F3 retirement. This includes descendants that become orphans, call `setsid` or `setpgid`, use `posix_spawn` or fork+exec, double-fork/daemonize, or exit and reparent while siblings continue. A count of visible PIDs, absent original PGID, quiet heartbeat, leader exit, EOF, returned exit_code, or successful `killpg` is NOT an adequate containment proof.

The guarantee must be **bounded and stated precisely**: processes admitted and constrained in an OS-enforced execution domain, not arbitrary external processes that the command requests via network/IPC or any host service unless those operations are independently blocked or included in the verified domain. It cannot retroactively undo filesystem writes, network transmissions, Git operations or other external side effects already performed. Such already-completed side effects remain subject to normal user authorization and recovery semantics.

The system MUST default to deny if it cannot prove an OS-enforced, irrevocable domain boundary **before spawn**, establish an unforgeable identity/ownership binding, perform a bounded cleanup/termination, and obtain direct evidence that the whole bound domain has terminated. A routine PID/PGID reused since a crash may NEVER be signalled as a recovery shortcut.

## 3. Option appraisal — feasibility hypotheses, not approved controls

| Candidate | What existing evidence supports | Limitation / design disposition |
| --- | --- | --- |
| H0. Legacy `killpg`, leader wait, heartbeat, `ps` ancestry snapshot or recursive PID killing | The repository actually implements group-only cleanup and direct-leader waiting. | **REJECT for F3 proof.** Escaped/reparented descendants and PID/PGID reuse make the completeness claim unprovable from these observations. Keep useful group cleanup as a secondary best effort ONLY. |
| H1. Per-command `launchd` job / Job label and launchctl stop | Apple documents management of launched Agents/Daemons and the managed job. | **NOT QUALIFIED.** The reviewed Apple material does not guarantee transitive descendant containment of double-fork/setsid escapees or their cleanup after manager crash. No launchd-only positive gate until a separate verified, supported contract proves both properties. |
| H2. Host sandbox or process-coalition tracker | May limit some actions or offer observability under specific OS APIs. | **NOT QUALIFIED.** No approved public mechanism has been identified here that proves irrevocable whole-tree confinement, anti-escape and cleanup for arbitrary signed/unsigned direct/Pipenv/Go/Python tools on supported macOS. Deprecated `sandbox-exec`, private OS APIs, and polling cannot be used as proof by assumption. |
| H3. Per-attempt OS-enforced isolated execution domain (candidate VM boundary) | Apple Virtualization.framework offers management of macOS/Linux VMs; its VZVirtualMachine exposes start, stop and state. Whole guest process membership is a plausible bounded containment domain for a proof experiment. | **FEASIBILITY CANDIDATE ONLY.** Independently prove VM identity, complete guest shutdown, absence of uncontained host child processes, no guest-to-host spawn broker, handling of abrupt host failure and native macOS direct/Pipenv compatibility. A Linux guest is not equivalent to executing macOS binaries on the user's Mac. VM setup, privilege/entitlement, image, shared files, network and startup cost may make M1 or the product parity target unattainable. |

**External platform references (informative; not pinned build inputs):**
- Apple Virtualization framework: https://developer.apple.com/documentation/virtualization
- Apple `VZVirtualMachine` API: https://developer.apple.com/documentation/virtualization/vzvirtualmachine
- Apple `requestStop()` explicitly only **requests** shutdown and does not show completion: https://developer.apple.com/documentation/virtualization/vzvirtualmachine/requeststop%28%29
- Apple launchd Service Management: https://developer.apple.com/documentation/servicemanagement/
- Apple Containerization is a separate Linux VM-per-container project with macOS 26 and Xcode 26 requirements in its published documentation, NOT proof of a macOS-15 host/Pipenv drop-in solution: https://github.com/apple/containerization

**F3 design recommendation for independent review:** prioritize investigating an enforceable per-attempt domain with a trustworthy, bounded *domain-termination* primitive, such as a VM where guest processes cannot escape. **Do not choose H3 as a shipping design yet**. First prove native macOS compatibility and kernel-enforced containment on approved disposable test resources. If no mechanism meets all required conditions, design decision must be `NO-GO_FOR_POSITIVE_EXEC`, while F1 stays safely deny-only.

## 4. Positive-proof architecture: normative proposal conditional on H3 or another verified domain

### 4.1 Proof identity, provenance and admission

A future `FullTreeQualification` is an internal non-client-controlled capability, NOT `server.exec.enabled` or `workspace.exec.enabled`, a test grant, environment variable, request header, CLI value, `PYTEST_CURRENT_TEST`, or a saved bare PID. It binds:
1. supported OS/build/version and verified containment backend binary/API/config identity;
2. exclusive private host state root / owner.lock and gateway process-instance identity;
3. specifically authorized Workspace root dev/ino and effective command policy;
4. unique attempt ID, lifetime, concrete OS-enforced domain identity, and supervised domain ownership;
5. verified source/guest image and native direct/Pipenv executable compatibility;
6. stable proof semantics at admission **and** finalization, with fail-closed treatment of any proof drift.

Qualification may only exist when independent design/code/native verification and explicit positive-Exec authorization for that bounded backend have occurred. No test-only group grant or legacy runner proof can be silently promoted to it. Initial implementation must keep `completion_capability=none` until that separate review is signed off.

### 4.2 Durable ordering, ownership and state

- Validate both opt-ins, Workspace ID, argv/allowlist, cwd, runner mode, state-root FD trust, owner.lock and current global quarantine; verify backend identity/capability before any positive admission. Keep error precedence `exec_disabled` > `exec_quarantined` > `exec_state_unavailable` > `exec_cleanup_proof_required` > `busy` (only when qualified).
- Under the synchronous Worker lease (one Workspace/four instance), durably fsync a unique `PREPARED` intent **before** any backend/guest command can start. Fail closed on any write, fsync, rename or directory-fsync failure.
- Allocate/launch the verified domain **only after** PREPARED; bind its authenticated domain handle and identity before any guest execution. If spawn/identity is ambiguous, persist `UNKNOWN`, quarantine globally, and do not send a clean result.
- Store bounded non-secret state: attempt ID, Workspace identity, backend/version, domain opaque ID/instance generation and observation phase; never raw argv, tokens, stdout/stderr, env or a bare PID/PGID as authority. Define `RUNNING` and `CLEANUP_PENDING` records without ever confusing them with permission to retry a command.
- On normal completion, timeout, cancellation, network disconnect, shutdown or cleanup exception, **stop the entire domain** within a bounded deadline and independently verify final domain termination. The command's exit code is insufficient. Only after success may it transition to a durable `RETIRED` with `cleanup_scope=full_bound_domain` and verified `full_descendant_tree_clean=proven` (subject to independent review). If any step is unclear, write or preserve `UNKNOWN`, latch instance-wide `QUARANTINED`, retain forensic evidence, and do not release a success response.
- A client cancellation or lost response **does not** free a Worker lease or cause automatic replay. The direct/MCP/REST/real-Tunnel routes must share one backend gate; File/Git independently authorized operations remain functional even when Exec is quarantined.
- On boot after crash, scan private state before accepting Exec. Any unresolved `PREPARED`/`RUNNING`/`CLEANUP_PENDING`/`UNKNOWN` or ambiguous state/VM-owner identity quarantines **all** Exec. A restart may NOT signal any stale PID, guess a domain handle or auto-remove quarantine just because a process cannot be seen. An operator-only separately reviewed recovery process may be needed.
- A guest VM stop request is **not** a terminal cleanup observation. The backend must supply a directly checked, bounded **terminated domain state** with no remaining guest execution and no unbounded external helper. The claim must be independently tested on the actual supported macOS ARM64 environment.

### 4.3 Compatibility and unintended privilege paths

Native macOS `direct` and `pipenv` semantics are part of M1: installed project tools, Pipfile resolution, command allowlist, relative cwd, path authorization, output cap, timeout and exit code must work without silently substituting a Linux guest. Any guest file/host mount or external broker must be explicitly authorized and must not give guest code an unreviewed method to start host processes outside the bound domain. Network/IPC to services with side effects and host filesystem writes are not rollback-safe by default; record scope and acceptance risks. Do not market the Exec Workspace path allowlist as a full OS filesystem sandbox.

### 4.4 Existing source integration points (future changes, NOT in this design PR)

- `gateway/workspaces.py:invoke_exec`: add a sealed proof-capability branch **only** after design/B/C authorization; keep existing disabled/quarantined/unavailable precedence; never enable ordinary Exec through a configurable proof flag.
- `gateway/executor.py:CommandRunner`: reuse existing argv validation/preview/direct-Pipenv formatter and output policy, but do not call unrestricted host `Popen` for a supposedly contained attempt. A supervisor/backend interface must perform controlled launch and termination.
- `gateway/exec_state.py`: new vetted state/schema and full-domain proof transitions (subject to file format/migration and owner-lock review); preserve old `UNKNOWN`/group-only `RETIRED` semantics and explicit quarantine. No blind schema upgrade or cleansing.
- `gateway/http_multi.py`, `gateway/mcp_multi.py`, `gateway/workspaces_config.py`: preserve typed input, policy and public transport contracts; do not add an untrusted `cleanup_proof=true` field.
- `tests/`, `.github/workflows/`: new separately gated native F3 test matrix; no accidental execution in prior deny-only F1/G05 CI.

## 5. Feasibility and authorization decision gates

| Gate | Required affirmative proof | Current status |
| --- | --- | --- |
| D1 — bound domain | Supported macOS OS-enforced membership includes `setsid`, double-fork, reparented grandchildren, spawn and indirect legitimate tools, with no escape to uncontrolled host execution | `NOT_PROVEN` |
| D2 — safe teardown | Authenticated domain handle, bounded stop, independently observed absence of whole domain, no PID reuse or user-global signals | `NOT_PROVEN` |
| D3 — crash/restart | PREPARED-before-launch, exact identity across crash windows, no blind signal, unresolved intent quarantines, operator recovery specification | `DESIGN_ONLY` |
| D4 — user functionality | native macOS ARM64 direct/Pipenv, Python/Go/pytest, 1–300s timeout, actual REST/MCP/Worker slots and cancellation work within domain | `NOT_RUN` |
| D5 — deployment boundary | supported macOS version, signed/authorized helper or VM entitlement, image supply chain, mount/IPC/network policy, operational rollback and upgrade path | `NOT_PROVEN` |
| D6 — approvals | B/C independently review design then new product Head/code/original T0/T1/T2 evidence and actual authorized integration | `NOT_ISSUED` |

**Decision logic**: if any D1–D3 lacks a defensible OS-backed mechanism, `DESIGN_FEASIBILITY=BLOCKED`, `M1_REAL_EXEC=NO_GO`. If only D4/D5 remain, label `PROTOTYPE_ONLY` until platform compatibility and deployment are proven. B/C design PASS (if obtained) means only *design accepted for bounded investigation*, NEVER product positive-Exec authorization. No proof can be inferred from signed reviews, test count or CI green alone.

## 6. One-day design checkpoint / time interpretation

At a user-approved start T0, target 0–4h frozen source/OS API feasibility comparison, 4–10h design proposal, 10–14h independent B/C handoff and counterexample matrix, 14–22h separate independent reviewer actions, 22–24h A records the real GO/NO-GO outcome and any remaining blockers. These are human-operated *decision checkpoints*, not an automatically running asynchronous agent or a guarantee of approval. Do not convert an unsigned or blocked design into a success when time expires. F3 implementation and high-risk native testing require a separate explicit decision and authorization.

**Current first-pass result:** documented F3 requirements and actual host Runner prove **H0 invalid**; H1/H2 lack suitable proven containment; H3 is a defensible *research candidate* but is **not yet validated for ordinary macOS host direct/Pipenv parity**. Therefore `F3_POSITIVE_EXEC_NO_GO` now, `F3_DESIGN_REVIEW=READY_FOR_INDEPENDENT_ASSESSMENT` once this document is frozen on an actual PR. No real Exec, Native C/C3, process signalling, production config, user Mac or Tunnel was run during this desk assessment.
