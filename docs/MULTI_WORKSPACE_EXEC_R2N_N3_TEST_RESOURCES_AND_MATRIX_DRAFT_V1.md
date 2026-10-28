# R2-N N3 — proposed T0/T1 resources, cases and authorization gate V1.0

**THIS PR is T0 STATIC DESIGN ONLY. This file proposes future T1 resources; it neither requests that tools run T1 automatically nor records any test as executed.**

REPO: chinanjjohn2012/mac-file-gateway
TASK_ID: MULTI-EXEC-R2N-N3-PRIVATE-STATE-DESIGN-20261028
REVIEW_ROUND: r001
REVIEW_TARGET: N3 mandatory legal, illegal, boundary and abnormal tests plus precise safety budget, fixture provenance, cleanup and user approval requirements.
CONTRACT: PR #93 r002 frozen N2 Base Head 162b5f697ec5bfdb228b6aff351b8ac5cc540e3c; approved PR #92 r001 D0 proposal and N0–N6 plan, operative F1/D0, B92/B93/C93 residual future P3.
CURRENT_AUTHORIZATION: docs/Manifest and T0 static scenario checking only. Not authorized: real filesystem private state, physical owner.lock, real Git subprocess/SDK/HTTP/MCP, native Exec/process/PGID/signal, T1/T2/T3, integration, merge or deploy.

## 1. Risk classes and no-run boundary

| Level | What MAY be planned | Status this round |
| --- | --- | --- |
| T0 | GitHub commit/tree/Manifest verification, independently read code, structured scenario case syntax checks, in-memory-only proposed state transition schedules, no external I/O | Authorized now. Any T0 case that has not been executed is explicitly PLAN_ONLY/NOT_RUN |
| T1 (future safe disposable) | Real local private-FS path/FD owner lock and fsync in an explicitly approved isolated temp root, controlled failure injection that does NOT kill processes, actual loopback REST/official MCP SDK and locally scoped Git/File legal operations | NOT_AUTHORIZED / NOT_RUN. Separate owner grant with exact resource/runner identity required |
| T2 (future high risk) | Real process terminate/kill/signal, crash/power-cut/disk-exhaustion destructive test, VM, simulated abrupt OS death, Native start/reparent/daemon experiments | NOT_AUTHORIZED / NOT_RUN. Requires separately approved isolation, external watchdog and rollback proof |
| T3 (future shared/live) | User Mac/Tunnel, shared build machines, networked Git remotes, production state or service config | NOT_AUTHORIZED / NOT_RUN. No inferred permission from T1 |

**Do not escalate a T0 "fsync error" string into a real fsync test, or an isolated T1 module into macOS signals.** T1 fault tests may inject a deterministic Python OSError into a disposable state adapter in a controlled scenario, but must not kill the parent, deliberately fill shared disk, or use OS process signals. When the same scenario requires an actual crash, classify it T2 and stop until new approval.

## 2. Proposed disposable T1 resource inventory — permission requested LATER, not granted

| Resource | Proposed safe fixture | Strict safeguards | Required original evidence |
| --- | --- | --- | --- |
| Linux x86_64 hosted ephemeral runner (optional) | Per-job temporary work root newly created under runner temp, fully disposable; GitHub code checked out at named fixed Head | No credentials, no shared mount, no production DB or Tunnel, no Native backend/signal, early G05 before source import | Runner OS/Python, exact Head/Tree, G05 preflight, file dev+ino, after-test cleanup and status |
| macOS 15 ARM64 hosted ephemeral runner (if filesystem semantics required) | Separate per-run private control root outside all fixture Workspaces, isolated test-only namespace & witness, temp local repo | No user Mac, no permanent profile change, no launch/killpg/PGID checks, bounded time/disk/FD, no network remotes | Runner image/arch, source + all dependencies, native FD/lock/fsync results and original Job/Log |
| Private state namespace | N3 test-only directory at generated random path; owner.lock and independent lineage at separate pinned roots within disposable job | 0700 directory/0600 regular file, single link, no symlinks, no inherited old store, generated unique namespace and manifest | Before/after inode metadata and exact marker bytes, error codes, temp/fence preservation |
| Workspace root | Distinct disposable root and local Git repository with hard local-only path allowance | N3 private state cannot intersect Workspace, root identity immutable for fixture lifetime, no production files | Root dev+ino, permission/grant maps, old/new source snapshot |
| Legal Git subprocess | Local-only dummy repo with no remotes, hook directory empty, test command restricted to previously approved Git-specific allowlist | Git runs *only* after separate T1 authorization under independent Git grant; never a Native Runner, no arbitrary scripts or remote requests | Correct successful Git/File and failed unauthorized Git/File in SAME service when Exec denied |
| REST + official MCP | Loopback only disposable Gateway fixture, bounded request IDs and no real Exec Apply | F1 non-preview default denial before Worker; never create Native consent/reset API; no external socket/Slack/Feishu | Both transports' sanitized policy snapshot, error codes, cancellation/response evidence |
| Fault injection adapter | Exact reviewed source with deterministic OSError at named precommit/rename/fsync/owner steps | No disk-fill, force-termination, signal or actual crash; exceptions only in disposable test data | Injection phase, intended operation, untouched committed bytes, failure/reboot-state characterization |
| Emergency journal reservation | Budgeted marker bytes and max attempts from exact design | Failure to reserve/confirm means no Native admission; never delete uncertain tombstones to fit budget | Quota counters and persisted conservative failure marker, not a mock PASS |
| Rollback baseline | Read-only digest/metadata copy of original disposable fixture state; no shared or user Mac state | Preserve forensic records after simulated failure; removal only after authorized test close, no auto-reset | Test fixture manifest and explicit cleanup receipt |

T1 still needs a **future user decision identifying** whether Linux only or both platforms, allowed exact transient runner(s), exact work roots, data volume, bounded runtime, externally supervised abort procedure, test command list, and cleanup method. If those details cannot be established from the authorized job environment, T1 stays NOT_RUN and source-stage evidence may be BLOCKED; do not substitute the user's Mac/Tunnel.

## 3. Prospective T0 scenario matrix (none is real FS proof)

The accompanying machine-readable *N3_T0_SCENARIOS_V1.json* captures scenario IDs, modeled preconditions, expected abstract decision, evidence level and contract link. A static validator may check syntax and expected-deny invariants; **that is a contract-table validation, not execution of any N3 state implementation**.

| Family / IDs | Legal assertion | Denied / boundary / abnormal counterexample | Current evidence |
| --- | --- | --- | --- |
| Lineage N3-01..N3-05 | Explicit prospective offline fresh provisioning only after identity+approval | Missing entire namespace; missing both independent roots; copied old consent; rollback; absent witness => DENY | DESIGN_ONLY; FS NOT_RUN |
| Owner N3-06..N3-09 | One pinned owner generation and valid lock | Second owner, owner.lock inode replacement, stale owner token, invalid private FD/ACL => DENY | DESIGN_ONLY; actual lock NOT_RUN |
| Consent N3-10..N3-14 | Mutable scripts/Git content alone keeps consent_epoch stable in a trusted setup | Changed Workspace root, server/Workspace Exec grant, runner/backend config/risk version, revoked/expired consent => FENCE/DENY | DESIGN_ONLY; future true identity NOT_RUN |
| Durable barrier N3-15..N3-20 | Prearmed boot-deny persists as future prestart condition | PREPARED write fail, after rename pre-fsync, after marker unlink, quota/ENOSPC, torn state, prior boot marker => DENY | DESIGN_ONLY; fsync/restart NOT_RUN |
| Survivor/response N3-21..N3-25 | Historical as-of result only after limited terminal qualification | Positive survivor before response; response before PREPARED terminal; response-first then late event; orphan, cancellation => QUARANTINE or historical-only | DESIGN_ONLY; transport/Native NOT_RUN |
| Migration/adjacency N3-26..N3-30 | Preview and independent legal Git/File unaffected while Exec denied | Old v1 RETIRED/S2 Fake promotion, remote reset/client profile, strict→Native fallback, status false available => DENY | DESIGN_ONLY; SDK/Git/File NOT_RUN |

The matrix is **falsifiable proposed behavior**, not a claim that any new test function exists. B/C should invent additional scenarios (for example, rollback of BOTH roots, after-final-marker-unlink fsync failure or extra API field) and may reject a design that cannot be qualified with permitted future resources.

## 4. Actual future T1 test methodology, only after a separate approved new Head

1. **Preflight:** pin exact GitHub Head/Tree and synthetic Merge independently, compare Base and intended diff, G05 verify working checkout tracked/untracked/ignored and import-path sources BEFORE any dependency import; fix installed external package identities and original R004 36-wheel RECORD-limited scope; do not claim RECORD-unlisted imports covered.
2. **Fixture creation:** create only the authorized disposable N3 private root and separate lineage root; prove both outside selected Workspace and state-v1/S2 roots. Record owner permissions, inode/dev, exact filenames, and allowed operation list.
3. **Negative first:** stage before/after fence and checkpoint failures via injection only, malformed JSON/duplicate keys, symlink/hardlink/unknown file, owner conflict and missing namespace, while retaining immutable pre-failure bytes. Test no healthy restart without the required witness, and **never** auto-generate a fresh empty namespace from absence.
4. **Boundaries:** attempt #4096/#4097, per-record bytes exactly 4096 and 4097, total attempt payload exactly 16MiB and +1, separate reserved safety journal full, double-owner, stale owner generation, consent epoch overflow, root change. No unbounded file generation or production disk pressure.
5. **Positive allowed legal paths:** F1 dry_run=true preview and independently authorized File/Git success; unauthorized File/Git refusal; dry_run=false still fails at exec_cleanup_proof_required before Worker regardless of well-formed N3 state; consistent REST and official MCP /info/health.
6. **Fault recovery:** read exact committed state at each injection, model reboot by closing/reopening ONLY the disposable state (no forced process kill); compare against operator-owned snapshot and guard marker. Mark actual crash-powercut proof NOT_RUN / T2. Verify no response commitment on failed durability and no client-ACK invention.
7. **After-test cleanup:** close all verified fixture FDs/locks and loopback transports, archive sanitized logs+hashes, then remove ONLY explicitly approved disposable fixture via identity-checked cleanup. Any unknown process or uncertain file identity stops cleanup and requires operator review; never delete production/Workspace state. There are no Native processes in authorized future T1.

No original current T1 Job exists for this design branch. Historical S2 private-FS or PR90 macOS results are different Head/code/contract scope; evaluate suitability if later needed, do not inherit their PASS.

## 5. Mandatory proposed log and acceptance template

For each actual authorized future test, capture: review target; exact Base/Head/Head Tree/merge parent and merge Tree; named test code Git Blob/SHA256, installed Python/OS arch and external dependencies; fixture root/workspace/lineage inode identities in **private** logs (public PR must redact actual sensitive paths and tokens); exact stage and safe fault type; test command and exit code; expected denied/positive; actual raw sanitized observations; pre/post source integrity and cleanup evidence. Distinguish RED, GREEN, FAIL, SKIP, NOT_RUN, and physical test category.

Scope-gated future success:
- **T0 scenario shape PASS:** checks source of case table only; no journal, owner.lock or OS claims.
- **T0 Fake PASS:** pure-memory event order only; never proves fsync, lifetime owner or response transport.
- **T1 private-FS PASS:** if separately authorized, exact disposable filesystem and SDK/Git/File path only, including true fstat/flock/fsync, but not power-loss/OS Native.
- **T2 Native PASS:** requires separate macOS lifetime-owned at-signal identity proof and approved T2 resources; absent here.
- **N3 FULL CODE REVIEW PASS:** never automatically follows a design PASS or a one-subset T1 result; R10, both roles, original code identity, necessary paths and authority must be satisfied.

## 6. Review-specific P3 closing conditions

B92 P3-01 only closes if future implementation preserves legal real Git-specific subprocess with Exec denied, on separately approved exact T1. B92 P3-02 requires fail-closed whole-namespace-loss plus separately trustworthy lineage or no-autoinit policy; static plan alone is not physical proof. B93 P3-01 requires exact effective grants/backend/runner/expiry binding to authority and per-field T0 negatives; B93 P3-02 requires count+byte limits and separately approved real durability evidence. C93 P3 future Native group witness, managed Worker concurrency and actual response ACK require separate code/OS/transport gates.

## 7. Safety declaration

This design PR performs **NO** T1, T2 or T3; no owner.lock, real file fsync, forced failure, network SDK, Git subprocess, Native start, process-group observation or signal. Every physical test cell is NOT_RUN and NOT_AUTHORIZED. The existing F1 default-deny policy, status and legal Git/File paths are unchanged. Submit the entire fixed design/Manifest/JSON Diff to B and C for independent TARGETED reviews before seeking an implementation/T1 approval.
