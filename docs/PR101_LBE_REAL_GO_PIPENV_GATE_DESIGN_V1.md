# PR101 Local Best Effort Real Go and Pipenv: Native Gate and Test Design V1

DESIGN_ID: PR101-LBE-REAL-GO-PIPENV-GATE-V1-CANDIDATE
STATUS: DESIGN_ONLY / NONOPERATIVE / NO_POSITIVE_EXEC_AUTHORITY / NO_NATIVE_T1_AUTHORITY
TASK_ID: MULTI-EXEC-LBE-REAL-GO-PIPENV-20261101
REVIEW_ROUND: r001 (design candidate; distinct from PR101 r015 FULL and r016 SOURCE_ONLY TARGETED)
REVIEW_TARGET: B/C independent TARGETED design review of this candidate contract and bounded test authorization proposal; NOT a request for source-code or integration PASS
PARENT_PR: chinanjjohn2012/mac-file-gateway#101
PARENT_BASE_SHA: 0fc1ae245de7cb582a69162c79c201d15bfaa258
PARENT_HEAD_SHA: ec25c34492912f3a82175fa9c1060e0632814687
PARENT_HEAD_TREE: 3a127bf341a0363b9fa77a570d88436a6fd48696
PARENT_PR98_REVIEWED_DESIGN: Head 07b7497e3d100be70a014d6ecdb5b5db018fc708; design Blob 9e6622401b198138039c692efe91fba1a8d06891; B and C r002 targeted design PASS only
RULESET_ID: ICR-V2.0
HANDOFF_PROTOCOL_ID: GHRH-2.0
EVIDENCE_PROFILE_ID: ETP-V2.0
OWNER_DIRECTION: On 2026-11-01 the owner selected real Local Best Effort Go/Pipenv execution as the desired future product, not Preview-only acceptance.
OWNER_EXACT_D0_EXCEPTION_APPROVAL: NOT_ISSUED
OWNER_REAL_GO_PIPENV_T1_AUTHORIZATION: NOT_ISSUED
OPERATIVE_F1_POLICY: DENY ordinary positive Exec without separately reviewed cleanup proof or an exact newly approved exception.

## 1. Review authority and decision boundary

The operative design and code remain governed by D0 Git Blob 6e25904aed9a62bb0f472b732021c2a7ca3b3bb0, F1 plan 76baeb820c6f8a9b067e45e2dcc42e76453fe5b1, Phase1 trusted-local OS contract b3f2383f292a59fd234269389e5338cd50e334a2, G05 source admission 76c1c2b8a7947e0b305d55c5f550ab59c638b6d1, and owner-limited R004 2ffe5341288e428be5ee5d0fa8d52aea3e9efc93 (36 locked Wheels and installed RECORD-listed file identities only).

PR98 r002 design received separate B/C TARGETED design passes on its exact Head but is NONOPERATIVE. PR101 r015 FULL and r016 TARGETED foreign-source Reviews remain REVIEW_COMPLETE / INSUFFICIENT / BLOCKED. This document reuses PR98 design rather than silently elevating it. The selected product direction is not acceptance of a specific D0 exception, permission to run unreviewed third-party programs, permission for destructive signals, or permission to deploy.

The new future capability intentionally is not F3 complete descendant isolation. It runs operator-trusted project code as the Gateway process user and can affect files, spawn descendants, or use the network unless the host separately constrains it. A command allowlist only selects the initial entrypoint; it is not an OS sandbox. Exact owner signoff must accept that distinction before any public positive Exec change.

## 2. Unchanged mandatory properties

- schema_version:1, existing Legacy, F1 fail-closed, private old-state quarantine/UNKNOWN, and independently authorized File/Git remain unchanged.
- No REST/MCP/direct caller input or local skill may create a new execution permission. All operations must pass the same WorkspaceService.invoke_exec synchronous authorization gate. No hidden bypass for CI or a feature-flag key masquerading as an approved contract.
- schema_version:2 adopts PR98 proposed explicit operator configuration using nonempty workspace exec.paths as the only public Exec grant, optional checked exec.runners inside those paths, and rejecting old server.exec.enabled or workspace.exec.enabled keys rather than reinterpreting them. Preview is nonexecuting by default.
- Before any positive v2 launch, the inherited private ExecStateStore root AND owner.lock must already exist, be exclusively owned, pass existing-only no-follow admission and boot scan, and be healthy. Missing/replaced lock, absent/unsafe root, old PREPARED/RUNNING/UNKNOWN/RETIRED, corrupt/foreign entries or quarantine refuse without creating a new clean state, deleting records, signalling old PIDs, or granting permission.
- One active witnessed original process per Workspace and four total, with a preallocated reaper, bounded pipe readers and a per-instance unavailable latch after ambiguous spawn/owner failure. Cancellation/timeout is a waiter annotation, never proof of process retirement. No retry on missing ACK and no automatic retransmission.
- A witnessed direct child exit yields its actual exit_code but cleanup_proven=false and full_descendant_tree_clean=not_proven. Timeout without witnessed exit yields timed_out=true, exit_code=null, process_may_be_running=true. A dropped transport yields no fictitious successful response. Stop adding new admissions if an owner or pipe reader is lost. No unqualified killpg, process.kill, rollback, cleanup success, or post-restart replay.
- Direct, REST and official MCP must agree on sanitized result/error/status fields, truthful capacity, mode and quarantine indicators. No PID/PGID, credentials or unredacted output. Preserve existing output truncation/redaction and command length limits.

## 3. Two independent approval gates

GATE A — exact-version operative D0 exception for the reviewed schema_version:2 local_best_effort mode. Required inputs: B/C independent TARGETED design verdicts on an identical immutable Git Head/Base/Tree, explicit owner approval citing that version and the accepted no-full-descendant-cleanup/no-rollback limitations, versioned config transition and the old-state denial oracle. Even after GATE A, no automatic production activation, user Mac/Tunnel, destructive experiments or merge/deploy. A code patch must be a separately reviewed new Head and must not silently change legacy/v1 semantics.

GATE B — extension of the currently Python-only disposable-hosted native T1 authorization to REAL Go and Pipenv. Required inputs: an exact new test-code Head/Tree, user-approved Go/Pipenv source lock + generated/embedded inputs, runner image and Python version identity, commands/fixtures, timeout/CPU/memory/output/concurrency budgets, network and filesystem scope, and failure handling. T1 is explicitly NOT_RUN until this exact scope is approved and its preflight succeeds; GATE A does not imply B and GATE B does not imply A.

GATE C — independent new-Head B/C FULL code review, matching actual source and test execution, necessary same-instance REST/MCP/Git/File integration and explicit R10 review. Neither targeted design PASS nor T1 PASS is enough for FULL_CODE_REVIEW_PASS or production release. T2/T3 and any user/shared machine test require their own separate authorization.

## 4. Exact ten external source archives already acquired, not qualified native execution

New source-only original GitHub Run 41275998082, Job 124758176084, auxiliary evidence commit 20dbf73d4d1747912e479267abd06bd23c4dc620, from separate evidence branch: a disposable GitHub-hosted macOS 15 ARM64 runner checked out exact PR101 PRODUCT Head and ran G05; all ten official source archive compressed hashes and Wheel RECORDs passed. Original Artifact 13071167376 has SHA256 5c435ef47200160826fdcf69485c6aa52f01b0c158819cfa54b7d87c914d6fcc and expires 2026-11-08T05:12:33Z. Reviewers B/C independently verified those real original bytes; Go original 15657 regular members, original ordered Go P007 SHA256 e43f516501f4e9b07de05dd470ffdab0b4c2acc086acf1e282d39c40fb00dc6a, and nine P006 member-hash streams all MATCH. This proves byte identity only.

Exact Go input: go1.27.3.darwin-arm64.tar.gz 68196737 bytes SHA256 dd3908cf20959d798c1e06ebe5b72213f0505ce01373b40ce3110975a6cd99c2.

Nine top-level Wheel input versions and archive SHA256:
- pipenv 2026.10.4: 308125623e4d08dfe32936f7259a9ed33c5480baa2c9a291a1ff8a9328eeeb1f
- certifi 2026.10.23: e9b54de76e530bb6cf0ccd036787103acb58fd42ba930ea8bf948ddbaa2f61d1
- packaging 26.3: d7193f7c8e4e93f444fde0262bf90af30e16fa0ad0ad44cb553c87339b23cd1c
- distlib 0.4.4: cf09d55b1e85a89576b036aeb71550bfd68320f3f21761ca329eadadad918638
- filelock 4.2.4: 301241438c57936ef93f4243a94f2559022268bfcf9b375a9a72eb0f8db8358e
- platformdirs 4.11.10: 973c4c082b964958c71588448488d2b14fb253893dfbdb82325a14c84e540e8f
- python-discovery 1.6.1: d43fcdef879fe795352bd13ccf8d185ba5a9f86f36cfcd00529f596e737442b3
- setuptools 84.2.1: ca140b45d5325a9478f880e351484f62fef15f336462e449ca0c03c873d589c2
- virtualenv 21.15.0: 013eb9c340466186ac8923ce920ae05becfa1390fdf3565b7eae0d191a2f4a2e

Four nested Wheel bodies INSIDE locked virtualenv 21.15.0 are additional execution-relevant sources; their 1737 regular files were independently verified as bundled bytes (not as actually loaded):
- pip 26.0.1, 472 files, embedded compressed SHA256 bdb1b08f4274833d62c1aa29e20907365a2ceb950410df15fc9521bad440122b.
- pip 26.2.2, 478 files, embedded compressed SHA256 fd7f4dfa8190e014013b9f08f3e973f4e4c26ffd179a204895533a7254813a70.
- setuptools 82.0.1, 439 files, embedded compressed SHA256 a59e362652f08dcd477c78bb6e7bd9d80a7995bc73ce773050228a348ce2e5bb.
- setuptools 84.2.1, 348 files, embedded compressed SHA256 ca140b45d5325a9478f880e351484f62fef15f336462e449ca0c03c873d589c2.
The virtualenv/seed/wheels/embed version selector for Python 3.13 prefers pip 26.2.2 and setuptools 84.2.1 as static logic; actual seeding is NOT_RUN.

## 5. Proposed executable-source admission design (NOT YET OPERATIVE)

Native source identity is more than an archive hash. A future trusted launcher must produce a provenance witness immediately BEFORE permitted Popen, and compare the actual observed child origin with the fixed test-only input manifest where the environment can support it. An observed PATH hit or initial SHA256 alone is insufficient; source files, installed RECORD members, shebang/interpreter, sys.path and dynamically selected seed code may change the effective code.

The preliminary witness design:
1. Verify exact source archive size, SHA256 and bounded member paths/types before any staging; use no-follow private runner-owned scratch. Reconcile all 15657 Go files with P007 and the four inner Wheels with their RECORD. No install or import occurs during this static stage.
2. In a SEPARATELY AUTHORIZED T1 preparation stage, stage the Go binary/compiler/stdlib under a private fresh directory with recorded executable mode, no symlinks/hardlinks, expected paths, and verify byte identity before and after controlled native T1. Never install into /usr/local, Homebrew, operator cache or project workspaces.
3. Fix native T1 environment explicitly: GOROOT to staged 1.27.3, GOTOOLCHAIN=local, GOPROXY=off, GOSUMDB=off, GOENV=off, GOWORK=off, CGO_ENABLED=0, private GOPATH/GOCACHE/GOMODCACHE/TMPDIR, and no unqualified system Go fallback. Empty module fixtures with pinned go.mod and local sources; make a positive Go compilation network-free only after source is staged. Environment variables alone are NOT an OS network sandbox or proof that a trusted project cannot spawn other programs.
4. In a SEPARATELY AUTHORIZED T1 preparation stage, stage the pinned nine Wheels offline into a private CPython 3.13 environment, verifying top-level and embedded source RECORD identities and installed RECORD-listed files before any Pipenv execution. Record which inner virtualenv seeder Wheels, Python interpreter and site paths were ACTUALLY selected. Do not treat a nine BASE-edges metadata graph as closure for 66 optional requirements, patched pip vendor trees, .pth startup and RECORD-unlisted importables. R004 continues to define what its verifier intentionally DOES NOT assess.
5. The initial test profile may use PIP_NO_INDEX=1, PIPENV_DONT_LOAD_ENV=1, PIPENV_SKIP_LOCK=1, PIPENV_IGNORE_VIRTUALENVS=1 and an explicitly owned PIPENV_VENV_IN_PROJECT=1 scope, with an exact Pipfile/Pipfile.lock and pre-created private venv. No automatic lock, install, sync, index fallback, dotenv loading, external virtualenv or background periodic-update path may be treated as qualified by its mere config name: independently inspect effective source and prove actual behavior before accepting T1.
6. The staged executable path must be absolute/canonical and have no untrusted ancestors; check source, metadata, and working tree identities before launcher spawn and after completion. A standard pathname Popen can have a last-moment pathname race even after hashing; this proposed contract does NOT claim race-free execve unless a separately reviewed execution-handle or immutable-mount mechanism can provide it. The local trusted-user boundary and residual race must be stated.
7. No new external runtime sources may be fetched by the actual Go/Pipenv command. A future native T1 job must independently check observed process/module/environment origin and unexpected network, process and filesystem effects within the authorized fixture. If those cannot be observed safely and conclusively, EVIDENCE_STATUS stays INSUFFICIENT and no runtime-qualified PASS is issued.

Potentially dangerous but legitimate upstream source behaviors already identified by r016 B/C: virtualenv seed acquire.py downloader; periodic_update.py background Popen; pipenv import-time patched-pip exec_module and sys.path modification; setuptools distutils-precedence.pth startup hook; Go toolchain auto-selection, modfetch and cgo. Their presence is NOT proof of malicious code; hashing them is NOT proof of behavior being disabled.

A targeted B/C design review should determine whether the security obligation can be bounded to exact reachable sources/loader and explicit operator-trusted-code residual risk for local_best_effort, rather than asserting unachievable complete semantic safety of every Go stdlib/compiler/member and every optional package. Such a risk-qualified exception is not effective until B/C accepts the exact contract and owner explicitly accepts the residual risk.

## 6. Command and result boundary

Candidate allowed positive operations only after GATE A+B plus applicable reviewed code: Direct Python pytest / -m pytest / -m compileall / canonical relative Python script; configured Pipenv run on those commands from an exact locked Pipfile; Go DIRECT test, vet, build of canonical ./ packages including go build -o and -o= forms with output under an authorized path.

Reject: shell, go run, Python -c/interactive/stdin, Pipenv install/lock/sync, explicit Go tool replacement/overlay/module file/ldflags/gcflags flags, absolute or traversal output, symlink/nonregular/hardlinked leaf, missing output parent, unapproved Workspace cwd, v1-to-v2 implicit migration, stale owner lock, UNKNOWN/quarantine and executable path/source mismatch. The request-level Go output validation is NOT a promise that trusted Go test/compiler code cannot write other files.

No positive command may be advertised as available before a new exact-version approved operative grant. Until then retain gateway/workspaces.py blob d01d13dbb965a46edb47b2a44363ad4fc567dd1b shared early exec_cleanup_proof_required denial, and gateway/lbe_native_launcher.py blob 1e0b78dd098b15bee1129ff40eeea0da40474abc Go/Pipenv pre-Popen refusal. Do not remove these fail-closed layers based only on this document.

## 7. Proposed future disposable native T1 profile, PRECISELY NOT APPROVED

Candidate resources: one GitHub-hosted disposable macOS 15 ARM64 job, exact independently checked Head+Tree+G05 BEFORE interpreter imports or dependencies; no user Mac/Tunnel, no shared Workspace, no production credentials, no shell for Gateway commands, private network-free fixtures and no system toolchain modification.

The historic Python-only hosted T1 profile does NOT cover Go/Pipenv. Proposed minimum operations, only after owner approves a new exact-version source/test envelope:
- Go test ./... positive on a frozen minimal standard-library-only local module, then Go vet ./... and Go build ./cmd/service, including separate -o bin/service positive and path/flag escape negatives. Report actual executable+compiler+stdlib identity, concrete direct-child exit and bounded output.
- Pipenv run python ok.py positive only in a prequalified private venv and authorized canonical project. Confirm exact interpreter, Pipenv original entrypoint, selected embedded seed code, Pipfile/Pipfile.lock, observed sys.path, installed RECORD, and no unapproved automatic download/lock/update. Reject invalid source/path/runner/extras.
- Source-shadow, unexpected PATH tool, missing private owner.lock, quarantined old v1 record, invalid Workspace, prohibited Go flags/build output, busy, ambiguous Popen, and unqualified source: all deny WITHOUT invoking unqualified foreign code. These negative T0 or otherwise strictly bounded tests must not create a foreign child.
- Same-instance shared direct/REST/official MCP and independently granted File/Git regression only with a separate approved T1/integration envelope and original raw logs. Never treat a transport HTTP status or CI check as a witnessed child exit.

Budget candidate for explicit owner decision (NOT an authorization): <=20 minute single hosted job, <=120 seconds per clearly bounded expected-to-exit original Go/Pipenv command (a proposed change from previous 5-second Python-only fixture), <=1 active original child/Workspace, <=4/service, <=48000 output characters per stream, no subprocess group kill, no OS PID/PGID signals, no intentional retained descendants or physical timeout/cancel/survivor experiments. Do not start native T1 if cold compile/venv seeding is not qualified to finish within the approved budget. If a timeout leaves an unowned child or background effect, report BLOCKED/uncertain and do not spawn again. Hosted runner teardown is not a descendant-cleanup certificate.

T2 (destructive termination, signal/unknown PID, crash/restart/actual survivor), T3 (shared/user Mac, Tunnel or production) and any stronger isolation claim are OUT OF SCOPE until distinct resource-specific authorization. A permitted T1 does not imply T2/T3.

## 8. Implementable milestone and R03-R08 test contract

M0: B Standards and C Spec independently review this exact candidate Head/Base/Tree and the exact PR98 design; owner explicitly accepts the fixed D0 local_best_effort exception and accepted host-code/descendant risks. Until then only design/static T0 is permitted.

M1: Source/loader input contract and source identity preflight in separate safe, explicitly reviewed implementation snapshot; no activation. Negative T0 tests for mismatched expected source, symlinks and tampered installed RECORD, nested Wheel selection, absent or corrupt old root/lock, missing executable, Go auto-fetch/virtualenv background branch. Maintain current deny-only in all public entrypoints.

M2: After separately authorized T1, stage pinned Go and Pipenv environments on disposable runner, run the small bounded native matrix, preserve original logs, independently qualify actual loaded inputs and exit/results. If any source escapes accepted closure, deny and report; no automatic risk waiver. No T2 signal tests.

M3: Only after M0 design exact-version approval plus reviewed implementation and necessary evidence, implement a single narrow versioned schema-v2 local_best_effort positive gate and accurate status, keeping v1/Legacy/UNKNOWN intact. A real direct child success is not full-descendant proof. Freeze a new implementation Head/Tree and request both role reviews independently, not by reusing PR98/PR101 PASS.

M4: Independently authorize and execute same-instance REST/MCP/direct, File/Git and relevant security and integration matrix, with separate actual Head and synthetic Merge identities; B/C FULL code reviews and R10 eligibility are separate. Release/merge/deploy require new explicit action, never inferred.

Mandatory positive/negative/boundary/exception oracles:
- identity and state: valid old-state owner+canonical v2 paths -> eligible ONLY after authority; missing lock, quarantined record, old v1 flags, source shadow -> DENY before spawn;
- commands: positive simple Go/Pipenv original command with witnessed output; wrong runner, go run, prohibited flags, unsafe -o, network origin drift -> DENY;
- lifecycle: original child completed -> record real exit; waiter timed out/cancelled -> uncertainty, no slot release while direct child live; ambiguous spawn/reader fault -> unavailable latch; NEVER claim descendant retirement;
- transport: same direct/REST/MCP response and status; no fabricated ACK/retry; preserve independent Git/File controls;
- rollback/UNKNOWN: no auto reset, no replay, no signals, no data deletion; future destructive tests require separate T2.

## 9. Explicit readiness decision

CURRENT B/C TARGETED SOURCE REVIEW: r016 REVIEW_COMPLETE / INSUFFICIENT / BLOCKED, with fully verified ten external source-byte identities; B/C did not issue full semantic/loaded native execution security PASS.
CURRENT FULL CODE REVIEW: NOT_ISSUED (PR101 r015 FULL BLOCKED).
CURRENT NATIVE GO/PIPENV T1: NOT_RUN / NOT_AUTHORIZED.
CURRENT INTEGRATION: NOT_TESTED.
CURRENT D0 EXCEPTION: NOT_APPROVED / NONOPERATIVE.
CURRENT R10: BLOCKED.
CURRENT USER GOAL: REAL LOCAL_BEST_EFFORT GO/PIPENV (DIRECTION_CONFIRMED ONLY).

Required decisions after independent design review: owner must accept or reject the exact source-controlled weaker mode and its explicit no-descendant-cleanup/non-sandbox risk; separately authorize or reject the proposed 120-second/20-minute T1 execution profile and exact third-party source/loader inputs. B and C must each independently report deficiencies; A cannot declare owner approval, B/C PASS, production safety or integration.

This document, its branch and any resulting design PR are not a positive Exec feature, a D0 exception, a live instance configuration change, or a license to execute Go/Pipenv.
