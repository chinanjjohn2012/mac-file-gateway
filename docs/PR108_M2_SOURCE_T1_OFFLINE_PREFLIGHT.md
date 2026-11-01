# M2 SOURCE_TOOLCHAIN_T1 - Nonoperative test preparation and offline precontact gate (T0)

STATUS: DESIGN_AND_STATIC_T0_ONLY / NATIVE_GO_PIPENV_NOT_RUN / NETWORK_ENFORCEMENT_NOT_ATTESTED / NO_PRODUCT_EXEC_AUTHORITY.

TASK_ID: MULTI-EXEC-LBE-M2-SOURCE-T1-OFFLINE-PREFLIGHT-20261102.

AUTHORITIES: PR #102 r002 reviewed nonoperative design GitBlob 7db3b77aadca8b0c284e28fa5ee64e315e9275d2 sections 3, 5.1-5.5, 7-9. Owner Gate A risk-consent PR #102 comment 6559619893 and conditional standalone SOURCE_TOOLCHAIN_T1 Gate B authorization PR #102 comment 6560708487. Neither grants a network-control implementation, a qualified external loader, product runtime execution or deployment. PR #107 r002 B/C TARGETED Head 7feb57a8374ca3b480c7b9157f19d89c56e414c4 / Tree cc6ce530acf4f9e7b4229f0ff4cc720e58a63dec is a predecessor STATIC source/environment input only.

Operative D0 GitBlob 6e25904aed9a62bb0f472b732021c2a7ca3b3bb0, F1 plan 76baeb820c6f8a9b067e45e2dcc42e76453fe5b1, Phase1 b3f2383f292a59fd234269389e5338cd50e334a2, G05 76c1c2b8a7947e0b305d55c5f550ab59c638b6d1 and R004 2ffe5341288e428be5ee5d0fa8d52aea3e9efc93 remain binding. Rules: ICR-V2.0 / GHRH-2.0 / ETP-V2.0.

## 1. Current exact patch and negative capability

- gateway/lbe_m2_native_t1_preflight_t0.py consumes an actual M1 nonoperative PrelaunchBindingT0 candidate and checks a proposed standalone Go/Pipenv T1 command, source-lock format and overlap, descriptive macOS Runner identity, candidate resource ceilings and the required shape of an OFFLINE_ONLY egress plan.
- tests/test_lbe_m2_native_t1_preflight_t0.py uses disposable SYNTHETIC files and the actual M1 source/env T0 chain; it covers legal proposals, unsafe argv, unknown Go flags, missing or mismatched source digests, runner/profile drift, bad limits, weaker egress or post-contact proposals and forged attestation fields. It spies on subprocess and socket creation. No real foreign Go/Pipenv code runs.
- A legal plan always yields status NONOPERATIVE_M2_TEST_PLAN_T0, launch_allowed=false, workspace_service_exec_authorized=false, native_t1=NOT_RUN, loaded_source_identity=NOT_ATTESTED, precontact_egress_enforcement=NOT_ATTESTED, same_domain_canary=NOT_RUN, resource_enforcement=NOT_ATTESTED, runner_execution_identity=NOT_ATTESTED.
- The same hard block remains even if every proposal SHA and network-policy request is syntactically well formed. Claims, request data and text values are not real source/runner/OS-enforcement evidence.
- No native T1 Actions workflow, executor, egress installer, privileged policy change, launch flag or WorkspaceService import is added. The existing Linux CI executes only first-party T0 regression and F1 deny-only tests.

## 2. Future SOURCE_TOOLCHAIN_T1 isolated native matrix - NOT_RUN

| Kind | Proposed standalone argv | Evidence required AFTER separate exact-runner admission |
| --- | --- | --- |
| Go | go test ./... | Actual Go1.27.3 entrypoint/compiler/stdlib/module, exit and bounded output |
| Go | go vet ./... | Same loaded identities, denied toolhooks |
| Go | go build ./cmd/service | No toolchain fallback/cgo/automatic downloads |
| Go | go build -o bin/service ./cmd/service | Approved private no-follow output target and origin |
| Pipenv | pipenv run python ok.py | Pipenv2026.10.4, shebang, private .venv Python3.13, site/seed/.pth and Pipfile.lock / RECORD |

Only operator-reviewed, private, tiny fixtures are contemplated: stdlib-only Go and explicit Pipfile/Pipfile.lock with private Pipenv .venv. Source-archive hashes and URLs alone cannot prove actual loaded compiler/stdlib/venv/site code. Effective importer paths, embedded/generator outputs, script shebangs, selected Python interpreter, virtualenv seeds, module cache and unlisted RECORD-adjacent importables need independent qualification.

The proposed source_lock in this T0 patch validates shape and consistency with the M1 checked-member map. It DOES NOT open or attest all fixture inputs, and does not cover every potentially importable source. Every real Go/Pipenv original-child, import, compile, wheel install, egress test and exit remains NOT_RUN.

Negative future prelaunch oracles include GOFLAGS -toolexec, alternate PATH/GOEXPERIMENT/toolchain, unqualified compiler or module, unsafe go build -o, go run/unknown flags, untrusted Pipenv entrypoint or shebang, .venv pointer file/symlink, changed venv Python and seed/.pth, proxy or source shadow, missing private old owner.lock and UNKNOWN/quarantine for future product admission. A negative involving unsafe external source must refuse with ZERO Go/Pipenv native Popen.

## 3. OFFLINE_ONLY network isolation precontact gate - UNMET

Before the first permitted native Go/Pipenv instruction, a separately reviewed future harness MUST:

1. Record the exact actual new test Head/Tree/Manifest, all effective source/generated/artifact bytes and the real disposable hosted macOS 15 ARM64 image/kernel/Python identity before any foreign loader.
2. Establish an independently inspectable OFFLINE_ONLY isolated VM/domain or audited attached OS policy, actually denying outbound TCP, UDP, DNS and unintended proxy paths for selected original child AND descendants, attached BEFORE FIRST instruction. Neither GOPROXY=off/PIP_NO_INDEX=1 nor a proxy variable nor a post-contact log is enforcement.
3. Prove SAME EXECUTION DOMAIN policy attachment and denial by a separately authorized NONDESTRUCTIVE canary before foreign code, preserving actual original deny logs, context identity and timing. This check must be impossible to satisfy with an unrelated unisolated helper, self-attested data or source-code mocks.
4. If hosted macOS cannot safely supply this proof without unapproved host/global pf/firewall/privileged or shared-runner modifications: STOP before any foreign native code, report NATIVE_T1=NOT_RUN, EGRESS_NOT_ATTESTED and EVIDENCE_STATUS=INSUFFICIENT. Do not silently fall back to environment-only controls.
5. No BOUNDED_EGRESS host/IP/port allowlist is authorized. Do not launch, retry, send OS signals, kill unknown PIDs/PGIDs, revoke processes, change product Gate A logic or treat an unexpected network request as an acceptable anomaly.

The new _validate_offline_proposal function checks only the planned policy syntax. It does not create, attach, inspect or prove any network enforcement; no real canary or network request is made in this PR. A newly reviewed executable verifier is required before T1.

## 4. Proposed resource envelope - NOT CURRENTLY ENFORCED

One ephemeral macOS 15 ARM64 hosted job with <=1,200 seconds total; each expected-to-naturally-exit standalone child <=120 wall-clock seconds; one standalone original child active at a time.

New candidate numerical ceilings: <=120 CPU-seconds and <=2,048 MiB memory per original child, plus per stdout and stderr <=48,000 retained raw BYTES and separately <=48,000 redacted returned CHARACTERS. CPU/RAM numerical values are proposed design ceilings, NOT previously accepted exact owner caps, and this module installs NO RLIMIT, process/pipe policy or actual job timeout. Before any native run, exact CPU/RAM enforcement, context and code profile need owner-approved parameters and source-reviewed implementation.

No T2 timeout survivors, forced termination, signal tests, restart/crash or unknown-child recovery. No T3 shared/user Mac, Tunnel, production, credentials, merge, tag or deployment. Hosted runner teardown is not full descendant cleanup proof.

The proposed runner image_id is a text descriptor, never a measured immutable hosted image identity. CI on Linux does not establish the future macOS image/kernel/arch/source-lock/egress identity.

## 5. Acceptance and outstanding gates

This NEW nonoperative M2 T0 Draft PR requires B Standards and C Spec to independently review the SAME new Base/Head/Tree and full in-scope effective diff, actual source and normal Linux CI logs, both positive source proposal and meaningful hostile negative/edge/exception tests; verify ordinary F1 dry_run=false still rejects exec_cleanup_proof_required, and separate Git/File are unaffected. Prior PR #107 targeted PASS cannot transfer to the new Head.

Actual T1-SOURCE would need a separate reviewed executable test snapshot, exact native Go/Pipenv source+fixture lock, actual selected loaded-source proof, macOS runner identity, enforceable precontact isolation + same-domain canary, real CPU/RAM/output bounds and an explicit owner profile covering those exact inputs. If any requirement fails, report T1=NOT_RUN / EVIDENCE_STATUS=INSUFFICIENT; do not issue a PASS merely because the current T0 tests are green.

T1-PRODUCT remains NOT_AUTHORIZED. It needs a separately granted actual WorkspaceService/Worker/Launcher original-child fixture after exact Gate A and Gate B, and cannot use Python-only hosted fixture, a monkeypatch, env flag or direct bypass. Full Gate C/R10 and same-instance Direct/REST/official MCP/Git/File integration remain BLOCKED. Neither a SOURCE-only test, nor B/C TARGETED T0 pass, nor CI GREEN authorizes release.

CURRENT REQUIRED RESULT: NONOPERATIVE_M2_TEST_PLAN_T0 / SOURCE_TOOLCHAIN_T1_NOT_RUN / PRECONTACT_NETWORK_ISOLATION_NOT_ATTESTED / NO_NATIVE_CHILD.


## 6. Review r001 targeted defect closure candidate - T0 only (r002)

After the first original PR #108 r001 Head, B Standards native review on that
fixed Head reported **FAIL** with two in-scope P2 findings, and C Spec
independently reported a bounded TARGETED PASS with P3 notes. Both old Reviews
remain immutable and cannot confer a verdict on this new Head.

- P2-108-01 (forged M1 candidate): the public frozen PrelaunchBindingT0
  dataclass can be constructed/replaced; checking its declared status,
  nonempty maps and self-reported matching SHA map is NOT proof of genuine M1
  source/env checks. The r002 preflight therefore requires
  m1_recheck_inputs, an exact kind-specific set of original privately staged
  roots and expected source digests/parent selectors, calls the actual M1
  Go/Pipenv no-follow original-file SHA inspection and closed-env constructor
  **again immediately at M2 T0 planning**, compares every candidate SHA
  entry and every effective environment key/value against the reconstructed
  result and validates the proposed source lock against freshly inspected
  bytes. A supplied M1 dataclass is never an unforgeable identity token.
  Forged GOFLAGS/toolhooks, LD_PRELOAD, PATH, Pipenv interpreter/Pipfile
  selectors and matching fake candidate+source_lock digests must deny.
  This is a bounded on-disk T0 recheck, NOT an actual loaded-source or
  immutable FD-to-Popen attestation, and does not remove same-UID TOCTOU.
- P2-108-02 (malformed kind/policy values): validate exact primitive kind
  type BEFORE any dictionary-membership operation, validate the exact
  primitive type of every proposed offline and runner value BEFORE semantic
  comparisons. Reject hostile equality methods or unhashable/nonstring
  kinds with LbeM2T1PreflightError without executing their methods or
  launching any child. Source/parent map inputs must also have exact
  first-party shapes and fail closed if M1 re-inspection fails.
- P3-108-01 (cross-field budget consistency): require candidate total
  job_seconds >= child_seconds + 60, reserving at least 60 seconds for
  setup/verification/cleanup in the proposed profile; numerical limits are
  still NOT approved as final executable CPU/RAM budgets and NOT OS-enforced.
  This margin is only a static candidate check.

Test-before-fix RED on new test-only Head 5dbb1b0d3e217de275f408d56358af9ec145761d,
Tree 79a086487a9ae6d5b3271d04c61b291d0120952e,
original Linux CI https://github.com/chinanjjohn2012/mac-file-gateway/actions/runs/41329122678/job/124915301592:
20 expected new failing cases, 2317 other passed, 19 skipped,
one warning. The failed pytest step terminates downstream smoke/final CI
steps; they must NOT be counted PASS on RED. This preceding RED is historical
evidence, NOT an r002 GREEN result.

For the r002 GREEN snapshot, independent B and C MUST re-read exact new
Head/Base/Tree, effective diff, actual original CI/skip reasons and separately
design meaningful counterexamples; neither C's old r001 targeted PASS nor
A's CI results prove new r002 role acceptance. The default disabled launch,
absence of native Go/Pipenv, absence of enforceable OFFLINE_ONLY attached
domain/canary, F1 deny and other Gate B/C blockers remain unchanged.
