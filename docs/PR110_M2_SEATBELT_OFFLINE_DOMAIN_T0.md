# M2 SOURCE_TOOLCHAIN_T1 - Seatbelt OFFLINE_ONLY candidate backend (canary-only, T0)

TASK_ID: MULTI-EXEC-LBE-M2-SEATBELT-OFFLINE-DOMAIN-20261102
REVIEW_SCOPE: TARGETED, NONOPERATIVE T0 SOURCE REVIEW
NATIVE_GO_PIPENV_T1: NOT_RUN
SEATBELT_MACOS_COMPILE_AND_CANARY: NOT_RUN
OFFLINE_ONLY_DOMAIN: NOT_ATTESTED
SAME_GO_PIPENV_EXEC_CONTEXT: NOT_ATTESTED
FULL_CODE_REVIEW_PASS: NOT_ISSUED
INTEGRATION: NOT_TESTED
RELEASE: NOT_AUTHORIZED

## 1. Current contract, predecessor and owner authority

Base: PR #109 r001 nonoperative SOURCE T1 source-closure+hard stop Head
c6535e6dd937d938ad4ccfcdfde0f1e391fc597a, Tree
ee1f4df5b71a8b6cdebb7619a9fd4e0317f26bbc. Independently issued
B Standards native TARGETED_REVIEW_PASS:
https://github.com/chinanjjohn2012/mac-file-gateway/pull/109#pullrequestreview-5731267454
and C Spec native TARGETED_REVIEW_PASS:
https://github.com/chinanjjohn2012/mac-file-gateway/pull/109#pullrequestreview-5731261764.
These verdicts are only for the old frozen PR109 T0 and are NOT inherited
by this new executable C source or a real native T1.

V2.0 rules: ICR-V2.0 / GHRH-2.0 / ETP-V2.0; only after current Project
full-source and multi-role approval. Frozen reviewed design:
PR102 r002 Git Blob 7db3b77aadca8b0c284e28fa5ee64e315e9275d2,
sections 3, 5.1-5.5 and 7-9; PR98 LBE schema-v2 design Git Blob
9e6622401b198138039c692efe91fba1a8d06891. Operative D0
6e25904aed9a62bb0f472b732021c2a7ca3b3bb0; F1
76baeb820c6f8a9b067e45e2dcc42e76453fe5b1; Phase1
b3f2383f292a59fd234269389e5338cd50e334a2; G05
76c1c2b8a7947e0b305d55c5f550ab59c638b6d1; R004
2ffe5341288e428be5ee5d0fa8d52aea3e9efc93.

The owner accepted exactly the weaker D0 schema-v2 risk (A transcription
PR102 #issuecomment-6559619893), and conditionally approved a ONE
disposable runner OFFLINE_ONLY standalone SOURCE_TOOLCHAIN_T1, including
same-domain non-destructive precontact denial canary (A transcription
PR102 #issuecomment-6560708487). The user explicitly requested this next
M2 OFFLINE_ONLY isolation backend development, not a waiver of executable
Head+source/image+resource/policy/native B/C requirements. No T1_PRODUCT,
T2/T3, user/shared Mac, host/global firewall, production, merge or deploy.

## 2. Independent external feasibility facts, not project execution proof

- GitHub ARM64 macOS hosted runners currently do NOT support nested
  virtualization. In particular, a VM INSIDE an ARM64 GitHub macOS VM
  is not an eligible default solution. Official docs:
  https://docs.github.com/en/actions/reference/runners/github-hosted-runners
  and https://docs.github.com/en/actions/reference/runners/larger-runners.
- Apple's sandbox_init(3) legacy API is explicitly DEPRECATED; no
  assumption that it is supported and enforceable on every hosted
  macOS 15 ARM64 image is justified. Manual:
  https://man.freebsd.org/cgi/man.cgi?manpath=macOS+13.6.5&query=sandbox_init&sektion=3
- Third-party macOS Seatbelt implementations provide an implementation
  precedent for process-scope sandbox_init between fork and exec, and
  network restrictions, but they do NOT attest this project's source,
  runner, profile, loaded code or actual kernel result. Example:
  https://github.com/microsoft/mxc/blob/main/docs/backends/seatbelt/seatbelt-backend.md.
- Apple App Sandbox signing/entitlements and this deprecated raw SBPL
  helper are different mechanisms. Do not infer equivalence or native
  inheritance guarantees from a static C profile alone.

These external docs motivate a candidate ONLY. Original positive
macOS platform, protocol, permissions, network and child evidence are
NOT_RUN / NOT_ATTESTED for the current exact Head.

## 3. Three new files and intentionally restricted capabilities

A. tools/lbe_m2_seatbelt_canary_only.c

First-party C canary source compiles on Apple only and is never built or
invoked by the existing Linux workflow. It accepts NO command, profile,
network endpoint, executable path, user-controlled shell, privilege
escalation or arbitrary subprocess arguments (argc must be exactly 1).
It only uses a FIXED compile-time Seatbelt profile:
(version 1); (deny default); allow file-read*, process-fork and
sysctl-read. It never grants network-outbound, network-inbound,
network-bind, process-exec, broad host-write or proxy extension.

Before calling sandbox_init, it rejects socket-based stdin/out/err
and delegates a complete enumeration-and-verification FD scrub to the
NEW fixed first-party tools/lbe_m2_fd_scrub_t0.h. The implementation
uses macOS /dev/fd (Linux T0 uses /proc/self/fd) to enumerate numeric
CURRENTLY OPEN descriptors, closes every inherited nonstdio FD except
its own enumeration directory, then independently re-enumerates and
DENIES if any other FD remains >=3. It never uses current soft/hard
RLIMIT_NOFILE as a range boundary. Unknown directory entries,
unsupported/enumeration/close/readdir errors, or an inaccessible FD
directory all DENY before sandbox_init. An inherited FD opened at a
high number before lowering RLIMIT_NOFILE is no longer silently skipped.
No source-only check proves actual macOS /dev/fd or kernel policy behavior;
separate native macOS B/C review and original evidence remain necessary.
It calls sandbox_init(profile, 0, &errorbuf), fails on a nonzero result,
then attempts nonblocking IPv4/IPv6 TCP and UDP to LOOPBACK port 9
inside its own context. Only an OS permission rejection EPERM/EACCES
qualifies the limited attempt; ECONNREFUSED, EINPROGRESS, an actual
connection or UDP send success MUST FAIL. No public IP, DNS query,
third-party service, external port or proxy request is made. The
helper natural-forks a single CHILD after sandbox_init and repeats
the same local probes in its descendant. It waits for a normal child
exit; no kill, killpg, pgid/cancel/timeout-signal or orphan experiment.
It prints a fixed CANARY_ONLY_NATIVE_GO_PIPENV_NOT_RUN message on
success. That message is NOT an independently authenticated OS witness
and is never consumed as authority by Python.

CRITICAL: This C helper does NOT exec Go or Pipenv in the same process
after successful denial canaries. Hence even a future successful
native macOS run would be only a LIMITED local loopback/descendant
canary observation, NOT the required SAME-process canary-to-Go/Pipenv
execution linkage, no remote TCP/UDP/DNS proof and no AF_UNIX/local
proxy route coverage. The code is not wired into any workflow or
product launcher. Its sandbox profile may fail to initialize or deny
required fork on macOS 15; that yields BLOCKED rather than fallback.

B. gateway/lbe_m2_seatbelt_offline_t0.py

Pure first-party T0 source admission verifies EXACT built-in bytes of
the C helper against one immutable pre-reviewed SHA256 and EXACT fixed
SBPL text. It returns a nonoperative frozen candidate showing the
helper source SHA, policy SHA and diagnostic system/machine. Every
authority field remains false/NOT_RUN/NOT_ATTESTED. Caller-supplied
policy strings, bytes, primitive shape changes and hostile equality
objects cannot mint policy. The function
require_verified_offline_domain_before_native_t1 ALWAYS raises an
explicit denial even if supplied a fake policy attachment, forged
canary PASS, fake runner label, or a dataclasses.replace "verified"
receipt. It contains NO ctypes, socket, process launcher or dynamic
native bridge.

C. tests/test_lbe_m2_seatbelt_offline_t0.py and
tests/test_lbe_m2_seatbelt_fd_scrub_t0.py

Real Python T0 tests with exact committed first-party C AND shared
FD-header source bytes,
G05-controlled artifact identity and synthetic policy/attestation
counterexamples: legal source/profile receipt remains blocked;
helper SHA tamper / C policy patch / unsafe or malformed custom
SBPL / hostile equality / forged successful receipt and OS environment
flags all fail to grant SOURCE_TOOLCHAIN_T1; original PR109
execute_source_toolchain_t1 still raises. Static C control-flow tests
check sandbox_init before socket/fork, fixed loopback targets, FD cleanup,
no execve/posix_spawn/native Go/Pipenv bridge, no signals, host firewall
or dynamic network target. These are STATIC inspections only, not
a native C compiler run or evidence of actual Seatbelt operation.

D. MANIFEST.sha256 adds all new first-party sources to G05. Its
SHA records do not attest installed Apple clang/libSystem headers or
hosted runner image. CI may only be a GitHub-hosted Linux Python 3.13
HEAD + 36 locked Wheel / RECORD-listed dependency scope; no synthetic
Merge CI or Darwin-specific egress canary is implied.

## 4. Hard preconditions before any actual macOS test or Go/Pipenv

Stage 1 (separate later new exact-Head B/C-reviewed native CANARY):
- Pin and verify compiled C helper compiler+source+binary and hosted
  macOS 15 ARM64 OS/image/Python identity, before any compilation/import
  outside G05's first-party repo checks; verify installed sandbox_init
  availability and that a private per-process profile truly attaches.
- Run only the independently authorized, non-destructive loopback
  canary on ONE disposable qualified runner; source, original stderr/
  stdout, return status, original/descendant PID and OS identity must
  be recorded without secrets. No global pf or host firewall.
- Show failure closed on missing policy, blocked fork, invalid socket,
  inherited-open-FD ambiguities, inconsistent binary/protocol IDs.
- Verify descendant policy inheritance independently; one returned
  stdout string or exit code 0 is NOT a kernel policy attestation by
  itself. This C helper does not prove all DNS, proxy or remote paths.

Stage 2 (FUTURE separately implemented and reviewed executable T1):
- Bind an exact private immutable approved Go1.27.3 or Pipenv2026.10.4
  source/stdlib/modules/venv/entrypoint/selected interpreter/seed/site/
  .pth and actual loaded identity to the child. A caller-made full SHA
  lock is not approved upstream provenance; same-UID path race after
  T0 is not closed by the current code.
- Integrate exact reviewed same-process precontact Seatbelt
  attachment+denial witness into the future launcher BEFORE the first
  Go/Pipenv instruction; enforce all relevant outbound TCP/UDP/DNS/
  proxy AF_UNIX/descendant paths with actual OS controls and independent
  positive/negative enforcement evidence. Do not allow the C
  canary-only binary's stdout to become an execution grant.
- Enforce the separately approved envelope on original hosted macOS
  job: one active standalone child, <=20min job, each natural-exit
  Go/Pipenv <=120s, <=120 CPU seconds, <=2048MiB RAM,
  <=48000 retained raw BYTES and <=48000 public redacted CHARACTERS
  EACH stdout/stderr independently. This patch enforces NONE of these
  native limits, and cannot claim native T1 PASS.
- Do not use Linux CI success, environmental GOPROXY=off,
  PIP_NO_INDEX=1, sandbox-exec helper presence, host firewall, or
  source/profile proposal to bypass the actual isolation gate. If
  a required OS/runtime guarantee is unavailable: T1=NOT_RUN,
  EVIDENCE_STATUS=INSUFFICIENT, R10_STATUS=BLOCKED.
- T1_PRODUCT and positive WorkspaceService/Direct/REST/official MCP,
  Git/File integration remain a separate owner-reviewed new Head,
  Gate C FULL, R10 and release decision; no automatic escalation.

## 5. Exact future independent B/C review target

Review the complete current Base/Head/Tree change set and actual
first-party source including C/C-header and Python, C policy and
no-exec call graph, real original T0 tests, malicious raw policy,
simulated forged receipts, inherited FD holes, fork/descendant
safety and untested DNS/proxy routes. Evaluate the known limitation:
a preexec process may inherit network-capable descriptors and the
legacy sandbox_init API can fail on hosted macOS. These must remain
explicit blockers, not be silently accepted from developer self-report.

T0 tests on Linux and source-level reasoning can prove this is a
fail-closed NONOPERATIVE candidate only. B/C independent
TARGETED_REVIEW_PASS, if obtained, does NOT prove real macOS
Seatbelt behavior, T1_SOURCE or T1_PRODUCT, and cannot issue
FULL_CODE_REVIEW_PASS. Neither A nor a GitHub comment may write or
sign B/C verdicts. A publishes one exact GH_HANDOFF_V2
READY_FOR_REVIEW with original CI, skips, failure evidence and
the known missing OS/native isolation evidence. Keep PR Draft.


## 6. PR110 r002: independent P2 on high inherited FD / safe T0 repair

The previous r001 freeze was PR110 Base
c6535e6dd937d938ad4ccfcdfde0f1e391fc597a / Head
09bed929b4fecd103ba807b92374391b5322686e / Tree
bc5773173a445fceb271e28aac9f7171c9b54347. Both distinct native
GitHub SHA-bound reviews independently concluded TARGETED FAIL:
- B Standards: P2-110-01, https://github.com/chinanjjohn2012/mac-file-gateway/pull/110#pullrequestreview-5731440660
- C Spec: C110-R001-SPEC-01, https://github.com/chinanjjohn2012/mac-file-gateway/pull/110#pullrequestreview-5731432858

Both found that old C function reject_inherited_socket_descriptors
closed ONLY descriptor numbers 3..current RLIMIT_NOFILE.SOFT-1; a
descriptor (including AF_UNIX/socket) opened at number >=128 BEFORE
lowering soft rlimit to 64 would survive this loop and allow
sandbox_init to proceed despite a preopened inherited FD, violating
this PR's explicit all-FD pre-sandbox contract.

A's first-party TEST-FIRST RED Head
332f072dd5a604d7db7f20cf84816710145e2288 / Tree
5155a75a73559fe82d1db0a7fb18f0598931531a
https://github.com/chinanjjohn2012/mac-file-gateway/actions/runs/41661699545/job/126006265508
actually ran hosted Linux first-party T0 and gave 2 FAILED,
2469 PASSED, 19 SKIPPED, one warning. The two fails were direct source
assertions rejecting the old soft-RLIMIT bounded loop and requiring
a new C source verified enumeration path. A separate harmless Python
AF_UNIX high-FD reproducer passed in a disposable interpreter and
observed old loop still left fd128 open. RED G05 checked 300 Blob/mode
and 299 Manifest entries before tests; subsequent HTTP/MCP/Git smoke
not run on RED due pytest failure. These are not an actual macOS
Seatbelt C execution or kernel escape experiment.

The proposed r002 fix is an auditable new first-party header
tools/lbe_m2_fd_scrub_t0.h directly included by the unchanged-design
Seatbelt C helper. It performs full current-open-FD enumeration from
the platform-native FD filesystem directory, closes ALL >=3 except
the enumerator's own FD, and independently enumerates a second time
to verify no other open descriptor remains. It checks socket stdio,
rejects nonnumeric unexpected entries, closers raising unexpected errno,
missing/incomplete FD directories, enumeration overflow/errors and
surviving handles. Its count limit bounds listing WORK, not the FD
NUMBER; soft and hard RLIMIT_NOFILE are NOT used as bounds. A
multithreaded or externally FD-injecting parent, non-working /dev/fd
on hosted macOS, or FDs opened afterward remain separate precontact
safety risks; this is a single-thread, no-exec canary-only helper,
NOT a production sandbox.

The updated pure-Python T0 identity checker pins BOTH C helper source
SHA256 and the exact included FD-scrub HEADER SHA256, rejects any
injected old or modified header, and STILL RETURNS T1=NOT_RUN. A new
safe Linux standalone C FD-algorithm fixture compiles only this exact
header via disposable compiler/source into a one-shot local test
executable, covering normal no-extra-FD, high AF_UNIX fd128 after
soft64, injected close failure, missing FD directory and socket stdio.
No Seatbelt sandbox_init or Go/Pipenv code is compiled, loaded or run
by this Linux fixture. Its OS/libc/compiler identity is a TEST input,
not Mac-native proof or locked Go/Pipenv source. Source and tests
must be revalidated against NEW r002 Head and original CI.

Known unresolved P3 from C: canary future blocking waitpid has NO
independent OS wall budget; without separately reviewed/native verified
canary runner and bounded natural-exit policy remain NOT_RUN. Even a
full r002 first-party GREEN plus independent B/C TARGETED PASS cannot
replace real macOS C binary/SDK, OS Seatbelt policy/descendant
attachment, DNS/proxy/remote egress, loaded Go/Pipenv provenance,
resource caps or R10 full integration. No native T1, host firewall,
signals, production, merge or deployment is authorized by r002.
