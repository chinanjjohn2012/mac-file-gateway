# M2 macOS Seatbelt native canary validation PREPARATION (T0-only)

TASK_ID: MULTI-EXEC-LBE-M2-MACOS-CANARY-VALIDATION-PREP-20261103
REVIEW_SCOPE: TARGETED
STAGE: NONOPERATIVE T0 / FUTURE NATIVE MACOS CANARY NOT_RUN
APPROVED_ACTION: Develop exact-source canary preparation in a NEW Draft PR, run safe Linux T0 only and submit B/C independent review.
EXPLICIT_EXCLUSIONS: No actual macOS helper compilation or execution, no sandbox_init invocation, no actual fork/kill/OS signals, no Go/Pipenv native T1, no global firewall, no user/shared Mac/Tunnel, no T2/T3, no product Exec, no merge/deploy.

## 1. Frozen authority and review boundary

- Parent is PR #110 r002 Head 437da2b75d1e5a1b488ecad05453fe73487d5f32 / Tree 355b3d427ec27a5eacfc74ce646e8809d7ad71a7. Independent B Standards native r002 TARGETED PASS: https://github.com/chinanjjohn2012/mac-file-gateway/pull/110#pullrequestreview-5755123592 . Independent C Spec native r002 TARGETED PASS: https://github.com/chinanjjohn2012/mac-file-gateway/pull/110#pullrequestreview-5755080402 . Both only accept NONOPERATIVE T0 FD scrub and related source; NOT actual macOS kernel protection or real native test eligibility. Prior PR #110 r001 FAIL was fixed on a new r002 Head. No inherited PASS for this new Head.
- Applicable static governance: ICR-V2.0 / GHRH-2.0 / ETP-V2.0 and A role V2.0. New B/C independent same-Head/Base/Tree source, executed evidence and exact target required.
- Frozen design: PR #102 r002 real Go/Pipenv SOURCE T1 OFFLINE_ONLY Gate B design GitBlob 7db3b77aadca8b0c284e28fa5ee64e315e9275d2 §§3,5.1-5.5,7-9; PR #98 schema-v2 local_best_effort candidate GitBlob 9e6622401b198138039c692efe91fba1a8d06891; PR110 native canary-only T0 design GitBlob 2a5e89df6a08accb5fbb781a949be483e1574e60.
- Operative D0 GitBlob 6e25904aed9a62bb0f472b732021c2a7ca3b3bb0; F1 GitBlob 76baeb820c6f8a9b067e45e2dcc42e76453fe5b1; Phase1 b3f2383f292a59fd234269389e5338cd50e334a2; G05 GitBlob 76c1c2b8a7947e0b305d55c5f550ab59c638b6d1; limited 36-Wheel RECORD scope R004 GitBlob 2ffe5341288e428be5ee5d0fa8d52aea3e9efc93. None is changed in this PR.
- User explicitly requested "继续开发 M2 macOS Seatbelt 原生 canary 验证准备，创建独立 Draft PR，先执行 T0 并交 B/C 复审". Existing owner Gate A design-risk approval PR #102 comment 6559619893 and Gate B conditional OFFLINE_ONLY standalone SOURCE_TOOLCHAIN_T1 and non-destructive same-domain canary approval PR #102 comment 6560708487 do not waive actual source/runner/OS/limits/safety. This task does NOT run the canary or activate schema v2 product Exec.

## 2. Observed prior P3 risk and bounded source change

Reviewers found PR110 r002 C110-R001-SPEC-02 / P3-110-R002-03: the Apple-only C helper blocked indefinitely with waitpid(child, &status, 0) after fork. That is a future native canary safety hazard, even though PR110 never actually compiled/executed the macOS helper.

This new proposed source adds tools/lbe_m2_canary_bounded_wait_t0.h, and changes tools/lbe_m2_seatbelt_canary_only.c to use it only AFTER the previously reviewed fixed FD scrub, Seatbelt attachment, local IPv4/v6 loopback-denial probes and single fork.

The C wait helper:
- Waits ONLY for a single POSITIVE named child PID; no group waits.
- Calls waitpid(child, &status, WNOHANG) via fixed libc binding, CLOCK_MONOTONIC for elapsed time and nanosleep 10 ms between checks.
- Uses a hardcoded at-most 2000 ms candidate wait budget and at-most 256 polls, so a stuck/faulty mock monotonic clock cannot create an infinite source loop. Validates the callback input and time nanoseconds; backward/invalid/failed clock, ECHILD/unexpected PID, abnormal/nonzero child, sleep errors and exhausted polling are explicit NON-PASS outcomes.
- Reports success only for observed WIFEXITED and WEXITSTATUS == 0. EINTR is retried within the finite budget; any other syscall error is a denial.
- Never uses kill, killpg, signal, setpgid, OS PID/PGID termination, automatic retry or group cleanup. This is NOT a grant to run a real Mac fork; timeouts and ECHILD mean the child MAY STILL BE ALIVE, and no tested retirement mechanism exists. A potential survivor must BLOCK any later native admission. The source-only bounded wait does not fulfill full natural-exit/lifecycle or original/descendant containment proof.

The C helper remains a FIXED-profile CANARY-ONLY program: no dynamic endpoint/profile/argument or Go/Pipenv command, no process-exec allow, no host-wide firewall, and no native test workflow. The entire C module remains uncompiled and unexecuted on macOS in this PR. It is not a legitimate T1 process context source-to-compiled-binary witness.

## 3. Real safe T0 implementation and source identity

- gateway/lbe_m2_seatbelt_offline_t0.py now locks three exact source bytes: the C helper, the existing real-open-FD scrub header, and new bounded-wait header. Type-mismatch and SHA mismatch fail before returning any descriptive T0 receipt. Source is caller-supplied, so byte match is not a GitHub-owner origin certificate or the identity of an actual compiled Mac binary.
- gateway/lbe_m2_macos_canary_validation_t0.py builds an immutable descriptive candidate only for explicitly syntactic 40-hex proposed Head/Tree and the three byte-verified helper files. Caller-provided SHA strings are NOT independently observed GitHub commit/tree identities. The candidate records GitHub-hosted macos-15 arm64, 2-second internal wait, proposed 10-second whole helper wall, 10 CPU seconds, 128 MiB RAM, per-stream 4KiB raw output and <=20-minute job. ALL are unverified future PROPOSALS (stricter than the original user-approved 120-second/120 CPU/2GiB/48KB standalone Go/Pipenv ceilings), NOT OS-enforced budgets or approval of actual native launch.
- execute_macos_seatbelt_native_canary() is an UNCONDITIONAL HARD DENY even if supplied a fake full OS attestation, GitHub environment, successful stdout or forged frozen dataclass. Existing require_verified_offline_domain_before_native_t1() and PR109 execute_source_toolchain_t1() remain hard-denied.
- tests/test_lbe_m2_canary_bounded_wait_t0.py actually compiles JUST the pure C bounded-wait header in a disposable Linux fixture and executes it with fake WNOHANG, monotonic clock and sleep callbacks. No real child, POSIX signal, Seatbelt kernel call or network occurs. Positive ordinary exit 0, delayed exit and EINTR are paired with nonzero, signaled, ECHILD, wrong PID, clock backward/error/jump, nanosleep error, frozen monotonic time, deadline, invalid budget/PID/callback, no-spawn code-inspection. This proves a narrow source-algorithm implementation in Linux, not the macOS process/wait system.
- tests/test_lbe_m2_macos_canary_validation_t0.py validates exact first-party source bytes, proposal status, type/identity errors, modified C/include header and spoofed capabilities. tests/test_lbe_m2_seatbelt_offline_t0.py is extended to cover the third header lock and bounded-wait call and keeps the existing FD scrub and static safety suite.
- MANIFEST.sha256 updated for all changed first-party paths. G05 can confirm first-party HEAD and tracked filenames/bytes/modes. Installed compiler/sysroot/libc/dynamic loader, helper generated Mach-O and actual macOS runner image/Python are still NOT_ASSESSED/NOT_ATTESTED. The Linux host cc in T0 is an external unpinned compiler and C-header execution proof only.

## 4. Future exact macOS native canary admission before any T1

Prelaunch requirements that this PR intentionally DOES NOT satisfy:
1. A separately approved, independently B/C-reviewed new runnable Head/Tree, full first-party G05 preflight, compiled Mach-O and actual compiler+SDK+linker/signature identities; audit all generated and other source-shadow inputs and embedded build metadata. No user Mac or shared host.
2. Exact disposable GitHub-hosted macOS 15 ARM64 Runner image, Python, compiler, dependencies and private single-thread canary host; freeze FD table and prevent later injection after two-pass /dev/fd enumeration. Verify actual /dev/fd behavior, no inherited socket/unsafe stdio relay and no unreviewed parent IPC; clock/wait/sandbox_init support must be directly observed.
3. Enforceable PRECONTACT OFFLINE_ONLY policy bound to the original canary and all natural descendants BEFORE any foreign native instruction, plus approved non-destructive deny probes and independent original OS evidence covering the intended TCP/UDP/DNS/proxy and local IPC escape routes. This helper's loopback-only port9 probes do NOT prove remote/DNS/proxy denial or future Go/Pipenv same-domain process-exec inheritance. Apple sandbox_init is deprecated; its availability and profile behavior must be verified, not inferred from code. GitHub ARM64-hosted macOS does not support nested VMs, so do not silently substitute a nested-VM design.
4. Preverified OS-enforced job, wall, CPU, RAM, output raw-byte/returned-char ceilings and exactly one owned original/descendant; independently prove safe natural termination, bounded wait, stable original owner identity and deterministic latch on timeout/unknown child. This source does NOT signal/reap a timed-out child or prove an orphan safely removed. If no trusted isolated supervisor can retire/contain a survivor without an unapproved destructive kill, physical native canary MUST remain NOT_RUN.
5. Only AFTER all above proofs and new reviews may an explicitly authorized non-destructive native macOS CANARY be considered. Even a real canary PASS is not Go/Pipenv SOURCE_TOOLCHAIN_T1 PASS. Actual Go1.27.3/Pipenv2026.10.4 source-qualified loader, compiler/module/venv/site/seed identity and same-domain canary-to-exec first-instruction safety require a separate new reviewed exact Head and original evidence. T1_PRODUCT, T2/T3, Gate C FULL and positive Direct/REST/official MCP+Git/File integration have separate contracts.

Official technical context (not project CI evidence):
- GitHub-hosted macOS arm64 nested virtualization limits: https://docs.github.com/en/actions/reference/runners/github-hosted-runners
- sandbox_init(3) DEPRECATED manual: https://man.freebsd.org/cgi/man.cgi?manpath=macOS+13.6.5&query=sandbox_init&sektion=3
- Apple engineer about inherited sandbox across fork and entitlement caveats: https://developer.apple.com/forums/thread/747499

## 5. Exact independent B/C review request and current statuses

Review ALL new Base..Head changed files, plus unchanged actual PR110 FD scrub, PR109 hard-deny source launcher, F1 default deny and native product launcher. Independently inspect helper C source control flow, profile and FD/clock/wait ordering; challenge frozen-clock infinite loops, EINTR storms, fake PID, errno-as-success, child survival after deadline, true CLOCK_MONOTONIC availability, source hash locks, fake runner OS claims and malicious dataclass mutation. Do not equate fake callback C tests or Linux G05 GREEN with actual macOS C program compilation or Seatbelt kernel deny. Do not claim P3 fully closed for native testing merely because source now has finite polling.

T0 current independent B/C reviews: NOT_ISSUED until current exact Head is frozen and A has published GH_HANDOFF_V2 READY_FOR_REVIEW. Native macOS Seatbelt, all-channel offline isolation, actual Go/Pipenv and product positive paths: NOT_RUN/NOT_ATTESTED. R10_STATUS: BLOCKED. FULL_CODE_REVIEW_PASS: NOT_ISSUED. INTEGRATION_STATUS: NOT_TESTED. No PR merge/tag/deploy/config change authorized.
