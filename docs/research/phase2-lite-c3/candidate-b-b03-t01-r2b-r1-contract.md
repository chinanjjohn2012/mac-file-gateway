# B03-T01-R2b-R1 — Native C no-group-signal contract RED

**Status:** CONTRACT-ONLY RED BASELINE; independent Standards / Spec code review REQUIRED. No native Forced Group KILL Helper, no native Runner, no C stub adapter and **no kernel signal** is created or executed here.

**Authority:** This PR is stacked on the exact independently reviewed R2b-D0 [PR #40](https://github.com/chinanjjohn2012/mac-file-gateway/pull/40), Head `7d72e4177ef4ed5bec6186b84a95cb7fb79cecb1`, Git Tree `5acfb2da22a74186769bf5936ec2f0d80b6e207c`, [independent Review #5607620035](https://github.com/chinanjjohn2012/mac-file-gateway/pull/40#pullrequestreview-5607620035), Standards PASS / Spec PASS. Upstream B03-R1 and R2b-D0 have **distinct purpose**: existing [11-mode contract](../../../tests/test_c3_candidate_b_kill.py) remains untouched; this document freezes the new **T01-only native no-signal ABI, fail-closed event contract, and evidence boundaries**. Design review PASS is NOT authorization to use true group TERM/SIGKILL.

## 1. R2b-R1 exact boundaries

- Allowed in **R2b-R1:** this document, `tests/native/c3_b03_t01_no_signal_contract.h`, `tests/test_c3_candidate_b_t01_r2b_contract_red.py`, an R1-only safe GitHub workflow, and matching SHA256 Manifest entries.
- Intentionally **ABSENT** at the RED Head: `tools/research/c3_candidate_b_kill.c`, `tools/research/run_c3_candidate_b_kill.py` and `tools/research/c3_candidate_b_kill_t01_no_signal_probe.py`. They are **not** generated, imported or executed in this phase.
- This absence is checked by **the R1-only CI**, never by a permanently unsatisfiable assertion in shared pytest. The frozen behavior tests can legitimately become GREEN in a later separately approved R2b-R2 branch, while that branch must use its *own* safety workflow.
- Only T01 `escalate-positive` synthetic mode is in scope. No caller-provided host PID/PGID, arbitrary process/path/binary/command, Workspace or group lifetime. Tests use the sole nonnumeric token `fixture:synthetic-owned-anchor-group-T01` and per-test synthetic nonces. The C test ABI has no PID, PGID, FD, handle or group signal syscall function.
- `group_kill_authorized=false`, `reuse_proven=false`, `g2_qualified=false`; T04/T08b/T10 `NOT_RUN/BLOCK`. T02/T03/T05/T06/T07/T08a/T09 are not qualified merely by a T01 no-signal test. Native execution, G2/G3/G4/G5 and product ExecSupervisor/REST/MCP Multi-Exec remain BLOCK.

## 2. Safe C contract seam, not C implementation

`tests/native/c3_b03_t01_no_signal_contract.h` is a **declaration-only TEST-OWNED C11 ABI**. It requires the compile-time `C3B03_TEST_NO_SIGNAL_STUB` macro and otherwise fails at preprocessing. Its enums and exact-layout mock structs contain only synthetic mode/phase, an opaque nonce, a seven/eight-field relative and absolute deadline policy, TERM/KILL *test facts*, and fake transport counters.

The header does **not** implement a helper, wrapper, dispatcher, subprocess, syscall, signal fallback or runtime argument parser. The R1 test checks a `cc -fsyntax-only` C11 snippet with the macro, and verifies compile refusal without the macro. It never links an executable or loads a native helper. `MANIFEST.sha256` includes the exact bytes of the header. Its `MOCK_INPUT` and `MOCK_OUTPUT` structures **cannot serve as syscall permission**: only separately researched native Owner evidence obtained at live entry could ever do so after different approval.

The future R2b-R2 no-signal implementation may expose test-only probe adapter `tools/research/c3_candidate_b_kill_t01_no_signal_probe.py` with immutable test interface:

`C3B03_TEST_NO_SIGNAL_STUB = True
NATIVE_SOURCE_REL = "tools/research/c3_candidate_b_kill.c"
TEST_ABI_HEADER_REL = "tests/native/c3_b03_t01_no_signal_contract.h"
run_no_signal_case(request: dict) -> dict`

A request has `abi_version=1`, exactly T01 synthetic fixture token, `phase`, finite test-only `fault`, fresh 64-bit nonzero `nonce`, original eight-field `policy`, any replacement `attempt_policy`, original `term_sent_at_ms` and `now_ms`. Policy `ORIGINAL_POLICY` is frozen by value at the first genuinely simulated successful TERM; KILL cannot rebase t0/outer deadline by presenting a new internally consistent policy. Test facts cannot substitute for true live kernel/IPC identity. Each black-box case has a fresh lifetime and must echo its nonce.

The response is an **exact 18-field test schema** (no extra/missing fields): ABI/version, nonce, test stub marker, `synthetic_only` flag, `real_group_signal_syscalls=0`, TERM/KILL fake transport counts, TERM/KILL attempt counts, `signals_closed`, `group_signals_after_close=0`, `decision`, `cleanup`, lawful-wait booleans, `reuse_proven`, `g2_qualified`, and `mutation_detected`. Exact Python bool/int types are checked; `True == 1` never qualifies as typed native evidence.

**Critical:** A GREEN `SIMULATED_GATE_ONLY` response is *not* a native `POSITIVE_EXPERIMENT`. In no-signal mode `worker_lawful_wait=False`, `anchor_lawful_wait=False` and `cleanup="UNRESOLVED"` regardless of simulated TERM/KILL counts. The only valid positive native wait evidence is Controller's lawful `waitpid(worker_pid)` and Owner's lawful `waitpid(anchor_pid)` plus Final/FD/clock evidence, obtained only after later separately authorized real experiments.

## 3. Forward-compatible RED behavior, not marker-only checks

`tests/test_c3_candidate_b_t01_r2b_contract_red.py` freezes independently falsifiable cases. Every negative test must first pass **an actual compiled no-signal safety gate** in the separately reviewed future R2b-R2 workflow. The shared test will **not** suppress exceptions using `xfail`, `skip`, or `|| true`; now the native source is missing and the real pytest outcome must be RED with the explicit `EXPECTED RED` assertion. No arbitrary OS signal is ever emitted by the RED tests.

| Family | Required injected counterexample | Minimum observable no-signal proof |
| --- | --- | --- |
| TERM identity/ownership | private root invalid, Anchor nonchild or reaped, PID≠PGID, PPID/SID drift, native SIG_IGN missing, Controller joined target PGID, Worker parent/group/ARM wrong, IPC writer spoofed | **0** fake TERM and **0** fake KILL transport, both attempt counts 0, irrevocably closed |
| TERM deadline | `now=term_cutoff` and `now=term_cutoff+1` under original policy | **0** fake TERM/KILL; cannot retry with earlier clock |
| KILL native witnesses | fresh Anchor post-TERM readback or advancing sequence missing; Anchor exited/reaped/reused; Controller lost/inside group/no lawful Worker waiter; Worker parent/PGID/live invalid; post-TERM IPC falsified | initial **one legitimate fake TERM**, then **0** fake KILL transport, KILL attempt count 0, closed |
| KILL deadline and grace | `now=kill_cutoff`, `now=kill_cutoff+1`, or `now=term_sent_at+grace-1` | after fake TERM, **0** fake KILL; fail closed without rebase |
| Late TERM discrimination | original TERM cutoff `108500`; claimed TERM at `108501`; grace ends `108701`; attempted KILL at `108702` (< kill cutoff `109000`) | **0 fake TERM**, **0 fake KILL**; rejection cannot be accidentally explained by unfinished grace |
| Original-policy rebase | Original `t0=100000`, outer deadline `112000`; replacement self-consistent policy `t0=107000`; KILL at `112100` (< replacement kill cutoff `116000`) | genuine fake TERM permitted under original only; changed policy **0** fake KILL, closed |
| Signal syscall error/retry | fake `EINTR`, `ESRCH`, `EPERM` at TERM and KILL | TERM failure: one attempted TERM, no KILL. KILL failure: one attempted TERM + one attempted KILL, both forever closed |
| Evidence truth | fake/missing Controller FINAL, lawful Worker/Anchor wait absent, FD not closed, NOTE_EXIT only, original outer deadline elapsed | Even if fake transports report success, `cleanup="UNRESOLVED"` and `decision="BLOCK"` |
| Gate Mutation | compile-time finite 12 missing/relaxed TERM/KILL guards, including repeated signal attempt | `mutation_detected=True`, never reaches fake KILL transport under an invalid gate, no real syscall |
| Post-signal evidence Mutation | fake Controller FINAL or FD close (2 variants) | `mutation_detected=True`, `BLOCK/UNRESOLVED`; not required to undo a previously legitimate synthetic KILL |
| Mode exclusivity | each of the other ten frozen B03-R1 modes, regardless of fake orphan preflight | **0** fake TERM/KILL, `BLOCK` |
| Positive synthetic control | normal original deadlines, complete mock identity, proper simulated TERM→KILL | Exactly one fake TERM and one fake KILL, **still** `SIMULATED_GATE_ONLY/UNRESOLVED`; second independent t0/grace vector also accepted |

Test-case output must bind **the input nonce**, correct phase/fault and actual compiled adapter source under `C3B03_TEST_NO_SIGNAL_STUB`. A hardcoded success string, a Python-only simulation pretending to be C, or `kill` return treated as wait evidence is not a valid implementation. Positive and negative case behavior both remain testable after future native code is added.

## 4. Future C no-signal execution admission (NOT granted here)

Before R2b-R2 CI may compile **and execute** the future native C/helper/probe, an independent source/ABI review must establish:

1. Every exposed C signal path in the test build is redirected to a test-only stub. The stub holds only synthetic token identity and **cannot** call or forward to live `kill`, `killpg`, `syscall`, spawn or any negative-PGID signal path, even when compile-time Mutation disables a preceding guard. Build must fail if the test-only macro is absent. Inlined assembly, direct system-call number and dynamically looked-up signal functions must also be excluded by source and disassembly/linked-binary review.
2. Compiler invocation, exact binary SHA and `nm`/`otool`/`objdump` (as applicable) symbol/relocation and executable-path inspection must show **no linkable live group-signal path in the built test binary**. A source-text search alone is not proof. The future R2 workflow must run the safety inspection **before** loading a test library or spawning any C binary.
3. Native Owner's **production-capable** source remains unavailable to PR/push-driven native group-signal execution. Any future real-signal workflow is a different artifact with manual `workflow_dispatch`, human protected environment approval, independently pinned commit+binary SHA, one hard-coded T01 role and separately frozen measured macOS ARM64 timing and self-expiry.
4. Every mutation build uses a distinct isolated synthetic lifetime and verified stub. If a mutation reaches even the fake transport when a negative gate ought to refuse, the corresponding test fails. A dedicated fake-transport canary may be used to prove the mutation detector itself is live, **never** as a signal-run permit.
5. Actual native legal waits, authenticated Owner/Controller IPC sources, Controller FINAL, checked FD close, one monotonic deadline, macOS ARM64 calibration and cooperative exits are separately evidenced in R2b-R2. They are **not** established by this R1 RED result.

**If ANY future candidate can issue real group TERM/SIGKILL from test-only code, STOP before executing it.** A compiled stub binary must not receive arbitrary numeric PID/PGID from the caller. This package never calls a Group KILL syscall.

## 5. CI, expected evidence and independent gate

`.github/workflows/c3-candidate-b-t01-r2b-r1-contract-red.yml` must run under **only** the isolated R2b-R1 research branch or matching same-repository PR head; no privileged environment, no `workflow_dispatch`, permission `contents: read`, exact checkout Head and full Manifest validation. Every Job first confirms all three native implementation/adapter files are absent, and that only the test-owned C header can be compiled with `-fsyntax-only`. It then runs unchanged upstream R1, R2a and R2b-D0 tests (**140 existing GREEN**) together with R2b-R1 contract tests (**expected genuine RED**). Failures must not be wrapped in shell `|| true` or pytest `xfail`/`skip` or Actions `continue-on-error`.

The B03-R2 original pre-signal workflow remains independent, and the Linux full suite will gain the R2b-R1 missing-implementation failures in addition to the already frozen 19 B03-R1 missing native contracts. Do **not** claim full CI PASS. Mac-specific Jobs may log test-only C syntax results, but cannot treat them as timing/waitpid/KILL evidence. Always capture exact Base SHA, Head SHA, Git Tree, per-Job raw error cause and expected/unexpected RED breakdown in the PR `READY_FOR_REVIEW` comment.

**Only after fresh independent Standards/Spec code-review PASS on the new fixed Head** may R2b-R2 implement the native C Helper in a new stacked PR, still under the no-signal compile and mutation gates. No real TERM/SIGKILL is authorized by passing these R1 contracts. T04/T08b/T10 remain `NOT_RUN/BLOCK`. `group_kill_authorized=false`, `reuse_proven=false`, `g2_qualified=false`; G2/G3/G4/G5/production execution stay BLOCK.
