# B03-T01-R1 — Contract RED / NO GROUP SIGNAL

**Status: CONTRACT RED ONLY — native TERM/SIGKILL NOT_AUTHORIZED; independent code review PENDING.**

**Frozen T01-D1 design:** PR #37 at `30c74b50d12e9d5763054da48be1d612b4b9fc02` (externally independently reviewed Standards PASS / Spec PASS). This document introduces *no design changes* and gives no further native-signal permission.  
**Frozen full B03-R1:** PR #34 at `d460052c68bbb723b6dd7597e950c66aab8cbf21`. Its 11 mode contracts, flags, enum schema, mutation inventory, and existing intended RED remain untouched.  
**B03-R2 no-signal preflight:** PR #36 at `ecbb5790edf75458f9e30ec4e507ca4906d383fe`; targeted Standards PASS / Spec PASS, but native Worker NOTE_EXIT is not Controller legal Worker `waitpid`.

## 1. Narrow scope, negative authority

This T01-R1 branch adds only:
1. `tests/test_c3_candidate_b_t01_contract_red.py`, a pure Python test-only contract (no spawning; no PID/PGID syscalls; no `ctypes`; no host signals).
2. `.github/workflows/c3-candidate-b-t01-contract-red.yml`, macOS ARM64 Python 3.13/3.14 and Linux 3.13 contract-only CI. The job **must actually FAIL** pytest for missing implementation.
3. This contract reference.
4. Their exact SHA256 entries in `MANIFEST.sha256`.

Forbidden in R1: any `tools/research/c3_candidate_b_kill.c`, `tools/research/run_c3_candidate_b_kill.py`, `tools/research/c3_candidate_b_kill_t01_gate.py`, a native-signal-capable workflow, a privileged environment approval, host PID/PGID inputs, product code changes, or runtime group TERM/KILL. A successful imported pre-signal C Helper from PR #36 is **not** permission for actual T01 SIGKILL.

The only supported target in the signal-free fixture is the **opaque nonnumeric** token `fixture:synthetic-owned-anchor-group-T01`. The fixture's `NoSignalRecorder.send(action, token)` validates the token and appends to an in-memory array. It cannot signal processes. "OK" or "EPERM" from this fixture represents a **synthetic transport return**, never a real kernel result. In particular, no forged complete record may be reported as native evidence or product-level G2 success.

## 2. Required future *pure* gate API — absent at this R1 Head

The test suite intentionally imports an **absent** Python research-only module `tools/research/c3_candidate_b_kill_t01_gate.py`. All these APIs remain RED until separately implemented and reviewed; *no R1 stub or fixed positive-return module shall be inserted*.

| API | Frozen test-facing contract |
| --- | --- |
| `derive_cutoffs(t0_ms, outer_budget_ms, cleanup_reserve_ms, term_grace_ms, kill_entry_margin_ms)` | Exact dict with keys `t0_ms`, `outer_deadline_ms`, `kill_cutoff_ms`, `term_cutoff_ms`, `cleanup_reserve_ms`, `term_grace_ms`, `kill_entry_margin_ms`. Strict positive budgets; otherwise raises `ValueError` |
| `term_admitted(cutoffs, now_ms, facts)` | Pure bool. Require all fixed `TERM_FACTS` as **exact bool True**, live native-check *claims* and `now_ms < term_cutoff_ms`; equality refused |
| `kill_admitted(cutoffs, now_ms, term_sent_at_ms, facts)` | Pure bool. Require all fixed `KILL_FACTS` as exact True, term legitimately before original term cutoff, `now_ms >= term_sent_at_ms + grace_ms`, `grace_end < kill_cutoff_ms`, and `now_ms < kill_cutoff_ms`. No rebase of original `t0_ms` |
| `begin_ledger()` | Fresh typed ledger: `term_attempts=0`, `term_succeeded=False`, `kill_attempts=0`, `kill_succeeded=False`, `signals_closed=False`, `group_signals_after_close=0`, `kill_errno_class="NONE"` |
| `attempt_term_no_signal(cutoffs, now_ms, facts, ledger, recorder, owned_ref)` | No external signal; try only if TERM admitted and ledger unused. Increment term attempts immediately before single in-memory recorder call. Any error closes authority, no retry |
| `attempt_kill_no_signal(cutoffs, now_ms, term_sent_at_ms, facts, ledger, recorder, owned_ref)` | No external signal; require prior successful TERM, zero previous KILL, open ledger and new native-check claims. On first simulated KILL attempt, increment count, irreversibly close all group signal authorization on both success and error. Never retry/fallback |
| `classify_t01(record)` | Strict schema classification *only*. Compare against the **unchanged** `escalate-positive` record from frozen B03-R1, rejecting missing, extra, wrong-typed or downgraded evidence as `BLOCK`. This is not an actual Darwin observation |
| `t01_mode_admitted(mode, orphan_preflight_proven=...)` | Admit **only** `escalate-positive` into T01 planning, even if a prior isolated orphan preflight happened; all other modes, especially T04/T08b/T10, refuse |

The `facts` map uses exact keys frozen in the test file. Each True value is a **claim of already-acquired evidence** for pure contract testing; a future native signal entry must independently verify real Darwin Kernel and IPC facts at the final signal boundary, not accept callers' booleans or blindly reuse this Python result.

### Frozen timing vector (pure arithmetic only)

- `t0_ms=100000`, `outer_budget_ms=12000` -> `outer_deadline_ms=112000`.
- `cleanup_reserve_ms=3000` -> `kill_cutoff_ms=109000`.
- `term_grace_ms=200`, `kill_entry_margin_ms=300` -> `term_cutoff_ms=108500`.
- `term_now_ms=108000`, `term_sent_at_ms=108000`; grace ends `108200`; `kill_now_ms=108300` is arithmetically inside the **test fixture** window.
- `term_now == term_cutoff`, `kill_now == kill_cutoff`, `kill_now < grace_end`, late TERM and nonpositive budgets **all refuse**, even if native witness flags claim success.

These numbers are a *synthetic example*, **not** the measured Darwin ARM64 time vector or an authorization to execute signals. Independent R2 admission must freeze actual self-expiry and cleanup budgets.

## 3. What RED must detect

- Every missing/mismatched critical TERM/KILL native fact, including Anchor initial and post-TERM `SIGTERM=SIG_IGN`, unreaped held Anchor, Controller live in an outside group, Worker direct Controller parentage, unique trusted IPC writers and final native gate recheck.
- Failed, zero or expired deadline; exact cutoff equality; missing post-TERM sequence; Anchor prematurely reaped; Worker exits during grace; Controller lost.
- A no-signal transport that records an attempted TERM/KILL **before** a safety gate is checked. For all negative mutants, transport must have zero calls; the mock must not be confused with a successful real group syscall.
- Successful synthetic transport KILL still needs exact Worker Controller `waitpid`, Owner Anchor `waitpid`, trusted Final, verified resource closure and deadline evidence **to be classified** as a complete positive. Classification of a fixture record is not real wait evidence.
- On simulated EINTR/EPERM/ESRCH the ledger must close and never retry. After `SIGNALS_CLOSED`, absolutely no second TERM/KILL or individual-PID fallback.
- T04 / T08b / T10 (and any other non-T01 mode) stay `NOT_RUN/BLOCK` for native execution, regardless of isolated NOTE_EXIT success.

**Expected outcome:** Safety preflight and Manifest/AST/static guards PASS. Contract functions involving missing T01 pure gate module FAIL with explicit `EXPECTED RED` evidence. No `xfail`, `pytest.skip` (for missing gate), `|| true`, `continue-on-error`, fabricated native record or inverted exit. Preserve raw failed Actions logs and fixed Head/Tree when submitting R1 for review.

## 4. Additional native boundaries for R2 — NOT in R1

- Independently reviewed C Helper must use a non-racy authority design to the extent possible with Darwin semantics, a single Owner group-signaling lane, native `posix_spawn` enrollment, Controller-only Worker `waitpid` and Owner-only Anchor `waitpid`, plus post-TERM Anchor signal-disposition readback. **User-space PID/PGID checking is not a kernel-atomic reuse guarantee.**
- A deliberately **no-signal** C compile variant must intercept every gate-bypass mutation before a real group syscall. R1 Python pure mocks do not substitute for C-level mutation evidence.
- Operator-only real-signal CI must be manually authorized, pinned to an exact reviewed binary SHA, use a protected environment and be impossible to launch by ordinary untrusted PR/push. T01-R2 implementation must finish and receive an **independent run-admission approval** first.
- Before expanding orphan modes, add real native Controller EOF and Native Owner stall tests to complement the current Python fail-closed timeout unit tests. Not part of R1 and cannot be bypassed by PR #36 targeted PASS.

**Stage decision at creation:** `T01_R1_CONTRACT_RED_PENDING_VERIFICATION`; `group_kill_authorized=false`, `reuse_proven=false`, `g2_qualified=false`. **Do not merge or deploy.**
