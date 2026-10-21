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

Forbidden at the *frozen R1 RED Head* (and enforced by its phase-specific workflow): any `tools/research/c3_candidate_b_kill.c`, `tools/research/run_c3_candidate_b_kill.py`, `tools/research/c3_candidate_b_kill_t01_gate.py`, a native-signal-capable workflow, a privileged environment approval, host PID/PGID inputs, product code changes, or runtime group TERM/KILL. **The shared pytest behavior contract must not assert that its future correct gate implementation stays absent.** The R1 workflow alone checks these files are absent; a separately reviewed R2 GREEN workflow may legitimately have the pure gate module and native research artifacts, without rewriting this shared contract. A successful imported pre-signal C Helper from PR #36 is **not** permission for actual T01 SIGKILL.

The only supported target in the signal-free fixture is the **opaque nonnumeric** token `fixture:synthetic-owned-anchor-group-T01`. The fixture's `NoSignalRecorder.send(action, token)` validates the token and appends to an in-memory array. It cannot signal processes. "OK" or "EPERM" from this fixture represents a **synthetic transport return**, never a real kernel result. In particular, no forged complete record may be reported as native evidence or product-level G2 success.

## 2. Required future *pure* gate API — absent at this R1 Head

The **R1 baseline** intentionally does not provide `tools/research/c3_candidate_b_kill_t01_gate.py`, so its behavior tests are expected RED. The **same unmodified behavior assertions must later be satisfiable** after independently approved R2 implementation. Absence is checked only by the R1-stage workflow, not a contradictory test in the shared pytest module. No R1 stub or hardcoded positive-return module may be inserted.

| API | Frozen test-facing contract |
| --- | --- |
| `derive_cutoffs(t0_ms, outer_budget_ms, cleanup_reserve_ms, term_grace_ms, kill_entry_margin_ms)` | Exact dict with keys `t0_ms`, `outer_deadline_ms`, `kill_cutoff_ms`, `term_cutoff_ms`, `cleanup_reserve_ms`, `term_grace_ms`, `kill_entry_margin_ms`. Strict positive budgets; otherwise raises `ValueError` |
| `term_admitted(cutoffs, now_ms, facts)` | Pure bool. Require all fixed `TERM_FACTS` as **exact bool True**, live native-check *claims* and `now_ms < term_cutoff_ms`; equality refused |
| `kill_admitted(cutoffs, now_ms, term_sent_at_ms, facts)` | Pure bool. Require all fixed `KILL_FACTS` as exact True, term legitimately before original term cutoff, `now_ms >= term_sent_at_ms + grace_ms`, `grace_end < kill_cutoff_ms`, and `now_ms < kill_cutoff_ms`. No rebase of original `t0_ms` |
| `begin_ledger()` | Fresh inspectable ledger, with `term_attempts=0`, `term_succeeded=False`, `kill_attempts=0`, `kill_succeeded=False`, `signals_closed=False`, `group_signals_after_close=0`, `kill_errno_class="NONE"`. Any later TERM success must additionally be associated with a **non-forgeable-in-this-pure-test** event provenance that cannot be recreated by `{**ledger, "term_attempts": 1, "term_succeeded": True}`; an immutable mapping/opaque event reference is one viable implementation. This is *only* simulated recorder provenance, not Darwin signal authority. |
| `attempt_term_no_signal(cutoffs, now_ms, facts, ledger, recorder, owned_ref)` | No external signal; try only if TERM admitted and ledger unused. Increment term attempts immediately before one memory recorder call. On success, store exact `term_sent_at_ms=now_ms`, `term_target_ref=owned_ref`, and event provenance derived from that **actual recorder call** (not public booleans). Any error closes authority. Repeated TERM after either success/failure is refused **and closes authorization**; a KILL-closed ledger also prohibits TERM. |
| `attempt_kill_no_signal(cutoffs, now_ms, term_sent_at_ms, facts, ledger, recorder, owned_ref)` | No external signal; require a **genuine simulated** prior successful TERM event from the same still-authorized ledger and target, `term_sent_at_ms == ledger["term_sent_at_ms"]`, `owned_ref == ledger["term_target_ref"]`, zero prior KILL, open ledger, and new gate facts. Caller-supplied timestamp or forged dict must never bootstrap authority. Any failed admission closes authorization without a transport call. On first simulated KILL attempt, increment count and irreversibly close group signals on both success and error. Never retry/fallback. |
| `classify_t01(record)` | Strict *pure data* classification only. Require `mode` present and exactly `"escalate-positive"`, all frozen `BOOL_FIELDS` of **exact type `int` (not `bool`)**, and `ENUM_FIELDS` of exact type `str`. Reject missing/extra fields, cross-mode records, downgraded evidence, wrong types, `True == 1` coercion, and unsupported values as `BLOCK`. An accepted fixture still is **not** a native Darwin Wait. |
| `t01_mode_admitted(mode, orphan_preflight_proven=...)` | Admit **only** `escalate-positive` for either Boolean value of `orphan_preflight_proven`. Reject **all other 10 modes** from the frozen 11-mode B03-R1 `MODES` tuple (including T02/T03/T05/T06/T07/T08a/T09 and T04/T08b/T10), unknown strings, empty strings, `None` and wrong-typed/unhashable inputs with **exact `False`**, not exception or truthiness |

The `facts` map uses exact keys frozen in the test file. Each True value is a **claim of already-acquired evidence** for pure contract testing; a future native signal entry must independently verify real Darwin Kernel and IPC facts at the final signal boundary, not accept callers' booleans or blindly reuse this Python result.

### Frozen timing vector (pure arithmetic only)

- `t0_ms=100000`, `outer_budget_ms=12000` -> `outer_deadline_ms=112000`.
- `cleanup_reserve_ms=3000` -> `kill_cutoff_ms=109000`.
- `term_grace_ms=200`, `kill_entry_margin_ms=300` -> `term_cutoff_ms=108500`.
- `term_now_ms=108000`, `term_sent_at_ms=108000`; grace ends `108200`; `kill_now_ms=108300` is arithmetically inside the **test fixture** window.
- `term_now == term_cutoff`, `kill_now == kill_cutoff`, `kill_now < grace_end`, late TERM and nonpositive budgets **all refuse**, even if native witness flags claim success.
- **Discriminating late-TERM counterexample:** `term_sent_at_ms=108501` is **after** `term_cutoff_ms=108500`; `grace_end=108701`, `kill_now=108702` is **after** grace and **before** `kill_cutoff_ms=109000`. Reject specifically for late TERM, rather than accidentally because grace has not completed.
- **Independent second vector:** `t0=30000`, `outer_budget=21000`, `reserve=6000`, `grace=900`, `margin=600`, giving `outer=51000`, `kill_cutoff=45000`, `term_cutoff=43500`. A delayed TERM at `43501` with KILL entry `44402` must refuse; shift `t0` to `230000` and recheck the same relative budgets to prohibit hardcoded first-vector logic.

These numbers are a *synthetic example*, **not** the measured Darwin ARM64 time vector or an authorization to execute signals. Independent R2 admission must freeze actual self-expiry and cleanup budgets.

## 3. What RED must detect

- Every missing/mismatched critical TERM/KILL native fact, including Anchor initial and post-TERM `SIGTERM=SIG_IGN`, unreaped held Anchor, Controller live in an outside group, Worker direct Controller parentage, unique trusted IPC writers and final native gate recheck.
- Failed, zero or expired deadline; exact cutoff equality; missing post-TERM sequence; Anchor prematurely reaped; Worker exits during grace; Controller lost.
- A no-signal transport that records an attempted TERM/KILL **before** a safety gate is checked. Both `attempt_term_no_signal()` and `attempt_kill_no_signal()` must reject **every** independently missing/False/wrong-type fact from `TERM_FACTS` and `KILL_FACTS`, respectively, not just their standalone `term_admitted()`/`kill_admitted()` counterparts. Each fault starts from **fresh** ledger state; each KILL fault starts from a **real successful simulated TERM recorder event**. `recorder.calls` stays empty for the refused signal, the relevant attempt count stays unchanged, and authority becomes/stays `signals_closed=True`, including when a later call supplies correct facts. Pure mocks do not establish real kernel safety.
- The two attempt entrypoints must independently refuse TERM cutoff **equality/late**, KILL cutoff **equality/late**, Grace-before-entry, delayed TERM at `108501` with KILL entry at `108702`, and changed or missing post-TERM witness. No rejected call may reach even the in-memory recorder. This is distinct from directly testing `term_admitted()` and `kill_admitted()`.
- Successful synthetic transport KILL still needs exact Worker Controller `waitpid`, Owner Anchor `waitpid`, trusted Final, verified resource closure and deadline evidence **to be classified** as a complete positive. Classification of a fixture record is not real wait evidence.
- On simulated EINTR/EPERM/ESRCH the ledger must close and never retry. A successful TERM cannot be attempted again; a failed TERM cannot be retried. After `SIGNALS_CLOSED`, absolutely no second TERM/KILL or individual-PID fallback.
- Direct KILL without a recorder-confirmed TERM, a forged `term_succeeded=True` copied dict, a caller-supplied mismatched/late TERM timestamp, and a changed target token cannot cause even a memory recorder KILL. Mutation setup must obtain its positive TERM prerequisite by *calling* `attempt_term_no_signal`, not `dict.update` on public flags.
- `classify_t01` is independently mode-pinned; every flag must remain an exact `int` rather than a Python `bool`. Even a complete string/numeric-equivalent record is `BLOCK` if wrong-typed or from T04/T08b/T10. Fixture classification NEVER establishes actual `waitpid` evidence.
- **All 11 frozen modes** are exercised at the T01-only mode admission interface with both `orphan_preflight_proven=False` and `True`: exactly `"escalate-positive"` may return `True`. T02, T03, T05, T06, T07, T08a and T09 are refused **alongside** T04, T08b, T10. Unknown/malformed mode inputs must return exact `False` without exception. This is a pure planning-mode gate only, not a native-run admission.

**Expected outcome:** Safety preflight and Manifest/AST/static guards PASS. Contract functions involving missing T01 pure gate module FAIL with explicit `EXPECTED RED` evidence. No `xfail`, `pytest.skip` (for missing gate), `|| true`, `continue-on-error`, fabricated native record or inverted exit. Preserve raw failed Actions logs and fixed Head/Tree when submitting R1 for review.

## 4. Additional native boundaries for R2 — NOT in R1

- Independently reviewed C Helper must use a non-racy authority design to the extent possible with Darwin semantics, a single Owner group-signaling lane, native `posix_spawn` enrollment, Controller-only Worker `waitpid` and Owner-only Anchor `waitpid`, plus post-TERM Anchor signal-disposition readback. **User-space PID/PGID checking is not a kernel-atomic reuse guarantee.**
- A deliberately **no-signal** C compile variant must intercept every gate-bypass mutation before a real group syscall. R1 Python pure mocks do not substitute for C-level mutation evidence.
- Operator-only real-signal CI must be manually authorized, pinned to an exact reviewed binary SHA, use a protected environment and be impossible to launch by ordinary untrusted PR/push. T01-R2 implementation must finish and receive an **independent run-admission approval** first.
- Before expanding orphan modes, add real native Controller EOF and Native Owner stall tests to complement the current Python fail-closed timeout unit tests. Not part of R1 and cannot be bypassed by PR #36 targeted PASS.

**Review status after independent re-review of P2-01～P2-04:** that prior review (Head `2660fc6e3deac4a2463223009e663d3d7a10e566`) marked **P2-01～P2-04 CLOSED**, but found two additional blocking contract gaps: **P2-05 attempt entrypoint gate completeness**, **P2-06 complete 11-mode admission**. This revision adds only tests and this reference; author-side expected RED and **fresh frozen-Head independent Standards/Spec re-review** are required before closing T01-R1. The RED baseline still fails because the pure Gate module is absent; the same shared behavior contract must be satisfiable by future approved R2 GREEN code without changing tests. `T01_R1_CONTRACT_RED_PENDING_VERIFICATION`; `group_kill_authorized=false`, `reuse_proven=false`, `g2_qualified=false`. **Do not merge or deploy.**
