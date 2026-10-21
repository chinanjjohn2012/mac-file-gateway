# B03-T01-R2a — Pure Gate GREEN / strictly NO GROUP SIGNAL

**Status:** AUTHOR IMPLEMENTATION UNDER VALIDATION; independent Standards / Spec code review and native-run admission still REQUIRED. This narrow stage is **R2a**, not the entire B03-T01-R2 native execution gate.

## Fixed upstream approvals and scope

- Independently reviewed T01-D1 design: [PR #37](https://github.com/chinanjjohn2012/mac-file-gateway/pull/37) Head `30c74b50d12e9d5763054da48be1d612b4b9fc02`.
- Independently reviewed immutable T01-R1 behavior contract: [PR #38](https://github.com/chinanjjohn2012/mac-file-gateway/pull/38), Head `d6ca7afa15642c82da263ffa6bb75063bbe0ac29` / Git Tree `492936df48b37273d84368f51bec38c33c2a4273`. GitHub COMMENT Review #5603243999 concluded Standards PASS / Spec PASS; P2-01 through P2-06 CLOSED. This does not authorize Native KILL.
- Frozen 11-mode B03-R1 RED test remains unchanged. Native C Helper `tools/research/c3_candidate_b_kill.c` and Native Runner `tools/research/run_c3_candidate_b_kill.py` remain **ABSENT**. PR #36 B03-R2 NOTE_EXIT preflight does not replace lawful Worker waitpid.
- This stacked Draft PR introduces precisely one **pure Python** research Gate, a dedicated no-signal GREEN test workflow, a small synthetic-only guard test, this document and their Manifest SHA256 entries. No application/Gateway/ExecSupervisor, live process API, shell, kill syscall, raw host PID/PGID, external path or service.

## Pure Gate contract implementation

`tools/research/c3_candidate_b_kill_t01_gate.py` implements the unchanged T01-R1 interface:

1. `derive_cutoffs(t0_ms, outer_budget_ms, cleanup_reserve_ms, term_grace_ms, kill_entry_margin_ms)` requires exact positive integer budgets and strictly positive startup reserve; derives only one original monotonic outer deadline, TERM cutoff, KILL cutoff. A second independent vector and shifted t0 are in the unchanged R1 tests.
2. `term_admitted()` and `kill_admitted()` are **pure Boolean predicates on synthetic claims**, with exact field-set/type validation, positive reserve, strictly-before cutoff admission, true post-TERM identity/witness claims and genuine elapsed grace. An input `True` is not kernel evidence.
3. `begin_ledger()` issues a *test-only* inspectable Mapping authority, externally immutable as a Mapping. Internal state is **single-use and shared by all aliases**; copying it into a public dict loses the internal simulated TERM event proof. A call to the in-memory test recorder that responds `OK` is required to attach that proof, exact `term_sent_at_ms` and the fixed opaque synthetic target token. Public `term_succeeded=True` flags alone never authorize KILL.
4. `attempt_term_no_signal()` and `attempt_kill_no_signal()` check admission **at the Recorder boundary**, not merely in a separately tested predicate. Invalid/missing/incorrectly-typed facts, malformed deadlines, wrong target, missing/mismatched simulated TERM event, stale/late grace or closed authority do **not** call the Recorder. Refusal closes authority so a later valid input cannot revive it. The first simulated KILL attempt irreversibly sets `signals_closed=True`, even if its in-memory transport returns EPERM, ESRCH, EINTR or raises an exception; no retry or fallback.
5. `classify_t01()` verifies the frozen T01 `escalate-positive` record's **entire exact schema** and field values: integer flag type (reject `True == 1`), enum type and values, unique T01 mode, and no additions/omissions. `POSITIVE_EXPERIMENT` for a fixture is **only classification of fake data**, not lawful native Worker/Anchor `waitpid` evidence or successful SIGKILL.
6. `t01_mode_admitted()` allows only literal `escalate-positive`, independently of either Boolean orphan-preflight flag; all other 10 frozen B03-R1 modes and malformed/unknown inputs refuse.

This implementation has **no signal-capable transport**. `_FIXTURE_TARGET="fixture:synthetic-owned-anchor-group-T01"` is an intentionally nonnumeric non-host-owned token. The `_Ledger` provenance is only in-process integrity for unit tests, never a privilege mechanism acceptable to a future Native Owner. Future native process identity and `waitpid` evidence must be obtained independently at the actual syscall boundary.

## CI and review boundary

`.github/workflows/c3-candidate-b-t01-pure-gate.yml`:

- Executes only on its isolated research branch push or matching in-repo PR head, with macOS ARM64 3.13 and 3.14, plus Linux 3.13. No environment with signal authority.
- Before importing/executing the Gate, verifies exact checkout SHA, complete `MANIFEST.sha256`, absence of Native C Helper/Runner, Python AST import and call denylist, architecture and bytecode compilation.
- Re-runs the **unchanged** previously reviewed R1 contract `tests/test_c3_candidate_b_t01_contract_red.py` plus additional R2a synthetic-only guards, with natural/non-inverted pytest exit. Their expected outcome is a genuine **GREEN** at the pure Python level. R1's old RED-specific workflow remains frozen and is guarded to its own branch.
- The full Linux suite may still be **FAILURE** due to the separately frozen 19 missing Native Forced Group KILL B03-R1 contracts. This is expected but must be evidenced; do not claim all CI green.

## Explicit future admission stops

**T01-R2b Native design/code/admission is NOT IMPLEMENTED or APPROVED by R2a.** Its remaining prerequisites include frozen architecture-specific timing and self-expiry vectors; complete Native Owner/Anchor/Controller/Worker identity and lawful distinct-parent waits; robust process/FD and orphan cleanup; C no-signal gate-bypass Mutation interception; and explicit operator-only exact-SHA, protected environment and *manual* native-run authorization. Ordinary push/PR actions cannot trigger a group SIGKILL job.

T04/T08b/T10 stay **NOT_RUN/BLOCK**. Product G2/G3/G4/G5, ExecSupervisor, REST/MCP Multi-Workspace Exec remain BLOCK. `group_kill_authorized=false`, `reuse_proven=false`, `g2_qualified=false`. No merge/release/deploy is authorized.

**Independent reviewer:** freeze R2a Base, Head and Tree; inspect exact T01-R1 unchanged test GREEN, R2a integrity guards, real original macOS and Linux CI logs, absolute deadline and immutable ledger handling, strict classifier, and **lack of live signal/process capability**. Do not inherit the upstream PASS after this Head changes.
