# Multi-Workspace Exec — R1 deterministic RED contracts (product track)

**Status: TEST-ONLY / EXPECTED RED / INDEPENDENT R1 REVIEW REQUIRED.**
This is a stacked, separate PR on top of D0 DESIGN PASS:
[PR #58 Review #5623166343](https://github.com/chinanjjohn2012/mac-file-gateway/pull/58#pullrequestreview-5623166343),
fixed Head `bec02bbcb7d3bf1b60bd7a27aff1b4b68f0fbab1`.

The R1 changes consist exclusively of test assets, a dedicated CI workflow,
this evidence document and `MANIFEST.sha256`. Do not edit the approved
Python product implementation, the already reviewed #56/#57/#58 sources,
or the Candidate C / Native C research line.

## 1. RED is intentional, but only when precisely classified

There are **two independent acceptance signals** for this R1 PR:

1. The existing `controlled-exec-tests` Linux workflow (including full
   default `pytest`, HTTP/MCP/stdIO/disconnect and Git smoke) must be
   **GREEN** on the exact new Head and Git Tree.
2. The new `multi-exec-r1-red.yml` workflow must also be **GREEN as a
   *RED verifier***. It explicitly runs a separate, deliberately
   non-default-collected contract file and requires the exact expected
   contract assertions to **FAIL** with `R1_RED_` markers, without
   collection/import errors, skips, unrelated crashes or unexpected
   successful tests. It first re-runs the default product suite.
   This result is named `RED_CONFIRMED_NOT_IMPLEMENTED` — it is **not**
   implementation GREEN or an acceptable released product build.

The contract file is named
`tests/r1_contracts/contract_multi_exec_recovery_r1.py`, not
`test_*.py`, and ordinary `python -m pytest -q` will not discover it.
Do not rewrite existing pytest tests or weaken the baseline assertions.
`tools/verify_multi_exec_recovery_r1_red.py` uses JUnit case names,
failure markers and exact test-group counts, rejects even one
unrecognized failure, and also requires known currently existing
deny-policy guardrails to continue **PASS**. REST probes MUST use a
127.0.0.1 loopback Host; a boundary-generated HTTP 421 or an unrelated
wrong error code is test-infrastructure failure, never an accepted RED. The checker must be
removed/replaced for R2 implementation verification; it is not a
production feature flag or a general CI tolerance for failing tests.

## 2. Evidence taxonomy and coverage boundary

**Actual current-product behavioral failures (test-level, no spawn):**

- Normal Gateway global + Workspace opt-in is not enough to apply
  without independent cleanup proof; direct/REST/MCP require
  `exec_cleanup_proof_required` before the fake CommandRunner.
- Headers/arguments/config/environment cannot grant an internal
  disposable-test completion scope. Existing rejection guards
  must remain GREEN.
- `available=false` without proof; `/info` and `/health` agree on
  `exec_policy`, capability exposure is not safe admission.
- Foreign files, an incomplete atomic temp, symlink/hardlink state,
  conflicting owner or unreadable state root must not become
  in-memory healthy Exec after service initialization.
- A quarantined dry-run is rejected; independent Workspace file
  reads and Git permissions remain available only under their own grants.
- An ambiguous sync Worker failure must conservatively latch
  `UNKNOWN`/quarantine, persist that admission block across restart,
  and never signal a stale PID/PGID found in state.

All product entrypoint tests monkeypatch the per-Workspace
`Gateway.run_command` (or deliberately make it raise) **before
any allowed command is launched**. They do not invoke Python scripts,
a real subprocess, OS signals or an external Tunnel.

**Internal fault-injection contract requiring R2's private seam:**

D0 sections A–L require precise filesystem durability / atomicity
faults, direct leader/group observation, test-only evidence scope and
crash window simulation. The R1 file defines an explicit scenario
table for these. The table presently fails with
`R1_RED_INTERNAL_PROBE_MISSING` until R2 provides a narrowly scoped
**internal-only** probe. Its expected outcomes are still asserted:
`outcome_code`, `spawn_attempts`, `quarantined`, and, when relevant,
`cleanup_scope`, `full_descendant_tree_clean`, `retry_count`,
`removed_unresolved_markers`.

The eventual probe must use an owned disposable fixture, mock/dummy
spawn and deterministic injected fault points. It must not be
reachable through `gateway.json`, REST/MCP, environment, public CLI,
production Workspaces or network calls. Test authors may adapt its
private wiring as R2's implementation is reviewed, but must not
silently weaken the listed scenario outcomes. In particular, the
current missing-probe RED **does not prove** that a per-case durability
fault has been observed yet. That implementation-level evidence is
a separate R2/R3 gate.

The R1 matrix includes:

| Contract | Test coverage |
| --- | --- |
| A | intent file/directory fsync and rename fail before spawn, owner lock, invalid state |
| B | no-spawn deadline, ambiguous Popen, wait, stream drain and final fsync failure |
| C | crashes at PREPARED/Popen/leader reap/final retirement; no restart replay |
| D | worker lease stays through durable finalization and cancellation |
| H | ordinary double opt-in applies default-DENY cleanup proof |
| I | private scoped grant allows only original-group test-only retirement |
| J | forged/mismatched/expired grant or detached child does not undo UNKNOWN |
| K | quota 4096 records, 4096 bytes each, 16 MiB aggregate; durable RETIRED-only pruning |
| L | status parity, conservative availability and structured REST/MCP denial |

Positive test-only outcomes **never** assert
`full_descendant_tree_clean=true`, production full-tree clean,
or authorization to run unrestricted project code.

## 3. Review and handoff gates

Independent reviewer must inspect actual new file content and diff,
fixed Head+Git Tree, original normal and R1 RED Jobs, verifier logic,
the exact D0 Review, and confirm all claimed RED failures arose
from contract predicates and/or explicitly labelled missing internal
probe — not Python import errors, pytest collection, environmental
disruption, timeouts or source mismatches.

The review should explicitly distinguish:

- Existing behavior confirmed to violate D0 (live entrypoint RED).
- Future private internal fault scenarios specified but still
  uninstrumented (missing-probe RED).
- Existing guards deliberately GREEN.
- Remaining R2 implementation and R3 macOS/Tunnel/protected-worker
  gates NOT_RUN.

Do not report `R1_GREEN`, `R2_IMPLEMENTED`, successful durability,
full descendant reaping, cleanup quarantine recovery or production
readiness on this R1 result. Even if the R1 workflow passes, it means
**the RED expectation verifier passed**, not that the application now
satisfies the new lifecycle contract.

**STOP:** No Native C/Candidate B, no process-tree signal research,
no real local Gateway or production project execution, no merge,
deployment, tag, production Exec enable, forced external process
shutdown, automatic recovery or remote reset. PR #56/#57/#58
stay Draft, unmerged; their historical fixed-SHA Reviews remain
separate from this R1 work.
