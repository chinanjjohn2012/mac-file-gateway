# R2-T02-B0 — Exec state startup, ownership lock, quarantine only

**Staged product implementation, NOT T02-B completion or release
authorization.**

R2-T02-A RED is independently PASS on PR #62 at Head
\`3a437244bb604c95f8669557142c53eba0bfec69\`,
Review #5625923825. Approved T01 private-store primitives come from
PR #60 Head \`10521900e5232ceb7f746f35a73fa811deae20f5\`.

## B0 limited scope

1. Integrate T01 ExecStateStore at Multi-Workspace service startup
   **only when effective Exec is enabled**; attach the lifetime
   Gateway-private owner lock, scan before exposing the service,
   release only on drained service close.
2. Any corrupt/unresolved persisted intent, competing owner or
   unsafe state root denies both dry_run and apply, without replay,
   signals or modification to forensic state files; independently
   granted File/Git APIs remain separate.
3. Expose sanitized \`durability_state\`, \`quarantined\` and
   \`quarantine_reason_code\` at service info; this B0 step does
   not yet revise the historical healthy Exec \`available\` flag
   because ordinary proof-gate integration and test bridge are
   not complete. Those remain T02-B1.
4. Add genuine disk, lock, quarantine, corruption, no-process
   restart and File read tests. Keep ALL existing product and
   real-disposable-process regression tests unchanged; verify
   new tests physically RED before implementing production code.

## Explicit unfinished D0 work / stop

B0 **does not implement** ordinary cleanup-proof rejection on a
healthy state, internal nonserializable test-only grant, or
PREPARED/RUNNING/RETIRED lifecycle. Thus a healthy old candidate
can still allow execution when both grants are enabled, as before
this incremental PR; **never enable production Exec** until T02-B1
and later R2-T02-C gates are independently satisfied.

Immediately following this bounded B0 batch, create a separately
reviewed internal disposable acceptance qualification/harness that
preserves PR #56 real subprocess, HTTP/MCP and disconnect regression.
It must be identity/FD/instance-bound, test-only, nonserializable,
created by a trusted private fixture, NEVER by configuration,
environment or client. Only then can T02-B1 safely add the
unconditional healthy no-proof denial without deleting/skipping
historical coverage. Later C batches must still add actual
durable PREPARED, UNKNOWN, cleanup and safe retirement; nothing
in B0 validates detached descendants or full-tree cleanup.

PR #56–#60, #62 and this PR remain Draft/unmerged/undeployed;
production Exec OFF; no local Mac Gateway/Tunnel restart; Native C
research paused; no unmanaged process signals, merge, tag or deploy.
