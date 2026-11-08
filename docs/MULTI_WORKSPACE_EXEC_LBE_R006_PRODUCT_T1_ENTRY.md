# R006 tracked PRODUCT_T1 entrypoint - source candidate only

`tools/lbe_r006_product_t1.py` is the reviewed direct-route entrypoint for a
future separately authorized disposable macOS T1. It loads only the private
SHA-bound reviewed source bundle, constructs the normal WorkspaceService,
uses the canonical R006 prepare/bootstrap/install harness, and finally calls
the same `WorkspaceService.invoke_exec(..., dry_run=False)` used by Direct,
REST and official MCP.

It does not add an alternate launcher, client capability, config authority or
owner/review/runtime fields to the Exec request. If any source bundle, FULL
review, live run, direct-owner grant, durable nonce or Runner check is missing,
the shared gate fails closed before a child.

This entrypoint is committed **before** r006 code freeze so a later authorized
T1 does not introduce unreviewed execution code. It is NOT_RUN in the current
development round. Real PRODUCT_T1 still requires explicit exact-run user
authorization after the frozen Head obtains B/C FULL review.
