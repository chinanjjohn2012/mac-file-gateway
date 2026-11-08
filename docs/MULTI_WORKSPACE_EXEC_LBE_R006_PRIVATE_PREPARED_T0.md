# R006 shared one-shot product admission - SAFE T0/source candidate

The R006 product flow is intentionally split into verifier-owned preparation
and the existing shared public Exec admission point.

1. **Prepare**: private service code stages and rechecks the reviewed
   first-party/operator/Mach-O/private-dylib source set, observes the fixed
   macOS selected-source profile and creates one process-bound
   `D4R006PreparedAttempt`. No executable slot or durable nonce is consumed.
2. **Bootstrap**: service-owned GitHub fetchers verify one direct repository
   owner exact-attempt comment, current r006 B/C FULL review objects, the
   private G05 Head/Tree/Manifest receipt and the live GitHub Actions run.
3. **Install**: private in-process code installs exactly one
   `prepared + trusted bootstrap` pair in `WorkspaceService`. There is no
   REST/MCP/config/environment field for this operation.
4. **Shared request**: Direct, REST and official MCP continue to call the same
   `WorkspaceService.invoke_exec`. An ordinary schema-v2 apply remains F1
   denied. Only a request whose Workspace/cwd/argv/timeout exactly equals the
   installed one-shot can atomically take it.
5. **Consume before launch**: the prepared candidate is burned, current
   runtime/grant/review/source bindings are repeated, and the cross-process
   nonce is durably O_EXCL+fsync consumed before Worker reservation/Popen.
   Post-accept cancellation cannot restore the nonce.

Wrong requests do not consume the pending capability. A cancellation already
known before atomic request acceptance does not take it. Once a matching
request takes the capability, any later cancellation/error is fail-closed and
requires a fresh owner grant/nonce.

Current safe T0 tests replace the actual native child with fake Popen or an
explicit no-child witness. They cover Direct plus REST and official MCP on the
same `WorkspaceService`, and all six fixed Python Direct/Pipenv/Go vectors at
the final private native boundary.

This source is **not** evidence that PRODUCT_T1 has run. Real execution still
requires a frozen current code Head, valid B/C FULL code reviews, exact direct
owner run-attempt authorization, current GitHub-hosted macOS identity/source
qualification and a separately authorized native T1. No T2/T3, production,
user-Mac/Tunnel, merge/tag/release/deploy authority is created.
