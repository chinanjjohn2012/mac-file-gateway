# R006 private native Runner source boundary - SAFE T0 candidate

This commit adds the first **private** source path that contains the future
Popen call for R006. It is deliberately not registered with
WorkspaceService.invoke_exec, REST, official MCP, config or a client token.

The boundary requires:
- exact WorkspaceContext + LbeWorkPlan + source-only D4NativeLaunchRecipe;
- process-bound D4ConsumedOwnerGrant created only after durable nonce fsync;
- existing D4OneUseAttemptMarker for first-party/staged/loader rechecks;
- fixed prior-run macOS selected-source profile, re-read immediately before
  Popen;
- exact closed environment and fixed argv/cwd.

Known pre-Popen denial returns a proven no-child witness. Once Popen is
entered, exceptions are not treated as proof of no child; Worker must latch
uncertainty. Tests replace Popen with a fake and therefore are T0/mock only.

Real macOS PRODUCT_T1, actual GitHub owner comment fetch, public positive Exec,
T2/T3 and production remain NOT_RUN/NOT_AUTHORIZED.
