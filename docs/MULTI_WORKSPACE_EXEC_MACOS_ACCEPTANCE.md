# Multi-Workspace Exec — macOS ARM64 real lifecycle acceptance

**Status:** PRODUCT ACCEPTANCE TEST CANDIDATE, PENDING MACOS CI. This
separate test PR is stacked on PR #56's independently reviewed Head
`e528ddb809df897b4f81802e0ae5f4f95ff5d2c7`. It does not revise
that Head or authorize a product merge or production activation.

## Actual acceptance surface

- GitHub-hosted **macos-15 / arm64**, Python 3.13. Require `uname -s=Darwin`
  and `uname -m=arm64`; print the fixed PR Head and Git Tree.
- Temporary, private `gateway.json` and **two disposable Workspace roots**.
  Explicit global + Workspace Exec grants only for one test root; Git and
  File Write remain disabled. No user Workspace, AWS key, or production
  connection is used.
- Start real Multi Gateway Uvicorn subprocess on dynamically selected
  **127.0.0.1** port, use standard TCP client and actual MCP SDK route.
- Exercise live REST preview/apply, denied Workspace B, modern MCP
  `run_command` preview/apply and permission denial.
- Start a real disposable Python parent and linked child. On configured
  command timeout, prove a timeout response and that the linked child
  **stops making progress**, not merely that the leader exited.
- Send a **single** REST command and a **single** modern MCP command over
  separate real TCP sockets; close each client after observing a started
  Worker. Prove its execution lease remains held, another Workspace's
  read still works, and execution completes once without automatic retry.
- Send a started command and close its TCP socket; signal only the
  **fixture's own Gateway subprocess** to stop. Check it does not exit
  while the temporary Worker is blocked; release and verify bounded exit.
- Run the existing disposable Multi Exec pytest regressions on macOS ARM64.

## Explicit exclusions and success language

If all steps pass, result is **PARTIAL_NATIVE_ACCEPTANCE_PASS** for
actual macOS ARM64 REST/MCP execution, linked-child group-timeout behavior,
TCP disconnect and ordinary Uvicorn stop/wait. Do **not** call this
complete macOS/native execution qualification or production release PASS.

These steps do **not** prove: detached child/process-group escape cleanup,
cleanup-failure quarantine, crash/restart state recovery, a production
Tunnel, or all operating-system-level Workspace isolation. Existing
`CommandRunner` does not claim full descendant reaping; no Native C or
Candidate C dynamic library is loaded or invoked.

Fail closed on any mismatch. Never turn a failing macOS job into a
passing status solely by changing result text or ignoring failures.
Investigate fixed-SHA raw GitHub Job logs and create a follow-up
product bug if incomplete cleanup is reproduced.

No merge, deployment, tag, enabling production Exec, external network
routing, privileged signals, or Native C safety research is authorized.
