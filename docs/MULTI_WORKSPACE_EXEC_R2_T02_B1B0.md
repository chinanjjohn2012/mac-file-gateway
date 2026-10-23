# R2-T02-B1-B0 — transport-owned disposable Listener evidence

**DRAFT, independent review REQUIRED.** This is the first bounded B1-B
batch, NOT the ordinary no-proof Default DENY, Worker durable lifecycle,
detached descendant cleanup, macOS R3, or production release.

Base: PR #64 B1-A independent Standards/Spec PASS on fixed Head
\`f75d4a3dc256eff5f9c1054e9d5e89bc4399fc11\`,
Review #5627504053. D0 authority is
\`docs/MULTI_WORKSPACE_EXEC_RECOVERY_D0_DESIGN.md\` §2.1, §4, §6, §7.

## Why B1-B0 is isolated

The B1-A predicate accepts the caller-provided literal
\`listener_host="127.0.0.1"\` for **test-only identity exploration**.
That string is trivially forgeable and **MUST NOT authorize a Worker**.
B1-B0 introduces a physically listening, private, in-process Uvicorn
transport belonging to the **same internal disposable fixture** and
the same B1-A service/grant instance. It provides an independent,
no-real-child provenance witness without changing the real product
CLI/REST/MCP/Worker admission code.

A factory, \`gateway._exec_test_transport.create_private_bound_transport()\`,
must have **no path, port, hostname, service or credentials parameter**.
It invokes the approved B1-A factory (which makes an entirely new
private 0700 root, pinned Exec state and one once-issued grant), binds
its own AF_INET/TCP socket to \`127.0.0.1:0\` and serves that exact
prebound socket with an in-process Uvicorn server and the real
\`create_multi_app(service)\` REST+SDK MCP entrypoints. Port is assigned
by the kernel; no prebind-port-selection race or exposure on \`0.0.0.0\`.

The transport's identity is the **object reference in the fixture**,
service reference, creating PID, pinned socket FD+inode, actual
\`getsockname()==("127.0.0.1",port)\`, \`SO_ACCEPTCONN\`,
thread and Uvicorn.started, and a real successful GET /health across
that *same port*. A string or a socket on a different fixture never
qualifies. \`grant.qualifies_transport(service,workspace,transport=...)\`
must require both this witness and B1-A's existing entire
service/Workspace/owner-lock/PID/ancestor identity predicate. The
service is not permitted to mint the witness itself from HTTP/MCP
arguments, \`Host\`, client IP, environment, config or CLI.

Closing transport must immediately invalidate/revoke qualification
and close the listener before releasing the disposable service. It
must be legal to call close twice, and forbidden to resume a revoked
grant even if an endpoint/port appears again.

## P2-01 — Listener shutdown failure retains FD ownership

[Independent Review #5628369472](https://github.com/chinanjjohn2012/mac-file-gateway/pull/65#pullrequestreview-5628369472)
found a B1-B0-only shutdown ordering defect on original fixed Head
\`852067f295ae6c28dad173ef29969d7852737166\`. The earlier
\`_BoundDisposableAcceptance.close()\` put \`fixture.close()\` in a
\`finally\` after \`listener.close()\`: a bounded \`thread.join()\`
timeout/exception still released the private ExecStateStore owner lock,
state root and pinned Workspace FDs although Uvicorn could be running.

**Required corrected order**:

1. Invalidate the entire test grant immediately and permanently.
2. Request Uvicorn shutdown and explicitly close the original listening
   socket so that the fixture no longer accepts new connections, even
   when later join/wait raises or times out.
3. Observe the actual Uvicorn thread's termination using a bounded
   \`join(timeout=7)\`. A timeout, join exception or still-alive thread
   reports a shutdown failure, and **retains** the entire disposable
   service, owner lock, Exec state-root FD and pinned Workspace roots;
   there is no \`finally: fixture.close()\` escape hatch.
4. Only after the real thread has stopped may \`fixture.close()\` free
   the protected resources. Calling \`close()\` again after a transient
   fault retries bounded termination before releasing ownership. No
   unbounded join, silently swallowed error, or new real subprocess.
5. On partial startup failure, the outer disposable wrapper must own
   the Listener object **before** socket/thread startup begins; if
   startup teardown fails, this same keep-service rule applies instead
   of losing the only reference to a live listener.

Fixed test-only RED Head
\`0b9a2782d60c43b28252fb281a42daeeb8bdf5e8\` adds two
physical negative cases: (a) \`thread.join\` raises while a real
Listener exists, and (b) a real loopback HTTP \`/run\` preview blocks
in the synchronous handler, leaving the actual Listener thread alive
while a bounded synthetic join returns without draining it. Both
must verify immediate grant revocation, closed listening FD,
**Service not closing/closed**, still-valid owner-lock/state/workspace
FDs, and complete bounded cleanup after the injected fault is removed.
Tests must keep their original Git Blob byte-identical between RED and
GREEN. This is an internal disposable fixture invariant; it is NOT
production Worker lifecycle, descendant cleanup or native macOS R3.

## Concrete RED/then GREEN gates

A default-collected test suite must run the actual socket listener and
make **real loopback HTTP** GET /health, GET /info and POST /run **preview
only**, plus real SDK MCP initialize / tools/list / run_command preview.
No test requests a non-preview Exec apply and the test interceptor
checks that no child process/group signal runs. Other cases attempt
foreign fixtures' sockets, forged literal Host/transport objects,
wrong Workspace, client-injected test grants, loss of listener
liveness and loss of wire-ready provenance. All must fail closed.
The original full suite (currently 1177 passed / 8 skipped on B1-A)
must remain GREEN with its test assets unmodified.

Do not replace real socket observations with a prefilled result dict
or Fake/Starlette TestClient; those cannot prove real bound transport.

## Explicit non-goals / next gate

- B1-B0 grants NO Worker execution rights, no test-only RETIRED, and
  does NOT change normal double-opt-in Exec's **historical** semantics
  from PR #56. That old behavior is **not** D0-conformant default
  DENY and is a separate blocking B1-B1 migration item.
- B1-B1 must preserve existing real subprocess, REST/MCP,
  cancellation/disconnect, slots and cleanup regression coverage
  via independently reviewed private disposable fixture integration
  (or an approved equivalent) before normal non-preview requests
  become \`exec_cleanup_proof_required\` **before any PREPARED write/Popen**.
  It must verify identical \`/info\` / \`/health\` / REST/MCP policy
  and error precedence, and convert the original T02-A RED contracts
  to true GREEN. Do not remove/skip existing real execution tests.
- R2-T02-C still needs actual durable PREPARED / RUNNING / UNKNOWN /
  group-only RETIRED with failure injection, restart quarantine and
  finalizer requalification. A bound Listener is neither actual
  process-tree proof nor safe standalone permission to launch.
- Linux CI cannot replace macOS ARM64 native lifecycle, advisory
  flock/socket validation or controlled descendant-cleanup R3/R4.

**HARD STOP:** PR #56–#60 and #62–#64 plus new B1-B0 remain Draft,
unmerged and undeployed; production Exec OFF, Native C/Candidate B
research paused. No local user Gateway/Tunnel restart, host unmanaged
group signal, auto-unquarantine, merge, Tag or deploy. Do not proceed
to B1-B1 until B1-B0 independently reviewed.
