# R2-T02-B1-B1-B/R0 — internal disposable acceptance bridge expected RED

**Stage: test-contract RED ONLY. NOT a Worker implementation or cleanup PASS.**

## Fixed reviewed parent and scope

Base is PR #67 B1-B1-A Head
c58269c798b62775f8621d69fa037d614c8861da,
Tree f1f50248f5198d9afe2e3f2648f5802efb83f5f8.
Separate independent reviews:
[Spec PASS #5636701611](https://github.com/chinanjjohn2012/mac-file-gateway/pull/67#pullrequestreview-5636701611)
and
[Standards PASS #5636703653](https://github.com/chinanjjohn2012/mac-file-gateway/pull/67#pullrequestreview-5636703653).
These pass only the prior **11 expected RED / 31 GREEN** contract, not
a full-descendant cleanup proof or an ordinary Worker default DENY.

Authority: docs/MULTI_WORKSPACE_EXEC_RECOVERY_D0_DESIGN.md §2.1/3/4/6/7H–J,
and docs/MULTI_WORKSPACE_EXEC_R2_T02_B1B1_A.md §Next.

R0 adds a new *nondefault-collected*, non-spawning RED contract suite,
a strict expected RED verifier and a Linux CI workflow. It does not
modify product Worker/Runner, ExecStateStore, REST/MCP/CLI, existing
B1-A/B0 Grant and Listener, the immutable B1-B1-A contract, or old
real-process acceptance tests.

## Acceptance bridge boundary to implement after independent R0 review

B1-A supplies a self-created disposable private root, single-use,
nonserializable TestOnlyGroupRetirementGrant, pinned service/state/owner-lock
and explicit Workspace identities. B1-B0 supplies a genuinely bound,
wire-ready 127.0.0.1 Uvicorn listener. **Neither grants spawn authority.**

The future private gateway._exec_test_bridge module will expose only a
parameter-free create_private_exec_acceptance_bridge() for a trusted
in-process disposable acceptance harness. The returned context object
owns fixture, service, private grant, bound Listener and a trusted,
**in-process-only** trusted_asgi_app. Only the pre-established, exact
live listener + service + pinned state + enumerated Workspace identity
may qualify. The trusted ASGI app MUST NOT be mounted to the network
Listener; no request body/header, Host value, config/env/CLI flag or
caller-minted scope may select it. Any normal/direct or untrusted network
nonpreview attempt on the private Listener must fail before Runner
and PREPARED with exec_cleanup_proof_required, HTTP 503 or MCP structured
isError=true. Ordinary read-only preview and File/Git remain independent.

On close, revoke before network teardown, do not release pinned FDs
while a real Listener thread is alive; failed join must fail closed.
A token object may not survive close, fork or restart, be serialized,
transferred to another service, Workspace or state inode, nor
become a general-purpose Gateway parameter.

**No real positive child launch is authorized in R0.** Next staged
B1-B1-B implementation must preserve historical real subprocess,
REST/MCP, four Workspace slots, cancellation/disconnect, close-wait
and original owner lock tests; no deletion/skip/mock-only substitution.
B1-B1-C separately implements the actual Worker proof-before-PREPARED,
RUNNING/UNKNOWN/test-only RETIRED, finalization, restart quarantine,
and full required status matrix. No original-group observation proves
complete detached-descendant cleanup.

## Exact R0 RED / GREEN classification

- **24 expected RED**, each with an exact B1B1B_RED_ marker:
  ordinary direct nonpreview on the existing bound test fixture must
  deny before Runner; unauthorized raw TCP REST and real SDK MCP
  apply must deny both with NO metadata and with forged headers;
  the new bridge factory must create instance-bound actual loopback
  proof; the new bridge's own wire must deny raw client nonpreview;
  a foreign bridge instance cannot borrow its grant; parameter-free
  factory must reject all supplied positional/keyword scopes;
  the new Bridge's own real TCP SDK MCP must deny both plain and
  forged-header applies; its separate in-process ASGI preview must
  work; a dynamic trusted-only route canary must not be reachable
  from any network route/mount/wrapper; close must revoke one-way;
  live in-flight REST preview plus injected join exception or
  no-op join must keep the owner.lock, state and Workspace FDs pinned
  **and the original exclusive flock proven by a second independent FD
  challenge** for a bounded retried close.
  **NEW Bridge** real REST and SDK MCP each have four adversarial
  request-body / arguments variants: `test_mode`,
  `group_only_test_grant`, `_trusted_bound_listener`, and
  `_internal_exec_grant`. Every variant must reject with stable
  invalid_argument, zero Runner, zero physical PREPARED mutation and
  unchanged public exec policy. Plain and forged-header cases remain.
  Existing product/bridge absence intentionally fails these.
- **21 required GREEN**: real bound Listener still previews with no
  subprocess or durable attempt; foreign Listener cannot borrow grant;
  both invalid client proof body fields denied; immutable inventory
  of historical real subprocess, REST/MCP, slots and cancel/close tests;
  ordinary product startup does not import bridge; existing private
  grant remains nonserializable and lifetime-revoked. Additionally,
  synthetic oracle selfchecks prove that nested import/initializer
  errors are never converted into expected missing-bridge markers,
  parameterized factory signatures cannot pass, and a simulated
  nested ASGI mount through a wrapper is actually detected.
  NEW physical mutation selfchecks: releasing LOCK_EX while leaving the
  owner.lock FD open lets a competing FD take the lock, and MUST fail
  the pinned-ownership assertion; a custom dispatcher with a dynamic
  `dispatch` dict and metadata-selected private route MUST be rejected
  regardless of fixed canary paths; a real Starlette closure forwarding
  an unknown /unlisted/ path to trusted ASGI via httpx.ASGITransport
  demonstrates the old graph detector's false GREEN and MUST fail the
  strict public route allowlist; a synthetic body-controlled REST/MCP
  parser bypass cannot be reported as an authorization denial.
- **Strict verifier** checks exact 45 expanded NodeIDs once, no skipped
  or unexpected failures, exact twenty-four absent-feature markers and twenty-one
  genuinely passing guards, pytest exit=1. It emits
  B1B1B_CONTRACT_STAGE=RED_NOT_IMPLEMENTED only for a matching RED.

Only the exact missing `gateway._exec_test_bridge` module or absent
`create_private_exec_acceptance_bridge` attribute may be classified
as expected RED: nested ImportError, module initializer failures and
factory execution exceptions must produce unexpected pytest errors.
Factory inspection and harmless dummy arguments enforce an actual
zero-parameter signature; a synthetic unsafe-signature GREEN selftest
prevents an optional root/Workspace/credential path from being accepted.

The new Bridge's *own* real REST and MCP wires are exercised with both
normal requests and forged headers. Trusted ASGI network isolation
requires BOTH the fixed, closed network ASGI construction
(`Boundary -> StrictPostAdmission -> Starlette`, official SDK /mcp,
only the exact `gateway.http_multi` REST route endpoints/paths/methods,
no unknown dynamic dispatchers, Proxy, custom route, catch-all or
arbitrary `application` wrappers), a recursive graph check, AND a
test-only GET route canary injected into the trusted app, observed
locally via TestClient and denied over actual bound TCP.
A known-good B1-B0 live listener must satisfy the allowlist; a synthetic
custom dispatcher and a real Starlette closure-forwarding proxy are
rejected by independent tests. Sampling a handful of guessed paths
alone is not a security proof.
The real in-flight TCP close-fault tests inject only join
exception or no-op join; they do not fake thread liveness. Before retry,
they require permanently revoked grants, closed listening socket,
still-open pinned owner-lock/state/Workspace FDs AND independent
second-OFD `flock(LOCK_EX|LOCK_NB)` challenge showing owner exclusivity
with the original physical lock inode. A deterministic mutation test
drops the original flock but leaves its FD statable, proves another FD
can obtain exclusivity and requires the oracle to fail.
No premature service close is permitted while the actual preview Worker
is active. Neither FD liveness nor an invalidated grant alone is lock
ownership.

The no-intent refusals reuse the identical frozen B1-B1-A physical
observer, not a final-snapshot-only test: a transient PREPARED write
and delete, record entry/link mutation or moved directory is therefore
not accepted as a clean denial. The new bridge must never mount its
in-process trusted ASGI app directly on the public bound Listener.

This R0 contract deliberately has no new actual Worker or child
process authority. When the new factory is absent, the added
factory-dependent RED cases (and old factory-dependent cases) fail
with an exact missing-module marker; the GREEN fault-injection
selfchecks ensure an unrelated nested import/init error cannot masquerade
as that missing-feature RED.

CI checks full tracked SHA-256 Manifest, reviewed parent ancestry,
source integrity, unchanged historical product/reviewed blobs, full
real product pytest, frozen B1-B1-A strict RED classifier, and this
new expected RED classifier. It does not spawn any *new* process
from R0 contracts. Existing full product regressions still perform
their preexisting true disposable subprocess acceptance.

## Independent Standards + Spec P2 corrections (current R0)

On Head `3b3415f555ad26ae20d4b10fb1ab8e82ede84488`,
[Standards FAIL #5637260572](https://github.com/chinanjjohn2012/mac-file-gateway/pull/68#pullrequestreview-5637260572)
identified a possible falsely GREEN close assertion when flock was
released while owner.lock FD stayed open, and an uninspected dynamic
ASGI dispatch mapping. Independently,
[Spec FAIL #5637266276](https://github.com/chinanjjohn2012/mac-file-gateway/pull/68#pullrequestreview-5637266276)
identified the missing Bridge-own REST/MCP **body and arguments**
forgery matrix and unknown ASGI closure forwarding paths. The added
contracts protect these four distinct P2 cases, preserve the prior
16 exact RED and 10 GREEN witnesses, and extend the classifier to
24 expected RED plus 14 mandatory GREEN on 38 NodeIDs. This is
developer-side test-only repair, NOT a fresh independent PASS,
Bridge implementation, kernel-level route audit, or full descendant
cleanup proof.

## Later fixed-Head Standards RED contract P2 repairs

At Head `10e05196890ef51e9ed731823515a04482dc6669`,
[Standards FAIL #5637359508](https://github.com/chinanjjohn2012/mac-file-gateway/pull/68#pullrequestreview-5637359508)
identified two possible false-GREEN paths: a public Starlette app with
`user_middleware`, `exception_handlers` or a cached
`middleware_stack` redirecting to trusted in-process ASGI despite
unchanged routes; plus MCP proof rejection inferred from free-text
`invalid_argument` instead of the structured error code. Independently,
[Standards FAIL #5637393379](https://github.com/chinanjjohn2012/mac-file-gateway/pull/68#pullrequestreview-5637393379)
identified that the actual `Route.app` callable can be substituted
while `Route.endpoint/path/methods` remain identical.

R0's public network audit is now a **closed execution-chain check**:
it verifies the actual `Boundary -> StrictPostAdmission -> Starlette`
composition, stock Router default and middleware callables, the
built `ServerErrorMiddleware -> ExceptionMiddleware -> Router`
chain, empty custom user/exception handlers, default HTTP/WebSocket
exception semantics, and actual `Route.app` wrapper's code and
closure-bound endpoint identity. Even a valid route table fails when
the actual dispatch path is changed. Its official SDK `/mcp` handler
is checked against an independent standard
`create_multi_app(service,enable_mcp=True,port=port)` instance
by executable code/source identity, not a spoofable
`__module__` string. Any foreign dispatcher, proxy, injected
middleware/handler or unknown handler fails closed. Newly required
GREEN selfchecks temporarily mutate only a disposable
loopback test fixture, prove client-selectable `Route.app` and
cached middleware can return a synthetic private-canary HTTP 200
on otherwise allowed paths, then restore the original stock public
listener. Custom 404 exceptions and forged SDK source are also
rejected. No real new host process/signal or user Gateway/Tunnel
is involved.

MCP forged arguments must be refused with HTTP 200 JSON-RPC
`result.isError=true` **AND**
`result.structuredContent.error="invalid_argument"`;
a textual message containing `invalid_argument` with
structured error `exec_cleanup_proof_required`, absent structured
content, isError=false or executed=true cannot satisfy the oracle.
A dedicated deterministic GREEN mutation selfcheck freezes this
error-priority requirement; all 8 Bridge-own REST/MCP bad-field RED
cases, physical no-PREPARED observer and zero-Runner requirements
remain intact.

With these four new GREEN selfchecks, the strict R0 classifier
requires **24 exact expected RED and 18 mandatory GREEN across
42 NodeIDs**. This is a test-only, no-host-spawn RED contract,
not a Bridge R1/Worker implementation, a kernel ASGI audit or
permission to enable production Exec.

## Fixed Head 0e67fd8 additional Standards counterexample closure

The exact independent reviews on Head
`0e67fd8e094321e8139d8d55d9040eaec55c5512` both rejected
the R0 contract:
[Standards #5637555516](https://github.com/chinanjjohn2012/mac-file-gateway/pull/68#pullrequestreview-5637555516)
found `Route.handle` instance override and clone
`types.FunctionType` with unchanged `__code__` and closure but
different `__globals__`;
[Standards #5637555679](https://github.com/chinanjjohn2012/mac-file-gateway/pull/68#pullrequestreview-5637555679)
independently found that an authentic SDK `StreamableHTTPASGIApp`
type can hold a foreign `session_manager`, proxy `asgi_app` or
wrong underlying MCP server. These are **test acceptance-oracle
false-GREEN paths**, not evidence of an existing private Bridge or
current production Exec leakage.

R0 now requires stock `Route.handle` to remain the class method
without instance override; each REST `Route.app` needs the real
`starlette.routing.request_response` function's code **and original
module globals identity**, along with its original closure and
endpoint. New mandatory GREEN fault injections modify ONLY an
isolated disposable, real loopback listener's handler, then clone
its function with `FunctionType(original.__code__,
changed_globals, ..., original.__closure__)`: each forged handler
serves a synthetic private `HTTP 200` if a previously untested
Header is sent over the **actual TCP wire**, while the existing
Route path, endpoint and HTTP method remain unchanged. Both must
make the structural predicate false; restoring the handler must
restore genuine normal Listener acceptance.

For official pinned MCP SDK 2.3.0, the callable
`StreamableHTTPASGIApp.__call__` is NOT sufficient proof of
public service identity: it delegates to
`StreamableHTTPSessionManager.asgi_app`, which itself wraps the
session manager's `_handle_request` using a stock
`RequestBodyLimitMiddleware`. R0 now follows that chain,
requires original types, correctly owned bound callback and
identical manager transport-security/size/stateless settings to
a separately built normal public MCP app. It verifies the
underlying low-level MCP server's `tools/call` callback is
bound to the exact `StrictWorkspaceMCP` instance, whose
`_lowlevel_server` is that manager's underlying server.
Registered tool function codes/globals/critical service
closure captures must match the reviewed `build_multi_mcp`
source and **exact current WorkspaceService**; a foreign
service/manager/proxy cannot qualify by presenting a genuine
SDK class name or `__call__`. A required mutation GREEN
test replaces a real public MCP handler's manager with a
test-only proxy, proves an extra Header can reach a private
MCP canary over actual loopback TCP, and checks that such a
proxy, a replaced ASGI delegate, or a foreign low-level Server
is rejected by the new oracle. No real subprocess is launched
by these R0 tests.

The strict classifier adds precisely 3 required GREEN tests,
so R0 expects **24 RED and 21 GREEN (45 exact NodeIDs)**.
All 24 missing-feature cases remain RED until separately
authorized staged private Bridge implementation; this review
stage does not enable Worker/default-DENY, descendant cleanup
or production Exec.

## Fixed Head 8eeef32c independent Standards P2 targeted repairs

On [Standards Review #5637928341](https://github.com/chinanjjohn2012/mac-file-gateway/pull/68#pullrequestreview-5637928341),
[Standards Review #5637930788](https://github.com/chinanjjohn2012/mac-file-gateway/pull/68#pullrequestreview-5637930788),
and [later re-review #5638211273](https://github.com/chinanjjohn2012/mac-file-gateway/pull/68#pullrequestreview-5638211273),
all bound to original Head \`8eeef32c921f8ab85635795340344540b5731bb9\`,
the still-unresolved RED-oracle P2 concern was **exact Service
provenance**, even with correct route syntax/callable source:

- REST path/method/stock \`Route.app\` and legitimate
  \`read_endpoint/write_endpoint.__code__\` do not by themselves prove
  the endpoint's *captured WorkspaceService* equals the current
  listener's exact owned Service. R0 now independently constructs the
  canonical REST routes using the actual listener Service and checks
  every function's \`__code__\`, \`__globals__\`, defaults, full critical
  closure captures, and the exact \`service is listener.service\`
  identity. Two mandatory GREEN independent real-loopback tests
  replace both GET \`/info\` and preview-only POST \`/run\` with an
  equivalent endpoint from a **second disposable real listener**,
  re-wrap through official Starlette \`request_response\`, demonstrate
  the caller receives a synthetic foreign-Service marker, require
  the provenance checker to fail closed, restore original handlers and
  verify both state directories unchanged. They do not launch or
  manipulate any host child.
- MCP tool functions \`read_file/list_files/search_files\` call a
  nested \`invoke\` closure which captures the WorkspaceService on the
  next level. Direct name-based \`service\` checks on tool.fn miss this.
  R0 now recursively verifies all actual Tool.fn function closures
  against a separately built factory reference, including
  \`tool.fn -> invoke -> service\`, asserting that every encountered
  WorkspaceService is exactly the current listener Service; unknown
  nested callables/objects fail closed. Two new mandatory GREEN tests
  transplant the foreign listener's *real* \`read_file\` or
  \`list_files\` Tool.fn into the public tool manager while keeping
  \`gateway_info/run_command\` normal; real SDK TCP \`tools/call\`
  returns a harmless synthetic FOREIGN marker, and the checker must
  reject before the original state/runner can change.
- The SDK 2.3.0 **ServerRunner executes \`lowlevel.middleware\`
  before \`_request_handlers["tools/call"]\`**. Exactly the stock
  two ordered middleware instances are required; a third injected
  short-circuiting middleware is rejected. A real loopback MCP wire
  test injects such middleware, returns a synthetic invalid success
  from \`tools/call\`, proves the checker fails closed, then restores
  the stock list. The low-level server's \`tools/call\` handler identity
  and owning StrictWorkspaceMCP remains pinned.
- An instance-level \`StrictWorkspaceMCP.call_tool\` override can
  intercept the genuine low-level handler without changing the class
  method. The checker now rejects that instance override. A real SDK
  TCP tools/call mutation demonstrates synthetic unauthorized content,
  restores the instance and rechecks normal provenance.
- The actual SDK \`/mcp\` \`Route.handle\` also has a separate mutable
  instance override seam even when StreamableHTTPASGIApp,
  manager, Tool.fn and \`Route.app\` remain official. One new real
  bound TCP mutation shows a header-selected private result, requires
  false qualification, and restores the class-bound stock method.

This is a **test-only R0 RED contract repair**, not permission to
launch subprocesses, not proof that a future private Bridge exists,
and not a full-tree cleanup/production admission pass. All seven new
GREEN counterexamples use disposable real loopback listeners,
synthetic canary output and Python NO-SPAWN guard. The previous 24
expected RED cases, all 21 existing GREEN guards, frozen B1-B1-A
11 RED / 31 GREEN and original full 1468+ product tests remain
unchanged. The strict R0 classifier now requires **24 expected RED
and 28 mandatory GREEN across exactly 52 expanded NodeIDs**.
Fresh Standards AND Spec reviews must be independent on this new
fixed Head and original SHA-bound CI before any R1 implementation.

## Required next gate

After original CI success, independently review Standards and Spec
against the exact immutable R0 Head, code, negative cases and Job logs.
Only after both pass may the follow-up bridge GREEN implementation begin.
R0 GREEN is not product Worker GREEN. Keep all stacked PRs Draft,
unmerged and undeployed, production Exec OFF, Native C/C3 paused.
No user Gateway/Tunnel restart, unmanaged group signals, automatic
unquarantine, merge, tag or deployment.
