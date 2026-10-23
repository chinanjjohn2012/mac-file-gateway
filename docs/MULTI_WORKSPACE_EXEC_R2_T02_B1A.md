# R2-T02-B1-A — private disposable acceptance qualification

**Stage: Python private test-factory qualification only.** This PR is
stacked on PR #63 fixed approved B0 Head
\`82b80f4c3fea988d628e9b8574c871950bae2bb9\` /
independent Review #5626413422. D0 authority: PR #58 §2.1,
§3–§4, §6–§7. R1/T02-A contracts: PR #59/#62.

## Why this must precede the healthy ordinary DENY gate

PR #56/#57 real disposable Worker/REST/MCP/lease/disconnect tests still
rely on historical double-opt-in execution. Removing or skipping them
to make D0 fail-closed ordinary Exec green would destroy key regression
coverage. The D0 contract makes an explicit *test-only*, single-service
original-group cleanup qualification possible for disposable acceptance;
it **never** represents full descendant-tree cleanup proof.

B1-A builds and independently reviews **only the test qualification
object and fixture factory** first, with default production invocation
unchanged. Normal Gateway/CLI/REST/MCP do not mint or attach a grant.

## Intended test-only factory contract

\`gateway._exec_test_grant.create_private_disposable_acceptance()\` is an
internal acceptance harness entrypoint, not the production Gateway or
public service factory. It creates its OWN brand-new OS-private 0700
temporary fixture root; callers cannot pass a user path, existing
Workspace or existing state root. A disposable config, explicit
Workspace A, separate Workspace B, runtime inventory, and the T01
0700 Exec state root/0600 owner lock live underneath this fixture.

The service-scoped \`TestOnlyGroupRetirementGrant\` must:
- be issued exactly once per fixture, nonserializable and unable to
  escape into config, environment, REST/MCP arguments or status;
- bind to the exact service object, current PID, FD-pinned fixture
  root, Exec state root dev/ino and owner-lock descriptor identity;
- allow only the pre-enumerated enabled Workspace name and exact
  pinned root dev/ino; never silently accept another Workspace or
  replacement/renamed/symlinked roots;
- require current healthy durable state, live owner FD and both
  Exec flags; fail permanently closed on quarantine, store/lock loss,
  root identity loss, service close, process PID change or fixture
  invalidation; never revive simply because a pathname reappeared;
- never treat runtime settings, CI/env flags, test-looking command
  names, caller-provided listeners or a localhost label alone as
  authority. An eventual real worker must recheck the same grant
  at durable admission and immediately before finalization.
- restrict B1-A's asserted listener policy to the exact loopback
  host; **B1-A does NOT prove an actual Gateway transport is bound
  to that address**. B1-B/C require an actual server-bound listener
  identity and corresponding recheck; no fabricated host string is
  sufficient to authorize an actual subprocess.

The B1-A product implementation intentionally provides **no
Worker execution integration or READY/RETIRED transition**. It must
not modify \`WorkspaceService.invoke_exec\` acceptance behavior in
this batch or expose an internal fixture grant through any client
input. A disposable harness can construct the object but cannot
use it as cleanup proof until separately approved lifecycle gates.

## Evidence and limits

The normal default-collected
\`tests/test_multi_exec_private_acceptance_b1a.py\` exercises physical
private temporary dirs, exact service/workspace/FD identities,
mutated path aliases, PID/fork-like identity change, lifecycle
invalidations, one-time issuance, serialization denial,
quarantined state, owner FD loss, and interception of accidental
host spawn/group signalling. It also checks the normal
configuration rejects client test-grant fields and that the
normal CLI/Service do not import this private acceptance factory.

The expected **RED commit** precedes factory implementation and
captures the missing internal trusted fixture; it is NOT evidence
that an existing unsafe grant was exploited. The **GREEN commit**
must use the identical test blob and prove the whole existing
1157-pass product suite is still GREEN. The GitHub original CI
Jobs and fixed SHA/Git Trees are required for independent review.

Historical P3 remains partially open: Git independence under Exec
quarantine and exact sanitized /health,/info,error priority
combinations. The B1-A acceptance object is only a building block
for B1-B default DENY/bridge; D0 durable PREPARED→RUNNING→UNKNOWN
and test-only RETIRED requires separate Worker fault-injection.

**Hard STOP:** PR #56–#60/#62/#63 and B1-A stay Draft/unmerged.
Production Exec remains OFF; no Native C, local Mac Gateway/Tunnel,
host group-signal experiments, uncontrolled command execution,
merge, Tag, deployment, auto-unquarantine or full-tree-cleanup claims.
