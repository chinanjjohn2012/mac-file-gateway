# R2-T02-B1-B1-A — ordinary Gateway cleanup-proof Default DENY RED

**Stage: test-only expected RED, NOT implementation GREEN.** This Draft PR
is stacked on PR #65's **second-reviewer Standards FULL PASS**
[Review #5632248307](https://github.com/chinanjjohn2012/mac-file-gateway/pull/65#pullrequestreview-5632248307)
and **separate Spec FULL PASS**
[Review #5632080200](https://github.com/chinanjjohn2012/mac-file-gateway/pull/65#pullrequestreview-5632080200),
both bound to immutable Head
\`682949dde29f35567a67748b3edde8196d910d9d\`,
Git Tree \`1d021d5d41a22004b341fe5a2c52385fb868b294\`.
This satisfies the B1-B0 precondition for **staged B1-B1 development**, not
release authorization, Worker admission or an implicit merge permission.

## Primary authority: D0 §2.1 / §4 / §6 / §7

A normal Gateway, even with both \`server.exec.enabled=true\` and selected
Workspace \`exec.enabled=true\`, **lacks independently reviewed, complete
descendant cleanup proof**. The two opt-ins grant permission to request
execution, not sufficient proof to attempt it. For every ordinary
\`dry_run=false\` request, the Worker MUST respond with the stable
\`exec_cleanup_proof_required\` before any \`PREPARED\` write (including a
transient write/delete) or \`Popen\`/simulated runner call. REST must return
HTTP 503 with \`{"error":"exec_cleanup_proof_required"}\`; MCP must return
a structured \`isError=true\` tool result using that code. A healthy,
configured and exposed ordinary instance must report
\`exec_policy.enabled=true\`, \`adapter_exposed=true\`,
\`available=false\`, \`completion_capability="none"\`,
\`durability_state="healthy"\`, \`quarantined=false\`, and a null reason.
\`/health\` and \`/info\` must return the same sanitized exec-policy snapshot.
Permission-disabled, unavailable and quarantined states take precedence
over proof denial; missing proof must be decided before busy slots.

Private B1-A/B0 grant identity is **NOT** available to an installed,
ordinary Gateway by config, env, CLI flag, REST/MCP input, client Host,
test-named command, CI marker, or forced literal \`127.0.0.1\`. B1-B0
\`qualifies_transport()\` is *only* a private real Listener provenance
witness; it is not standalone Worker execution authorization.

## Frozen B1-B1-A acceptance baseline

New non-default-collected test module
\`tests/b1b1_contracts/contract_multi_exec_default_deny_b1b1.py\`
contains 33 exact parameter-expanded cases, protected by a
**fixture-lifetime** Python-level no-host-Popen/fork/signal guard.
Its independent _IntentWitness records ExecStateStore.prepare,
_atomic_write, physical attempt/temp write-open through os.open,
io.open/Path.open/Path.write_bytes and builtins.open, plus os.replace,
os.rename, os.unlink and os.remove against the pinned Exec state root.
Negative-oracle selfchecks cover both standard store PREPARED->unlink and
fsynced Path.open("wb")/Path.write_bytes/builtins.open -> os.remove ->
directory fsync sequences. Identical before/after bytes or zero Runner
calls alone cannot make a false default DENY GREEN. Python-level
interception is not a kernel file audit or descendant-cleanup proof.

**Expected new RED (11 exact NodeIDs):** ordinary direct, real
Starlette/SDK REST 503, SDK MCP structured error, /info-/health sanitized
unavailable policy, proof-before-busy-slot error precedence, two
external-environment spoof cases, **two REST synthetic-header metadata**
cases and **two MCP synthetic-header metadata** cases. Every failure
must include its specified \`B1B1_RED_*\` marker from an actual failed
assertion, not unrelated exceptions, skips or setup/collection errors.

**Required GREEN witnesses (22 exact NodeIDs):** ordinary dry-run
preview with zero physical attempt intent, global-off \`exec_disabled\`
precedence, independent File read, **seven** unknown REST client
proof fields including explicit \`test_mode\`, **five** actual SDK MCP
\`tools/call\` arguments rejected with \`invalid_argument\`, actual
physical PREPARED->unlink mutation detection in both ordinary and
occupied-slot scenes, a strict public status-policy privacy oracle
selfcheck covering PID/argv/environment/root/state path/credentials,
three additional physical Python-file-API write/delete oracle
selfchecks, and the type-preserving Popen/killpg prohibition selfcheck.
Every rejected REST/MCP spoof must also have **zero** Runner calls,
\`ExecStateStore.prepare\`, atomic write, write-open,
rename/replace/unlink or physical state mutation; \`exec_policy\` must
remain unchanged. The case lifetime covers service construction,
app setup, REST/MCP dispatch and teardown; **never** executes a real
child or process-group signal.

\`tools/verify_multi_exec_b1b1_default_deny_red.py\` runs the isolated
suite, parses original JUnit for every expected NodeID and marker,
requires exactly 11 RED + 22 GREEN, rejects any skipped, setup/collection
failure or unexpected NodeID, and prints
\`B1B1_CONTRACT_STAGE=RED_NOT_IMPLEMENTED\` **only on a matching RED**.
The separate GitHub Action checks an exact Head + complete tracked
SHA-256 Manifest and demands that **all existing default-collected
product regressions remain GREEN** on Linux. It also checks the exact
Git diff leaves original real-Exec products, the old T02-A contract
suite/verifier, and B1-A/B0 Listener/grant product sources untouched.

The preexisting \`tests/t02_contracts/contract_multi_exec_admission_t02.py\`
and \`tools/verify_multi_exec_r2_t02_admission_red.py\` are deliberately
**not changed**. Their former 14 failures were a snapshot *before* T02-B0
boot-state GREEN; it is incorrect to rerun the old 14-failed-only
classifier unchanged and treat newly GREEN boot tests as a product
regression. B1-B1-A adds independent current-baseline contracts rather
than rewriting historical expected-RED evidence.

## Independent-review P2 targeted repairs — contract-only Sprint Day 1

The first frozen SHA
\`15160ad347e4ecb2f2d1be85a401465f3ecabbdb\` received
[Spec FAIL #5635750494](https://github.com/chinanjjohn2012/mac-file-gateway/pull/67#pullrequestreview-5635750494)
and independent
[Standards FAIL #5635753681](https://github.com/chinanjjohn2012/mac-file-gateway/pull/67#pullrequestreview-5635753681).
Both reviews checked valid original evidence **7 expected RED + 8 GREEN**,
but identified three overlapping false-GREEN oracle gaps in the
**test contract**, not a new production Worker exploit:

1. **D0 §6 status privacy and consistency.** The old
   \`/info\`--\`/health\` check only excluded two string fragments.
   The replacement uses an exact public \`exec_policy\` field
   whitelist, strict native types, stable reason/status/capability
   enums and fixed non-private warning. A separate GREEN oracle
   constructs a valid public policy, then injects/mutates synthetic
   PID, argv, environment, synthetic credential, actual temporary
   Workspace/state roots, lock path, test-grant metadata, nested
   request metadata, warning, enum and bool-as-int. All must fail.
   CI never prints unsafe raw policy values.
2. **D0 §2.1 / §7H client \`test_mode\` / synthetic metadata.**
   The updated REST negative table uses seven real /run requests,
   including explicit \`test_mode\` and internal qualification names;
   real SDK MCP \`tools/call\` separately rejects five forged
   arguments. Rejections must preserve \`exec_policy\`, and produce
   zero Runner, PREPARED/transient write/delete events. Two REST
   and two SDK MCP header spoofs are **additional ordinary default
   DENY expected RED**, requiring full proof denial rather than
   merely unrecognized-argument rejection.
3. **D0 §4 proof-before-busy.** The occupied-slot expected RED
   case now installs the physical \`_IntentWitness\` and before/after
   state check. A separate GREEN selfcheck performs a real fsynced
   PREPARED->unlink->fsync on the held-slot fixture and confirms
   the transient event is observed despite identical final bytes.
   Ordinary dry_run's prior GREEN guard now also demands zero
   physical state mutations.

The verifier now enforces **11 RED / 22 GREEN** exact expanded
NodeIDs. Product/runtime and historical real subprocess/test blobs
are unchanged. No implementation GREEN, no Worker grant admission,
no change to production Exec and no R3/R4 acceptance is claimed.
The new SHA needs original CI and renewed **independent full
Standards/Spec RED review** before B1-B1-B can begin.

## Follow-up Spec review P2 — transient Python-file-IO false GREEN

The immutable Head `159c4afaf3183d508ff2b3f929b4c593299666fb`
received independent
[Standards PASS #5636445985](https://github.com/chinanjjohn2012/mac-file-gateway/pull/67#pullrequestreview-5636445985)
and
[Spec FAIL #5636451189](https://github.com/chinanjjohn2012/mac-file-gateway/pull/67#pullrequestreview-5636451189).
The latter found that patching os.open/os.unlink alone missed a real
`Path.open("wb") -> fsync -> os.remove() -> dir fsync` write-delete sequence,
allowing a false zero-intent result with identical disk snapshots.

The expanded `_IntentWitness` now checks pinned-root attempt/temp writes
through io.open and builtins.open (including pathlib) and captures
os.remove separately from os.unlink. Three independent negative-oracle
GREEN cases create actual test-owned PREPARED records with fsync and
os.remove, and require BOTH a write event and a remove event even when
the on-disk snapshot returns to its prior bytes. No host subprocess or
process-group signal is used. The strict verifier pins **11 expected RED /
22 GREEN guards**, and product/Worker/test-grant code remains unchanged.
This is a developer-side fix, NOT an independent Spec or Standards PASS
for the new SHA; B1-B1-B remains blocked until both SHA-bound reviews.

## Next, but NOT implemented here

**B1-B1-B** (separate Draft PR **after independent B1-B1-A RED
Standards and Spec reviews**): design a safe, strictly internal, actually
bound disposable acceptance bridge that allows *real* original-group-only
test execution **without extending it to normal Gateway requests**.
Migrate the existing disposable real subprocess, REST/MCP,
four-Workspace-slot, cancellation/disconnect and close-wait assertions
to this trusted test-only fixture **without deleting, skipping,
weakening or merely mocking out their real-process acceptance**.
Explicitly test the historical P3 private Listener against unauthorized
network \`dry_run=false\` client attempts and ensure a normal instance
cannot receive or import private credentials. Preserve all legacy
read/file/Git behaviors and fail closed on partial initialization,
concurrent close, state quarantine, and stale readiness.

**B1-B1-C** (separately reviewed product implementation): only then
connect actual Worker to trusted internal proof evaluation at admission
and finalization, preserve old real Exec tests through the accepted
private fixture, and make normal default-deny/direct/REST/MCP/status
tests **truly GREEN**. Do not change \`B1B1_RED\` expectations until
a new separate strict *actual GREEN* verifier checks every required
assertion and preserves the original RED test Git Blob. Do not use an
existing B1-B0 Listener proof as a sole substitute for durable
PREPARED→RUNNING→UNKNOWN/test-only RETIRED or full descendant evidence.

**NOT covered by B1-B1-A**: ordinary Gateway product is still
historically executable with both opt-ins; D0 healthy default DENY,
durable Worker finalize, descendant cleanup, /health parity, full R2,
macOS R3/R4 OS process tree, Git independence under Exec quarantine,
production Tunnel/release, and Native C research remain unimplemented
or unproven. PR #65 full B1-B0 PASS is scope-specific.

**HARD STOP:** PR #56–#60, #62–#66 and this B1-B1-A PR remain
Draft/unmerged/undeployed. Production Exec OFF; Candidate C/C3/Native C
research paused. No local Mac Gateway/Tunnel restart, unmanaged
host group signal, auto-unquarantine, merge, tag or deployment.
