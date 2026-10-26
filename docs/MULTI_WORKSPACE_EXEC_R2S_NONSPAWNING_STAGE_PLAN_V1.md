# Multi-Workspace Exec — R2-S nonspawning state and coordination plan V1

**STATUS: DESIGN PROPOSAL ONLY; NO R2 CODE AUTHORIZATION, NO POSITIVE EXEC OR NATIVE TESTS.**

- TASK_ID: \`MULTI-EXEC-R2S-NONSPAWNING-DESIGN-20261026\`
- REVIEW_TARGET: R2-S nonspawning state/coordination and migration plan, with explicit Candidate-A Native contract dependency
- CONTRACT_SCOPE: approved D0/F1/Phase1/G05 + R0 design proposal, frozen R1 nonspawning behavior
- RULES: original ICR-V1.0 / GHRH-1.0; V2.0 candidate not formally activated

## 0. Frozen authority and history

- **R1 source**: PR [#82](https://github.com/chinanjjohn2012/mac-file-gateway/pull/82) Head \`0af04817f61e2e45d702daecf9c7a1b1cf310cd0\`, Head Tree \`397de0543d277727a7c20ce180fa1b67d02bc98e\`, Base \`b95414ae0287b66def3fb25853a0a553a9849aca\`. R1 B r002 = \`BLOCKED\`, C r002 = \`ROLE_FULL_SCOPE_PASS\` for bounded nonspawning R1. User excluded B's two general governance/evidence issues from A's product task list; **this does not clear B's verdict or R10**.
- **R0 proposed contracts**: PR [#78](https://github.com/chinanjjohn2012/mac-file-gateway/pull/78) Head \`d502254934961ebe53720fb0708def85db6cd202\`, Head Tree \`b54fb1e875264aa4d046410533f1998d07052359\`. Independent B/C r002 \`TARGETED_REVIEW_PASS\` applies to design documents only, not new product authority. Sources: \`docs/MULTI_WORKSPACE_EXEC_RUNNER_CONTRACT_V1.md\` Blob \`5d9d4d899bea0f921fe731e2ece0eb24e6c9d343\`; architecture Blob \`f83bf9efb87d1cb5698554a427db1af8b0afefe5\`; recovery Blob \`644017dd873bccd3f0671b99a2a9afc8bad9c605\`; test matrix Blob \`21a73076364786be5a1f68aa9624a8dd112778e6\`.
- **Owner direction**: the exact user answer “选择候选 A” is recorded in [PR #78](https://github.com/chinanjjohn2012/mac-file-gateway/pull/78#issuecomment-6414363063). It selects \`native_limited + mutable_workspace\` rather than revision-pinned Candidate B for **future contract design**; it does not create a local Workspace consent record, enact a D0 amendment, authorize actual Native Exec, or permit T2/T3.
- **Current operative sources**: \`docs/MULTI_WORKSPACE_EXEC_RECOVERY_D0_DESIGN.md\` Blob \`6e25904aed9a62bb0f472b732021c2a7ca3b3bb0\`; F1 plan Blob \`76baeb820c6f8a9b067e45e2dcc42e76453fe5b1\`; Phase1 trust Blob \`b3f2383f292a59fd234269389e5338cd50e334a2\`; R004 verifier scope Blob \`2ffe5341288e428be5ee5d0fa8d52aea3e9efc93\`. Current D0 §0.4 remains in force. R004 limited 36 locked Wheel SHA256 + installed RECORD-listed bytes remains unchanged; Candidate A does not waive independent executable-source evidence requirements.

## 1. Disambiguate the two old "R2" labels

| Source | Original meaning | Proposed stage label |
| --- | --- | --- |
| D0 §8 | Private durable intent/admission and restart quarantine, after R1 review | **R2-S** state/coordination; design-only today |
| R0 Runner Contract §6 | Candidate Native Runner code, positive path remains unreachable pending approvals | **R2-N** separate later candidate |
| R0 §6 R3 | Real bounded Native acceptance | **R3** separately authorized macOS experiments |
| R0 §6 R4/R5 | Strict F3 OS-domain qualification / implementation | R4/R5 unchanged NO-GO |

These labels are planning aids, not replacements for D0 or its prerequisites.

## 2. Actual source inventory at R1 Head

| File | Already exists | Proposed, not implemented |
| --- | --- | --- |
| \`gateway/runner_seam.py\` Blob \`1518efccb8e089856defc4a06c39d2dff08610b4\` | Immutable structural Attempt/Command/Evidence; \`RunnerCoordinator.deny_unqualified_apply\` always denies, no real backend | Deterministic offline fake lifecycle and fencing only |
| \`gateway/exec_state.py\` Blob \`d3dc2c0ec9dec0a571f768eb6aa15edf5d0153b0\` | v1 states PREPARED/RUNNING/UNKNOWN/RETIRED; pinned private FD, owner lock, fsync and bounded quota | Separate versioned v2 state/migration contract; do not reinterpret v1 RETIRED |
| \`gateway/workspaces.py\` Blob \`6d2c0b4087f17bcc543b467b04e405f0e994369d\` | No-proof Apply unconditionally raises \`exec_cleanup_proof_required\` before slot/PREPARED/Popen | Keep unchanged until independent product contract and positive backend gate |
| \`gateway/workspaces_config.py\` Blob \`4ffd1bea9464732266e85d6cee32611317270f49\` | schema v1 only; no Native profile or consent | Separate local-only v2 configuration proposal, never implicitly enabled |
| \`gateway/executor.py\` Blob \`e578c72f0133bb74e64d03a1cca2c70e133da0a3\` | Legacy runner validates Direct/Pipenv, original group cleanup not descendant proof | Do not reuse historical Popen/killpg as Native safe-identity proof |

## 3. Proposed R2-S state contract, offline only

1. **Attempt identity:** versioned, random attempt ID, owner generation/fencing, canonical Workspace + pinned root \`(dev,ino)\`, profile, backend identity/config fingerprint. Numeric PID/PGID and timestamps are never identity authority. Request fields cannot mint approval.
2. **Ordering:** future qualified positive flow would require held admission lease and fully fsynced \`PREPARED\` before allocation/start. A failed fsync/rename or missing owner lock means *no launch*. R2-S fake must never launch or persist to production Exec state.
3. **Single launch:** Fake \`allocate/start_once/observe/terminate_and_prove/reconcile\` must use the same attempt+generation. ACK loss leads to authenticated lookup or UNKNOWN; never retry a non-idempotent command.
4. **Conceptual future v2 phases (not current code):** \`IDLE -> PREPARED -> STARTING -> RUNNING -> CLEANUP_PENDING -> RETIRED_LIMITED | RETIRED_PROVEN\`; all uncertain persistence/identity/cleanup leads to \`UNKNOWN\` + global Exec QUARANTINED. \`RETIRED_LIMITED\` is Native-only and \`full_descendant_tree_clean=not_proven\`; \`RETIRED_PROVEN\` is Strict-only with separate OS domain proof. No v1 RETIRED auto-migration, no automatic UNKNOWN deletion.
5. **Independent outcomes:** command execution/exit, cleanup observation/proof, response delivery/ack separately. Exit 0, group absence, EOF or HTTP timeout is not full-tree cleanup nor authority to repeat a command.
6. **Capacity and shutdown:** preserve D0 4096 records, 4096 bytes/record, 16 MiB total and current 1 per Workspace/4 per instance managed admission. UNKNOWN consumes unresolved potential resource even when Worker slot is released; repeated unobserved detached descendants are NOT bounded by 1/4 slots.
7. **Real entrypoint invariant:** REST \`POST /run\` and official MCP \`run_command\` share \`WorkspaceService.invoke_exec\`, with stable deny before Worker/PREPARED. Valid Preview, independently authorized real Git apply/File Write remain legal. Legacy Exec/Local Skills are not modified.

**No R2-S mock or any proposed admission predicate may turn ordinary current F1 \`dry_run=false\` into positive Exec.**

## 4. Candidate A consent dependence and hard Native stop

Future local-only consent binds \`profile=native_limited\`, \`trust_scope=mutable_workspace\`, Workspace ID/root dev/ino, effective Exec command/path/runner grant fingerprint, backend identity/version, exact risk acknowledgement and revocation status. All must match at admission and finalization. Explicitly accepted changes to Workspace bytes, Git HEAD and Pipenv deps **do not** automatically revoke consent; expanded grants, changed root/backend, missing local approval, revoked/unsupported version must deny. No REST/MCP grant or reset.

An observed detached child ALWAYS => \`UNKNOWN\`/global quarantine, even if original group is absent; not observing a child never proves it does not exist. No clean Native retirement unless the directly owned leader and original group are authenticated absent and no detached survivor was positively seen **under the separately approved Native limited contract**. No group signal if target is not race-resistently bound at signal time; a PID/PGID check followed by \`killpg\` is insufficient. No signal experiment or positive Exec until exact approval and T2 evidence.

## 5. Future batches and approval gates

| Batch | Candidate deliverable | Testing | Hard stop |
| --- | --- | --- | --- |
| **S0 — this PR** | Propose D0 exception wording, R2-S FSM, traceability and tests | Read-only docs/Manifest and CI if run | No runtime/config/schema change or positive Exec |
| **S1 — later** | Pure offline mock state/evidence/fencing and consent model | T0, no subprocess | Requires accepted R2-S scoped design and applicable R1 disposition |
| **S2 — later** | Disposable private FS state/migration and nonspawning coordinator tests | T0 + non-destructive authorized T1 | Real REST/MCP remain hard-deny, no live state migration |
| **R2-N** | Native Runner candidate with independently qualified live target identity | Separate authorization and code reviews | No positive route without effective D0 amendment and owner consent |
| **R3** | Real Native Direct/Pipenv/Go, cleanup/crash/watchdog acceptance on disposable macOS ARM64 | T2 only if independently authorized | No user Mac, Tunnel, shared/production T3 |

R0 design B/C TARGETED PASS, current R1 C ROLE_FULL_SCOPE_PASS, CI GREEN and user's Candidate-A direction do not jointly provide R1 R10 or positive-mode activation. For new R2 code, freeze a different Head/Base/Tree and request independent full-scope B/C code reviews. Stage-based grouping reduces intermediate review events, never scope or evidence.

**This PR is DOCUMENTS + Manifest ONLY. NOT_RUN:** new R2 T0/T1 code (not implemented), real Native Runner/process/group signal/VM, T2/T3, current user Mac/Tunnel, release/integration. No merge/deploy/tag/config or UNKNOWN reset.
