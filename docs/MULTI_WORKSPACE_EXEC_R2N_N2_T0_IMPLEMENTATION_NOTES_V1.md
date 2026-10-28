# R2-N N2 — pure-memory, nonspawning source and T0 scope

STATUS: NONOPERATIVE T0 CODE CANDIDATE; F1 DEFAULT DENY. No Native Runner, OS process start, signal, filesystem state store, user-local consent, deployment or activation is implemented.

TASK_ID: MULTI-EXEC-R2N-N2-MEMORY-20261028
REVIEW_ROUND: r001, new PR only; ICR-V2.0 / GHRH-2.0 / ETP-V2.0.
APPROVED_DESIGN_BASE: user-approved PR #92 r001 frozen Head 5a0ad28802aafbdc8f84a200eb1dc656b87deaae, Tree d69693d9a6d4663349da6357b91fbf7c2c1413c5, independent Standards Review 5679804738, Spec Review 5679796819. PR #90/#91/#92 remain frozen.
USER_SCOPE: separate approval to write isolated N2 pure-memory Fake/interface and T0 tests under a NEW Draft PR and submit independent B/C code reviews only. No T1/T2/T3, Native positive Exec, real signals, real integration, merge or deployment.

## Implementation boundaries

The added gateway/r2n_n2_offline.py is a standalone, standard-library-only, single-threaded event-ordering model. It is NOT imported by WorkspaceService, RunnerCoordinator, REST, MCP, ExecStateStore or production config. It has no real startup, backend allocation, process APIs, filesystem persistence, network or signal. The only externally meaningful admission-style method, N2MemoryFake.deny_apply, ALWAYS raises exec_cleanup_proof_required; every snapshot always exposes preview_only, completion_capability=none, available_for_real_exec=false.

Frozen dataclass scope/tickets and simulated state distinguish consent_epoch, service owner_generation and attempt_generation. In this Fake only, permitted mutable Workspace content edits do not rotate an existing consent epoch; changed effective Exec scope/backend/risk identity does. Records model prearmed restart-deny marker, PREPARED/STARTING, a counter-only hypothetical first dispatch, simulated limited retirement and a positive late-survivor event. No process or real descendant is ever created or observed. All limited cleanup metadata state full_descendant_tree_clean=not_proven. Any known or orphan synthetic late event latches quarantine; a fake response decision cannot claim a client or socket ACK and is ordered as historical limited or quarantined/unknown. Old decisions are immutable historical snapshots, not current health.

The external provisioning witness and Native namespace are separate Fake booleans: a previously provisioned instance with a missing complete namespace or witness refuses reinitialization even if old Fake consent data survives. This does NOT prove a power-loss-safe independent witness or durable rollback resistance. Every simulated commit or restart event is a Python memory transition, not fsync, disk journal, macOS at-signal identity or transport delivery. Original PR #92 draft D0 remains unchanged and is not itself a production amendment.

## B92 independent nonblocking P3 coordination

B92-R001-P3-01: The old N2/N3 wording forbidding every real OS process is overbroad. This N2 model performs NO process operation. In a future distinctly authorized N3 T1, the pre-existing lawful Git-specific subprocess and independently granted File Write/official SDK paths MUST still work in the same service under Exec missing-proof or UNKNOWN. Only Native/Exec child spawn and group/signal operations remain prohibited in the unqualified line. No global Popen ban. No such N3 T1 run is authorized or claimed here; this note does NOT modify the frozen PR #92.

B92-R001-P3-02: Complete Native namespace deletion/rollback with retained consent must never look like a fresh healthy installation. The Fake has an explicit prior-install witness and blocks repeat first-init after loss; simulated reboot also refuses when its prearmed marker exists. A future N3 real private-FS design MUST specify an actually trustworthy separate provisioning witness, pinned owner.lock and backing-store identity, or always deny Native when any namespace is missing/rolled-back or attribution is uncertain. Explicit offline first init or recovery, real ENOSPC/fsync and private-FS T1 require separately approved resources and proof. No such physical evidence exists at N2.

## T0 validation and explicit NOT_RUN

Only isolated stdlib unittest tests under tests/test_r2n_n2_offline.py are eligible here: positive/negative/edge/fault combinations of the memory Fake, including revoke-first/dispatch-first, owner generation, invalid scope, immutable decisions, response-first versus late event-first, known/orphan synthetic survivor, quota, failed synthetic commits, missing whole namespace and surviving consent. These are not equivalent to any real Native result. The exact local tested source/test bytes must be independently matched to the final committed Head if those local T0 results are cited. All [skip ci] commits avoid triggering broader GitHub CI with unapproved T1 operations; real original Head CI is reported as NOT_RUN if none exists.

The following are NOT_RUN/NOT_AUTHORIZED: real Exec child/Runner/Popen, macOS PGID/signal/killpg/crash/VM, T1 disposable real Git/File/REST/MCP/private-FS, T2 native lifecycle, T3 user Mac/Tunnel/production, real I/O/fsync/ENOSPC, real owner consent, configuration/schema migration, integration, merge, release, deployment and offline UNKNOWN clearing. Native positive remains hard NO-GO pending reviewed macOS lifetime identity and separately authorized T2 proof. Strict F3 domain proof remains independent, not an automatic Native fallback. B/C must separately independently inspect the exact new code Head, full diff, T0 source/runner identity and safety boundaries; A cannot sign their reviews.
