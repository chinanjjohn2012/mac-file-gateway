# RC119 T1 initial-source and one-shot controller code candidate 002 (T0 only)

STATUS: DEVELOPING / NONOPERATIVE / NATIVE_T1_NOT_AUTHORIZED / NOT_RELEASE_READY
ROLE: A Developer; B/C independent reviews are not replaced by this document.
REPO: chinanjjohn2012/mac-file-gateway
TASK_ID: MULTI-EXEC-LBE-RC119-T1-QUALIFICATION-PREP-20261118
MILESTONE_ID: RC119-T1-QUALIFICATION-PREPARATION-001
REVIEW_ROUND: NOT_STARTED (the PR #122 head remains developing until milestone freeze)
PRODUCT_SOURCE: PR #119 Head 33c30b6c2710cac0f8533370c1ca42f31ef6747a / Tree 27e26c423e700cdbad0aeca27efcdf82594507c1
PREPARATION_PARENT: PR #121 Head 22bae3bf359ccc0678a6f691b1e8188a4872cee2 / Tree 77b66717276e279d78064c444341315f12873c78
PARENT_STATIC: PR #120 Head 299bcaff1c075396d205caa450344f7246350d62
SOURCE_CONTRACT: Product six-only Design-002 immutable Blob d90df6de3bdbd81a314109d5f73959799b5a10a6
NETWORK_BASELINE: PR102 Gate B immutable Blob 7db3b77aadca8b0c284e28fa5ee64e315e9275d2 (retained)
PROFILE_B_DESIGN: PR #121 revision v1.1 Blob 1df5ccf9dbf920ff243e04d0e57f45a82e1b2a13; B/C targeted design PASS, Owner direct-chat six-risk decision relayed at PR #121 issuecomment-6954483933; NOT a current test or permission to execute.
RULES: ICR-V2.0 / GHRH-2.0 / ETP-V2.0

## Scope and factual authority

Owner explicitly authorized A on 2026-11-18 to implement external-input qualification and one-shot T1 *code candidates* in an isolated disposable development snapshot, with static/SAFE T0 tests. This is not approval to acquire/install third-party Go/Pipenv/Python modules, execute a native original child, test actual egress/credentials/host, relax strict R006, change product/previous frozen PR Heads, or merge, tag, release, deploy or operate in a shared environment. No real Owner-signed GitHub execution grant exists.

The current stronger original PR102 Gate B precontact OFFLINE_ONLY/BOUNDED_EGRESS requirement remains the default, outside a separately independently qualified effective exception. User's exact-Blob six-risk acceptance is a risk decision for potential future bounded testing, not proof of host eligibility, loaded-source closure, an actual operative implementation or native execution authority. Under proposed Profile B, no complete runtime dynamic downloaded-code execution graph can be asserted on initial hashes alone.

## Implemented features in this development snapshot

1. `tools/rc119_t1_input_qualification.py` independently enumerates all 22 source/input identity categories from PR #120, verifies the fixed product Head/Tree and exact top-level/row template schema, rejects missing, extra, duplicate, optimistic or changed attestation claims. It returns SOURCE_GRADE=NOT_ATTESTED and native_execution_authorized=false even when a template is correctly shaped. Actual currently selected input bytes remain 22/22 NOT_ATTESTED; no sources are downloaded by this tool.
2. The same module reads *existing private synthetic T0 fixture bytes only* with fd-relative O_NOFOLLOW / O_DIRECTORY / O_CLOEXEC, checking regular single-link file, size limit, content SHA256 and pre/post metadata. Never follows symlink/path traversal or reads FIFOs as files. This local digest demonstrates the dummy bytes agree with the provided test claim, **not** authenticated origin, real installed Go/Python/Pipenv/SDK source selection, macOS runtime loader or future process immutability. No actual foreign interpreter or Hook is imported or called.
3. Runtime source grading explicitly preserves `RUNTIME_DYNAMIC_EXECUTION_NOT_ATTESTED` on any asserted prelaunch hash match without a qualifying independent witness, and marks observed dynamic helper as blocked. It never returns SOURCE_CLOSED_NATIVE_T1_PASS.
4. `tools/rc119_t1_one_shot_controller.py` is a **durable LOCAL SQLite state-machine simulator**, not an executable T1 controller: exactly bound repository/PR/current Head/Tree, immutable Profile B Blob, a synthetically claimed control Head/Tree, input-lock digest, nonce digest, run_id, attempt=1, claimed actor and expiry. Synthetic claims explicitly carry AUTHORITY_GRADE=SYNTHETIC_T0_UNAUTHENTICATED, SOURCE_GRADE=NOT_ATTESTED, HOST_GRADE=NOT_QUALIFIED. Extra fields, fake production authority grade, wrong actor, changed Head, attempt=2, replay/duplicate run or nonce and stale/expired claims are denied.
5. Atomic local SQLite transactions protect one-shot state among clients of one temporary local DB file (including concurrent threads). Allowed **simulation states only** are `SIX_RESERVED -> SIX_CONSUMED -> SIX_PASSED -> MIXED_CONSUMED -> MIXED_FINALIZED`; FAILED / REVOKED / EXPIRED are terminal. Synthetic per-phase receipts bind run and fingerprint but DO NOT attest actual SIX/MIXED execution. No controller method has an actual Popen/launch capability or native ALLOW branch.
6. Tests exercise legal *synthetic* progression, denial, boundary, invalid provenance, path safety, 2-client local race, post-reopen replay/expiry, wrong phase/cross-run receipt, source grade ambiguity, and adjacent historical receipt audit. All executed tests are SAFE T0. The existing product/real File/Git/MCP routes are not changed.

## Why the one-shot control is NOT yet an executable T1 authority

- **Authentication unavailable:** No independently verified Owner-signed run grant, no observed trusted GitHub dispatch event or workflow permissions binding, no protected cross-VM Owner confirmation, revoke/expiry from authenticated primary source. `actor` and `run_id` in a synthetic dictionary are not signed assertions.
- **Cross-runner CAS unavailable:** The SQLite test DB protects only its own file. It is NOT a durable globally atomic GitHub Actions multi-VM lease, it lacks a verified host/file locking contract, cross-job recovery and authenticated retry/phase receipts. Never copy this SQLite file into a production/GitHub T1 executable profile and call it sufficient.
- **Real input identity unavailable:** The 22 classes require separately authorized acquisition and independent archive/installed RECORD/unlisted importable, Pipenv `.venv`/seed, Python/Go/SDK, generated-fixture, loader-precedence verification in the actual future execution context. Current 22/22 classes remain NOT_ATTESTED. A local dummy file digest does not qualify any of these.
- **Real host unavailable:** PR #119 strict macOS R006 remains FAILED due ambient credential-bearing environment. No same-UID file/FD/SSH/OIDC/mount/metadata access verification is authorized or attested; no disposable runner/native host can be claimed clean.
- **Risk budget/effectiveness unavailable:** PR121 proposed N1-B is not executable by itself; per child CPU/RSS/disk hard containment and actual line-by-line source authenticity are not proved, possible descendants/network/open egress remain disclosed. No real TIME/OUTPUT/OOM or original-child cleanup test was performed.
- **Product integration unavailable:** Current PR #119 173-file RC B/C FULL reviews remain BLOCKED. Historical PR #114 native 18/18 and mixed real operation belong to DIFFERENT source/runner/authorization scope, not an actual current PR #119 run. No current `INTEGRATION_PASS`, R10 `FULL_CODE_REVIEW_PASS`, production, Tag or release authority.

The eventual executable controller requires a separate bounded design/implementation qualification with independent B/C scope review, a GLOBAL durable atomic owner-run/phase lease and authentic Owner/CI identity, actual selected input/host proof from before the first foreign installer/import/build hook, exact no-secrets domain, a future explicit run_id+attempt-bound one-shot native permission, and physical current-Head original-child proof. If any proof is unavailable, fail closed without making a foreign instruction.

## SAFE T0 matrix and limits

- Unit tests: `tests/test_rc119_t1_input_qualification_t0.py` and `tests/test_rc119_t1_one_shot_controller_t0.py` (74 new safe tests); adjacent PR #122 historical static auditor `tests/test_rc119_native_evidence_static_audit_t0.py` (21 existing safe tests). Total local 95 passing on Python 3.13.5 / pytest 9.0.2; no skipped/failed in selected local set.
- Positive: complete inert 22-category inventory, dummy bytes hash-only, simulated one-run/two-phase state progression (native_authorized=false), preserved historical source audit.
- Negative: extra 23rd category, incomplete/duplicate identity, wrong Head/actor/attempt/event, invalid nonce/content lock/receipt, fake signed owner claim, forbidden native execute function, path traversal/symlink/hardlink/FIFO, replay, expired and revoked records, lost/reordered SIX and MIXED.
- Concurrent/exception: two clients of one temp SQLite DB competing for the same synthetic run; local post-reopen expiry and denial; no claim of cross-host safety.
- Unrun / separately authorized: actual real third-party source/download/install; macOS credential/network/host/canary; first foreign code; real 18 x S1-S6 Original Child Direct/REST/SDK-backed MCP; real S1 MIXED File/Git; T2/T3, user Mac/Tunnel, production.

## Milestone / freeze guard

MILESTONE_STATUS: DEVELOPING; full authorized code candidate implemented and locally validated but source and native prequalification itself remains BLOCKED. Check actual GitHub original current-Head CI before any bounded review freeze.
FREEZE_READY: NO until a full bounded test-control preparation review target, all applicable source/Manifest and current-Head safe evidence, and remaining contract/qualification gaps are accurately resolved and classified; no premature GH_HANDOFF_V2.
NEXT_ROLE: A Developer on the unfinished preparation milestone. B/C only once a coherent complete authorized code candidate is legitimately frozen and handed off; Owner must authorize later high-risk stages separately.
