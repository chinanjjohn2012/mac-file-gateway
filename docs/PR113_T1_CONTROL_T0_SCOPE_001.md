# PR #113 - isolated one-time T1 CONTROL PREPARATION 001 (T0 only)

STATUS: DEVELOPING_T0_CANDIDATE / NATIVE_T1_NOT_AUTHORIZED / NETWORK_UNDECIDED
TASK_ID: MULTI-EXEC-LBE-FIVE-DAY-CANDIDATE-20261105
MILESTONE_ID: PR113-T1-CONTROL-PREPARATION-T0-001
PARENT_PR: #113
PARENT_BASE_SHA: ec25c34492912f3a82175fa9c1060e0632814687
PARENT_HEAD_SHA: fc94cc36ce793e32a3fb97d5a500a47608be6781
PARENT_HEAD_TREE: fa51d2a7a881f8e4915badcfe0fb088f2fca0ee3
FIXED_PRODUCT_DESIGN: Git Blob d90df6de3bdbd81a314109d5f73959799b5a10a6
DESIGN_WORKING_BLOB: 4806c2958eebdf14e3e3c02cbc50764d0bc823ed (NOT independently approved)
RULES: ICR-V2.0 / GHRH-2.0 / ETP-V2.0

## Allowed deliverable and boundary

This separate test-control branch/PR is BASED ON frozen PR #113 product Head and targets its feature branch. It changes only one new static tool, one new pure-stdlib unittest source, this document, an INCOMPLETE external-input lock, and the branch-only Manifest. It does NOT edit any existing gateway/* code, native launcher, old PR113 frozen Head/Tree, R006 workflow or policy, security gate, PR113 test scripts, workflow trigger, Go/Pipenv/python fixture, or protected base branch.

The source under `tools/pr113_t1_control_t0.py` has NO launch adapter, NO workflow runner, NO network probing, no Go/Pipenv invocation, no external download, and NO public positive Exec path. Its `native_execution_decision` ALWAYS raises `GateDenied`; editing the JSON file cannot authorize a native run. `check_event_shape` checks self-reported shape only: it cannot authenticate a GitHub Owner or mint a permission. `consume_local_once_t0` demonstrates private local exclusive-create serialization in throwaway temp directories, but does NOT provide cross-run/job globally consumed authorization on different hosted runners. Separate Owner-authenticated run identity, replay-proof durable authorization and distinct reviewed control implementation are necessary for T1.

Negative-command T0 uses a mocked `subprocess.Popen` inside a negative-only callback and treats attempted Popen as failure; this is not an OS-wide sandbox or proof against imports that captured other process creation functions. Native tests must use separate vetted control processes after security review. One fake fail-open callback is intentionally exercised UNDER THE MOCK ONLY to demonstrate that a seventh Go child is not launched.

## Explicitly unfinished foreign-input and network gate

`docs/PR113_T1_FOREIGN_INPUT_LOCK_001.json` is a typed manifest with 9 required classes of external inputs and no future trusted hashes for any of them. Historical Python/Go/Pipenv SHA-256 strings are receipts, not validated new toolchain bytes. Mac image exact identity, Python/Go/Pipenv distribution, all actual wheels/installed RECORD and import/loader origins, full action commit SHAs, test-control SHA, generated fixture/Pipfile/venv, network policy and Owner-authenticated authorization remain INCOMPLETE.

Two potential future network modes (strict enforceable OFFLINE_ONLY or separately approved Design-002 trusted-local bounded risk) were proposed in the nonoperative Design working Blob. NEITHER is selected or approved. There is no precontact network sandbox, no UDP/DNS denial attestation, no hosted Runner CPU/RAM/FS hard isolation, and no unqualified fallback. The more demanding PR102 Gate B must be independently reconciled with Design-002's six-only risk before any test execution. No child should start on the basis of this manifest.

## T0 coverage and safe-only commands

The new unittest suite covers exact Head/Tree/contract shape, rejecting wrong PR/actor/event/Head/Tree/control/run ID/run_attempt, replay and duplicate local claims, two-phase chronology, conservative global elapsed deadline, schema and digest checks, negative-only Popen interception under fail-open callbacks on three declared route identifiers, and an unconditionally refusing native gate. The suite uses only Python stdlib, simulated metadata, temporary local files and unittest.mock. It contains zero actual service-origin native attempts or Go/Pipenv calls.

For a safe local environment with Python already present, from the isolated branch checkout only:

    python3 -B -m unittest discover -s tests -p test_pr113_t1_control_t0.py -v

`unittest` does not prove the future test-control workflow, app imports or third-party source bytes, even if all cases pass. The actual PR branch CI, when triggered by GitHub, is separately recorded as CI evidence; this document does not claim any pending workflow has already run.

## Frozen snapshot and milestones

PARENT: PR113 source round r002 remains frozen; C source FULL PASS applies only to that source, B source P2-EVID-02 remains OPEN, R10 BLOCKED. Existing PR113 R006 strict host CI was FAILED from ambient credential-bearing environment and MUST NOT be masked.

CURRENT CONTROL MILESTONE: prepare a separate reviewable Draft PR containing safe T0 control source, typed missing-input lock and verified T0 tests. This is NOT qualified native T1 control, is NOT a PRODUCT feature, and is not a new Owner test execution authorization. B/C independently review new control snapshot and any later chosen network contract; no reuse of B/C previous design BLOCKED results as PASS.

NOT_RUN / NOT_AUTHORIZED: new PR113 actual native six S1-S6 x Direct/REST/MCP 18 tests, one mixed S1+Git/File T1, Go/Pipenv installations or project commands, arbitrary network probe, precontact firewall/VM changes, T2/T3, user Mac/Tunnel, shared/production, process kills/signals, merge, deploy, release or tag.

Next milestone: once separately authorized network mode and exact external code/byte provenance are qualified, implement a separate frozen executable workflow/controller and request new B/C targeted security and Spec reviews; then seek Owner's new exact one-shot NATIVE T1 approval. There is no automatic promotion from this T0-only candidate.
