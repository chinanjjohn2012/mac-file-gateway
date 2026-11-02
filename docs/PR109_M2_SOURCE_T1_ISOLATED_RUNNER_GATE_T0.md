# M2 SOURCE_TOOLCHAIN_T1: Source-locked execution admission and OFFLINE_ONLY hard stop (T0)

TASK_ID: MULTI-EXEC-LBE-M2-SOURCE-T1-HARNESS-OFFLINE-GATE-20261102
STATUS: NONOPERATIVE T0 TEST HARNESS / REAL GO-PIPENV T1 NOT_RUN / OFFLINE ISOLATION NOT_ATTESTED / NO PRODUCT EXEC AUTHORITY.

## 1. Fixed authority, independent review, and owner grant

New independent Draft PR based on PR #108 r003 Head 8760cf6bf1498ad38741d2e417a732b88a4e0391 Tree f64ba5b1f2bfbe384aebcab9dacecb3948e23981, after B Standards and C Spec independent TARGETED r003 PASS, solely for the prior M2 NONOPERATIVE T0. Older role passes are NOT inherited by this new source. Project rules ICR-V2.0 / GHRH-2.0 / ETP-V2.0.

Fixed product/design refs: PR #102 r002 native gate Git Blob 7db3b77aadca8b0c284e28fa5ee64e315e9275d2 sections 3,5.1-5.5,7-9; PR #98 schema-v2 local_best_effort design Git Blob 9e6622401b198138039c692efe91fba1a8d06891. Operative D0 6e25904aed9a62bb0f472b732021c2a7ca3b3bb0, F1 76baeb820c6f8a9b067e45e2dcc42e76453fe5b1, Phase1 b3f2383f292a59fd234269389e5338cd50e334a2, G05 76c1c2b8a7947e0b305d55c5f550ab59c638b6d1, and R004 2ffe5341288e428be5ee5d0fa8d52aea3e9efc93 remain binding.

Owner Gate A exact-version risk consent recorded via A on PR #102 comment 6559619893. Owner Gate B conditionally approved an isolated OFFLINE_ONLY standalone SOURCE_TOOLCHAIN_T1, recorded transparently by A on PR #102 comment 6560708487. Owner separately instructed A in the present conversation to create a NEW Draft PR based on PR #108, implement test execution framework, source identity checking, precontact offline gate and T0 counterexamples, obtain new B/C review, and only permit native T1 when all independent execution requirements are really satisfied. The owner accepted candidate runner and resource ceilings, not unqualified GO/Pipenv execution, product Exec or deployment.

## 2. Actual new code and observable boundaries

- gateway/lbe_m2_t1_source_tree_t0.py is an actual first-party SHA256 checker of ALL files in the operator-approved private staged source tree. The source staging root must be the DIRECT lexical child of its explicitly chosen private trusted base, in addition to M1 no-follow traversal; a caller-provided ancestor alone does not prove owner provenance. It uses the reviewed M1 no-follow descriptor traversal, owner and mode checks, before/after inode and content hashing and rejects unlisted importables (including .pth), hardlinks, symlinks, FIFO/socket/device files, unexpected executables, altered digests or casefold-colliding names. Bounds: 20000 listed files, 30000 directories, 128 MiB max per member and 2 GiB aggregate. A matching caller-provided manifest is evidence of the inspected T0 bytes ONLY, not upstream source authenticity or the source ultimately selected by a native child.
- gateway/lbe_m2_t1_source_execution_gate_t0.py provides a test execution admission control. It requires a previously verified NONOPERATIVE M2 plan, rechecks the staged source closure and records inspected source bytes, proposed Git Head/Tree and diagnostic local platform. The result is ALWAYS BLOCKED_PRECONTACT_EXECUTION_GATE_T0 and has execution_allowed=False, product_exec_authorized=False, native_t1=NOT_RUN, actual loaded source/runner/CPU-RAM/egress NOT_ATTESTED and same-domain canary NOT_RUN. Its execute_source_toolchain_t1 entrypoint is deliberately HARD-DENIED for EVERY receipt or caller-provided approval claim. It cannot spawn any native child.
- tests/test_lbe_m2_t1_source_execution_gate_t0.py constructs only synthetic fake Go/Pipenv trees and uses ACTUAL predecessor M1/M2 T0 source APIs, with subprocess/socket spies, to verify legal source closure and unsafe source/manifest, linked shadow, special file, changed bytes, modes, base path, budget, claims and forged receipt rejection. No real Go/Pipenv binary or live networking is used.
- This PR does not modify existing F1, WorkspaceService, Native Launcher, Worker, public Direct/REST/MCP/Git/File, production config or CI workflows; the existing Linux Head CI executes only ordinary T0 plus existing deny-only/live adjacent regression. A future independently reviewed actual runnable provider is required to turn the test control surface into a native executor. Calling this code a real launched or isolated T1 would be a false claim.

## 3. Specific future standalone native T1 matrix and budget

Only after a NEW fixed/independently reviewed executable runner and verified Gate B prerequisites: Go1.27.3 with go test ./..., go vet ./..., go build ./cmd/service and go build -o bin/service ./cmd/service on private minimal stdlib-only fixture. Pipenv2026.10.4 with pipenv run python ok.py on fixed Pipfile/Pipfile.lock/private .venv Python3.13. No go run, Pipenv install/lock/sync, user scripts, external downloads or unknown hooks. Actual compiler/stdlib/modules/generated code and Pipenv shebang/selected interpreter/venv/site/seed/.pth/RECORD-unlisted imports must be qualified as ACTUALLY LOADED. Static hash closure does not prove this.

The owner-approved resource proposal is ONE disposable GitHub-hosted macOS 15 ARM64 job, <=20 minutes overall, <=120 seconds naturally expected-to-exit original child, exactly one standalone child active, <=120 CPU seconds, <=2048 MiB RAM, <=48000 retained raw BYTES for EACH stdout/stderr stream and separately <=48000 redacted returned CHARACTERS per stream. This T0-only code does not enforce real OS CPU/RAM/wall/pipe budgets. Prior Python-only 5-second fixture is not authorization to start Go/Pipenv; a future exact T1 job must independently enforce every limit and prove its actual runner image, Python version, source identity and execution code SHA/tree before any Go/Pipenv child.

## 4. Mandatory OFFLINE_ONLY precontact isolation

Before ANY native Go/Pipenv instruction, separately reviewed first-party controls must create an independently inspectable isolated execution domain or audited equivalent, actually denying outbound TCP/UDP/DNS and unexpected proxy routes for the original child AND every descendant. The source and actual identity of that domain enforcer must be fixed. A separately permitted non-destructive denial canary must produce original DENIED evidence inside the SAME attached domain BEFORE a foreign process starts. Require actual domain attachment, inheritance and witness linked to the selected job/child, not user-provided text.

No enforceable hosted macOS precontact domain or provider/canary has been implemented or qualified in THIS PR. Environ flags GOPROXY=off, PIP_NO_INDEX=1, a proxy value, claimed witness, CI GREEN, post-contact monitor or a source-only digest are not enforcement proof. Do not install host-wide pf/firewall or try unapproved privileged modification. If no qualified policy is obtainable, STOP before native code, report T1 NOT_RUN / EVIDENCE_STATUS INSUFFICIENT; bounded egress fallback is separately unapproved.

## 5. Safety limits, risks and required separate test/review

No actual Popen, native Go/Pipenv import or compiler, network or firewall, unrelated shell, unqualified process signal, OS PID/PGID kill, timeout survivor, T2 crash/restart, T3 user/shared Mac or production experiment, grant activation, merge/tag/deploy is permitted by this code. Candidate source trees still have same-UID race after T0, and the M2 plan's Git SHA, toolchain origin and hosted runner image are NOT independently measured here. Even future hosted runner teardown is not proof of descendant retirement. Native child timeout/unknown state in a future reviewed execution must stop further admissions, not auto replay.

The existing ordinary F1 dry_run=false Exec stays denied before Popen (exec_cleanup_proof_required), and unapproved Go/Pipenv launcher selection stays denied. Legacy/v1/UNKNOWN and distinct Git/File grants are unchanged. T1_PRODUCT and positive WorkspaceService/Direct/REST/official MCP/native integration require separate product-origin authorization, new source code, independent B/C FULL reviews and actual integration proof; standalone SOURCE_T1 PASS is never enough for Gate C/R10.

For this new Head, require B Standards and C Spec to independently review the complete effective changed file set and actual Head+Tree, original Linux T0 CI/skip reasons, T0 pass/fail/edge/exception tests and nearby F1 regression. All 19 historical Linux skips and unrun current native/egress/source-loaded tests must remain explicitly NOT_RUN/INSUFFICIENT for claims depending on them. Freeze current Head after an accurate A GH_HANDOFF_V2 READY_FOR_REVIEW. Changing Head/Base/Tree, source, rule or contract versions needs a new review round; no historical PASS transfer.


## 6. Initial Linux CI T0 red and narrow baseline correction

The new Draft PR initial Head 3e8d990213f10c302a8578ef90a11a78749683c7
and Tree 7f5678f944a2d79b1fe09b510eb596ea8bb6eb44 was exercised by
https://github.com/chinanjjohn2012/mac-file-gateway/actions/runs/41365741602/job/125025403368.
Original G05 verified 295 Blob/mode identities and 294 SHA Manifest entries;
pytest produced 2423 passed, 2 failed, 19 skipped, 1 warning.
Both new red failures were test_wrong_trusted_base_or_root_does_not_become_a_grant:
the older M1 preflight accepted an ancestor private base in the valid path
lineage; the new standalone T1 staging contract must instead require
private_root.parent == trusted_base. The rejected ancestor is a T0 path
qualification issue, NOT a proved native Go/Pipenv escape. The failed pytest
prevented all later smoke and posttest final steps from running on this RED
snapshot. A has changed the T1-only source tree checker to require the
direct lexical private base child, and must verify it on a new exact Head.
No historical RED or CI badge is represented as a new GREEN result.
