# PR #101 — r004 F1 adjacent legal Git and File regression under v2 Exec denial

TASK_ID: MULTI-EXEC-LBE-V1-CONSOLIDATED-20261030
REVIEW_ROUND: r004 (new Head, additive evidence-only change, not r003 review mutation)
ROLE: DEVELOPER (A), not B/C independent reviewer
REVIEW_TARGET: TARGETED proof of same-WorkspaceService real authorized Git Apply and File Write after healthy ordinary v2 Exec proof denial AND after a real persisted old Exec UNKNOWN/quarantine.
CONTRACT_SCOPE: Operative D0 F1 §0.1, §0.2 and §0.3 Git Blob 6e25904aed9a62bb0f472b732021c2a7ca3b3bb0; F1 production-first plan Git Blob 76baeb820c6f8a9b067e45e2dcc42e76453fe5b1; Phase1 trust Git Blob b3f2383f292a59fd234269389e5338cd50e334a2; G05 Git Blob 76c1c2b8a7947e0b305d55c5f550ab59c638b6d1; user-accepted NONOPERATIVE local_best_effort PR98 r002 design Git Blob 9e6622401b198138039c692efe91fba1a8d06891. Exact V2 ICR/GHRH/ETP rule sources must be independently verified per role.
HISTORICAL_PRIOR_REVIEWS: PR #101 r003 independent B Standards GitHub native Review ID PRR_kwDOU5v3IM8AAAABVPTaXA and C Spec Review ID PRR_kwDOU5v3IM8AAAABVPTANA, both TARGETED_REVIEW_PASS at Head 5617c8f3edfbb6a23c17ccd82c2337ecc0f29a6b and Tree 3b1ee9e3fc300ee302f586ff605fa90489da936b. They were not FULL reviews. B disclosed in its independent R03–R06 adjacent coverage section that a v2 **same-service** legitimate Exec proof denial + REAL Git Apply after healthy and UNKNOWN, plus authorized File Write, was not observed together.
DYNAMIC_SOURCE: current GitHub PR #101 HEAD/BASE/TREE/MANIFEST and new original CI; no static doc is substituted for those.

## The new evidence-only T0/T1 adjacent test

The added tests/test_lbe_adjacent_git_file.py::test_v2_same_instance_real_git_and_file_write_after_proof_denial_and_unknown uses one actual schema-v2 WorkspaceService with a single Workspace A configured for BOTH allowed Exec preview paths, allowed Git status, and allowed File Write; Workspace B has no such permissions. Only a disposable pytest tmp_path Git repository is initialized via the already-authorized real Git CLI; no project command/native Go/Pipenv Exec is launched.

The private ExecStateStore is created once in a disposable root OUTSIDE both Workspaces and re-opened existing-only by schema-v2 service. Assert configured legal Python Exec dry_run=true returns preview with no child. With a scoped Popen-__init__ and OS kill/killpg trap active, invoke the same authorized Workspace A's legal Python dry_run=false and require exec_cleanup_proof_required *before* intent write/slot/Runner/Popen. Verify no records and no acquired direct-child slot. REMOVE the scoped trap before invoking Git: it must launch a REAL separately authorized Git subprocess and return exit_code 0 + execute_started true + repository_checked true, on this SAME service AND SAME Workspace. A separately authorized File Write/read-back must work on that same instance.

Next, deliberately seed a persisted UNKNOWN through the ORIGINAL ExecStateStore.prepare / mark_unknown methods for the same disposable Workspace A; this creates an actual private intent record solely as an inert test fixture, without an Exec child. Snapshot the raw UNKNOWN bytes. Verify subsequent dry_run=false Exec returns exec_quarantined with Popen/signals trapped. REMOVE trap again; REAL Git status and real File Write/read-back must still succeed in the same WorkspaceService/Workspace. Record bytes and quarantined state must remain unchanged. Unauthorized Workspace B Git, File Write and Exec must still refuse, and no denied file should be written.

This is a bounded non-destructive Git subprocess and private-state T0/T1 accepted by the existing F1/G05 contract; not user Mac/Tunnel, OS process signalling, Native C, or a new public Exec grant. The global Popen trap is never active during legal Git; it only proves denied Exec could not spawn. This closes a developer-evidence gap, NOT a B or C independent counterexample or review verdict.

## Qualification and remaining gates

Only new exact-Head original Linux/macOS CI can prove the new test actually ran; job and test counts, G05 100% source/exec modes, Git Tree/Manifest and environment must be checked. This additive change creates a NEW r004 Head and does not inherit r003 FULL review or re-label r003 TARGETED as an r004 independent PASS.

R004 does not approve a real Go/Pipenv executable, complete external Go compiler/stdlib or nine-wheel source code audit, new product D0 positive Exec exception, external REST/MCP/Tunnel integration, unsafe descendant cleanup, T2/T3 experiments or production deployment. Full 65-file code R10 remains BLOCKED until separate independent FULL reviews and legally scoped tests/permissions. NO merge/tag/release/deploy.
