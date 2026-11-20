# RC119 T1 source evidence qualification — T0-only development record

MILESTONE_ID: RC119-T1-QUALIFICATION-PREPARATION-001
MILESTONE_STATUS: DEVELOPING / STATIC_SUBSET_DONE / OVERALL_QUALIFICATION_BLOCKED
ROLE: A DEVELOPER (NOT B/C or authenticated Owner GitHub signature)
REPO: chinanjjohn2012/mac-file-gateway
SOURCE_RC_PR: #119 (OPEN/DRAFT/FROZEN)
SOURCE_RC_BASE_SHA: ec25c34492912f3a82175fa9c1060e0632814687
SOURCE_RC_HEAD_SHA: 33c30b6c2710cac0f8533370c1ca42f31ef6747a
SOURCE_RC_HEAD_TREE: 27e26c423e700cdbad0aeca27efcdf82594507c1
PARENT_STATIC_CONTROL_PR: #120, Head 299bcaff1c075396d205caa450344f7246350d62
PARENT_PROFILE_B_DESIGN_PR: #121, Head 22bae3bf359ccc0678a6f691b1e8188a4872cee2
PROFILE_B_CONTRACT_BLOB: 1df5ccf9dbf920ff243e04d0e57f45a82e1b2a13
PRODUCT_DESIGN_BLOB: d90df6de3bdbd81a314109d5f73959799b5a10a6
RETAINED_PR102_GATE_B_BLOB: 7db3b77aadca8b0c284e28fa5ee64e315e9275d2
RULES: ICR-V2.0 / GHRH-2.0 / ETP-V2.0

## Contract and authorization boundary

The user directly accepted all six residual risks in the exact #121 v1.1 Profile B proposal **as a candidate for one disposable six-command test only**. A recorded this decision at https://github.com/chinanjjohn2012/mac-file-gateway/pull/121#issuecomment-6954483933. A's GitHub comment is an accurate **relay**, NOT a signed owner GitHub event or independent B/C provenance decision. Historical text headers `PROPOSED_NOT_EFFECTIVE` remain historical. No operative blanket downgrade to PR102 Gate B is made by this document.

Six accepted risks: arbitrary first outbound network contact without enforceable egress restriction; same-UID filesystem/process effects; unknown descendant cleanup; repeated effects after crash/retry; source/loader path race; and post-admission dynamic downloaded code without complete runtime source graph attestation. Accepting these does NOT prove they did not occur and cannot convert a behavior observation into `SOURCE_CLOSED_NATIVE_T1_PASS`.

No permission was given for external source download/install, native T1, network/credential/metadata/host probing, executable T1 controller implementation, T2/T3, user Mac/Tunnel, shared/production, R006 relaxation, merge, Tag, release or deploy. An exact one-run authorized event is still required separately and not issued.

## Delivered SAFE T0 source check

`tools/rc119_native_evidence_static_audit.py` reads separately retained original PR114 ZIP receipt bytes **as data**, never imports them or launches a subprocess. It verifies the complete ZIP digest and unique JSON member, old product Head/Tree/contract, unique six x three original-child results and separately recorded real File/Git mixed phases. In-memory negative cases reject wrong old-vs-current identity, duplicate/missing route, false exit/output and false descendant-cleanup claims. The report always states current RC source/host/loader/integration as unqualified, `native_execution_decision=DENY_UNAUTHORIZED_AND_UNQUALIFIED`, `release_decision=BLOCKED`.

Run only offline against separately preserved evidence files, without downloading or executing anything:

```sh
python3 tools/rc119_native_evidence_static_audit.py --archive-dir /path/to/already-preserved-pr114-receipts --output /path/to/local/report.json
python3 -m pytest -q tests/test_rc119_native_evidence_static_audit_t0.py
```

Old original source was PR114 Head `1ef390638a5ba69802d152621544e02d89461788`, Tree `fa51d2a7a881f8e4915badcfe0fb088f2fca0ee3`, not current PR119 Head or Tree. Native original Artifact 14106505883 ZIP SHA256 `5c4b167ebf922e93396f82c922f56d398855bc346abdbc8eb212253c69308344`; mixed Artifact 14105873594 ZIP SHA256 `3f86aa0c7f941d3232a9d61efff9d1c914b5f9a017572967e270f4a45a4b49a9`. The archived ZIPs are not part of the Git Tree and no current RC native PASS is inferred. The script's old observed executable SHA256 values belong solely to PR114's old execution.

## Remaining mandatory gates, prioritized

1. **Current external input lock:** PR120's fixed JSON template has 22/22 categories with `NOT_ATTESTED` current selected external bytes. No upstream installation/source graph/RECORD/Go and Python/Pipenv import precedence may be treated as pinned. Archival old tool checksums are not current receipts.
2. **Host/no accessible secrets:** fresh, qualified same-effective-UID, FD, socket, HOME, mount and metadata domain, with no reachable credentials **before first foreign installer/hook**. Existing current PR119 macOS strict R006 CI FAIL is not waived, and actual host qualification requires separate approval.
3. **One-use authorized source controller:** independent authenticated Owner run/attempt=1 exact RC/Controller/lock/profile, durable atomic cross-job claim/revocation, trusted SIX-to-MIXED phase continuity, exact no-seventh-child interlock, budget/remaining-time stop, independent B/C applicable review. Only nonoperative T0 checks exist so far; executable Controller work requires its own permission.
4. **Product evidence:** source-equivalence PR114 historical results are auxiliary, not current PR119 native and SDK/REST/mixed real evidence. B Standards and C Spec on PR119 are BOTH full BLOCKED, PR113 B P2-EVID-02 OPEN, PR120 B BLOCKED. Real full integration, R10, release and deployment remain blocked. Run and release would need separate future authorization even after qualification.

This is a developing STATIC evidence supplement only. It intentionally does not issue `GH_HANDOFF_V2 READY_FOR_REVIEW` or `FIX_READY`, certify a runner, activate a network exception, or claim the complete native qualification milestone is frozen.
