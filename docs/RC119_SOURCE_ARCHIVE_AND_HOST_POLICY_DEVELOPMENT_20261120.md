# PR122 — real source archive evidence + inert host metadata policy (A development)

TASK_ID: MULTI-EXEC-LBE-RC119-T1-QUALIFICATION-PREP-20261118
MILESTONE_ID: RC119-T1-QUALIFICATION-PREPARATION-001
MILESTONE_STATUS: DEVELOPING / NOT FROZEN / NO FORMAL B/C CODE HANDOFF
ROLE: A DEVELOPER (not B/C independent code sign-off)
REVIEW_TARGET: Two new nonoperative tools, two targeted SAFE T0 test suites, this development note, the **unchanged** standalone already-targeted safety design Blob, and MANIFEST.sha256 if/when actually committed.
PRODUCT_PR: #119
PRODUCT_BASE: ec25c34492912f3a82175fa9c1060e0632814687
PRODUCT_HEAD: 33c30b6c2710cac0f8533370c1ca42f31ef6747a
PRODUCT_TREE: 27e26c423e700cdbad0aeca27efcdf82594507c1
CONTROL_PR: #122
DEVELOPMENT_HEAD_PREPARATION_BASELINE: 77d262c8afba8a98512c30f72172bf22ae1fe5a0
DEVELOPMENT_TREE_PREPARATION_BASELINE: 55c1dd70498642a6fa568f4432a2aef988310d83
SOURCE_SCOPE_BLOB: fed1cdae899d38fb300b860eb307c2d027ae8b39
PROFILE_B_CONTRACT_BLOB: 1df5ccf9dbf920ff243e04d0e57f45a82e1b2a13 (nonoperative conditional design)
PR102_GATE_B_BLOB: 7db3b77aadca8b0c284e28fa5ee64e315e9275d2
PRODUCT_DESIGN_002_BLOB: d90df6de3bdbd81a314109d5f73959799b5a10a6
RULES: ICR-V2.0 / GHRH-2.0 / ETP-V2.0

## 1. Actually obtained source bytes (not simulated)

Existing GitHub disposable macOS source-only Job 135671539342 of Run 41275998082 on **PR101 Head ec25... / Tree 3a127...**, NOT PR119 product Head, fetched and verified the 10 exact Go 1.27.3 Darwin ARM64 / Pipenv and Python Wheel original archives. Artifact ID 14545306271 is 81,608,549 bytes, SHA256 1e949b334398f51d9f5eadae716e3107877c61deff2654d9ad6c5052b741a67f; it expires 2026-11-26T15:32:31Z on GitHub. Prior independent archive download/verification was made in the authorized source-only milestone.

`tools/rc119_source_archive_bridge.py` implements **local read-only, stream-bound** re-verification of exactly that known outer Artifact and ten original compressed SHA256 identities. It enforces an exact 16-member ZIP set, no duplicates, no traversal, no symlink or deflated payload, source-only PR101 evidence identities and a fixed compressed-archive file-size budget. It does **not** unzip to disk, install, import or run Go/Pipenv/Wheels. The artifact itself stays outside the Git repository and does not become part of product install or execution.

The evidence grade is always TEN_ORIGINAL_COMPRESSED_ARCHIVES_VERIFIED_ONLY. The PR120 22 selected execution input categories (installed Python/Pipenv/Go/SDK, actual action/image, import precedence, fixture, credential/FD/mount domain) remain NOT_ATTESTED. No `SOURCE_CLOSED_NATIVE_T1_PASS` or runtime dynamic-source guarantee is supplied by 10 raw archives.

## 2. Host safety design and implementation boundary

The separate immutable document Blob fed1cdae899d38fb300b860eb307c2d027ae8b39 was independently reviewed on PR122 by C in rounds labelled `RC119-HOST-N1B-METADATA-ONLY-TEST-SCOPE-001` and B in round labelled `RC119-HOST-READONLY-DESIGN-001`; both TARGETED DESIGN PASS on the SAME Blob, not full code review, actual host run or first-hand Owner exact-run authority. This exact text may be included unchanged in the future development snapshot (its Git Blob SHA MUST remain identical). PR122 nine-path code review was not covered by their decisions.

`tools/rc119_host_metadata_policy_t0.py` has **NO host collector, no os.environ, no path/FD/socket/mount/network read, no CLI and no installer/child launch**. It accepts only bounded caller-supplied synthetic JSON category fixtures: bootstrap, environment, credential paths, FDs/socket, mounts, cloud identity, sentinel, stability and exact synthetic host identity. For each category RISK => `HOST_DENIED_SIMULATED`, UNKNOWN => `HOST_UNKNOWN_SIMULATED`; even all CLEAR yields `HOST_CATEGORICAL_CLEAN_SIMULATED` with `actual_host_job=NOT_RUN`, `n1b_qualified_pre_foreign=false`, `native_execution_authorized=false`. No payload contents or exception paths are emitted. Fixed enumerated redacted reason labels and <=1300-byte receipts are the only output.

This is a **non-executing source candidate** for the later exact verifier safety review. Before any real host job, a distinct reviewed nofollow/macOS source metadata collector, strict mounted-path/policy API, bootstrap/checkout permissions, bounded output/exception schema, the specific future host image and credentials/FD domain, and an independent first-hand Owner exact one-run approval remain required. No R006 workaround or Profile B open-egress waiver is implemented.

## 3. Representative SAFE T0 checks / exceptions

- Actual PR101 ZIP offline re-read rechecks 10 archived compressed source identities and retains `NOT_ATTESTED` for the current 22 loaded inputs.
- Synthetic duplicate ZIP entry, `..`, absolute, unapproved file, symlink, compression, damaged archive, wrong SHA or length, local symlink to artifact and oversized synthetic fixture -> reject before any extraction/foreign import.
- Synthetic environment clean + inherited agent FD risk, no visible OIDC env yet cloud reachability unknown, credential-helper/secret path risk, writable autofs, wrong image/UID/attempt, absent sentinel/metadata -> deny/unknown.
- No raw path or untrusted token in the emitted reason codes; malformed/oversized JSON, malformed receipt, exception object and forged actual Host/N1B/native success -> refuse.
- Real-host API checks, live path/FD/socket inspection, any outside-network experiment, downloaded tool installation/import, native S1–S6 x3+MIXED are NOT_RUN by these tests.

## 4. Remaining full milestone / handoff requirements

A. Exact installed and **actually selected** runtime sources, complete 22-category identity and source-shadow/loader evidence; raw compressed artifact identity alone is partial.
B. Verified same-UID secret-inaccessible disposable macOS host evidence and R006 applicability, only under separate review and exact Owner test authority; a metadata-only outcome cannot prove full same-process no-secret reachability.
C. Independently reviewed authenticated cross-runner once-only control/immutable run permission, approved Profile B executable implementation and actual 18-route native+MIXED evidence.
D. Product PR119 B Standards and C Spec FULL evidence blockers, R10 and real integration; separate explicit release/merge/tag/deploy authorization.

DEVELOPMENT_STATUS: CODE_CANDIDATES_LOCAL_ONLY_UNTIL_ACTUAL_GITHUB_COMMIT_IS_VERIFIED. A direct GitHub Blob alone is not a PR Head. Existing standard PR122 GitHub CI auto-downloads and installs ordinary pinned Python packages; the Owner's narrower source-only/no-install instruction does NOT authorize silently triggering that CI. Code candidates may be prepared/tested locally without any new GitHub runner. No GH_HANDOFF_V2 READY_FOR_REVIEW/FIX_READY until the complete applicable milestone's actual freeze conditions hold.
FREEZE_READY: NO
NEXT_ROLE: A for remaining authorized development/evidence and Owner for distinct real host/loader/CI authorization.
