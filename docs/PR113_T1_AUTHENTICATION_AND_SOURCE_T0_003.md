# PR113 — T1 one-shot authority and loaded-input qualification controls (T0-only implementation)

STATUS: COMPLETE_CANDIDATE_FOR_STATIC_T0_SCOPE_ONLY / NONOPERATIVE / NATIVE_T1_NOT_AUTHORIZED
TASK_ID: MULTI-EXEC-LBE-FIVE-DAY-CANDIDATE-20261105
MILESTONE_ID: PR113-T1-CONTROL-PREQUALIFICATION-T0-002
PARENT_PRODUCT_PR: #113 (FROZEN Head fc94cc36ce793e32a3fb97d5a500a47608be6781, Tree fa51d2a7a881f8e4915badcfe0fb088f2fca0ee3)
PARENT_CONTROL_PR: #116 (FROZEN Head d4b5a70415db6422fef7996f186bdc235436bbc3, Tree a180edbd0d6e0f87c20f527fea5245f6566e5e47)
CURRENT_CONTROL_PR: #117 (development/freeze Head to be populated from REAL GitHub Git object; never self-reference in source)
NETWORK_CONTRACT: PR113-T1-NETWORK-DESIGN-002, immutable Blob 89206350f8025425c74033780a3166df5d68b88c
PRODUCT_CONTRACT: six-only Design-002 Blob d90df6de3bdbd81a314109d5f73959799b5a10a6, retained PR102 Gate B Blob 7db3b77aadca8b0c284e28fa5ee64e315e9275d2
RULES: ICR-V2.0 / GHRH-2.0 / ETP-V2.0
AUTHORIZATION: Owner selected **Profile B risk model only**, via direct A chat relayed on PR #116 (issuecomment-6897512856). No Owner grant for any real native T1 execution, network probe, host configuration or external code acquisition is issued.

## Code delivered, capability limits and independent proof requirements

`tools/pr113_t1_attestation_t0.py` extends existing **nonspawning** controls under `tools/pr113_t1_qualification_t0.py`. It has no GitHub client, environment takeover, installer, network requester, shell or native-execution adapter. The sole `native_execution_decision` unconditionally throws `GateDenied` regardless of the contents of any supplied JSON, receipt or Owner claim.

| Control | Actually checked by T0 | Still unproven before native T1 |
| --- | --- | --- |
| Fixed run identity | Exact repository/PR/product Head+Tree/independent network design/claimed control Head+Tree+input-lock hash; workflow_dispatch actor, run ID, attempt=1, job ID and phase; exact-field rejection of extra claims and booleans | Trusted GitHub primary API/original Owner authorization, correct branch/permission, execution-time checkout, globally persisted consumed grant |
| Two-Job sequencing | A four-stage SIX START/PASS → MIXED START/PASS ordered transcript; independent Job IDs, no duplicate receipt hashes, mismatch/replay rejection | Authentic Job lifecycle, atomic cross-Runner compare-and-swap and revocation, actual S1–S6 and mixed observations |
| Minimal environment | Exact allowlist of *names*, deny ambient token/proxy/GOCACHEPROG/GOFLAGS/PIPENV_PYTHON/PYTHONPATH/SSH/OIDC selectors | Values, accessible files, metadata endpoints, private mounts, source loader hooks, process environment at the real earliest foreign instruction |
| Existing selected file bytes | Read-only O_NOFOLLOW fd-based digest of existing private dummy fixtures; compare size+SHA256 with caller claim | Trusted acquisition origin, installed selected runtime / interpreter / Go module / wheel source identity, signed provenance or full closed imports |
| Wheel `RECORD` | In-memory read-only `zipfile`+stdlib CSV SHA256/size check for all ZIP files; reject missing/duplicate metadata, unlisted files, hashes, path escapes, case-shadowing, nonregular members and large compressed/uncompressed budgets | Actual wheel bytes, external download sources and redirect chain, all transitive wheel files, installed filesystem RECORD and loaded `.pth`/startup hooks |
| Positive native result | **No ALLOW result exists**; an otherwise well-formed fake run or archive only returns a `T0_ONLY` classification | Full executable test-control source/B+C review, actual Owner run approval and independent T1 execution evidence |

### One-shot authentication distinction

A claimed `workflow_dispatch` event, a matching `run_id` / `run_attempt=1`, and even a four-step `six_pass → mixed_pass` transcript are **not** authenticated merely because user-supplied values match a template. `inspect_untrusted_run_claim_t0` and `inspect_two_job_transcript_t0` deliberately return `owner_authenticated=false`, `github_origin_authenticated=false`, `globally_consumed=false` and/or `native_execution_authorized=false`. The previous `consume_local_once_t0` (`O_EXCL` in a disposable test directory) is local-only and cannot prevent parallel GitHub runs on separate VMs.

An actual future native test must validate the real Owner primary approval and immutable reviewed control and input SHAs from a trusted GitHub API context, not a user-controlled event field. It must provide a durable **atomic** consumed-grant barrier shared across both Jobs and concurrent/retry workflows, with revocation, unique Run ID and attempt=1; separately review and T0-test all such actual source. None of these external-service elements exists or is exercised here. **No executable workflow is created by this milestone.** The workflow path constant is a future exact-name guard, not an actual authorized workflow.

### Selected-byte and network-security distinction

`inspect_private_bytes_t0` reads only already-present caller-selected bytes inside private owned disposable paths. It never fetches a toolchain or installs/loads a Wheel; even all dummy-file matches would not independently attest their origins. If asked to prove a Git Blob SHA using this SHA256-only helper, it fails closed: it never reopens a verified path after hashing, which would create a TOCTOU race. The Wheel `RECORD` scanner consumes **in-memory** synthetic ZIP bytes, does not extract/install/import anything and refuses to imply the wheel is part of an actually qualified dependency closure.

The approved Profile B permits potential uncontained child DNS/HTTP/network and same-UID effects only within its strictly named *risk* scope, but **does not waive** the earliest installer/import no-accessible-secrets requirement or source-integrity failure on unqualified loaded code. A correct wheel `RECORD` or minimal environment *keys* alone cannot prove those conditions. Under strict Profile A, original PR102 OFFLINE_ONLY precontact network denial would still require a separately authorized real witness; the test here makes no such claim. Strict R006 ambient-credential checks remain unchanged.

## Safe original and future validation

T0-only commands in an isolated developer workspace containing the exact reviewed test-control files:

```text
python3 -B -m unittest discover -s tests -p 'test_pr113_t1*' -q
python3 -B -m tools.pr113_t1_qualification_t0
```

The second command must emit `DENY` and exit 3. New tests cover valid format **without** authorization, all run-claim field drifts and forged consent, Attempt 2/new Run ID, mixed-before-six, duplicate/retired receipts, same-Job phase reuse, strict env name allowlist, symlink/hardlink/outside-root/nonprivate-file SHA mismatch, ZIP path escapes/RECORD omission/shadowed files/bomb sizes and nearby legitimate fixture bytes. An isolated stdlib test is **not** Go/Pipenv product T1, original child, Git/File mixed or macOS host source proof.

Before any native T1: freeze exact code/manifest and independent B+C review; qualify real hosted macOS Runner image/credential absence at earliest hook, preapproved actual external wheel/Go/Pipenv/fixture/toolchain bytes and paths, install/RECORD/source startup closure and GitHub trusted durable one-shot Owner grant; then request a **new separate exact Owner execution authorization** for one Run ID/Attempt, resources, 18 six-command observations and one mixed case. Without all of those, `T1=NOT_RUN / INTEGRATION_STATUS=NOT_TESTED / PR113_R10=BLOCKED` regardless of T0 test counts.

SAFETY: No native T1/T2/T3, cross-Runner hosted job/dispatch, external artifact download, actual secret/environment inspection, credential value logs, live network canary/probe, Mac Tunnel, Mac/shared/production filesystem change, process signal/kill, R006 relaxation, merge/deploy/release/tag has been executed or authorized by this document.
