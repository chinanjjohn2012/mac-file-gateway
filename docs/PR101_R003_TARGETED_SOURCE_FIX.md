# PR #101 — C/B targeted source security findings, A r003 fail-closed candidate

TASK_ID: MULTI-EXEC-LBE-V1-CONSOLIDATED-20261030
A_FIX_CANDIDATE_ROUND: r003 (new Head, not inherited r002 PASS)
REVIEW_TARGET: C101-SOURCE-01 P1, C101-SOURCE-02 P2, adjacent v1/Git/File safety
ROLE: A DEVELOPER; independent B/C conclusions cannot be issued by A
AUTHORITY: PR98 r002 design GitBlob 9e6622401b198138039c692efe91fba1a8d06891 (owner-accepted proposed NONOPERATIVE LBE); operative D0/F1 GitBlobs 6e25904aed9a62bb0f472b732021c2a7ca3b3bb0 / 76baeb820c6f8a9b067e45e2dcc42e76453fe5b1; G05 GitBlob 76c1c2b8a7947e0b305d55c5f550ab59c638b6d1
RULES: ICR-V2.0 / GHRH-2.0 / ETP-V2.0; verify A/B/C Project parity and user activation before declaring effective.
DYNAMIC_SOURCE: current GitHub PR #101 Base/Head/Tree + original Job logs, never this static document.

## Independent same-Head findings to address

C Spec REVIEW PRR_kwDOU5v3IM8AAAABVLLh_A on Head 7b94a54543db48af4760490f2bc6c70823d7cf2a, Tree f2638f07a6b51139a97272d6d605bfcf0fd8026c: P1 C101-SOURCE-01 says paths-only schema-v2 invoked Popen without separate exact operative D0 exception approval. Original Python-only macOS T1 was a bounded disposable TEST grant, not a general product permission. P2 C101-SOURCE-02 says independent source archive checks in P001-P007 do not bind actual future Go/Pipenv executable, PATH, compiler/stdlib/modules or virtualenv to Popen.

B Standards REVIEW PRR_kwDOU5v3IM8AAAABVLLvLA on the same Head/Base/Tree was TARGETED BLOCKED: full independently inspectable Go compiler/stdlib and nine-Wheel external code source corpus not available; hashes and regex hints are not code security. B P3 B101-SRC-P3-01 found that curl --location validated only final HTTPS origin rather than every intermediate hop. Not a full implementation role review.

## A candidate protective fixes, not independent verdicts

- Ordinary schema-v2 WorkspaceService with valid exec.paths and old owner.lock remains PREVIEW_ONLY. Before any Worker, slot reservation, state PREPARED or subprocess.Popen, any dry_run=false raises exec_cleanup_proof_required; existing v1 denial remains unchanged. Successful v2 preview is still distinct from apply.
- Configured v2 exec_policy.enabled=true indicates paths present; exec_policy.available=false and completion_capability=none indicate no operative positive authorization. Existing missing/quarantined old-state and wrong-Workspace denials remain independent.
- The ONLY allowed exception is the explicitly previously authorized hosted macOS-15 ARM64 Python-only original-child T1 fixture, constructed with a private test-only argument and further bounded to GitHub pull_request, fixed repo/branch/workflow, dedicated grant marker and all Workspace/config roots under RUNNER_TEMP. REST/MCP/client input/config cannot mint this permission. This does not constitute a cryptographic trust boundary against the trusted OS owner; it is an isolated test exemption only, not production D0 approval.
- Inside native launcher, fail closed on any Go/Pipenv primary or Pipenv runner immediately after plan revalidation, before effective PATH/Popen. Exact P001-P007 source bytes were checked only in prior CI and are NOT connected to live executable identity. This is DENIAL pending full approval, not positive provenance proof.
- New synthetic T0 must test direct/REST/official MCP denial before child, healthy old-state, private test marker spoof rejection, and same-service File/Git independence. Old native Python-only hosted T1 remains approved only under the explicit disposable CI fixture. All new Head actual CI, FAIL/SKIP/NOT_RUN and Manifest must be verified from raw Jobs, not prior Head results.

## Remaining safety and independent gates

A must not close B/C findings unilaterally. P1/P2 remain A FIX CANDIDATE until new Head independently reviewed by B and C. Source-only Go and Pipenv, optional/dynamic packages, distlib absent Requires-Python and publisher provenance are not full source-security PASS; B's P3 redirect/egress hardening remains open. New Go test/vet/build/-o, primary Pipenv run, local Mac/Tunnel, external network TCP REST/MCP, signals/T2/T3, production configuration, merge/tag/deploy are NOT_AUTHORIZED or NOT_RUN. FULL_CODE_REVIEW_PASS, INTEGRATION_PASS and R10 remain BLOCKED.
