# PR #101 / P003 — Six fixed P002 Wheel payloads, source byte and RECORD qualification

PROPOSAL_ID: PR101-PIPENV-P003-SIX-WHEEL-BYTES-SOURCE-ONLY-20261030
ROLE: DEVELOPER (A) — no independent Standards/Spec source verdict
TASK_ID: MULTI-EXEC-LBE-V1-CONSOLIDATED-20261030
REVIEW_TARGET: exactly six known P002 transitive Pipenv candidate wheel archives
RULESET: ICR-V2.0 / GHRH-2.0 / ETP-V2.0 REFERENCED, NOT PROVEN EFFECTIVE
DYNAMIC_SNAPSHOT: GitHub PR #101 is the authoritative HEAD/BASE/TREE and CI location
SOURCE_CONTRACT: PR98 r002 design Git Blob 9e6622401b198138039c692efe91fba1a8d06891
TOOLCHAIN_PROPOSAL: PR101 P001 Git Blob 96bbd02cd384bd9769cd6af9f5a763442e25d61a
P002_IMMUTABLE_CANDIDATES: ci/lbe-pipenv-p002-metadata-candidates.json Git Blob c39a83d001512169bf9bb2cc19a0e56b1c0d79c4
STATUS: USER_AUTHORIZED_EXACT_SIX_SOURCE_DOWNLOAD_AND_BOUNDED_ISOLATED_INSTALL_IMPORT_EXEC; P003 WORKFLOW INSPECTS BYTES ONLY

## Specific user authorization and phased gates

The owner authorized source-byte downloads, followed in a separate message by
installation, import and execution of **these same six Wheel dependencies**.
This is scoped to a disposable GitHub-hosted macOS 15 ARM64 test environment
with CPython 3.13, not the owner Mac, shared/production data or a deployment.

**P003 is a fail-closed FIRST PHASE only:** get exact real bytes for these six
previously fixed candidates, assert published archive hash against downloaded
bytes, check no symlink/archive path traversal, zip members, metadata identity,
SHA256 hashes and sizes of every wheel RECORD-listed file. Report exact HEAD,
TREE and six post-download SHA values. No install, import or wheel-provided
executable is run in P003, even though the owner's latest scope permits bounded
subsequent isolated execution once mandatory source/closure/review gates are met.

We do NOT infer independent source-code security qualification or compatible
recursive Python3.13 dependency closure from a hash/RECORD check. Those are
separate gates before a later P004 isolated offline install/import/real T1.
The P001 Go compiler/stdlib and original Pipenv wheel are separately scoped.
This new grant does not authorize Go/Pipenv themselves, process termination,
OS signals, T2/T3, production Exec, native C, merge, tags, releases or deploy.

## Exact six fixed third-party sources

| Distribution | Version | Filename | Official candidate SHA256 |
| --- | --- | --- | --- |
| distlib | 0.4.4 | distlib-0.4.4-py2.py3-none-any.whl | cf09d55b1e85a89576b036aeb71550bfd68320f3f21761ca329eadadad918638 |
| filelock | 4.2.4 | filelock-4.2.4-py3-none-any.whl | 301241438c57936ef93f4243a94f2559022268bfcf9b375a9a72eb0f8db8358e |
| platformdirs | 4.11.10 | platformdirs-4.11.10-py3-none-any.whl | 973c4c082b964958c71588448488d2b14fb253893dfbdb82325a14c84e540e8f |
| python-discovery | 1.6.1 | python_discovery-1.6.1-py3-none-any.whl | d43fcdef879fe795352bd13ccf8d185ba5a9f86f36cfcd00529f596e737442b3 |
| setuptools | 84.2.1 | setuptools-84.2.1-py3-none-any.whl | ca140b45d5325a9478f880e351484f62fef15f336462e449ca0c03c873d589c2 |
| virtualenv | 21.15.0 | virtualenv-21.15.0-py3-none-any.whl | 013eb9c340466186ac8923ce920ae05becfa1390fdf3565b7eae0d191a2f4a2e |

## P003 deterministic procedure

1. Checkout the real HEAD in GitHub Actions and require fixed PR101 Base,
   hosted macOS-15 ARM64, G05 254+N tracked blobs/MANIFEST and pinned
   P002 candidate lock Git blob. Do this BEFORE external metadata fetch.
2. Execute pure stdlib fake ZIP/RECORD, wrong-hash, symlink/traversal,
   file-link, HTTP-response and redirect-deny T0 adversarial tests.
3. Fetch only six official PyPI version-release JSON documents.
4. Validate exact declared version, filename, sha256 description, size,
   yanked=false and no-credentials official files.pythonhosted.org HTTPS URL.
5. Download exactly six wheels to a new owner-only RUNNER_TEMP directory;
   do not follow HTTP redirects or proxy; hash actual downloaded bytes and
   require identical declared size/official SHA256, using no shell package
   manager or auto resolver for these downloads.
6. Inspect ZIP entry paths and types, bounded total/member sizes and count,
   duplicate/casefold names, version + wheel metadata and every ordinary
   file's internal RECORD SHA256/size; reject missing or unexpected RECORD.
7. Persist an owner-only report in ephemeral RUNNER_TEMP; require 6 valid
   results and re-check tracked Git diff + stage, no wheel import/install,
   no external Go/Pipenv invocation.

## Explicit limitations / closure conditions

- A valid wheel RECORD proves internal byte consistency, not safety of the
  wheel's Python imports, import-time effects, recursive closure, or the
  maintainer's identity. PyPI upload provenance remains independently unreviewed
  for several releases. distlib 0.4.4 lacks Requires-Python metadata.
- The P002 metadata-only job is unchanged. P003 CI does not overwrite P001,
  does not replace the original 36-wheel R004 source lock, and creates no
  new installed RECORD attestation until future offline qualified P004.
- Later installation/import/execution under the owner's scope must still
  freeze complete Python3.13 marker-compatible dependency inputs, attest
  installed files before/after, inspect code/import roots and PATH, use a
  disposable environment with no new network post staging, honor 12-minute
  job and per original-child budgets, and receive independent B/C source
  security review where required. No automatic grant escalation.
- A cannot publish B/C approval or R10. Until full independent role
  review and complete authorized evidence: R10_STATUS=INCOMPLETE,
  FULL_CODE_REVIEW_PASS=NOT_ISSUED, INTEGRATION_PASS=NOT_ISSUED.

NEXT_ROLE: A for source-only P003 CI results and source-risk gate accounting;
B/C independently for source/security and complete code review on a frozen
eligible snapshot; subsequent P004 only after remaining pre-execution gates.
