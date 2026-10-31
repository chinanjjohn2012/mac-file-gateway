# PR #101 — P006 exact-nine-Wheel source inventory for independent review

PROPOSAL_ID: PR101-PIPENV-P006-NINE-WHEEL-SOURCE-INVENTORY-20261030
TASK_ID: MULTI-EXEC-LBE-V1-CONSOLIDATED-20261030
ROLE: A DEVELOPER ONLY (NOT B STANDARDS / C SPEC)
CONTRACT_ID: MWE-LOCAL-BEST-EFFORT-V1.0-CANDIDATE
CONTRACT_BLOB: 9e6622401b198138039c692efe91fba1a8d06891
P001_INPUT_BLOB: 96bbd02cd384bd9769cd6af9f5a763442e25d61a
P002_SIX_WHEEL_LOCK_BLOB: c39a83d001512169bf9bb2cc19a0e56b1c0d79c4
R004_ORIGINAL_36_WHEEL_LOCK_BLOB: f6310fef4596ce20bfa8da35ae8d4883e6b714b5
APPLICABLE_REFERENCES: ICR-V2.0 / GHRH-2.0 / ETP-V2.0. User-approved fixed PR #75 r005 governance Head 600c5c96ba89c06d0787695f0bce1cc27bcd65f7, B/C Project-source exact-version attested; the first effective NEW V2 review round was PR #90 r010 (A handoff comment 6460818725). Historic preactivation rounds remain historic.
REVIEW_TARGET: P001+P002 nine pinned Wheel source identity and review preparation
DYNAMIC_SNAPSHOT: exact GitHub PR #101 Head/Base/Tree and original CI jobs, not this document

## Inputs, after independent source-byte and installed-RECORD gates

The staged inputs are the **same nine** P005 BASE marker graph candidates,
with NO new distribution downloads: Pipenv 2026.10.4 and certifi 2026.10.23
from already-approved source-only P005, packaging 26.3 from the original R004
approved source lock, and six previously owner-authorized, SHA-locked
P002 distributions (distlib, filelock, platformdirs, python-discovery,
setuptools, virtualenv). Exact filenames, versions and SHA256 values are
hard-coded by P005; this stage does not resolve new dependency names.

Run only after checked-out actual Head+Tree G05, P003 actual downloaded
byte SHA/RECORD and P004 permitted disposable six imports, plus P005's
actual-Wheel BASE metadata graph and its raw evidence file. The source
inventory executes standard-library ZIP/hash functions; it does NOT
install, import or execute any third-party Wheel contents or Go/Pipenv
primary programs. The only previous P005 imported library was the
pre-attested original R004 packaging 26.3 parser.

## P006 evidence per exact physical Wheel

- Revalidate actual source Wheel SHA256 and all internal RECORD SHA256/size
  entries; Pipenv uses the separately vetted P001 wheel archive qualifier.
- Enumerate EVERY regular archive member. Store path, actual decompressed
  byte SHA256 and byte size and a cumulative byte-hash stream digest.
- Parse bounded UTF-8 Python source files (maximum 262,144 bytes each)
  using standard-library `ast.parse` with Python 3.13 grammar. Decode with
  strict `utf-8-sig` to accept a Python-supported leading UTF-8 BOM but
  preserve embedded-BOM syntax errors. On bounded source, stdlib
  `tokenize.detect_encoding` checks the ORIGINAL bytes' PEP 263 declaration
  (first two lines) before AST, flagging conflicting BOM/cookies or unknown
  codecs. Matching UTF-8 cookies and valid ASCII Latin-1 cookies do not
  create false syntax hints. The check does NOT compile or execute foreign
  code. The size cap and invalid UTF-8 are **independent flags**, so the
  same member can be both oversized and non-UTF-8. At the exact cap,
  valid syntax is still parsed. Never import, compile, run or install Wheel
  code. Tokenizer and AST hints do NOT establish complete byte-source
  compilation, interpreter compatibility or code safety. All source members
  remain hashed and inventoried, even if AST is skipped.
- Count Python source files and flag only coarse manual-review **hints**:
  native/compiled payloads, startup hooks such as .pth, console/plugin
  entrypoint metadata, packaged script/tool files, bundled Pipenv benchmark
  sources, and syntactic text patterns mentioning network/process/dynamic
  execution. These flags are intentionally neither exhaustive nor a verdict.
- Reject unbounded expanded/source sizes, ZIP path traversal, special
  members, wrong source hash and malformed/missing internal RECORD.
  File metadata is still required for every pin.
- Store the complete file-by-file source identity and bounded manual-review
  hint path lists only in private disposable RUNNER_TEMP. Log per-Wheel
  summary counts and the deterministic hash stream, not raw code.
  Never publish untrusted source directly as commands or host artifacts.

The standalone offline T0 suite exercises successful fake records,
untrusted Python source NEVER executed, wrong SHA/RECORD,
traversal/symlinks, excluded filesystem roots and no P005 evidence.
A result of INVENTORY_PASS means **evidence collected** only.
It is not external-source safety, malicious-code absence, license review,
authentic publisher attestation, full Python 3.13 compatibility,
verified Go compiler/stdlib or reviewed Pipenv benchmarks.

## Independent-review and product gates

B Standards and C Spec must each independently review the immutable
external source identity and relevant code surfaces using their own
read-only acquisition and threat assessment, as well as the full
product contract on a fixed Head/Base/Tree/round. Developer A's
source inventory, classifications, code and tests cannot be substituted
for either B or C's source-security conclusion.

Remaining NOT_RUN / NOT_VERIFIED: Pipenv primary execution/virtualenv
creation, Go test/vet/build as a real original child, real authenticated
external REST/MCP/Tunnel and production operation, full extra/optional
dependency graph, compatibility of distlib with no published
Requires-Python, and independent B/C FULL nine-Wheel/Go external-source code
security reviews. The V2 governance activation and A/B/C same-source
attestations are documented separately in PR #75/#90; they do NOT grant
third-party source security or product approval. No T2/T3 process signals, unknown descendant cleanup,
native C, user Mac, release, merge, deployment or production activation.

R10_STATUS: INCOMPLETE/BLOCKED
NEXT_ROLE: Use the CURRENT GitHub PR #101 SHA-bound A handoff/B/C reviews
for dynamic progress and next-role decisions; this static source document
cannot assign a later review round. No automatic security acceptance.
