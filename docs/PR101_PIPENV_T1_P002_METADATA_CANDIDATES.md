# PR #101 / P002 — Pipenv transitive runtime wheel candidates (METADATA ONLY)

DOCUMENT_ID: PR101-PIPENV-T1-P002-METADATA-ONLY-CANDIDATE
STATUS: PUBLIC_PYPI_RELEASE_METADATA_CANDIDATES / NOT_USER_APPROVAL / NOT_SOURCE_BYTES_LOCKED
TASK_ID: MULTI-EXEC-LBE-V1-CONSOLIDATED-20261030
REVIEW_TARGET: Six new Python 3.13 macOS ARM64 runtime-distribution candidates for P001
EVIDENCE_PROFILE_ID: ETP-V2.0 REFERENCED; three-Project V2.0 governance activation NOT_VERIFIED
CONTRACT: PR #98 r002 MWE-LOCAL-BEST-EFFORT-V1.0-CANDIDATE Git Blob
  9e6622401b198138039c692efe91fba1a8d06891; PR #101 P001 proposal Git Blob
  96bbd02cd384bd9769cd6af9f5a763442e25d61a
SOURCE_OF_DYNAMIC_SNAPSHOT: Current GitHub PR #101; this document does NOT pin a future current HEAD.

## Why a separate metadata-only gate is necessary

The user authorized **exact P001** isolated Go/Pipenv T1 resource/command scope
on 2026-10-30. The authorization forbids silently treating UNKNOWN third-party
wheel bytes as approved. P001 original real-byte CI run 41056700899 verified
Go1.27.3 compressed archive and Pipenv2026.10.4 wheel; it did **not** download
or install the six additional runtime wheels, prove full Python 3.13 marker
resolution, independently review bundled Pipenv `benchmarks/`, approve Go
compiler/runtime execution, or run Go/Pipenv subprocesses.

The original 36 locked wheels include `certifi==2026.10.23` and
`packaging==26.3` which preliminarily satisfy two Pipenv root requirements.
Pipenv's observed default `Requires-Dist` adds `setuptools>=67` and
`virtualenv>=21.14.6`; the source-only P001 run also identified the
`virtualenv` transitive requirements:
`distlib>=0.4.3,<1`,
`filelock>=3.24.2,<5` (Python 3.13),
`packaging>=26.3`,
`platformdirs>=4.4,<5`,
`python-discovery>=1.6.1`.
`typing-extensions` conditional on Python <3.11 is NOT selected for
Python 3.13. These are the observed first-level inputs, NOT proof that
all recursively selected wheels/markers/import sources are qualified.

## Six published Wheel SHA256 *candidates*, NOT downloaded-byte attestations

| Distribution | Fixed candidate version | Official Wheel SHA256 | Publisher provenance display |
| --- | --- | --- | --- |
| setuptools | 84.2.1 | `ca140b45d5325a9478f880e351484f62fef15f336462e449ca0c03c873d589c2` | PyPI shows no provenance |
| virtualenv | 21.15.0 | `013eb9c340466186ac8923ce920ae05becfa1390fdf3565b7eae0d191a2f4a2e` | PyPI shows publish attestation; not independently checked |
| distlib | 0.4.4 | `cf09d55b1e85a89576b036aeb71550bfd68320f3f21761ca329eadadad918638` | PyPI shows no provenance |
| filelock | 4.2.4 | `301241438c57936ef93f4243a94f2559022268bfcf9b375a9a72eb0f8db8358e` | PyPI shows publish attestation; not independently checked |
| platformdirs | 4.11.10 | `973c4c082b964958c71588448488d2b14fb253893dfbdb82325a14c84e540e8f` | PyPI shows publish attestation; not independently checked |
| python-discovery | 1.6.1 | `d43fcdef879fe795352bd13ccf8d185ba5a9f86f36cfcd00529f596e737442b3` | PyPI shows publish attestation; not independently checked |

**Independent declaration pinning (source-only):** the metadata inspector now
compares each of the six candidate SHA256 strings and publication-provenance
labels to an explicit, separate fixed table in its own reviewed source. A
different but well-formed 64-character digest, or a swapped allowed provenance
label, fails closed before release-JSON comparison. Two offline adversarial
T0 regressions cover both changes. This is still a *declaration-consistency*
gate, NOT downloaded-byte verification, package-source approval, installed
RECORD attestation, transitive-closure qualification or native T1 permission.

**Authorization/target header pinning (source-only T0):** the inspector
requires the precise complete top-level schema and immutable primary
Pipenv filename, isolated macOS 15 ARM64/Python 3.13 target, inherited
36-wheel subset, conditional-approval limitation and explicit
nonapproval of older virtualenv. Changing a field, adding an invented
authorization field or omitting a field fails closed; these checks do
not approve any additional third-party byte, installation or execution.

**Primary metadata sources (public; publisher claims not independently accepted):**
- https://pypi.org/pypi/setuptools/84.2.1/json
- https://pypi.org/pypi/virtualenv/21.15.0/json
- https://pypi.org/pypi/distlib/0.4.4/json
- https://pypi.org/pypi/filelock/4.2.4/json
- https://pypi.org/pypi/platformdirs/4.11.10/json
- https://pypi.org/pypi/python-discovery/1.6.1/json

**Missing compatibility declaration:** the actual PyPI release JSON for
`distlib==0.4.4` has `info.requires_python=null` (no declared
Requires-Python bound). The P002 inspector accepts this solely to record
`requires_python_raw=NOT_DECLARED`, and it **never** infers Python
3.13 compatibility or complete marker closure from absence of a bound.

**Machine-readable companion:** `ci/lbe-pipenv-p002-metadata-candidates.json`.
Its six filenames, versions and published SHA256 candidate strings are fixed
from the above official PyPI release pages. The *only* proposed CI networking
for these additional packages is reading six public RELEASE JSON documents,
not wheel/file payloads. `tools/lbe_pipenv_p002_metadata.py` compares the
JSON identities and SHA256 *descriptions*, rejects unknown release/URL/size/
yanked/duplicate/extra/missing metadata, preserves raw `Requires-Dist`
without executing or resolving it, and reports explicit insufficient evidence.
Offline adversarial tests use fabricated release JSON only.

## No automatic upgrade of evidence or test authorization

- A release JSON file stating a SHA256 is **not** a verified SHA256 of a
  downloaded Wheel; actual new Wheel bytes, internal RECORD, importable roots,
  executable dependencies and installed RECORD remain NOT_VERIFIED.
- PyPI publisher provenance (when displayed) is not an independent
  package security/source approval. Setuptools, distlib and Pipenv primary
  wheel have no official publish attestation shown in the cited releases.
- Newly observed `Requires-Dist` entries or markers are **not** silently
  accepted. The metadata comparison retains raw requirements but makes
  **NO** complete recursive dependency closure or Python3.13 marker claim.
- Known `virtualenv` 21.14.x advisories must be checked against the chosen
  21.15.0; selection is a candidate only, not a published security verdict.
  `virtualenv` 21.15.1 is a distinct release, not a silent allowed upgrade.
- Exact PR #101 G05 before any source import, same Head/Tree, original
  36-wheel/RECORD policy, and all P001 T1 limits remain mandatory.
- No Go, Pipenv, setuptools, virtualenv, or downloaded Python Wheel is
  installed or invoked under this metadata-only job; no source-only metadata
  step can activate production Exec, clean/kill children or make R10 PASS.

**Actual next closure conditions**: evaluate new raw `Requires-Dist`
recursively with a reviewed marker-capable resolver on the fixed Python
3.13 macOS ARM64 profile; select only explicitly approved transitive bytes;
independently assess publication/security provenance, Go toolchain/stdlib
and Pipenv `benchmarks/`; then seek necessary separate authorization for
additional Wheel downloads, installations and real native T1. All tested
artifacts must be byte-hash/RECORD attested BEFORE execution and original
logs must show actual Head/Tree/code/env and precise PASS/FAIL/SKIP/NOT_RUN.
Until then `EVIDENCE_STATUS=INSUFFICIENT`,
`PIPENV_NATIVE_T1=NOT_RUN`, `GO_NATIVE_T1=NOT_RUN`,
`R10_STATUS=INCOMPLETE`, no merge/tag/deploy or user Mac/Tunnel.
