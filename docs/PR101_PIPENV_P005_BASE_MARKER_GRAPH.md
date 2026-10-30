# PR #101 P005: BASE Pipenv runtime marker-graph metadata qualification

PROPOSAL_ID: PR101-PIPENV-P005-BASE-RUNTIME-MARKER-GRAPH-20261030
TASK_ID: MULTI-EXEC-LBE-V1-CONSOLIDATED-20261030
ROLE: DEVELOPER (A), NOT an independent Standards/Spec source-security review
REVIEW_TARGET: Pipenv 2026.10.4 BASE CPython3.13 macOS 15 ARM64 dependencies
CONTRACT: user-accepted PR98 r002 MWE-LOCAL-BEST-EFFORT-V1.0-CANDIDATE
CONTRACT_BLOB: 9e6622401b198138039c692efe91fba1a8d06891
P001_SOURCE_BLOB: 96bbd02cd384bd9769cd6af9f5a763442e25d61a
P002_SIX_INPUT_BLOB: c39a83d001512169bf9bb2cc19a0e56b1c0d79c4
ORIGINAL_R004_WHEEL_LOCK_BLOB: f6310fef4596ce20bfa8da35ae8d4883e6b714b5
RULESET: ICR-V2.0/GHRH-2.0/ETP-V2.0 references, NOT EFFECTIVE_FOR_NEW_ROUNDS until proven
DYNAMIC_SNAPSHOT: current GitHub PR #101, not this static document

## Fixed source and authorization boundary

This stage uses EXACTLY the previous P001 primary Pipenv 2026.10.4
wheel (SHA256 308125623e4d08dfe32936f7259a9ed33c5480baa2c9a291a1ff8a9328eeeb1f),
the six explicitly owner-authorized P002 source Wheels in the frozen
JSON, and two previously approved original R004 Wheel-lock sources
(packaging==26.3, certifi==2026.10.23). No new dependency names,
versions, unknown artifacts, compiler binaries, scripts or processes
are sourced.

Pipenv and certifi are downloaded only as SOURCE bytes from the
exact official PyPI version release JSON and HTTPS Wheel origin,
and individually require their previously pinned actual SHA256 and
every Wheel RECORD hash. Six P002 sources and original packaging
are rehashed and RECORD-checked on the same ephemeral CI runner.

Only original-lock packaging 26.3, already installed and with RECORD
attested, may be imported as a local PEP 508 requirement/marker parser.
Pipenv's bundled benchmarks, entry point and program are NOT
imported, installed or executed. No Go compiler, Pipenv program,
new native toolchain, T2/T3, OS signal, local Mac/Tunnel, production
configuration, merge, tag, release or deploy is authorized.

## Exact BASE scope and proof

1. Bind nine fixed source distributions: Pipenv 2026.10.4, certifi
   2026.10.23, packaging 26.3, setuptools 84.2.1, virtualenv 21.15.0,
   distlib 0.4.4, filelock 4.2.4, platformdirs 4.11.10,
   python-discovery 1.6.1.
2. Compare complete SHA256, safe ZIP and RECORD bytes, and actual
   Name/Version/METADATA identity of all nine artifacts.
3. Evaluate Requires-Dist with packaging 26.3 PEP 508 marker semantics
   for actual CPython3.13 Darwin arm64 and empty extras. No optional
   extras are activated; report skipped extras/markers separately.
4. For every active edge: verify target pinned identity and version
   specifier. Reject malformed declarations, active unknown dependencies,
   direct URLs, unexpectedly activated extras, unreachable/missing nodes
   and incompatible declared Requires-Python. Reject wrong platform.
5. Record all actual active edges, inactive marker declarations, missing
   Requires-Python declarations, exact source hashes and environmental
   provenance in ephemeral runner-owned evidence.

Permitted scoped result: BASE Requires-Dist marker graph satisfied
for exactly these nine known source distributions and extras empty.
This is not a claim of complete Python compatibility, complete optional
extras, real Pipenv/native execution, security source review, runtime
side effects, or production readiness. Distlib lacks published
Requires-Python; missing declared compatibility is NEVER a PASS.

## Remaining independent blockers

- B/C independent external-source security and publisher provenance
  assessments NOT_ISSUED; Pipenv benchmarks and Go compiler/stdlib
  independent source review NOT_ISSUED.
- Optional extras / dynamic plugins, user project dependencies and
  runtime compatibility beyond the declared BASE graph NOT_PROVEN.
- No real primary Go/Pipenv native test/vet/build/virtualenv creation
  or real REST/MCP/Tunnel integration in this source-only stage.
- P004 limited six import smoke cannot be upgraded to full
  integration or an R10 PASS on metadata evidence alone.
- Safety remains disposable hosted macOS15 ARM64, <=12min job,
  no T2/T3 signals, no user Mac, no production activation.
- V2 rule parity and owner formal effective round not verified.
- R10_STATUS remains INCOMPLETE/BLOCKED.

NEXT_ROLE: A to verify exact HEAD P005 original job; then independent
B/C source security review and eventual full code review only after
same-source rule activation, frozen snapshot and complete evidence.
