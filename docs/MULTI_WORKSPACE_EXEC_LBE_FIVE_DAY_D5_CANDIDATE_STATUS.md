# D5 five-day LBE code candidate: safe-scope closure and execution blockers

TASK_ID: MULTI-EXEC-LBE-FIVE-DAY-CANDIDATE-20261105
REVIEW_ROUND: r003
REVIEW_SCOPE: TARGETED_SAFE_T0_AND_DESIGN
STATUS: DEVELOPMENT_CANDIDATE / NO_NATIVE_AUTHORIZATION / F1_POSITIVE_DENIED
RULESET_ID: ICR-V2.0
HANDOFF_PROTOCOL_ID: GHRH-2.0
EVIDENCE_PROFILE_ID: ETP-V2.0

## D1-D4 historical source and current milestone

PR113 D1 B/C independently passed a strictly NONOPERATIVE scoped review
on Head ca90cf30095695479615e475b8440e09f02f34d9.
PR114 r002 D2-D4 B/C independently passed TARGETED T0 and proposal
review on exact Head 1295852c3886b7b7e77a54e61ccc85965abb64bb,
Tree 19cf9b4c4f9983fdcdf0d560f7e13a0260779960.
Current operative D0/F1/Phase1/G05, PR102 OFFLINE_ONLY source-T1
and PR98 lightweight product scope remain unchanged. Prior roles' PASS
does not transfer to new source edits or authorize native Go/Pipenv.

## D5 additional real source work

gateway/lbe_go_fixture_t0.py and tests/test_lbe_go_fixture_t0.py
provide a bounded nofollow readonly file-byte SHA256 snapshot for
THREE private staged Go executable paths:
  <GOROOT>/bin/go
  <GOROOT>/pkg/tool/darwin_arm64/compile
  <GOROOT>/pkg/tool/darwin_arm64/link
where GOROOT is inside an exact pre-created private root. Reject unsafe
directory ownership/modes, link redirection, hardlinked tools, nonregular
and writable tools, changed inode metadata during streaming hash, bad
digest values and noncanonical paths. Positive synthetic file bytes
MUST NOT be executed or interpreted as a real Go distribution.

This establishes limited selected file identity at the time of a
read-only snapshot. It does NOT prove the actual Go loader/PATH after
FD close, all linked/shared/compiler and stdlib inputs, per-package
module graph, Go test binaries, tool- and module-spawned children,
runtime OS confinement or network non-contact. Native launch is
UNCONDITIONALLY denied regardless of snapshot or forged receipt. These
are separate future implementation and owner authorization gates.

## Remaining product delivery conditions, no contract waiver

- Proposed lighter trusted PRODUCT_T1 risk profile must gain B and C
  independent new exact version design review plus the owner's explicit
  same-UID/network/retry/crash risk and disposable-macOS test consent.
  It must NOT be silently substituted for PR102's stronger standalone
  SOURCE_TOOLCHAIN_T1 OFFLINE_ONLY qualification.
- Fix and review exact executable runnable product snapshot including
  authoritative WorkspaceService single authorization gate, private
  old-state lock/quarantine and no-v1-escalation, inspected Go/Pipenv
  loaded code and closed effective env. Current source-only utilities
  do NOT grant public v2 positive Exec or lift Go/Pipenv hard stop.
- Scope test runner, exact Head/Tree/G05, native CPython/Go/Pipenv
  artifacts, child/job time/output and enforceable applicable resource
  limits; no production credentials or shared Mac/Tunnel mounts.
- Only after the above conditions, run authorized disposable-platform
  T1 with actual Go/Pipenv positive path and original direct-child
  timeouts, retry denial and Direct/REST/official MCP+File/Git matrix.
  Capture raw original evidence and new independent B/C FULL scope.
- NO_GO if any required authorization, platform or source-input
  precondition is missing. No T2 process-kill experiments, T3 shared
  or production tests, release, tag, merge or deployment implied.

T0_STATUS: SOURCE_AND_FAKE_FIXTURE_TESTS_ONLY
INTEGRATION_STATUS: NOT_TESTED
R10_STATUS: BLOCKED
FULL_CODE_REVIEW_PASS: NOT_ISSUED
NATIVE_GO_PIPENV: NOT_RUN
NEXT_ROLE: B and C independent exact D5 candidate scope, followed by
USER precise trusted PRODUCT_T1 risk/fixture authority only if accepted.
