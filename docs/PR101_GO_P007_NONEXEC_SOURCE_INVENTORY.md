# PR #101 — P007 Go archive-to-stage source provenance

PROPOSAL_ID: PR101-GO-P007-NONEXEC-SOURCE-BYTES-20261031
TASK_ID: MULTI-EXEC-LBE-V1-CONSOLIDATED-20261030
ROLE: A DEVELOPER; NOT AN INDEPENDENT STANDARDS/SPEC REVIEW
REVIEW_TARGET: Go 1.27.3 darwin-arm64 compiler/stdlib byte identity
CONTRACT_BLOB: 9e6622401b198138039c692efe91fba1a8d06891 (owner-approved local_best_effort)
P001_SOURCE_BLOB: 96bbd02cd384bd9769cd6af9f5a763442e25d61a
RULESET: ICR-V2.0 / GHRH-2.0 / ETP-V2.0 reference only, activation NOT_VERIFIED
DYNAMIC_SNAPSHOT: GitHub PR #101 HEAD/BASE/TREE and original CI

## Exact permitted input

P001 already approved and downloaded Go 1.27.3 darwin-arm64 compressed source only. Compressed source file: go1.27.3.darwin-arm64.tar.gz; size 68196737 bytes; SHA256 dd3908cf20959d798c1e06ebe5b72213f0505ce01373b40ce3110975a6cd99c2. P001 nonexecutable staged member count 15657; original complete SHA-prefixed line-sorted manifest SHA256 e43f516501f4e9b07de05dd470ffdab0b4c2acc086acf1e282d39c40fb00dc6a.

## P007 source-only checks

After exact Head G05, P001 byte hash and nonexecuting stage, P007 re-reads every compressed tar regular member alongside its separate one-link private staged file; it checks byte-for-byte equality, stat/type/mode/identity before and after reading, disallows missing/unlisted files and symlink/executable stage content, and reconstructs the exact P001 manifest algorithm. Crucially the original manifest sorts complete SHA256 + two spaces + ./relative-path lines, not filenames. It checks the 15657 files and anchored digest without executing any staged code. Only the same already sourced archive and private source bytes are read; no new download or package resolution.

The ephemeral local report contains each file's path, SHA256 and size, compiler/runtime/source category and bounded manual risk hints. Print key SHA values for go/VERSION, go/bin/go, the darwin_arm64 compile/link tools and go/src/runtime/proc.go; the full report remains private to RUNNER_TEMP and is not uploaded. Inert synthetic tar tests cover positive byte identity, staged mutation, symlink and executable drift, missing or unexpected file, invalid tar/manifest hash, missing critical compiler/linker file, noncanonical source root and absent P001 stage evidence.

## Limits and safety gates

This evidence is source identity only, not Go compiler/stdlib security review, publisher provenance, runtime qualification, authenticated native execution, or a GOROOT toolchain install. A does not issue B/C code review verdicts, and the bounded heuristic source flags are not security PASS. Actual go test/vet/build/-o and Pipenv primary execution require separate exact-scope authorization and independent source checks. No T2/T3 signals, unknown PID/PGID termination, Mac/Tunnel, production config, merge, tag or deploy. R10_STATUS=INCOMPLETE/BLOCKED; B/C independent source review=NOT_ISSUED; V2 A/B/C Project parity/effective rule approval NOT_VERIFIED.
