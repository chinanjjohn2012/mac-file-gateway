# R2-T01 — Python Exec durable state store (staged)

**T01 first implementation candidate; independent review pending.** Stack this Draft PR on
reviewed PR #59 Head 79cae93e7b4c03293b95dcc8c51e55e97ec2a934.
Accepted D0 design: PR #58, review #5623166343. Accepted R1 contract:
PR #59, review #5624517768. This first slice is deliberately **only**
the isolated private Python durable store and conservative boot scanner.

- Stage RED: explicit new pytest file tests actual persistent directory,
  lock, file+directory fsync, atomic rename, fault-triggered fail-close,
  storage format, unresolved restart, and unsafe-state quarantine.
  Stub must fail these assertions without launching any command.
- Stage GREEN: replace stub with production \`ExecStateStore\` primitives
  only, rerun targeted suite and entire existing product suite.
- R2-T01 does NOT connect state to WorkspaceService, qualify a test-only
  grant, return an R1 private serializer, or implement process cleanup,
  group-only retirement, real Popen, OS signals, or reset/unquarantine.
  A passing T01 does not imply the R1 full-state-machine suite is GREEN.
- Next gate: independent SHA-bound Standards + Spec T01 code review.
  Subsequent R2 slices separately wire startup and Exec admission/HTTP/MCP,
  implement test-only grant/Worker and UNKNOWN cleanup, then perform
  R3 macOS fault acceptance and R4 release acceptance.

**Hard stop:** PR #56/#57/#58/#59 and this PR stay Draft/unmerged;
production Exec OFF, Native C/Candidate B suspended, no Tunnel,
no merge, tag, deployment or actual Gateway restart.

## Original T01 RED checkpoint (before code)

Head `379176c7f6451cea2c05bb945d2e07b0d1e2e474`: [workflow
#39910941273](https://github.com/chinanjjohn2012/mac-file-gateway/actions/runs/39910941273)
/ [raw Job #120273549215](https://github.com/chinanjjohn2012/mac-file-gateway/actions/runs/39910941273/job/120273549215):
`17 failed, 1129 passed, 8 skipped, 1 warning`. All 17 expected
T01 failures arose from stub behavior (missing directory, lock, intents,
restart quarantine and durability syscall fault handling); no product
regression. This checkpoint is preserved in Git history, not rewritten.

## T01 scoped implementation

`gateway.exec_state.ExecStateStore` is a standalone, private storage
primitive: FD-pinned private root; mode/type/link checks; nonblocking
lifetime owner-lock via flock; strict, bounded record schema; unique
attempts; write-all + file fsync + atomic replace + directory fsync;
UNKNOWN persistence; fail-closed boot scan and sanitized error codes.
Incomplete temporary files and all unresolved/retired legacy markers
remain quarantined for offline review; there is no auto replay or remote
reset. Capacity is bounded conservatively; eligible RETIRED-only pruning,
private R1 serializer/fixture grant and actual Worker execution are **not**
implemented in T01. Existing WorkspaceService Exec behavior remains the
already-reviewed PR #56 product candidate, **not** D0-complete.

**This standalone unit GREEN, if achieved, is only storage-primitives
GREEN.** Later R2 batches must wire D0 default cleanup-proof refusal into
normal REST/MCP Exec *before* production activation, add private test-only
acceptance grant, and prove interrupted Worker/quarantine with external
witnesses. Do not use this isolated module as evidence of runtime safety.
