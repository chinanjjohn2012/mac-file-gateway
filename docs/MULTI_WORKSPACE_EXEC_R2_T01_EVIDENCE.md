# R2-T01 — Python Exec durable state store (staged)

**RED checkpoint; implementation not yet GREEN.** Stack this Draft PR on
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
