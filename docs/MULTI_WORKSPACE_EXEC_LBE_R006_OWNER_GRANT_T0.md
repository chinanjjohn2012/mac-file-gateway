# R006 owner exact-attempt grant source milestone (SAFE T0, NOT T1)

Fixed authority remains D4 R006 Git Blob
`b8d8a1cb32fb7130dfa6d00b37831dfddfaad11c` and the two independent
targeted design reviews on PR #114. The user's nine-risk acceptance has been
transcribed by A in PR comment 6717010359, but that is deliberately **not** an
exact owner-authenticated T1 run grant.

This milestone defines an exact, canonical, one-attempt grant format for a
future direct repository-owner GitHub issue comment. The verifier binds owner
login + OWNER association, PR/comment URL, unedited timestamp, fixed R006
design and design review IDs, future current code review IDs, Base/Head/Tree,
Manifest, GitHub run ID/attempt, macOS image version/build, source and runner
fingerprints, Workspace/cwd/runner, requested/effective argv digests, timeout,
nonce and short expiry.

The parser performs **no network request** and therefore cannot itself prove
that arbitrary response bytes came from authenticated GitHub transport. A
future trusted bootstrap must fetch the exact comment using a service-owned
authenticated channel; public REST/MCP/client bytes must never be accepted as
that bootstrap. The returned `D4VerifiedOwnerGrant` cannot be normally
constructed without the module verifier token, and WorkspaceService now rejects
a plain `D4AttemptIdentity` at its durable nonce-consumption boundary.

No positive F1/D0 exception or macOS Runner/Popen is enabled. Real GitHub owner
comment fetch, independent provider/image/source qualification, current FULL
code reviews, same-instance positive integration and exact native T1 remain
NOT_RUN/NOT_AUTHORIZED.
