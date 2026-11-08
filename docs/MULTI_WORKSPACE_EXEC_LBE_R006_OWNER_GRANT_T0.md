# R006 exact owner grant and trusted bootstrap - SAFE T0/source candidate

Fixed authority remains D4 R006 Git Blob
`b8d8a1cb32fb7130dfa6d00b37831dfddfaad11c`. The user's nine-risk acceptance
is recorded by A in PR #114 comment 6717010359; that record is intentionally
**not** an exact owner-authenticated PRODUCT_T1 attempt grant.

The executable candidate now defines and verifies a canonical direct
repository-owner GitHub issue-comment grant. It binds owner identity/OWNER
association, immutable unedited comment identity, fixed R006 contract and
design reviews, current B/C FULL code review IDs, Base/Head/Tree/Manifest,
GitHub Run ID/attempt, fixed macOS image/build and selected-source/runner
fingerprints, exact Workspace/cwd/runner/argv fingerprints, timeout, one-use
nonce and short expiry.

`gateway/lbe_owner_grant_bootstrap.py` performs the service-owned GitHub
comment fetch using the fixed public GitHub API URL, system TLS, no ambient
proxy, no Authorization header, no redirect, bounded JSON and exact response
URL/content type. Supplied REST/MCP body bytes are never accepted by the
canonical bootstrap.

`gateway/lbe_r006_trusted_bootstrap.py` then combines that verified owner
grant with:
- the current native GitHub B/C FULL review pair from
  `gateway/lbe_r006_review_gate.py`; and
- the current private G05 receipt + live GitHub Actions run identity from
  `gateway/lbe_r006_runtime_identity.py`.

The result is a process-bound `D4TrustedBootstrapBundle`, not a client token.
It can be paired with one service-created prepared source candidate and
installed only through a private in-process method. Public Direct/REST/MCP
requests provide only the existing command arguments.

Durable replay protection is separate: an accepted exact request burns the
verified grant nonce in the existing-only private `d4-journal` sibling before
Worker/Popen. Lost ACK, post-accept cancellation and restart do not release it.

No exact owner T1 comment has been issued for the current developing Head.
Actual PRODUCT_T1 therefore remains NOT_RUN/NOT_AUTHORIZED.
