# Build record

Isolated new repository: /mnt/data/mac-file-gateway, branch build-gateway.
No existing user repository was accessed or modified.

Ruling: keep the standard SDK instead of hand-implementing MCP. Package-index
network access is unavailable here; missing-SDK integration tests must be
reported as skipped, not passed. The user can run them after setup on macOS.

Ruling: use a private Secure MCP Tunnel, not an unauthenticated public HTTP
quick tunnel. Requires workspace developer-mode access and Platform tunnel
permissions. The filesystem gateway itself needs no OpenAI API key.

Ruling: provide UTF-8 text/code only in version 1. No PDF/Office/binary parser.
Ruling: use explicit root plus built-in and --exclude patterns; .gitignore is
not used as a security policy. No claim of complete secret detection.

Task 1: initial RED run: 53 failed (missing implementation).
Root-policy regression: filename secret globs incorrectly checked explicitly
selected root ancestors; narrowed startup checks to protected/hidden directories.
Added a failing regression test before the correction.

Task 2: HTTP boundary and official SDK adapter implemented. HTTP tests were
observed failing before implementation. Real SDK tests remain unexecuted here.
Task 3: CLI tests observed failing before implementation, then passed.
Additional regression: a credential-URL regular expression was quadratic on
very long non-URL lines. A subprocess deadline test reproduced the problem;
bounded URL components and an explicit URL-marker check fixed it.

Final review: self-review (no subagent tool available). Inspected filesystem
policy, per-component opens, HTTP middleware, SDK adapter, scripts and README
in a separate pass. This is not an independent review or security audit.

Ruling: keep the trusted single-user/authorized-private-tunnel deployment model;
no public OAuth deployment is claimed. Wrongly using it as a multi-user or public
server can expose project contents. This limitation is prominent in README.
Ruling: keep SDK validation as a mandatory post-install gate on the user's Mac;
no substitute or fake MCP implementation was used to obtain passing tests.
Cost: actual Mac/SDK/cloud interoperability may still require adjustment.

Deferred minor: long-line search snippets are prefix-only and can omit the
matched substring beyond the display limit; line_truncated marks that case.
Deferred minor: dependency ranges permit compatible patch updates; there is no
fully pinned transitive lockfile. Setup runs pip check and the full test suite.
