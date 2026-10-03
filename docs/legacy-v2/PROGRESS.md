# Guarded writes build ledger
Baseline: original archive copied into a separate container directory. No live
Mac files changed. Baseline: 88 passed, 1 skipped (MCP SDK module absent).
Scope: implementation requested directly; ship a tested download, not deployment.
Interfaces: core -> writer -> descriptor-relative storage; core -> REST/MCP.
All write operations share the same policy and error type.

Task 1: complete. Snapshot hash RED -> GREEN; write policy RED -> GREEN. 125 core/write tests passed. Original REST and CLI regression suite also run.
SDK installation failed (package index returned no candidates, direct download unavailable); integration tests will remain explicit skips unless SDK becomes available.
Build tests use /opt/pyvenv/bin/python; nested venv does not inherit that environment.

Task 2: complete. REST/CLI RED -> GREEN, full suite 191 passed / 2 skipped.
Final review: author self-review; no independent reviewer tool available.
Review fixes: missing-final-newline preview, read-only POSIX source protection, invalid Unicode paths; 4 reproducing cases RED -> GREEN.
Read-only wording in MCP initialization instructions corrected by source review; SDK execution remains unverified.

Task 3: complete. Documentation and real HTTP smoke test added. Final build suite:
200 passed, 2 skipped (11 real-SDK MCP test functions not executed), 8.36s.
Real Uvicorn subprocess checks: health, side-effect-free preview, create, raw
read hash, exact replacement, original-byte backup, whole-file update, stale
conflict, hidden-file rejection. All PASS. Only temporary test projects used.
Compilation, all four shell syntax checks and git diff whitespace check PASS.
Deployment remains unverified on native macOS, private tunnel and ChatGPT.
Packaging is validated separately against the re-extracted source archive.
