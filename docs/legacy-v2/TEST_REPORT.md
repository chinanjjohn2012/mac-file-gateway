# Verification report: Mac File Gateway 2.0

Date: 2026-09-22

## What was actually tested

Tests ran inside a Linux build container, NOT the user's Mac. The original
archive was copied into an isolated working directory; no user project was
accessed or modified.

- Python: 3.13.5
- Platform: Linux
- starlette: 0.50.0
- uvicorn: 0.48.0
- httpx: 0.28.1
- pydantic: 2.13.4
- pytest: 9.0.2
- Official MCP SDK: not installed; package index had no accessible candidate,
  and a direct wheel download failed. No replacement/mock MCP implementation
  was substituted.

## Full suite

Command: `python -m pytest -q`

```
200 passed, 2 skipped in 8.36s
```

The two skips are entire real-SDK integration modules: test_mcp.py (4 test
functions) and test_mcp_write.py (7 test functions). Those **11 MCP test
functions did not execute**. "200 passed" covers the collected non-MCP cases;
it is NOT a successful MCP integration or ChatGPT deployment claim.

The full suite covers the original read-only behavior plus:
- Read-only default, opt-in writes and subtree/file allowlists.
- Creation with no clobber; whole-file update; exact text replacement.
- Side-effect-free previews and explicit final-newline diff markers.
- Original-byte hashes, BOM/CRLF preservation in exact replacement, stale hashes,
  changed source during commit preparation and expected-match counts.
- Backup byte accuracy/private modes, retention limit, state substitution,
  injected backup/rename failures and truthful post-commit sync warnings.
- Threaded races, two gateway instances sharing an advisory project lock,
  and an injected late destination creation race.
- Hidden/excluded paths, traversal, symlinks, hardlinks, FIFOs, malformed Unicode,
  NUL/invalid content, credential-like text and redaction placeholders.
- POSIX read-only mode protection and preservation of ordinary mode bits.
- UTF-8 byte limits, bounded diffs, HTTP body size limits, unique JSON keys,
  content types, strict argument validation, Host/Origin/Fetch Metadata checks,
  optional bearer authorization, and CLI flags.

## Real HTTP smoke test

Command: `python tests/smoke_live.py`

A real Uvicorn subprocess bound to a temporary loopback port. Requests created
and modified only a temporary test project, and the process was terminated at
the end. This exercised REST only, with --http-only explicitly set.

```json
{
  "real_http_listener": "PASS",
  "checks": [
    "health",
    "preview_no_change",
    "create",
    "read_raw_hash",
    "exact_replace",
    "backup_original_bytes",
    "whole_file_write",
    "stale_conflict",
    "hidden_file_blocked"
  ],
  "mcp_verified": false
}
```

## Additional checks

- Python compilation: `python -m compileall -q gateway tests` passed.
- setup.sh, run.sh, verify.sh and tunnel.sh each passed `bash -n`.
- `git diff --check` passed.
- Source archive CRC, member selection and re-extracted tests are checked during
  packaging; the final package report is stored alongside the downloaded ZIP.

## Review

A separate author self-review was performed. It found and fixed misleading
no-final-newline diffs, POSIX read-only-file replacement and invalid Unicode path
exceptions, with four reproducing cases run RED -> GREEN. MCP initialization
wording was corrected by source review; its real SDK test remains unexecuted.
There was no independent reviewer or security audit.

## Not verified; do not infer success

- Native macOS/APFS behavior, file flags, ACLs, resource forks, extended
  attributes or crash/power-failure durability.
- Official MCP SDK initialization, schemas, annotations and write transport.
- Homebrew installation, tunnel runtime, account permissions, app tool snapshot
  refresh, client confirmation behavior or real ChatGPT end-to-end writes.
- Protection against a malicious local process moving directories, or against
  the narrow final hash-check-to-rename race with non-cooperating editors.

The implementation preserves ordinary file mode bits, not all original
metadata. Source writes may trigger a separately running file watcher or dev
server. Backup files are local unencrypted originals; exclude them from Git.

On the Mac, `bash setup.sh` installs the official SDK and invokes
`bash verify.sh --require-mcp`, which must pass the SDK integration modules and
the temporary HTTP smoke test. Then test your private tunnel using a disposable
project. Passing setup still does not establish a live ChatGPT end-to-end test.
