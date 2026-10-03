# Verification report: Mac File Gateway 2.1

Date: 2026-09-22

## Environment and scope

Python 3.13.5; Linux build container, NOT macOS.
Source was extracted from the supplied v2.0 ZIP into an independent directory.
No live user project, account permission, tunnel or connected app was modified.

Dependencies actually used: {"httpx": "0.28.1", "pydantic": "2.13.4", "pytest": "9.0.2", "starlette": "0.50.0", "uvicorn": "0.48.0"}.
Official MCP SDK: not installed. Both the default package index and an explicit
public-index install attempt reported no available distribution for
mcp>=1.28.1,<2 in this environment. The dependency is not replaced or mocked.

## Actual test evidence

Original v2.0 baseline: 200 passed, 2 skipped.
New core and REST directory tests before implementation: 69 failed as expected
(missing API/route and policy capability).
After implementation: those 69 passed.
Author review added one syscall-failure resource-leak test: 1 failed before the
fix, then passed after the descriptor-close fix.

Full command: `python -m pytest -q`

```
........................................................................ [ 26%]
........................................................................ [ 53%]
........................................................................ [ 80%]
......................................................                   [100%]
270 passed, 2 skipped in 7.68s
```

The two skips are entire official-SDK test modules, not successful tests.
Unexecuted test function counts: {"tests/test_mcp.py": 4, "tests/test_mcp_write.py": 13}. Parametrized cases would
expand further. MCP initialization, tool schemas, annotations, errors and calls
have NOT been executed here. The 270 passes are non-MCP cases.

New coverage: preview without side effects; single/recursive creation; file
creation inside new directories; existing-directory no-op and strict conflict;
file and ancestor-type conflicts; strict booleans; traversal/root rejection;
hidden/sensitive paths; exclusions; every-new-parent write scope; exact-case
scope (including file-write regression); symlinks and an injected link swap;
depth/byte limits; Unicode/spaces; concurrent gateways; partial I/O failures;
truthful sync warnings; descriptor cleanup; HTTP JSON/method/auth/Origin checks.

## Real HTTP listener

Command: `python tests/smoke_live.py`

Starts a real Uvicorn subprocess on temporary loopback port with --http-only,
operates only on a disposable project, then terminates the process.

```json
{
  "real_http_listener": "PASS",
  "checks": [
    "mkdir_preview",
    "recursive_mkdir",
    "existing_directory_noop",
    "strict_directory_conflict",
    "file_inside_new_directory",
    "mkdir_file_conflict",
    "mkdir_blocked_path",
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

This is real REST verification, NOT MCP or ChatGPT end-to-end verification.

## Review and compatibility choices

A separate author self-review was performed; no independent reviewer tool was
available. No independent security audit was performed.

Write scope now requires exact component spelling; this deliberately prevents
case-folded sibling access on case-sensitive filesystems. Existing callers that
use different casing must use the configured spelling. Exclusion checks remain
case-insensitive. Recursive creation leaves partial directories on I/O failure
and reports them instead of deleting possibly-in-use directories.

## Packaging verification

The final ZIP is CRC-checked, extracted again, and tested in that extracted copy.
The adjacent mac-file-gateway-v2.1-PACKAGE_CHECK.txt contains those final results
and the ZIP SHA-256. Shell scripts and Python compilation are also checked.
The ZIP excludes dependency environments, caches, user files and backups.

## Not verified here

Native macOS/APFS behavior, ACLs/flags, crash durability, official MCP SDK
transport, Homebrew or tunnel runtime, account permissions, workspace action
snapshot updates, human-confirmation behavior, and actual ChatGPT calls.
No guarantee against malicious concurrent directory moves. Preview is not a
human authorization barrier. Runtime requirements remain the maintained SDK v1
API range; this update does not attempt an SDK v2 migration.

On the Mac run `bash setup.sh`, which requires the official SDK and executes all
local tests plus the temporary HTTP smoke test. Then connect a disposable
project to ChatGPT and verify actual calls before exposing important work.
