# Mac File Gateway Implementation Plan

Goal: deliver a runnable, limited, read-only gateway with Mac setup scripts.
Architecture: POSIX filesystem core, Starlette HTTP boundary, official MCP SDK
adapter, and private OpenAI tunnel configured separately by the user.
Tech stack: Python 3.11+, Starlette, Uvicorn, MCP Python SDK v1, pytest.
Spec: docs/DESIGN.md

## Global constraints
- Never expose writes, command execution, or the entire home directory.
- All transports share the same filesystem policy.
- Bind to IPv4 loopback only; no public quick-tunnel deployment.
- Run code only inside this new isolated build directory.
- Distinguish actual test results from untested Mac/cloud integration.

## Review focus
- Case-insensitive macOS filenames and hidden/secret path components.
- Symlink escapes, final-file symlinks, hardlinks, and FIFO devices.
- Untrusted HTTP origins and DNS-rebinding-style Host headers.
- Bounded output for huge lines, oversized files, and truncated searches.
- Useful errors and graceful empty-file/empty-directory behavior.

## Task 1: Filesystem core
- [x] Write tests for list/read/search and each security boundary.
- [x] Run pytest tests/test_core.py and observe missing behavior.
- [x] Implement gateway/core.py with one pinned root and shared policy.
- [x] Run the complete available test suite and commit.

## Task 2: HTTP and MCP adapters
- [x] Write REST boundary tests and SDK initialize/list/call integration tests.
- [x] Run REST tests before implementing the adapter.
- [x] Implement bounded middleware, REST routes, and official SDK tools.
- [x] Run all tests; report unavailable SDK tests explicitly.

## Task 3: Mac delivery
- [x] Write setup/start/verification scripts and dependency declarations.
- [x] Document private tunnel prerequisites and exact local commands.
- [x] Verify shell syntax, Python compilation, live HTTP, and archive contents.
- [x] Conduct a separate self-review and deliver a ZIP plus clear limitations.

SDK integration execution is explicitly excluded from completion claims in this environment.
