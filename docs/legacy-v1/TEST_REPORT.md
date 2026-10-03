# Verification report

Date: 2026-09-21

## Actual build environment

This report concerns the Linux build container, NOT the user's Mac.

- Python: 3.13.5
- OS: Linux
- starlette: 0.50.0
- uvicorn: 0.48.0
- httpx: 0.28.1
- pydantic: 2.13.4
- pytest: 9.0.2
- Official MCP SDK: unavailable; package-index network access failed.

## Full available suite

Command: `python -m pytest -q`

```
........................................................................ [ 81%]
................                                                         [100%]
88 passed, 1 skipped in 4.55s
```

The single skip is the entire MCP integration module, containing four test
functions (tool schemas/annotations, read, search, hidden-file rejection), each
with SDK initialization in its fixture. These four functions were NOT executed.
No protocol mock was used, and successful REST tests are not MCP validation.

Covered by executed tests: directory pagination, line reads, literal search,
Unicode, UTF-8/BOM handling, size/output limits, exclusions, hidden files,
secret filenames, symlinks, hardlinks, FIFOs, binaries, redaction, long-line
performance regression, Host/Origin/Fetch Metadata, optional bearer token,
request size/parameter validation, and CLI root/port checks.

## Real HTTP smoke test

An actual Uvicorn subprocess was started on an ephemeral IPv4-loopback port
with a temporary project. Real HTTP requests verified health, listing,
reading, keyword search, and HTTP 403 rejection for a hidden .env file.
The process was terminated and the temporary project deleted afterwards.

```json
{
  "real_http_listener": "PASS",
  "checks": [
    "health",
    "list",
    "read",
    "search",
    "hidden-file rejection"
  ],
  "transport": "REST only",
  "mcp_verified": false
}
```

## Additional checks

- Python compilation: `python -m compileall -q gateway tests` passed.
- Each of setup.sh, run.sh, verify.sh and tunnel.sh passed its own `bash -n`.
- `git diff --check` passed.
- Final ZIP contents and CRC were checked after packaging.

## Not verified here

Native macOS/APFS behavior; Homebrew installation; MCP SDK transport execution;
tunnel-client installation and runtime behavior; account permissions; tunnel
workspace association; actual ChatGPT tool discovery or end-to-end file reads.
No claim is made that these stages have succeeded.

On the Mac, run `bash setup.sh`, which requires the official SDK and runs all
tests, then perform the tunnel/ChatGPT checks in README.md. A successful setup
verifies local integration, not the external tunnel/ChatGPT connection.

Review was an author self-review because no independent reviewer tool was
available. This is not an independent security assessment. Deployment is for a
trusted single-user Mac and an authorized private tunnel, not the public web.
