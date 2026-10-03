# Guarded Writes Implementation Plan

> For agentic workers: use executing-plans inline, with test-driven-development.

**Goal:** Add opt-in, preview-first creation and modification of local files.
**Architecture:** Retain Gateway as the public interface; add a focused writer
and a filesystem commit/backup module; reuse descriptor-relative read policy.
**Tech Stack:** Python 3.11+, Starlette, official MCP Python SDK v1.
**Spec:** docs/superpowers/specs/2026-09-22-guarded-writes.md

## Global Constraints
UTF-8, max 1 MiB/file, read-only default, no shell/delete/directory creation,
all writes scoped to the selected project and optional --write-path values.
New tools default to dry_run=True. Source hashes represent original bytes.

## Review Focus
1. BOM/CRLF and final-newline changes must invalidate a stale hash.
2. Symlink/hardlink/FIFO targets and backup directory substitution must fail.
3. Disk/backup/commit failures must not leave a partially overwritten target.
4. Repeated/stale concurrent changes must not silently overwrite each other.
5. REST and MCP must share the same write restrictions and truthful annotations.

## Task 1: Core snapshot and guarded writes
Files: gateway/core.py, gateway/writer.py, gateway/write_storage.py,
tests/test_writes.py.
Consumes: Gateway._checked, Gateway._directory, _redact, GatewayError, Limits.
Produces: Gateway.create_file, write_file, replace_text; read_file.file_sha256.
- [x] Add actual-file tests for policy, dry-run, digest, create, replacement,
  backup, conflicts, byte limits, sensitive content, filesystem failures.
- [x] Run `python -m pytest tests/test_writes.py::test_read_hash_uses_original_bytes -q`;
  expect failure because file_sha256 is not implemented.
- [x] Implement snapshot sharing, policy checks and atomic guarded commits.
- [x] Run `python -m pytest tests/test_writes.py tests/test_core.py -q`;
  require every test to pass; record output in evidence/core.txt.

## Task 2: HTTP, CLI and MCP adapters
Files: gateway/http.py, gateway/mcp_adapter.py, gateway/__main__.py,
run.sh, tests/test_write_http.py, tests/test_write_cli.py, tests/test_mcp_write.py.
Consumes: Task 1 public Gateway interfaces and error codes.
Produces: three JSON POST routes, optional CLI flags, three annotated MCP tools
exposed only when writes are enabled.
- [x] Add HTTP POST/JSON/body-limit tests, CLI policy tests, real SDK tests.
- [x] Run new REST/CLI tests before changes; expect 404/unsupported flags.
- [x] Implement adapters without bypassing the core policy.
- [x] Run `python -m pytest -q`; record real SDK skips rather than fake a transport.

## Task 3: Packaging and verification
Files: README.md, docs/UPGRADE.md, docs/TEST_REPORT.md, tests/smoke_live.py.
- [x] Write and run a real-Uvicorn HTTP create/modify/conflict/backup smoke test.
- [x] Run compilation, shell syntax, complete pytest, SDK verification when
  available, and a separate author security review.
- [x] Document known race, metadata and native macOS limitations.
- [x] Build a source-only ZIP; verify CRC, exclude environments/keys/caches,
  re-extract it and run the full suite against the packaged copy.
