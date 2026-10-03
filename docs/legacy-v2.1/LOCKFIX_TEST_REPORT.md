# Mac File Gateway 2.1 lock-open hotfix: verification report

Date: 2026-09-22

## What the user's report proves, and what remains uncertain

The reported native-macOS test returned ["write_failed", true] instead of one
successful write and one "conflict". The old implementation discards the OS
errno and error stage. This output alone does NOT prove which syscall failed.
The Linux environment did not reproduce the native failure without injection.

Source inspection found a single-shot os.open(".lock", O_CREAT | O_NOFOLLOW ...)
inside the lock initialization code. A first-party report of an analogous
Darwin concurrent-first-create openat(O_CREAT) ENOENT race is documented at:
https://github.com/Gentleman-Programming/gentle-ai/issues/4276
https://github.com/Gentleman-Programming/gentle-ai/pull/4277
This supports the working hypothesis; it is not proof about the user's Mac.

The hotfix targets that narrowly defined failure and adds safe diagnostics so
a different native failure can be identified rather than guessed at.

## Changed behavior

Only the existing gateway/write_storage.py runtime module is replaced.
- On Darwin only, retry ENOENT when opening the fixed .lock leaf, with at most
  three attempts and 10 ms between attempts.
- Reuse the same validated parent descriptor and all original security flags.
- Keep private ownership/mode and hardlink/symlink validation unchanged.
- Do NOT retry other open errors, the write operation, or the commit.
- Keep fcntl.flock and hash conflict checks unchanged.
- Keep the original concurrency test and its assertion byte-for-byte unchanged.
- Add bounded stage/errno diagnostics without OS filenames or file contents.
- Add 21 regression-test cases and a standalone temporary-project diagnostic.

No dependencies, key permissions, tunnel settings, exposed MCP schemas, source
hash checks, write scopes, write defaults, or directory behavior are changed.
Gateway info still reports 2.1.0: this is a targeted hotfix, not a new API release.

## Actual test environment

Linux; Python 3.13.5; pytest 9.0.2; starlette 0.50.0; uvicorn 0.48.0;
httpx 0.28.1; anyio 4.13.0.
Not Python 3.14 and not native macOS/APFS.

The official MCP SDK was unavailable. A fresh installation attempt failed with
"No matching distribution found for mcp<2,>=1.28.1" from the available index.
No MCP transport result is claimed and no mocked protocol substitutes for it.

## Evidence observed in this session

1. Original ZIP baseline: 270 passed, 2 skipped.
2. New regression suite before implementation: 16 failed, 5 passed.
   The injected two-instance first-create race returned exactly
   ['write_failed', True], matching the reported outer error shape.
3. Same regression suite after implementation: 21 passed.
4. Delivery-script tests: 7 passed after a failing pre-implementation run.
   Includes original-source backup, idempotence, modified-source refusal,
   conflicting-file refusal, symlink-directory refusal, and old/new diagnostics.
5. Freshly extracted original ZIP, patched using the delivered script:

```text
........................................................................ [ 24%]
........................................................................ [ 49%]
........................................................................ [ 74%]
........................................................................ [ 98%]
...                                                                      [100%]
291 passed, 2 skipped in 15.13s
```

The two skips are entire MCP integration modules, not two individual functions.
Existing user-side MCP tests ran in the supplied log, but this Linux run cannot
verify those SDK tests. The Mac must run bash verify.sh --require-mcp.

6. Freshly patched installation, repeated real thread contention:

```text
{"python": "3.13.5", "platform": "linux", "storage_sha256": "83189c0b31b16a07ab95ee723a2a0bd3dd2866e91f26b1902eed9ea35a667658", "test": "two threads, independent Gateway instances, fresh temporary project each round"}
Concurrent write check: 50/50 passed; 0 failed.
Only disposable temporary projects were written; no served project was accessed.
```

7. Independent real processes:

```text
Independent process contention: 10/10 passed; one applied and one conflict per round.
```

8. Actual local HTTP server:

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

9. compileall for gateway/tests/tools, py_compile for the delivery scripts, and
   bash -n for setup.sh/run.sh/verify.sh/tunnel.sh passed.
10. Compared every original ZIP file after patching: the only modified original
    file was gateway/write_storage.py. New tests/tools were added; the original
    test_write_review.py and all API adapters remained unchanged.

## Review and remaining limits

Author self-review only; no independent reviewer tool or security audit.
No native macOS/APFS or Python 3.14 test was available, and no Mac -> tunnel ->
ChatGPT end-to-end test was executed. A passing fault-injection test is not an
emulation of APFS. Keep writes stopped until native verification passes.
If native tests still fail, run tools/diagnose_lock.py to capture the safe OS
errno and stage. Do not broaden the retry or skip the concurrency assertion.

The patch installer is for a trusted, stopped, single-user installation.
It refuses unknown source hashes, existing conflicting files, symlinks and
hardlinked targets. Its multi-file installation is not transactional; it
backs up the original runtime module and replaces that module last.
The tests and diagnostic write only temporary test projects.

## Artifact hashes

- `apply_gateway_lock_fix.py`: `156641ffead28f1703c2cce78d03a56764e5a71d12632a081d6cff74aec5b79f`
- `diagnose_gateway_lock.py`: `6b0a5f1252e90d7b3479993a37bf9be265bb28680f0aff62552c6f4f863b23ab`
- `gateway-lock-fix.diff`: `dad95e4cfc222d741308f80a6d258eabcd7e8a3bd6a8ec4331552a802cca34af`
