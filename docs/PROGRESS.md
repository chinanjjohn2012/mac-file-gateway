# Progress

## 2.2.0 file lifecycle

Implemented and locally verified in the build environment:

- guarded delete core with exact-byte backup
- MCP aliases `delete_file`, `remove_file`, `unlink`
- atomic no-overwrite move core
- MCP aliases `rename`, `move`
- matching REST routes
- source-hash conflict checks
- write-scope enforcement on both move paths
- redacted-source delete/move support
- directory/symlink deletion refusal
- destination overwrite refusal
- live HTTP move -> delete smoke path

Remaining deployment verification:

- native macOS/APFS behavior
- official MCP SDK integration on the Mac
- tunnel/action refresh and ChatGPT end-to-end calls


## 2.3.0 controlled execution

- Added opt-in `run_command` MCP tool and `POST /run`.
- Added independent `--allow-exec` / repeatable `--exec-path` scope.
- Added explicit `--exec-runner PATH=pipenv|direct` plus Pipfile fallback constrained to exec scope.
- Added pytest, Python compile/test/script, Go test/vet allowlist; no shell parsing.
- Added minimized environment, disabled stdin, process-group timeout and bounded/redacted output.
- GitHub Actions with official MCP SDK: 391 passed, 1 warning; HTTP smoke/compileall/shell syntax passed.
