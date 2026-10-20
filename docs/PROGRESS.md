# Phase 2 Lite core foundation candidate - 2026-10-19

Plan: PR #12, e5d551f7bcf177b956a36c6810de5506b87a3e66.
Spec: PR #11, ca1a17cc943b2f5b7f5cf43d9d77211fe090de40.
Runtime code base: PR #10, cd345b0cb46f48b70c6e4478ae4d7d97269c5894.
The project owner confirmed independent design review and approved the plan.

A1/A2/A3 implementation candidate:
- Immutable exec declarations and strict activation guards at public factories.
- Shared signed-off argv validation, immutable requests and Service-only planning.
- Memory-only owner leases, 1-per-workspace / 4-global immediate admission.
- Coordinated file-worker and simulated-owner drain before root closure.

No Multi /run route or run_command tool is added. All workspace Gateways
remain allow_exec=False. No SDK modification, native launcher, OS signalling,
remote job API, fake backend configuration, deployment or enablement.
Runtime cwd/PGID (G2), restricted MCP profile (G3), integration (G4) and
release (G5) remain separate outstanding gates. Task 2's signed-off argv
fixes are inherited unchanged; Q0 is not repeated as a core-development gate.

Verification must distinguish the local offline snapshot from the complete
remote code-base CI and native macOS acceptance. Author self-review is not
independent review; this candidate requires external code review before merge.

---

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
