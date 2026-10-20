# MCP Python SDK v2 migration (feature/mcp-sdk-v2)

Scope: adapter-only migration from mcp==1.30.0 to pinned mcp==2.3.0.
Base: release/ms1 (e32cb5124bbd8b08a79c75b4940799e041dd1295).

## Contract retained

- The MCP endpoint remains /mcp; REST paths are unchanged.
- Both legacy 2025-11-25 and modern 2026-07-28 MCP clients use the same endpoint.
- Legacy and multi-workspace call_tool guards reject missing, unknown, and incorrectly typed arguments before Pydantic coercion.
- Single-workspace read and write/exec limits remain 64 KiB and 7 MiB respectively; multi-workspace remains 8 MiB raw with independent decoded JSON complexity limits.
- The same Host, Origin, bearer-token, dry-run, SHA-256, Workspace and file-descriptor security gates remain in force.
- stdio and HTTP share the SDK v2 MCPServer tool registrations.
- Phase 1 multi-workspace still exposes no command or Local Skill tools. The legacy-mode Local Skill bridge is opt-in.
- Both MCP adapters set `subscriptions=False`. Gateway does not offer the long-lived `subscriptions/listen` SSE method introduced by the SDK 2.x default.

## Source changes

- Switch FastMCP -> MCPServer and pass the SDK v2 tool Context through call_tool.
- Move SDK transport settings from the old constructor to streamable_http_app.
- Add gateway/mcp_transport.py to share explicit HTTP limits, stateless JSON response, and DNS rebinding policy.
- Keep strict Gateway envelope checks and WorkspaceService authorization independently of SDK schema validation.
- Move Local Skill registry test to public async list_tools API.
- Explicitly disable the unused SDK v2 subscription stream on legacy and multi adapters; cover HTTP-level method-not-found behavior.

## Verification / release gates

1. Use Python 3.11+ (CI uses 3.13) and run bash setup.sh, bash verify.sh --require-mcp.
2. Run existing legacy MCP protocol tests for initialize, list, read, preview, apply, stale hashes, schema, command, Local Skill and multi-workspace.
3. Run test_mcp_sdk_v2.py for modern server/discover, tools/list, tools/call, strict errors and 4-8 MiB wire request admission.
4. Run `python tests/smoke_mcp_live.py` for a separate real HTTP listener with modern and legacy MCP tool exchange. The REST-only smoke intentionally reports `mcp_verified: false` for its own subprocess.
5. Run `python tests/smoke_mcp_stdio.py` for official SDK client-to-real-Gateway stdio subprocess regression in both protocol eras. Run `python tests/smoke_mcp_disconnect.py` to verify controlled command completion and timeout through a real modern MCP HTTP listener, including disconnect after confirmed start. The fake Local Skill cancellation fixture does not run any business scripts. Independently verify the live ChatGPT Tunnel on the user's macOS host; that cannot be proven by CI.
6. Check GitHub Actions success, release manifest integrity, and independent architecture/security review.
7. Do not merge into release/ms1 before the above have passed. Never treat source review as CI or live-environment evidence.

## In-flight work, disconnect and cancellation contract

- With `json_response=True`, a client closing an HTTP response is **not** authorization to undo or terminate an operation already started by the server. The SDK v2 modern JSON path has no guaranteed HTTP disconnect-to-subprocess cancellation propagation; the pre-v2 JSON path also provided no such guarantee.
- `run_command` and `run_skill_script` are synchronous threadpool operations. Once authorized with their explicit execution arguments, they may finish after the client connection closes. Their own server-side `timeout_seconds` limits remain in effect (1–300 seconds), with process-group termination on timeout. This is a bounded-execution contract, **not** an exactly-once execution or guaranteed completion contract if the host crashes or is forcibly killed.
- A lost HTTP response means **outcome unknown to the caller**. Do not automatically retry a possibly non-idempotent run merely because the response was lost; first inspect any available effects or logs and obtain appropriate fresh authorization.
- `tests/smoke_mcp_disconnect.py` uses only temporary paths and a harmless script to verify an already-started `run_command` can complete after a client disconnect, alongside normal completion, timeout termination and listener survival. `tests/test_local_skill_mcp.py` uses a fake Bridge to test the cancellation boundary without invoking real Skill scripts; the real SkillScriptExecutor timeout is separately covered by `tests/test_local_skill_executor.py`.
- Immediate cancellation on disconnect, server-managed operation IDs, definitive post-disconnect delivery and retry deduplication are **not** features of this SDK migration. Any such changes require a separate lifecycle design and review.

## Rollback

Switch deployment back to unchanged release/ms1 and re-run its existing verification. Do not alter the stable branch or the external client connector as part of this change.
