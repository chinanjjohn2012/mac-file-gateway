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

## Source changes

- Switch FastMCP -> MCPServer and pass the SDK v2 tool Context through call_tool.
- Move SDK transport settings from the old constructor to streamable_http_app.
- Add gateway/mcp_transport.py to share explicit HTTP limits, stateless JSON response, and DNS rebinding policy.
- Keep strict Gateway envelope checks and WorkspaceService authorization independently of SDK schema validation.
- Move Local Skill registry test to public async list_tools API.

## Verification / release gates

1. Use Python 3.11+ (CI uses 3.13) and run bash setup.sh, bash verify.sh --require-mcp.
2. Run existing legacy MCP protocol tests for initialize, list, read, preview, apply, stale hashes, schema, command, Local Skill and multi-workspace.
3. Run test_mcp_sdk_v2.py for modern server/discover, tools/list, tools/call, strict errors and 4-8 MiB wire request admission.
4. Verify stdio by real SDK client and live Tunnel with ChatGPT. Confirm exposed tools and returns match existing client contracts.
5. Check GitHub Actions success, release manifest integrity, and independent architecture/security review.
6. Do not merge into release/ms1 before the above have passed. Never treat source review as CI or live-environment evidence.

## Rollback

Switch deployment back to unchanged release/ms1 and re-run its existing verification. Do not alter the stable branch or the external client connector as part of this change.
