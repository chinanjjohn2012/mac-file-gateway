"""Pinned Streamable HTTP transport settings for official MCP SDK v2.

Keep one shared SDK transport configuration for the legacy and multi-workspace
adapters. The independent Gateway HTTP and admission boundaries still apply.
"""
from __future__ import annotations

from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from starlette.applications import Starlette


def build_streamable_http_app(mcp: MCPServer, *, port: int, max_request_body_size: int) -> Starlette:
    """Preserve the v1 external HTTP contract while selecting v2 transport settings."""
    return mcp.streamable_http_app(
        streamable_http_path="/mcp",
        stateless_http=True,
        json_response=True,
        max_request_body_size=max_request_body_size,
        host="127.0.0.1",
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=[f"127.0.0.1:{port}", f"localhost:{port}"],
            allowed_origins=[f"http://127.0.0.1:{port}", f"http://localhost:{port}"],
        ),
    )
