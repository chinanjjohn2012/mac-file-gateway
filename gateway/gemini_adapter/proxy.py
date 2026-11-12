"""Fail-closed, scope-aware JSON-RPC MCP relay to the existing local Gateway.

This is NOT a general HTTP proxy. It recognizes only the limited MCP methods
used by the main Gateway and never forwards external credentials or Host.
"""
from __future__ import annotations

import json
import re
from typing import Any

import httpx
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from .config import Config

READ = frozenset({"gateway_info", "list_workspaces", "list_files", "read_file", "search_files"})
WRITE = frozenset({"create_directory", "create_file", "write_file", "replace_text", "rename", "move"})
DELETE = frozenset({"delete_directory", "delete_file", "remove_file", "unlink"})
TOOLS = READ | WRITE | DELETE
FORWARDED_HEADERS = ("mcp-protocol-version", "mcp-method", "mcp-name", "accept", "content-type", "mcp-session-id")


def permission(tool: str) -> str | None:
    if tool in READ:
        return "files:read"
    if tool in WRITE:
        return "files:write"
    if tool in DELETE:
        return "files:delete"
    return None


def parse_json(raw: bytes):
    def no_dupes(pairs: list[tuple[str,Any]]):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate JSON field")
            result[key] = value
        return result
    def no_nonfinite(value):
        raise ValueError("Invalid JSON number")
    return json.loads(raw, object_pairs_hook=no_dupes, parse_constant=no_nonfinite)


def rpc_error(id: Any, code: int, message: str, status: int = 200):
    return JSONResponse({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}},status_code=status,headers={"Cache-Control":"no-store"})


def scrub_tool_metadata(tool: dict[str, Any]):
    # The source Gateway marks non-destructive creates. Gemini's confirmation
    # UI benefits from a conservative state-changing/destructive classification.
    name = tool.get("name")
    result = dict(tool)
    if name in WRITE | DELETE:
        annotations = dict(result.get("annotations") or {})
        annotations["readOnlyHint"] = False
        annotations["destructiveHint"] = True
        result["annotations"] = annotations
    return result


def restrict_workspace_fields(value: Any, allowed: set[str]) -> Any:
    """Filter workspace inventory in both structured and text tool results.

    Multi Gateway info embeds workspace listings and Git capabilities. A
    tool-name filter alone does not prevent this sensitive enumeration.
    """
    if isinstance(value, list):
        return [restrict_workspace_fields(x, allowed) for x in value]
    if not isinstance(value, dict):
        return value
    clean = {}
    for key, item in value.items():
        if key in {"git_policy", "git", "sensitive_grants", "sensitive_content"}:
            continue
        if key == "workspaces" and isinstance(item, list):
            clean[key] = [restrict_workspace_fields(x, allowed) for x in item
                          if (x in allowed if isinstance(x, str) else
                              isinstance(x, dict) and (x.get("id") or x.get("name")) in allowed)]
        elif key == "workspace_count" and "workspaces" in value and isinstance(value["workspaces"], list):
            clean[key] = len([x for x in value["workspaces"]
                              if (x in allowed if isinstance(x, str) else
                                  isinstance(x, dict) and (x.get("id") or x.get("name")) in allowed)])
        else:
            clean[key] = restrict_workspace_fields(item, allowed)
    return clean


class MCPRelay:
    def __init__(self, config: Config, client: httpx.AsyncClient | None = None):
        self.config = config
        self.client = client or httpx.AsyncClient(timeout=httpx.Timeout(75.0, connect=5.0), follow_redirects=False, trust_env=False)
        self.owns_client = client is None

    async def close(self):
        if self.owns_client:
            await self.client.aclose()

    async def forward(self, request: Request, grant: dict):
        if request.method != "POST":
            return Response(status_code=405,headers={"Allow":"POST"})
        if request.headers.get("content-type", "").split(";", 1)[0].lower() != "application/json":
            return rpc_error(None,-32600,"JSON content type required",415)
        length = request.headers.get("content-length")
        if length:
            try:
                if int(length) > 8*1024*1024 or int(length) < 0:
                    return rpc_error(None,-32600,"Request too large",413)
            except ValueError:
                return rpc_error(None,-32600,"Invalid content length",400)
        data = bytearray()
        async for chunk in request.stream():
            if len(data) + len(chunk) > 8*1024*1024:
                return rpc_error(None,-32600,"Request too large",413)
            data.extend(chunk)
        body = bytes(data)
        try:
            envelope = parse_json(body)
            if not isinstance(envelope,dict) or envelope.get("jsonrpc") != "2.0" or not isinstance(envelope.get("method"),str):
                raise ValueError("Invalid MCP envelope")
            method = envelope["method"]
            if "id" in envelope and (type(envelope["id"]) not in (int,str) or len(str(envelope["id"])) > 100):
                raise ValueError("Invalid request id")
            params = envelope.get("params") or {}
            if not isinstance(params, dict):
                raise ValueError("Invalid params")
        except (ValueError,UnicodeError):
            return rpc_error(None,-32700,"Invalid JSON-RPC payload",400)
        rpc_id = envelope.get("id")
        if method not in {"initialize", "notifications/initialized", "ping", "server/discover", "tools/list", "tools/call"}:
            return rpc_error(rpc_id,-32601,"MCP method is not available")
        tool = None
        if method == "tools/call":
            tool = params.get("name")
            arguments = params.get("arguments", {})
            if not isinstance(tool,str) or not isinstance(arguments, dict):
                return rpc_error(rpc_id,-32602,"Invalid tool arguments")
            required = permission(tool)
            if required is None or required not in grant["scopes"]:
                return rpc_error(rpc_id,-32601,"Tool not permitted")
            workspace = arguments.get("workspace")
            if workspace is not None and (not isinstance(workspace,str) or workspace not in grant["workspaces"]):
                return rpc_error(rpc_id,-32602,"Workspace not authorized")
            if tool == "list_workspaces" and not grant["workspaces"]:
                return rpc_error(rpc_id,-32601,"Tool not permitted")
            # There is no server-recognized confirmation field in generic MCP
            # calls. Gateway's existing dry_run policy remains authoritative.
        elif method == "tools/list" and "files:read" not in grant["scopes"]:
            return rpc_error(rpc_id,-32601,"Tool discovery not permitted")
        headers = {k:request.headers[k] for k in FORWARDED_HEADERS if k in request.headers}
        headers.setdefault("accept", "application/json, text/event-stream")
        headers["content-type"] = "application/json"
        try:
            upstream = await self.client.post(self.config.upstream,content=body,headers=headers)
        except (httpx.TimeoutException,httpx.RequestError):
            return rpc_error(rpc_id,-32000,"Local Gateway unavailable",503)
        if upstream.status_code == 202:
            return Response(status_code=202,headers={"Cache-Control":"no-store"})
        if upstream.status_code >= 500:
            return rpc_error(rpc_id,-32000,"Local Gateway unavailable",503)
        if upstream.headers.get("content-type", "").split(";",1)[0].strip().lower() != "application/json":
            return rpc_error(rpc_id,-32000,"Unexpected local Gateway response",502)
        if len(upstream.content) > 8*1024*1024:
            return rpc_error(rpc_id,-32000,"Local Gateway response too large",502)
        try:
            result = parse_json(upstream.content)
            if not isinstance(result,dict):
                raise ValueError
            if method == "tools/list" and isinstance(result.get("result"),dict):
                tools = result["result"].get("tools")
                if not isinstance(tools,list):
                    raise ValueError
                # The upstream may expose Git/Exec/Skills; they are never
                # included in this Gemini authorization boundary.
                allowed = []
                for item in tools:
                    if not isinstance(item,dict):
                        raise ValueError
                    name = item.get("name")
                    if (isinstance(name,str) and permission(name) in grant["scopes"]
                        and (name != "list_workspaces" or grant["workspaces"])):
                        allowed.append(scrub_tool_metadata(item))
                result["result"]["tools"] = allowed
            if method == "tools/call" and tool in {"list_workspaces", "gateway_info"} and isinstance(result.get("result"),dict):
                payload = result["result"]
                structured = payload.get("structuredContent")
                if not isinstance(structured,dict):
                    # Do not leak inventories via an unexpected upstream format.
                    return rpc_error(rpc_id,-32000,"Unsupported workspace response",502)
                safe = restrict_workspace_fields(structured,set(grant["workspaces"]))
                payload["structuredContent"] = safe
                # MCP SDK also serializes the complete tool result in content.
                # Never leave the unfiltered JSON there after filtering the
                # structured representation.
                payload["content"] = [{"type":"text","text":json.dumps(safe,ensure_ascii=False)}]
        except (ValueError,UnicodeError):
            return rpc_error(rpc_id,-32000,"Invalid local Gateway response",502)
        return JSONResponse(result,status_code=upstream.status_code,headers={"Cache-Control":"no-store"})
