"""Local-only Gemini listener. Public HTTPS ingress must expose allowlisted paths only."""
from __future__ import annotations

import re

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route
from starlette.types import ASGIApp, Scope, Receive, Send

from .config import Config
from .oauth import routes as oauth_routes
from .proxy import MCPRelay
from .store import Store


class LocalHostBoundary:
    """Expect tunnel-side Host rewrite; do not loosen the original 8765 boundary."""
    def __init__(self, app: ASGIApp, port: int, public_url: str):
        self.app = app
        self.public_url = public_url
        self.hosts = {f"localhost:{port}", f"127.0.0.1:{port}"}

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        pairs = [(k.lower(), v) for k,v in scope.get("headers", [])]
        hosts = [v.decode("latin-1").lower() for k,v in pairs if k == b"host"]
        origins = [v.decode("latin-1") for k,v in pairs if k == b"origin"]
        if (len(hosts) != 1 or hosts[0] not in self.hosts or len(origins) > 1
            or (origins and origins[0] != self.public_url)
            or len(scope.get("query_string", b"")) > 4096):
            response = JSONResponse({"error":"invalid_host_or_origin"}, status_code=421)
            return await response(scope, receive, send)
        async def no_cache(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                headers = [(k,v) for k,v in headers if k.lower() not in {b"cache-control",b"x-content-type-options",b"referrer-policy"}]
                headers.extend([(b"cache-control",b"no-store"),(b"x-content-type-options",b"nosniff"),(b"referrer-policy",b"no-referrer")])
                message={**message,"headers":headers}
            await send(message)
        await self.app(scope,receive,no_cache)


def create_app(config: Config, *, store: Store | None = None, relay: MCPRelay | None = None):
    local_store = store or Store(config.state_file)
    local_relay = relay or MCPRelay(config)
    async def mcp_endpoint(request: Request):
        values = request.headers.getlist("authorization")
        token = ""
        if len(values) == 1 and values[0].startswith("Bearer "):
            token = values[0][7:]
        grant = local_store.lookup(token) if re.fullmatch(r"[A-Za-z0-9_-]{40,512}", token) else None
        challenge = ('Bearer resource_metadata="' + config.public_url
                     + '/.well-known/oauth-protected-resource", scope="' + " ".join(config.scopes) + '"')
        if grant is None or grant["client"] != config.client_id:
            return JSONResponse({"error":"unauthorized"},status_code=401,headers={"WWW-Authenticate":challenge})
        # Config changes immediately reduce even previously issued grants.
        grant["scopes"] = tuple(x for x in grant["scopes"] if x in config.scopes)
        grant["workspaces"] = tuple(x for x in grant["workspaces"] if x in config.workspaces)
        if request.method != "POST":
            return Response(status_code=405,headers={"Allow":"POST"})
        if "files:read" not in grant["scopes"]:
            return JSONResponse({"error":"insufficient_scope"},status_code=403,
                                headers={"WWW-Authenticate":challenge.replace('Bearer ', 'Bearer error="insufficient_scope", ',1)})
        return await local_relay.forward(request,grant)

    async def health(request: Request):
        # Never include this path in the public Tunnel route allowlist.
        return JSONResponse({"status":"ok","mode":"gemini-adapter","mcp":True})

    async def shutdown():
        await local_relay.close()
        if store is None:
            local_store.close()

    app = Starlette(
        routes=[Route("/health",health,methods=["GET"]),
                Route("/mcp",mcp_endpoint,methods=["POST","GET"])]+oauth_routes(config,local_store),
        on_shutdown=[shutdown],
    )
    return LocalHostBoundary(app,config.listen_port,config.public_url)
