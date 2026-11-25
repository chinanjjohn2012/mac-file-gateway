"""OAuth authorization-code + PKCE for a local-operator approved Gemini client."""
from __future__ import annotations

import base64
import html
import hmac
import json
import re
from urllib.parse import parse_qsl, urlencode

from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Route

from .config import Config
from .store import Store

PKCE_CHALLENGE = re.compile(r"[A-Za-z0-9_-]{43,128}\Z")
PKCE_VERIFIER = re.compile(r"[A-Za-z0-9._~-]{43,128}\Z")


def _json(body: dict, status: int = 200, headers: dict | None = None):
    return JSONResponse(body, status_code=status, headers={"Cache-Control":"no-store", "Pragma":"no-cache", **(headers or {})})


def _oauth_error(code: str, status: int = 400):
    extra = {"WWW-Authenticate": 'Basic realm="Mac File Gateway"'} if status == 401 else {}
    return _json({"error": code}, status, extra)


def _unique_params(raw: str):
    fields = parse_qsl(raw, keep_blank_values=True, strict_parsing=True, max_num_fields=24)
    if len({k for k, _ in fields}) != len(fields):
        raise ValueError("Duplicate OAuth parameter")
    return dict(fields)


def _client_credentials(request: Request, params: dict, config: Config) -> bool:
    auth = request.headers.get("authorization", "")
    if auth:
        if not auth.startswith("Basic ") or "client_secret" in params:
            return False
        try:
            decoded = base64.b64decode(auth[6:], validate=True).decode("utf-8")
            cid, secret = decoded.split(":", 1)
        except (ValueError, UnicodeError):
            return False
    else:
        cid, secret = params.get("client_id"), params.get("client_secret")
    return (isinstance(cid, str) and isinstance(secret, str)
            and hmac.compare_digest(cid, config.client_id)
            and hmac.compare_digest(secret, config.client_secret))


def routes(config: Config, store: Store) -> list[Route]:
    async def resource_metadata(request: Request):
        return _json({"resource":config.resource,"authorization_servers":[config.issuer],
                      "bearer_methods_supported":["header"],"scopes_supported":list(config.scopes)})

    async def authorization_metadata(request: Request):
        return _json({
            "issuer":config.issuer,
            "authorization_endpoint":config.public_url + "/oauth/authorize",
            "token_endpoint":config.public_url + "/oauth/token",
            "revocation_endpoint":config.public_url + "/oauth/revoke",
            "response_types_supported":["code"],
            "grant_types_supported":["authorization_code", "refresh_token"],
            "token_endpoint_auth_methods_supported":["client_secret_basic", "client_secret_post"],
            "code_challenge_methods_supported":["S256"],
            "scopes_supported":list(config.scopes),
        })

    async def authorize(request: Request):
        try:
            p = _unique_params(request.scope.get("query_string", b"").decode("ascii"))
            required = {"client_id", "redirect_uri", "response_type", "code_challenge", "code_challenge_method"}
            if required - p.keys() or set(p) - required - {"scope", "state", "resource"}:
                raise ValueError("Invalid parameters")
            if p["client_id"] != config.client_id or not config.validate_redirect(p["redirect_uri"]):
                raise ValueError("Client/redirect not allowed")
            if p["response_type"] != "code" or p["code_challenge_method"] != "S256" or not PKCE_CHALLENGE.fullmatch(p["code_challenge"]):
                raise ValueError("PKCE S256 required")
            if p.get("resource", config.resource) != config.resource:
                raise ValueError("Resource mismatch")
            requested = tuple(p.get("scope", " ".join(config.scopes)).split())
            if not requested or len(set(requested)) != len(requested) or not set(requested).issubset(config.scopes):
                raise ValueError("Invalid scope")
            state = p.get("state", "")
            if len(state) > 512 or any(ord(ch) < 32 or ord(ch) == 127 for ch in state):
                raise ValueError("Invalid state")
        except (ValueError, UnicodeDecodeError):
            # Do not redirect OAuth errors to an unvalidated redirect URI.
            return _oauth_error("invalid_request")
        try:
            rid, sid = store.create_request(client=config.client_id, redirect=p["redirect_uri"],
                                             state=state,challenge=p["code_challenge"],
                                             scopes=requested,workspaces=config.workspaces)
        except ValueError:
            return _oauth_error("temporarily_unavailable", 503)
        page = f"""<!doctype html><html><head><meta charset='utf-8'><title>Mac File Gateway authorization</title></head>
<body><h1>Approve Gemini on this Mac</h1>
<p>Requested permissions: <code>{html.escape(', '.join(requested))}</code></p>
<p>Requested workspaces: <code>{html.escape(', '.join(config.workspaces) or '(single workspace)')}</code></p>
<p>Request ID: <code>{html.escape(rid)}</code></p>
<p>Run on your Mac: <code>python -m gateway.gemini_adapter approve {html.escape(rid)} --config /path/to/gemini.json</code></p>
<p>Review the request on your Mac before approving. The web page alone cannot grant access.</p>
<form method='post' action='/oauth/continue'><input type='hidden' name='request_id' value='{html.escape(rid)}'><button>Continue after local approval</button></form>
</body></html>"""
        reply = HTMLResponse(page, headers={"Cache-Control":"no-store", "Referrer-Policy":"no-referrer", "X-Content-Type-Options":"nosniff", "Content-Security-Policy":"default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"})
        reply.set_cookie("mfg_gemini_consent", sid, max_age=600, httponly=True, secure=True, samesite="lax", path="/oauth")
        return reply

    async def continue_auth(request: Request):
        if request.headers.get("content-type", "").split(";", 1)[0].lower() != "application/x-www-form-urlencoded":
            return _oauth_error("invalid_request")
        try:
            data = bytearray()
            async for chunk in request.stream():
                if len(data) + len(chunk) > 1024:
                    raise ValueError
                data.extend(chunk)
            raw = data.decode("ascii")
            p = _unique_params(raw)
            if set(p) != {"request_id"}:
                raise ValueError
            code, redirect, state = store.issue_code(p["request_id"], request.cookies.get("mfg_gemini_consent", ""))
        except (ValueError, UnicodeDecodeError):
            return HTMLResponse("<p>Approval pending, expired or invalid. Please review the request locally.</p>", status_code=409,headers={"Cache-Control":"no-store"})
        reply = RedirectResponse(redirect + "?" + urlencode({"code":code, "state":state}), status_code=303)
        reply.delete_cookie("mfg_gemini_consent", path="/oauth")
        reply.headers["Cache-Control"] = "no-store"
        reply.headers["Referrer-Policy"] = "no-referrer"
        return reply

    async def oauth_form(request: Request):
        if request.headers.get("content-type", "").split(";", 1)[0].lower() != "application/x-www-form-urlencoded":
            raise ValueError("Expected form")
        data = bytearray()
        async for chunk in request.stream():
            if len(data) + len(chunk) > 8192:
                raise ValueError("Form too large")
            data.extend(chunk)
        return _unique_params(bytes(data).decode("ascii"))

    async def token(request: Request):
        try:
            p = await oauth_form(request)
        except (ValueError, UnicodeDecodeError):
            return _oauth_error("invalid_request")
        if not _client_credentials(request, p, config):
            return _oauth_error("invalid_client", 401)
        if p.get("resource", config.resource) != config.resource:
            return _oauth_error("invalid_target")
        grant = p.get("grant_type")
        if grant == "authorization_code":
            verifier = p.get("code_verifier", "")
            if (not PKCE_VERIFIER.fullmatch(verifier) or not p.get("code")
                or not config.validate_redirect(p.get("redirect_uri", ""))):
                return _oauth_error("invalid_grant")
            issued = store.exchange_code(code=p["code"],client=config.client_id,
                                         redirect=p["redirect_uri"],verifier=verifier)
        elif grant == "refresh_token":
            refresh = p.get("refresh_token", "")
            if not refresh or len(refresh) > 512:
                return _oauth_error("invalid_grant")
            issued = store.rotate_refresh(refresh=refresh, client=config.client_id)
        else:
            return _oauth_error("unsupported_grant_type")
        return _json(issued) if issued else _oauth_error("invalid_grant")

    async def revoke(request: Request):
        try:
            p = await oauth_form(request)
        except (ValueError, UnicodeDecodeError):
            return _oauth_error("invalid_request")
        if not _client_credentials(request, p, config):
            return _oauth_error("invalid_client", 401)
        if p.get("token"):
            store.revoke(p["token"],config.client_id)
        return Response(status_code=200, headers={"Cache-Control":"no-store"})

    return [
        Route("/.well-known/oauth-protected-resource", resource_metadata, methods=["GET"]),
        Route("/.well-known/oauth-protected-resource/mcp", resource_metadata, methods=["GET"]),
        Route("/.well-known/oauth-authorization-server", authorization_metadata, methods=["GET"]),
        Route("/oauth/authorize", authorize, methods=["GET"]),
        Route("/oauth/continue", continue_auth, methods=["POST"]),
        Route("/oauth/token", token, methods=["POST"]),
        Route("/oauth/revoke", revoke, methods=["POST"]),
    ]
