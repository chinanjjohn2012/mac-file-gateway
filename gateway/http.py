"""Small local HTTP API and shared HTTP security boundary."""
from __future__ import annotations

import secrets
import json
from typing import Any

from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .core import Gateway, GatewayError

MAX_BODY = 65_536
MAX_WRITE_BODY = 7 * 1024 * 1024


class Boundary:
    """Loopback Host/Origin policy, optional token, and bounded request bodies.

This is not a public deployment authentication system. External access must
use an authenticated private tunnel; there is deliberately no CORS support.
"""
    def __init__(self, app: ASGIApp, *, port: int, token: str | None = None, max_body: int = MAX_BODY):
        self.app = app
        self.max_body = max_body
        self.hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
        self.origins = {f"http://{host}" for host in self.hosts}
        if token and (len(token) < 32 or not token.isascii()):
            raise ValueError("GATEWAY_TOKEN must be an ASCII token of at least 32 characters.")
        self.token = token

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def secure_send(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                for key, value in [(b"cache-control", b"no-store"), (b"x-content-type-options", b"nosniff"), (b"referrer-policy", b"no-referrer")]:
                    headers = [(k, v) for k, v in headers if k.lower() != key]
                    headers.append((key, value))
                message = {**message, "headers": headers}
            await send(message)

        async def reject(status: int, code: str) -> None:
            await JSONResponse({"error": code}, status_code=status)(scope, receive, secure_send)

        headers: dict[bytes, list[bytes]] = {}
        for key, value in scope.get("headers", []):
            headers.setdefault(key.lower(), []).append(value)
        if len(headers.get(b"host", [])) != 1 or len(headers.get(b"origin", [])) > 1:
            await reject(400, "invalid_headers")
            return
        host = headers[b"host"][0].decode("latin-1").lower()
        if host not in self.hosts:
            await reject(421, "host_not_allowed")
            return
        origin = headers.get(b"origin", [b""])[0].decode("latin-1")
        if origin and origin not in self.origins:
            await reject(403, "origin_not_allowed")
            return
        fetch_site = headers.get(b"sec-fetch-site", [b""])[0].decode("latin-1")
        if fetch_site and fetch_site not in {"none", "same-origin"}:
            await reject(403, "cross_site_request_not_allowed")
            return
        if self.token:
            values = headers.get(b"authorization", [])
            expected = ("Bearer " + self.token).encode("ascii")
            if len(values) != 1 or not secrets.compare_digest(values[0], expected):
                await reject(401, "unauthorized")
                return
        if len(scope.get("query_string", b"")) > 4_096:
            await reject(414, "query_too_long")
            return
        lengths = headers.get(b"content-length", [])
        if len(lengths) > 1:
            await reject(400, "invalid_content_length")
            return
        if lengths:
            try:
                length = int(lengths[0])
                if length < 0:
                    raise ValueError
            except ValueError:
                await reject(400, "invalid_content_length")
                return
            if length > self.max_body:
                await reject(413, "request_body_too_large")
                return
        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            if message["type"] != "http.request":
                await reject(400, "invalid_request")
                return
            chunk = message.get("body", b"")
            if len(body) + len(chunk) > self.max_body:
                await reject(413, "request_body_too_large")
                return
            body.extend(chunk)
            if not message.get("more_body", False):
                break
        consumed = False

        async def replay() -> Message:
            nonlocal consumed
            if not consumed:
                consumed = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()

        await self.app(scope, replay, secure_send)


def _params(request: Request, allowed: set[str], required: set[str] | None = None) -> dict[str, str]:
    pairs = list(request.query_params.multi_items())
    params = dict(pairs)
    if len(params) != len(pairs) or set(params) - allowed:
        raise GatewayError("invalid_argument", "Unknown or repeated query parameter.")
    if (required or set()) - set(params):
        raise GatewayError("invalid_argument", "A required query parameter is missing.")
    return params


def _int(params: dict[str, str], name: str, default: int) -> int:
    try:
        return int(params[name]) if name in params else default
    except ValueError:
        raise GatewayError("invalid_argument", f"{name} must be an integer.") from None


def _bool(params: dict[str, str], name: str, default: bool) -> bool:
    if name not in params:
        return default
    if params[name].lower() not in {"true", "false"}:
        raise GatewayError("invalid_argument", f"{name} must be true or false.")
    return params[name].lower() == "true"


def _error(exc: GatewayError) -> JSONResponse:
    status = {"unavailable": 404, "parent_missing": 404, "blocked_path": 403, "blocked_type": 403,
              "too_large": 413, "file_changed": 409, "not_text": 415,
              "write_disabled": 403, "write_scope": 403, "sensitive_content": 403, "write_protected": 403,
              "conflict": 409, "already_exists": 409, "match_count": 409,
              "busy": 409, "backup_full": 507, "backup_unavailable": 503,
              "cross_device": 409, "move_unavailable": 501,
              "exec_disabled": 403, "exec_scope": 403, "command_not_allowed": 403,
              "runner_unavailable": 503, "exec_failed": 500,
              "write_failed": 500, "json_required": 415}.get(exc.code, 400)
    payload = {"error": exc.code, "message": str(exc)}
    if exc.details is not None:
        payload["details"] = exc.details
    return JSONResponse(payload, status_code=status)


async def _json_params(request: Request, allowed: set[str], required: set[str]) -> dict[str, Any]:
    _params(request, set())
    if request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
        raise GatewayError("json_required", "Write endpoints require application/json.")

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result = dict(pairs)
        if len(result) != len(pairs):
            raise ValueError("duplicate key")
        return result

    def reject_constant(value: str) -> None:
        raise ValueError("non-standard JSON constant")

    try:
        data = json.loads((await request.body()).decode("utf-8"),
                          object_pairs_hook=unique_object, parse_constant=reject_constant)
    except (ValueError, UnicodeError, RecursionError):
        raise GatewayError("invalid_argument", "A valid UTF-8 JSON object with unique keys is required.") from None
    if not isinstance(data, dict) or set(data) - allowed or required - set(data):
        raise GatewayError("invalid_argument", "Unknown or missing JSON arguments.")
    return data


def create_app(gateway: Gateway, *, enable_mcp: bool = True, port: int = 8765, token: str | None = None, local_skill_bridge: Any | None = None) -> ASGIApp:
    async def endpoint(request: Request) -> JSONResponse:
        try:
            operation = request.url.path
            if operation == "/health":
                _params(request, set())
                result: dict[str, Any] = {"status": "ok", "read_only": not gateway.allow_write, "mcp_enabled": enable_mcp}
            elif operation == "/info":
                _params(request, set())
                result = gateway.info()
            elif operation == "/list":
                p = _params(request, {"path", "offset", "limit"})
                result = await run_in_threadpool(gateway.list_files, p.get("path", "."), _int(p, "offset", 0), _int(p, "limit", 100))
            elif operation == "/read":
                p = _params(request, {"path", "start_line", "max_lines"}, {"path"})
                result = await run_in_threadpool(gateway.read_file, p["path"], _int(p, "start_line", 1), _int(p, "max_lines", 200))
            else:
                p = _params(request, {"q", "path", "file_glob", "max_results", "case_sensitive"}, {"q"})
                result = await run_in_threadpool(gateway.search_files, p["q"], p.get("path", "."), p.get("file_glob", "*"), _int(p, "max_results", 50), _bool(p, "case_sensitive", False))
            return JSONResponse(result)
        except GatewayError as exc:
            return _error(exc)

    async def write_endpoint(request: Request) -> JSONResponse:
        try:
            route = request.url.path
            if route == "/run":
                if not gateway.allow_exec:
                    raise GatewayError("exec_disabled", "Command execution is disabled. Restart locally with --allow-exec.")
                args = await _json_params(request, {"cwd", "argv", "timeout_seconds", "dry_run"}, {"cwd", "argv"})
                result = await run_in_threadpool(gateway.run_command, **args)
                return JSONResponse(result)
            if not gateway.allow_write:
                raise GatewayError("write_disabled", "Writes are disabled. Restart locally with --allow-write.")
            if route == "/mkdir":
                args = await _json_params(request, {"path", "parents", "exist_ok", "dry_run"}, {"path"})
                result = await run_in_threadpool(gateway.create_directory, **args)
            elif route == "/create":
                args = await _json_params(request, {"path", "content", "dry_run"}, {"path", "content"})
                result = await run_in_threadpool(gateway.create_file, **args)
            elif route == "/write":
                args = await _json_params(request, {"path", "content", "expected_sha256", "dry_run"}, {"path", "content", "expected_sha256"})
                result = await run_in_threadpool(gateway.write_file, **args)
            elif route == "/replace":
                args = await _json_params(request, {"path", "old_text", "new_text", "expected_sha256", "expected_count", "dry_run"}, {"path", "old_text", "new_text", "expected_sha256"})
                result = await run_in_threadpool(gateway.replace_text, **args)
            elif route in {"/delete", "/remove", "/unlink"}:
                args = await _json_params(request, {"path", "expected_sha256", "dry_run"}, {"path", "expected_sha256"})
                function = {"/delete": gateway.delete_file, "/remove": gateway.remove_file, "/unlink": gateway.unlink}[route]
                result = await run_in_threadpool(function, **args)
            else:
                args = await _json_params(request, {"source", "destination", "expected_sha256", "dry_run"}, {"source", "destination", "expected_sha256"})
                function = gateway.rename if route == "/rename" else gateway.move
                result = await run_in_threadpool(function, **args)
            return JSONResponse(result)
        except GatewayError as exc:
            return _error(exc)

    routes = [Route(path, endpoint, methods=["GET"]) for path in ("/health", "/info", "/list", "/read", "/search")]
    routes += [Route(path, write_endpoint, methods=["POST"]) for path in ("/create", "/write", "/replace", "/mkdir", "/delete", "/remove", "/unlink", "/rename", "/move", "/run")]
    if enable_mcp:
        from .mcp_adapter import build_mcp
        app = build_mcp(gateway, port=port, local_skill_bridge=local_skill_bridge).streamable_http_app()
        app.router.routes.extend(routes)
    else:
        app = Starlette(routes=routes)
    return Boundary(app, port=port, token=token, max_body=MAX_WRITE_BODY if (gateway.allow_write or gateway.allow_exec) else MAX_BODY)
