"""L0: every multi-mode HTTP POST is admitted or rejected BEFORE SDK/REST.

The validated request body bytes are replayed UNMODIFIED. Only the already
validated Content-Type header is canonicalized for the SDK.
"""
from __future__ import annotations

import json
from typing import Any

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send, Message

MAX_RAW_BODY = 8 * 1024 * 1024
MAX_DECODED_TEXT_BYTES = 4 * 1024 * 1024
MAX_JSON_NODES = 10_000
MAX_JSON_DEPTH = 32
MAX_OBJECT_MEMBERS = 256


class RejectPost(ValueError):
    def __init__(self, code: str, status: int = 400):
        self.code, self.status = code, status


def media_type(headers: list[tuple[bytes, bytes]]) -> None:
    types = [value for key, value in headers if key.lower() == b'content-type']
    if len(types) != 1:
        raise RejectPost('invalid_content_type', 400 if len(types) > 1 else 415)
    try:
        raw = types[0].decode('ascii')
    except UnicodeError:
        raise RejectPost('invalid_content_type', 415) from None
    segments = raw.split(';')
    if segments[0].strip().lower() != 'application/json' or len(segments) > 2:
        raise RejectPost('invalid_content_type', 415)
    if len(segments) == 2:
        option = segments[1].strip().split('=', 1)
        if len(option) != 2 or option[0].strip().lower() != 'charset' or option[1].strip().lower() != 'utf-8':
            raise RejectPost('invalid_content_type', 415)


def parse_envelope(raw: bytes, *, mcp: bool) -> dict[str, Any]:
    def no_duplicate(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        if len(pairs) > MAX_OBJECT_MEMBERS:
            raise RejectPost('json_too_complex')
        obj: dict[str, Any] = {}
        for key, value in pairs:
            if key in obj:
                raise RejectPost('json_duplicate_key')
            obj[key] = value
        return obj
    try:
        data = json.loads(raw.decode('utf-8'), object_pairs_hook=no_duplicate,
                          parse_constant=lambda _: (_ for _ in ()).throw(RejectPost('invalid_json')))
    except RejectPost:
        raise
    except (ValueError, UnicodeError, RecursionError):
        raise RejectPost('invalid_json') from None
    if type(data) is not dict:
        raise RejectPost('invalid_json')
    count, text_bytes = 0, 0
    stack: list[tuple[Any, int]] = [(data, 1)]
    while stack:
        value, depth = stack.pop()
        count += 1
        if depth > MAX_JSON_DEPTH:
            raise RejectPost('json_too_deep')
        if count > MAX_JSON_NODES:
            raise RejectPost('json_too_complex')
        if type(value) is dict:
            if len(value) > MAX_OBJECT_MEMBERS:
                raise RejectPost('json_too_complex')
            for key, child in value.items():
                text_bytes += len(key.encode('utf-8'))
                stack.append((child, depth + 1))
        elif type(value) is list:
            stack.extend((child, depth + 1) for child in value)
        elif type(value) is str:
            text_bytes += len(value.encode('utf-8'))
        if text_bytes > MAX_DECODED_TEXT_BYTES:
            raise RejectPost('decoded_content_too_large', 413)
    if mcp:
        if (type(data.get('jsonrpc')) is not str or data['jsonrpc'] != '2.0' or
                type(data.get('method')) is not str or
                ('params' in data and type(data['params']) is not dict)):
            raise RejectPost('invalid_jsonrpc')
    return data


class StrictPostAdmission:
    """Transport-neutral ASGI guard around *all* multi-mode POST routes."""
    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope['type'] != 'http' or scope.get('method', '').upper() != 'POST':
            await self.app(scope, receive, send)
            return

        async def reject(error: RejectPost) -> None:
            await JSONResponse({'error': error.code}, status_code=error.status)(scope, receive, send)

        try:
            media_type(scope.get('headers', []))
        except RejectPost as error:
            await reject(error)
            return

        body = bytearray()
        while True:
            msg = await receive()
            if msg['type'] != 'http.request':
                await reject(RejectPost('invalid_request'))
                return
            chunk = msg.get('body', b'')
            if len(body) + len(chunk) > MAX_RAW_BODY:
                await reject(RejectPost('request_body_too_large', 413))
                return
            body.extend(chunk)
            if not msg.get('more_body', False):
                break
        raw = bytes(body)
        try:
            parse_envelope(raw, mcp=scope.get('path', '').startswith('/mcp'))
        except RejectPost as error:
            await reject(error)
            return
        new_scope = dict(scope)
        new_scope['headers'] = [(key, value) if key.lower() != b'content-type' else (key, b'application/json')
                                for key, value in scope.get('headers', [])]
        sent = False

        async def replay() -> Message:
            nonlocal sent
            if not sent:
                sent = True
                return {'type': 'http.request', 'body': raw, 'more_body': False}
            return await receive()
        await self.app(new_scope, replay, send)


__all__ = ['StrictPostAdmission', 'parse_envelope', 'media_type', 'MAX_RAW_BODY']
