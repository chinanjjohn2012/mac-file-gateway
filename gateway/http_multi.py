"""HTTP MCP and REST adapter for the Phase-1 Multi-Workspace service.

A single StrictPostAdmission wraps every POST, including SDK-owned paths.
Legacy create_app remains an independent, unchanged entrypoint.
"""
from __future__ import annotations

from typing import Any

from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.types import ASGIApp

from .core import GatewayError
from .http import Boundary, _params, _int, _bool, _json_params, _error, MAX_GIT_BODY
from .multi_admission import StrictPostAdmission, MAX_RAW_BODY
from .multi_fields import validate_tool_arguments
from .workspaces import WorkspaceService

_GET_ROUTES: dict[str, tuple[str, set[str], set[str]]] = {
    '/list': ('list_files', {'workspace', 'path', 'offset', 'limit'}, {'workspace'}),
    '/read': ('read_file', {'workspace', 'path', 'start_line', 'max_lines'}, {'workspace', 'path'}),
    '/search': ('search_files', {'workspace', 'q', 'path', 'file_glob', 'max_results', 'case_sensitive'}, {'workspace', 'q'}),
}
_POST_ROUTES: dict[str, tuple[str, set[str], set[str]]] = {
    '/git/run': ('run_git',
                 {'command', 'cwd', 'options', 'paths', 'timeout_seconds', 'dry_run'},
                 {'command'}),
    '/mkdir': ('create_directory', {'path', 'parents', 'exist_ok', 'dry_run'}, {'path'}),
    '/rmdir': ('delete_directory', {'path', 'dry_run'}, {'path'}),
    '/create': ('create_file', {'path', 'content', 'dry_run'}, {'path', 'content'}),
    '/write': ('write_file', {'path', 'content', 'expected_sha256', 'dry_run'}, {'path', 'content', 'expected_sha256'}),
    '/replace': ('replace_text', {'path', 'old_text', 'new_text', 'expected_sha256', 'expected_count', 'dry_run'},
                 {'path', 'old_text', 'new_text', 'expected_sha256'}),
    '/delete': ('delete_file', {'path', 'expected_sha256', 'dry_run'}, {'path', 'expected_sha256'}),
    '/remove': ('remove_file', {'path', 'expected_sha256', 'dry_run'}, {'path', 'expected_sha256'}),
    '/unlink': ('unlink', {'path', 'expected_sha256', 'dry_run'}, {'path', 'expected_sha256'}),
    '/rename': ('rename', {'source', 'destination', 'expected_sha256', 'dry_run'},
                {'source', 'destination', 'expected_sha256'}),
    '/move': ('move', {'source', 'destination', 'expected_sha256', 'dry_run'},
              {'source', 'destination', 'expected_sha256'}),
}


def _get_arguments(route: str, p: dict[str, str]) -> dict[str, Any]:
    if route == '/list':
        return {'workspace': p['workspace'], 'path': p.get('path', '.'),
                'offset': _int(p, 'offset', 0), 'limit': _int(p, 'limit', 100)}
    if route == '/read':
        return {'workspace': p['workspace'], 'path': p['path'],
                'start_line': _int(p, 'start_line', 1), 'max_lines': _int(p, 'max_lines', 200)}
    return {'workspace': p['workspace'], 'query': p['q'], 'path': p.get('path', '.'),
            'file_glob': p.get('file_glob', '*'), 'max_results': _int(p, 'max_results', 50),
            'case_sensitive': _bool(p, 'case_sensitive', False)}


def create_multi_app(service: WorkspaceService, *, enable_mcp: bool = True,
                     port: int = 8765, token: str | None = None) -> ASGIApp:
    async def read_endpoint(request: Request) -> JSONResponse:
        route = request.url.path
        try:
            if route in {'/health', '/info', '/workspaces'}:
                _params(request, set())
                if route == '/health':
                    value = {'status': 'ok', 'mode': 'multi',
                             'workspace_count': len(service.settings.workspaces),
                             'read_only': not service.any_write, 'mcp_enabled': enable_mcp}
                elif route == '/info':
                    value = service.info()
                else:
                    value = service.list_workspaces()
                return JSONResponse(value)
            operation, allowed, required = _GET_ROUTES[route]
            p = _params(request, allowed, required)
            args = _get_arguments(route, p)
            validate_tool_arguments(operation, args, multi=True)
            workspace = args.pop('workspace')
            # REST/SDK file signatures converge on one explicit positional map.
            order = {
                'list_files': ('path', 'offset', 'limit'),
                'read_file': ('path', 'start_line', 'max_lines'),
                'search_files': ('query', 'path', 'file_glob', 'max_results', 'case_sensitive'),
            }[operation]
            result = await run_in_threadpool(service.invoke, workspace, operation,
                                             *(args[field] for field in order))
            return JSONResponse(result)
        except GatewayError as exc:
            if exc.code == 'service_closing':
                return JSONResponse({'error': exc.code}, status_code=503)
            if exc.code in {'workspace_not_found', 'workspace_required'}:
                return JSONResponse({'error': exc.code}, status_code=404 if exc.code == 'workspace_not_found' else 400)
            return _error(exc)

    async def write_endpoint(request: Request) -> JSONResponse:
        try:
            operation, fields, required = _POST_ROUTES[request.url.path]
            if operation == 'run_git' and len(await request.body()) > MAX_GIT_BODY:
                raise GatewayError('too_large', 'Git request body exceeds its fixed limit.')
            args = await _json_params(request, fields | {'workspace'}, required | {'workspace'})
            validate_tool_arguments(operation, args, multi=True)
            workspace = args.pop('workspace')
            if operation == 'run_git':
                # Each actual synchronous Git Worker repeats global/Workspace
                # authorization and retains root FD until terminal cleanup.
                command = args.pop('command')
                result = await run_in_threadpool(service.invoke_git, workspace, command, **args)
            else:
                # Do not route Git through the File-only service.invoke().
                result = await run_in_threadpool(service.invoke, workspace, operation, **args)
            return JSONResponse(result)
        except GatewayError as exc:
            if exc.code == 'service_closing':
                return JSONResponse({'error': exc.code}, status_code=503)
            if exc.code in {'workspace_not_found', 'workspace_required'}:
                return JSONResponse({'error': exc.code}, status_code=404 if exc.code == 'workspace_not_found' else 400)
            return _error(exc)

    routes = [Route(path, read_endpoint, methods=['GET']) for path in
              ('/health', '/info', '/workspaces', '/list', '/read', '/search')]
    routes.extend(Route(path, write_endpoint, methods=['POST']) for path in _POST_ROUTES)
    if enable_mcp:
        from .mcp_multi import build_multi_mcp
        from .mcp_transport import build_streamable_http_app
        app = build_streamable_http_app(
            build_multi_mcp(service, port=port), port=port, max_request_body_size=MAX_RAW_BODY
        )
        app.router.routes.extend(routes)
    else:
        app = Starlette(routes=routes)
    built = Boundary(StrictPostAdmission(app), port=port, token=token, max_body=MAX_RAW_BODY)
    if service.any_git:
        service._git_adapter_exposed = True
    return built


__all__ = ['create_multi_app']
