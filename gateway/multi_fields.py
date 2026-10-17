"""Strict MCP/REST operation envelopes, validated before SDK argument coercion.

This is an adapter contract, not an authorization source. WorkspaceService and
Gateway always enforce scopes again at the actual filesystem operation.
"""
from __future__ import annotations

from typing import Any
from .core import GatewayError

# required arguments, optional arguments, and strict runtime types
# (not Pydantic coercions). Numeric bounds also enforced by Gateway.
_SPECS: dict[str, tuple[dict[str, type], dict[str, type]]] = {
    'gateway_info': ({}, {}),
    'list_workspaces': ({}, {}),
    'list_files': ({}, {'path': str, 'offset': int, 'limit': int}),
    'read_file': ({'path': str}, {'start_line': int, 'max_lines': int}),
    'search_files': ({'query': str}, {'path': str, 'file_glob': str,
                                    'max_results': int, 'case_sensitive': bool}),
    'create_directory': ({'path': str}, {'parents': bool, 'exist_ok': bool, 'dry_run': bool}),
    'delete_directory': ({'path': str}, {'dry_run': bool}),
    'create_file': ({'path': str, 'content': str}, {'dry_run': bool}),
    'write_file': ({'path': str, 'content': str, 'expected_sha256': str}, {'dry_run': bool}),
    'replace_text': ({'path': str, 'old_text': str, 'new_text': str,
                     'expected_sha256': str}, {'expected_count': int, 'dry_run': bool}),
    'delete_file': ({'path': str, 'expected_sha256': str}, {'dry_run': bool}),
    'remove_file': ({'path': str, 'expected_sha256': str}, {'dry_run': bool}),
    'unlink': ({'path': str, 'expected_sha256': str}, {'dry_run': bool}),
    'move': ({'source': str, 'destination': str, 'expected_sha256': str}, {'dry_run': bool}),
    'rename': ({'source': str, 'destination': str, 'expected_sha256': str}, {'dry_run': bool}),
    'run_command': ({'cwd': str, 'argv': list}, {'timeout_seconds': int, 'dry_run': bool}),
    'local_skill_info': ({}, {}),
    'begin_local_skill': ({'skill': str, 'request': str}, {}),
    'read_skill_file': ({'skill_run_id': str, 'skill': str, 'path': str}, {}),
    'run_skill_script': ({'skill_run_id': str, 'skill': str, 'script': str},
                         {'argv': list, 'timeout_seconds': int}),
}
_GLOBAL = {'gateway_info', 'list_workspaces'}
_PHASE2 = {'run_command', 'local_skill_info', 'begin_local_skill',
           'read_skill_file', 'run_skill_script'}


def validate_tool_arguments(name: str, arguments: Any, *, multi: bool) -> dict[str, Any]:
    if type(name) is not str or name not in _SPECS or (multi and name in _PHASE2):
        raise GatewayError('invalid_argument', 'This tool is not supported in this mode.')
    if type(arguments) is not dict:
        raise GatewayError('invalid_argument', 'Tool arguments must be an object.')
    required, optional = _SPECS[name]
    wanted = dict(required)
    wanted.update(optional)
    if multi and name not in _GLOBAL:
        wanted['workspace'] = str
        required = {**required, 'workspace': str}
    if set(arguments) - set(wanted) or set(required) - set(arguments):
        missing = set(required) - set(arguments)
        if multi and 'workspace' in missing:
            raise GatewayError('workspace_required', 'An explicit Workspace ID is required.')
        raise GatewayError('invalid_argument', 'Unknown or missing tool argument.')
    if any(type(arguments[k]) is not expected for k, expected in wanted.items() if k in arguments):
        raise GatewayError('invalid_argument', 'Incorrect tool argument type.')
    if 'workspace' in arguments and (not arguments['workspace'] or len(arguments['workspace']) > 32):
        raise GatewayError('workspace_not_found', 'Workspace is not available.')
    if 'argv' in arguments and (len(arguments['argv']) > 64 or
                                any(type(x) is not str for x in arguments['argv'])):
        raise GatewayError('invalid_argument', 'Invalid argv argument.')
    return arguments


__all__ = ['validate_tool_arguments']
