"""F4: an edit must not declassify bytes originating in a hidden line."""
import hashlib
import json

import pytest
from starlette.testclient import TestClient

from gateway.http_multi import create_multi_app
from gateway.workspaces import ActiveRuntimeInventory, WorkspaceService
from gateway.workspaces_config import parse_workspace_config
from gateway.visibility import SensitiveContentPolicy


@pytest.fixture
def surface(tmp_path):
    paths = {name: tmp_path / name for name in ('a', 'b', 'config', 'runtime')}
    for path in paths.values():
        path.mkdir()
    settings = parse_workspace_config({'schema_version': 1, 'workspaces': {
        'a': {'root': str(paths['a']), 'write': {'enabled': True, 'paths': ['.']}},
        'b': {'root': str(paths['b'])},
    }})
    service = WorkspaceService(settings, config_dir=paths['config'],
                               inventory=ActiveRuntimeInventory(paths=(paths['runtime'],)))
    try:
        with TestClient(create_multi_app(service), base_url='http://127.0.0.1:8765') as client:
            headers = {'Accept': 'application/json, text/event-stream'}
            init = client.post('/mcp', headers=headers, json={
                'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {
                    'protocolVersion': '2025-11-25', 'capabilities': {},
                    'clientInfo': {'name': 'f4-regression', 'version': '1'},
                }})
            assert init.status_code == 200
            yield client, paths, service
    finally:
        service.close()


def replace(client, transport, **args):
    if transport == 'rest':
        response = client.post('/replace', json={'workspace': 'a', 'path': 'sample.py', **args})
        return response.status_code == 403, response.json()
    response = client.post('/mcp', headers={'Accept': 'application/json, text/event-stream'}, json={
        'jsonrpc': '2.0', 'id': 2, 'method': 'tools/call', 'params': {
            'name': 'replace_text', 'arguments': {'workspace': 'a', 'path': 'sample.py', **args},
        }})
    assert response.status_code == 200
    value = response.json()['result']
    return value.get('isError') is True, value


@pytest.mark.parametrize('transport', ['rest', 'mcp'])
@pytest.mark.parametrize('dry_run', [True, False])
@pytest.mark.parametrize('newline', ['\n', '\r\n'])
@pytest.mark.parametrize('bom', ['', '\ufeff'])
@pytest.mark.parametrize('kind', ['credential', 'protected_path'])
@pytest.mark.parametrize('secret', ['alpha', 'beta'])
def test_visible_newline_removal_cannot_expose_hidden_source(surface, transport, dry_run, newline, bom, kind, secret):
    client, paths, service = surface
    hidden = f'password={secret}' if kind == 'credential' else str(paths['b'] / f'{secret}.py')
    source = (bom + 'x' + newline + hidden + newline).encode('utf-8')
    target = paths['a'] / 'sample.py'
    target.write_bytes(source)
    read = client.get('/read', params={'workspace': 'a', 'path': 'sample.py'}).json()
    assert hidden not in read['content'] and read['redacted_lines'] == 1
    rejected, value = replace(client, transport, old_text='x' + newline, new_text='x',
                              expected_sha256=read['file_sha256'], dry_run=dry_run)
    assert rejected, value
    # Both text and structuredContent are inspected by serializing the whole result.
    assert secret not in json.dumps(value)
    assert hidden not in json.dumps(value)
    assert target.read_bytes() == source
    assert not list((paths['a'] / '.gateway-backups').glob('*.bak'))


@pytest.mark.parametrize('transport', ['rest', 'mcp'])
@pytest.mark.parametrize('newline', ['\n', '\r\n'])
@pytest.mark.parametrize('bom', ['', '\ufeff'])
def test_safe_neighbor_edit_preserves_hidden_bytes_and_raw_hash(surface, transport, newline, bom):
    client, paths, service = surface
    source = (bom + 'x' + newline + 'password=alpha' + newline + 'tail' + newline).encode()
    target = paths['a'] / 'sample.py'
    target.write_bytes(source)
    args = dict(old_text='x' + newline, new_text='xy' + newline,
                expected_sha256=hashlib.sha256(source).hexdigest())
    rejected, preview = replace(client, transport, **args, dry_run=True)
    assert not rejected
    assert 'alpha' not in json.dumps(preview)
    assert target.read_bytes() == source
    rejected, applied = replace(client, transport, **args, dry_run=False)
    assert not rejected
    assert 'alpha' not in json.dumps(applied)
    expected = (bom + 'xy' + newline + 'password=alpha' + newline + 'tail' + newline).encode()
    assert target.read_bytes() == expected
    read = client.get('/read', params={'workspace': 'a', 'path': 'sample.py'}).json()
    assert read['file_sha256'] == hashlib.sha256(expected).hexdigest()
    assert 'alpha' not in read['content']


def test_provenance_does_not_accept_equal_hidden_counts_at_other_offsets():
    policy = SensitiveContentPolicy()
    source = 'x\npassword=alpha\ntail\n'
    # A replacement must not be allowed to borrow another hidden line's identity.
    spans = [(0, 2)]
    updated = 'password=alpha\nxpassword=alpha\ntail\n'
    assert not policy.preserves_hidden_lines(source, updated, spans, 'password=alpha\nx')


def test_provenance_accepts_removing_whole_visible_prefix():
    policy = SensitiveContentPolicy()
    source = 'x\npassword=alpha\ntail\n'
    assert policy.preserves_hidden_lines(source, 'password=alpha\ntail\n', [(0, 2)], '')
