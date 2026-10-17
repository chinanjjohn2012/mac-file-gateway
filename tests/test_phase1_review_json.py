"""F5/F7: first JSON decoder rejects unencodable strings and non-finite floats."""
import json

import pytest
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from gateway.http_multi import create_multi_app
from gateway.multi_admission import RejectPost, StrictPostAdmission, parse_envelope
from gateway.workspaces import ActiveRuntimeInventory, WorkspaceService
from gateway.workspaces_config import parse_workspace_config


INVALID = [
    br'{"\ud800":1}',
    br'{"\udfff":1}',
    br'{"value":"\ud800"}',
    br'{"value":"\udc00"}',
    br'{"items":[{"x":"ok\ud800bad"}]}',
    br'{"jsonrpc":"2.0","id":2,"method":"\ud800"}',
    br'{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"workspace":"a","path":"\udc00"}}}',
    br'{"jsonrpc":"2.0","id":1e400,"method":"ping"}',
    br'{"jsonrpc":"2.0","id":-1e400,"method":"ping"}',
    br'{"items":[1e400]}',
    br'{"items":[-1e400]}',
    br'{"items":[NaN]}',
    br'{"items":[Infinity]}',
    br'{"items":[-Infinity]}',
]


@pytest.mark.parametrize('raw', INVALID)
def test_invalid_decoded_value_is_a_controlled_rejection(raw):
    with pytest.raises(RejectPost) as exc:
        parse_envelope(raw, mcp=False)
    assert exc.value.status == 400
    assert exc.value.code == 'invalid_json'


@pytest.mark.parametrize('route', ['/create', '/mcp'])
def test_invalid_envelopes_never_reach_downstream_app(route):
    arrivals = []
    async def endpoint(request):
        arrivals.append(await request.body())
        return JSONResponse({'ok': True})
    app = StrictPostAdmission(Starlette(routes=[Route(route, endpoint, methods=['POST'])]))
    with TestClient(app, raise_server_exceptions=False) as client:
        for raw in INVALID:
            response = client.post(route, content=raw, headers={'Content-Type': 'application/json'})
            assert response.status_code == 400, (raw, response.text)
            assert response.json() == {'error': 'invalid_json'}
    assert not arrivals


@pytest.fixture
def sdk_client(tmp_path, monkeypatch):
    paths = {name: tmp_path / name for name in ('a', 'config', 'runtime')}
    for path in paths.values():
        path.mkdir()
    settings = parse_workspace_config({'schema_version': 1, 'workspaces': {
        'a': {'root': str(paths['a']), 'write': {'enabled': True, 'paths': ['.']}},
    }})
    service = WorkspaceService(settings, config_dir=paths['config'],
                               inventory=ActiveRuntimeInventory(paths=(paths['runtime'],)))
    calls = []
    invoke = service.invoke
    def traced(*args, **kwargs):
        calls.append(args)
        return invoke(*args, **kwargs)
    monkeypatch.setattr(service, 'invoke', traced)
    try:
        with TestClient(create_multi_app(service), base_url='http://127.0.0.1:8765',
                        raise_server_exceptions=False) as client:
            yield client, paths['a'], calls
    finally:
        service.close()


@pytest.mark.parametrize('route', ['/create', '/mcp'])
def test_real_rest_and_sdk_reject_invalid_decoded_values(sdk_client, route):
    client, root, calls = sdk_client
    for raw in INVALID:
        response = client.post(route, content=raw, headers={
            'Content-Type': 'application/json', 'Accept': 'application/json, text/event-stream'})
        assert response.status_code == 400, (raw, response.text)
        assert response.json() == {'error': 'invalid_json'}
    assert not calls
    assert list(root.iterdir()) == []


def test_valid_unicode_pair_and_unicode_key_still_decode():
    result = parse_envelope(br'{"\ud83d\ude00":"\ud83d\ude00","n":1e300}', mcp=False)
    assert result == {'\U0001f600': '\U0001f600', 'n': 1e300}


def test_valid_surrogate_pair_can_be_created_through_rest(sdk_client):
    client, root, calls = sdk_client
    raw = br'{"workspace":"a","path":"unicode.txt","content":"\ud83d\ude00\n","dry_run":false}'
    response = client.post('/create', content=raw, headers={'Content-Type': 'application/json'})
    assert response.status_code == 200
    assert response.json()['applied'] is True
    assert (root / 'unicode.txt').read_text() == '\U0001f600\n'
    assert len(calls) == 1


@pytest.mark.parametrize('identifier', [1, -2, 'request-3'])
def test_valid_mcp_request_id_keeps_response_semantics(sdk_client, identifier):
    client, _, _ = sdk_client
    headers = {'Accept': 'application/json, text/event-stream'}
    response = client.post('/mcp', headers=headers, json={
        'jsonrpc': '2.0', 'id': identifier, 'method': 'ping'})
    assert response.status_code == 200
    payload = response.json()
    assert payload['id'] == identifier
    assert 'result' in payload
