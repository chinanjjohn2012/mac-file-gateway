import asyncio
import json
from starlette.testclient import TestClient
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from gateway.multi_admission import StrictPostAdmission, media_type, parse_envelope, RejectPost, MAX_RAW_BODY


def make_client():
    arrivals = []
    async def route(request):
        body = await request.body()
        arrivals.append((body, request.headers.get('content-type')))
        return JSONResponse({'ok': True})
    return TestClient(StrictPostAdmission(Starlette(routes=[Route('/mcp', route, methods=['POST']),
                                                        Route('/create', route, methods=['POST'])]))), arrivals


def test_json_media_variants():
    client, calls = make_client()
    data = b'{"jsonrpc":"2.0","method":"ping","params":{}}'
    for header in ['application/json', 'Application/JSON', 'application/json; charset=UTF-8']:
        result = client.post('/mcp', content=data, headers={'content-type': header})
        assert result.status_code == 200
        assert calls[-1] == (data, 'application/json')
    assert len(calls) == 3
    for bad in ['application/json, text/plain', 'application/json; foo=bar',
                'text/plain', 'application/json; charset=latin-1',
                'application/json; charset=utf-8; charset=utf-8']:
        result = client.post('/mcp', content=data, headers={'content-type': bad})
        assert result.status_code == 415
    assert len(calls) == 3


def test_duplicate_headers_rejected():
    try:
        media_type([(b'content-type',b'application/json'), (b'Content-Type',b'application/json')])
    except RejectPost:
        pass
    else:
        raise AssertionError('duplicate Content-Type accepted')


def test_duplicate_json_keys_and_escaped_duplicates_never_dispatch():
    client, calls = make_client()
    cases = [
        b'{"workspace":"a","workspace":"b"}',
        b'{"workspace":"a","\\u0077orkspace":"b"}',
        b'{"workspace":"a","path":"x","path":"y"}',
        b'{"workspace":"a","dry_run":true,"dry_run":false}',
        b'{"jsonrpc":"2.0","method":"tools/call","params":{"arguments":{"workspace":"a","workspace":"b"}}}',
        b'{"jsonrpc":"2.0","method":"tools/call","params":{"arguments":{},"arguments":{}}}',
        b'[ {"jsonrpc":"2.0","method":"ping"} ]',
    ]
    for body in cases:
        res = client.post('/mcp', content=body, headers={'content-type':'application/json'})
        assert res.status_code == 400
    assert not calls


def test_complexity_budget_rejects():
    client, calls = make_client()
    huge = b'{"x":"' + b'a' * (4*1024*1024+1) + b'"}'
    assert client.post('/create', content=huge,headers={'content-type':'application/json'}).status_code == 413
    deeply_nested = ('{"value":'+ '['*40+'0'+']'*40+'}').encode()
    assert client.post('/create', content=deeply_nested,headers={'content-type':'application/json'}).status_code == 400
    many = b'{"values":[' + b','.join(b'0' for _ in range(10_010)) + b']}'
    assert client.post('/create',content=many,headers={'content-type':'application/json'}).status_code == 400
    assert not calls


def test_large_wire_body_accepted_if_decoded_content_bounded():
    client, calls = make_client()
    body = b'{"content":"' + b'\\u0061' * (1 << 20) + b'"}'
    assert len(body) < MAX_RAW_BODY
    assert client.post('/create', content=body, headers={'content-type':'application/json'}).status_code == 200
    assert calls[-1] == (body, 'application/json')


def test_above_raw_budget_and_invalid_utf8():
    client, calls = make_client()
    assert client.post('/create', content=b' '*(MAX_RAW_BODY+1),
                       headers={'content-type':'application/json'}).status_code == 413
    assert client.post('/create', content=b'{"x":"\xff"}',
                       headers={'content-type':'application/json'}).status_code == 400
    assert not calls
