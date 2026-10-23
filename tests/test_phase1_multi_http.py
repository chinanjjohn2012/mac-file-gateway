"""Real REST transport with one multi WorkspaceService, not stubbed file IO."""
import json
from pathlib import Path

import pytest
from starlette.testclient import TestClient
from gateway.workspaces_config import parse_workspace_config
from gateway.workspaces import WorkspaceService, ActiveRuntimeInventory
from gateway.http_multi import create_multi_app


@pytest.fixture
def multi_service(tmp_path):
    project = tmp_path / 'projects'
    project.mkdir()
    a, b = project / 'a', project / 'b'
    a.mkdir()
    b.mkdir()
    (a / 'hello.py').write_text('print(1)\n')
    (b / 'hello.py').write_text('print(2)\n')
    config = tmp_path / 'private'
    config.mkdir(mode=0o700)
    config.chmod(0o700)
    runtime = tmp_path / 'trusted-runtime'
    runtime.mkdir()
    settings = parse_workspace_config({
        'schema_version': 1,
        'workspaces': {
            'a': {'root': str(a), 'write': {'enabled': True, 'paths': ['.']}},
            'b': {'root': str(b), 'write': {'enabled': False}},
        },
    })
    service = WorkspaceService(settings, config_dir=config, inventory=ActiveRuntimeInventory(paths=(runtime,)))
    try:
        yield service, a, b
    finally:
        service.close()


def test_multi_rest_routing_and_permissions(multi_service):
    service, a, b = multi_service
    with TestClient(create_multi_app(service, enable_mcp=False), base_url='http://127.0.0.1:8765') as client:
        assert client.get('/workspaces').json()['workspaces'][0]['id'] == 'a'
        assert client.get('/list?workspace=a').status_code == 200
        assert client.get('/read?workspace=a&path=hello.py').json()['content'].endswith('print(1)')
        assert client.get('/read?workspace=b&path=hello.py').json()['content'].endswith('print(2)')
        assert client.get('/read?path=hello.py').status_code == 400
        assert client.get('/read?workspace=unknown&path=hello.py').status_code == 404
        assert client.post('/create', json={'workspace':'b','path':'x.py','content':'print(3)','dry_run':False}).status_code == 403
        assert not (b/'x.py').exists()
        assert client.post('/create', json={'workspace':'a','path':'x.py','content':'print(3)','dry_run':True}).json()['applied'] is False
        assert not (a/'x.py').exists()
        assert client.post('/create', json={'workspace':'a','path':'x.py','content':'print(3)','dry_run':False}).json()['applied'] is True
        assert (a/'x.py').read_text() == 'print(3)'
        assert client.post('/run', json={'workspace':'a','cwd':'.','argv':['go','test']}).status_code == 404


def test_multi_rest_l0_rejects_before_writes(multi_service):
    service, a, b = multi_service
    with TestClient(create_multi_app(service, enable_mcp=False), base_url='http://127.0.0.1:8765') as client:
        for body in [
            b'{"workspace":"a","workspace":"b","path":"x.py","content":"foo","dry_run":false}',
            b'{"workspace":"a","\\u0077orkspace":"b","path":"x.py","content":"foo","dry_run":false}',
            b'{"workspace":"a","path":"x.py","content":"foo","dry_run":false,"dry_run":true}',
        ]:
            r=client.post('/create',content=body,headers={'Content-Type':'application/json'})
            assert r.status_code==400
        r=client.post('/create',content=b'{"workspace":"a","path":"x.py","content":"foo","dry_run":false}',headers={'Content-Type':'application/json, text/plain'})
        assert r.status_code==415
        assert not (a/'x.py').exists()


def test_multi_diff_and_source_protection(multi_service):
    service, a, b = multi_service
    source = 'visible=hello\npassword="alpha"\nedit=ready\n'
    (a/'hello.py').write_text(source)
    with TestClient(create_multi_app(service, enable_mcp=False), base_url='http://127.0.0.1:8765') as client:
        read = client.get('/read',params={'workspace':'a','path':'hello.py'}).json()
        assert 'alpha' not in read['content']
        args = {'workspace':'a','path':'hello.py','old_text':'ready','new_text':'done',
                'expected_sha256':read['file_sha256']}
        preview=client.post('/replace',json=args).json()
        assert preview['applied'] is False
        assert 'alpha' not in json.dumps(preview)
        assert client.post('/write',json={'workspace':'a','path':'hello.py','content':read['content'],
                                         'expected_sha256':read['file_sha256']}).status_code==403
        assert client.post('/replace',json={**args,'dry_run':False}).json()['applied'] is True
        assert (a/'hello.py').read_text() == source.replace('ready','done')


def test_multi_search_does_not_match_hidden_content(multi_service):
    service, a, b = multi_service
    (a/'hello.py').write_text('visible\npassword="alpha"\n')
    with TestClient(create_multi_app(service, enable_mcp=False), base_url='http://127.0.0.1:8765') as client:
        assert client.get('/search',params={'workspace':'a','q':'alpha'}).json()['matches']==[]
        assert client.get('/search',params={'workspace':'a','q':'visible'}).json()['matches']
