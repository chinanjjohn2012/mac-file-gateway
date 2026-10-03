"""Real ASGI REST dispatch and request boundaries for POST /mkdir."""
import errno
import os

import pytest
from starlette.testclient import TestClient
from gateway.core import Gateway
from gateway.http import create_app


@pytest.fixture
def root(tmp_path):
    p = tmp_path / 'project'
    p.mkdir()
    return p


@pytest.fixture
def client(root):
    g = Gateway(root, allow_write=True)
    with TestClient(create_app(g, enable_mcp=False), base_url='http://127.0.0.1:8765') as c:
        yield c
    g.close()


def test_rest_mkdir_preview_apply_list_and_create_file(client, root):
    args = {'path': 'src/generated', 'parents': True}
    r = client.post('/mkdir', json=args)
    assert r.status_code == 200, r.text
    assert not r.json()['applied'] and not (root / 'src').exists()
    r = client.post('/mkdir', json={**args, 'dry_run': False})
    assert r.status_code == 200 and r.json()['created_paths'] == ['src', 'src/generated']
    assert client.get('/list', params={'path': 'src'}).json()['entries'][0]['name'] == 'generated'
    r = client.post('/create', json={'path': 'src/generated/new.py', 'content': 'pass\n', 'dry_run': False})
    assert r.status_code == 200 and (root / 'src/generated/new.py').is_file()


def test_rest_mkdir_conflict_and_missing_parent(client, root):
    assert client.post('/mkdir', json={'path': 'a/b', 'dry_run': False}).status_code == 404
    (root / 'a').mkdir()
    assert client.post('/mkdir', json={'path': 'a', 'exist_ok': False}).status_code == 409
    (root / 'note.txt').write_text('keep')
    assert client.post('/mkdir', json={'path': 'note.txt'}).status_code == 409


@pytest.mark.parametrize('payload', [[], {}, {'path': 'a', 'parents': 'true'}, {'path': 'a', 'exist_ok': 1}, {'path': 'a', 'dry_run': 'false'}, {'path': 'a', 'mode': '777'}, {'path': None}])
def test_rest_mkdir_bad_arguments(client, root, payload):
    r = client.post('/mkdir', json=payload)
    assert r.status_code == 400, r.text
    assert list(root.iterdir()) == []


def test_rest_mkdir_no_get_and_no_cross_site(client, root):
    assert client.get('/mkdir').status_code == 405
    assert client.post('/mkdir', json={'path': 'a', 'dry_run': False}, headers={'Origin': 'https://evil.example'}).status_code == 403
    assert client.post('/mkdir', content='{"path":"a"}', headers={'Content-Type': 'text/plain'}).status_code == 415
    assert client.post('/mkdir?dry_run=false', json={'path': 'a'}).status_code == 400
    assert list(root.iterdir()) == []


def test_rest_mkdir_readonly_and_bearer(root):
    for allow_write in (False, True):
        g = Gateway(root, allow_write=allow_write)
        with TestClient(create_app(g, enable_mcp=False, token='a' * 40), base_url='http://127.0.0.1:8765') as c:
            data = {'path': 'a', 'dry_run': False}
            assert c.post('/mkdir', json=data).status_code == 401
            r = c.post('/mkdir', json=data, headers={'Authorization': 'Bearer ' + 'a' * 40})
            assert r.status_code == (200 if allow_write else 403)
        g.close()


def test_rest_mkdir_error_keeps_partial_paths(client, root, monkeypatch):
    original = os.mkdir
    def fail(name, *args, **kwargs):
        if name == 'second':
            raise OSError(errno.ENOSPC, 'disk full')
        return original(name, *args, **kwargs)
    monkeypatch.setattr(os, 'mkdir', fail)
    r = client.post('/mkdir', json={'path': 'first/second', 'parents': True, 'dry_run': False})
    assert r.status_code == 500, r.text
    assert r.json()['details']['created_paths'] == ['first']
