from pathlib import Path
import pytest
from starlette.testclient import TestClient
from gateway.core import Gateway
from gateway.http import create_app

@pytest.fixture
def root(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "hello.py").write_text("# click\nprint('hello')\n")
    (root / ".env").write_text("KEY=topsecret")
    return root

@pytest.fixture
def client(root):
    g = Gateway(root)
    with TestClient(create_app(g, enable_mcp=False), base_url="http://127.0.0.1:8765") as client:
        yield client
    g.close()

def test_rest_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["read_only"] is True
    assert r.json()["mcp_enabled"] is False
    assert r.headers["cache-control"] == "no-store"
    assert r.headers["x-content-type-options"] == "nosniff"

def test_rest_list_read_search(client):
    assert client.get("/list").json()["entries"][0]["path"] == "hello.py"
    assert "1: # click" in client.get("/read", params={"path": "hello.py"}).json()["content"]
    r = client.get("/search", params={"q": "click", "file_glob": "*.py"})
    assert r.json()["matches"][0]["line"] == 1

def test_rest_info_hides_absolute_path(client, root):
    r = client.get("/info")
    assert r.status_code == 200
    assert str(root) not in r.text
    assert r.json()["path_base"] == "."

@pytest.mark.parametrize("path", ["../outside.py", ".env", "/etc/passwd", "sub/../../outside.py", "%2e%2e/outside.py"])
def test_rest_rejects_escape_or_secret(client, path):
    r = client.get("/read", params={"path": path})
    assert r.status_code in (400, 403, 404)
    assert "topsecret" not in r.text

@pytest.mark.parametrize("headers", [{"Host": "evil.test:8765"}, {"Host": "127.0.0.1.evil.test:8765"}, {"Origin": "https://evil.test"}, {"Origin": "null"}, {"Sec-Fetch-Site": "cross-site"}])
def test_host_origin_and_fetch_metadata(client, headers):
    r = client.get("/list", headers=headers)
    assert r.status_code in (403, 421)
    assert "hello.py" not in r.text
    assert "access-control-allow-origin" not in r.headers

@pytest.mark.parametrize("url", ["/read", "/read?path=hello.py&start_line=0", "/read?path=hello.py&max_lines=xyz", "/read?path=hello.py&unexpected=1", "/read?path=hello.py&path=.env", "/search", "/search?q=x&case_sensitive=maybe"])
def test_bad_http_arguments(client, url):
    assert client.get(url).status_code == 400

@pytest.mark.parametrize("method", ["post", "put", "patch", "delete"])
def test_no_rest_writes(client, method):
    assert getattr(client, method)("/read?path=hello.py").status_code == 405

def test_request_body_limit(client):
    assert client.post("/mcp", content=b"x" * 65_537).status_code == 413

def test_oversized_query_string(client):
    assert client.get("/list?path=" + "x" * 4_097).status_code == 414

def test_optional_bearer_token(root):
    g = Gateway(root)
    with TestClient(create_app(g, enable_mcp=False, token="A" * 40), base_url="http://127.0.0.1:8765") as client:
        assert client.get("/list").status_code == 401
        assert client.get("/list", headers={"Authorization": "Bearer wrong"}).status_code == 401
        assert client.get("/list", headers={"Authorization": "Bearer " + "A" * 40}).status_code == 200
    g.close()

def test_no_absolute_error_leak(client, root):
    r = client.get("/read", params={"path": "missing.py"})
    assert r.status_code == 404
    assert str(root) not in r.text
