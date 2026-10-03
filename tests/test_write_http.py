"""HTTP writes must reach exactly the same guarded filesystem API."""
import hashlib
import json

import pytest
from starlette.testclient import TestClient

from gateway.core import Gateway
from gateway.http import create_app


@pytest.fixture
def root(tmp_path):
    p = tmp_path / "project"
    p.mkdir()
    (p / "app.py").write_bytes(b"count = 1\n")
    return p


@pytest.fixture
def client(root):
    g = Gateway(root, allow_write=True)
    with TestClient(create_app(g, enable_mcp=False), base_url="http://127.0.0.1:8765") as c:
        yield c
    g.close()


def test_http_create_is_preview_by_default(client, root):
    r = client.post("/create", json={"path": "new.py", "content": "pass\n"})
    assert r.status_code == 200, r.text
    assert r.json()["applied"] is False
    assert not (root / "new.py").exists()


def test_http_create_apply(client, root):
    r = client.post("/create", json={"path": "new.py", "content": "pass\n", "dry_run": False})
    assert r.status_code == 200, r.text
    assert r.json()["applied"] is True
    assert (root / "new.py").read_bytes() == b"pass\n"


def test_http_hash_read_write_and_conflict(client, root):
    read = client.get("/read", params={"path": "app.py"}).json()
    assert read["file_sha256"] == hashlib.sha256(b"count = 1\n").hexdigest()
    request = {"path": "app.py", "content": "count = 2\n", "expected_sha256": read["file_sha256"], "dry_run": False}
    r = client.post("/write", json=request)
    assert r.status_code == 200, r.text
    assert (root / r.json()["backup_path"]).read_bytes() == b"count = 1\n"
    again = client.post("/write", json=request)
    assert again.status_code == 409
    assert again.json()["error"] == "conflict"


def test_http_exact_replace(client, root):
    sha = client.get("/read", params={"path": "app.py"}).json()["file_sha256"]
    r = client.post("/replace", json={"path": "app.py", "old_text": "1", "new_text": "8", "expected_sha256": sha, "dry_run": False})
    assert r.status_code == 200, r.text
    assert (root / "app.py").read_bytes() == b"count = 8\n"


def test_http_write_mode_health_is_truthful(client):
    assert client.get("/health").json()["read_only"] is False
    assert client.get("/info").json()["write_policy"]["enabled"] is True


@pytest.mark.parametrize("route", ["/create", "/write", "/replace"])
def test_http_new_routes_disabled_without_opt_in(root, route):
    g = Gateway(root)
    try:
        with TestClient(create_app(g, enable_mcp=False), base_url="http://127.0.0.1:8765") as c:
            r = c.post(route, json={"path": "app.py", "content": "pass\n", "dry_run": False})
            assert r.status_code == 403, r.text
            assert r.json()["error"] == "write_disabled"
    finally:
        g.close()


@pytest.mark.parametrize("route", ["/create", "/write", "/replace"])
def test_http_no_get_side_effects(client, route):
    assert client.get(route).status_code == 405


@pytest.mark.parametrize("payload", [[], None, {"path": "new.py"}, {"path": "new.py", "content": "pass", "unexpected": True}, {"path": "new.py", "content": "pass", "dry_run": "false"}, {"path": "new.py", "content": 5}])
def test_http_invalid_json_shapes(client, root, payload):
    r = client.post("/create", content=json.dumps(payload), headers={"Content-Type": "application/json"})
    assert r.status_code == 400
    assert not (root / "new.py").exists()


@pytest.mark.parametrize("content_type", ["text/plain", "application/x-www-form-urlencoded"])
def test_http_rejects_non_json_posts(client, root, content_type):
    body = '{"path":"new.py","content":"pass","dry_run":false}'
    r = client.post("/create", content=body, headers={"Content-Type": content_type})
    assert r.status_code == 415
    assert not (root / "new.py").exists()


def test_http_duplicate_json_keys_rejected(client):
    r = client.post("/create", content='{"path":"a.py","path":"b.py","content":"pass"}', headers={"Content-Type": "application/json"})
    assert r.status_code == 400


def test_http_malformed_json_and_query_args(client):
    assert client.post("/create", content='{', headers={"Content-Type": "application/json"}).status_code == 400
    assert client.post("/create?dry_run=false", json={"path": "a.py", "content": "pass"}).status_code == 400


def test_http_blocked_paths_in_write_mode(client):
    r = client.post("/create", json={"path": ".env", "content": "data", "dry_run": False})
    assert r.status_code == 403


@pytest.mark.parametrize("headers", [{"Origin": "https://evil.example"}, {"Host": "evil.example:8765"}, {"Sec-Fetch-Site": "cross-site"}])
def test_http_csrf_and_host_protection_on_writes(client, root, headers):
    r = client.post("/create", json={"path": "new.py", "content": "pass", "dry_run": False}, headers=headers)
    assert r.status_code in (403, 421)
    assert not (root / "new.py").exists()


def test_http_write_accepts_larger_than_old_request_cap(client, root):
    content = "x" * 100_000
    r = client.post("/create", json={"path": "large.txt", "content": content, "dry_run": False})
    assert r.status_code == 200, r.text
    assert (root / "large.txt").stat().st_size == 100_000


def test_http_content_byte_limit_enforced(client, root):
    r = client.post("/create", json={"path": "large.txt", "content": "x" * 1_048_577, "dry_run": False})
    assert r.status_code == 413
    assert not (root / "large.txt").exists()


def test_http_request_body_still_bounded(client):
    assert client.post("/create", content=b"x" * (7 * 1024 * 1024 + 1)).status_code == 413


def test_http_bearer_required_for_writes_when_configured(root):
    g = Gateway(root, allow_write=True)
    with TestClient(create_app(g, enable_mcp=False, token="A" * 40), base_url="http://127.0.0.1:8765") as c:
        body = {"path": "new.py", "content": "pass", "dry_run": False}
        assert c.post("/create", json=body).status_code == 401
        assert c.post("/create", json=body, headers={"Authorization": "Bearer " + "A" * 40}).status_code == 200
    g.close()

def test_http_redacted_source_returns_hash_and_allows_visible_replace(client, root):
    raw = b"password = 'keep-me'\ncount = 1\n"
    (root / "settings.py").write_bytes(raw)
    read = client.get("/read", params={"path": "settings.py"}).json()
    assert read["redacted_lines"] == 1
    assert read["file_sha256"] == hashlib.sha256(raw).hexdigest()
    r = client.post("/replace", json={
        "path": "settings.py",
        "old_text": "count = 1",
        "new_text": "count = 2",
        "expected_sha256": read["file_sha256"],
        "dry_run": False,
    })
    assert r.status_code == 200, r.text
    assert (root / "settings.py").read_bytes() == b"password = 'keep-me'\ncount = 2\n"
