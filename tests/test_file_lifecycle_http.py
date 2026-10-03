import hashlib

import pytest
from starlette.testclient import TestClient

from gateway.core import Gateway
from gateway.http import create_app


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


@pytest.fixture
def root(tmp_path):
    p = tmp_path / "project"
    p.mkdir()
    (p / "src").mkdir()
    (p / "dst").mkdir()
    (p / "src/app.py").write_bytes(b"count = 1\n")
    return p


@pytest.fixture
def client(root):
    g = Gateway(root, allow_write=True)
    with TestClient(create_app(g, enable_mcp=False), base_url="http://127.0.0.1:8765") as c:
        yield c
    g.close()


@pytest.mark.parametrize("route", ["/delete", "/remove", "/unlink"])
def test_http_delete_aliases(client, root, route):
    name = route[1:] + ".py"
    path = root / "src" / name
    path.write_bytes(b"pass\n")
    r = client.post(route, json={"path": f"src/{name}", "expected_sha256": sha(b"pass\n"), "dry_run": False})
    assert r.status_code == 200, r.text
    assert r.json()["operation"] == "delete"
    assert not path.exists()


@pytest.mark.parametrize("route", ["/rename", "/move"])
def test_http_move_aliases(client, root, route):
    name = route[1:] + ".py"
    source = root / "src" / name
    source.write_bytes(b"pass\n")
    r = client.post(route, json={
        "source": f"src/{name}",
        "destination": f"dst/{name}",
        "expected_sha256": sha(b"pass\n"),
        "dry_run": False,
    })
    assert r.status_code == 200, r.text
    assert r.json()["operation"] == "move"
    assert not source.exists()
    assert (root / "dst" / name).read_bytes() == b"pass\n"


def test_http_delete_requires_hash(client):
    r = client.post("/delete", json={"path": "src/app.py", "dry_run": False})
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_argument"


def test_http_move_never_overwrites_destination(client, root):
    raw = (root / "src/app.py").read_bytes()
    (root / "dst/app.py").write_bytes(b"keep\n")
    r = client.post("/move", json={
        "source": "src/app.py", "destination": "dst/app.py",
        "expected_sha256": sha(raw), "dry_run": False,
    })
    assert r.status_code == 409
    assert r.json()["error"] == "already_exists"
    assert (root / "src/app.py").read_bytes() == raw
    assert (root / "dst/app.py").read_bytes() == b"keep\n"
