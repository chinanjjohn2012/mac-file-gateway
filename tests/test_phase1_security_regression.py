"""Phase-1 cross-workspace negative tests using real REST and filesystem IO.

No external users, production roots, tunnels, or execution tools are involved.
"""
from __future__ import annotations

import hashlib
import os

import pytest
from starlette.testclient import TestClient

from gateway.http_multi import create_multi_app
from gateway.workspaces import ActiveRuntimeInventory, WorkspaceService
from gateway.workspaces_config import parse_workspace_config


@pytest.fixture
def pair(tmp_path):
    parent = tmp_path / "projects"
    parent.mkdir()
    writable = parent / "writable"
    readonly = parent / "readonly"
    writable.mkdir()
    readonly.mkdir()
    (readonly / "private.py").write_text("origin = 'readonly'\n")
    (writable / ".scratch").mkdir()

    config = tmp_path / "config"
    config.mkdir()
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    settings = parse_workspace_config({
        "schema_version": 1,
        "workspaces": {
            "w": {
                "root": str(writable),
                "hidden_paths": [".scratch"],
                "write": {"enabled": True, "paths": ["."]},
            },
            "r": {
                "root": str(readonly),
                "write": {"enabled": False},
            },
        },
    })
    svc = WorkspaceService(
        settings,
        config_dir=config,
        inventory=ActiveRuntimeInventory(paths=(runtime,)),
    )
    try:
        with TestClient(create_multi_app(svc, enable_mcp=False),
                        base_url="http://127.0.0.1:8765") as client:
            yield client, writable, readonly
    finally:
        svc.close()


def test_symlinks_do_not_cross_workspace_for_read_create_or_delete(pair):
    client, writable, readonly = pair
    original = (readonly / "private.py").read_bytes()

    (writable / "link.py").symlink_to(readonly / "private.py")
    (writable / "subdir").symlink_to(readonly, target_is_directory=True)

    assert client.get("/read", params={
        "workspace": "w", "path": "link.py",
    }).status_code in {403, 404}
    assert client.get("/read", params={
        "workspace": "w", "path": "subdir/private.py",
    }).status_code in {403, 404}
    assert client.get("/list", params={
        "workspace": "w", "path": "subdir",
    }).status_code in {403, 404}

    assert client.post("/create", json={
        "workspace": "w", "path": "link.py",
        "content": "unexpected", "dry_run": False,
    }).status_code == 409

    digest = hashlib.sha256(original).hexdigest()
    assert client.post("/delete", json={
        "workspace": "w", "path": "link.py",
        "expected_sha256": digest, "dry_run": False,
    }).status_code in {403, 404}

    assert (readonly / "private.py").read_bytes() == original
    assert (writable / "link.py").is_symlink()


def test_hardlink_to_other_workspace_is_never_read_modified_or_moved(pair):
    client, writable, readonly = pair
    target = readonly / "private.py"
    alias = writable / "alias.py"
    original = target.read_bytes()
    os.link(target, alias)
    assert os.stat(target).st_nlink >= 2
    digest = hashlib.sha256(original).hexdigest()

    assert client.get("/read", params={
        "workspace": "w", "path": "alias.py",
    }).status_code == 403

    assert client.post("/replace", json={
        "workspace": "w", "path": "alias.py",
        "old_text": "readonly", "new_text": "modified",
        "expected_sha256": digest, "dry_run": False,
    }).status_code == 403

    assert client.post("/delete", json={
        "workspace": "w", "path": "alias.py",
        "expected_sha256": digest, "dry_run": False,
    }).status_code == 403

    assert client.post("/move", json={
        "workspace": "w", "source": "alias.py",
        "destination": "moved.py",
        "expected_sha256": digest, "dry_run": False,
    }).status_code == 403

    assert target.read_bytes() == original
    assert alias.exists()
    assert not (writable / "moved.py").exists()


def test_readonly_workspace_denies_known_hash_updates_and_deletes(pair):
    client, writable, readonly = pair
    response = client.get("/read", params={
        "workspace": "r", "path": "private.py",
    })
    assert response.status_code == 200
    digest = response.json()["file_sha256"]

    for route, data in [
        ("/write", {"path": "private.py", "content": "replaced", "expected_sha256": digest}),
        ("/delete", {"path": "private.py", "expected_sha256": digest}),
        ("/rename", {"source": "private.py", "destination": "renamed.py", "expected_sha256": digest}),
    ]:
        r = client.post(route, json={"workspace": "r", **data, "dry_run": False})
        assert r.status_code == 403

    assert (readonly / "private.py").read_text() == "origin = 'readonly'\n"
    assert not (readonly / "renamed.py").exists()


def test_protected_names_remain_denied_inside_granted_hidden_directory(pair):
    client, writable, _ = pair
    hidden = writable / ".scratch" / ".ssh"
    hidden.mkdir()
    (hidden / "notes.txt").write_text("local-only\n")

    assert client.get("/read", params={
        "workspace": "w", "path": ".scratch/.ssh/notes.txt",
    }).status_code == 403
    assert client.post("/create", json={
        "workspace": "w", "path": ".scratch/.ssh/new.txt",
        "content": "unexpected", "dry_run": False,
    }).status_code == 403
    assert (hidden / "notes.txt").read_text() == "local-only\n"
    assert not (hidden / "new.txt").exists()


def test_backup_state_cannot_leak_into_another_workspace(pair):
    client, writable, readonly = pair
    source = writable / "created.py"
    result = client.post("/create", json={
        "workspace": "w", "path": source.name,
        "content": "version = 1\n", "dry_run": False,
    })
    assert result.status_code == 200 and result.json()["applied"] is True

    current = client.get("/read", params={
        "workspace": "w", "path": source.name,
    }).json()
    updated = client.post("/write", json={
        "workspace": "w", "path": source.name,
        "content": "version = 2\n",
        "expected_sha256": current["file_sha256"],
        "dry_run": False,
    })
    assert updated.status_code == 200 and updated.json()["applied"] is True
    backup = updated.json()["backup_path"]
    assert backup.startswith(".gateway-backups/")
    assert (writable / backup).read_bytes() == b"version = 1\n"
    assert source.read_bytes() == b"version = 2\n"
    assert not (readonly / ".gateway-backups").exists()
