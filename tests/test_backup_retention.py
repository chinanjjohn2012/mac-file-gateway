"""Tests for write-triggered 15-day backup retention."""
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os

import pytest

from gateway import write_storage as storage
from gateway.core import Gateway, GatewayError


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


@pytest.fixture
def project(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "app.py").write_bytes(b"before")
    g = Gateway(root, allow_write=True)
    try:
        yield root, g
    finally:
        g.close()


def seed(root, days, suffix, *, now=None):
    folder = root / ".gateway-backups"
    folder.mkdir(mode=0o700, exist_ok=True)
    timestamp = (now or datetime.now(timezone.utc)) - timedelta(days=days)
    ident = timestamp.strftime("%Y%m%dT%H%M%SZ-") + suffix * 32
    bak = folder / (ident + ".bak")
    meta = folder / (ident + ".json")
    bak.write_bytes(b"old")
    meta.write_text(json.dumps({"path": "app.py", "sha256": sha(b"old"),
                                "bytes": 3, "backup": bak.name}))
    bak.chmod(0o600)
    meta.chmod(0o600)
    return bak, meta


def test_prunes_old_pair_and_keeps_fresh(project):
    root, g = project
    old = seed(root, 16, "a")
    fresh = seed(root, 14, "b")
    result = g.write_file("app.py", "after", sha(b"before"), dry_run=False)
    assert result["applied"]
    assert all(not p.exists() for p in old)
    assert all(p.exists() for p in fresh)


def test_cleanup_precedes_quota_check(project, monkeypatch):
    root, g = project
    old = seed(root, 16, "c")
    monkeypatch.setattr(storage, "BACKUP_COUNT_LIMIT", 1)
    monkeypatch.setattr(storage, "BACKUP_BYTES_LIMIT", 6)
    result = g.write_file("app.py", "after", sha(b"before"), dry_run=False)
    assert result["applied"]
    assert all(not p.exists() for p in old)
    assert (root / result["backup_path"]).read_bytes() == b"before"


def test_does_not_use_mtime(project):
    root, g = project
    old = seed(root, 16, "d")
    for path in old:
        os.utime(path, None)
    g.write_file("app.py", "after", sha(b"before"), dry_run=False)
    assert all(not p.exists() for p in old)


def test_does_not_prune_incomplete_pair(project):
    root, g = project
    old = seed(root, 16, "e")
    old[1].unlink()
    g.write_file("app.py", "after", sha(b"before"), dry_run=False)
    assert old[0].exists()


def test_symlink_metadata_fails_closed(project):
    root, g = project
    old = seed(root, 16, "f")
    outside = root / "outside.json"
    outside.write_text("unchanged")
    old[1].unlink()
    old[1].symlink_to(outside)
    with pytest.raises(GatewayError):
        g.write_file("app.py", "after", sha(b"before"), dry_run=False)
    assert (root / "app.py").read_bytes() == b"before"
    assert outside.read_text() == "unchanged"


def test_preview_and_noop_do_not_prune(project):
    root, g = project
    old = seed(root, 16, "1")
    g.write_file("app.py", "after", sha(b"before"), dry_run=True)
    g.write_file("app.py", "before", sha(b"before"), dry_run=False)
    assert all(p.exists() for p in old)


def test_fresh_pair_is_not_evicted_if_quota_full(project, monkeypatch):
    root, g = project
    fresh = seed(root, 1, "2")
    monkeypatch.setattr(storage, "BACKUP_COUNT_LIMIT", 1)
    with pytest.raises(GatewayError) as exc:
        g.write_file("app.py", "after", sha(b"before"), dry_run=False)
    assert exc.value.code == "backup_full"
    assert all(p.exists() for p in fresh)
    assert (root / "app.py").read_bytes() == b"before"


def test_prune_failure_preserves_source(project, monkeypatch):
    root, g = project
    old = seed(root, 16, "3")
    real_unlink = storage.os.unlink
    def fail(name, *, dir_fd=None):
        if name == old[0].name and dir_fd is not None:
            raise OSError("injected")
        return real_unlink(name, dir_fd=dir_fd)
    monkeypatch.setattr(storage.os, "unlink", fail)
    with pytest.raises(GatewayError):
        g.write_file("app.py", "after", sha(b"before"), dry_run=False)
    assert (root / "app.py").read_bytes() == b"before"
