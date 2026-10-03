"""Security and preview regressions found during the separate author review."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import os
import stat

import pytest
from gateway.core import Gateway, GatewayError


@pytest.fixture
def root(tmp_path):
    p = tmp_path / "project"
    p.mkdir()
    (p / "app.py").write_bytes(b"before")
    return p


@pytest.fixture
def g(root):
    gateway = Gateway(root, allow_write=True)
    yield gateway
    gateway.close()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def test_preview_marks_missing_final_newline(g):
    r = g.write_file("app.py", "after", sha(b"before"))
    assert "-before\n\\ No newline at end of file\n" in r["diff"]
    assert "+after\n\\ No newline at end of file\n" in r["diff"]


def test_readonly_posix_mode_is_respected(root, g):
    p = root / "app.py"
    p.chmod(0o444)
    try:
        with pytest.raises(GatewayError) as exc:
            g.write_file("app.py", "after", sha(b"before"), dry_run=False)
        assert exc.value.code == "write_protected"
        assert p.read_bytes() == b"before"
    finally:
        p.chmod(0o644)


@pytest.mark.parametrize("path", ["\ud800.py", "x\udfff.py"])
def test_unpaired_surrogate_path_is_a_safe_validation_error(g, path):
    with pytest.raises(GatewayError) as exc:
        g.create_file(path, "pass", dry_run=False)
    assert exc.value.code == "invalid_path"


def test_backup_limit_fails_closed(root, g, monkeypatch):
    import gateway.write_storage as storage
    monkeypatch.setattr(storage, "BACKUP_COUNT_LIMIT", 1)
    g.write_file("app.py", "after", sha(b"before"), dry_run=False)
    with pytest.raises(GatewayError) as exc:
        g.write_file("app.py", "later", sha(b"after"), dry_run=False)
    assert exc.value.code == "backup_full"
    assert (root / "app.py").read_bytes() == b"after"


def test_world_readable_backup_directory_fails_closed(root, g):
    (root / ".gateway-backups").mkdir(mode=0o755)
    with pytest.raises(GatewayError) as exc:
        g.write_file("app.py", "after", sha(b"before"), dry_run=False)
    assert exc.value.code == "backup_unavailable"
    assert (root / "app.py").read_bytes() == b"before"


def test_late_create_race_never_clobbers(root, g, monkeypatch):
    import gateway.write_storage as storage
    original_link = storage.os.link
    def race_then_link(*args, **kwargs):
        (root / "late.txt").write_bytes(b"another writer won")
        return original_link(*args, **kwargs)
    monkeypatch.setattr(storage.os, "link", race_then_link)
    with pytest.raises(GatewayError) as exc:
        g.create_file("late.txt", "our data", dry_run=False)
    assert exc.value.code == "already_exists"
    assert (root / "late.txt").read_bytes() == b"another writer won"
    assert not list(root.glob(".gateway-tmp-*"))


def test_two_gateway_instances_share_the_project_lock(root, g):
    second = Gateway(root, allow_write=True)
    def update(which):
        gateway, text = which
        try:
            return gateway.write_file("app.py", text, sha(b"before"), dry_run=False)["applied"]
        except GatewayError as exc:
            return exc.code
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(update, [(g, "one"), (second, "two")]))
    finally:
        second.close()
    assert results.count(True) == 1 and results.count("conflict") == 1


def test_parent_fsync_failure_reports_committed_write_truthfully(root, g, monkeypatch):
    import gateway.write_storage as storage
    original = storage.os.fsync
    root_ino = root.stat().st_ino
    def fsync(fd):
        info = os.fstat(fd)
        if stat.S_ISDIR(info.st_mode) and info.st_ino == root_ino:
            raise OSError("injected final directory sync failure")
        return original(fd)
    monkeypatch.setattr(storage.os, "fsync", fsync)
    r = g.create_file("new.txt", "created", dry_run=False)
    assert r["applied"] is True
    assert r["warnings"] and (root / "new.txt").read_bytes() == b"created"
