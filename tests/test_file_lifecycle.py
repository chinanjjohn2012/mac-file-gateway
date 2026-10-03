import hashlib
import os

import pytest

from gateway.core import Gateway, GatewayError


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


@pytest.fixture
def root(tmp_path):
    p = tmp_path / "project"
    p.mkdir()
    (p / "src").mkdir()
    (p / "dst").mkdir()
    (p / "src" / "app.py").write_bytes(b"count = 1\n")
    return p


@pytest.fixture
def gateway(root):
    g = Gateway(root, allow_write=True)
    try:
        yield g
    finally:
        g.close()


def test_delete_preview_does_not_change_or_backup(root, gateway):
    before = (root / "src/app.py").read_bytes()
    result = gateway.delete_file("src/app.py", sha(before))
    assert result["operation"] == "delete"
    assert result["dry_run"] is True
    assert result["applied"] is False
    assert result["changed"] is True
    assert result["old_sha256"] == sha(before)
    assert (root / "src/app.py").read_bytes() == before
    assert not (root / ".gateway-backups").exists()


def test_delete_apply_creates_backup_then_removes_file(root, gateway):
    before = (root / "src/app.py").read_bytes()
    result = gateway.delete_file("src/app.py", sha(before), dry_run=False)
    assert result["applied"] is True
    assert result["backup_path"]
    assert not (root / "src/app.py").exists()
    assert (root / result["backup_path"]).read_bytes() == before


@pytest.mark.parametrize("method", ["delete_file", "remove_file", "unlink"])
def test_delete_aliases_share_behavior(root, method):
    p = root / "src" / f"{method}.py"
    p.write_bytes(b"pass\n")
    g = Gateway(root, allow_write=True)
    try:
        result = getattr(g, method)(f"src/{method}.py", sha(b"pass\n"), dry_run=False)
        assert result["operation"] == "delete"
        assert result["applied"] is True
        assert not p.exists()
    finally:
        g.close()


def test_delete_stale_sha_is_conflict_and_keeps_file(root, gateway):
    original = (root / "src/app.py").read_bytes()
    stale = sha(original)
    (root / "src/app.py").write_bytes(b"changed elsewhere\n")
    with pytest.raises(GatewayError) as exc:
        gateway.delete_file("src/app.py", stale, dry_run=False)
    assert exc.value.code == "conflict"
    assert (root / "src/app.py").read_bytes() == b"changed elsewhere\n"


def test_delete_redacted_source_is_allowed(root, gateway):
    raw = b"password = 'actual-secret'\ncount = 1\n"
    (root / "src/settings.py").write_bytes(raw)
    read = gateway.read_file("src/settings.py")
    assert read["redacted_lines"] == 1
    result = gateway.delete_file("src/settings.py", read["file_sha256"], dry_run=False)
    assert result["applied"] is True
    assert (root / result["backup_path"]).read_bytes() == raw


def test_delete_rejects_symlink_and_directory(root, gateway):
    os.symlink("app.py", root / "src/link.py")
    for path, expected in [("src/link.py", "unavailable"), ("src/folder.py", "blocked_type")]:
        if path.endswith("folder.py"):
            (root / path).mkdir()
        with pytest.raises(GatewayError) as exc:
            gateway.delete_file(path, "0" * 64, dry_run=False)
        assert exc.value.code == expected
    assert (root / "src/app.py").exists()


def test_move_preview_does_not_change_filesystem(root, gateway):
    raw = (root / "src/app.py").read_bytes()
    result = gateway.move("src/app.py", "dst/app.py", sha(raw))
    assert result["operation"] == "move"
    assert result["dry_run"] is True
    assert result["applied"] is False
    assert result["changed"] is True
    assert (root / "src/app.py").read_bytes() == raw
    assert not (root / "dst/app.py").exists()


@pytest.mark.parametrize("method", ["move", "rename"])
def test_move_aliases_apply_without_overwrite(root, method):
    source = root / "src" / f"{method}.py"
    source.write_bytes(b"print('ok')\n")
    before_ino = source.stat().st_ino
    g = Gateway(root, allow_write=True)
    try:
        result = getattr(g, method)(f"src/{method}.py", f"dst/{method}.py", sha(source.read_bytes()), dry_run=False)
        assert result["operation"] == "move"
        assert result["applied"] is True
        assert result["old_sha256"] == result["new_sha256"] == sha(b"print('ok')\n")
        assert not source.exists()
        destination = root / "dst" / f"{method}.py"
        assert destination.read_bytes() == b"print('ok')\n"
        assert destination.stat().st_ino == before_ino
    finally:
        g.close()


def test_move_refuses_existing_destination_without_overwrite(root, gateway):
    raw = (root / "src/app.py").read_bytes()
    (root / "dst/app.py").write_bytes(b"keep destination\n")
    with pytest.raises(GatewayError) as exc:
        gateway.move("src/app.py", "dst/app.py", sha(raw), dry_run=False)
    assert exc.value.code == "already_exists"
    assert (root / "src/app.py").read_bytes() == raw
    assert (root / "dst/app.py").read_bytes() == b"keep destination\n"


def test_move_stale_sha_is_conflict(root, gateway):
    stale = sha((root / "src/app.py").read_bytes())
    (root / "src/app.py").write_bytes(b"changed elsewhere\n")
    with pytest.raises(GatewayError) as exc:
        gateway.move("src/app.py", "dst/app.py", stale, dry_run=False)
    assert exc.value.code == "conflict"
    assert (root / "src/app.py").exists()
    assert not (root / "dst/app.py").exists()


def test_move_requires_existing_destination_parent(root, gateway):
    raw = (root / "src/app.py").read_bytes()
    with pytest.raises(GatewayError) as exc:
        gateway.move("src/app.py", "missing/app.py", sha(raw), dry_run=False)
    assert exc.value.code in {"unavailable", "parent_missing"}
    assert (root / "src/app.py").exists()


def test_move_rejects_destination_outside_write_scope(root):
    raw = (root / "src/app.py").read_bytes()
    g = Gateway(root, allow_write=True, write_paths=("src",))
    try:
        with pytest.raises(GatewayError) as exc:
            g.move("src/app.py", "dst/app.py", sha(raw), dry_run=False)
        assert exc.value.code == "write_scope"
    finally:
        g.close()


def test_move_redacted_source_is_allowed(root, gateway):
    raw = b"password = 'actual-secret'\ncount = 1\n"
    (root / "src/settings.py").write_bytes(raw)
    read = gateway.read_file("src/settings.py")
    result = gateway.move("src/settings.py", "dst/settings.py", read["file_sha256"], dry_run=False)
    assert result["applied"] is True
    assert not (root / "src/settings.py").exists()
    assert (root / "dst/settings.py").read_bytes() == raw


def test_move_same_path_is_invalid(root, gateway):
    raw = (root / "src/app.py").read_bytes()
    with pytest.raises(GatewayError) as exc:
        gateway.move("src/app.py", "src/app.py", sha(raw), dry_run=False)
    assert exc.value.code == "invalid_argument"


def test_write_policy_reports_file_delete_and_move(root, gateway):
    policy = gateway.info()["write_policy"]
    assert policy["file_delete"] is True
    assert policy["file_move"] is True
    assert policy["directory_delete"] is False
    assert policy["command_tools"] is False
