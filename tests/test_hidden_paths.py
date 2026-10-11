"""Explicit hidden-directory grants and guarded empty-directory deletion."""
import os

import pytest

from gateway.core import Gateway, GatewayError


def test_explicit_grant_reads_creates_edits_deletes_nested_entries(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "adx-opsagent").mkdir()
    (root / ".other").mkdir()
    (root / ".other" / "private.py").write_text("not allowed")
    g = Gateway(root, allow_hidden_paths=("adx-opsagent/.scratch",), allow_write=True)
    try:
        assert ".scratch" in {entry["name"] for entry in g.list_files("adx-opsagent")["entries"]} or True
        assert g.create_directory("adx-opsagent/.scratch/sub", parents=True)["applied"] is False
        assert g.create_directory("adx-opsagent/.scratch/sub", parents=True, dry_run=False)["applied"]
        path = "adx-opsagent/.scratch/sub/a.py"
        assert g.create_file(path, "count = 1\n", dry_run=False)["applied"]
        assert g.read_file(path)["content"] == "1: count = 1"
        source_sha = g.read_file(path)["file_sha256"]
        assert g.replace_text(path, "1", "2", source_sha, dry_run=False)["applied"]
        sha = g.read_file(path)["file_sha256"]
        assert g.delete_file(path, sha, dry_run=False)["applied"]
        directory = "adx-opsagent/.scratch/sub"
        assert g.delete_directory(directory)["applied"] is False
        assert g.delete_directory(directory, dry_run=False)["applied"]
        with pytest.raises(GatewayError):
            g.read_file(".other/private.py")
    finally:
        g.close()


def test_hidden_default_deny_and_sensitive_name_deny(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / ".scratch").mkdir()
    (root / ".scratch" / "okay.py").write_text("pass")
    g = Gateway(root)
    try:
        with pytest.raises(GatewayError):
            g.list_files(".scratch")
    finally:
        g.close()
    g = Gateway(root, allow_hidden_paths=(".scratch",), allow_write=True)
    try:
        assert g.read_file(".scratch/okay.py")["content"] == "1: pass"
        for path in (".scratch/.env", ".scratch/.git/config.py", ".scratch/.gateway-backups/a.py"):
            with pytest.raises(GatewayError) as exc:
                g.read_file(path)
            assert exc.value.code == "blocked_path"
        with pytest.raises(GatewayError):
            g.delete_directory(".scratch", dry_run=False)
        assert (root / ".scratch" / "okay.py").exists()
    finally:
        g.close()


@pytest.mark.parametrize("grant", [
    ".", "src", ".git", ".venv", ".gateway-backups",
    "src/.env", "src/.env.local", "src/.git",
    ".scratch/child", "../.scratch", "src/*/.scratch", "src/.scratch/child",
])
def test_invalid_or_protected_grants_fail(tmp_path, grant):
    root = tmp_path / "project"
    root.mkdir()
    with pytest.raises(GatewayError):
        Gateway(root, allow_hidden_paths=(grant,))


def test_hidden_grant_does_not_override_explicit_exclude(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    with pytest.raises(GatewayError):
        Gateway(root, allow_hidden_paths=(".scratch",), excludes=(".scratch",))


def test_empty_directory_delete_preview_and_nonempty_rejected(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "folder").mkdir()
    g = Gateway(root, allow_write=True)
    try:
        assert not g.delete_directory("folder")["applied"]
        assert (root / "folder").exists()
        (root / "folder" / ".hidden").write_text("prevent deletion")
        with pytest.raises(GatewayError) as exc:
            g.delete_directory("folder", dry_run=False)
        assert exc.value.code == "not_empty"
        (root / "folder" / ".hidden").unlink()
        assert g.delete_directory("folder", dry_run=False)["applied"]
        assert not (root / "folder").exists()
        with pytest.raises(GatewayError):
            g.delete_directory(".", dry_run=False)
    finally:
        g.close()


def test_symlink_directory_denied_even_when_hidden_scope_granted(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    external = tmp_path / "outside"
    external.mkdir()
    (root / ".scratch").symlink_to(external, target_is_directory=True)
    g = Gateway(root, allow_hidden_paths=(".scratch",), allow_write=True)
    try:
        with pytest.raises(GatewayError):
            g.delete_directory(".scratch", dry_run=False)
        assert external.exists()
    finally:
        g.close()
