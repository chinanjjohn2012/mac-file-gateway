"""Actual-file write tests. Fault injection only simulates OS failures/races."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import replace
import hashlib
import os
import stat

import pytest

from gateway.core import Gateway, GatewayError, Limits


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


@pytest.fixture
def root(tmp_path):
    p = tmp_path / "project"
    p.mkdir()
    (p / "src").mkdir()
    (p / "src" / "app.py").write_bytes(b"count = 1\nprint(count)\n")
    return p


@contextmanager
def writer(root, **kwargs):
    g = Gateway(root, allow_write=True, **kwargs)
    try:
        yield g
    finally:
        g.close()


def test_read_hash_uses_original_bytes(root):
    raw = b"\xef\xbb\xbfhello\r\nworld\r\n"
    (root / "sample.txt").write_bytes(raw)
    g = Gateway(root)
    try:
        result = g.read_file("sample.txt")
        assert result.get("file_sha256") == digest(raw)
        assert result["content_sha256"] != result["file_sha256"]
    finally:
        g.close()


def test_writes_disabled_by_default(root):
    g = Gateway(root)
    try:
        with pytest.raises(GatewayError) as exc:
            g.create_file("new.py", "pass\n", dry_run=False)
        assert exc.value.code == "write_disabled"
        assert not (root / "new.py").exists()
        assert g.info()["read_only"] is True
    finally:
        g.close()


def test_write_policy_reports_opt_in(root):
    with writer(root, write_paths=("src",)) as g:
        info = g.info()
        assert info["read_only"] is False
        assert info["write_policy"]["paths"] == ["src"]
        assert info["write_policy"]["dry_run_default"] is True
        assert str(root) not in str(info)


def test_create_defaults_to_preview_with_no_filesystem_changes(root):
    before = sorted(str(p.relative_to(root)) for p in root.rglob("*"))
    with writer(root) as g:
        r = g.create_file("src/new.py", "print('hello')\n")
    assert r["applied"] is False and r["dry_run"] is True
    assert r["changed"] is True and "+print('hello')" in r["diff"]
    assert sorted(str(p.relative_to(root)) for p in root.rglob("*")) == before


def test_create_applies_exact_bytes_with_private_permissions(root):
    text = "# \u4f60\u597d\n"
    with writer(root) as g:
        r = g.create_file("src/hello \u4e2d\u6587.py", text, dry_run=False)
    p = root / "src/hello \u4e2d\u6587.py"
    assert p.read_bytes() == text.encode()
    assert stat.S_IMODE(p.stat().st_mode) == 0o600
    assert r["applied"] is True and r["new_sha256"] == digest(p.read_bytes())
    assert r["backup_path"] is None


def test_create_empty_file(root):
    with writer(root) as g:
        r = g.create_file("empty.txt", "", dry_run=False)
    assert (root / "empty.txt").read_bytes() == b""
    assert r["applied"] is True


def test_create_never_overwrites_existing_file(root):
    p = root / "src/app.py"
    original = p.read_bytes()
    with writer(root) as g:
        with pytest.raises(GatewayError) as exc:
            g.create_file("src/app.py", "lost\n", dry_run=False)
    assert exc.value.code == "already_exists"
    assert p.read_bytes() == original


def test_parent_directories_must_exist(root):
    with writer(root) as g:
        with pytest.raises(GatewayError):
            g.create_file("missing/new.py", "pass\n", dry_run=False)
    assert not (root / "missing").exists()


def test_write_preview_then_apply_and_backup(root):
    p = root / "src/app.py"
    original = p.read_bytes()
    with writer(root) as g:
        sha = g.read_file("src/app.py")["file_sha256"]
        r = g.write_file("src/app.py", "count = 2\n", sha)
        assert not r["applied"] and "-count = 1" in r["diff"]
        assert p.read_bytes() == original
        assert not (root / ".gateway-backups").exists()
        applied = g.write_file("src/app.py", "count = 2\n", sha, dry_run=False)
        assert (root / applied["backup_path"]).read_bytes() == original
        assert stat.S_IMODE((root / applied["backup_path"]).stat().st_mode) == 0o600
        assert stat.S_IMODE((root / ".gateway-backups").stat().st_mode) == 0o700
        assert ".gateway-backups" not in str(g.list_files())
    assert applied["applied"] and p.read_bytes() == b"count = 2\n"


def test_write_requires_existing_file(root):
    with writer(root) as g:
        with pytest.raises(GatewayError):
            g.write_file("missing.py", "pass\n", "0" * 64, dry_run=False)
    assert not (root / "missing.py").exists()


@pytest.mark.parametrize("bad", [None, "", "1234", 10, True, "x" * 64])
def test_invalid_source_hash_rejected(root, bad):
    with writer(root) as g:
        with pytest.raises(GatewayError) as exc:
            g.write_file("src/app.py", "count = 9\n", bad, dry_run=False)
    assert exc.value.code == "invalid_argument"
    assert (root / "src/app.py").read_bytes().startswith(b"count = 1")


def test_source_change_after_read_is_conflict(root):
    p = root / "src/app.py"
    with writer(root) as g:
        sha = g.read_file("src/app.py")["file_sha256"]
        p.write_bytes(b"edited elsewhere\n")
        with pytest.raises(GatewayError) as exc:
            g.write_file("src/app.py", "count = 2\n", sha, dry_run=False)
    assert exc.value.code == "conflict"
    assert p.read_bytes() == b"edited elsewhere\n"


def test_newline_only_change_is_conflict(root):
    p = root / "src/app.py"
    with writer(root) as g:
        sha = g.read_file("src/app.py")["file_sha256"]
        p.write_bytes(p.read_bytes().replace(b"\n", b"\r\n"))
        with pytest.raises(GatewayError) as exc:
            g.write_file("src/app.py", "pass\n", sha, dry_run=False)
    assert exc.value.code == "conflict"


def test_replace_preserves_bom_crlf_and_unmodified_text(root):
    p = root / "src/app.py"
    p.write_bytes(b"\xef\xbb\xbfcount = 1\r\nprint(count)\r\n")
    with writer(root) as g:
        sha = g.read_file("src/app.py")["file_sha256"]
        r = g.replace_text("src/app.py", "count = 1", "count = 7", sha, dry_run=False)
    assert p.read_bytes() == b"\xef\xbb\xbfcount = 7\r\nprint(count)\r\n"
    assert r["replacements"] == 1


@pytest.mark.parametrize("old,new,expected", [("missing", "new", 1), ("count", "value", 1), ("", "new", 1)])
def test_exact_replacement_match_safety(root, old, new, expected):
    p = root / "src/app.py"
    before = p.read_bytes()
    with writer(root) as g:
        with pytest.raises(GatewayError):
            g.replace_text("src/app.py", old, new, digest(before), expected_count=expected, dry_run=False)
    assert p.read_bytes() == before


def test_replace_all_requires_explicit_match_count(root):
    p = root / "src/app.py"
    with writer(root) as g:
        r = g.replace_text("src/app.py", "count", "value", digest(p.read_bytes()), expected_count=2, dry_run=False)
    assert r["replacements"] == 2 and b"count" not in p.read_bytes()


@pytest.mark.parametrize("value", [0, -1, True, "1", 101])
def test_bad_expected_count(root, value):
    with writer(root) as g:
        with pytest.raises(GatewayError):
            g.replace_text("src/app.py", "count", "value", digest((root / "src/app.py").read_bytes()), expected_count=value)


def test_noop_does_not_backup_or_change_inode(root):
    p = root / "src/app.py"
    raw = p.read_bytes()
    inode = p.stat().st_ino
    with writer(root) as g:
        r = g.write_file("src/app.py", raw.decode(), digest(raw), dry_run=False)
    assert r["changed"] is False and r["applied"] is False
    assert r["backup_path"] is None and p.stat().st_ino == inode
    assert not list((root / ".gateway-backups").glob("*.bak"))


@pytest.mark.parametrize("path", ["../escape.py", "/tmp/escape.py", ".env", ".git/config", "private.pem", "a.png", "node_modules/x.py", "src/../../x.py", "src\\x.py", "x\x00.py", "credentials.json"])
def test_write_inherits_path_denials(root, path):
    with writer(root) as g:
        with pytest.raises(GatewayError):
            g.create_file(path, "data", dry_run=False)


def test_write_allowlist_and_exclusion(root):
    (root / "src2").mkdir()
    with writer(root, write_paths=("src",), excludes=("src/private.py",)) as g:
        g.create_file("src/ok.py", "pass\n", dry_run=False)
        for path in ("other.py", "src2/no.py", "src/private.py"):
            with pytest.raises(GatewayError):
                g.create_file(path, "pass\n", dry_run=False)
    assert (root / "src/ok.py").exists()


def test_allowlist_can_select_one_file(root):
    with writer(root, write_paths=("src/app.py",)) as g:
        with pytest.raises(GatewayError):
            g.create_file("src/another.py", "pass\n", dry_run=False)


def test_executable_mode_retained(root):
    p = root / "src/app.py"
    p.chmod(0o751)
    with writer(root) as g:
        g.write_file("src/app.py", "pass\n", digest(p.read_bytes()), dry_run=False)
    assert stat.S_IMODE(p.stat().st_mode) == 0o751


@pytest.mark.parametrize("kind", ["file_symlink", "dir_symlink", "hardlink", "fifo"])
def test_unsafe_target_types_never_modified(root, tmp_path, kind):
    outside = tmp_path / "outside"
    outside.mkdir()
    p = outside / "target.py"
    p.write_bytes(b"keep\n")
    target = "linked.py"
    if kind == "file_symlink":
        (root / target).symlink_to(p)
    elif kind == "dir_symlink":
        (root / "linked").symlink_to(outside, target_is_directory=True)
        target = "linked/target.py"
    elif kind == "hardlink":
        os.link(p, root / target)
    else:
        os.mkfifo(root / target)
    with writer(root) as g:
        with pytest.raises(GatewayError):
            g.write_file(target, "overwrite\n", digest(b"keep\n"), dry_run=False)
        with pytest.raises(GatewayError):
            g.create_file(target, "overwrite\n", dry_run=False)
    assert p.read_bytes() == b"keep\n"


@pytest.mark.parametrize("content", ["x\x00y", "[REDACTED] possible credential\n", "x [...line truncated...]", "api_key = 'example'\n", "-----BEGIN PRIVATE KEY-----\nabc\n"])
def test_suspicious_or_placeholder_content_rejected(root, content):
    with writer(root) as g:
        with pytest.raises(GatewayError):
            g.create_file("new.txt", content, dry_run=False)
    assert not (root / "new.txt").exists()


def test_redacted_source_cannot_be_overwritten(root):
    p = root / "settings.py"
    raw = b"password = 'keep-me'\ncount = 1\n"
    p.write_bytes(raw)
    with writer(root) as g:
        r = g.read_file("settings.py")
        assert r["file_sha256"] == digest(raw)
        with pytest.raises(GatewayError) as exc:
            g.write_file("settings.py", "count = 2\n", digest(raw), dry_run=False)
        assert exc.value.code == "sensitive_content"
        assert "keep-me" not in str(exc.value)
    assert p.read_bytes() == raw


@pytest.mark.parametrize("content", [None, 1, True, b"bytes", "\ud800"])
def test_content_type_and_encoding_validation(root, content):
    with writer(root) as g:
        with pytest.raises(GatewayError):
            g.create_file("new.txt", content, dry_run=False)


@pytest.mark.parametrize("dry_run", [0, 1, "false", None])
def test_dry_run_requires_boolean(root, dry_run):
    with writer(root) as g:
        with pytest.raises(GatewayError):
            g.create_file("new.py", "pass\n", dry_run=dry_run)


def test_write_size_is_utf8_bytes_not_characters(root):
    with writer(root, limits=replace(Limits(), max_file_bytes=12)) as g:
        g.create_file("allowed.txt", "\u4e2d" * 4, dry_run=False)
        with pytest.raises(GatewayError) as exc:
            g.create_file("blocked.txt", "\u4e2d" * 5, dry_run=False)
    assert exc.value.code == "too_large"


def test_large_diff_is_explicitly_bounded(root):
    with writer(root) as g:
        r = g.create_file("long.txt", "x\n" * 20_000)
    assert r["diff_truncated"] is True
    assert len(r["diff"]) <= 24_000
    assert r["applied"] is False


def test_backup_directory_symlink_is_rejected(root, tmp_path):
    outside = tmp_path / "backups"
    outside.mkdir()
    (root / ".gateway-backups").symlink_to(outside, target_is_directory=True)
    p = root / "src/app.py"
    before = p.read_bytes()
    with writer(root) as g:
        with pytest.raises(GatewayError):
            g.write_file("src/app.py", "pass\n", digest(before), dry_run=False)
    assert p.read_bytes() == before and list(outside.iterdir()) == []


def test_backup_failure_does_not_touch_target(root, monkeypatch):
    import gateway.write_storage as storage
    p = root / "src/app.py"
    before = p.read_bytes()
    def fail(*args, **kwargs):
        raise OSError("injected full disk /private/path")
    monkeypatch.setattr(storage, "save_backup", fail)
    with writer(root) as g:
        with pytest.raises(GatewayError) as exc:
            g.write_file("src/app.py", "pass\n", digest(before), dry_run=False)
    assert p.read_bytes() == before
    assert "/private/path" not in str(exc.value)
    assert not list((root / "src").glob(".gateway-tmp-*"))


def test_atomic_replace_failure_keeps_old_content(root, monkeypatch):
    import gateway.write_storage as storage
    p = root / "src/app.py"
    before = p.read_bytes()
    def fail(*args, **kwargs):
        raise OSError("injected rename failure")
    monkeypatch.setattr(storage.os, "replace", fail)
    with writer(root) as g:
        with pytest.raises(GatewayError):
            g.write_file("src/app.py", "pass\n", digest(before), dry_run=False)
    assert p.read_bytes() == before
    assert not list((root / "src").glob(".gateway-tmp-*"))


def test_change_during_backup_is_detected_before_commit(root, monkeypatch):
    import gateway.write_storage as storage
    original_backup = storage.save_backup
    p = root / "src/app.py"
    before = p.read_bytes()
    def edit_then_backup(*args, **kwargs):
        result = original_backup(*args, **kwargs)
        p.write_bytes(b"editor saved concurrently\n")
        return result
    monkeypatch.setattr(storage, "save_backup", edit_then_backup)
    with writer(root) as g:
        with pytest.raises(GatewayError) as exc:
            g.write_file("src/app.py", "pass\n", digest(before), dry_run=False)
    assert exc.value.code == "conflict"
    assert p.read_bytes() == b"editor saved concurrently\n"


def test_competing_creates_do_not_clobber(root):
    with writer(root) as g:
        def create(i):
            try:
                return g.create_file("race.txt", str(i), dry_run=False)["applied"]
            except GatewayError as exc:
                return exc.code
        with ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(create, range(6)))
    assert results.count(True) == 1
    assert results.count("already_exists") == 5


def test_competing_updates_with_one_hash_only_apply_once(root):
    p = root / "src/app.py"
    sha = digest(p.read_bytes())
    with writer(root) as g:
        def update(i):
            try:
                return g.write_file("src/app.py", f"count = {i + 2}\n", sha, dry_run=False)["applied"]
            except GatewayError as exc:
                return exc.code
        with ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(update, range(6)))
    assert results.count(True) == 1 and results.count("conflict") == 5
    assert len(list((root / ".gateway-backups").glob("*.bak"))) == 1

def test_redacted_source_can_replace_visible_region_with_raw_hash(root):
    p = root / "main.go"
    raw = b"Password: \"actual-secret-value\",\nSampleMigrationMode: oldValue,\n"
    p.write_bytes(raw)
    with writer(root) as g:
        read = g.read_file("main.go")
        assert read["redacted_lines"] == 1
        assert read["file_sha256"] == digest(raw)
        result = g.replace_text(
            "main.go",
            "SampleMigrationMode: oldValue,",
            "SampleMigrationMode: newValue,",
            read["file_sha256"],
            dry_run=False,
        )
    assert result["applied"] is True
    assert p.read_bytes() == b"Password: \"actual-secret-value\",\nSampleMigrationMode: newValue,\n"


def test_redacted_source_replace_still_rejects_stale_hash(root):
    p = root / "main.go"
    raw = b"password = 'keep-me'\ncount = 1\n"
    p.write_bytes(raw)
    with writer(root) as g:
        read = g.read_file("main.go")
        p.write_bytes(b"password = 'keep-me'\ncount = 2\n")
        with pytest.raises(GatewayError) as exc:
            g.replace_text("main.go", "count = 1", "count = 3", read["file_sha256"], dry_run=False)
        assert exc.value.code == "conflict"


def test_redacted_source_still_cannot_be_whole_file_written(root):
    p = root / "settings.py"
    raw = b"password = 'keep-me'\ncount = 1\n"
    p.write_bytes(raw)
    with writer(root) as g:
        read = g.read_file("settings.py")
        assert read["file_sha256"] == digest(raw)
        with pytest.raises(GatewayError) as exc:
            g.write_file("settings.py", "count = 2\n", read["file_sha256"], dry_run=False)
        assert exc.value.code == "sensitive_content"
    assert p.read_bytes() == raw


def test_redacted_source_replace_does_not_expose_secret_only_matches(root):
    p = root / "settings.py"
    raw = b"password = 'keep-me'\ncount = 1\n"
    p.write_bytes(raw)
    with writer(root) as g:
        sha = g.read_file("settings.py")["file_sha256"]
        with pytest.raises(GatewayError) as exc:
            g.replace_text("settings.py", "keep-me", "changed", sha, dry_run=False)
        assert exc.value.code == "match_count"
    assert p.read_bytes() == raw


def test_redacted_source_replaces_only_visible_duplicate_matches(root):
    p = root / "settings.py"
    raw = b"password = 'count = 1'\ncount = 1\n"
    p.write_bytes(raw)
    with writer(root) as g:
        sha = g.read_file("settings.py")["file_sha256"]
        result = g.replace_text("settings.py", "count = 1", "count = 2", sha, dry_run=False)
    assert result["applied"] is True
    assert result["replacements"] == 1
    assert p.read_bytes() == b"password = 'count = 1'\ncount = 2\n"


@pytest.mark.parametrize(
    "new_text",
    [
        "[REDACTED] possible credential",
        "password = 'new-secret'",
        'Password: "new-secret"',
    ],
)
def test_replace_rejects_placeholder_or_new_credential_literal(root, new_text):
    p = root / "settings.py"
    raw = b"password = 'keep-me'\ncount = 1\n"
    p.write_bytes(raw)
    with writer(root) as g:
        sha = g.read_file("settings.py")["file_sha256"]
        with pytest.raises(GatewayError) as exc:
            g.replace_text("settings.py", "count = 1", new_text, sha, dry_run=False)
        assert exc.value.code == "sensitive_content"
    assert p.read_bytes() == raw
