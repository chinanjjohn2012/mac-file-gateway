"""Directory creation: exercise real temporary trees and opt-in policy.

These tests fail if the API is missing, previews write, mkdir follows links,
recursive creation crosses scope, or an error hides already-created paths.
"""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import errno
import os
import stat

import pytest

from gateway.core import Gateway, GatewayError, Limits


@pytest.fixture
def root(tmp_path):
    p = tmp_path / "project"
    p.mkdir()
    (p / "src").mkdir()
    return p


@contextmanager
def gateway(root, **kwargs):
    g = Gateway(root, allow_write=True, **kwargs)
    try:
        yield g
    finally:
        g.close()


def test_mkdir_preview_has_no_side_effects(root):
    before = set(root.iterdir())
    with gateway(root) as g:
        r = g.create_directory("src/new")
    assert r["operation"] == "mkdir"
    assert r["planned_paths"] == ["src/new"]
    assert r["created_paths"] == []
    assert r["dry_run"] is True and r["applied"] is False and r["changed"] is True
    assert r["already_exists"] is False
    assert set(root.iterdir()) == before and not (root / "src/new").exists()


def test_mkdir_apply_and_create_file_inside(root):
    with gateway(root) as g:
        r = g.create_directory("src/new", dry_run=False)
        assert r["applied"] is True and r["created_paths"] == ["src/new"]
        assert stat.S_IMODE((root / "src/new").stat().st_mode) & 0o077 == 0
        g.create_file("src/new/hello.py", "print('hello')\n", dry_run=False)
        assert g.read_file("src/new/hello.py")["content"] == "1: print('hello')"


def test_recursive_preview_then_apply(root):
    with gateway(root) as g:
        r = g.create_directory("one/two/three", parents=True)
        assert r["planned_paths"] == ["one", "one/two", "one/two/three"]
        assert not (root / "one").exists() and not (root / ".gateway-backups").exists()
        r = g.create_directory("one/two/three", parents=True, dry_run=False)
    assert r["created_paths"] == ["one", "one/two", "one/two/three"]
    assert (root / "one/two/three").is_dir()


@pytest.mark.parametrize("dry_run", [True, False])
def test_missing_parent_without_parents_is_error(root, dry_run):
    with gateway(root) as g, pytest.raises(GatewayError) as exc:
        g.create_directory("missing/child", dry_run=dry_run)
    assert exc.value.code == "parent_missing"
    assert not (root / "missing").exists() and not (root / ".gateway-backups").exists()


@pytest.mark.parametrize("dry_run", [True, False])
def test_existing_directory_noop_by_default(root, dry_run):
    with gateway(root) as g:
        r = g.create_directory("src", dry_run=dry_run)
    assert r["already_exists"] is True
    assert not r["applied"] and not r["changed"]
    assert r["created_paths"] == r["planned_paths"] == []
    assert not (root / ".gateway-backups").exists()


@pytest.mark.parametrize("dry_run", [True, False])
def test_existing_directory_strict_mode(root, dry_run):
    with gateway(root) as g, pytest.raises(GatewayError) as exc:
        g.create_directory("src", exist_ok=False, dry_run=dry_run)
    assert exc.value.code == "already_exists"


def test_file_is_never_treated_as_existing_directory(root):
    (root / "notes.txt").write_text("keep")
    with gateway(root) as g, pytest.raises(GatewayError) as exc:
        g.create_directory("notes.txt", parents=True, exist_ok=True, dry_run=False)
    assert exc.value.code == "already_exists"
    assert (root / "notes.txt").read_text() == "keep"


def test_file_in_parent_chain_is_rejected(root):
    (root / "notes.txt").write_text("keep")
    with gateway(root) as g, pytest.raises(GatewayError):
        g.create_directory("notes.txt/new", parents=True, dry_run=False)
    assert (root / "notes.txt").read_text() == "keep"


def test_read_only_blocks_directory_creation(root):
    g = Gateway(root)
    try:
        with pytest.raises(GatewayError) as exc:
            g.create_directory("new", dry_run=False)
        assert exc.value.code == "write_disabled"
        assert not g.info()["write_policy"]["directory_creation"]["enabled"]
    finally:
        g.close()
    assert not (root / "new").exists()


@pytest.mark.parametrize("option", ["parents", "exist_ok", "dry_run"])
@pytest.mark.parametrize("value", ["false", "true", 0, 1, None])
def test_mkdir_boolean_flags_are_strict(root, option, value):
    with gateway(root) as g, pytest.raises(GatewayError) as exc:
        g.create_directory("new", **{option: value})
    assert exc.value.code == "invalid_argument" and not (root / "new").exists()


@pytest.mark.parametrize("path", ["", ".", "./", "../outside", "/tmp/outside", "src/../outside", "~/outside", "x\\y", "x\x00y"])
def test_mkdir_rejects_root_and_unsafe_paths(root, path):
    with gateway(root) as g, pytest.raises(GatewayError) as exc:
        g.create_directory(path, parents=True, dry_run=False)
    assert exc.value.code == "invalid_path"
    assert not (root / ".gateway-backups").exists()


@pytest.mark.parametrize("path", [".git/hooks", "safe/.env/child", "node_modules/pkg", "safe/secrets/child", "safe/key.pem/child"])
def test_all_recursive_components_checked_before_writing(root, path):
    with gateway(root) as g, pytest.raises(GatewayError) as exc:
        g.create_directory(path, parents=True, dry_run=False)
    assert exc.value.code == "blocked_path"
    assert list(root.iterdir()) == [root / "src"]


def test_exclusions_checked_before_any_mkdir(root):
    with gateway(root, excludes=("safe/nope",)) as g, pytest.raises(GatewayError):
        g.create_directory("safe/nope/leaf", parents=True, dry_run=False)
    assert not (root / "safe").exists()


def test_scope_contains_every_new_directory(root):
    with gateway(root, write_paths=("src/generated",)) as g:
        r = g.create_directory("src/generated/helpers", parents=True, dry_run=False)
        assert r["created_paths"] == ["src/generated", "src/generated/helpers"]
        with pytest.raises(GatewayError) as exc:
            g.create_directory("src/other", dry_run=False)
        assert exc.value.code == "write_scope"


def test_recursive_creation_does_not_broaden_scope_to_missing_ancestors(root):
    with gateway(root, write_paths=("missing/allowed",)) as g, pytest.raises(GatewayError) as exc:
        g.create_directory("missing/allowed/child", parents=True, dry_run=False)
    assert exc.value.code == "write_scope"
    assert not (root / "missing").exists()


@pytest.mark.parametrize("path", ["src-other/new", "SRC/new"])
def test_scope_is_component_and_case_exact(root, path):
    with gateway(root, write_paths=("src",)) as g, pytest.raises(GatewayError) as exc:
        g.create_directory(path, parents=True, dry_run=False)
    assert exc.value.code == "write_scope"


def test_file_scope_also_rejects_case_alias(root):
    (root / "SRC").mkdir(exist_ok=True)
    with gateway(root, write_paths=("src",)) as g, pytest.raises(GatewayError) as exc:
        g.create_file("SRC/escape.py", "pass\n", dry_run=False)
    assert exc.value.code == "write_scope"


@pytest.mark.parametrize("suffix", ["", "/new"])
def test_symlink_to_outside_not_followed(root, tmp_path, suffix):
    outside = tmp_path / "outside"
    outside.mkdir()
    (root / "link").symlink_to(outside, target_is_directory=True)
    with gateway(root) as g, pytest.raises(GatewayError) as exc:
        g.create_directory("link" + suffix, parents=True, exist_ok=True, dry_run=False)
    assert exc.value.code == "blocked_type"
    assert list(outside.iterdir()) == []


def test_dangling_symlink_rejected(root):
    (root / "link").symlink_to(root / "absent", target_is_directory=True)
    with gateway(root) as g, pytest.raises(GatewayError) as exc:
        g.create_directory("link", dry_run=False)
    assert exc.value.code == "blocked_type" and not (root / "absent").exists()


def test_depth_and_component_bytes_prevalidated(root):
    with gateway(root, limits=Limits(max_depth=3)) as g:
        for path in ["a/b/c/d", "a/" + "x" * 256, "a/" + "\u4e2d" * 86]:
            with pytest.raises(GatewayError) as exc:
                g.create_directory(path, parents=True, dry_run=False)
            assert exc.value.code == "invalid_path"
    assert not (root / "a").exists()


def test_unicode_spaces_and_normalized_separators(root):
    path = "src//./new \u4e2d\u6587/child/"
    with gateway(root) as g:
        r = g.create_directory(path, parents=True, dry_run=False)
    assert r["path"] == "src/new \u4e2d\u6587/child"
    assert (root / r["path"]).is_dir()


def test_concurrent_gateways_create_once(root):
    def make(_):
        with gateway(root) as g:
            return g.create_directory("src/concurrent/deep", parents=True, dry_run=False)
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(make, range(8)))
    assert sum(r["applied"] for r in results) == 1
    assert (root / "src/concurrent/deep").is_dir()


def test_partial_failure_reports_created_paths_and_no_raw_os_message(root, monkeypatch):
    original = os.mkdir
    def fail(name, *args, **kwargs):
        if name == "second":
            raise OSError(errno.ENOSPC, "/private/absolute/path must not leak")
        return original(name, *args, **kwargs)
    monkeypatch.setattr(os, "mkdir", fail)
    with gateway(root) as g, pytest.raises(GatewayError) as exc:
        g.create_directory("first/second/third", parents=True, dry_run=False)
    assert exc.value.code == "write_failed"
    assert exc.value.details["created_paths"] == ["first"]
    assert exc.value.details["partial"] is True
    assert "/private/absolute" not in str(exc.value)
    assert (root / "first").is_dir() and not (root / "first/second").exists()


def test_symlink_swap_after_mkdir_does_not_follow_link(root, tmp_path, monkeypatch):
    outside = tmp_path / "outside"
    outside.mkdir()
    original = os.mkdir
    def swap(name, *args, **kwargs):
        result = original(name, *args, **kwargs)
        if name == "swap":
            os.rmdir(name, dir_fd=kwargs["dir_fd"])
            os.symlink(outside, name, dir_fd=kwargs["dir_fd"])
        return result
    monkeypatch.setattr(os, "mkdir", swap)
    with gateway(root) as g, pytest.raises(GatewayError):
        g.create_directory("swap/child", parents=True, dry_run=False)
    assert list(outside.iterdir()) == []


def test_sync_failure_is_success_with_warning_not_false_failure(root, monkeypatch):
    def fail(_):
        raise OSError(errno.EIO, "sync failed")
    monkeypatch.setattr(os, "fsync", fail)
    with gateway(root) as g:
        r = g.create_directory("new", dry_run=False)
    assert r["applied"] and r["warnings"] and (root / "new").is_dir()


def test_info_declares_directory_policy(root):
    with gateway(root) as g:
        info = g.info()
    assert info["version"] == "2.4.0"
    policy = info["write_policy"]["directory_creation"]
    assert policy["enabled"] is True
    assert policy["parents_default"] is False
    assert policy["exist_ok_default"] is True
    assert policy["max_depth"] == 20


def test_directory_open_closes_descriptor_when_fstat_fails(root, monkeypatch):
    from gateway.directories import _open_child
    original_open, original_fstat = os.open, os.fstat
    parent = original_open(root, os.O_RDONLY | os.O_DIRECTORY)
    opened = []
    def track(*args, **kwargs):
        fd = original_open(*args, **kwargs)
        opened.append(fd)
        return fd
    def fail(_):
        raise OSError(errno.EIO, 'simulated fstat failure')
    try:
        with monkeypatch.context() as patch:
            patch.setattr(os, 'open', track)
            patch.setattr(os, 'fstat', fail)
            with pytest.raises(OSError):
                _open_child(parent, 'src', final=True)
        assert len(opened) == 1
        with pytest.raises(OSError):
            original_fstat(opened[0])
    finally:
        for fd in opened:
            try:
                os.close(fd)
            except OSError:
                pass
        os.close(parent)
