import os
import importlib.util
from pathlib import Path
import sys
import pytest

spec = importlib.util.spec_from_file_location('gateway_private_fs_isolated', Path(__file__).resolve().parents[1] / 'gateway/private_fs.py')
private_fs = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = private_fs
spec.loader.exec_module(private_fs)


def private_config(tmp_path, text='{"schema_version":1}'):
    directory = tmp_path / 'config'
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    path = directory / 'gateway.json'
    path.write_text(text)
    path.chmod(0o600)
    return directory, path


def test_load_safe_private_json(tmp_path):
    _, f = private_config(tmp_path)
    assert private_fs.read_private_json(f) == {'schema_version': 1}


@pytest.mark.parametrize('text', ['{"a":1,"a":2}', '{"a":1,"\\u0061":2}', '{"a": NaN}', '{"a":Infinity}', '[1,2]', '"no"'])
def test_bad_json(tmp_path, text):
    _, f = private_config(tmp_path, text)
    with pytest.raises(private_fs.PrivateFileError):
        private_fs.read_private_json(f)


def test_private_config_not_gated_by_local_permissions(tmp_path):
    d, f = private_config(tmp_path)
    # Multi-Workspace intentionally trusts local OS accounts. Only Web/MCP
    # API path boundaries are enforced. Keep strict filesystem permissions
    # as a recommendation rather than a startup prerequisite.
    f.chmod(0o644)
    d.chmod(0o777)
    assert private_fs.read_private_json(f) == {'schema_version': 1}
    f.chmod(0o666)
    assert private_fs.read_private_json(f) == {'schema_version': 1}


def test_reject_symlink_parents_and_leaf(tmp_path):
    d, f = private_config(tmp_path)
    alias = tmp_path / 'alias'
    alias.symlink_to(d)
    with pytest.raises(private_fs.PrivateFileError):
        private_fs.read_private_json(alias / 'gateway.json')
    (d / 'link.json').symlink_to(f)
    with pytest.raises(private_fs.PrivateFileError):
        private_fs.read_private_json(d / 'link.json')


def test_reject_hardlinks_and_special_files(tmp_path):
    d, f = private_config(tmp_path)
    os.link(f, d / 'second.json')
    with pytest.raises(private_fs.PrivateFileError):
        private_fs.read_private_json(f)
    os.mkfifo(d / 'fifo.json', mode=0o600)
    with pytest.raises(private_fs.PrivateFileError):
        private_fs.read_private_json(d / 'fifo.json')


def test_reject_oversized_without_read(tmp_path):
    _, f = private_config(tmp_path, 'x' * (256 * 1024 + 1))
    with pytest.raises(private_fs.PrivateFileError):
        private_fs.read_private_json(f)


def test_parse_depth_and_nodes_budget():
    deep = b'{' + b'"a":{' * 34 + b'"x":1' + b'}' * 34 + b'}'
    with pytest.raises(private_fs.PrivateFileError):
        private_fs.parse_strict_json(deep)
    with pytest.raises(private_fs.PrivateFileError):
        private_fs.parse_strict_json(b'{"a":[1,2,3]}', max_nodes=2)



def test_directory_fd_identity_survives_name_swap(tmp_path):
    d, _ = private_config(tmp_path)
    pinned = private_fs.open_pinned_directory(d, private_leaf=True)
    try:
        d.rename(tmp_path / 'old-config')
        d.mkdir(mode=0o700)
        new = private_fs.open_pinned_directory(d, private_leaf=True)
        try:
            assert os.fstat(pinned.fd).st_ino != os.fstat(new.fd).st_ino
        finally:
            new.close()
    finally:
        pinned.close()


def test_group_writable_runtime_and_control_directory_allowed(tmp_path):
    parent = tmp_path / 'homebrew'
    parent.mkdir()
    cellar = parent / 'Cellar'
    cellar.mkdir()
    cellar.chmod(0o775)
    for private in (False, True):
        pinned = private_fs.open_pinned_directory(cellar, private_leaf=private)
        try:
            assert pinned.ancestor_ids[-1] == (cellar.stat().st_dev, cellar.stat().st_ino)
        finally:
            pinned.close()


def test_other_writable_ancestors_are_not_an_admission_gate(tmp_path):
    d, f = private_config(tmp_path)
    d.parent.chmod(0o777)
    d.chmod(0o777)
    f.chmod(0o644)
    assert private_fs.read_private_json(f) == {'schema_version': 1}


def test_workspace_root_with_0777_and_world_writable_ancestor_allowed(tmp_path):
    project = tmp_path / 'projects'
    project.mkdir()
    root = project / 'rtb'
    root.mkdir()
    root.chmod(0o777)
    project.chmod(0o777)
    pinned = private_fs.open_pinned_directory(root)
    try:
        assert pinned.ancestor_ids[-1] == (root.stat().st_dev, root.stat().st_ino)
    finally:
        pinned.close()


def test_config_fd_type_identity_guards_preserved(tmp_path):
    d, f = private_config(tmp_path)
    os.link(f, d / 'second.json')
    with pytest.raises(private_fs.PrivateFileError, match='singly linked'):
        private_fs.read_private_json(f)
    (d / 'another.json').symlink_to(f)
    with pytest.raises(private_fs.PrivateFileError):
        private_fs.read_private_json(d / 'another.json')
