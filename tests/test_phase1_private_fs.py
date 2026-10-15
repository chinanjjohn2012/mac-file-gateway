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


def test_reject_insecure_file_and_directory_permissions(tmp_path):
    d, f = private_config(tmp_path)
    f.chmod(0o644)
    with pytest.raises(private_fs.PrivateFileError):
        private_fs.read_private_json(f)
    f.chmod(0o600)
    d.chmod(0o755)
    with pytest.raises(private_fs.PrivateFileError):
        private_fs.read_private_json(f)


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


def test_acl_fail_closed_invalid_fd():
    assert private_fs.check_extended_acl(-1) is private_fs.ACLState.ACL_CHECK_ERROR


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
