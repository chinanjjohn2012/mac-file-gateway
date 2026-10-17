"""F3: expired backup pruning validates actual payload bytes before unlink.

All objects and backup directories are created in pytest's synthetic temp root.
"""
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path

import pytest

from gateway import write_storage as storage
from gateway.core import Gateway, GatewayError


def _sha(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _seed(root: Path, *, marker: str, payload: bytes, claimed: bytes):
    state = root / '.gateway-backups'
    state.mkdir(mode=0o700, exist_ok=True)
    timestamp = (datetime.now(timezone.utc) - timedelta(days=16)).strftime('%Y%m%dT%H%M%SZ-')
    name = timestamp + marker * 32
    backup, metadata = state / (name + '.bak'), state / (name + '.json')
    backup.write_bytes(payload)
    metadata.write_text(json.dumps({
        'path': 'sample.py', 'sha256': _sha(claimed),
        'bytes': len(payload), 'backup': backup.name,
    }))
    backup.chmod(0o600)
    metadata.chmod(0o600)
    return backup, metadata


@pytest.fixture
def project(tmp_path):
    root = tmp_path / 'project'
    root.mkdir()
    (root / 'sample.py').write_bytes(b'before\n')
    gateway = Gateway(root, allow_write=True)
    try:
        yield root, gateway
    finally:
        gateway.close()


def test_equal_length_corrupt_expired_pair_survives_real_write(project):
    root, gateway = project
    corrupt = _seed(root, marker='a', payload=b'BAD', claimed=b'old')
    valid = _seed(root, marker='b', payload=b'valid', claimed=b'valid')
    result = gateway.write_file('sample.py', 'after\n', _sha(b'before\n'), dry_run=False)
    assert result['applied'] is True
    assert all(path.exists() for path in corrupt), 'Corrupt pair must remain for manual review'
    assert corrupt[0].read_bytes() == b'BAD'
    assert all(not path.exists() for path in valid), 'Verified old pair should be deleted'
    assert (root / result['backup_path']).read_bytes() == b'before\n'
    assert (root / 'sample.py').read_bytes() == b'after\n'


def test_large_valid_expired_backup_is_hashed_in_chunks(project):
    root, gateway = project
    data = b'chunk' * 80000  # More than several 64 KiB chunks.
    old = _seed(root, marker='c', payload=data, claimed=data)
    result = gateway.write_file('sample.py', 'after\n', _sha(b'before\n'), dry_run=False)
    assert result['applied'] is True
    assert all(not path.exists() for path in old)
    assert (root / result['backup_path']).read_bytes() == b'before\n'


def test_corrupt_expired_pair_still_counts_toward_quota(project, monkeypatch):
    root, gateway = project
    corrupt = _seed(root, marker='d', payload=b'BAD', claimed=b'old')
    monkeypatch.setattr(storage, 'BACKUP_COUNT_LIMIT', 1)
    with pytest.raises(GatewayError) as caught:
        gateway.write_file('sample.py', 'after\n', _sha(b'before\n'), dry_run=False)
    assert caught.value.code == 'backup_full'
    assert all(path.exists() for path in corrupt)
    assert (root / 'sample.py').read_bytes() == b'before\n'
