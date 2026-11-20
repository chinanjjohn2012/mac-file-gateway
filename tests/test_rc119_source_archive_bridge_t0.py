"""Adversarial offline tests; never install/extract/import archived Go/Wheels."""
import hashlib
import io
import stat
import sys
import zipfile
import warnings
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools import rc119_source_archive_bridge as m


def build_zip(entries, *, compression=zipfile.ZIP_STORED, special=None):
    buff = io.BytesIO()
    with zipfile.ZipFile(buff, 'w') as zipf:
        for n, raw in entries:
            info = zipfile.ZipInfo(n)
            info.compress_type = compression
            info.create_system = 3
            info.external_attr = ((stat.S_IFLNK if n == special else stat.S_IFREG) | 0o600) << 16
            with warnings.catch_warnings():
                warnings.filterwarnings("ignore", message="Duplicate name:", category=UserWarning)
                zipf.writestr(info, raw)
    return buff.getvalue()


def test_successful_synthetic_fixture_never_real_attestation():
    b = build_zip([('test/a.whl', b'fake bytes')])
    actual = m.audit_fixture_zip(b, {'a.whl': (10, hashlib.sha256(b'fake bytes').hexdigest())})
    assert actual == {'fixture_count': 1, 'evidence_grade': 'SYNTHETIC_SAFE_T0_ONLY',
                      'native_execution_authorized': False}


@pytest.mark.parametrize('changed', [
    [('test/../a.whl', b'ok')],
    [('test/a.whl', b'ok'), ('test/a.whl', b'ok')],
    [('test/a.whl', b'ok'), ('test/extra.whl', b'ok')],
    [('/absolute.whl', b'ok')],
    [('other/a.whl', b'ok')],
])
def test_unknown_duplicate_traversal_and_missing_member_rejected(changed):
    with pytest.raises(m.SourceBridgeDenied):
        m.audit_fixture_zip(build_zip(changed), {'a.whl': (2, hashlib.sha256(b'ok').hexdigest())})


def test_wrong_digest_rejected_even_when_size_matches():
    with pytest.raises(m.SourceBridgeDenied, match='ARCHIVE_SHA256_DRIFT'):
        m.audit_fixture_zip(build_zip([('test/a.whl', b'no')]),
                            {'a.whl': (2, hashlib.sha256(b'ok').hexdigest())})


def test_wrong_length_rejected_before_read():
    with pytest.raises(m.SourceBridgeDenied, match='ARCHIVE_BYTE_LENGTH_DRIFT'):
        m.audit_fixture_zip(build_zip([('test/a.whl', b'a')]),
                            {'a.whl': (2, hashlib.sha256(b'aa').hexdigest())})


def test_archive_symlink_rejected_without_extracting():
    with pytest.raises(m.SourceBridgeDenied, match='ARCHIVE_MEMBER_TYPE_OR_BUDGET'):
        m.audit_fixture_zip(build_zip([('test/a.whl', b'x')], special='test/a.whl'),
                            {'a.whl': (1, hashlib.sha256(b'x').hexdigest())})


def test_compressed_member_rejected():
    with pytest.raises(m.SourceBridgeDenied, match='ARCHIVE_MEMBER_TYPE_OR_BUDGET'):
        m.audit_fixture_zip(build_zip([('test/a.whl', b'data' * 100)], compression=zipfile.ZIP_DEFLATED),
                            {'a.whl': (400, hashlib.sha256(b'data' * 100).hexdigest())})


@pytest.mark.parametrize('garbage', [b'not a zip', b'', b'PK\x03\x04'])
def test_invalid_zip_fails_closed(garbage):
    with pytest.raises(m.SourceBridgeDenied):
        m.audit_fixture_zip(garbage, {'a.whl': (1, 'a'*64)})


def test_test_oracle_refuses_unbounded_bytes():
    with pytest.raises(m.SourceBridgeDenied):
        m.audit_fixture_zip(b'a' * 2_000_001, {})


def test_real_bundle_read_only_evidence_from_previous_source_only_job():
    p = Path('/mnt/data/rc119-source-only-ten-original-archives-20261119.zip')
    if not p.is_file():
        pytest.skip('Real historical artifact not available in CI: NOT_RUN, no inherited proof')
    result = m.audit_original_archive_bundle(p)
    assert result['actual_archives_verified'] == 10
    assert result['artifact_sha256'] == m.ARTIFACT_SHA256
    assert result['source_bundle_head'] == m.PR101_HEAD != result['candidate_product_head']
    assert result['installed_or_loaded_source'] == 'NOT_ATTESTED'
    assert result['current_22_runtime_input_categories'] == 'NOT_ATTESTED'
    assert result['native_execution_authorized'] is False


def test_wrong_exact_original_artifact_rejected_without_payload_execution(tmp_path):
    p = tmp_path / 'bad.zip'
    p.write_bytes(build_zip([('test/a.whl', b'harmless')]))
    with pytest.raises(m.SourceBridgeDenied, match='WRONG_ARTIFACT_TYPE_OR_SIZE'):
        m.audit_original_archive_bundle(p)


def test_local_symlink_to_artifact_rejected(tmp_path):
    p = tmp_path / 'artifact.zip'
    p.symlink_to('/mnt/data/rc119-source-only-ten-original-archives-20261119.zip')
    with pytest.raises(m.SourceBridgeDenied, match='INVALID_LOCAL_ARTIFACT_PATH'):
        m.audit_original_archive_bundle(p)


def test_never_enables_native_or_downloads():
    assert m.NATIVE_EXECUTION_AUTHORIZED is False
    with pytest.raises(m.SourceBridgeDenied, match='NATIVE_T1_NOT_AUTHORIZED'):
        m.native_execution_decision('anything')
    src=Path(m.__file__).read_text()
    for snippet in ('subprocess', 'pip install', 'urllib.request', 'socket.connect(', 'extractall(', 'os.system('):
        assert snippet not in src
