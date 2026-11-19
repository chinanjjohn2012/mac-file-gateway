"""Pure synthetic host policy regression; NO real host/environment/FD/mount IO."""
import copy
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools import rc119_host_metadata_policy_t0 as m


def fixture():
    return {'kind':'SAFE_T0_SYNTHETIC_HOST_METADATA',
            'scope_blob':m.SCOPE_BLOB,'product_head':m.PRODUCT_HEAD,
            'product_tree':m.PRODUCT_TREE,
            'host_identity':{'runner_kind':'DISPOSABLE_GITHUB_HOSTED','os':'macos-15',
                'arch':'arm64','image_identity':'SYNTHETIC_MATCH','uid_consistency':'SYNTHETIC_MATCH',
                'run_attempt':1},
            'categories':dict.fromkeys(m.CATEGORIES,'CLEAR')}


def test_clean_synthetic_is_never_native_or_real_host_pass():
    result=m.evaluate_synthetic_fixture(fixture())
    assert result['synthetic_host_decision']=='HOST_CATEGORICAL_CLEAN_SIMULATED'
    assert result['actual_host_job']=='NOT_RUN'
    assert result['host_metadata_observed'] is False
    assert result['n1b_qualified_pre_foreign'] is False
    assert result['native_execution_authorized'] is False
    assert result['real_external_loaded_source']=='NOT_ATTESTED'
    assert len(m.render_categorical_receipt(result)) < m.MAX_OUTPUT_BYTES


@pytest.mark.parametrize('risk', sorted(m.CATEGORIES))
def test_each_risk_denies_even_if_other_categories_say_clear(risk):
    x=fixture();x['categories'][risk]='RISK'
    assert m.evaluate_synthetic_fixture(x)['synthetic_host_decision']=='HOST_DENIED_SIMULATED'


@pytest.mark.parametrize('unknown', sorted(m.CATEGORIES))
def test_each_unknown_is_not_pass(unknown):
    x=fixture();x['categories'][unknown]='UNKNOWN'
    assert m.evaluate_synthetic_fixture(x)['synthetic_host_decision']=='HOST_UNKNOWN_SIMULATED'


def test_env_clean_but_fd4_ssh_agent_risk_is_denied():
    x=fixture();x['categories']['fd_socket']='RISK'
    assert m.evaluate_synthetic_fixture(x)['reason_codes']==['RISK_FD_SOCKET']


def test_env_clean_unknown_oidc_reachability_is_unknown():
    x=fixture();x['categories']['cloud_identity']='UNKNOWN'
    assert m.evaluate_synthetic_fixture(x)['synthetic_host_decision']=='HOST_UNKNOWN_SIMULATED'


def test_readonly_synthetic_sentinel_does_not_grant_credential_proof():
    x=fixture();x['categories']['sentinel']='CLEAR'
    assert m.evaluate_synthetic_fixture(x)['n1b_qualified_pre_foreign'] is False


@pytest.mark.parametrize('field,value', [('os','linux'), ('arch','amd64'),('runner_kind','self-hosted'),
                                        ('image_identity','DIFFERENT'),('uid_consistency','UNKNOWN'),
                                        ('run_attempt',2),('run_attempt',True)])
def test_mismatched_runner_identity_denied(field,value):
    x=fixture();x['host_identity'][field]=value
    assert m.evaluate_synthetic_fixture(x)['synthetic_host_decision']=='HOST_DENIED_SIMULATED'


def test_closed_schema_rejects_unknown_secret_field_and_leak_free():
    x=fixture();x['secret_value']='SPECIAL_DO_NOT_DISCLOSE'
    report=m.evaluate_synthetic_fixture(x)
    rendered=m.render_categorical_receipt(report)
    assert b'SPECIAL_DO_NOT_DISCLOSE' not in rendered
    assert report['synthetic_host_decision']=='HOST_UNKNOWN_SIMULATED'


def test_category_text_cannot_be_path_value():
    x=fixture();x['categories']['credential_paths']='/secret/private/location'
    report=m.evaluate_synthetic_fixture(x)
    assert report['reason_codes']==['CATEGORIES_NOT_CLOSED']
    assert b'/secret/private/location' not in m.render_categorical_receipt(report)


def test_strange_raw_error_object_not_stringified():
    class Leak:
        def __repr__(self):
            raise RuntimeError('unsafe repr used')
        def __str__(self):
            raise RuntimeError('unsafe str used')
    x=fixture();x['categories']['mounts']=Leak()
    assert m.evaluate_synthetic_fixture(x)['reason_codes']==['CATEGORIES_NOT_CLOSED']


def test_disallow_forged_real_job_and_positive_verdict():
    report=m.evaluate_synthetic_fixture(fixture());report['host_metadata_observed']=True
    with pytest.raises(ValueError,match='UNTRUSTED_RECEIPT_CONTENT'):
        m.render_categorical_receipt(report)
    report=m.evaluate_synthetic_fixture(fixture());report['actual_host_job']='SUCCESS'
    with pytest.raises(ValueError,match='UNTRUSTED_REAL_HOST_CLAIM'):
        m.render_categorical_receipt(report)
    report=m.evaluate_synthetic_fixture(fixture());report['n1b_qualified_pre_foreign']=True
    with pytest.raises(ValueError,match='UNTRUSTED_RECEIPT_CONTENT'):
        m.render_categorical_receipt(report)


def test_render_rejects_injected_reason_with_path_or_token():
    r=m.evaluate_synthetic_fixture(fixture());r['reason_codes']=['RISK_ENVIRONMENT\nTOKEN=FAKE']
    with pytest.raises(ValueError,match='UNTRUSTED_RECEIPT_CONTENT'):
        m.render_categorical_receipt(r)


def test_unknown_category_and_non_dict_denied():
    x=fixture();x['categories']['too_many']='CLEAR'
    assert m.evaluate_synthetic_fixture(x)['reason_codes']==['CATEGORIES_NOT_CLOSED']
    assert m.evaluate_synthetic_fixture(None)['reason_codes']==['SCHEMA_NOT_CLOSED']



def test_bounded_synthetic_json_decoder():
    x=fixture()
    raw=json.dumps(x,sort_keys=True).encode('utf-8')
    assert m.parse_synthetic_fixture_json(raw)['synthetic_host_decision']=='HOST_CATEGORICAL_CLEAN_SIMULATED'
    assert m.parse_synthetic_fixture_json(b'\xff')['reason_codes']==['SCHEMA_NOT_CLOSED']
    assert m.parse_synthetic_fixture_json(b'{broken')['reason_codes']==['SCHEMA_NOT_CLOSED']
    assert m.parse_synthetic_fixture_json(b'a' * (m.MAX_JSON_BYTES+1))['reason_codes']==['SCHEMA_NOT_CLOSED']
    assert m.parse_synthetic_fixture_json('not bytes')['reason_codes']==['SCHEMA_NOT_CLOSED']


def test_host_module_no_actual_io_or_native():
    assert m.OWNER_HOST_RUN_AUTHORIZED is False
    assert m.N1B_QUALIFIED_PRE_FOREIGN is False
    assert m.NATIVE_T1_AUTHORIZED is False
    with pytest.raises(ValueError,match='NATIVE_T1_NOT_AUTHORIZED'):
        m.native_execution_decision()
    code=Path(m.__file__).read_text()
    for word in ('subprocess', 'os.environ', 'os.stat(', 'os.lstat(', 'os.open(', 'urllib',
                 'socket.', 'ctypes', 'mount(', 'os.scandir(', 'os.walk(', 'fstat('):
        assert word not in code
