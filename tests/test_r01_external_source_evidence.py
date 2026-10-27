"""Isolated T0/T1 fixtures for *additional* R01 evidence, not R004 changes."""
import csv
import importlib.util
import json
import py_compile
from pathlib import Path
import subprocess
import sys

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / 'tools' / 'r01_external_source_evidence.py'
# On the test-first RED commit the R01 add-on deliberately does not exist;
# collection must still succeed so raw CI shows individual contract failures.
probe = None
if SCRIPT.is_file():
    spec = importlib.util.spec_from_file_location('r01_external_source_evidence', SCRIPT)
    assert spec and spec.loader
    probe = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(probe)


def _site(tmp_path):
    root = tmp_path / 'site-packages'
    (root / 'safe').mkdir(parents=True)
    (root / 'safe' / '__init__.py').write_text('VALUE = 1\n')
    di = root / 'safe_pkg-1.0.dist-info'
    di.mkdir()
    with (di / 'RECORD').open('w', newline='') as fd:
        w = csv.writer(fd)
        w.writerow(['safe/__init__.py', '', ''])
        w.writerow(['safe_pkg-1.0.dist-info/RECORD', '', ''])
    return root


def test_clean_recorded_import_root_passes(tmp_path):
    site = _site(tmp_path)
    result = probe.site_snapshot([site])
    assert result['site'][0]['dist_record_count'] == 1
    assert result['site'][0]['importable'][0][0] == 'safe/__init__.py'
    assert len(result['site'][0]['importable'][0][1]) == 64

@pytest.mark.parametrize('name', [
    'hidden.py', 'orphan.pyc', 'dangerous.pth', 'shims.so', 'payload.zip', 'binary.pyd'
])
def test_record_unlisted_executable_refused(tmp_path, name):
    site = _site(tmp_path)
    (site / name).write_bytes(b'raise RuntimeError("should never run")\n')
    with pytest.raises(probe.EvidenceError, match='RECORD-unlisted'):
        probe.site_snapshot([site])


def test_recorded_exec_source_hash_change_detected(tmp_path):
    site = _site(tmp_path)
    before = probe.site_snapshot([site])
    (site / 'safe' / '__init__.py').write_text('VALUE = 2\n')
    assert before != probe.site_snapshot([site])


def test_nonimportable_unlisted_metadata_explicitly_counted(tmp_path):
    site = _site(tmp_path)
    (site / 'README.txt').write_text('not importable')
    result = probe.site_snapshot([site])
    assert result['site'][0]['unlisted_nonexecutables'] == 1


def test_site_symlink_refused(tmp_path):
    site = _site(tmp_path)
    (site / 'safe' / 'escape.py').symlink_to(site / 'safe' / '__init__.py')
    with pytest.raises(probe.EvidenceError, match='nonregular/symlink'):
        probe.site_snapshot([site])


def test_pth_outside_root_rejected(tmp_path):
    site = _site(tmp_path)
    pth = site / 'unsafe.pth'
    pth.write_text(str(tmp_path) + '\n')
    with (site / 'safe_pkg-1.0.dist-info' / 'RECORD').open('a') as f:
        f.write('unsafe.pth,,\n')
    with pytest.raises(probe.EvidenceError, match='pth injects outside site'):
        probe.site_snapshot([site])


def test_preimport_cli_isolated_plus_no_site(tmp_path):
    site = _site(tmp_path)
    output = tmp_path / 'evidence.json'
    result = subprocess.run([sys.executable,'-B','-I','-S',str(SCRIPT),'preimport',
                             '--site-root',str(site),'--snapshot',str(output)],
                            capture_output=True,text=True,check=False)
    assert result.returncode == 0, (result.stdout,result.stderr)
    assert 'R01_SITE_UNLISTED_EXECUTABLES=NONE_DETECTED' in result.stdout
    assert output.is_file()
    again = subprocess.run([sys.executable,'-B','-I','-S',str(SCRIPT),'verify',
                             '--site-root',str(site),'--snapshot',str(output)],
                            capture_output=True,text=True,check=False)
    assert again.returncode == 0, (again.stdout,again.stderr)
    (site/'unknown.py').write_text('raise AssertionError("not executed")')
    rejected = subprocess.run([sys.executable,'-B','-I','-S',str(SCRIPT),'verify',
                             '--site-root',str(site),'--snapshot',str(output)],
                            capture_output=True,text=True,check=False)
    assert rejected.returncode == 2
    assert 'RECORD-unlisted' in rejected.stderr


def test_preimport_requires_dash_I_dash_S(tmp_path):
    site = _site(tmp_path)
    output = tmp_path / 'bad.json'
    result = subprocess.run([sys.executable,'-B','-I',str(SCRIPT),'preimport',
                             '--site-root',str(site),'--snapshot',str(output)],
                            capture_output=True,text=True,check=False)
    assert result.returncode == 2
    assert not output.exists()


def test_extra_python_import_root_rejected(tmp_path):
    site = _site(tmp_path)
    snapshot = probe.site_snapshot([site])
    repo = tmp_path/'repo'
    repo.mkdir()
    payload = {"schema":1,"executable":snapshot['interpreter'],
               "prefix":snapshot['prefix'],"user_site_enabled":False,
               "sys_path":[str(repo),str(site),str(tmp_path/'rogue')]}
    observation=tmp_path/'runtime.json'
    observation.write_text(json.dumps(payload))
    with pytest.raises(probe.EvidenceError,match='unexpected actual Python import root'):
        probe.verify_runtime(observation,repo,snapshot)


def test_known_scoped_site_and_repo_roots_classified(tmp_path):
    site = _site(tmp_path)
    snapshot = probe.site_snapshot([site])
    repo = tmp_path/'repo'
    repo.mkdir()
    payload={"schema":1,"executable":snapshot['interpreter'],
             "prefix":snapshot['prefix'],"user_site_enabled":False,
             "sys_path":[str(repo),str(site)]}
    obs=tmp_path/'runtime.json'
    obs.write_text(json.dumps(payload))
    categories=[x[1] for x in probe.verify_runtime(obs,repo,snapshot)['observed']]
    assert categories==['HEAD_REPOSITORY_G05','INSTALLED_SITE_ROOT']


def test_r004_existing_record_only_contract_remains_unchanged():
    # Marker test: this independent supplement does not replace or import
    # tools/ci_dependency_provenance.py and never changes its declared scope.
    assert 'ci_dependency_provenance' not in SCRIPT.read_text()


def test_r01_actual_import_source_tool_present():
    assert SCRIPT.is_file(), "r004 RED: required additional R01 evidence source is not committed"

def test_r004_record_only_verifier_explicit_scope_unchanged():
    original = Path(__file__).resolve().parents[1] / 'tools' / 'ci_dependency_provenance.py'
    src = original.read_text('utf-8')
    assert 'CI_UNLISTED_IMPORTABLE_FILES=NOT_ASSESSED' in src
    assert 'LOCKED_WHEELS_AND_RECORD_FILES_ONLY' in src


def test_pip_like_unlisted_optimized_pyc_accepted_only_if_reproducible(tmp_path):
    site = _site(tmp_path)
    src = site/'safe'/'__init__.py'
    cache = site/'safe'/'__pycache__'
    cache.mkdir()
    pyc = cache/'__init__.cpython-313.opt-1.pyc'
    py_compile.compile(str(src), cfile=str(pyc), doraise=True, optimize=1)
    result = probe.site_snapshot([site])
    assert result['site'][0]['derived_bytecode'] == [
        ['safe/__pycache__/__init__.cpython-313.opt-1.pyc', 'safe/__init__.py', True]
    ]
    old = pyc.read_bytes()
    pyc.write_bytes(old[:-1] + bytes([old[-1] ^ 1]))
    with pytest.raises(probe.EvidenceError, match='payload differs'):
        probe.site_snapshot([site])


def test_stale_pyc_header_only_accepted_with_identical_recompiled_payload(tmp_path):
    site = _site(tmp_path)
    src = site/'safe'/'__init__.py'
    cache = site/'safe'/'__pycache__'
    cache.mkdir()
    pyc = cache/'__init__.cpython-313.opt-1.pyc'
    py_compile.compile(str(src), cfile=str(pyc), doraise=True, optimize=1)
    original = bytearray(pyc.read_bytes())
    # Wrong cache invalidation timestamp cannot be called matching PEP552,
    # but the on-disk executable bytecode is still fully reproducible.
    original[8:12] = (0).to_bytes(4, 'little')
    pyc.write_bytes(original)
    snapshot = probe.site_snapshot([site])
    assert snapshot['site'][0]['derived_bytecode'][0][2] is False
    original[-1] ^= 1
    pyc.write_bytes(original)
    with pytest.raises(probe.EvidenceError, match='payload differs'):
        probe.site_snapshot([site])
