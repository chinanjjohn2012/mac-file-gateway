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

# r005 independent disposable T0/T1 adversarial ZIP/zipapp path coverage.
import zipfile


def _r005_zip(site: Path, name: str) -> Path:
    archive = site / name
    with zipfile.ZipFile(archive, "w") as zipped:
        zipped.writestr("r005_zip_probe.py", "VALUE=12345\n")
    return archive


def _r005_record(site: Path, rel: str) -> None:
    with (site / "safe_pkg-1.0.dist-info" / "RECORD").open("a", newline="") as stream:
        csv.writer(stream).writerow([rel, "", ""])


def _r005_pth(site: Path, name: str) -> None:
    (site / "legal.pth").write_text(name + "\n")
    _r005_record(site, "legal.pth")


def _r005_observation(site: Path, tmp_path: Path, snapshot: dict, archive: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    obs = tmp_path / "r005-runtime.json"
    obs.write_text(json.dumps({
        "schema": 1, "executable": snapshot["interpreter"],
        "prefix": snapshot["prefix"], "user_site_enabled": False,
        "sys_path": [str(repo), str(site), str(archive)],
        "loaded_origins": [],
    }))
    return obs, repo


@pytest.mark.parametrize("name", ["unlisted.pyz", "unlisted.asset", "noextension"])
def test_r005_unlisted_zipimport_via_recorded_pth_denied(tmp_path, name):
    site = _site(tmp_path)
    archive = _r005_zip(site, name)
    _r005_pth(site, name)
    assert zipfile.is_zipfile(archive)
    # Execute only harmless code in a brand-new temporary Python site.
    actual = subprocess.run([
        sys.executable, "-B", "-I", "-S", "-c",
        "import sys,site;site.addsitedir(sys.argv[1]);"
        "import r005_zip_probe;print(r005_zip_probe.VALUE)", str(site),
    ], capture_output=True, text=True, check=False)
    assert actual.returncode == 0, actual.stderr
    assert actual.stdout.strip() == "12345"
    with pytest.raises(probe.EvidenceError, match="RECORD-unlisted"):
        probe.site_snapshot([site])


@pytest.mark.parametrize("name", ["recorded.pyz", "recorded.asset"])
def test_r005_recorded_zip_and_pth_legally_hashed(tmp_path, name):
    site = _site(tmp_path)
    archive = _r005_zip(site, name)
    _r005_record(site, name)
    _r005_pth(site, name)
    assert zipfile.is_zipfile(archive)
    result = probe.site_snapshot([site])
    found = [row[0] for row in result["site"][0]["importable"]]
    assert name in found and "legal.pth" in found
    assert result["site"][0]["unlisted_nonexecutables"] == 0


def test_r005_recorded_zip_bytes_change_not_inherited(tmp_path):
    site = _site(tmp_path)
    archive = _r005_zip(site, "tracked.pyz")
    _r005_record(site, archive.name)
    first = probe.site_snapshot([site])
    assert archive.name in [row[0] for row in first["site"][0]["importable"]]
    with archive.open("ab") as stream:
        stream.write(b"changed since preimport")
    assert probe.site_snapshot([site]) != first


def test_r005_corrupt_recorded_pyz_via_pth_rejected(tmp_path):
    site = _site(tmp_path)
    archive = site / "corrupt.pyz"
    archive.write_bytes(b"corrupt non-ZIP bytes")
    _r005_record(site, archive.name)
    _r005_pth(site, archive.name)
    assert not zipfile.is_zipfile(archive)
    with pytest.raises(probe.EvidenceError, match="invalid|corrupt|ZIP"):
        probe.site_snapshot([site])


def test_r005_unlisted_plain_metadata_still_allowed(tmp_path):
    site = _site(tmp_path)
    (site / "README.note").write_bytes(b"plain nonzip documentation")
    assert probe.site_snapshot([site])["site"][0]["unlisted_nonexecutables"] == 1


def test_r005_runtime_unattested_site_zip_root_rejected(tmp_path):
    site = _site(tmp_path)
    snapshot = probe.site_snapshot([site])
    archive = _r005_zip(site, "late.pyz")
    runtime, repo = _r005_observation(site, tmp_path, snapshot, archive)
    with pytest.raises(probe.EvidenceError, match="unattested|unlisted|ZIP"):
        probe.verify_runtime(runtime, repo, snapshot)


def test_r005_runtime_changed_recorded_zip_root_rejected(tmp_path):
    site = _site(tmp_path)
    archive = _r005_zip(site, "recorded.pyz")
    _r005_record(site, archive.name)
    snapshot = probe.site_snapshot([site])
    runtime, repo = _r005_observation(site, tmp_path, snapshot, archive)
    assert probe.verify_runtime(runtime, repo, snapshot)["observed"][-1][1] == "INSTALLED_SITE_ROOT"
    with archive.open("ab") as stream:
        stream.write(b"changed after preimport")
    with pytest.raises(probe.EvidenceError, match="changed|mismatch|unattested"):
        probe.verify_runtime(runtime, repo, snapshot)


def test_r005_real_recorded_zip_member_origin_attested(tmp_path):
    site = _site(tmp_path)
    archive = _r005_zip(site, "legitimate.pyz")
    _r005_record(site, archive.name)
    _r005_pth(site, archive.name)
    snapshot = probe.site_snapshot([site])
    runtime, repo = _r005_observation(site, tmp_path, snapshot, archive)
    observation = json.loads(runtime.read_text())
    # CPython zipimport module.__file__ is archive.pyz/inner.py, not an OS file.
    observation["loaded_origins"] = [
        ["r005_zip_probe", str(archive) + "/r005_zip_probe.py"]
    ]
    runtime.write_text(json.dumps(observation))
    verified = probe.verify_runtime(runtime, repo, snapshot)
    assert verified["attested_site_module_origins"] == 1


# r006 reviewer-derived lexical and symlink import-root/source-origin negatives.
# These are harmless, disposable CPython imports, not Gateway Exec or signals.
import hashlib


@pytest.mark.parametrize("anchor", ["repo", "site"])
def test_r006_actual_recorded_pth_parent_escape_import_root_denied(tmp_path, anchor):
    site = _site(tmp_path)
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "r006_external_probe.py").write_text("VALUE=42\n")
    escaped = str((repo if anchor == "repo" else site) / ".." / "outside")
    (site / "escape_r006.pth").write_text(
        "import sys;sys.path.insert(0," + repr(escaped) + ")\n"
    )
    _r005_record(site, "escape_r006.pth")
    snapshot = probe.site_snapshot([site])
    # Execute genuine site.addsitedir() and importlib through a disposable interpreter.
    command = (
        "import sys,site,json;"
        "site.addsitedir(sys.argv[1]);"
        "import r006_external_probe;"
        "print(json.dumps({'sys_path':sys.path,"
        "'origin':r006_external_probe.__file__,"
        "'value':r006_external_probe.VALUE}))"
    )
    actual = subprocess.run(
        [sys.executable, "-B", "-I", "-S", "-c", command, str(site)],
        capture_output=True, text=True, check=False
    )
    assert actual.returncode == 0, actual.stderr
    runtime = json.loads(actual.stdout)
    assert runtime["value"] == 42
    assert ".." in Path(runtime["origin"]).parts
    assert Path(runtime["origin"]).resolve().parent == outside.resolve()
    observation = tmp_path / "r006-runtime.json"
    observation.write_text(json.dumps({
        "schema": 1, "executable": snapshot["interpreter"],
        "prefix": snapshot["prefix"], "user_site_enabled": False,
        "sys_path": [str(repo)] + runtime["sys_path"],
        # For the site case the root must fail independently of module-origin
        # validation, whose old path already rejects the unlisted site member.
        "loaded_origins": ([["r006_external_probe", runtime["origin"]]]
                           if anchor == "repo" else []),
    }))
    with pytest.raises(probe.EvidenceError, match="unexpected|noncanonical|unattested"):
        probe.verify_runtime(observation, repo, snapshot)


def test_r006_actual_parent_escape_module_origin_not_qualified_as_head(tmp_path):
    site = _site(tmp_path)
    snapshot = probe.site_snapshot([site])
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    escaped = repo / ".." / "outside" / "r006_external_probe.py"
    escaped.write_text("VALUE=42\n")
    observation = tmp_path / "r006-origin.json"
    observation.write_text(json.dumps({
        "schema": 1, "executable": snapshot["interpreter"],
        "prefix": snapshot["prefix"], "user_site_enabled": False,
        "sys_path": [str(repo), str(site)],
        "loaded_origins": [["r006_external_probe", str(escaped)]],
    }))
    # A path outside the HEAD Tree must not silently become "G05 trusted".
    try:
        checked = probe.verify_runtime(observation, repo, snapshot)
    except probe.EvidenceError:
        pass
    else:
        assert ["r006_external_probe", str(escaped)] in checked["out_of_scope_module_origins"]


def test_r006_repo_origin_requires_manifest_and_matching_sha256(tmp_path):
    site = _site(tmp_path)
    snapshot = probe.site_snapshot([site])
    repo = tmp_path / "repo"
    repo.mkdir()
    source = repo / "tracked_r006.py"
    source.write_text("VALUE=8\n")
    observation = tmp_path / "r006-repo-origin.json"
    observation.write_text(json.dumps({
        "schema": 1, "executable": snapshot["interpreter"],
        "prefix": snapshot["prefix"], "user_site_enabled": False,
        "sys_path": [str(repo), str(site)],
        "loaded_origins": [["tracked_r006", str(source)]],
    }))
    # A trusted directory name by itself is not a verified tracked Git Blob.
    with pytest.raises(probe.EvidenceError, match="MANIFEST|manifest|unattested|HEAD"):
        probe.verify_runtime(observation, repo, snapshot)
    sha = hashlib.sha256(source.read_bytes()).hexdigest()
    (repo / "MANIFEST.sha256").write_text(sha + "  ./tracked_r006.py\n")
    _r007_commit_repo(repo)
    assert probe.verify_runtime(observation, repo, snapshot)["out_of_scope_module_origins"] == []
    source.write_text("VALUE=9\n")
    with pytest.raises(probe.EvidenceError, match="changed|mismatch|unattested|HEAD"):
        probe.verify_runtime(observation, repo, snapshot)


def test_r006_repo_symlink_root_outside_not_qualified(tmp_path):
    site = _site(tmp_path)
    snapshot = probe.site_snapshot([site])
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (repo / "linked").symlink_to(outside, target_is_directory=True)
    observation = tmp_path / "r006-link.json"
    observation.write_text(json.dumps({
        "schema": 1, "executable": snapshot["interpreter"],
        "prefix": snapshot["prefix"], "user_site_enabled": False,
        "sys_path": [str(repo), str(site), str(repo / "linked")],
        "loaded_origins": [],
    }))
    with pytest.raises(probe.EvidenceError, match="unexpected|noncanonical|symlink"):
        probe.verify_runtime(observation, repo, snapshot)


# r007 test-first RED from C90-R006-P2-01. All source generation/imports
# happen in disposable private pytest directories; no Gateway Exec or signals.
def _r007_commit_repo(repo: Path):
    """Build a genuine local committed HEAD and complete SHA256 manifest."""
    entries = []
    for path in sorted(repo.rglob("*")):
        if path.is_file() and ".git" not in path.parts and path.name != "MANIFEST.sha256":
            rel = path.relative_to(repo).as_posix()
            entries.append(hashlib.sha256(path.read_bytes()).hexdigest() + "  ./" + rel + "\n")
    manifest = repo / "MANIFEST.sha256"
    if not manifest.exists():
        manifest.write_text("".join(entries))
    for argv in (
        ["init", "-q"],
        ["add", "--", "."],
        ["-c", "user.name=R01 Test", "-c", "user.email=r01-test@example.invalid",
         "commit", "-q", "-m", "disposable HEAD source"],
    ):
        proc = subprocess.run(["git", "-C", str(repo), *argv],
                              capture_output=True, text=True, check=False)
        assert proc.returncode == 0, (argv, proc.stderr)


def _r007_runtime(repo: Path, site: Path, snapshot: dict, observation: Path,
                  *, roots: list[str] | None = None, origins: list | None = None) -> Path:
    observation.write_text(json.dumps({
        "schema": 1, "executable": snapshot["interpreter"],
        "prefix": snapshot["prefix"], "user_site_enabled": False,
        "sys_path": roots if roots is not None else [str(repo), str(site)],
        "loaded_origins": [] if origins is None else origins,
    }))
    return observation


def test_r007_transient_recorded_pth_generated_deleted_zip_refused(tmp_path):
    site = _site(tmp_path)
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "tracked.py").write_text("VALUE=3\n")
    _r007_commit_repo(repo)
    phantom_zip = repo / "transient_unlisted.pyz"
    code = (
        "import sys,os,zipfile\n"
        "p=" + repr(str(phantom_zip)) + "\n"
        "with zipfile.ZipFile(p,'w') as z:z.writestr('r007_probe.py','VALUE=77\\n')\n"
        "sys.path.insert(0,p)\n"
        "import r007_probe\n"
        "sys._r007_marker=r007_probe.VALUE\n"
        "del sys.modules['r007_probe']\n"
        "os.unlink(p)\n"
    )
    (site / "active_r007.pth").write_text("import sys;exec(" + repr(code) + ")\n")
    _r005_record(site, "active_r007.pth")
    snapshot = probe.site_snapshot([site])
    command = (
        "import sys,site,json;"
        "site.addsitedir(sys.argv[1]);"
        "print(json.dumps({'marker':sys._r007_marker,"
        "'sys_path':sys.path,'module_retained':'r007_probe' in sys.modules}))"
    )
    actual = subprocess.run([sys.executable, "-B", "-I", "-S", "-c", command, str(site)],
                            capture_output=True, text=True, check=False)
    assert actual.returncode == 0, actual.stderr
    seen = json.loads(actual.stdout)
    assert seen["marker"] == 77 and seen["module_retained"] is False
    assert str(phantom_zip) in seen["sys_path"]
    assert not phantom_zip.exists()
    observation = _r007_runtime(
        repo, site, snapshot, tmp_path / "r007-transient.json",
        roots=[str(repo)] + seen["sys_path"],
    )
    with pytest.raises(probe.EvidenceError, match="unattested|unqualified|missing|HEAD|pth"):
        probe.verify_runtime(observation, repo, snapshot)


def test_r007_missing_repo_zip_sys_path_must_not_be_head_qualified(tmp_path):
    site = _site(tmp_path)
    snapshot = probe.site_snapshot([site])
    repo = tmp_path / "repo"
    repo.mkdir()
    ziproot = repo / "removed.zip"
    observation = _r007_runtime(repo, site, snapshot, tmp_path / "r007-missing.json",
                                roots=[str(repo), str(site), str(ziproot)])
    with pytest.raises(probe.EvidenceError, match="unattested|missing|HEAD"):
        probe.verify_runtime(observation, repo, snapshot)


def test_r007_present_untracked_repo_zip_sys_path_must_be_rejected(tmp_path):
    site = _site(tmp_path)
    snapshot = probe.site_snapshot([site])
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "tracked.py").write_text("VALUE=3\n")
    _r007_commit_repo(repo)
    ziproot = _r005_zip(repo, "untracked.pyz")
    observation = _r007_runtime(repo, site, snapshot, tmp_path / "r007-untracked.json",
                                roots=[str(repo), str(site), str(ziproot)])
    with pytest.raises(probe.EvidenceError, match="unattested|HEAD|MANIFEST"):
        probe.verify_runtime(observation, repo, snapshot)


def test_r007_tracked_repo_zip_positive_then_changed_bytes_negative(tmp_path):
    site = _site(tmp_path)
    snapshot = probe.site_snapshot([site])
    repo = tmp_path / "repo"
    repo.mkdir()
    ziproot = _r005_zip(repo, "legitimate.pyz")
    _r007_commit_repo(repo)
    observation = _r007_runtime(repo, site, snapshot, tmp_path / "r007-legal.json",
                                roots=[str(repo), str(site), str(ziproot)])
    assert probe.verify_runtime(observation, repo, snapshot)["observed"][-1][1] == "HEAD_REPOSITORY_G05"
    with ziproot.open("ab") as stream:
        stream.write(b"unauthorized drift")
    with pytest.raises(probe.EvidenceError, match="changed|unattested|HEAD"):
        probe.verify_runtime(observation, repo, snapshot)


def test_r007_coordinated_repo_source_and_manifest_drift_rejected(tmp_path):
    site = _site(tmp_path)
    snapshot = probe.site_snapshot([site])
    repo = tmp_path / "repo"
    repo.mkdir()
    src = repo / "tracked.py"
    src.write_text("VALUE=3\n")
    _r007_commit_repo(repo)
    observation = _r007_runtime(
        repo, site, snapshot, tmp_path / "r007-drift.json",
        origins=[["tracked", str(src)]],
    )
    assert probe.verify_runtime(observation, repo, snapshot)["out_of_scope_module_origins"] == []
    src.write_text("VALUE=9\n")
    (repo / "MANIFEST.sha256").write_text(
        hashlib.sha256(src.read_bytes()).hexdigest() + "  ./tracked.py\n"
    )
    with pytest.raises(probe.EvidenceError, match="immutable|HEAD|MANIFEST|changed"):
        probe.verify_runtime(observation, repo, snapshot)


def test_r007_plain_recorded_pth_directory_stays_legal(tmp_path):
    site = _site(tmp_path)
    repo = tmp_path / "repo"
    repo.mkdir()
    (site / "legal_r007.pth").write_text("safe\n")
    _r005_record(site, "legal_r007.pth")
    snapshot = probe.site_snapshot([site])
    observation = _r007_runtime(repo, site, snapshot, tmp_path / "r007-legal-pth.json",
                                roots=[str(repo), str(site), str(site / "safe")])
    assert probe.verify_runtime(observation, repo, snapshot)["out_of_scope_module_origins"] == []


def test_r007_imperative_pth_unobserved_startup_effect_refused(tmp_path):
    site = _site(tmp_path)
    repo = tmp_path / "repo"
    repo.mkdir()
    (site / "active_r007.pth").write_text("import sys;sys._r007_marker=77\n")
    _r005_record(site, "active_r007.pth")
    snapshot = probe.site_snapshot([site])
    # Actual CPython site.addsitedir runs the hook, but the final sys.path and
    # sys.modules have no trace that its arbitrary imperative effect occurred.
    actual = subprocess.run([
        sys.executable, "-B", "-I", "-S", "-c",
        "import sys,site;site.addsitedir(sys.argv[1]);print(sys._r007_marker)",
        str(site)], capture_output=True, text=True, check=False)
    assert actual.returncode == 0 and actual.stdout.strip() == "77", actual.stderr
    observation = _r007_runtime(repo, site, snapshot, tmp_path / "r007-pth-only.json")
    with pytest.raises(probe.EvidenceError, match="pth|startup|unqualified|imperative"):
        probe.verify_runtime(observation, repo, snapshot)


# r008: actual disposable Git + Python evidence counterexamples, no Gateway Exec.
def _r008_git(repo: Path, *args: str) -> str:
    p = subprocess.run(["git", "-C", str(repo), *args],
                       capture_output=True, text=True, check=False)
    assert p.returncode == 0, (args, p.stderr)
    return p.stdout.strip()


def test_r008_required_original_pr_head_in_ci(tmp_path, monkeypatch):
    site = _site(tmp_path)
    snapshot = probe.site_snapshot([site])
    repo = tmp_path / "repo"
    repo.mkdir()
    source = repo / "tracked_r008.py"
    source.write_text("VALUE=8\n")
    _r007_commit_repo(repo)
    head_a = _r008_git(repo, "rev-parse", "HEAD")
    observation = _r007_runtime(repo, site, snapshot, tmp_path / "r008-expected.json",
                                origins=[["tracked_r008", str(source)]])
    monkeypatch.setenv("GITHUB_WORKSPACE", str(repo))
    monkeypatch.delenv("G05_EXPECTED_HEAD", raising=False)
    with pytest.raises(probe.EvidenceError, match="expected|missing|HEAD"):
        probe.verify_runtime(observation, repo, snapshot)
    monkeypatch.setenv("G05_EXPECTED_HEAD", head_a)
    assert probe.verify_runtime(observation, repo, snapshot)["out_of_scope_module_origins"] == []


def test_r008_real_git_a_to_b_commit_does_not_rebind_early_head(tmp_path, monkeypatch):
    site = _site(tmp_path)
    snapshot = probe.site_snapshot([site])
    repo = tmp_path / "repo"
    repo.mkdir()
    source = repo / "tracked_r008.py"
    source.write_text("VALUE=8\n")
    _r007_commit_repo(repo)
    head_a = _r008_git(repo, "rev-parse", "HEAD")
    observation = _r007_runtime(repo, site, snapshot, tmp_path / "r008-rebind.json",
                                origins=[["tracked_r008", str(source)]])
    monkeypatch.setenv("GITHUB_WORKSPACE", str(repo))
    monkeypatch.setenv("G05_EXPECTED_HEAD", head_a)
    assert probe.verify_runtime(observation, repo, snapshot)["out_of_scope_module_origins"] == []
    source.write_text("VALUE=99\n")
    (repo / "MANIFEST.sha256").write_text(
        hashlib.sha256(source.read_bytes()).hexdigest() + "  ./tracked_r008.py\n")
    _r008_git(repo, "add", "--", "tracked_r008.py", "MANIFEST.sha256")
    _r008_git(repo, "-c", "user.name=R01 Test", "-c",
              "user.email=r01-test@example.invalid", "commit", "-q",
              "-m", "second independently committed source")
    head_b = _r008_git(repo, "rev-parse", "HEAD")
    assert head_b != head_a
    assert _r008_git(repo, "status", "--porcelain") == ""
    monkeypatch.delenv("G05_EXPECTED_HEAD", raising=False)
    with pytest.raises(probe.EvidenceError, match="expected|missing|HEAD"):
        probe.verify_runtime(observation, repo, snapshot)
    monkeypatch.setenv("G05_EXPECTED_HEAD", head_a)
    with pytest.raises(probe.EvidenceError, match="HEAD|expected"):
        probe.verify_runtime(observation, repo, snapshot)


def test_r008_preimport_blocks_recorded_imperative_pth_before_site(tmp_path):
    site = _site(tmp_path)
    (site / "active_r008.pth").write_text("import sys;sys._r008_marker=1\n")
    _r005_record(site, "active_r008.pth")
    evidence = tmp_path / "r008-preimport.json"
    p = subprocess.run([sys.executable, "-B", "-I", "-S", str(SCRIPT), "preimport",
                        "--site-root", str(site), "--snapshot", str(evidence)],
                       capture_output=True, text=True, check=False)
    assert p.returncode == 2, (p.stdout, p.stderr)
    assert "imperative" in p.stderr or "unattested" in p.stderr
    assert not evidence.exists()


def test_r008_nested_head_directory_deleted_untracked_module_must_deny(tmp_path):
    site = _site(tmp_path)
    snapshot = probe.site_snapshot([site])
    repo = tmp_path / "repo"
    repo.mkdir()
    nested = repo / "pkg_r008"
    nested.mkdir()
    (nested / "README.txt").write_text("tracked metadata only\n")
    _r007_commit_repo(repo)
    ephemeral = nested / "ephemeral_r008.py"
    ephemeral.write_text("VALUE=72\n")
    cmd = ("import sys,os,json;"
           "sys.path.insert(0,sys.argv[1]);"
           "import ephemeral_r008;"
           "v=ephemeral_r008.VALUE;"
           "del sys.modules['ephemeral_r008'];"
           "os.unlink(sys.argv[2]);"
           "print(json.dumps({'value':v,"
           "'retained':'ephemeral_r008' in sys.modules}))")
    p = subprocess.run([sys.executable, "-B", "-I", "-S", "-c", cmd,
                        str(nested), str(ephemeral)], capture_output=True,
                       text=True, check=False)
    assert p.returncode == 0, p.stderr
    assert json.loads(p.stdout) == {"value": 72, "retained": False}
    assert not ephemeral.exists() and _r008_git(repo, "status", "--porcelain") == ""
    observation = _r007_runtime(repo, site, snapshot, tmp_path / "r008-nested.json",
                                roots=[str(repo), str(site), str(nested)])
    with pytest.raises(probe.EvidenceError, match="nested|unattested|unqualified"):
        probe.verify_runtime(observation, repo, snapshot)
