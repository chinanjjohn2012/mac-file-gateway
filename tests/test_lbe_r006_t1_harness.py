"""SAFE T0 for tracked R006 source-bundle harness."""
import hashlib
import json

import pytest

from gateway import lbe_r006_t1_harness as mod
from gateway.lbe_r006_t1_harness import (
    D4R006HarnessDenied, D4R006SourceBundle,
    load_r006_source_bundle, parse_r006_source_bundle,
    prepare_and_install_r006_one_shot,
)
from gateway.workspaces import WorkspaceService


def _raw(cwd="go-project"):
    if cwd=="go-project":
        manifests={"go":[["go/VERSION","a"*64]]}; venv=None; vid=None
        p007=True; dists=None; argv=["go","test","./..."]
    elif cwd=="py-pipenv":
        manifests={"bin":[["pipenv","a"*64]],"lib":[["x.py","b"*64]]}
        venv=[["bin/python","c"*64]]; vid="d"*64; p007=False
        dists=[["pipenv","2026.10.4"]]; argv=["python","-m","pytest","-q"]
    else:
        manifests={"bin":[["python","a"*64]],"lib":[["os.py","b"*64]]}
        venv=None; vid=None; p007=False; dists=None
        argv=["python","-m","pytest","-q"]
    obj={"marker":"MFG_R006_REVIEWED_SOURCE_BUNDLE_V1","workspace":"a",
         "cwd":cwd,"argv":argv,"timeout_seconds":120,
         "private_root":"/private/r006","provisioner_root":"/private/source",
         "staged_manifests":manifests,"venv_manifest":venv,
         "expected_source_identities":{k:"e"*64 for k in manifests},
         "expected_venv_identity_sha256":vid,
         "require_go_p007_stage_source":p007,
         "expected_venv_record_distributions":dists}
    return (json.dumps(obj,sort_keys=True,separators=(",",":"))+"\n").encode()


@pytest.mark.parametrize("cwd",["go-project","py-pipenv","py-direct"])
def test_bundle_roles(cwd):
    raw=_raw(cwd)
    item=parse_r006_source_bundle(raw,hashlib.sha256(raw).hexdigest())
    assert type(item) is D4R006SourceBundle
    assert item.cwd == cwd


def test_bundle_digest_and_role_fail_closed():
    raw=_raw()
    with pytest.raises(D4R006HarnessDenied):
        parse_r006_source_bundle(raw,"0"*64)
    obj=json.loads(raw); obj["require_go_p007_stage_source"]=False
    bad=(json.dumps(obj,sort_keys=True,separators=(",",":"))+"\n").encode()
    with pytest.raises(D4R006HarnessDenied):
        parse_r006_source_bundle(bad,hashlib.sha256(bad).hexdigest())


def test_bundle_file_requires_0600(tmp_path):
    raw=_raw("py-direct"); path=tmp_path/"bundle.json"
    path.write_bytes(raw); path.chmod(0o600)
    assert load_r006_source_bundle(
        str(path),hashlib.sha256(raw).hexdigest()).cwd=="py-direct"
    path.chmod(0o644)
    with pytest.raises(D4R006HarnessDenied):
        load_r006_source_bundle(str(path),hashlib.sha256(raw).hexdigest())


def test_prepare_bootstrap_install_order(monkeypatch):
    service=object.__new__(WorkspaceService)
    raw=_raw(); bundle=parse_r006_source_bundle(
        raw,hashlib.sha256(raw).hexdigest())
    events=[]; prepared=object(); bootstrap=object()
    monkeypatch.setattr(
        WorkspaceService,"_prepare_d4_r006_private_attempt",
        lambda self,*a,**k:(events.append("prepare") or prepared))
    monkeypatch.setattr(
        mod,"fetch_r006_trusted_bootstrap",
        lambda *a,**k:(events.append("bootstrap") or bootstrap))
    monkeypatch.setattr(
        WorkspaceService,"_install_d4_r006_one_shot",
        lambda self,p,b:events.append("install"))
    assert prepare_and_install_r006_one_shot(
        service,bundle,owner_comment_id=7712345678,
        g05_receipt_path="/private/g05.json") is prepared
    assert events==["prepare","bootstrap","install"]
