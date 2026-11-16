"""SAFE T0 for tracked R006 PRODUCT_T1 entrypoint; no real child."""
import hashlib
import json

from gateway import lbe_r006_t1_harness as harness
from gateway.lbe_r006_t1_harness import parse_r006_source_bundle
from gateway.workspaces import WorkspaceService
from tools import lbe_r006_product_t1 as entry


def _bundle():
    obj={"marker":"MFG_R006_REVIEWED_SOURCE_BUNDLE_V1","workspace":"a",
         "cwd":"go-project","argv":["go","test","./..."],
         "timeout_seconds":120,"private_root":"/private/r006",
         "provisioner_root":"/private/source",
         "staged_manifests":{"go":[["go/VERSION","a"*64]]},
         "venv_manifest":None,
         "expected_source_identities":{"go":"e"*64},
         "expected_venv_identity_sha256":None,
         "require_go_p007_stage_source":True,
         "expected_venv_record_distributions":None}
    raw=(json.dumps(obj,sort_keys=True,separators=(",",":"))+"\n").encode()
    return parse_r006_source_bundle(raw,hashlib.sha256(raw).hexdigest())


def test_entry_installs_then_uses_shared_invoke_gate(monkeypatch):
    service=object.__new__(WorkspaceService)
    bundle=_bundle(); events=[]
    monkeypatch.setattr(
        entry,"prepare_and_install_r006_one_shot",
        lambda service,bundle,**kw: events.append(("install",kw)))
    monkeypatch.setattr(
        WorkspaceService,"invoke_exec",
        lambda self,name,cwd,argv,**kw:
            (events.append(("invoke",name,cwd,tuple(argv),kw))
             or {"status":"launch_failed","executed":False}))
    result=entry.run_r006_product_t1_once(
        service,bundle,owner_comment_id=7712345678,
        g05_receipt_path="/private/g05.json")
    assert result=={"status":"launch_failed","executed":False}
    assert [x[0] for x in events]==["install","invoke"]
    assert events[1][1:4]==("a","go-project",("go","test","./..."))
    assert events[1][4]=={"timeout_seconds":120,"dry_run":False}
