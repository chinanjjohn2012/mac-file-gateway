"""Safe T0 for owner GitHub transport shape and exact runtime binding."""
from datetime import datetime, timezone
import hashlib
import json
import time
from types import SimpleNamespace
import urllib.request

import pytest

from gateway.lbe_owner_grant_bootstrap import (
    D4OwnerBootstrapDenied, _argv_fingerprint,
    bind_verified_owner_grant_t0, fetch_verified_owner_grant,
)
from gateway.lbe_owner_grant import verify_d4_owner_github_comment_t0
from gateway.lbe_r006_macos_allowlist import (
    D4R006HostAllowlistObservation, R006_HOST_SOURCE_FINGERPRINT,
    R006_RUNNER_PROFILE_FINGERPRINT,
)
from gateway.lbe_hosted_source_probe import D4HostedSelectedSourceObservation
from gateway.lbe_worker import LbeWorkPlan

H = "a" * 40
M = "b" * 64
NOW = 1794100000

def _plan():
    argv = ("python", "-m", "pytest", "-q")
    return LbeWorkPlan(
        workspace="a", cwd="py-direct", runner="direct",
        runner_project="", requested_argv=argv, effective_argv=argv,
        timeout_seconds=120, planned_go_output=None,
        planned_script_sha256=None, planned_pipfile_sha256=None,
    )

def _host():
    obs = D4HostedSelectedSourceObservation(
        root_identity=(1,2,3,4,5,0o40755,0,1),
        selected=(("x", M, (1,2,1,4,5,0o100444,0,1)),),
        root_ancestor_identities=((1,2,0o40755,0),),
    )
    return D4R006HostAllowlistObservation(
        system=obs, usr=obs,
        source_fingerprint=R006_HOST_SOURCE_FINGERPRINT,
        runner_profile_fingerprint=R006_RUNNER_PROFILE_FINGERPRINT,
        image_version="20261104.0514.1", macos_version="15.8.2",
        os_build="24H232",
    )

def _verified(monkeypatch):
    monkeypatch.setattr(time, "time", lambda: NOW)
    plan = _plan()
    p = {
        "authorization":"PRODUCT_T1_ONE_ATTEMPT_ONLY",
        "risk_acceptance":"R006_NINE_RESIDUAL_RISKS_ACCEPTED",
        "repo":"chinanjjohn2012/mac-file-gateway","pr":114,
        "base_sha":H,"head_sha":H,"head_tree":H,"manifest_sha256":M,
        "r006_design_blob":"b8d8a1cb32fb7130dfa6d00b37831dfddfaad11c",
        "b_design_review_id":"PRR_kwDOU5v3IM8AAAABWq0I_w",
        "c_design_review_id":"PRR_kwDOU5v3IM8AAAABWq0iKA",
        "b_code_review_id":"PRR_currentStandards123",
        "c_code_review_id":"PRR_currentSpecReview123",
        "github_run_id":42445537246,"github_run_attempt":1,
        "image_os":"macos15","image_version":"20261104.0514.1",
        "os_build":"24H232","source_fingerprint":R006_HOST_SOURCE_FINGERPRINT,
        "runner_fingerprint":R006_RUNNER_PROFILE_FINGERPRINT,
        "workspace":"a","cwd":"py-direct","runner":"direct",
        "requested_argv_sha256":_argv_fingerprint(plan.requested_argv),
        "effective_argv_sha256":_argv_fingerprint(plan.effective_argv),
        "timeout_seconds":120,"nonce":"c"*64,
        "expires_at":datetime.fromtimestamp(
            NOW + 900, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    created=datetime.fromtimestamp(
        NOW, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    cid=7712345678
    obj={"id":cid,"body":"R006_OWNER_T1_GRANT_V1\n"+json.dumps(p,sort_keys=True,separators=(",",":")),
         "html_url":f"https://github.com/chinanjjohn2012/mac-file-gateway/pull/114#issuecomment-{cid}",
         "issue_url":"https://api.github.com/repos/chinanjjohn2012/mac-file-gateway/issues/114",
         "created_at":created,"updated_at":created,"author_association":"OWNER",
         "user":{"login":"chinanjjohn2012","type":"User"},"performed_via_github_app":None}
    return verify_d4_owner_github_comment_t0(json.dumps(obj,separators=(",",":")).encode()), plan

def test_exact_runtime_binding_remains_nonexecuting(monkeypatch):
    grant, plan = _verified(monkeypatch)
    bound = bind_verified_owner_grant_t0(
        grant, _host(), plan, base_sha=H, head_sha=H, head_tree=H,
        manifest_sha256=M, run_id=42445537246, run_attempt=1)
    assert bound.attempt.nonce == "c"*64

@pytest.mark.parametrize("field,value", [
    ("head_sha","d"*40),("head_tree","d"*40),("manifest_sha256","d"*64),
    ("run_id",9),("run_attempt",2),
])
def test_runtime_identity_drift_denied(monkeypatch, field, value):
    grant, plan = _verified(monkeypatch)
    kw=dict(base_sha=H,head_sha=H,head_tree=H,manifest_sha256=M,
            run_id=42445537246,run_attempt=1)
    kw[field]=value
    with pytest.raises(D4OwnerBootstrapDenied):
        bind_verified_owner_grant_t0(grant,_host(),plan,**kw)

def test_plan_drift_denied(monkeypatch):
    grant, plan = _verified(monkeypatch)
    changed = LbeWorkPlan(
        workspace=plan.workspace,cwd=plan.cwd,runner=plan.runner,
        runner_project=plan.runner_project,requested_argv=plan.requested_argv,
        effective_argv=("python","-m","compileall","-q","./src"),
        timeout_seconds=plan.timeout_seconds,planned_go_output=None,
        planned_script_sha256=None,planned_pipfile_sha256=None)
    with pytest.raises(D4OwnerBootstrapDenied):
        bind_verified_owner_grant_t0(
            grant,_host(),changed,base_sha=H,head_sha=H,head_tree=H,
            manifest_sha256=M,run_id=42445537246,run_attempt=1)

class _Response:
    status=200
    headers={"Content-Type":"application/json","Content-Length":"10"}
    def __init__(self,url,data): self.url=url; self.data=data
    def __enter__(self): return self
    def __exit__(self,*a): return None
    def geturl(self): return self.url
    def read(self,n): return self.data[:n]

def test_fetch_bootstrap_uses_fixed_public_https_no_auth_header(monkeypatch):
    grant, _ = _verified(monkeypatch)
    # Reuse semantic bytes from a known verified object's original fixture is
    # not available; transport behavior is tested with malformed body and must
    # fail only after the fake HTTPS response is consumed.
    captured={}
    class Opener:
        def open(self,req,timeout):
            captured["url"]=req.full_url
            captured["headers"]=dict(req.header_items())
            captured["timeout"]=timeout
            return _Response(req.full_url,b"{}")
    monkeypatch.setattr(urllib.request,"build_opener",lambda *handlers: Opener())
    with pytest.raises(D4OwnerBootstrapDenied):
        fetch_verified_owner_grant(7712345678)
    assert captured["url"]=="https://api.github.com/repos/chinanjjohn2012/mac-file-gateway/issues/comments/7712345678"
    assert "Authorization" not in captured["headers"]
    assert captured["timeout"]==5
