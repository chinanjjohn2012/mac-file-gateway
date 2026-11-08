"""SAFE T0 for R006 G05 receipt + GitHub run binding; no native child."""
from datetime import datetime, timezone
import hashlib
import json
import os
import time

import pytest

from gateway.lbe_owner_grant import verify_d4_owner_github_comment_t0
from gateway.lbe_owner_grant_bootstrap import _argv_fingerprint
from gateway.lbe_r006_macos_allowlist import (
    R006_HOST_SOURCE_FINGERPRINT, R006_RUNNER_PROFILE_FINGERPRINT,
)
from gateway.lbe_r006_runtime_identity import (
    D4R006RuntimeIdentityDenied, D4VerifiedRuntimeIdentity,
    verify_r006_runtime_identity_t0,
)

H = "a" * 40
T = "b" * 40
M = "c" * 64
NOW = 1794100000
RUN = 42445537246


def _grant(monkeypatch):
    monkeypatch.setattr(time, "time", lambda: NOW)
    created = datetime.fromtimestamp(NOW, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    expires = datetime.fromtimestamp(NOW + 900, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    argv = ("python", "-m", "pytest", "-q")
    p = {
        "authorization":"PRODUCT_T1_ONE_ATTEMPT_ONLY",
        "risk_acceptance":"R006_NINE_RESIDUAL_RISKS_ACCEPTED",
        "repo":"chinanjjohn2012/mac-file-gateway","pr":114,
        "base_sha":H,"head_sha":H,"head_tree":T,"manifest_sha256":M,
        "r006_design_blob":"b8d8a1cb32fb7130dfa6d00b37831dfddfaad11c",
        "b_design_review_id":"PRR_kwDOU5v3IM8AAAABWq0I_w",
        "c_design_review_id":"PRR_kwDOU5v3IM8AAAABWq0iKA",
        "b_code_review_id":"PRR_fullStandardsR006ABC",
        "c_code_review_id":"PRR_fullSpecR006XYZ",
        "github_run_id":RUN,"github_run_attempt":1,
        "image_os":"macos15","image_version":"20261104.0514.1",
        "os_build":"24H232","source_fingerprint":R006_HOST_SOURCE_FINGERPRINT,
        "runner_fingerprint":R006_RUNNER_PROFILE_FINGERPRINT,
        "product_recipe_fingerprint":"d"*64,"workspace":"a","cwd":"py-direct",
        "runner":"direct","requested_argv_sha256":_argv_fingerprint(argv),
        "effective_argv_sha256":_argv_fingerprint(argv),"timeout_seconds":120,
        "nonce":"e"*64,"expires_at":expires,
    }
    cid=7712345678
    obj={"id":cid,"body":"R006_OWNER_T1_GRANT_V1\n"+json.dumps(p,sort_keys=True,separators=(",",":")),
         "html_url":f"https://github.com/chinanjjohn2012/mac-file-gateway/pull/114#issuecomment-{cid}",
         "issue_url":"https://api.github.com/repos/chinanjjohn2012/mac-file-gateway/issues/114",
         "created_at":created,"updated_at":created,"author_association":"OWNER",
         "user":{"login":"chinanjjohn2012","type":"User"},"performed_via_github_app":None}
    return verify_d4_owner_github_comment_t0(json.dumps(obj,separators=(",",":")).encode())


def _receipt(**changes):
    p={"marker":"MFG_G05_R006_RECEIPT_V1","repo":"chinanjjohn2012/mac-file-gateway",
       "pr":114,"head_sha":H,"head_tree":T,"manifest_sha256":M}
    p.update(changes)
    return (json.dumps(p,sort_keys=True,separators=(",",":"))+"\n").encode()


def _run(**changes):
    p={"id":RUN,"run_attempt":1,"event":"pull_request","head_sha":H,
       "status":"in_progress","conclusion":None,
       "repository":{"full_name":"chinanjjohn2012/mac-file-gateway"},
       "head_repository":{"full_name":"chinanjjohn2012/mac-file-gateway"},
       "pull_requests":[{"number":114,"head":{"sha":H},"base":{"sha":H}}]}
    p.update(changes)
    return json.dumps(p,separators=(",",":")).encode()


def _env(**changes):
    p={"GITHUB_ACTIONS":"true","GITHUB_EVENT_NAME":"pull_request",
       "GITHUB_REPOSITORY":"chinanjjohn2012/mac-file-gateway",
       "GITHUB_RUN_ID":str(RUN),"GITHUB_RUN_ATTEMPT":"1",
       "G05_EXPECTED_HEAD":H,"RUNNER_ENVIRONMENT":"github-hosted",
       "RUNNER_OS":"macOS","RUNNER_ARCH":"ARM64"}
    p.update(changes)
    return p


def test_exact_receipt_run_and_local_claims_bind(monkeypatch):
    grant=_grant(monkeypatch)
    item=verify_r006_runtime_identity_t0(
        grant,_receipt(),_run(),environ=_env())
    assert type(item) is D4VerifiedRuntimeIdentity
    item.check_grant(grant)
    assert item.head_tree == T and item.manifest_sha256 == M
    assert item.run_id == RUN and item.run_attempt == 1


@pytest.mark.parametrize("kind", [
    "receipt_head","receipt_tree","receipt_manifest","run_id","run_attempt",
    "run_head","run_base","run_repo","run_status","env_run","env_head","env_runner",
])
def test_any_runtime_identity_drift_denies(monkeypatch, kind):
    grant=_grant(monkeypatch); receipt=_receipt(); run=_run(); env=_env()
    if kind=="receipt_head": receipt=_receipt(head_sha="f"*40)
    elif kind=="receipt_tree": receipt=_receipt(head_tree="f"*40)
    elif kind=="receipt_manifest": receipt=_receipt(manifest_sha256="f"*64)
    elif kind=="run_id": run=_run(id=RUN+1)
    elif kind=="run_attempt": run=_run(run_attempt=2)
    elif kind=="run_head": run=_run(head_sha="f"*40)
    elif kind=="run_base":
        data=json.loads(_run()); data["pull_requests"][0]["base"]["sha"]="f"*40
        run=json.dumps(data).encode()
    elif kind=="run_repo": run=_run(repository={"full_name":"other/repo"})
    elif kind=="run_status": run=_run(status="completed",conclusion="success")
    elif kind=="env_run": env=_env(GITHUB_RUN_ID=str(RUN+1))
    elif kind=="env_head": env=_env(G05_EXPECTED_HEAD="f"*40)
    else: env=_env(RUNNER_ENVIRONMENT="self-hosted")
    with pytest.raises(D4R006RuntimeIdentityDenied):
        verify_r006_runtime_identity_t0(grant,receipt,run,environ=env)


def test_duplicate_receipt_json_key_denied(monkeypatch):
    grant=_grant(monkeypatch)
    raw=(b'{"marker":"MFG_G05_R006_RECEIPT_V1","marker":"x",'
         b'"repo":"chinanjjohn2012/mac-file-gateway","pr":114,'
         b'"head_sha":"' + H.encode() + b'","head_tree":"' + T.encode()
         + b'","manifest_sha256":"' + M.encode() + b'"}')
    with pytest.raises(D4R006RuntimeIdentityDenied):
        verify_r006_runtime_identity_t0(grant,raw,_run(),environ=_env())


def test_verified_runtime_identity_cannot_be_directly_constructed():
    with pytest.raises(D4R006RuntimeIdentityDenied):
        D4VerifiedRuntimeIdentity(
            object(),base_sha=H,head_sha=H,head_tree=T,
            manifest_sha256=M,run_id=RUN,run_attempt=1)
