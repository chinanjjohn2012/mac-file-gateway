"""SAFE T0 for R006 fresh G05 receipt + GitHub run/job binding."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import time

import pytest

from gateway.lbe_owner_grant import verify_d4_owner_github_comment_t0
from gateway.lbe_owner_grant_bootstrap import _argv_fingerprint
from gateway.lbe_r006_macos_allowlist import (
    R006_HOST_SOURCE_FINGERPRINT, R006_RUNNER_PROFILE_FINGERPRINT,
)
from gateway.lbe_r006_runtime_identity import (
    D4R006RuntimeIdentityDenied, D4VerifiedRuntimeIdentity,
    _fresh_checkout_receipt, verify_r006_runtime_identity_t0,
)

H = "a" * 40
T = "b" * 40
M = "c" * 64
NOW = 1794100000
RUN = 42445537246
JOB_ID = 128623556504
ROOT = "/Users/runner/work/mac-file-gateway/mac-file-gateway"
ROOT_ID = [1, 2, 0o40755, 501, 20, 1794100000000000000]


def _grant(monkeypatch, *, run_attempt=1):
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
        "b_code_review_id":"PRR_fullStandardsR007ABC",
        "c_code_review_id":"PRR_fullSpecR007XYZ",
        "github_run_id":RUN,"github_run_attempt":run_attempt,
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


def _receipt(*, run_attempt=1, job_name="observe-macos-15-arm64-t0", **changes):
    p={"marker":"MFG_G05_R006_RECEIPT_V1",
       "repo":"chinanjjohn2012/mac-file-gateway","pr":114,
       "head_sha":H,"head_tree":T,"manifest_sha256":M,
       "run_id":RUN,"run_attempt":run_attempt,"job_name":job_name,
       "checkout_root":ROOT,"checkout_identity":ROOT_ID,
       "checkout_credentials_clean":True}
    p.update(changes)
    return (json.dumps(p,sort_keys=True,separators=(",",":"))+"\n").encode()


def _run(*, run_attempt=1, **changes):
    p={"id":RUN,"run_attempt":run_attempt,"event":"pull_request","head_sha":H,
       "status":"in_progress","conclusion":None,
       "repository":{"full_name":"chinanjjohn2012/mac-file-gateway"},
       "head_repository":{"full_name":"chinanjjohn2012/mac-file-gateway"},
       "pull_requests":[{"number":114,"head":{"sha":H},"base":{"sha":H}}]}
    p.update(changes)
    return json.dumps(p,separators=(",",":")).encode()


def _jobs(*, run_attempt=1, job_name="observe-macos-15-arm64-t0", **changes):
    job={"id":JOB_ID,"run_id":RUN,"run_attempt":run_attempt,"head_sha":H,
         "name":job_name,"status":"in_progress","conclusion":None}
    job.update(changes)
    return json.dumps({"total_count":1,"jobs":[job]},separators=(",",":")).encode()


def _env(*, run_attempt=1, job_name="observe-macos-15-arm64-t0", **changes):
    p={"GITHUB_ACTIONS":"true","GITHUB_EVENT_NAME":"pull_request",
       "GITHUB_REPOSITORY":"chinanjjohn2012/mac-file-gateway",
       "GITHUB_RUN_ID":str(RUN),"GITHUB_RUN_ATTEMPT":str(run_attempt),
       "GITHUB_JOB":job_name,"G05_EXPECTED_HEAD":H,
       "RUNNER_ENVIRONMENT":"github-hosted","RUNNER_OS":"macOS",
       "RUNNER_ARCH":"ARM64"}
    p.update(changes)
    return p


def test_exact_receipt_run_job_and_fresh_checkout_bind(monkeypatch):
    grant=_grant(monkeypatch)
    receipt=_receipt()
    item=verify_r006_runtime_identity_t0(
        grant,receipt,_run(),_jobs(),receipt,environ=_env())
    assert type(item) is D4VerifiedRuntimeIdentity
    item.check_grant(grant)
    assert item.head_tree == T and item.manifest_sha256 == M
    assert item.run_id == RUN and item.run_attempt == 1
    assert item.job_id == JOB_ID and item.checkout_root == ROOT


@pytest.mark.parametrize("kind",[
    "receipt_head","receipt_manifest","receipt_job","fresh_checkout",
    "run_attempt","run_head","run_base","run_status",
    "job_attempt","job_head","job_status","env_run","env_job",
])
def test_any_runtime_or_fresh_checkout_drift_denies(monkeypatch,kind):
    grant=_grant(monkeypatch); receipt=_receipt(); fresh=receipt
    run=_run(); jobs=_jobs(); env=_env()
    if kind=="receipt_head": receipt=_receipt(head_sha="f"*40); fresh=receipt
    elif kind=="receipt_manifest": receipt=_receipt(manifest_sha256="f"*64); fresh=receipt
    elif kind=="receipt_job": receipt=_receipt(job_name="other-job"); fresh=receipt
    elif kind=="fresh_checkout": fresh=_receipt(checkout_identity=[9,2,0o40755,501,20,1])
    elif kind=="run_attempt": run=_run(run_attempt=2)
    elif kind=="run_head": run=_run(head_sha="f"*40)
    elif kind=="run_base":
        data=json.loads(_run()); data["pull_requests"][0]["base"]["sha"]="f"*40
        run=json.dumps(data).encode()
    elif kind=="run_status": run=_run(status="completed",conclusion="success")
    elif kind=="job_attempt": jobs=_jobs(run_attempt=2)
    elif kind=="job_head": jobs=_jobs(head_sha="f"*40)
    elif kind=="job_status": jobs=_jobs(status="completed",conclusion="success")
    elif kind=="env_run": env=_env(GITHUB_RUN_ID=str(RUN+1))
    else: env=_env(GITHUB_JOB="other-job")
    with pytest.raises(D4R006RuntimeIdentityDenied):
        verify_r006_runtime_identity_t0(
            grant,receipt,run,jobs,fresh,environ=env)


def test_same_head_receipt_from_prior_run_attempt_is_rejected(monkeypatch):
    grant=_grant(monkeypatch,run_attempt=2)
    with pytest.raises(D4R006RuntimeIdentityDenied):
        verify_r006_runtime_identity_t0(
            grant,_receipt(run_attempt=1),_run(run_attempt=2),
            _jobs(run_attempt=2),_receipt(run_attempt=1),
            environ=_env(run_attempt=2))


def test_duplicate_receipt_json_key_denied(monkeypatch):
    grant=_grant(monkeypatch)
    raw=(b'{"marker":"MFG_G05_R006_RECEIPT_V1","marker":"x"}')
    with pytest.raises(D4R006RuntimeIdentityDenied):
        verify_r006_runtime_identity_t0(
            grant,raw,_run(),_jobs(),raw,environ=_env())


def test_verified_runtime_identity_cannot_be_directly_constructed():
    with pytest.raises(D4R006RuntimeIdentityDenied):
        D4VerifiedRuntimeIdentity(
            object(),base_sha=H,head_sha=H,head_tree=T,
            manifest_sha256=M,run_id=RUN,run_attempt=1,
            job_id=JOB_ID,checkout_root=ROOT)


def _git(root: Path, *argv: str) -> str:
    result = subprocess.run(
        ["git", *argv], cwd=root, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    return result.stdout.strip()


def _make_runtime_checkout(tmp_path: Path):
    root = tmp_path / "runtime-checkout"
    root.mkdir()
    _git(root, "init", "-q")
    _git(root, "config", "user.name", "R007 T0")
    _git(root, "config", "user.email", "r007@example.invalid")
    (root / ".gitignore").write_text("ignored_runtime.py\n", encoding="ascii")
    (root / "gateway").mkdir()
    (root / "gateway" / "__init__.py").write_text("VALUE = 1\n", encoding="ascii")
    records = []
    for path in sorted(
            p for p in root.rglob("*")
            if p.is_file() and ".git" not in p.parts
            and p.name != "MANIFEST.sha256"):
        rel = path.relative_to(root).as_posix()
        records.append(
            hashlib.sha256(path.read_bytes()).hexdigest() + "  ./" + rel)
    (root / "MANIFEST.sha256").write_text(
        "\n".join(records) + "\n", encoding="ascii")
    _git(root, "add", ".")
    _git(root, "commit", "-q", "-m", "runtime fixture")
    head = _git(root, "rev-parse", "HEAD")
    tree = _git(root, "rev-parse", "HEAD^{tree}")
    manifest = hashlib.sha256((root / "MANIFEST.sha256").read_bytes()).hexdigest()
    st = root.lstat()
    receipt = {
        "marker": "MFG_G05_R006_RECEIPT_V1",
        "repo": "chinanjjohn2012/mac-file-gateway", "pr": 114,
        "head_sha": head, "head_tree": tree, "manifest_sha256": manifest,
        "run_id": RUN, "run_attempt": 1, "job_name": "r007-t0",
        "checkout_root": str(root.resolve()),
        "checkout_identity": [
            st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_gid,
            st.st_ctime_ns],
        "checkout_credentials_clean": True,
    }
    env = {
        "GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "pull_request",
        "GITHUB_REPOSITORY": "chinanjjohn2012/mac-file-gateway",
        "GITHUB_RUN_ID": str(RUN), "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_JOB": "r007-t0", "G05_EXPECTED_HEAD": head,
    }
    return root, receipt, env


def test_canonical_fresh_checkout_rejects_post_receipt_ignored_and_untracked(
        tmp_path):
    root, receipt, env = _make_runtime_checkout(tmp_path)
    raw = (json.dumps(
        receipt, sort_keys=True, separators=(",", ":")) + "\n").encode()
    assert _fresh_checkout_receipt(receipt, environ=env) == raw

    ignored = root / "ignored_runtime.py"
    ignored.write_text("UNREVIEWED = True\n", encoding="ascii")
    with pytest.raises(
            D4R006RuntimeIdentityDenied,
            match="checkout root identity changed|untracked/ignored"):
        _fresh_checkout_receipt(receipt, environ=env)
    ignored.unlink()

    untracked = root / "unreviewed.txt"
    untracked.write_text("x\n", encoding="ascii")
    with pytest.raises(
            D4R006RuntimeIdentityDenied,
            match="checkout root identity changed|tracked/untracked"):
        _fresh_checkout_receipt(receipt, environ=env)
