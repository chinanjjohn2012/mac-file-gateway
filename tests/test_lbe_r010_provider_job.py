"""R010 current Provider Workflow Run/Job identity: pure fake REST SAFE T0."""
from copy import deepcopy
from dataclasses import replace
import json
import os
import socket
import subprocess

import pytest

from gateway.lbe_r010_job_envelope import R010JobKey
from gateway.lbe_r010_oidc_verify import (
    R010OIDCExpected, R010OIDCSignatureReceipt,
)
from gateway.lbe_r010_provider_transport import (
    R010ProviderOIDCSource, _current_job_api_url, _API,
)
from gateway.lbe_r010_provider_job import (
    R010CurrentJobDenied, read_r010_current_github_job_source,
)

REPO = "chinanjjohn2012/mac-file-gateway"
DESIGN = "f57e39543a6fe3d64fe99b8669fc7da854b93a64"
NOW = 1800000000


@pytest.fixture(autouse=True)
def forbid_live_product_or_provider(monkeypatch):
    def denied(*_a, **_kw):
        raise AssertionError("Safe T0 forbids real socket/child/signal")
    monkeypatch.setattr(socket.socket, "connect", denied)
    monkeypatch.setattr(subprocess, "Popen", denied)
    monkeypatch.setattr(os, "kill", denied)
    monkeypatch.setattr(os, "killpg", denied, raising=False)


def packet():
    key = R010JobKey(
        repo=REPO, pr=114, workflow_id=145,
        workflow_path=".github/workflows/r010.yml",
        workflow_ref=REPO + "/.github/workflows/r010.yml@refs/heads/main",
        run_id=1001, run_attempt=1, check_run_id=2001,
        job_name="r010_preexec_hold", head_sha="a" * 40,
        design_id="MWE-LBE-R010-AUTHORITY-CHAIN-DESIGN-013-CANDIDATE",
        design_blob=DESIGN, owner_choice_comment_id=6740275850,
        host_option="A1", review_sequence_option="B1",
        state_domain="R010_EPHEMERAL_JOB_STATE_V1",
    )
    ex = R010OIDCExpected(
        implementation_head_sha=key.head_sha,
        job_local_secret_sha256="b" * 64,
        run_id=str(key.run_id), run_attempt=str(key.run_attempt),
        check_run_id=str(key.check_run_id),
        workflow_ref=key.workflow_ref, workflow_sha="c" * 40,
        signed_source_sha=key.head_sha,
        subject="repo:" + REPO + ":pull_request",
    )
    signature = R010OIDCSignatureReceipt(
        jwt_sha256="1" * 64, signing_input_sha256="2" * 64,
        signed_payload_sha256="3" * 64,
        issuer_metadata_sha256="4" * 64, jwks_sha256="5" * 64,
        issuer="https://token.actions.githubusercontent.com",
        jwks_url="https://token.actions.githubusercontent.com/.well-known/jwks",
        key_id="synthetic", algorithm="RS256",
        checked_run_id=ex.run_id,
        checked_run_attempt=ex.run_attempt,
        checked_check_run_id=ex.check_run_id,
        signed_subject=ex.subject, verified_at_unix=NOW - 35,
        expires_unix=NOW + 250,
    )
    provider = R010ProviderOIDCSource(
        signature=signature, metadata_sha256="4" * 64,
        jwks_sha256="5" * 64, original_jwt_sha256="1" * 64)
    return dict(job_key=key, signed_expected=ex, source=provider,
                now_unix=NOW)


def api_json():
    run_url = _API + "/actions/runs/1001"
    jobs_url = (
        run_url + "/attempts/1/jobs?per_page=100&page=1")
    run = {
        "id": 1001, "run_attempt": 1, "status": "in_progress",
        "conclusion": None, "head_sha": "a" * 40,
        "workflow_id": 145, "path": ".github/workflows/r010.yml",
        "event": "pull_request", "repository": {"full_name": REPO},
    }
    jobs = {"total_count": 1, "jobs": [{
        "id": 3001, "run_id": 1001, "run_attempt": 1,
        "run_url": run_url, "head_sha": "a" * 40,
        "check_run_url": _API + "/check-runs/2001",
        "name": "r010_preexec_hold", "status": "in_progress",
        "conclusion": None, "completed_at": None,
        "started_at": "2026-11-10T07:00:00Z",
    }]}
    return run_url, jobs_url, run, jobs


@pytest.fixture
def fake_api(monkeypatch):
    from gateway.lbe_r010_provider_transport import _ConstrainedHttps
    run_url, jobs_url, run, jobs = api_json()
    objects = {run_url: run, jobs_url: jobs}
    calls = []

    def get(self, url, *, limit, oidc_bearer=None):
        assert oidc_bearer is None
        assert url in objects
        calls.append((url, limit))
        return json.dumps(objects[url], sort_keys=True).encode()

    monkeypatch.setattr(_ConstrainedHttps, "get", get)
    return objects, calls


def test_provider_current_run_and_check_run_source_match_but_no_grant(fake_api):
    objects, calls = fake_api
    observed = read_r010_current_github_job_source(**packet())
    assert observed.job_id == 3001
    assert observed.check_run_id == 2001  # distinct from job ID
    assert observed.run_id == 1001 and observed.run_attempt == 1
    assert observed.current_job_source_matched is True
    assert observed.provider_full_provenance_attested is False
    assert observed.owner_product_t1_grant_verified is False
    assert observed.native_launch_allowed is False
    assert observed.six_command_product_t1_pass is False
    assert len(observed.run_body_sha256) == 64
    assert [url for url, _ in calls] == list(objects)


@pytest.mark.parametrize("root,field,wrong", [
    ("run", "id", 1002),
    ("run", "run_attempt", 2),
    ("run", "status", "completed"),
    ("run", "conclusion", "success"),
    ("run", "event", "push"),
    ("run", "head_sha", "f" * 40),
    ("run", "workflow_id", 1),
    ("run", "path", ".github/workflows/other.yml"),
    ("jobs", "total_count", 2),
    ("job", "check_run_url", _API + "/check-runs/2222"),
    ("job", "run_id", 1002),
    ("job", "run_attempt", 2),
    ("job", "status", "completed"),
    ("job", "completed_at", "2026-11-10T07:01:00Z"),
    ("job", "head_sha", "f" * 40),
    ("job", "name", "other-job"),
])
def test_wrong_provider_run_job_or_sibling_attestation_denied(
        fake_api, root, field, wrong):
    objects, _ = fake_api
    run_url, jobs_url, _, _ = api_json()
    if root == "run":
        objects[run_url][field] = wrong
    elif root == "jobs":
        objects[jobs_url][field] = wrong
    else:
        objects[jobs_url]["jobs"][0][field] = wrong
    with pytest.raises(R010CurrentJobDenied):
        read_r010_current_github_job_source(**packet())


def test_duplicate_check_run_and_noncanonical_provider_job_list_denied(fake_api):
    objects, _ = fake_api
    _, jobs_url, _, _ = api_json()
    extra = deepcopy(objects[jobs_url]["jobs"][0])
    extra["id"] = 3002
    objects[jobs_url]["jobs"].append(extra)
    objects[jobs_url]["total_count"] = 2
    with pytest.raises(R010CurrentJobDenied, match="not unique"):
        read_r010_current_github_job_source(**packet())


@pytest.mark.parametrize("change", [
    lambda p: p.update(job_key=replace(p["job_key"], head_sha="f" * 40)),
    lambda p: p.update(signed_expected=replace(
        p["signed_expected"], check_run_id="999")),
    lambda p: p.update(source=replace(p["source"],
        original_jwt_sha256="f" * 64)),
    lambda p: p.update(source=replace(p["source"],
        native_launch_allowed=True)),
    lambda p: p.update(now_unix=NOW + 300),
])
def test_t0_signed_identity_tuple_drift_rejected_before_api(fake_api, change):
    _, calls = fake_api
    data = packet()
    change(data)
    with pytest.raises(R010CurrentJobDenied):
        read_r010_current_github_job_source(**data)
    assert calls == []


def test_transport_only_two_canonical_job_urls():
    assert _current_job_api_url(_API + "/actions/runs/1001")
    assert _current_job_api_url(
        _API + "/actions/runs/1001/attempts/1/jobs?per_page=100&page=1")
    for bad in (
        _API + "/actions/runs/01",
        _API + "/actions/runs/1001/attempts/0/jobs?per_page=100&page=1",
        _API + "/actions/runs/1001/attempts/1/jobs?per_page=100&page=2",
        _API + "/actions/runs/1001/attempts/1/jobs?per_page=100&page=1&x=1",
        "http://api.github.com/repos/" + REPO + "/actions/runs/1001",
        _API + "/actions/runs/1001/attempts/1/jobs%3fper_page=100&page=1",
        _API + "/actions/runs/1001/check-runs",
    ):
        assert not _current_job_api_url(bad)
