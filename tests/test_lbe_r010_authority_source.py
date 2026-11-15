"""R010 same-Job authority source binding: offline SAFE T0 only."""

from dataclasses import replace
import hashlib
import json
import os
import socket
import subprocess

import pytest

from gateway.lbe_r010_authority_source import (
    R010AuthoritySourceDenied, bind_r010_authority_source_to_job,
)
from gateway.lbe_r010_grant_candidate import (
    R010GrantExpected, R010GrantSourceObservation,
)
from gateway.lbe_r010_job_envelope import (
    R010JobEnvelopeDenied, R010JobKey, _create_once_in_pinned_anchor,
)
from gateway.lbe_r010_owner_choice import R010OwnerDesignChoiceObservation
from gateway.lbe_r010_provider_job import R010CurrentJobSource
from gateway.lbe_r010_provider_transport import R010GithubOwnerRead
from gateway.lbe_r010_serial_journal import (
    R010SerialAdmissionDenied, R010SerialNonceJournal,
)


@pytest.fixture(autouse=True)
def forbid_any_live_provider_or_child(monkeypatch):
    def denied(*_args, **_kwargs):
        raise AssertionError("SAFE T0 forbids real subprocess/network/signal")
    monkeypatch.setattr(socket.socket, "connect", denied)
    monkeypatch.setattr(subprocess, "Popen", denied)
    monkeypatch.setattr(os, "kill", denied)
    monkeypatch.setattr(os, "killpg", denied, raising=False)


def job_key():
    return R010JobKey(
        repo="chinanjjohn2012/mac-file-gateway", pr=114,
        workflow_id=145, workflow_path=".github/workflows/r010.yml",
        workflow_ref=("chinanjjohn2012/mac-file-gateway/"
                      ".github/workflows/r010.yml@refs/heads/main"),
        run_id=1001, run_attempt=1, check_run_id=2001,
        job_name="r010_preexec_hold", head_sha="a" * 40,
        design_id="MWE-LBE-R010-AUTHORITY-CHAIN-DESIGN-013-CANDIDATE",
        design_blob="f57e39543a6fe3d64fe99b8669fc7da854b93a64",
        owner_choice_comment_id=6740275850,
        host_option="A1", review_sequence_option="B1",
        state_domain="R010_EPHEMERAL_JOB_STATE_V1",
    )


def six_nonces():
    raw = tuple("%064x" % (i + 1) for i in range(6))
    hashed = tuple(hashlib.sha256(bytes.fromhex(v)).hexdigest() for v in raw)
    return raw, hashed


@pytest.fixture
def active_job(tmp_path):
    anchor = tmp_path / "fixed"
    anchor.mkdir(mode=0o700)
    fd = os.open(anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        with _create_once_in_pinned_anchor(fd, job_key()) as instance:
            raw, hashed = six_nonces()
            journal = R010SerialNonceJournal(
                instance, six_nonce_sha256=hashed)
            workdir = anchor / instance.snapshot()["envelope_root_name"]
            yield instance, journal, workdir / "command-journal", raw
    finally:
        os.close(fd)


def candidates(instance, journal):
    key = job_key()
    choice = R010OwnerDesignChoiceObservation(
        comment_id=6740275850, body_sha256="1" * 64,
        design_id=key.design_id, design_blob=key.design_blob,
        b_review_node_id="PRR_R014_B", c_review_node_id="PRR_R014_C",
        options=("A1", "B1"),
        risk_marker="R010_REAFFIRM_R006_RISK1_9_PLUS_RISK10_11",
    )
    owner = R010GithubOwnerRead(
        choice=choice, raw_choice_sha256="2" * 64,
        raw_reviews_sha256="3" * 64)
    current = R010CurrentJobSource(
        run_id=1001, run_attempt=1, job_id=3001, check_run_id=2001,
        head_sha="a" * 40, run_body_sha256="4" * 64,
        jobs_body_sha256="5" * 64, oidc_jwt_sha256="6" * 64)
    grant = R010GrantSourceObservation(
        grant_comment_id=987654321, body_sha256="7" * 64,
        implementation_head_sha="a" * 40,
        standards_review_node_id="PRR_CODE_B",
        spec_review_node_id="PRR_CODE_C",
        signed_jwt_sha256="6" * 64,
        job_envelope_key_sha256=key.key_sha256(),
        grant_expires_unix=1800000100,
    )
    names = set(R010GrantExpected.__dataclass_fields__)
    values = {name: "f" * 64 for name in names}
    values.update(base_sha="b" * 40, head_sha="a" * 40,
                  tree_sha="c" * 40,
                  job_envelope_key_sha256=key.key_sha256())
    expected = R010GrantExpected(**values)
    return dict(
        envelope=instance, job_key=key, journal=journal,
        owner_source=owner, current_job=current,
        grant_source=grant, expected=expected)


def test_one_canonical_job_fsync_source_binding_is_never_product_grant(
        active_job):
    instance, journal, directory, raw = active_job
    args = candidates(instance, journal)
    result = bind_r010_authority_source_to_job(**args)
    assert result.status == "COMPOSED_CURRENT_SOURCE_ONLY_NO_T1"
    assert result.provider_runtime_authenticated is False
    assert result.owner_runtime_authenticated is False
    assert result.native_launch_allowed is False
    assert result.six_command_product_t1_pass is False
    path = directory / "r010-authority-source-binding.json"
    data = json.loads(path.read_text())
    assert data["job_key_sha256"] == job_key().key_sha256()
    assert data["grant_body_sha256"] == "7" * 64
    assert data["source_model_only"] is True
    assert data["native_launch_allowed"] is False
    assert data["six_command_product_t1_pass"] is False
    assert result.source_digest_sha256 == hashlib.sha256(path.read_bytes()).hexdigest()
    with pytest.raises(R010AuthoritySourceDenied, match="already used"):
        bind_r010_authority_source_to_job(**args)
    with pytest.raises(R010SerialAdmissionDenied, match="not implemented"):
        journal.begin_later_row(2, raw[1])
    assert journal.burn_first_nonce(raw[0])["native_launch_allowed"] is False


@pytest.mark.parametrize("mutation", [
    lambda d: d.update(current_job=replace(
        d["current_job"], run_id=999)),
    lambda d: d.update(current_job=replace(
        d["current_job"], check_run_id=999)),
    lambda d: d.update(current_job=replace(
        d["current_job"], native_launch_allowed=True)),
    lambda d: d.update(grant_source=replace(
        d["grant_source"], implementation_head_sha="f" * 40)),
    lambda d: d.update(grant_source=replace(
        d["grant_source"], owner_comment_authenticated=True)),
    lambda d: d.update(grant_source=replace(
        d["grant_source"], native_launch_allowed=True)),
    lambda d: d.update(owner_source=replace(
        d["owner_source"], native_launch_allowed=True)),
    lambda d: d.update(owner_source=replace(
        d["owner_source"], choice=replace(
            d["owner_source"].choice, options=("A0", "B1")))),
    lambda d: d.update(expected=replace(
        d["expected"], head_sha="f" * 40)),
    lambda d: d.update(expected=replace(
        d["expected"], job_envelope_key_sha256="f" * 64)),
])
def test_cross_component_or_claimed_t1_drift_denied(active_job, mutation):
    instance, journal, directory, _ = active_job
    args = candidates(instance, journal)
    mutation(args)
    with pytest.raises(R010AuthoritySourceDenied):
        bind_r010_authority_source_to_job(**args)
    assert not (directory / "r010-authority-source-binding.json").exists()


def test_source_binding_must_precede_any_burn(active_job):
    instance, journal, directory, raw = active_job
    journal.burn_first_nonce(raw[0])
    with pytest.raises(R010AuthoritySourceDenied, match="after row burn"):
        bind_r010_authority_source_to_job(
            **candidates(instance, journal))
    assert not (directory / "r010-authority-source-binding.json").exists()


def test_uncertain_fsync_prevents_reclaim_or_second_attempt(active_job, monkeypatch):
    from gateway import lbe_r010_authority_source as mod
    instance, journal, _, _ = active_job
    args = candidates(instance, journal)
    def fail(*_a, **_kw):
        raise R010JobEnvelopeDenied("synthetic storage fault")
    monkeypatch.setattr(mod, "_write_once", fail)
    with pytest.raises(R010AuthoritySourceDenied, match="uncertain"):
        bind_r010_authority_source_to_job(**args)
    with pytest.raises(R010AuthoritySourceDenied, match="already used"):
        bind_r010_authority_source_to_job(**args)


def test_closed_envelope_never_accepts_authority_source(active_job):
    instance, journal, directory, _ = active_job
    args = candidates(instance, journal)
    instance.close()
    with pytest.raises(R010AuthoritySourceDenied, match="closed"):
        bind_r010_authority_source_to_job(**args)
    assert not (directory / "r010-authority-source-binding.json").exists()
