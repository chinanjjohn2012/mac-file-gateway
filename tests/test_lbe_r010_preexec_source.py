"""R010 all-source PREEXEC composition with synthetic RSA/Job/Mount, T0."""
from dataclasses import replace
import base64
import hashlib
import json
import os
import socket
import subprocess

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from gateway.lbe_r010_preexec_source import (
    R010PreexecSourceDenied, compose_r010_preexec_source_only,
)
from gateway.lbe_r010_job_envelope import R010JobKey, _create_once_in_pinned_anchor
from gateway.lbe_r010_oidc_verify import R010OIDCExpected
from gateway.lbe_r010_preexec_env import R010ExpectedRunnerEnv
from gateway.lbe_r010_a1_mount import inspect_r010_a1_mounts

REPO = "chinanjjohn2012/mac-file-gateway"
DESIGN = "f57e39543a6fe3d64fe99b8669fc7da854b93a64"
BASE = "ca90cf30095695479615e475b8440e09f02f34d9"
R014_HEAD = "0ef4671b63617c3a3519087f695cb335c67e9d9d"
R014_TREE = "0b7f3585329b4c679ec2b200803cda762a94ec87"
DESIGN_ID = "MWE-LBE-R010-AUTHORITY-CHAIN-DESIGN-013-CANDIDATE"
ROUND = "D4-R014-AUTHORITY-CHAIN-DESIGN-013"
B = "PRR_kwDOU5v3IM8AAAABWtAZjQ"
C = "PRR_kwDOU5v3IM8AAAABWtBPMQ"
NOW = 1800000000
ISSUER = "https://token.actions.githubusercontent.com"


@pytest.fixture(autouse=True)
def never_spawn_or_connect(monkeypatch):
    def deny(*args, **kwargs):
        raise AssertionError("R010 synthetic T0 cannot spawn/activate/connect")
    monkeypatch.setattr(subprocess, "Popen", deny)
    monkeypatch.setattr(os, "kill", deny)
    monkeypatch.setattr(os, "killpg", deny, raising=False)
    monkeypatch.setattr(socket.socket, "connect", deny)


@pytest.fixture(scope="module")
def signing_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def owner_choice():
    fields = {
        "repo": REPO, "pr": "114",
        "task_id": "MULTI-EXEC-LBE-FIVE-DAY-CANDIDATE-20261105",
        "review_round": ROUND, "r010_design_id": DESIGN_ID,
        "r010_design_blob": DESIGN,
        "design_base_sha": BASE, "design_head_sha": R014_HEAD,
        "design_head_tree": R014_TREE,
        "b_r010_design_review_id": B, "c_r010_design_review_id": C,
        "host_option": "A1", "review_sequence_option": "B1",
        "state_domain": "R010_EPHEMERAL_JOB_STATE_V1",
        "risk_marker": "R010_REAFFIRM_R006_RISK1_9_PLUS_RISK10_11",
    }
    body = (
        "R010_OWNER_DESIGN_CHOICE_V1\n\n" +
        "\n".join(k + ": " + v for k, v in fields.items()) +
        "\n\n## 1. Choice\nA1 + B1 RISK_10 RISK_11\n"
        "PRODUCT_T1: NOT_AUTHORIZED\n"
        "FULL_CODE_REVIEW_PASS: NOT_ISSUED\n"
        "INTEGRATION_STATUS: NOT_TESTED\nR10_STATUS: BLOCKED\n"
    )
    return {
        "id": 6740275850,
        "user": {"login": "chinanjjohn2012", "id": 13314291, "type": "User"},
        "author_association": "OWNER",
        "issue_url": "https://api.github.com/repos/" + REPO + "/issues/114",
        "created_at": "2026-11-09T12:39:35Z",
        "updated_at": "2026-11-09T12:39:35Z",
        "body": body,
    }


def review(role):
    key = "STANDARDS_REVIEW" if role == "STANDARDS_REVIEWER" else "SPEC_REVIEW"
    fields = {
        "ROLE": role, "REPO": REPO, "REVIEW_ROUND": ROUND,
        "REVIEWED_BASE_SHA": BASE, "REVIEWED_HEAD_SHA": R014_HEAD,
        "REVIEWED_TREE_SHA": R014_TREE, "REVIEW_SCOPE": "TARGETED",
        "REVIEW_PROGRESS": "REVIEW_COMPLETE",
        "REVIEW_LEVEL": "TARGETED_REVIEW_PASS", "VERDICT": "PASS",
        "EVIDENCE_STATUS": "SUFFICIENT",
        "CONTRACT_SCOPE": DESIGN_ID + " " + DESIGN,
    }
    return {
        "node_id": B if role == "STANDARDS_REVIEWER" else C,
        "commit_id": R014_HEAD, "state": "COMMENTED",
        "submitted_at": "2026-11-08T16:01:21Z",
        "body": "GH_HANDOFF_V2 " + key + "\n" +
        "\n".join(k + ": " + v for k, v in fields.items()) +
        "\n" + ("SOURCE_ONLY_CANDIDATE " * 35),
    }


def job_key():
    return R010JobKey(
        repo=REPO, pr=114, workflow_id=145,
        workflow_path=".github/workflows/r010.yml",
        workflow_ref=REPO + "/.github/workflows/r010.yml@refs/heads/main",
        run_id=42640408843, run_attempt=1, check_run_id=129239691259,
        job_name="r010_preexec_hold", head_sha="a" * 40,
        design_id=DESIGN_ID, design_blob=DESIGN,
        owner_choice_comment_id=6740275850,
        host_option="A1", review_sequence_option="B1",
        state_domain="R010_EPHEMERAL_JOB_STATE_V1",
    )


def mount_rows():
    ordinary = [("apfs", "/", "/dev/disk0", 0x1000)]
    ordinary += [
        ("apfs", "/private/safe" + str(i), "/dev/disk" + str(i), 0x1000)
        for i in range(1, 10)
    ]
    return tuple(sorted(ordinary + [
        ("autofs", "/System/Volumes/Data/home", "map auto_home", 72351744),
    ]))


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def original_signed_jwt(key, expected):
    claims = {
        "iss": ISSUER, "aud": expected.audience,
        "repository": expected.repository, "run_id": expected.run_id,
        "run_attempt": expected.run_attempt,
        "check_run_id": expected.check_run_id,
        "workflow_ref": expected.workflow_ref,
        "workflow_sha": expected.workflow_sha,
        "sha": expected.signed_source_sha,
        "sub": expected.subject, "runner_environment": "github-hosted",
        "iat": NOW - 5, "nbf": NOW - 5, "exp": NOW + 100,
    }
    header = {"alg": "RS256", "typ": "JWT", "kid": "source-only-key"}
    signed = (b64(json.dumps(header).encode()) + "." +
              b64(json.dumps(claims).encode())).encode("ascii")
    signature = key.sign(signed, padding.PKCS1v15(), hashes.SHA256())
    pub = key.public_key().public_numbers()
    jwks = {"keys": [{
        "kid": "source-only-key", "kty": "RSA", "use": "sig", "alg": "RS256",
        "n": b64(pub.n.to_bytes(256, "big")),
        "e": b64(pub.e.to_bytes(3, "big")),
    }]}
    metadata = {"issuer": ISSUER, "jwks_uri": ISSUER + "/.well-known/jwks"}
    return (
        signed + b"." + b64(signature).encode("ascii"),
        json.dumps(metadata).encode(), json.dumps(jwks).encode(),
    )


def env_for(e):
    return {
        "PATH": "/usr/bin:/bin", "HOME": e.private_home,
        "TMPDIR": e.private_tmp, "LANG": "C", "LC_ALL": "C",
        "GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "pull_request",
        "GITHUB_REPOSITORY": REPO, "GITHUB_RUN_ID": e.run_id,
        "GITHUB_RUN_ATTEMPT": e.run_attempt, "GITHUB_JOB": e.job_name,
        "G05_EXPECTED_HEAD": e.head_sha, "RUNNER_ENVIRONMENT": "github-hosted",
        "RUNNER_OS": "macOS", "RUNNER_ARCH": "ARM64",
        "ImageOS": "macos15", "ImageVersion": e.image_version,
        "SSH_AUTH_SOCK": "/private/tmp/source-only-ssh-socket",
        "ACTIONS_ID_TOKEN_REQUEST_URL":
        "https://pipelinesghubeus15.actions.githubusercontent.com/"
        "_apis/oidc/token?api-version=2.0",
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "test-oidc-bearer-do-not-log-1234567890",
    }


@pytest.fixture
def source_inputs(tmp_path, signing_key):
    parent = tmp_path / "anchor"
    parent.mkdir(mode=0o700)
    fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        key = job_key()
        with _create_once_in_pinned_anchor(fd, key) as env:
            env_snapshot = env.snapshot()
            expected = R010OIDCExpected(
                implementation_head_sha=key.head_sha,
                job_local_secret_sha256=env_snapshot["job_local_secret_sha256"],
                run_id=str(key.run_id), run_attempt=str(key.run_attempt),
                check_run_id=str(key.check_run_id),
                workflow_ref=key.workflow_ref, workflow_sha="c" * 40,
                signed_source_sha=key.head_sha,
                subject="repo:" + REPO + ":ref:refs/heads/main",
            )
            jwt, metadata, jwks = original_signed_jwt(signing_key, expected)
            e = R010ExpectedRunnerEnv(
                run_id=str(key.run_id), run_attempt=str(key.run_attempt),
                head_sha=key.head_sha, job_name=key.job_name,
                image_version="20261104.0514.1",
                private_home="/private/tmp/mfg-test-home",
                private_tmp="/private/tmp/mfg-test-tmp",
            )
            data = {
                "comment": owner_choice(),
                "standards_review": review("STANDARDS_REVIEWER"),
                "spec_review": review("SPEC_REVIEWER"),
                "job_key": key, "envelope": env,
                "oidc_expected": expected, "original_jwt_bytes": jwt,
                "issuer_metadata_bytes": metadata, "issuer_jwks_bytes": jwks,
                "verified_at_unix": NOW, "env_expected": e,
                "bootstrap_env": env_for(e),
                "original_mount_snapshot":
                    inspect_r010_a1_mounts(observed_rows=mount_rows()),
                "mount_rows_t0": mount_rows(),
            }
            yield data
    finally:
        os.close(fd)


def test_exact_all_source_only_components_scrub_and_remain_deny(source_inputs):
    env = source_inputs["bootstrap_env"]
    original_token = env["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]
    obs = compose_r010_preexec_source_only(**source_inputs)
    assert obs.native_launch_allowed is False
    assert obs.signed_provider_job_live is False
    assert obs.owner_product_t1_grant_verified is False
    assert obs.full_code_review_pass is False
    assert obs.six_command_product_t1_pass is False
    assert len(obs.oidc_original_jwt_sha256) == 64
    assert "SSH_AUTH_SOCK" not in env
    assert "ACTIONS_ID_TOKEN_REQUEST_TOKEN" not in env
    assert original_token not in repr(obs)
    assert set(env) == {"PATH", "HOME", "TMPDIR", "LANG", "LC_ALL"}
    assert obs.helper_env_sha256 == hashlib.sha256(json.dumps(
        env, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True).encode("ascii")).hexdigest()


@pytest.mark.parametrize("kind", [
    "wrong_owner", "wrong_oidc_job", "wrong_runner", "wrong_signature",
    "altered_mount", "extra_env", "wrong_envelope",
])
def test_cross_component_drift_fails_closed_and_scrubs(source_inputs, kind):
    data = dict(source_inputs)
    if kind == "wrong_owner":
        item = dict(data["comment"])
        item["id"] = 10
        data["comment"] = item
    elif kind == "wrong_oidc_job":
        data["oidc_expected"] = replace(
            data["oidc_expected"], run_attempt="2")
    elif kind == "wrong_runner":
        data["env_expected"] = replace(
            data["env_expected"], head_sha="b" * 40)
    elif kind == "wrong_signature":
        data["original_jwt_bytes"] = data["original_jwt_bytes"][:-3] + b"abc"
    elif kind == "altered_mount":
        rows = list(data["mount_rows_t0"])
        rows[0] = ("nfs", "/", "remote", 0)
        data["mount_rows_t0"] = tuple(rows)
    elif kind == "extra_env":
        data["bootstrap_env"]["HTTP_PROXY"] = "https://unreviewed.example"
    elif kind == "wrong_envelope":
        data["job_key"] = replace(data["job_key"], run_id=1)
    with pytest.raises(R010PreexecSourceDenied):
        compose_r010_preexec_source_only(**data)
    assert data["bootstrap_env"] == {}
    with pytest.raises(Exception):
        data["envelope"].snapshot()


def test_no_object_can_claim_runtime_execution_from_source_receipt(source_inputs):
    result = compose_r010_preexec_source_only(**source_inputs)
    for name in ("grant", "start_row", "spawn", "open_socket", "launch"):
        assert not hasattr(result, name)
