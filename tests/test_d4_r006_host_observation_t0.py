"""Pure T0 proof that labels are not real PRODUCT_T1 authorization."""
import os
import subprocess
from types import SimpleNamespace

import pytest

from tools.d4_r006_host_observation_t0 import observe_r006_host_t0

GOOD_ENV = {
    "GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "pull_request",
    "GITHUB_REPOSITORY": "chinanjjohn2012/mac-file-gateway",
    "GITHUB_RUN_ID": "42445457687", "GITHUB_RUN_ATTEMPT": "1",
    "G05_EXPECTED_HEAD": "a" * 40, "RUNNER_ENVIRONMENT": "github-hosted",
    "RUNNER_OS": "macOS", "RUNNER_ARCH": "ARM64",
    "ImageOS": "macos15", "ImageVersion": "20261104.0514.1",
}
DARWIN = SimpleNamespace(sysname="Darwin", machine="arm64")


def check(env=None, kernel=DARWIN, tag="darwin", mac="15.8.2"):
    return observe_r006_host_t0(
        environ=GOOD_ENV if env is None else env,
        uname=kernel, platform_tag=tag, macos_release=mac,
    )


def test_structurally_valid_host_is_still_never_a_grant(monkeypatch):
    def forbidden(*_a, **_kw):
        raise AssertionError("host T0 cannot spawn or send OS signal")
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(os, "kill", forbidden)
    p = check()
    assert p["t0_platform_claims_consistent"] is True
    assert p["native_launch_allowed"] is False
    assert p["real_product_t1_executed"] is False
    assert p["owner_signed_run_attempt_approved"] is False
    assert p["github_provider_authenticated_from_independent_api"] is False
    assert p["full_boot_image_attested"] is False
    assert p["actual_loaded_graph_proven"] is False


@pytest.mark.parametrize("name,value", [
    ("RUNNER_ENVIRONMENT", "self-hosted"),
    ("RUNNER_OS", "Linux"),
    ("RUNNER_ARCH", "X64"),
    ("GITHUB_RUN_ATTEMPT", "0"),
    ("GITHUB_RUN_ID", "-1"),
    ("G05_EXPECTED_HEAD", "bad"),
    ("GITHUB_EVENT_NAME", "workflow_dispatch"),
    ("GITHUB_REPOSITORY", "attacker/repo"),
    ("ImageOS", "macos26"),
    ("ImageVersion", "unknown"),
    ("ImageVersion", "20261104.0514.1" + "X" * 200),
])
def test_invalid_identity_claims_fail_closed(name, value):
    p = check({**GOOD_ENV, name: value})
    assert p["t0_platform_claims_consistent"] is False
    assert p["native_launch_allowed"] is False


@pytest.mark.parametrize("kernel,tag,release", [
    (SimpleNamespace(sysname="Linux", machine="arm64"), "linux", "15.8.2"),
    (SimpleNamespace(sysname="Darwin", machine="x86_64"), "darwin", "15.8.2"),
    (DARWIN, "darwin", "14.8.0"),
    (DARWIN, "darwin", "26.0"),
])
def test_mismatched_physical_host_never_passes_t0(kernel, tag, release):
    p = check(kernel=kernel, tag=tag, mac=release)
    assert p["t0_platform_claims_consistent"] is False


def test_ambient_secrets_cannot_be_logged_by_observer():
    p = check({**GOOD_ENV, "GH_TOKEN": "supersecret",
               "AWS_SECRET_ACCESS_KEY": "PRIVATE", "PATH": "secret-path"})
    serialized = str(p)
    for secret in ("supersecret", "PRIVATE", "secret-path"):
        assert secret not in serialized
    assert set(p["claimed_job_and_image_metadata"]) == set(GOOD_ENV)
