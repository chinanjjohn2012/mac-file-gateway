"""R010 A1 PREEXEC credential-selector to helper boundary SAFE T0.

No live GitHub OIDC, JWT, socket connects, SSH agent, autofs, Popen or T1.
Exercises real exact-map validation, in-place scrub and closed child recipe.
"""
from dataclasses import replace
import os
import socket
import subprocess

import pytest

from gateway.lbe_r010_preexec_env import (
    R010ExpectedRunnerEnv,
    R010PreexecEnvDenied,
    build_closed_product_child_env,
    scrub_preexec_mapping,
    validate_preexec_mapping,
)

HEAD = "e" * 40
URL = (
    "https://pipelinesghubeus15.actions.githubusercontent.com/"
    "_apis/oidc/token?api-version=2.0"
)
TOKEN = "non-secret-mock-oidc-bearer-1234567890"
SOCK = "/private/tmp/ssh-agent-metadata-only"


def expected(**kw):
    data = dict(
        run_id="42495003699", run_attempt="2", head_sha=HEAD,
        job_name="r010_preexec_hold", image_version="20261104.0514.1",
        private_home="/private/tmp/mfg-private-home",
        private_tmp="/private/tmp/mfg-private-tmp",
    )
    data.update(kw)
    return R010ExpectedRunnerEnv(**data)


def env_for(identity=None):
    e = identity or expected()
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": e.private_home, "TMPDIR": e.private_tmp,
        "LANG": "C", "LC_ALL": "C",
        "GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "pull_request",
        "GITHUB_REPOSITORY": "chinanjjohn2012/mac-file-gateway",
        "GITHUB_RUN_ID": e.run_id, "GITHUB_RUN_ATTEMPT": e.run_attempt,
        "GITHUB_JOB": e.job_name, "G05_EXPECTED_HEAD": e.head_sha,
        "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "macOS",
        "RUNNER_ARCH": "ARM64", "ImageOS": "macos15",
        "ImageVersion": e.image_version, "SSH_AUTH_SOCK": SOCK,
        "ACTIONS_ID_TOKEN_REQUEST_URL": URL,
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN": TOKEN,
    }


def _deny_foreign_process(monkeypatch):
    def denied(*args, **kwargs):
        raise AssertionError("SAFE T0 forbids real network, socket or Popen")
    monkeypatch.setattr(subprocess, "Popen", denied)
    monkeypatch.setattr(os, "kill", denied)
    monkeypatch.setattr(os, "killpg", denied, raising=False)
    monkeypatch.setattr(socket.socket, "connect", denied, raising=True)


def test_exact_runner_env_scrubs_to_five_product_keys_before_any_child(monkeypatch):
    _deny_foreign_process(monkeypatch)
    bootstrap = env_for()
    validate_preexec_mapping(bootstrap, expected())
    helper = scrub_preexec_mapping(bootstrap, expected())
    assert bootstrap == helper
    assert frozenset(helper) == frozenset({"PATH","HOME","TMPDIR","LANG","LC_ALL"})
    assert "SSH_AUTH_SOCK" not in helper
    assert "ACTIONS_ID_TOKEN_REQUEST_URL" not in helper
    assert "ACTIONS_ID_TOKEN_REQUEST_TOKEN" not in helper
    assert TOKEN not in repr(helper)
    child = build_closed_product_child_env(
        helper,
        requested_extra_names=frozenset({"PYTHONUNBUFFERED","PIP_NO_INDEX"}))
    assert child["PYTHONUNBUFFERED"] == "1"
    assert child["PIP_NO_INDEX"] == "1"
    assert "SSH_AUTH_SOCK" not in child
    assert TOKEN not in repr(child)
    assert build_closed_product_child_env(helper) == helper


@pytest.mark.parametrize("key,value", [
    ("SSH_ASKPASS", "/tmp/mock"),
    ("GIT_ASKPASS", "/tmp/mock"),
    ("HTTP_PROXY", "http://invalid.local"),
    ("ALL_PROXY", "socks5://invalid.local"),
    ("AWS_ACCESS_KEY_ID", "not-a-secret"),
    ("PIP_INDEX_URL", "https://example.invalid/simple"),
    ("GITHUB_RUN_ID_EXTRA", "7"),
    ("RUNNER_OS_EXTRA", "Linux"),
    ("ACTIONS_ID_TOKEN_REQUEST_EXTRA", "fake"),
    ("RANDOM_UNREVIEWED_KEY", "1"),
])
def test_extra_bootstrap_key_denied_and_inplace_scrub_attempted(key, value):
    wrong = env_for()
    wrong[key] = value
    with pytest.raises(R010PreexecEnvDenied):
        scrub_preexec_mapping(wrong, expected())
    assert wrong == {}


@pytest.mark.parametrize("key", [
    "SSH_AUTH_SOCK", "ACTIONS_ID_TOKEN_REQUEST_URL",
    "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "GITHUB_RUN_ATTEMPT",
    "ImageVersion", "RUNNER_ARCH",
])
def test_missing_runner_selector_denied(key):
    wrong = env_for()
    del wrong[key]
    with pytest.raises(R010PreexecEnvDenied):
        validate_preexec_mapping(wrong, expected())


@pytest.mark.parametrize("url", [
    "https://pipelinesghubeus15.actions.githubusercontent.com/wrong?api-version=2.0",
    URL + "&unexpected=x",
    URL + "&api-version=2.0",
    URL + "&audience=forged",
    URL.replace("/token?", "/%74oken?"),
    URL.replace("api-version=2.0", "api-version=%32.0"),
    URL.replace("https://", "http://"),
    URL.replace("https://", "https://user@"),
    URL.replace(".com/", ".com:443/"),
    URL + "#fragment",
    URL.replace("https://", "https://other.example.com/"),
])
def test_oidc_endpoint_cannot_be_changed_or_inject_extra_parameters(url):
    wrong = env_for()
    wrong["ACTIONS_ID_TOKEN_REQUEST_URL"] = url
    with pytest.raises(R010PreexecEnvDenied):
        validate_preexec_mapping(wrong, expected())


@pytest.mark.parametrize("attempt", ["0","01","+2"," 2","2 ","2.0","2e0","\u0662","\uff12"])
def test_noncanonical_current_run_attempt_rejected(attempt):
    sample = env_for()
    sample["GITHUB_RUN_ATTEMPT"] = attempt
    with pytest.raises(R010PreexecEnvDenied):
        validate_preexec_mapping(sample, expected(run_attempt=attempt))


@pytest.mark.parametrize("kind,wrong", [
    ("GITHUB_RUN_ID","5"), ("GITHUB_JOB","other_job"),
    ("G05_EXPECTED_HEAD","f"*40), ("ImageVersion","unreviewed-image"),
    ("RUNNER_ENVIRONMENT","self-hosted"), ("RUNNER_OS","Linux"),
    ("GITHUB_REPOSITORY","other/repository"),
])
def test_wrong_runtime_source_identity_denied(kind, wrong):
    sample = env_for()
    sample[kind] = wrong
    with pytest.raises(R010PreexecEnvDenied):
        validate_preexec_mapping(sample, expected())


def test_unknown_or_credential_child_recipe_never_allowed(monkeypatch):
    _deny_foreign_process(monkeypatch)
    helper = scrub_preexec_mapping(env_for(), expected())
    bad = [
        frozenset({"SSH_AUTH_SOCK"}), frozenset({"GIT_ASKPASS"}),
        frozenset({"ACTIONS_ID_TOKEN_REQUEST_TOKEN"}),
        frozenset({"PIPENV_DOTENV_LOCATION"}),
        frozenset({"RUNNER_OS"}),
        frozenset({"HTTP_PROXY"}),
        frozenset({"AWS_ACCESS_KEY_ID"}),
        frozenset({"UNKNOWN"}),
        frozenset({"PIP_INDEX_URL"}),
    ]
    for extras in bad:
        with pytest.raises(R010PreexecEnvDenied):
            build_closed_product_child_env(helper, requested_extra_names=extras)
    with pytest.raises(R010PreexecEnvDenied):
        build_closed_product_child_env(helper, requested_extra_names={"PIP_NO_INDEX"})
    with pytest.raises(R010PreexecEnvDenied):
        build_closed_product_child_env({**helper, "SSH_AUTH_SOCK": SOCK})


@pytest.mark.parametrize("extra", [
    "PYTHONUNBUFFERED","PYTHONDONTWRITEBYTECODE",
    "PIP_NO_INDEX","PIP_DISABLE_PIP_VERSION_CHECK",
])
def test_reviewed_extra_child_variables_exact_value_only(extra):
    helper = scrub_preexec_mapping(env_for(), expected())
    value = build_closed_product_child_env(
        helper, requested_extra_names=frozenset({extra}))
    assert value[extra] == "1"
    assert len(value) == 6
    assert "ACTIONS_ID_TOKEN_REQUEST_TOKEN" not in value


def test_invalid_bearer_and_renamed_selector_value_denied():
    wrong = env_for()
    wrong["ACTIONS_ID_TOKEN_REQUEST_TOKEN"] = "too-short"
    with pytest.raises(R010PreexecEnvDenied):
        scrub_preexec_mapping(wrong, expected())
    assert not wrong
    wrong = env_for()
    wrong["HOME"] = "/private/" + TOKEN + "-renamed"
    with pytest.raises(R010PreexecEnvDenied):
        validate_preexec_mapping(wrong, expected(private_home=wrong["HOME"]))


def test_invalid_expected_bootstrap_clears_selector_not_authorizes_native():
    wrong = env_for()
    with pytest.raises(R010PreexecEnvDenied):
        scrub_preexec_mapping(wrong, replace(expected(), run_attempt="02"))
    assert wrong == {}
