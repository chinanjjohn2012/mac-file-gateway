"""PREEXEC stdlib-only initial environment closure, fully synthetic SAFE T0.

No actual OIDC request, Github Job, SSH agent, autofs activation or product
Popen. This guards the pre-gateway-import bootstrap SOURCE contract only.
"""
from dataclasses import replace
import ast
import inspect
import os
import socket
import subprocess

import pytest

from tools import r010_a1_preexec_bootstrap as bootstrap
from gateway.lbe_r010_preexec_env import (
    R010ExpectedRunnerEnv, scrub_preexec_mapping,
    build_closed_product_child_env,
)

HEAD = "a" * 40
SOCK = "/private/tmp/mock-ssh-agent"
URL = (
    "https://pipelinesghubeus15.actions.githubusercontent.com/"
    "_apis/oidc/token?api-version=2.0"
)
BEARER = "synthetic-not-real-github-oidc-bearer"


@pytest.fixture(autouse=True)
def forbid_native_product_or_network(monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("SAFE T0 may not launch/contact/signal")
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(os, "kill", forbidden)
    monkeypatch.setattr(os, "killpg", forbidden, raising=False)


def expected():
    return bootstrap.R010BootstrapExpected(
        head_sha=HEAD, run_id="42778400689", run_attempt="1",
        job_name="observe-macos-15-arm64-t0",
        image_version="20261104.0514.1",
        private_home="/private/tmp/r010-test-home",
        private_tmp="/private/tmp/r010-test-tmp",
    )


def environment():
    ex = expected()
    return {
        "PATH": "/usr/bin:/bin", "HOME": ex.private_home,
        "TMPDIR": ex.private_tmp, "LANG": "C", "LC_ALL": "C",
        "GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "pull_request",
        "GITHUB_REPOSITORY": "chinanjjohn2012/mac-file-gateway",
        "GITHUB_RUN_ID": ex.run_id, "GITHUB_RUN_ATTEMPT": ex.run_attempt,
        "GITHUB_JOB": ex.job_name, "G05_EXPECTED_HEAD": ex.head_sha,
        "RUNNER_ENVIRONMENT": "github-hosted",
        "RUNNER_OS": "macOS", "RUNNER_ARCH": "ARM64",
        "ImageOS": "macos15", "ImageVersion": ex.image_version,
        "SSH_AUTH_SOCK": SOCK,
        "ACTIONS_ID_TOKEN_REQUEST_URL": URL,
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN": BEARER,
    }


def test_tiny_module_has_no_top_level_or_nested_gateway_import():
    tree = ast.parse(inspect.getsource(bootstrap))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert all(not item.name.startswith("gateway")
                       for item in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert node.module is None or not node.module.startswith("gateway")
    assert not hasattr(bootstrap, "launch_product")
    assert not hasattr(bootstrap, "request_oidc")


def test_exact_18_plus_2_preexec_scrub_matches_existing_product_rule():
    env = environment()
    control = dict(env)
    observed = bootstrap.close_r010_a1_preimport_bootstrap(
        env=env, expected=expected())
    assert observed.status == "R010_A1_PREIMPORT_SCRUB_SOURCE_ONLY"
    assert observed.native_launch_allowed is False
    assert observed.original_oidc_token_requested is False
    assert observed.ssh_agent_protocol_calls == 0
    assert observed.real_preexec_job_provider_attested is False
    assert env == {
        "PATH": "/usr/bin:/bin", "HOME": "/private/tmp/r010-test-home",
        "TMPDIR": "/private/tmp/r010-test-tmp", "LANG": "C", "LC_ALL": "C"}
    assert set(observed.helper_names) == set(env)
    assert "SSH_AUTH_SOCK" not in env
    assert BEARER not in repr(observed)
    assert SOCK not in repr(observed)
    typed = R010ExpectedRunnerEnv(
        run_id=expected().run_id, run_attempt=expected().run_attempt,
        head_sha=HEAD, job_name=expected().job_name,
        image_version=expected().image_version,
        private_home=expected().private_home,
        private_tmp=expected().private_tmp)
    product_helper = scrub_preexec_mapping(control, typed)
    assert product_helper == env
    assert build_closed_product_child_env(env) == env


@pytest.mark.parametrize("key,value", [
    ("SSH_AUTH_SOCK", None),
    ("SSH_AUTH_SOCK", "relative-agent.sock"),
    ("SSH_AUTH_SOCK", "/private/../tmp/agent"),
    ("ACTIONS_ID_TOKEN_REQUEST_TOKEN", ""),
    ("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "bad"),
    ("ACTIONS_ID_TOKEN_REQUEST_URL", URL + "&audience=forged"),
    ("GITHUB_REPOSITORY", "attacker/repo"),
    ("GITHUB_RUN_ID", "0"),
    ("GITHUB_RUN_ATTEMPT", "02"),
    ("G05_EXPECTED_HEAD", "f" * 40),
    ("ImageVersion", "unknown-image"),
    ("RUNNER_ENVIRONMENT", "self-hosted"),
    ("HOME", "/private/tmp/" + BEARER),
    ("HTTPS_PROXY", "http://untrusted.invalid/"),
    ("GIT_ASKPASS", "/tmp/agent"),
])
def test_unreviewed_preexec_selector_clears_all_on_failure(key, value):
    env = environment()
    if value is None:
        env.pop(key)
    else:
        env[key] = value
    with pytest.raises(bootstrap.R010BootstrapDenied):
        bootstrap.close_r010_a1_preimport_bootstrap(
            env=env, expected=expected())
    assert env == {}


def test_malformed_expectations_cannot_mint_preexec_or_preserve_selectors():
    for broken in (
        replace(expected(), head_sha="short"),
        replace(expected(), run_attempt="0"),
        replace(expected(), private_home="../outside"),
        replace(expected(), image_version="old"),
    ):
        env = environment()
        with pytest.raises(bootstrap.R010BootstrapDenied):
            bootstrap.close_r010_a1_preimport_bootstrap(
                env=env, expected=broken)
        assert not env


def test_nonmutable_preexec_env_is_always_denied():
    with pytest.raises(bootstrap.R010BootstrapDenied):
        bootstrap.close_r010_a1_preimport_bootstrap(
            env=None, expected=expected())
