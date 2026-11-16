"""R010 A1 host/source vs R006 A0 negative-control: SAFE T0 only.

No real SSH agent connect, OIDC token, autofs target access, child Popen,
Go/Pipenv/Python PRODUCT_T1 or destructive test. All host sources are injected.
"""
from dataclasses import replace
import hashlib
import json
from types import SimpleNamespace
import os
import socket
import subprocess

import pytest

from gateway import lbe_r010_a1_host as a1
from gateway.lbe_hosted_source_probe import D4HostedSelectedSourceObservation
from gateway.lbe_r006_macos_allowlist import (
    D4R006HostAllowlistDenied, verify_r006_fixed_host_allowlist_t0,
)
from gateway.lbe_r010_preexec_env import R010ExpectedRunnerEnv

SHA = "a" * 40
URL = (
    "https://pipelinesghubeus15.actions.githubusercontent.com/"
    "_apis/oidc/token?api-version=2.0"
)
BEARER = "synthetic-non-live-oidc-test-only"
SSH = "/private/tmp/ssh-agent-T0-only"
KERNEL = SimpleNamespace(sysname="Darwin", machine="arm64")
AUTOFS = ("autofs", "/System/Volumes/Data/home", "map auto_home", 72351744)


@pytest.fixture(autouse=True)
def no_real_executable_or_network(monkeypatch):
    def denied(*_args, **_kwargs):
        raise AssertionError("R010 host SAFE T0 MUST NOT use native resources")
    monkeypatch.setattr(subprocess, "Popen", denied)
    monkeypatch.setattr(os, "kill", denied)
    monkeypatch.setattr(os, "killpg", denied, raising=False)
    monkeypatch.setattr(socket.socket, "connect", denied)


def mounts():
    return tuple(sorted(
        [("apfs", "/", "/dev/disk0", 0x1000)] +
        [("apfs", f"/private/safe{i}", f"/dev/disk{i}", 0x1000)
         for i in range(1, 10)] + [AUTOFS]))


def runner_env():
    return {
        "GITHUB_ACTIONS": "true",
        "GITHUB_EVENT_NAME": "pull_request",
        "GITHUB_REPOSITORY": "chinanjjohn2012/mac-file-gateway",
        "GITHUB_RUN_ID": "42778400689",
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_JOB": "observe-macos-15-arm64-t0",
        "G05_EXPECTED_HEAD": SHA,
        "RUNNER_ENVIRONMENT": "github-hosted",
        "RUNNER_OS": "macOS", "RUNNER_ARCH": "ARM64",
        "ImageOS": "macos15", "ImageVersion": "20261104.0514.1",
        "SSH_AUTH_SOCK": SSH,
    }


@pytest.fixture
def host_readers(monkeypatch):
    def selected(*, source_root, expected):
        assert source_root in ("/System", "/usr")
        assert 1 <= len(expected) <= 2
        return D4HostedSelectedSourceObservation(
            root_identity=(1, 2, 3), selected=(),
            root_ancestor_identities=((1, 2, 3),))
    monkeypatch.setattr(a1, "_actual_system_version",
                        lambda _: ("15.8.2", "24H232"))
    monkeypatch.setattr(a1, "inspect_d4_hosted_selected_source_files", selected)


def observed(env=None, rows=None):
    return a1.inspect_r010_a1_host_source_t0(
        environ=runner_env() if env is None else env, uname=KERNEL,
        macos_release="15.8.2", mount_rows_t0=mounts() if rows is None else rows,
        system_version_t0=("15.8.2", "24H232"))


def preexec_expected():
    return R010ExpectedRunnerEnv(
        run_id="42778400689", run_attempt="1", head_sha=SHA,
        job_name="observe-macos-15-arm64-t0",
        image_version="20261104.0514.1",
        private_home="/private/tmp/r010-reviewed-home",
        private_tmp="/private/tmp/r010-reviewed-tmp")


def bootstrap():
    ex = preexec_expected()
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
        "SSH_AUTH_SOCK": SSH,
        "ACTIONS_ID_TOKEN_REQUEST_URL": URL,
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN": BEARER,
    }


def test_a1_approves_metadata_only_host_source_but_never_native(host_readers):
    item = observed()
    assert item.status == "R010_A1_HOST_SOURCE_ONLY_NO_PRODUCT_T1"
    assert item.ssh_selector_observed is True
    assert item.host_snapshot_from_original_os is False
    assert item.no_ambient_ssh_agent_proven is False
    assert item.no_shared_writable_mounts_proven is False
    assert item.native_launch_allowed is False
    assert len(item.mount_table_sha256) == 64
    assert SSH not in repr(item)
    assert BEARER not in repr(item)


def test_r006_a0_still_denies_same_host_while_r010_a1_is_source_only(
        host_readers):
    source = observed()
    with pytest.raises(D4R006HostAllowlistDenied,
                       match="ambient credential-bearing"):
        verify_r006_fixed_host_allowlist_t0(
            environ=runner_env(), uname=KERNEL,
            macos_release="15.8.2", mount_rows=mounts(),
            system_version=("15.8.2", "24H232"))
    assert source.native_launch_allowed is False


def test_a1_mount_or_selected_host_mutation_rejected(host_readers, monkeypatch):
    for rows in (
        mounts()[:-1],
        mounts() + (("nfs", "/shared", "remote:/data", 0),),
        tuple(row if row[1] != AUTOFS[1]
              else ("autofs", AUTOFS[1], "foreign", AUTOFS[3])
              for row in mounts()),
    ):
        with pytest.raises(a1.R010A1HostDenied):
            observed(rows=rows)
    def corrupt(*_a, **_kw):
        raise ValueError("selected host source drift")
    monkeypatch.setattr(a1, "inspect_d4_hosted_selected_source_files",
                        corrupt)
    with pytest.raises(a1.R010A1HostDenied):
        observed()


@pytest.mark.parametrize("key,value", [
    ("SSH_AUTH_SOCK", ""),
    ("SSH_AUTH_SOCK", "relative/agent.sock"),
    ("SSH_AUTH_SOCK", "/private/../tmp/agent"),
    ("SSH_AUTH_SOCK", "/private/tmp/agent\n"),
    ("GITHUB_REPOSITORY", "other/repo"),
    ("RUNNER_ENVIRONMENT", "self-hosted"),
    ("ImageVersion", "unknown"),
    ("G05_EXPECTED_HEAD", "f" * 40 + "x"),
    ("GITHUB_RUN_ATTEMPT", "0"),
    ("HTTPS_PROXY", "http://untrusted.invalid/"),
])
def test_a1_rejects_unreviewed_host_tuple(host_readers, key, value):
    env = runner_env()
    env[key] = value
    with pytest.raises(a1.R010A1HostDenied):
        observed(env=env)


def test_a1_exact_18_plus_2_preexec_scrubs_into_closed_five_keys(host_readers):
    source = observed()
    original = bootstrap()
    result = a1.close_r010_a1_preexec_source_t0(
        host=source, expected=preexec_expected(), bootstrap=original)
    assert result.status == "R010_A1_SOURCE_ONLY_SCRUBBED_NOT_LIVE_PREEXEC"
    assert result.native_launch_allowed is False
    assert result.live_oidc_token_requested is False
    assert result.verified_current_provider_job is False
    assert result.ssh_agent_protocol_called is False
    assert set(result.helper_keys) == {
        "PATH", "HOME", "TMPDIR", "LANG", "LC_ALL"}
    assert original == {
        "PATH": "/usr/bin:/bin",
        "HOME": "/private/tmp/r010-reviewed-home",
        "TMPDIR": "/private/tmp/r010-reviewed-tmp",
        "LANG": "C", "LC_ALL": "C",
    }
    assert result.helper_env_sha256 == hashlib.sha256(
        json.dumps(original, sort_keys=True, separators=(",", ":"),
                   ensure_ascii=True).encode("ascii")).hexdigest()
    for bad in ("SSH_AUTH_SOCK", "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
                "ACTIONS_ID_TOKEN_REQUEST_URL"):
        assert bad not in original


@pytest.mark.parametrize("mutate", ["forged_host", "wrong_head", "extra_key",
                                     "proxy", "missing_ssh", "renamed_bearer"])
def test_a1_preexec_host_binding_or_scrub_failure_destroys_selectors(
        host_readers, mutate):
    host = observed()
    env = bootstrap()
    ex = preexec_expected()
    if mutate == "forged_host":
        host = replace(host, native_launch_allowed=True)
    elif mutate == "wrong_head":
        ex = replace(ex, head_sha="f" * 40)
    elif mutate == "extra_key":
        env["GIT_ASKPASS"] = "/private/tmp/agent"
    elif mutate == "proxy":
        env["HTTPS_PROXY"] = "http://untrusted.invalid/"
    elif mutate == "missing_ssh":
        del env["SSH_AUTH_SOCK"]
    else:
        env["HOME"] = "/private/tmp/" + BEARER
        ex = replace(ex, private_home=env["HOME"])
    with pytest.raises(a1.R010A1HostDenied):
        a1.close_r010_a1_preexec_source_t0(
            host=host, expected=ex, bootstrap=env)
    assert not env


def test_no_a1_source_object_can_claim_launch_or_remote_provenance(host_readers):
    item = observed()
    for name in ("grant_native_launch", "run", "popen", "mint_grant",
                 "request_oidc", "open_ssh_agent"):
        assert not hasattr(item, name)
    assert not hasattr(
        a1.close_r010_a1_preexec_source_t0(
            host=item, expected=preexec_expected(), bootstrap=bootstrap()),
        "launch")


def test_actual_host_probe_marks_a0_expected_deny_without_executable_pass(
        host_readers, monkeypatch, capsys):
    from tools import r010_a1_host_observation_t0 as probe

    # The probe requires evidence specifically marked as original OS
    # observation; ordinary synthetic host rows must remain denied.
    monkeypatch.setattr(
        probe, "inspect_r010_a1_host_source_t0",
        lambda: replace(observed(), host_snapshot_from_original_os=True))
    def expected_a0_deny():
        raise D4R006HostAllowlistDenied(
            "ambient credential-bearing environment is present")
    monkeypatch.setattr(probe, "verify_r006_fixed_host_allowlist_t0",
                        expected_a0_deny)
    assert probe.main() == 0
    message = capsys.readouterr().out
    assert "A0_EXPECTED_CREDENTIAL_DENY_UNCHANGED" in message
    assert "R010_A1_HOST_SOURCE_ONLY_NO_PRODUCT_T1" in message
    assert '"native_launch_allowed":false' in message
    assert '"native_product_t1":"NOT_RUN"' in message
    assert SSH not in message
    assert BEARER not in message


def test_actual_host_probe_rejects_unexpected_a0_or_a1_error(
        host_readers, monkeypatch, capsys):
    from tools import r010_a1_host_observation_t0 as probe

    # The probe requires evidence specifically marked as original OS
    # observation; ordinary synthetic host rows must remain denied.
    monkeypatch.setattr(
        probe, "inspect_r010_a1_host_source_t0",
        lambda: replace(observed(), host_snapshot_from_original_os=True))
    for reason in (
        None, "current GitHub/macOS image claim mismatch",
        "writable non-local/shared mount is present",
    ):
        if reason is None:
            monkeypatch.setattr(probe, "verify_r006_fixed_host_allowlist_t0",
                                lambda: None)
        else:
            def reject(msg=reason):
                raise D4R006HostAllowlistDenied(msg)
            monkeypatch.setattr(probe, "verify_r006_fixed_host_allowlist_t0",
                                reject)
        assert probe.main() == 1
        message = capsys.readouterr().out
        assert "R010_A1_HOST_SOURCE_T0_DENY" in message
        assert SSH not in message
        assert BEARER not in message


def test_actual_probe_rejects_synthetic_host_snapshot_even_if_a0_denies(
        host_readers, monkeypatch, capsys):
    from tools import r010_a1_host_observation_t0 as probe
    monkeypatch.setattr(probe, "inspect_r010_a1_host_source_t0", observed)
    def expected_denied():
        raise D4R006HostAllowlistDenied(
            "ambient credential-bearing environment is present")
    monkeypatch.setattr(probe, "verify_r006_fixed_host_allowlist_t0",
                        expected_denied)
    assert probe.main() == 1
    output = capsys.readouterr().out
    assert "R010_A1_HOST_SOURCE_T0_DENY" in output
    assert SSH not in output
