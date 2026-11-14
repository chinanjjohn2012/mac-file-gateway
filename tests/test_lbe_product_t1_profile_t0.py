"""D4 R003 declaration-only PRODUCT_T1 tests. Never run native children."""
from dataclasses import replace
import os
import socket
import subprocess

import pytest

from gateway.lbe_product_t1_profile_t0 import (
    D4ProductT1T0Denied,
    NETWORK_PROFILE,
    PROFILE_GIT_BLOB,
    PROFILE_ID,
    _COMMANDS,
    _RISK_DISCLOSURES,
    _SOURCE_KEYS,
    authorize_native_product_t1_from_t0,
    prepare_d4_product_t1_packet_t0,
)


def candidate(**updates):
    data = {
        "profile_id": PROFILE_ID,
        "profile_git_blob": PROFILE_GIT_BLOB,
        "head": "a" * 40,
        "tree": "b" * 40,
        "manifest_sha256": "c" * 64,
        "runner": {
            "provider": "github-hosted", "os_version": "macos-15",
            "arch": "arm64", "image_id": "macos-15-arm64-candidate",
            "image_sha256": "d" * 64, "disposable": True,
            "checkout_persist_credentials": False,
            "secrets_present": False, "user_mac": False,
            "tunnel": False, "shared_mounts": False,
            "production_access": False,
        },
        "source_hashes": {
            name: f"{i:064x}" for i, name in enumerate(_SOURCE_KEYS, 1)
        },
        "limits": {
            "job_seconds": 1200, "child_seconds": 120,
            "worker_timeout_seconds": 300,
            "cpu_millicores": 2000, "memory_mib": 4096,
            "raw_output_bytes_per_stream": 48000,
            "returned_chars_per_stream": 48000,
            "concurrent_jobs": 1, "children_per_workspace": 1,
            "children_per_service": 4,
        },
        "commands": [list(vec) for vec in _COMMANDS],
        "risk_disclosures": list(_RISK_DISCLOSURES),
        "network_profile": NETWORK_PROFILE,
    }
    data.update(updates)
    return data


def prepare(**updates):
    return prepare_d4_product_t1_packet_t0(**candidate(**updates))


def test_d4_complete_structural_candidate_is_never_exec_authority(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("D4 T0 must never create a process, signal or socket")

    with monkeypatch.context() as m:
        m.setattr(subprocess, "Popen", forbidden)
        m.setattr(subprocess, "run", forbidden)
        m.setattr(socket, "socket", forbidden)
        m.setattr(os, "system", forbidden)
        m.setattr(os, "kill", forbidden)
        m.setattr(os, "killpg", forbidden, raising=False)
        packet = prepare()
        assert packet.status == "NONOPERATIVE_D4_PRODUCT_T1_DECLARATION_T0"
        assert packet.native_launch_allowed is False
        assert packet.product_apply_allowed is False
        assert packet.runner_identity_observed is False
        assert packet.loaded_source_observed is False
        assert packet.os_resource_enforcement_proven is False
        assert packet.credential_isolation_proven is False
        assert packet.risk_acceptance_by_owner_observed is False
        assert packet.proposed_commands == _COMMANDS
        assert len(packet.blockers) >= 8
        with pytest.raises(D4ProductT1T0Denied, match="NOT_AUTHORIZED"):
            authorize_native_product_t1_from_t0(packet)
        forged = replace(
            packet, native_launch_allowed=True,
            product_apply_allowed=True,
            runner_identity_observed=True,
            risk_acceptance_by_owner_observed=True,
        )
        with pytest.raises(D4ProductT1T0Denied, match="NOT_AUTHORIZED"):
            authorize_native_product_t1_from_t0(
                forged, owner_approval=True, bypass_gate_b=True)
        assert packet.risk_wording_only == _RISK_DISCLOSURES


@pytest.mark.parametrize("key,wrong", [
    ("profile_id", "MWE-LBE-TRUSTED-PRODUCT-T1-PROFILE-R001"),
    ("profile_id", True),
    ("profile_git_blob", "0" * 40),
    ("profile_git_blob", PROFILE_GIT_BLOB.upper()),
    ("head", "a" * 39),
    ("head", "A" * 40),
    ("head", "0" * 40),
    ("tree", "0" * 40),
    ("tree", "b" * 41),
    ("manifest_sha256", "c" * 63),
    ("manifest_sha256", "0" * 64),
    ("network_profile", "OFFLINE_ONLY"),
    ("network_profile", "BOUNDED_EGRESS"),
    ("network_profile", True),
])
def test_d4_wrong_version_identity_or_network_profile_denied(key, wrong):
    with pytest.raises(D4ProductT1T0Denied):
        prepare(**{key: wrong})


@pytest.mark.parametrize("name,value", [
    ("provider", "self-hosted"),
    ("os_version", "macos-14"),
    ("arch", "amd64"),
    ("image_id", "../other"),
    ("image_id", "x"),
    ("image_sha256", "f" * 63),
    ("disposable", False),
    ("checkout_persist_credentials", True),
    ("secrets_present", True),
    ("user_mac", True),
    ("tunnel", True),
    ("shared_mounts", True),
    ("production_access", True),
    ("disposable", 1),
    ("secrets_present", 0),
])
def test_d4_unsafe_or_malformed_declared_runner_denied(name, value):
    runner = candidate()["runner"]
    runner[name] = value
    with pytest.raises(D4ProductT1T0Denied):
        prepare(runner=runner)


def test_d4_runner_missing_extra_and_mapping_subclass_denied():
    runner = candidate()["runner"]
    runner.pop("arch")
    with pytest.raises(D4ProductT1T0Denied):
        prepare(runner=runner)
    runner = candidate()["runner"]
    runner["token"] = "not permitted"
    with pytest.raises(D4ProductT1T0Denied):
        prepare(runner=runner)

    class DictSubclass(dict):
        def __eq__(self, other):
            raise AssertionError("hostile mapping comparison reached")

    with pytest.raises(D4ProductT1T0Denied):
        prepare(runner=DictSubclass(candidate()["runner"]))


@pytest.mark.parametrize("name,wrong", [
    ("job_seconds", 1201),
    ("job_seconds", 0),
    ("job_seconds", True),
    ("child_seconds", 121),
    ("child_seconds", 0),
    ("worker_timeout_seconds", 301),
    ("cpu_millicores", 999),
    ("cpu_millicores", 8001),
    ("memory_mib", 511),
    ("memory_mib", 16385),
    ("raw_output_bytes_per_stream", 48001),
    ("returned_chars_per_stream", 48001),
    ("concurrent_jobs", 2),
    ("children_per_workspace", 2),
    ("children_per_service", 3),
    ("memory_mib", 4096.0),
])
def test_d4_proposed_resource_limits_invalid(name, wrong):
    limits = candidate()["limits"]
    limits[name] = wrong
    with pytest.raises(D4ProductT1T0Denied):
        prepare(limits=limits)


def test_d4_missing_resource_or_child_longer_than_job_denied():
    limits = candidate()["limits"]
    del limits["cpu_millicores"]
    with pytest.raises(D4ProductT1T0Denied):
        prepare(limits=limits)
    limits = candidate()["limits"]
    limits["job_seconds"] = 90
    with pytest.raises(D4ProductT1T0Denied):
        prepare(limits=limits)
    limits = candidate()["limits"]
    limits["extra_timeout_signal"] = 1
    with pytest.raises(D4ProductT1T0Denied):
        prepare(limits=limits)


@pytest.mark.parametrize("wrong", ["f" * 63, "F" * 64, "0" * 64, True, 11])
def test_d4_source_declaration_hash_invalid(wrong):
    source = candidate()["source_hashes"]
    source["go_compiler"] = wrong
    with pytest.raises(D4ProductT1T0Denied):
        prepare(source_hashes=source)


def test_d4_source_closure_missing_unexpected_and_untrusted_values():
    source = candidate()["source_hashes"]
    del source["python_import_closure"]
    with pytest.raises(D4ProductT1T0Denied):
        prepare(source_hashes=source)
    source = candidate()["source_hashes"]
    source["unknown_dynamic_module"] = "e" * 64
    with pytest.raises(D4ProductT1T0Denied):
        prepare(source_hashes=source)

    hooks = []

    class HostileHash:
        def __eq__(self, other):
            hooks.append("eq")
            return True
        def __hash__(self):
            hooks.append("hash")
            return 1

    source = candidate()["source_hashes"]
    source["python_seed"] = HostileHash()
    with pytest.raises(D4ProductT1T0Denied):
        prepare(source_hashes=source)
    assert hooks == []


@pytest.mark.parametrize("vector", [
    ["go", "run", "./cmd/app"],
    ["go", "test", "-exec=/bin/sh", "./..."],
    ["go", "build", "-o", "../outside", "./cmd/app"],
    ["python", "-c", "print(1)"],
    ["pipenv", "install"],
    ["sh", "-c", "echo test"],
])
def test_d4_unapproved_candidate_command_denied(vector):
    commands = candidate()["commands"]
    commands[0] = vector
    with pytest.raises(D4ProductT1T0Denied):
        prepare(commands=commands)


def test_d4_partial_duplicate_and_custom_command_vectors_denied():
    commands = candidate()["commands"]
    with pytest.raises(D4ProductT1T0Denied):
        prepare(commands=commands[:-1])
    commands[-1] = commands[0]
    with pytest.raises(D4ProductT1T0Denied):
        prepare(commands=commands)

    class EvilStr(str):
        def __eq__(self, other):
            raise AssertionError("malicious eq on command")
    commands = candidate()["commands"]
    commands[0][0] = EvilStr("python")
    with pytest.raises(D4ProductT1T0Denied):
        prepare(commands=commands)


def test_d4_risk_wording_not_user_permission_and_must_be_complete():
    risks = candidate()["risk_disclosures"]
    for invalid in (risks[:-1], risks + ["OWNER_APPROVED"], list(reversed(risks))):
        with pytest.raises(D4ProductT1T0Denied):
            prepare(risk_disclosures=invalid)
    assert prepare().risk_acceptance_by_owner_observed is False


def test_d4_input_mutation_cannot_mutate_returned_declaration():
    raw = candidate()
    result = prepare_d4_product_t1_packet_t0(**raw)
    raw["limits"]["cpu_millicores"] = 8001
    raw["runner"]["image_id"] = "another-image"
    raw["source_hashes"]["go_compiler"] = "0" * 64
    raw["commands"][0][0] = "sh"
    raw["risk_disclosures"].clear()
    assert dict(result.proposed_resource_limits)["cpu_millicores"] == 2000
    assert dict(result.runner_declarations)["image_id"] == "macos-15-arm64-candidate"
    assert result.proposed_commands == _COMMANDS
    assert result.native_launch_allowed is False

@pytest.mark.parametrize("unsafe_compileall", [
    ["python", "-m", "compileall"],
    ["python", "-m", "compileall", "-q"],
    ["python", "-m", "compileall", "-q", "../outside"],
    ["python", "-m", "compileall", "-q", "/tmp/outside"],
    ["python", "-m", "compileall", "-q", "./src", "../outside"],
    ["python", "-m", "compileall", "-b", "-q", "./src"],
    ["python", "-m", "compileall", "-q", "./other"],
])
def test_d4_r003_compileall_must_have_exact_scoped_fixture_operand(unsafe_compileall):
    commands = candidate()["commands"]
    commands[1] = unsafe_compileall
    with pytest.raises(D4ProductT1T0Denied, match="unapproved D4 fixture command"):
        prepare(commands=commands)
    assert _COMMANDS[1] == ("python", "-m", "compileall", "-q", "./src")


@pytest.mark.parametrize("name,wrong", [
    ("cpu_millicores", 2001),
    ("cpu_millicores", 3000),
    ("memory_mib", 4097),
    ("memory_mib", 8192),
    ("job_seconds", 1199),
    ("child_seconds", 119),
    ("worker_timeout_seconds", 299),
    ("raw_output_bytes_per_stream", 47999),
    ("returned_chars_per_stream", 47999),
])
def test_d4_r003_exact_candidate_budget_not_just_large_ceiling(name, wrong):
    limits = candidate()["limits"]
    limits[name] = wrong
    with pytest.raises(D4ProductT1T0Denied, match="invalid proposed exact budget"):
        prepare(limits=limits)


def test_d4_r003_t0_packet_cannot_assert_owner_or_runtime_grants():
    packet = prepare()
    assert dict(packet.proposed_resource_limits)["cpu_millicores"] == 2000
    assert dict(packet.proposed_resource_limits)["memory_mib"] == 4096
    assert packet.proposed_commands[1][-1] == "./src"
    assert packet.runner_identity_observed is False
    assert packet.credential_isolation_proven is False
    assert packet.os_resource_enforcement_proven is False
    assert packet.loaded_source_observed is False
    assert packet.risk_acceptance_by_owner_observed is False
    assert packet.native_launch_allowed is False
    with pytest.raises(D4ProductT1T0Denied, match="NOT_AUTHORIZED"):
        authorize_native_product_t1_from_t0(packet, owner_risk_consent=True)
