"""Seatbelt OFFLINE_ONLY native canary candidate: T0 only, no foreign child.

This suite reads committed C source and executes only ordinary Python checks
on fake claims. It does not compile, load, execute, fork, open sockets or
install a macOS sandbox and cannot establish an OS-denial canary result.
"""
from dataclasses import replace
import os
from pathlib import Path
import re
import socket
import subprocess

import pytest

from gateway.lbe_m2_seatbelt_offline_t0 import (
    LbeM2SeatbeltT0Error, SEATBELT_CANARY_PROFILE,
    prepare_seatbelt_offline_backend_t0,
    require_verified_offline_domain_before_native_t1,
)
from gateway.lbe_m2_t1_source_execution_gate_t0 import (
    LbeT1SourceRunDenied, execute_source_toolchain_t1,
)

_ROOT = Path(__file__).resolve().parents[1]
_HELPER = _ROOT / "tools" / "lbe_m2_seatbelt_canary_only.c"
_FD_SCRUB = _ROOT / "tools" / "lbe_m2_fd_scrub_t0.h"
_WAIT_SOURCE = _ROOT / "tools" / "lbe_m2_canary_bounded_wait_t0.h"


def _candidate(**overrides):
    inputs = {"native_helper_bytes": _HELPER.read_bytes(),
              "fd_scrub_header_bytes": _FD_SCRUB.read_bytes(),
              "bounded_wait_header_bytes": _WAIT_SOURCE.read_bytes()}
    inputs.update(overrides)
    return prepare_seatbelt_offline_backend_t0(**inputs)


@pytest.mark.parametrize("proposed_platform", ("Linux", "Darwin"))
def test_first_party_helper_digest_and_policy_t0_are_still_nonoperative(
        proposed_platform, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("T0 must never start a process or open a socket")
    with monkeypatch.context() as m:
        m.setattr(subprocess, "Popen", forbidden)
        m.setattr(socket, "socket", forbidden)
        m.setattr("gateway.lbe_m2_seatbelt_offline_t0.platform.system",
                  lambda: proposed_platform)
        result = _candidate()

    assert result.backend == "MACOS15_ARM64_SEATBELT_C_CANARY_CANDIDATE"
    assert result.observed_platform == proposed_platform
    assert result.status == "NONOPERATIVE_SEATBELT_CANARY_SOURCE_T0"
    assert result.policy_source == SEATBELT_CANARY_PROFILE
    assert len(result.policy_sha256) == 64
    assert len(result.native_helper_source_sha256) == 64
    assert len(result.bounded_wait_header_sha256) == 64
    assert result.bounded_wait_header_path == "tools/lbe_m2_canary_bounded_wait_t0.h"
    assert result.native_helper_source_path == (
        "tools/lbe_m2_seatbelt_canary_only.c")
    assert result.kernel_attachment == "NOT_ATTESTED"
    assert result.original_context_canary == "NOT_RUN"
    assert result.descendant_context_canary == "NOT_RUN"
    assert result.dns_and_proxy_coverage == "NOT_ATTESTED"
    assert result.native_helper_executed is False
    assert result.native_go_pipenv_executed is False
    assert result.source_t1_authorized is False
    assert result.product_exec_authorized is False


def test_compiled_C_policy_literals_equal_static_python_policy():
    source = _HELPER.read_text(encoding="ascii")
    for line in SEATBELT_CANARY_PROFILE.splitlines():
        assert ('"' + line + r"\n" + '"') in source
    assert "(deny default)" in SEATBELT_CANARY_PROFILE
    assert "(allow process-fork)" in SEATBELT_CANARY_PROFILE
    assert "(allow process-exec)" not in SEATBELT_CANARY_PROFILE
    assert not re.search(
        r"\(\s*allow\s+network", SEATBELT_CANARY_PROFILE)
    assert not re.search(
        r"\(\s*allow\s+mach-lookup", SEATBELT_CANARY_PROFILE)


def test_native_canary_must_sandbox_before_any_socket_and_child_fork():
    source = _HELPER.read_text(encoding="ascii")
    main = source.split("int main(int argc, char **argv) {", 1)[1]
    assert 'if (argc != 1)' in main
    assert "reject_inherited_socket_descriptors()" in main
    assert "sandbox_init(kSeatbeltPolicy, 0, &errorbuf)" in main
    assert "deny_loopback_canaries()" in main
    assert "child = fork()" in main
    assert "lbe_canary_wait_bounded(child)" in main
    assert "waitpid(child, &status, 0)" not in main
    assert "return 69;" in main
    assert main.index("reject_inherited_socket_descriptors()") < (
        main.index("sandbox_init(kSeatbeltPolicy, 0, &errorbuf)"))
    assert main.index("sandbox_init(kSeatbeltPolicy, 0, &errorbuf)") < (
        main.index("deny_loopback_canaries()"))
    assert main.index("deny_loopback_canaries()") < main.index(
        "child = fork()")
    assert "return 0;" in main
    assert "NATIVE_GO_PIPENV_NOT_RUN" in main
    assert "O_NONBLOCK" in source
    assert "INADDR_LOOPBACK" in source
    assert "in6addr_loopback" in source
    # Inspect C executable statements, not comments, without compiling it.
    no_comments = re.sub(r"/\*.*?\*/", "", source, flags=re.S)
    assert not re.search(r"\b(?:execl?|execv?p?|posix_spawn|system|popen)"
                         r"\s*\(", no_comments)
    assert not re.search(r"\b(?:kill|killpg|setpgid|alarm)\s*\(",
                         no_comments)
    assert "#if !defined(__APPLE__)" in source
    assert "#include \"lbe_m2_fd_scrub_t0.h\"" in source
    assert "#include \"lbe_m2_canary_bounded_wait_t0.h\"" in source
    assert "lbe_scrub_inherited_fds()" in source
    assert "getrlimit(RLIMIT_NOFILE" not in source
    fd_scrub = _FD_SCRUB.read_text(encoding="ascii")
    assert "S_ISSOCK" in fd_scrub
    assert "opendir(directory)" in fd_scrub
    assert "lbe_verify_no_remaining_fds" in fd_scrub


@pytest.mark.parametrize("bad", [
    b"", b"fake source", b"\0", "not bytes",
    bytearray(b"fake"), None, True, 42, [], {},
])
def test_incorrect_or_forged_native_helper_source_denied(bad):
    with pytest.raises(LbeM2SeatbeltT0Error):
        _candidate(native_helper_bytes=bad)


def test_modified_native_helper_source_bytes_denied():
    content = _HELPER.read_bytes()
    for altered in (
        content + b"\n",
        content.replace(b"(deny default)", b"(allow default)", 1),
        content.replace(b"INADDR_LOOPBACK", b"INADDR_ANY", 1),
    ):
        assert altered != content
        with pytest.raises(LbeM2SeatbeltT0Error):
            _candidate(native_helper_bytes=altered)


@pytest.mark.parametrize("policy", [
    "", "(version 1)\n(allow default)\n",
    "(version 1)\n(deny default)\n(allow network-outbound)\n",
    "(version 1)\n(deny default)\n(allow network-outbound"
    " (remote ip \"localhost:1234\"))\n",
    SEATBELT_CANARY_PROFILE + "(allow network-outbound)\n",
    SEATBELT_CANARY_PROFILE.replace("(allow process-fork)\n", ""),
    SEATBELT_CANARY_PROFILE.replace("(deny default)\n", ""),
    None, True, 7, [], {},
])
def test_unreviewed_policy_or_type_denied_before_any_os_call(policy):
    with pytest.raises(LbeM2SeatbeltT0Error):
        _candidate(proposed_policy=policy)


def test_policy_comparator_object_cannot_execute_custom_equal():
    class Dangerous:
        def __eq__(self, other):
            raise AssertionError("untrusted compare must not run")
    with pytest.raises(LbeM2SeatbeltT0Error):
        _candidate(proposed_policy=Dangerous())


@pytest.mark.parametrize("claim", [
    None, "PASS", b"SEATBELT_CANARY_ONLY_NATIVE_GO_PIPENV_NOT_RUN\n",
    {"policy": "ATTACHED", "same_domain": True},
    True, 1, object(),
])
def test_no_self_reported_canary_or_runner_can_grant_real_t1(claim):
    receipt = _candidate()
    for args in (
        (receipt, receipt, claim, claim, claim),
        (None, None, claim, claim, claim),
    ):
        with pytest.raises(LbeM2SeatbeltT0Error,
                           match="NATIVE_SOURCE_T1=NOT_RUN"):
            require_verified_offline_domain_before_native_t1(*args)


def test_forged_successful_attestation_receipt_cannot_unlock():
    original = _candidate()
    forged = replace(
        original, status="REAL_OFFLINE_T1_PASS",
        kernel_attachment="VERIFIED", original_context_canary="PASS",
        descendant_context_canary="PASS",
        dns_and_proxy_coverage="VERIFIED",
        native_helper_executed=True, native_go_pipenv_executed=True,
        source_t1_authorized=True, product_exec_authorized=True,
        blockers=(),
    )
    assert forged.source_t1_authorized is True  # Forged dataclass only.
    with pytest.raises(LbeM2SeatbeltT0Error):
        require_verified_offline_domain_before_native_t1(
            forged, forged, forged, forged, forged)
    with pytest.raises(LbeT1SourceRunDenied):
        execute_source_toolchain_t1(forged, True, True, True)


@pytest.mark.parametrize("platform_var", [
    ("RUNNER_OS", "macOS"),
    ("RUNNER_ARCH", "ARM64"),
    ("GOPROXY", "off"),
    ("PIP_NO_INDEX", "1"),
    ("GITHUB_ACTIONS", "true"),
    ("M2_SEATBELT_CANARY", "PASS"),
])
def test_environment_variables_never_create_attestation(
        platform_var, monkeypatch):
    monkeypatch.setenv(*platform_var)
    receipt = _candidate()
    assert receipt.source_t1_authorized is False
    assert receipt.kernel_attachment == "NOT_ATTESTED"
    with pytest.raises(LbeM2SeatbeltT0Error):
        require_verified_offline_domain_before_native_t1(
            receipt, True, "attached", "PASS", "trusted")


def test_no_new_host_firewall_or_native_workflow_is_executed():
    source = _HELPER.read_text(encoding="ascii")
    python_module = (_ROOT / "gateway" / "lbe_m2_seatbelt_offline_t0.py")
    text = python_module.read_text(encoding="ascii")
    # C helper uses only fixed Seatbelt profile, not a host/global rule.
    assert "sandbox_init(kSeatbeltPolicy, 0, &errorbuf)" in source
    assert "pfctl " not in source
    assert "iptables " not in source
    assert "import subprocess" not in text
    assert "import socket" not in text
    assert "import ctypes" not in text



@pytest.mark.parametrize("bad", [
    b"", b"fake header", b"\0", "not bytes", bytearray(b"wrong"),
    None, True, 7, [], {},
])
def test_changed_or_forged_fd_scrub_header_is_rejected(bad):
    with pytest.raises(LbeM2SeatbeltT0Error):
        _candidate(fd_scrub_header_bytes=bad)


def test_unreviewed_close_fd_header_logic_mutation_denied():
    source = _FD_SCRUB.read_bytes()
    alterations = (
        source + b"\n",
        source.replace(b"lbe_verify_no_remaining_fds", b"do_not_verify_fd", 1),
        source.replace(b"opendir(directory)", b"opendir(\"/tmp\")", 1),
        source.replace(b"if (closer(fd) != 0", b"if (0 /* ignore close */", 1),
    )
    for changed in alterations:
        assert changed != source
        with pytest.raises(LbeM2SeatbeltT0Error):
            _candidate(fd_scrub_header_bytes=changed)


@pytest.mark.parametrize("bad", [
    b"", b"unreviewed-wait-header", b"\0", "not bytes",
    bytearray(b"bad"), None, True, 1, {}, [],
])
def test_bad_or_missing_bounded_wait_source_is_denied(bad):
    with pytest.raises(LbeM2SeatbeltT0Error):
        _candidate(bounded_wait_header_bytes=bad)


def test_mutated_bounded_wait_header_and_unbounded_wait_risk_rejected():
    original = _WAIT_SOURCE.read_bytes()
    for changed in (
        original + b"\n",
        original.replace(b"WNOHANG", b"0", 1),
        original.replace(b"CLOCK_MONOTONIC", b"CLOCK_REALTIME", 1),
        original.replace(b"LBE_CANARY_MAX_POLLS 256U",
                         b"LBE_CANARY_MAX_POLLS 999999U", 1),
    ):
        assert changed != original
        with pytest.raises(LbeM2SeatbeltT0Error):
            _candidate(bounded_wait_header_bytes=changed)
    header = original.decode("ascii")
    assert "WNOHANG" in header
    assert "CLOCK_MONOTONIC" in header
    assert "LBE_CANARY_CHILD_UNVERIFIED_TIMEOUT" in header
    assert "LBE_CANARY_MAX_POLLS" in header
    assert "kill(" not in header
    assert "killpg(" not in header
    assert "posix_spawn(" not in header
