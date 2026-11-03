"""Native macOS Seatbelt canary PREPARATION: real T0 source bytes, no native run.

Checks strict identity, immutable proposal, fake OS approvals and hard stop.
No C helper compilation, kernel isolation, network canary, Go/Pipenv or
physical child. Prior exact first-party source validator stays exercised.
"""
from dataclasses import replace
from pathlib import Path
import socket
import subprocess

import pytest

from gateway.lbe_m2_macos_canary_validation_t0 import (
    LbeM2NativeCanaryPreparationDenied,
    MacOSCanaryValidationPlanT0,
    execute_macos_seatbelt_native_canary,
    prepare_macos_canary_validation_t0,
)

_ROOT = Path(__file__).resolve().parents[1]
_GOOD_HEAD = "a" * 40
_GOOD_TREE = "b" * 40


def _inputs():
    return {
        "proposed_head_sha": _GOOD_HEAD,
        "proposed_tree_sha": _GOOD_TREE,
        "native_helper_bytes": (
            _ROOT / "tools/lbe_m2_seatbelt_canary_only.c").read_bytes(),
        "fd_scrub_header_bytes": (
            _ROOT / "tools/lbe_m2_fd_scrub_t0.h").read_bytes(),
        "bounded_wait_header_bytes": (
            _ROOT / "tools/lbe_m2_canary_bounded_wait_t0.h").read_bytes(),
    }


def _make(**kw):
    inputs = _inputs()
    inputs.update(kw)
    return prepare_macos_canary_validation_t0(**inputs)


def test_valid_current_three_sources_produce_only_blocked_t0(monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("T0 must never start a child or open a socket")
    with monkeypatch.context() as m:
        m.setattr(subprocess, "Popen", forbidden)
        m.setattr(socket, "socket", forbidden)
        p = _make()
    assert type(p) is MacOSCanaryValidationPlanT0
    assert p.proposed_head_sha == _GOOD_HEAD
    assert p.proposed_tree_sha == _GOOD_TREE
    assert p.status == "NONOPERATIVE_MACOS_CANARY_VALIDATION_PREP_T0"
    assert p.source_bytes_status == "MATCHED_C_AND_TWO_HEADERS_T0"
    assert len(p.seatbelt_c_sha256) == 64
    assert len(p.fd_scrub_header_sha256) == 64
    assert len(p.bounded_wait_header_sha256) == 64
    assert p.candidate_runner_label == "macos-15"
    assert p.candidate_arch == "arm64"
    assert p.canary_bounded_wait_ms == 2000
    assert p.candidate_native_canary_wall_seconds == 10
    assert p.candidate_job_wall_seconds == 1200
    assert p.candidate_native_canary_cpu_seconds == 10
    assert p.candidate_native_canary_memory_mib == 128
    assert p.candidate_stdout_raw_bytes == 4096
    assert p.candidate_stderr_raw_bytes == 4096
    for name in (
        "github_head_tree_independently_attested", "runner_image_attested",
        "compiler_and_sdk_attested", "native_canary_compiled",
        "native_canary_executed", "macos_kernel_isolation_attested",
        "network_canary_executed", "descendant_retired_proven",
        "native_go_pipenv_t1_executed", "source_t1_launch_allowed",
        "product_t1_launch_allowed",
    ):
        assert getattr(p, name) is False, name
    assert "CANARY_UNKNOWN_CHILD_CANNOT_BE_RETIRED_OR_RETRIED" in p.blockers


@pytest.mark.parametrize("bad_head,bad_tree", [
    ("", _GOOD_TREE), ("A"*40, _GOOD_TREE),
    ("0"*39, _GOOD_TREE), ("g"*40, _GOOD_TREE),
    (_GOOD_HEAD, _GOOD_HEAD), (_GOOD_HEAD, ""),
    (_GOOD_HEAD, "B"*40), (_GOOD_HEAD, "f"*39),
    (None, _GOOD_TREE), (True, _GOOD_TREE), (7, _GOOD_TREE),
    ({}, _GOOD_TREE), (_GOOD_HEAD, []),
])
def test_invalid_or_forged_git_identity_cannot_prepare(bad_head,bad_tree):
    with pytest.raises(LbeM2NativeCanaryPreparationDenied):
        _make(proposed_head_sha=bad_head, proposed_tree_sha=bad_tree)


@pytest.mark.parametrize("which", (
    "native_helper_bytes", "fd_scrub_header_bytes",
    "bounded_wait_header_bytes",
))
def test_any_source_or_header_mutation_refused(which):
    orig = _inputs()[which]
    with pytest.raises(LbeM2NativeCanaryPreparationDenied):
        _make(**{which: orig + b"\n"})
    with pytest.raises(LbeM2NativeCanaryPreparationDenied):
        _make(**{which: "not immutable binary source"})


@pytest.mark.parametrize("claim", [
    None, True, False, "PASS", "OS_ATTACHED", 1, {}, [],
    {"confirmed":"ATTACHED","canary":"PASS","runner":"macos-15"},
    b"SEATBELT_CANARY_ONLY_NATIVE_GO_PIPENV_NOT_RUN\n",
])
def test_any_user_claim_or_plan_cannot_unlock_native_canary(claim):
    p = _make()
    with pytest.raises(LbeM2NativeCanaryPreparationDenied,
                       match="NATIVE_MACOS_CANARY=NOT_RUN"):
        execute_macos_seatbelt_native_canary(
            p, claim, claim, claim, claim, claim)


def test_even_forged_mutable_dataclass_values_cannot_promote():
    forged = replace(
        _make(), native_canary_executed=True, runner_image_attested=True,
        compiler_and_sdk_attested=True, source_t1_launch_allowed=True,
        macos_kernel_isolation_attested=True, network_canary_executed=True,
        descendant_retired_proven=True, product_t1_launch_allowed=True,
        blockers=(),
    )
    assert forged.source_t1_launch_allowed
    with pytest.raises(LbeM2NativeCanaryPreparationDenied):
        execute_macos_seatbelt_native_canary(
            forged, True, True, True, True, True)


def test_os_environment_and_fake_runner_labels_do_not_grant(monkeypatch):
    monkeypatch.setenv("RUNNER_OS", "macOS")
    monkeypatch.setenv("RUNNER_ARCH", "ARM64")
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GOPROXY", "off")
    monkeypatch.setenv("PIP_NO_INDEX", "1")
    monkeypatch.setenv("M2_CANARY_ALLOW", "true")
    plan = _make()
    assert not plan.native_canary_executed
    assert not plan.source_t1_launch_allowed
    with pytest.raises(LbeM2NativeCanaryPreparationDenied):
        execute_macos_seatbelt_native_canary(plan, True, True, True, True, True)


def test_validation_module_does_not_import_runtime_or_network_executors():
    s = (_ROOT / "gateway/lbe_m2_macos_canary_validation_t0.py").read_text(
        encoding="ascii")
    assert "import subprocess" not in s
    assert "import socket" not in s
    assert "import ctypes" not in s
    assert "import os" not in s
    assert "sandbox_init(" not in s
    assert "execute_macos_seatbelt_native_canary(" in s
