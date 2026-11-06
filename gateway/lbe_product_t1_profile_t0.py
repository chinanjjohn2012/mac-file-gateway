"""D4 R003 PRODUCT_T1 nonoperative qualification *declaration* for review.

This T0 checker inspects plain proposed input shapes only. It performs no
filesystem reads, network contact, subprocess, runner discovery or credential
inspection. A valid declaration is NOT an observed runner, a source/loader
attestation, an owner approval, an executable Gate B exception, or permission
to turn off the public F1/native Go/Pipenv refusal.
"""
from __future__ import annotations

from dataclasses import dataclass
import re


class D4ProductT1T0Denied(ValueError):
    """The proposed, untrusted D4 qualification packet is malformed."""


PROFILE_ID = "MWE-LBE-TRUSTED-PRODUCT-T1-PROFILE-R003"
PROFILE_GIT_BLOB = "f8556b48ab5f4af7390fb015092862a8a87768fb"
NETWORK_PROFILE = "TRUSTED_HOST_EGRESS_POSSIBLE_NOT_OFFLINE_ONLY"

# These are proposed first-party TEST vectors, not executable grants.
_COMMANDS = (
    ("python", "-m", "pytest", "-q"),
    ("python", "-m", "compileall", "-q", "./src"),
    ("pipenv", "run", "python", "-m", "pytest", "-q"),
    ("go", "test", "./..."),
    ("go", "vet", "./..."),
    ("go", "build", "-o", "bin/app", "./cmd/app"),
)

# A declaration of a SHA is not a measurement of the loaded source.
_SOURCE_KEYS = (
    "go_archive", "go_compiler", "go_linker", "go_stdlib",
    "go_module_graph", "pipenv_cli", "python_interpreter",
    "python_venv_site", "python_seed", "pipfile_lock",
    "python_import_closure",
)
_RUNNER_KEYS = (
    "provider", "os_version", "arch", "image_id", "image_sha256",
    "disposable", "checkout_persist_credentials", "secrets_present",
    "user_mac", "tunnel", "shared_mounts", "production_access",
)
_LIMIT_CEILINGS = {
    "job_seconds": 1200,
    "child_seconds": 120,
    "worker_timeout_seconds": 300,
    "cpu_millicores": 8000,
    "memory_mib": 16384,
    "raw_output_bytes_per_stream": 48000,
    "returned_chars_per_stream": 48000,
    "concurrent_jobs": 1,
    "children_per_workspace": 1,
    "children_per_service": 4,
}
# Exact draft tuple for R003; numeric claims alone are never enforcement.
_EXACT_LIMITS = dict(_LIMIT_CEILINGS)
_RISK_DISCLOSURES = (
    "SAME_UID_HOST_ACCESS_POSSIBLE",
    "OUTBOUND_NETWORK_ACCESS_POSSIBLE",
    "ORIGINAL_AND_DESCENDANTS_MAY_SURVIVE_CRASH",
    "LOST_ACK_OR_MANUAL_RETRY_MAY_DUPLICATE_EFFECTS",
    "NO_FULL_DESCENDANT_CLEANUP_OR_ROLLBACK",
    "NO_OS_SANDBOX_OR_F3_GUARANTEE",
)
_BLOCKERS = (
    "D4_PROFILE_R003_PROPOSED_NOT_EFFECTIVE",
    "NEW_D4_PRODUCT_T1_OWNER_NETWORK_AND_HOST_CONSENT_NOT_GRANTED",
    "NEW_D4_R003_B_C_EXECUTABLE_REVIEW_NOT_ISSUED",
    "RUNNER_IMAGE_AND_CREDENTIAL_ISOLATION_NOT_OBSERVED",
    "CPU_RAM_PROCESS_TREE_ENFORCEMENT_NOT_OBSERVED",
    "REAL_GO_PIPENV_PYTHON_LOADED_SOURCE_NOT_OBSERVED",
    "G05_AND_SOURCE_AT_REAL_RUNNER_NOT_REVALIDATED",
    "PR102_OFFLINE_ONLY_SOURCE_GATE_B_NOT_REPLACED",
    "PUBLIC_F1_AND_GO_PIPENV_NATIVE_LAUNCH_DENY_STILL_ACTIVE",
    "NATIVE_PRODUCT_T1_AND_INTEGRATION_NOT_RUN",
)
_SHA40 = re.compile(r"[0-9a-f]{40}\Z")
_SHA64 = re.compile(r"[0-9a-f]{64}\Z")
_IMAGE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{2,119}\Z")


@dataclass(frozen=True, slots=True)
class D4ProductT1PacketT0:
    """Immutable *declared* candidate fields, not a security capability."""

    head: str
    tree: str
    manifest_sha256: str
    runner_declarations: tuple[tuple[str, str | bool], ...]
    source_hash_declarations: tuple[tuple[str, str], ...]
    proposed_resource_limits: tuple[tuple[str, int], ...]
    proposed_commands: tuple[tuple[str, ...], ...]
    risk_wording_only: tuple[str, ...]
    status: str = "NONOPERATIVE_D4_PRODUCT_T1_DECLARATION_T0"
    runner_identity_observed: bool = False
    loaded_source_observed: bool = False
    os_resource_enforcement_proven: bool = False
    credential_isolation_proven: bool = False
    risk_acceptance_by_owner_observed: bool = False
    native_launch_allowed: bool = False
    product_apply_allowed: bool = False
    blockers: tuple[str, ...] = _BLOCKERS


def _plain_fields(value: object, keys: tuple[str, ...], label: str) -> dict:
    # Reject custom mapping, key subclasses and hash/equality hooks BEFORE
    # any equality or sorting of attacker-supplied keys/values.
    if type(value) is not dict or any(type(key) is not str for key in value):
        raise D4ProductT1T0Denied("untrusted " + label + " shape")
    if tuple(sorted(value)) != tuple(sorted(keys)):
        raise D4ProductT1T0Denied("missing or unexpected " + label + " field")
    return value


def _digest(value: object, length: int, label: str) -> str:
    if (type(value) is not str
            or (length == 40 and _SHA40.fullmatch(value) is None)
            or (length == 64 and _SHA64.fullmatch(value) is None)
            or value == "0" * length):
        raise D4ProductT1T0Denied("invalid declared " + label + " digest")
    return value


def prepare_d4_product_t1_packet_t0(
    *, profile_id: object, profile_git_blob: object,
    head: object, tree: object, manifest_sha256: object,
    runner: object, source_hashes: object, limits: object,
    commands: object, risk_disclosures: object,
    network_profile: object,
) -> D4ProductT1PacketT0:
    """Prepare a safe, strict review packet; return BLOCKED even on success."""

    if type(profile_id) is not str or profile_id != PROFILE_ID:
        raise D4ProductT1T0Denied("unknown D4 contract version")
    if type(profile_git_blob) is not str or profile_git_blob != PROFILE_GIT_BLOB:
        raise D4ProductT1T0Denied("D4 proposal Git Blob mismatch")
    if type(network_profile) is not str or network_profile != NETWORK_PROFILE:
        raise D4ProductT1T0Denied(
            "this proposed product test is NOT PR102 OFFLINE_ONLY")
    checked_head = _digest(head, 40, "Head")
    checked_tree = _digest(tree, 40, "Tree")
    checked_manifest = _digest(manifest_sha256, 64, "Manifest")

    source = _plain_fields(source_hashes, _SOURCE_KEYS, "source")
    for key in _SOURCE_KEYS:
        _digest(source[key], 64, key)

    actual_runner = _plain_fields(runner, _RUNNER_KEYS, "runner")
    if (type(actual_runner["provider"]) is not str
            or actual_runner["provider"] != "github-hosted"
            or type(actual_runner["os_version"]) is not str
            or actual_runner["os_version"] != "macos-15"
            or type(actual_runner["arch"]) is not str
            or actual_runner["arch"] != "arm64"
            or type(actual_runner["image_id"]) is not str
            or _IMAGE_ID.fullmatch(actual_runner["image_id"]) is None):
        raise D4ProductT1T0Denied("wrong proposed disposable runner")
    _digest(actual_runner["image_sha256"], 64, "runner image")
    for name, expected in {
        "disposable": True,
        "checkout_persist_credentials": False,
        "secrets_present": False,
        "user_mac": False,
        "tunnel": False,
        "shared_mounts": False,
        "production_access": False,
    }.items():
        if type(actual_runner[name]) is not bool or actual_runner[name] is not expected:
            raise D4ProductT1T0Denied("unsafe proposed runner flag: " + name)

    budget = _plain_fields(limits, tuple(_LIMIT_CEILINGS), "limits")
    for name, ceiling in _LIMIT_CEILINGS.items():
        number = budget[name]
        if type(number) is not int or not 1 <= number <= ceiling:
            raise D4ProductT1T0Denied("invalid proposed budget: " + name)
    for name, expected in _EXACT_LIMITS.items():
        if budget[name] != expected:
            raise D4ProductT1T0Denied("invalid proposed exact budget: " + name)
    if (budget["child_seconds"] > budget["worker_timeout_seconds"]
            or budget["child_seconds"] > budget["job_seconds"]):
        raise D4ProductT1T0Denied("inconsistent proposed time ceilings")
    if budget["cpu_millicores"] < 1000 or budget["memory_mib"] < 512:
        raise D4ProductT1T0Denied("unrealistically underspecified budget")

    if type(commands) is not list or len(commands) != len(_COMMANDS):
        raise D4ProductT1T0Denied("wrong D4 command matrix")
    if any(type(vector) is not list
           or any(type(arg) is not str for arg in vector)
           for vector in commands):
        raise D4ProductT1T0Denied("untrusted command vector")
    selected = tuple(tuple(vector) for vector in commands)
    if selected != _COMMANDS:
        raise D4ProductT1T0Denied("unapproved D4 fixture command")

    if (type(risk_disclosures) is not list
            or any(type(risk) is not str for risk in risk_disclosures)
            or tuple(risk_disclosures) != _RISK_DISCLOSURES):
        raise D4ProductT1T0Denied("missing or altered risk disclosures")

    return D4ProductT1PacketT0(
        head=checked_head, tree=checked_tree,
        manifest_sha256=checked_manifest,
        runner_declarations=tuple(sorted(actual_runner.items())),
        source_hash_declarations=tuple(sorted(source.items())),
        proposed_resource_limits=tuple(sorted(budget.items())),
        proposed_commands=selected,
        risk_wording_only=tuple(risk_disclosures),
    )


def authorize_native_product_t1_from_t0(*_args: object, **_kwargs: object) -> None:
    """Unconditionally fail: no T0 packet or forged receipt grants a T1 child."""
    raise D4ProductT1T0Denied(
        "PRODUCT_T1=NOT_AUTHORIZED; native execution requires separate "
        "B/C, owner consent and actual observed runner/source evidence")
