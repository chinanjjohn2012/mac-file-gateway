"""PR113 six-command T1 qualification oracle, OFFLINE T0 ONLY.

This never launches an original child, installs a package, makes network calls,
authenticates GitHub Owner approval or confers T1 execution permission.
It separately classifies observed product-child behavior and the eligibility of
that observation under immutable NETWORK-DESIGN-002.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Mapping, NoReturn

from tools.pr113_t1_control_t0 import GateDenied, check_product_identity

NETWORK_DESIGN_BLOB = "89206350f8025425c74033780a3166df5d68b88c"
PROFILE_A = "SOURCE_CLOSED_OFFLINE"
PROFILE_B = "NEW_EXCEPTION_TRUSTED_LOCAL_DISPOSABLE_NETWORK_RISK"
NETWORK_PROFILES = (PROFILE_A, PROFILE_B)
CONTROL_SOURCE_HEAD = "d4b5a70415db6422fef7996f186bdc235436bbc3"
CONTROL_SOURCE_TREE = "a180edbd0d6e0f87c20f527fea5245f6566e5e47"
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")

# Expected workspace / runner / effective argv are not a client-supplied shell.
# S3 request belongs to Python; Pipenv is inserted by the reviewed service.
COMMANDS = {
    "S1": ("py-direct", "direct", ("python", "-m", "pytest", "-q"), ("python", "-m", "pytest", "-q")),
    "S2": ("py-direct", "direct", ("python", "-m", "compileall", "-q", "./src"), ("python", "-m", "compileall", "-q", "./src")),
    "S3": ("py-pipenv", "pipenv", ("python", "-m", "pytest", "-q"), ("pipenv", "run", "python", "-m", "pytest", "-q")),
    "S4": ("go-project", "direct", ("go", "test", "./..."), ("go", "test", "./...")),
    "S5": ("go-project", "direct", ("go", "vet", "./..."), ("go", "vet", "./...")),
    "S6": ("go-project", "direct", ("go", "build", "-o", "bin/app", "./cmd/app"), ("go", "build", "-o", "bin/app", "./cmd/app")),
}
TRANSPORTS = ("Direct", "REST", "MCP_SERVER_JSON_RPC")

# T01..T12 event/origin/result rules are the NONOPERATIVE contract's
# observable scenarios. Unseen adverse events cannot be inferred absent.
EVENT_ORIGINS = {
    "T01": "controller_acquisition", "T02": "controller_foreign_stage",
    "T03": "native_child", "T04": "native_child", "T05": "native_child",
    "T06": "native_child", "T07": "preflight", "T08": "native_child",
    "T09": "native_child", "T10": "preflight", "T11": "monitor",
    "T12": "preflight",
}
_B_RESULTS = {
    "T01": "PREACQUISITION_ONLY", "T02": "CONTROL_FAIL",
    "T03": "LOCKED_INPUT_ONLY", "T04": "ACCEPTED_NETWORK_RISK",
    "T05": "SOURCE_RESULT_PROVENANCE_FAIL", "T06": "SOURCE_INTEGRITY_FAIL",
    "T07": "PRELAUNCH_BLOCKED", "T08": "SECURITY_FAIL",
    "T09": "SECURITY_FAIL", "T10": "NOT_APPLICABLE_TO_B",
    "T11": "NETWORK_NOT_ASSESSED", "T12": "PRELAUNCH_BLOCKED",
}
_A_RESULTS = {
    "T01": "PREACQUISITION_ONLY", "T02": "CONTROL_FAIL",
    "T03": "LOCKED_INPUT_ONLY", "T04": "SECURITY_FAIL",
    "T05": "SECURITY_FAIL", "T06": "SECURITY_FAIL",
    "T07": "PRELAUNCH_BLOCKED", "T08": "SECURITY_FAIL",
    "T09": "SECURITY_FAIL", "T10": "PRELAUNCH_BLOCKED",
    "T11": "NETWORK_NOT_ASSESSED", "T12": "PRELAUNCH_BLOCKED",
}
_DISQUALIFY = frozenset(("CONTROL_FAIL", "SECURITY_FAIL", "SOURCE_RESULT_PROVENANCE_FAIL",
                          "SOURCE_INTEGRITY_FAIL", "PRELAUNCH_BLOCKED", "UNVERIFIED_EVENT"))


def _mapping(data: object, keys: frozenset[str], name: str) -> Mapping[str, object]:
    if type(data) is not dict or frozenset(data) != keys:
        raise GateDenied(f"{name}: exact fields required")
    return data


def _hex(value: object, chars: int, name: str) -> None:
    regex = HEX40 if chars == 40 else HEX64
    if type(value) is not str or not regex.fullmatch(value):
        raise GateDenied(f"{name}: immutable lowercase hex required")


def _operator_workspace_id(value: object) -> str:
    """T0 fixture identity only; never accepts a client-declared grant."""
    if type(value) is not str or not value.strip() or "\x00" in value:
        raise GateDenied("operator workspace ID must be an exact nonempty string")
    return value


def check_command_vector(data: object, *, operator_workspace_id: str) -> None:
    """Validate six-vector data against an independently selected Workspace ID.

    The caller MUST supply operator_workspace_id from a reviewed, trusted
    Workspace fixture, not from data itself. This inert comparison does not
    authenticate config, grant Exec, or launch any original child.
    """
    expected_id = _operator_workspace_id(operator_workspace_id)
    x = _mapping(data, frozenset(("command_id", "transport", "workspace_id",
                                  "cwd", "runner", "request_argv",
                                  "effective_argv")), "vector")
    code = x["command_id"]
    if type(code) is not str or code not in COMMANDS:
        raise GateDenied("outside six approved commands")
    if type(x["transport"]) is not str or x["transport"] not in TRANSPORTS:
        raise GateDenied("outside three approved transports")
    cwd, runner, requested, effective = COMMANDS[code]
    if type(x["workspace_id"]) is not str or x["workspace_id"] != expected_id:
        raise GateDenied("workspace ID differs from operator fixture")
    if type(x["cwd"]) is not str or x["cwd"] != cwd:
        raise GateDenied("canonical command cwd changed")
    if type(x["runner"]) is not str or x["runner"] != runner:
        raise GateDenied("runner changed")
    if type(x["request_argv"]) is not list or tuple(x["request_argv"]) != requested:
        raise GateDenied("requested argv changed")
    if type(x["effective_argv"]) is not list or tuple(x["effective_argv"]) != effective:
        raise GateDenied("effective argv changed")
    if any(type(a) is not str for a in x["request_argv"] + x["effective_argv"]):
        raise GateDenied("argv type changed")


def canonical_vector(code: str, transport: str, *, operator_workspace_id: str) -> dict[str, object]:
    """Produce a data-only candidate for the caller's trusted Workspace fixture."""
    trusted_id = _operator_workspace_id(operator_workspace_id)
    if type(code) is not str or type(transport) is not str or code not in COMMANDS or transport not in TRANSPORTS:
        raise GateDenied("not a fixed command or route")
    cwd, runner, requested, effective = COMMANDS[code]
    return dict(command_id=code, transport=transport, workspace_id=trusted_id,
                cwd=cwd, runner=runner, request_argv=list(requested),
                effective_argv=list(effective))


@dataclass(frozen=True)
class EventGrade:
    code: str
    origin: str
    profile: str
    rule: str
    stop_new_admissions: bool
    source_closed_proven: bool = False  # T0 never proves actual network containment
    no_egress_proven: bool = False


def classify_event(event: object, *, profile: str) -> EventGrade:
    """Classifies an assertion, NEVER authenticates the asserted observation."""
    if type(profile) is not str or profile not in NETWORK_PROFILES:
        raise GateDenied("network contract not selected")
    x = _mapping(event, frozenset(("code", "origin", "observed")), "event")
    code = x["code"]
    if type(code) is not str or code not in EVENT_ORIGINS:
        raise GateDenied("unreviewed T1 event")
    if type(x["origin"]) is not str or x["origin"] != EVENT_ORIGINS[code]:
        raise GateDenied("event origin mismatch")
    if type(x["observed"]) is not bool:
        raise GateDenied("observation must be boolean")
    # No monitoring is not a clean bill of health: missing observation blocks
    # positive assertions; it can never be promoted into 'no contact'.
    rule = (_B_RESULTS if profile == PROFILE_B else _A_RESULTS)[code] if x["observed"] else "UNVERIFIED_EVENT"
    return EventGrade(code, x["origin"], profile, rule, rule in _DISQUALIFY)


def grade_observation(*, original_child_exit: object, events: object, profile: str) -> dict[str, object]:
    """T0-only two-axis receipt; never returns a native T1 PASS."""
    if original_child_exit is not None and (type(original_child_exit) is not int or not -255 <= original_child_exit <= 255):
        raise GateDenied("untrusted original-child exit")
    if type(events) is not list or not events or len(events) > 40:
        raise GateDenied("missing or oversized observation evidence")
    graded = [classify_event(x, profile=profile) for x in events]
    ids = [x.code for x in graded]
    if len(ids) != len(set(ids)):
        raise GateDenied("duplicate event assertion")
    rules = {x.rule for x in graded}
    priority = ("SECURITY_FAIL", "SOURCE_INTEGRITY_FAIL", "SOURCE_RESULT_PROVENANCE_FAIL",
                "CONTROL_FAIL", "PRELAUNCH_BLOCKED", "UNVERIFIED_EVENT")
    issue = next((x for x in priority if x in rules), "NO_DISQUALIFYING_EVENT_OBSERVED")
    return {
        "original_child_observation": "NOT_OBSERVED" if original_child_exit is None else ("OBSERVED_EXIT0" if original_child_exit == 0 else "OBSERVED_NONZERO"),
        "first_disqualifier": issue,
        "qualified_t1": "NOT_QUALIFIED_T0_ONLY",
        "network_profile": profile,
        "source_closed_proven": False,
        "no_egress_proven": False,
        "network_observability": "NOT_ASSESSED" if "NETWORK_NOT_ASSESSED" in rules else "EVENT_ASSERTIONS_NOT_AUTHENTICATED",
        "stop_new_admissions": any(x.stop_new_admissions for x in graded),
    }


REQUIRED_INPUT_CLASSES = frozenset(("runner_image", "selected_python", "selected_go", "selected_pipenv",
                                   "python_wheelhouse_record", "go_module_stdlib", "pipfile_venv",
                                   "github_actions", "test_control_and_fixture"))


def check_qualification_lock(data: object) -> tuple[str, ...]:
    """Validate typed inventory; even complete-looking input cannot enable T1."""
    x = _mapping(data, frozenset(("schema", "product", "network_design_blob", "network_profile",
                                  "owner_selection_evidence", "owner_t1_authorized", "inputs",
                                  "credential_absence_proven", "global_one_use_proven",
                                  "executable_controller_reviewed", "runner_context_qualified", "notes")), "qualification lock")
    if type(x["schema"]) is not int or x["schema"] != 2:
        raise GateDenied("lock schema invalid")
    check_product_identity(x["product"])
    if x["network_design_blob"] != NETWORK_DESIGN_BLOB:
        raise GateDenied("unknown network contract")
    if x["network_profile"] != PROFILE_B:
        raise GateDenied("mode B selected for this candidate; no implicit fallback")
    if x["owner_selection_evidence"] != "A_CHAT_OWNER_DIRECT_DEVELOPER_RELAY_NOT_INDEPENDENT_GITHUB_PROOF":
        raise GateDenied("unreviewed owner provenance")
    pending = []
    for gate in ("owner_t1_authorized", "credential_absence_proven", "global_one_use_proven",
                 "executable_controller_reviewed", "runner_context_qualified"):
        if type(x[gate]) is not bool:
            raise GateDenied("gate must be boolean")
        if not x[gate]:
            pending.append(gate)
    entries = x["inputs"]
    if type(entries) is not list or len(entries) != len(REQUIRED_INPUT_CLASSES):
        raise GateDenied("nine required input classes")
    names = set()
    for entry in entries:
        y = _mapping(entry, frozenset(("class", "status", "source_git_blob", "selected_sha256",
                                       "selected_size_bytes", "historical_sha256", "evidence_uri")), "foreign input")
        name = y["class"]
        if type(name) is not str or name not in REQUIRED_INPUT_CLASSES or name in names:
            raise GateDenied("missing/duplicate input class")
        names.add(name)
        if y["status"] not in ("PENDING", "HISTORICAL_REFERENCE", "SOURCE_BLOB_ONLY"):
            raise GateDenied("unreviewed input qualification transition")
        for key in ("source_git_blob", "selected_sha256", "historical_sha256"):
            value = y[key]
            if value is not None:
                _hex(value, 40 if key == "source_git_blob" else 64, key)
        if y["selected_size_bytes"] is not None and (type(y["selected_size_bytes"]) is not int or y["selected_size_bytes"] < 0):
            raise GateDenied("invalid selected size")
        if y["evidence_uri"] is not None and (type(y["evidence_uri"]) is not str or not y["evidence_uri"].startswith("https://")):
            raise GateDenied("unknown evidence URI")
        # A Git Blob for reviewed PRODUCT sources does not prove the selected
        # loaded foreign wheel/tool binary or a host image's actual bytes.
        pending.append(name)
    if type(x["notes"]) is not str:
        raise GateDenied("invalid notes")
    return tuple(pending)


def digest_existing_regular(path: Path, root: Path) -> tuple[str, int]:
    """T0 content digest under an existing owned symlink-free disposable root.

    No writable opens, no path.resolve through a symlink, no network. Ancestors
    between root and file are opened with O_DIRECTORY|O_NOFOLLOW. This is NOT a
    general filesystem sandbox, all mount/owner/loader provenance remains open.
    """
    if not isinstance(path, Path) or not isinstance(root, Path):
        raise GateDenied("Path objects required")
    if not root.is_absolute() or not path.is_absolute() or path == root or root not in path.parents:
        raise GateDenied("path escapes disposable root")
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise GateDenied("host lacks needed no-follow capability")
    # Open each root ancestor relative to its directory descriptor. A bare
    # O_NOFOLLOW on the final root would still follow a symlink in a parent.
    opened = []
    try:
        ancestor_fd = os.open(root.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        opened.append(ancestor_fd)
        for part in root.parts[1:]:
            if part in ("", ".", ".."):
                raise GateDenied("unsafe ancestor component")
            ancestor_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                  dir_fd=ancestor_fd)
            opened.append(ancestor_fd)
        root_fd = ancestor_fd
        st = os.fstat(root_fd)
        if st.st_uid != os.getuid() or not stat.S_ISDIR(st.st_mode) or st.st_mode & 0o077:
            raise GateDenied("root is not a private owned directory")
        parent_fd = root_fd
        parts = path.relative_to(root).parts
        for name in parts[:-1]:
            if name in ("", ".", ".."):
                raise GateDenied("invalid path part")
            child_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
            opened.append(child_fd)
            pst = os.fstat(child_fd)
            if pst.st_uid != os.getuid() or not stat.S_ISDIR(pst.st_mode) or pst.st_mode & 0o077:
                raise GateDenied("unsafe parent directory")
            parent_fd = child_fd
        file_fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0), dir_fd=parent_fd)
        opened.append(file_fd)
        file_st = os.fstat(file_fd)
        if not stat.S_ISREG(file_st.st_mode) or file_st.st_nlink != 1 or file_st.st_uid != os.getuid():
            raise GateDenied("not a private regular single-link file")
        digest = hashlib.sha256()
        count = 0
        while True:
            block = os.read(file_fd, 1024 * 128)
            if not block:
                break
            count += len(block)
            if count > 100_000_000:
                raise GateDenied("file exceeds T0 verification budget")
            digest.update(block)
        end_st = os.fstat(file_fd)
        if (end_st.st_ino, end_st.st_dev, end_st.st_size, end_st.st_mtime_ns) != (
                file_st.st_ino, file_st.st_dev, file_st.st_size, file_st.st_mtime_ns):
            raise GateDenied("file changed during digest")
        return digest.hexdigest(), count
    except OSError as exc:
        raise GateDenied("unsafe or unreadable fixture input") from exc
    finally:
        for fd in reversed(opened):
            os.close(fd)


def native_execution_decision(*_args: object, **_kwargs: object) -> NoReturn:
    """This module is nonoperative even if all user-supplied gates are true."""
    raise GateDenied("native T1 is NOT AUTHORIZED; no workflow or launch adapter is provided")


def preflight_report(lock: object) -> dict[str, object]:
    """Machine-readable nonoperative preflight; never supplies a permit token."""
    pending = check_qualification_lock(lock)
    return {
        "schema": "PR113_T1_T0_PREFLIGHT_002",
        "decision": "DENY",
        "native_execution_authorized": False,
        "network_profile": PROFILE_B,
        "network_design_blob": NETWORK_DESIGN_BLOB,
        "expected_previous_control_head": CONTROL_SOURCE_HEAD,
        "expected_previous_control_tree": CONTROL_SOURCE_TREE,
        "input_classes_pending": len(REQUIRED_INPUT_CLASSES),
        "blockers": list(pending),
        "reason": "T0-only status; no global one-use, provenance, no-secret or Owner T1 run grant",
    }


def main(argv: list[str] | None = None) -> int:
    """Offline CLI with NO command/target/path knobs; expected exit 3 DENY."""
    argv = sys.argv[1:] if argv is None else argv
    if argv:
        print(json.dumps({"decision": "DENY", "reason": "unsupported arguments"}, sort_keys=True))
        return 3
    src = Path(__file__).absolute().parents[1] / "docs" / "PR113_T1_QUALIFICATION_LOCK_002.json"
    try:
        # Reuse the previously reviewed nonspawning duplicate-key/symlink guard.
        from tools.pr113_t1_control_t0 import load_lock_json
        report = preflight_report(load_lock_json(src))
    except GateDenied:
        report = {"decision": "DENY", "reason": "unqualified or unsafe preflight data"}
    print(json.dumps(report, sort_keys=True))
    return 3


if __name__ == "__main__":
    raise SystemExit(main())
