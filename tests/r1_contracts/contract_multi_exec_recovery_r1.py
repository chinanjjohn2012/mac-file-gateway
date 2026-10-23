"""R1 RED-only deterministic contracts for D0 durable Exec lifecycle.

NOT discovered by plain pytest: filename intentionally does not start test_.
Invoke explicitly with the dedicated R1 workflow. No Popen, real signals,
private Tunnel, Native C, or external Workspace is used. Real product
entrypoints are probed with a fake runner; deeper failure windows use the
test-owned OS-call witnesses; R2 needs an internal-only disposable grant factory.

A failing assertion is not proof of a working state machine. It shows the
reviewed D0 outcome is not yet enforced. See R1 acceptance evidence document.
"""
from __future__ import annotations

import asyncio
import io
import json
import os
import stat
import subprocess
import threading
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from gateway.core import GatewayError
from gateway.private_fs import PrivateFileError
from gateway.workspaces import ActiveRuntimeInventory, WorkspaceService
from gateway.workspaces_config import parse_workspace_config
from gateway.http_multi import create_multi_app


@pytest.fixture
def disposable(tmp_path):
    """Fully disposable two-Workspace service; never launches a real process."""
    roots = tmp_path / "projects"
    roots.mkdir()
    for name in ("a", "b"):
        src = roots / name / "src"
        src.mkdir(parents=True)
        (src / "ok.py").write_text("print('disposable-only')\n")
    config_dir = tmp_path / "control"
    config_dir.mkdir(mode=0o700)
    config_dir.chmod(0o700)
    runtime = tmp_path / "trusted-runtime"
    runtime.mkdir()
    services = []

    class Scene:
        state_root = config_dir / "exec-state"
        config = config_dir
        roots = None

        runtime = None

        def settings(self, *, server=True, workspace=True):
            return parse_workspace_config({
                "schema_version": 1,
                "server": {"exec": {"enabled": server}},
                "workspaces": {
                    "a": {"root": str(roots / "a"), "exec": {
                        "enabled": workspace,
                        "paths": ["src"] if workspace else [],
                        "runners": ["src=direct"] if workspace else [],
                    }},
                    "b": {"root": str(roots / "b")},
                },
            })

        def service(self, *, server=True, workspace=True):
            service = WorkspaceService(
                self.settings(server=server, workspace=workspace),
                config_dir=config_dir,
                inventory=ActiveRuntimeInventory(paths=(runtime,)),
            )
            services.append(service)
            return service

        @staticmethod
        def fake_runner(service, monkeypatch):
            """Patch the last Python runner boundary: zero actual Popen."""
            calls = []

            def fake(cwd, argv, timeout_seconds=60, dry_run=True):
                calls.append((cwd, tuple(argv), timeout_seconds, dry_run))
                return {"cwd": cwd, "dry_run": dry_run,
                        "executed": not dry_run, "exit_code": 0,
                        "stdout": "stubbed; no child", "stderr": ""}
            monkeypatch.setattr(service.get("a").gateway, "run_command", fake)
            return calls

        def add_state_entry(self, filename, contents=b'{"unexpected":true}\n'):
            self.state_root.mkdir(mode=0o700, exist_ok=True)
            candidate = self.state_root / filename
            candidate.write_bytes(contents)
            candidate.chmod(0o600)
            return candidate

    scene = Scene()
    scene.roots = roots
    scene.runtime = runtime
    scene.services = services
    try:
        yield scene
    finally:
        for svc in reversed(services):
            svc.close()


def _must_deny(func, code, red):
    try:
        result = func()
    except GatewayError as exc:
        if exc.code != code:
            raise AssertionError("R1_TEST_INFRA_WRONG_DENIAL_CODE: expected "
                                 + code + ", received " + exc.code)
    else:
        pytest.fail("R1_RED_" + red + ": unauthorized result " + repr(result),
                    pytrace=False)


def _must_status(policy, field, expected, red):
    if field not in policy or policy[field] != expected:
        pytest.fail("R1_RED_" + red + ": expected " + field + "="
                    + repr(expected) + ", observed "
                    + repr(policy.get(field, "<missing>")), pytrace=False)


# H: Test-only proof must be independent of ordinary global/Workspace Exec grants.

def test_normal_two_grants_do_not_authorize_apply(disposable, monkeypatch):
    svc = disposable.service()
    calls = disposable.fake_runner(svc, monkeypatch)
    _must_deny(lambda: svc.invoke_exec("a", "src", ["python", "ok.py"],
                                       dry_run=False),
               "exec_cleanup_proof_required", "NORMAL_PROOF_GATE")
    assert calls == [], "R1_RED_NORMAL_PROOF_GATE: Python runner was invoked"


def test_normal_rest_apply_is_503_before_runner(disposable, monkeypatch):
    svc = disposable.service()
    calls = disposable.fake_runner(svc, monkeypatch)
    with TestClient(create_multi_app(svc, enable_mcp=False),
                    base_url="http://127.0.0.1:8765") as client:
        response = client.post("/run", json={
            "workspace": "a", "cwd": "src", "argv": ["python", "ok.py"],
            "dry_run": False,
        })
        if response.status_code == 200:
            pytest.fail("R1_RED_REST_PROOF_GATE: normal apply was accepted",
                        pytrace=False)
        if (response.status_code != 503 or
                response.json().get("error") != "exec_cleanup_proof_required"):
            raise AssertionError("R1_TEST_INFRA_UNEXPECTED_HTTP: "
                                 + str(response.status_code) + " "
                                 + response.text[:160])
    assert not calls, "R1_RED_REST_PROOF_GATE: execution reached runner"


def test_normal_mcp_apply_rejects_cleanup_proof(disposable, monkeypatch):
    from gateway.mcp_multi import build_multi_mcp
    from mcp.server.mcpserver.exceptions import ToolError

    svc = disposable.service()
    calls = disposable.fake_runner(svc, monkeypatch)
    mcp = build_multi_mcp(svc)
    arguments = {"workspace": "a", "cwd": "src",
                 "argv": ["python", "ok.py"], "dry_run": False}
    try:
        response = asyncio.run(mcp.call_tool("run_command", arguments))
    except ToolError as exc:
        if "exec_cleanup_proof_required" not in str(exc):
            raise AssertionError("R1_TEST_INFRA_WRONG_MCP_ERROR: " + str(exc))
    else:
        pytest.fail("R1_RED_MCP_PROOF_GATE: returned " + repr(response)[:180],
                    pytrace=False)
    assert not calls, "R1_RED_MCP_PROOF_GATE: execution reached runner"



def test_normal_denial_is_no_spawn_and_no_false_unknown(disposable, monkeypatch):
    """P2-01: a normal default-DENY is NOT ambiguous or quarantined."""
    svc = disposable.service()
    calls = disposable.fake_runner(svc, monkeypatch)
    _must_deny(lambda: svc.invoke_exec("a", "src", ["python", "ok.py"],
                                       dry_run=False),
               "exec_cleanup_proof_required", "NORMAL_DENIAL_ZERO_SPAWN")
    _require(not calls, "NORMAL_DENIAL_CALLED_RUNNER", repr(calls))
    _require(not _state_contains(disposable.state_root,
                                 {"PREPARED", "RUNNING", "UNKNOWN"}),
             "NORMAL_DENIAL_LEFT_FALSE_INTENT", "pre-launch denial persisted")
    policy = svc.info()["exec_policy"]
    _require(policy.get("quarantined") is False,
             "NORMAL_DENIAL_FALSE_QUARANTINE", repr(policy))


def test_mcp_transport_structured_exec_cleanup_denial(disposable, monkeypatch):
    """P3-02: actual SDK JSON-RPC tools/call, not an internal ToolError."""
    svc = disposable.service()
    calls = disposable.fake_runner(svc, monkeypatch)
    headers = {"Accept": "application/json, text/event-stream",
               "Content-Type": "application/json"}
    def rpc(client, method, params=None):
        response = client.post("/mcp", headers=headers, json={
            "jsonrpc": "2.0", "id": 101, "method": method,
            "params": params or {},
        })
        if response.status_code != 200:
            raise AssertionError("R1_TEST_INFRA_MCP_HTTP: " + response.text[:160])
        return response.json()
    with TestClient(create_multi_app(svc),
                    base_url="http://127.0.0.1:8765") as client:
        init = rpc(client, "initialize", {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "r1-transport-contract", "version": "1"},
        })
        assert "result" in init, init
        client.post("/mcp", headers=headers, json={
            "jsonrpc": "2.0", "method": "notifications/initialized"})
        resp = rpc(client, "tools/call", {
            "name": "run_command", "arguments": {
                "workspace": "a", "cwd": "src",
                "argv": ["python", "ok.py"], "dry_run": False,
            }})
        tool = resp.get("result", {})
        if tool.get("isError") is not True:
            pytest.fail("R1_RED_MCP_TRANSPORT_ACCEPTED_UNQUALIFIED_EXEC",
                        pytrace=False)
        content = tool.get("structuredContent") or {}
        if content.get("error") != "exec_cleanup_proof_required":
            pytest.fail("R1_RED_MCP_TRANSPORT_NOT_STRUCTURED: " + repr(tool)[:240],
                        pytrace=False)
    _require(not calls, "MCP_TRANSPORT_CALLED_RUNNER", repr(calls))


@pytest.mark.parametrize("env_name", [
    "GATEWAY_EXEC_TEST_GRANT",
    "GATEWAY_R1_TEST_ONLY",
    "PYTEST_CURRENT_TEST",
])
def test_environment_cannot_grant_test_only_retirement(
        disposable, monkeypatch, env_name):
    monkeypatch.setenv(env_name, "trusted:yes")
    svc = disposable.service()
    calls = disposable.fake_runner(svc, monkeypatch)
    _must_deny(lambda: svc.invoke_exec("a", "src", ["python", "ok.py"],
                                       dry_run=False),
               "exec_cleanup_proof_required", "ENV_PROOF_BYPASS")
    assert not calls, "R1_RED_ENV_PROOF_BYPASS: runner invoked"


def test_config_test_only_grant_is_not_a_public_option(disposable):
    settings = {
        "schema_version": 1,
        "server": {"exec": {"enabled": True, "test_only": True}},
        "workspaces": {"a": {"root": str(disposable.roots / "a"),
                             "exec": {"enabled": True, "paths": ["src"]}}},
    }
    with pytest.raises(PrivateFileError):
        parse_workspace_config(settings)


def test_rest_test_grant_request_field_is_rejected(disposable):
    svc = disposable.service()
    with TestClient(create_multi_app(svc, enable_mcp=False),
                    base_url="http://127.0.0.1:8765") as client:
        response = client.post("/run", json={
            "workspace": "a", "cwd": "src", "argv": ["python", "ok.py"],
            "test_only_grant": True, "dry_run": False,
        })
        assert response.status_code == 400, response.text


# L: registered capability, grant and proof-available are separate states.

def test_info_false_available_when_proof_missing(disposable):
    svc = disposable.service()
    policy = svc.info()["exec_policy"]
    _must_status(policy, "available", False, "AVAILABLE_WITHOUT_PROOF")
    _must_status(policy, "completion_capability", "none", "CAPABILITY_DEFAULT")


def test_info_health_same_exec_policy(disposable):
    svc = disposable.service()
    with TestClient(create_multi_app(svc, enable_mcp=False),
                    base_url="http://127.0.0.1:8765") as client:
        info = client.get("/info").json()
        health = client.get("/health").json()
    if "exec_policy" not in health or health["exec_policy"] != info["exec_policy"]:
        pytest.fail("R1_RED_HEALTH_STATUS_PARITY: missing/different exec_policy",
                    pytrace=False)
    _must_status(info["exec_policy"], "adapter_exposed", True,
                 "REGISTERED_ROUTE_STILL_VISIBLE")


def test_nonqualified_status_never_exposes_full_tree_capability(disposable):
    svc = disposable.service()
    policy = svc.info()["exec_policy"]
    _must_status(policy, "completion_capability", "none",
                 "NO_FULL_TREE_PROOF_BY_DEFAULT")
    _must_status(policy, "durability_state", "healthy",
                 "HEALTHY_STATE_REPORTED")


# A/C: boot scan must latch global quarantine before exposing Exec API.

@pytest.mark.parametrize("filename", [
    "unexpected-control.json",
    "temp-crash-after-write.tmp",
    "r-stale-running.json",
    "unknown-unretired.json",
])
def test_boot_untrusted_state_entry_quarantines(disposable, filename):
    entry = disposable.add_state_entry(filename)
    svc = disposable.service()
    policy = svc.info()["exec_policy"]
    _must_status(policy, "quarantined", True, "BOOT_SCAN_QUARANTINE")
    _must_status(policy, "available", False, "BOOT_SCAN_AVAILABLE")
    assert entry.exists(), "R1_RED_BOOT_SCAN_QUARANTINE: evidence was erased"


def test_quarantined_dry_run_is_not_misleading_preview(disposable):
    disposable.add_state_entry("foreign-entry.json")
    svc = disposable.service()
    _must_deny(lambda: svc.invoke_exec("a", "src", ["python", "ok.py"],
                                       dry_run=True),
               "exec_quarantined", "QUARANTINED_PREVIEW")


def test_quarantined_other_workspace_read_still_works(disposable):
    disposable.add_state_entry("stale-record.json")
    svc = disposable.service()
    result = svc.invoke("b", "list_files", ".")
    assert result["workspace"] == "b"
    _must_status(svc.info()["exec_policy"], "quarantined", True,
                 "FILE_READ_INDEPENDENT_OF_EXEC")


def test_state_root_is_not_allowed_to_be_a_symlink(disposable):
    target = disposable.config / "other-private"
    target.mkdir(mode=0o700)
    disposable.state_root.symlink_to(target, target_is_directory=True)
    svc = disposable.service()
    policy = svc.info()["exec_policy"]
    _must_status(policy, "available", False, "SYMLINK_STATE_UNAVAILABLE")
    if policy.get("durability_state") not in ("unavailable", "quarantined"):
        pytest.fail("R1_RED_SYMLINK_STATE_UNAVAILABLE: unsafe state accepted",
                    pytrace=False)


def test_foreign_hardlinked_record_fails_closed(disposable):
    disposable.state_root.mkdir(mode=0o700)
    outside = disposable.config / "linked-record"
    outside.write_text('{"kind":"RUNNING"}')
    os.link(outside, disposable.state_root / "foreign.json")
    svc = disposable.service()
    _must_status(svc.info()["exec_policy"], "available", False,
                 "HARDLINK_STATE_UNAVAILABLE")


def test_conflicting_second_owner_cannot_admit_exec(disposable):
    first = disposable.service()
    second = disposable.service()
    first_policy = first.info()["exec_policy"]
    second_policy = second.info()["exec_policy"]
    if second_policy.get("durability_state") not in ("unavailable", "quarantined"):
        pytest.fail("R1_RED_OWNER_LOCK: second state owner was admitted "
                    + repr((first_policy, second_policy)), pytrace=False)


def test_unreadable_state_root_cannot_fall_back_to_inmemory(disposable, monkeypatch):
    real_open = os.open

    def deny_exec_state(path, *args, **kwargs):
        if str(path) == "exec-state" or str(path).endswith("/exec-state"):
            raise PermissionError("R1 injected Exec state directory permission error")
        return real_open(path, *args, **kwargs)

    with monkeypatch.context() as m:
        m.setattr(os, "open", deny_exec_state)
        svc = disposable.service()
    policy = svc.info()["exec_policy"]
    _must_status(policy, "available", False, "STATE_IO_FAIL_CLOSED")
    _must_status(policy, "durability_state", "unavailable",
                 "STATE_IO_DIAGNOSTIC")


# B/C/I/K: test-owned witnesses, NEVER a product-reported outcome dictionary.
#
# R2 must supply ONLY an internal disposable fixture constructor (not a case-
# dispatch probe). The test itself owns all fault triggers and observations.
# The constructor must refuse ordinary user roots and external parameters.

def _qualified_service(scene, *, granted_workspaces=("a",), hooks=None):
    """Internal R2 acceptance seam; missing seam is explicit specification RED.

    The returned value must be an actual WorkspaceService, not a test result.
    It must carry a nonserializable grant bound to the private fixture,
    loopback listener, exact service identity, pinned state root, and scopes.
    """
    try:
        from gateway.exec_recovery_acceptance import _create_disposable_test_service
    except ModuleNotFoundError as exc:
        if exc.name != "gateway.exec_recovery_acceptance":
            raise
        pytest.fail("R1_RED_PRIVATE_FACTORY_MISSING", pytrace=False)
    svc = _create_disposable_test_service(
        settings=scene.settings(), config_dir=scene.config,
        inventory=ActiveRuntimeInventory(paths=(scene.runtime,)),
        fixture_root=scene.roots, state_root=scene.state_root,
        listener_host="127.0.0.1", granted_workspaces=granted_workspaces,
        lifecycle_fault_hooks=hooks,
    )
    assert isinstance(svc, WorkspaceService), (
        "R1_TEST_INFRA_FACTORY_MUST_RETURN_REAL_WORKSPACE_SERVICE")
    scene.services.append(svc)
    return svc


def _on_disk_records(root):
    """Independent real bytes read; do not accept reports from the system."""
    if not root.exists():
        return []
    records = []
    for path in sorted(root.iterdir()):
        if not path.is_file() or path.is_symlink():
            continue
        data = path.read_bytes()
        try:
            obj = json.loads(data)
        except (ValueError, UnicodeDecodeError):
            continue
        if isinstance(obj, dict) and obj.get("phase") in (
                "PREPARED", "RUNNING", "UNKNOWN", "RETIRED"):
            assert obj.get("attempt_id") and obj.get("workspace") == "a", (
                "R1_TEST_INFRA_INVALID_CANONICAL_RECORD")
            records.append((path.name, obj))
    return records


def _state_contains(root, phases):
    return [(filename, obj) for filename, obj in _on_disk_records(root)
            if obj["phase"] in phases]


def _require(condition, marker, detail):
    if not condition:
        pytest.fail("R1_RED_" + marker + ": " + detail, pytrace=False)


class _DummyProcess:
    """An inert child handle. NEVER calls Popen, waitpid, kill or real signals."""
    pid = 587231

    def __init__(self, witness, *args, **kwargs):
        self.owner = witness
        self.returncode = None
        self.stdout = io.BytesIO(b"deterministic-output")
        self.stderr = io.BytesIO(b"")
        self.owner.events.append("dummy_child_constructed")

    def wait(self, timeout=None):
        self.owner.events.append("leader_wait")
        if self.owner.fault == "leader_wait_failure":
            self.owner.fired.append("leader_wait_failure")
            raise OSError("R1 controlled dummy leader-wait fault")
        self.returncode = 0
        return 0

    def poll(self):
        return self.returncode

    def kill(self):
        self.owner.events.append("dummy_kill")
        self.returncode = -9

    def terminate(self):
        self.owner.events.append("dummy_terminate")
        self.returncode = -15


class _ExternalWitness:
    """Owned by the test: syscall tracing + actual disk inspection.

    A future implementation cannot pass this test by returning a canned dict.
    Every induced fault needs a traced call at the intended OS boundary,
    and terminal/reboot claims are checked by a separate filesystem scan.
    """
    def __init__(self, state_root, fault=None):
        self.root = state_root
        self.fault = fault
        self.events = []
        self.fired = []
        self.spawns = []
        self.snapshot_at_spawn = []
        self.unlinked = []
        self.state_writes = []
        self.signal_attempts = []

    def _fd_kind(self, fd):
        try:
            st = os.fstat(fd)
            root = self.root.stat()
            if (st.st_dev, st.st_ino) == (root.st_dev, root.st_ino):
                return "directory"
            for path in self.root.iterdir():
                try:
                    item = path.stat(follow_symlinks=False)
                    if (st.st_dev, st.st_ino) == (item.st_dev, item.st_ino):
                        return "record"
                except OSError:
                    pass
        except (OSError, ValueError):
            pass
        return None

    def _is_state_path(self, path, dir_fd=None):
        if dir_fd is not None and self._fd_kind(dir_fd) == "directory":
            return True
        return str(path).startswith(str(self.root) + os.sep)

    def install(self, monkeypatch):
        original_write, original_fsync = os.write, os.fsync
        original_replace, original_unlink = os.replace, os.unlink

        def write(fd, payload):
            kind = self._fd_kind(fd)
            if kind == "record":
                self.events.append("state_write")
                self.state_writes.append(bytes(payload))
            return original_write(fd, payload)

        def fsync(fd):
            kind = self._fd_kind(fd)
            if kind:
                self.events.append(kind + "_fsync")
                trigger = (self.fault == "intent_file_fsync_failure"
                           and kind == "record" and not self.spawns) or (
                           self.fault == "intent_directory_fsync_failure"
                           and kind == "directory" and not self.spawns) or (
                           self.fault == "post_spawn_finalization_fsync_failure"
                           and kind == "record" and bool(self.spawns)
                           and any(b'RETIRED' in chunk for chunk in self.state_writes))
                if (self.fault == "retired_prune_directory_fsync_failure"
                        and kind == "directory" and self.unlinked):
                    trigger = True
                if trigger:
                    self.fired.append(self.fault)
                    raise OSError("R1 injected state " + str(self.fault))
            return original_fsync(fd)

        def replace(source, target, *args, **kwargs):
            if self._is_state_path(target, kwargs.get("dst_dir_fd")):
                self.events.append("state_atomic_rename")
                if self.fault == "intent_atomic_rename_failure" and not self.spawns:
                    self.fired.append(self.fault)
                    raise OSError("R1 injected atomic rename fault")
            return original_replace(source, target, *args, **kwargs)

        def unlink(path, *args, **kwargs):
            if self._is_state_path(path, kwargs.get("dir_fd")):
                self.events.append("state_unlink")
                self.unlinked.append(str(path))
                # A prune fault is injected only at a directory fsync after
                # an actual RETIRED unlink, never by fabricating a response.
            return original_unlink(path, *args, **kwargs)

        def popen(*args, **kwargs):
            self.events.append("spawn_attempt")
            self.spawns.append((args, kwargs))
            self.snapshot_at_spawn.append(_on_disk_records(self.root))
            if self.fault in ("ambiguous_popen_failure",
                              "restart_after_popen_before_identity"):
                self.fired.append(self.fault)
                raise OSError("R1 injected ambiguous fake Popen")
            return _DummyProcess(self, *args, **kwargs)

        def forbid_signals(*args, **kwargs):
            self.signal_attempts.append((args, kwargs))
            # Signal 0 is a group-presence probe, not real termination.
            if len(args) >= 2 and args[1] == 0:
                raise ProcessLookupError("R1 dummy group is absent")
            self.events.append("signal_intercepted")
            return None

        monkeypatch.setattr(os, "write", write)
        monkeypatch.setattr(os, "fsync", fsync)
        monkeypatch.setattr(os, "replace", replace)
        monkeypatch.setattr(os, "unlink", unlink)
        monkeypatch.setattr(subprocess, "Popen", popen)
        monkeypatch.setattr(os, "killpg", forbid_signals)
        monkeypatch.setattr(os, "kill", forbid_signals)

    def assert_fsynced_before_spawn(self, *, required=True):
        if self.spawns:
            first = self.events.index("spawn_attempt")
            leading = self.events[:first]
            _require("record_fsync" in leading and
                     "directory_fsync" in leading and
                     bool(self.snapshot_at_spawn[0]) and
                     bool([v for _, v in self.snapshot_at_spawn[0]
                           if v["phase"] in ("PREPARED", "RUNNING")]),
                     "DURABLE_INTENT_PRECEDES_SPAWN",
                     "real fsync + directory fsync + readable PREPARED absent")
        elif required:
            pytest.fail("R1_RED_SPAWN_NOT_WITNESSED", pytrace=False)

    def assert_unknown_on_disk(self):
        records = _state_contains(self.root, {"PREPARED", "RUNNING", "UNKNOWN"})
        _require(bool(records), "UNCERTAIN_RECORD_MISSING",
                 "actual unresolved durable intent not found")
        return records


def _attempt(service):
    """No real child. The test's Popen stub is installed before this call."""
    try:
        return service.invoke_exec("a", "src", ["python", "ok.py"],
                                   dry_run=False)
    except (OSError, GatewayError, TimeoutError, PermissionError,
            _SyntheticWorkerCrash):
        return None


def _assert_quarantined(service):
    policy = service.info()["exec_policy"]
    _require(policy.get("quarantined") is True and
             policy.get("available") is False,
             "UNKNOWN_NOT_QUARANTINED", repr(policy))



class _SyntheticWorkerCrash(BaseException):
    """Simulated abrupt worker loss, never a real process kill."""


class _LifecycleFaultHooks:
    """Test-owned callbacks executed at specific R2 Worker stages.

    Returning a dictionary cannot satisfy these tests. Each callback records
    the exact stage before injecting the requested fault. Product REST/MCP
    cannot construct or choose this private acceptance-only hook.
    """
    EVENTS = {
        "deadline_before_popen": "before_popen",
        "stream_drain_failure": "before_stream_drain",
        "restart_after_prepared_before_popen": "after_prepared_fsync",
        "restart_after_popen_before_identity": "after_popen_before_identity",
        "restart_after_leader_reap": "after_leader_reap",
        "restart_after_retire_before_response": "after_retire_fsync",
        "grant_invalidated_during_finalization": "before_grant_finalize",
        "detached_descendant_observed": "after_original_group_absent",
        "cancellation_during_final_state_fsync": "before_retire_fsync",
    }

    def __init__(self, case):
        self.case = case
        self.events = []
        self.fired = []
        self.pause_entered = threading.Event()
        self.pause_release = threading.Event()

    def on_event(self, stage):
        self.events.append(stage)
        if stage != self.EVENTS.get(self.case):
            return
        self.fired.append(stage)
        if self.case == "cancellation_during_final_state_fsync":
            self.pause_entered.set()
            if not self.pause_release.wait(5):
                raise AssertionError("R1_TEST_INFRA_UNRELEASED_FINALIZATION")
        elif self.case == "deadline_before_popen":
            raise TimeoutError("R1 test clock expired before Popen")
        elif self.case.startswith("restart_after_"):
            raise _SyntheticWorkerCrash("R1 simulated worker crash at " + stage)
        elif self.case == "grant_invalidated_during_finalization":
            raise PermissionError("R1 injected private grant lifetime loss")
        elif self.case == "detached_descendant_observed":
            raise OSError("R1 injected positive detached descendant evidence")
        else:
            raise OSError("R1 injected lifecycle fault at " + stage)


def _make_valid_record(scene, phase, *, attempt_id="9a" * 16, padding=0):
    """R2 serializer produces real bytes, independently parsed by R1.

    This is NOT a mocked Gateway outcome: callers write those bytes to the
    pinned private state fixture, close/reopen and audit boot scanning.
    """
    try:
        from gateway.exec_state import _serialize_disposable_state_record
    except (ImportError, AttributeError) as exc:
        if isinstance(exc, ModuleNotFoundError) and exc.name != "gateway.exec_state":
            raise
        pytest.fail("R1_RED_CANONICAL_STATE_CODEC_MISSING", pytrace=False)
    st = (scene.roots / "a").stat()
    record = _serialize_disposable_state_record(
        attempt_id=attempt_id, workspace="a",
        workspace_dev=st.st_dev, workspace_ino=st.st_ino, phase=phase,
        cleanup_scope="none", source="r1-disposable-fault-fixture",
        bounded_padding_bytes=padding,
    )
    _require(isinstance(record, bytes) and len(record) <= 4096,
             "INVALID_CANONICAL_BYTES", repr(type(record)))
    obj = json.loads(record)
    _require(obj.get("phase") == phase and obj.get("workspace") == "a"
             and obj.get("attempt_id") == attempt_id,
             "INVALID_CANONICAL_SCHEMA", repr(obj))
    return record


def _fsync_fixture_record(scene, data, filename="r1-9a.json"):
    """Physical bytes and directory fsync, not a fabricated state summary."""
    scene.state_root.mkdir(mode=0o700, exist_ok=True)
    candidate = scene.state_root / filename
    with candidate.open("xb") as file:
        file.write(data)
        file.flush()
        os.fsync(file.fileno())
    fd = os.open(scene.state_root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    _require(candidate.read_bytes() == data, "RECORD_NOT_PERSISTED",
             "fixture bytes changed on disk")
    return candidate


def test_ambiguous_sync_worker_failure_latches_quarantine(disposable, monkeypatch):
    """P2-01: *eligible internal* disposable attempt, never normal Gateway."""
    svc = _qualified_service(disposable)
    w = _ExternalWitness(disposable.state_root, "ambiguous_popen_failure")
    with monkeypatch.context() as m:
        w.install(m)
        _attempt(svc)
    _require(w.fired == ["ambiguous_popen_failure"] and len(w.spawns) == 1,
             "AMBIGUOUS_FAULT_NOT_INVOKED", repr(w.events))
    w.assert_fsynced_before_spawn()
    w.assert_unknown_on_disk()
    _assert_quarantined(svc)


def test_ambiguous_state_survives_service_restart(disposable, monkeypatch):
    """P2-01: fsynced RUNNING from an *actually valid* prior fixture."""
    record = _fsync_fixture_record(
        disposable, _make_valid_record(disposable, "RUNNING"))
    first_bytes = record.read_bytes()
    svc = disposable.service()   # ordinary Gateway boot-scan, no test grant
    _assert_quarantined(svc)
    _require(record.read_bytes() == first_bytes, "RESTART_ERASED_UNKNOWN",
             "boot removed earlier durable RUNNING evidence")
    svc.close()
    second = disposable.service()
    _assert_quarantined(second)
    _require(record.read_bytes() == first_bytes, "RESTART_REPLAYED_UNKNOWN",
             "second boot modified unresolved record")


@pytest.mark.parametrize("phase", ["PREPARED", "RUNNING", "UNKNOWN"])
def test_boot_well_formed_historical_attempt_is_quarantined(
        disposable, phase):
    """P3-03: legal schema, real file/directory fsync, actual new Service."""
    record = _fsync_fixture_record(disposable, _make_valid_record(disposable, phase))
    before = record.read_bytes()
    svc = disposable.service()
    _assert_quarantined(svc)
    _require(record.read_bytes() == before, "VALID_HISTORY_ERASED",
             "boot discarded a valid durable " + phase)


def test_quarantine_never_triggers_stale_pid_signal(disposable, monkeypatch):
    disposable.add_state_entry("unknown-process-record.json",
                               b'{"phase":"UNKNOWN","pid":123456}\n')
    signals = []
    with monkeypatch.context() as m:
        m.setattr(os, "killpg", lambda *a: signals.append(("killpg", a)))
        m.setattr(os, "kill", lambda *a: signals.append(("kill", a)))
        svc = disposable.service()
    _must_status(svc.info()["exec_policy"], "quarantined", True,
                 "UNKNOWN_NO_STALE_PID_SIGNAL")
    assert signals == [], "R1_RED_UNKNOWN_NO_STALE_PID_SIGNAL: unsafe signal"


# H/I/J/K: scenarios specify external witness conditions; no _r1_contract_probe.
#
# Every scenario is distinct in the strict JUnit verifier. Missing internal
# factory/codec is a clearly marked UNIMPLEMENTED FIXTURE RED, not evidence
# that the scenario fault already fired. Future GREEN must prove external
# OS-call, state-file and restart observations from the tests below.

_SCENARIOS = (
    "intent_file_fsync_failure",
    "intent_directory_fsync_failure",
    "intent_atomic_rename_failure",
    "deadline_before_popen",
    "ambiguous_popen_failure",
    "stream_drain_failure",
    "leader_wait_failure",
    "post_spawn_finalization_fsync_failure",
    "restart_after_prepared_before_popen",
    "restart_after_popen_before_identity",
    "restart_after_leader_reap",
    "restart_after_retire_before_response",
    "valid_internal_test_grant_group_retirement",
    "forged_or_client_supplied_grant",
    "grant_bound_to_other_service",
    "grant_bound_to_other_workspace_inode",
    "grant_invalidated_by_restart",
    "grant_invalidated_during_finalization",
    "detached_descendant_observed",
    "quota_full_without_retired",
    "retired_only_prune_and_dir_fsync",
    "retired_prune_directory_fsync_failure",
    "quota_exact_4096_records_16mib",
    "cancellation_during_final_state_fsync",
)

_PRESPAWN_FAULTS = {
    "intent_file_fsync_failure", "intent_directory_fsync_failure",
    "intent_atomic_rename_failure",
}
_POSTSPAWN_FAULTS = {
    "ambiguous_popen_failure", "stream_drain_failure",
    "leader_wait_failure", "post_spawn_finalization_fsync_failure",
    "restart_after_popen_before_identity",
    "grant_invalidated_during_finalization", "detached_descendant_observed",
}
_RESTART_SCENARIOS = {
    "restart_after_prepared_before_popen", "restart_after_popen_before_identity",
    "restart_after_leader_reap", "restart_after_retire_before_response",
}
_QUOTA_SCENARIOS = {
    "quota_full_without_retired", "retired_only_prune_and_dir_fsync",
    "retired_prune_directory_fsync_failure", "quota_exact_4096_records_16mib",
}
_GRANT_DENIALS = {
    "forged_or_client_supplied_grant", "grant_bound_to_other_service",
    "grant_bound_to_other_workspace_inode", "grant_invalidated_by_restart",
}


@pytest.mark.parametrize("case", _SCENARIOS, ids=_SCENARIOS)
def test_internal_state_fault_injection_contract(
        disposable, monkeypatch, case):
    """Independent tests own the failure, attempted spawn, durable records.

    R2's only internal-only seam is the private *service constructor*,
    never case-dispatch/summary-return. No test receives or trusts a
    returned 'outcome_code', 'spawn_count', 'quarantine', etc. dictionary.
    """
    if case == "forged_or_client_supplied_grant":
        svc = disposable.service()
        w = _ExternalWitness(disposable.state_root)
        with monkeypatch.context() as m:
            w.install(m)
            _must_deny(lambda: svc.invoke_exec("a", "src", ["python", "ok.py"],
                                               dry_run=False),
                       "exec_cleanup_proof_required", "FORGED_GRANT_ACCEPTED")
        _require(not w.spawns, "FORGED_GRANT_SPAWNED", repr(w.events))
        return

    if case in _QUOTA_SCENARIOS:
        # The actual state root is the authority; returned dicts have no role.
        # Unique attempt IDs are required, never 4096 aliases of one marker.
        if case == "quota_full_without_retired":
            for idx in range(4096):
                ident = "%032x" % (idx + 1)
                data = _make_valid_record(disposable, "UNKNOWN",
                                          attempt_id=ident)
                _fsync_fixture_record(disposable, data,
                                      filename="r1-capacity-%04d.json" % idx)
            original = {p.name: p.read_bytes()
                        for p in disposable.state_root.iterdir()
                        if p.is_file()}
            w = _ExternalWitness(disposable.state_root)
            with monkeypatch.context() as m:
                w.install(m)
                svc = disposable.service()
                _attempt(svc)
            _require(not w.spawns and not w.unlinked,
                     "QUOTA_UNKNOWN_DELETED_OR_STARTED", repr(w.events))
            _assert_quarantined(svc)
            _require(all((disposable.state_root / name).read_bytes() == data
                         for name, data in original.items()),
                     "QUOTA_ERASED_UNKNOWN",
                     "unresolved marker physically modified or removed")
            return

        # Positive retired-only reclamation requires a still-live disposable
        # test service, so old test-only RETIRED proof isn't imported into
        # another process as if it were a production full-tree certificate.
        svc = _qualified_service(disposable)
        seed = getattr(svc, "_r1_stage_retired_in_active_fixture", None)
        if not callable(seed):
            pytest.fail("R1_RED_ACTIVE_STATE_STORE_SEAM_MISSING", pytrace=False)
        exact_bytes = case == "quota_exact_4096_records_16mib"
        for idx in range(4096):
            ident = "%032x" % (idx + 1)
            data = _make_valid_record(
                disposable, "RETIRED", attempt_id=ident,
                padding=4096 if exact_bytes else 0)
            if exact_bytes:
                _require(len(data) == 4096, "QUOTA_RECORD_SIZE_NOT_EXACT",
                         repr(len(data)))
            seed(data)  # must write to real private store, no summary accepted
        before = _on_disk_records(disposable.state_root)
        _require(len(before) == 4096, "QUOTA_FIXTURE_NOT_PHYSICAL",
                 repr(len(before)))
        w = _ExternalWitness(disposable.state_root,
                             "retired_prune_directory_fsync_failure"
                             if case == "retired_prune_directory_fsync_failure"
                             else None)
        with monkeypatch.context() as m:
            w.install(m)
            _attempt(svc)
        _require(all("UNKNOWN" != record["phase"] for _, record in before),
                 "QUOTA_BAD_FIXTURE", "nonretired record entered eligible pool")
        _require("state_unlink" in w.events,
                 "RETIRED_PRUNE_NEVER_EXECUTED", repr(w.events))
        last_unlink = max(i for i, event in enumerate(w.events)
                          if event == "state_unlink")
        _require("directory_fsync" in w.events[last_unlink + 1:],
                 "RETIRED_PRUNE_NOT_DURABLE", repr(w.events))
        if case == "retired_prune_directory_fsync_failure":
            _require(case in w.fired, "RETIRED_PRUNE_FAULT_NOT_INJECTED",
                     repr(w.events))
            _assert_quarantined(svc)
        else:
            _require(len(w.spawns) == 1, "QUOTA_RETIREMENT_NOT_ADMITTED",
                     repr(w.events))
            w.assert_fsynced_before_spawn()
        _require(len(_on_disk_records(disposable.state_root)) <= 4096,
                 "QUOTA_CAPACITY_EXCEEDED",
                 "actual on-disk state record count exceeded limit")
        return

    if case in ("grant_bound_to_other_service",
                "grant_invalidated_by_restart"):
        owner = _qualified_service(disposable)
        if case == "grant_invalidated_by_restart":
            owner.close()  # grant is destroyed even with an empty state root
            other = disposable.service()
        else:
            # Separate private owner root avoids conflating lost grant
            # with a correct rejection of a *contended owner lock*.
            foreign_root = disposable.config.parent / "foreign-control"
            foreign_root.mkdir(mode=0o700)
            other = WorkspaceService(
                disposable.settings(), config_dir=foreign_root,
                inventory=ActiveRuntimeInventory(paths=(disposable.runtime,)))
            disposable.services.append(other)
        w = _ExternalWitness(
            disposable.state_root if case == "grant_invalidated_by_restart"
            else foreign_root / "exec-state")
        with monkeypatch.context() as m:
            w.install(m)
            _must_deny(lambda: other.invoke_exec(
                "a", "src", ["python", "ok.py"], dry_run=False),
                "exec_cleanup_proof_required", "OTHER_SERVICE_GRANT_REUSED")
        _require(not w.spawns, "OTHER_SERVICE_SPAWNED", repr(w.events))
        return

    hooks = _LifecycleFaultHooks(case)
    svc = _qualified_service(
        disposable,
        granted_workspaces=("b",) if
        case == "grant_bound_to_other_workspace_inode" else ("a",),
        hooks=hooks,
    )
    fault = case if case in _PRESPAWN_FAULTS | {
        "ambiguous_popen_failure", "leader_wait_failure",
        "post_spawn_finalization_fsync_failure",
    } else None
    w = _ExternalWitness(disposable.state_root, fault)
    if case == "cancellation_during_final_state_fsync":
        result = []
        def run_worker():
            with monkeypatch.context() as m:
                w.install(m)
                result.append(_attempt(svc))
        worker = threading.Thread(target=run_worker, daemon=True)
        worker.start()
        try:
            _require(hooks.pause_entered.wait(4), "FINAL_FSYNC_PAUSE_NOT_REACHED",
                     repr(hooks.events))
            _must_deny(lambda: svc.invoke_exec(
                "a", "src", ["python", "ok.py"], dry_run=False),
                "busy", "FINALIZATION_LEASE_RELEASED_EARLY")
        finally:
            hooks.pause_release.set()
            worker.join(timeout=5)
        _require(not worker.is_alive() and len(w.spawns) == 1,
                 "FINALIZATION_LEASE_NOT_RELEASED", repr(w.events))
        w.assert_fsynced_before_spawn()
        return
    with monkeypatch.context() as m:
        w.install(m)
        _attempt(svc)

    if case in _GRANT_DENIALS:
        _require(not w.spawns, "MISBOUND_GRANT_SPAWNED", repr(w.events))
        _must_status(svc.info()["exec_policy"], "available", False,
                     "MISBOUND_GRANT_AVAILABLE")
        return

    if case in _PRESPAWN_FAULTS:
        _require(w.fired == [case], "PREFLIGHT_FAULT_NOT_INJECTED",
                 repr(w.events))
        _require(not w.spawns, "PREFLIGHT_STARTED_CHILD", repr(w.events))
        _require(svc.info()["exec_policy"].get("available") is False,
                 "PREFLIGHT_ADMISSION_OPEN", repr(svc.info()["exec_policy"]))
        return

    if case == "deadline_before_popen":
        _require(hooks.fired == ["before_popen"] and not w.spawns,
                 "PRESPAWN_DEADLINE_WAS_NOT_OBSERVED",
                 repr({"callbacks": hooks.events, "syscalls": w.events}))
        return

    if case in _POSTSPAWN_FAULTS:
        _require(len(w.spawns) == 1, "POSTSPAWN_NOT_REACHED", repr(w.events))
        w.assert_fsynced_before_spawn()
        _require(case in w.fired or
                 _LifecycleFaultHooks.EVENTS.get(case) in hooks.fired,
                 "POSTSPAWN_FAULT_NOT_FIRED",
                 repr({"syscalls": w.events, "callbacks": hooks.events}))
        w.assert_unknown_on_disk()
        _assert_quarantined(svc)
        svc.close()
        again = disposable.service()
        _assert_quarantined(again)
        return

    if case in _RESTART_SCENARIOS:
        # Start a fully valid fixture, inspect real bytes, close and boot.
        _require(len(w.spawns) in (0, 1), "UNEXPECTED_SPAWN_COUNT",
                 repr(w.spawns))
        if w.spawns:
            w.assert_fsynced_before_spawn()
        _require(hooks.fired == [
            _LifecycleFaultHooks.EVENTS[case]
        ], "RESTART_CRASH_WINDOW_NOT_INJECTED", repr(hooks.events))
        before = _on_disk_records(disposable.state_root)
        _require(bool(before), "RESTART_RECORD_NOT_PERSISTED", repr(w.events))
        svc.close()
        again = disposable.service()
        if case == "restart_after_retire_before_response":
            _require(bool(_state_contains(disposable.state_root, {"RETIRED"})),
                     "RETIRED_NOT_DURABLE", repr(before))
            _assert_quarantined(again)  # prior test-only scope is NOT a grant
            _require(not hasattr(again, "_r1_contract_probe"),
                     "REPLAY_SIDE_CHANNEL", "product exposed test probe")
        else:
            _assert_quarantined(again)
            _require(bool(_state_contains(
                disposable.state_root, {"PREPARED", "RUNNING", "UNKNOWN"})),
                "RESTART_ERASED_UNRESOLVED", repr(before))
        return

    if case == "valid_internal_test_grant_group_retirement":
        _require(len(w.spawns) == 1, "QUALIFIED_TEST_DID_NOT_RUN",
                 repr(w.events))
        w.assert_fsynced_before_spawn()
        records = _state_contains(disposable.state_root, {"RETIRED"})
        _require(any(obj.get("cleanup_scope") == "original_group_only" and
                     obj.get("full_descendant_tree_clean") == "not_proven"
                     for _, obj in records),
                 "TEST_GROUP_PROOF_MISSING", repr(records))
        _require(svc.info()["exec_policy"].get("quarantined") is False,
                 "QUALIFIED_TEST_INCORRECT_QUARANTINE",
                 repr(svc.info()["exec_policy"]))
        return

    pytest.fail("R1_TEST_INFRA_UNCLASSIFIED_CASE: " + case, pytrace=False)


def test_unrelated_git_authority_not_inferred(disposable):
    svc = disposable.service()
    assert svc.info()["git_policy"]["enabled"] is False
    assert svc.info()["exec_policy"]["enabled"] is True
    with pytest.raises(GatewayError) as exc:
        svc.invoke_git("a", "status")
    assert exc.value.code == "git_disabled"


def test_no_remote_unquarantine_route(disposable):
    svc = disposable.service()
    with TestClient(create_multi_app(svc, enable_mcp=False),
                    base_url="http://127.0.0.1:8765") as client:
        for route in ("/exec/reset", "/exec/unquarantine"):
            assert client.post(route, json={}).status_code == 404
