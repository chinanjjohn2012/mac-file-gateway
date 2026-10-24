"""R2-T02-B1-B1-A: independently staged ordinary no-proof Default DENY RED.

This non-default-collected contract runs only via the strict B1-B1 RED
verifier. A successful verifier means **missing product functionality**.
No actual subprocess, signals, native C, user Workspace or Tunnel are run.
A separate later B1-B1 Worker migration MUST preserve all original real
Exec acceptance tests, never rewrite/skip them to make a green report.
"""
from __future__ import annotations

import asyncio
import builtins
import io
import json
import os
from pathlib import Path
import signal
import stat
import subprocess

import pytest
from starlette.testclient import TestClient

from gateway.core import GatewayError
from gateway.exec_state import ExecStateStore
from gateway.http_multi import create_multi_app
from gateway.workspaces import WorkspaceService, ActiveRuntimeInventory
from gateway.workspaces_config import parse_workspace_config

RPC_HEADERS = {"Accept": "application/json, text/event-stream",
               "Content-Type": "application/json"}
APPLY = {"workspace": "a", "cwd": "src",
         "argv": ["python", "probe.py"], "dry_run": False}


class _HostGuard:
    """Protect the ENTIRE test lifetime, including startup and teardown.

    Test-owned Python-level witness, not a kernel process sandbox. We do not
    run commands or signal OS PIDs; all future accidental attempts fail.
    """
    def __init__(self):
        self.attempts = []

    def _ban(self, name):
        def stop(*args, **kwargs):
            self.attempts.append(name)
            raise AssertionError("B1B1_FORBIDDEN_HOST_ACTION:" + name)
        return stop

    def install(self, patch):
        base = subprocess.Popen
        guard = self
        class _ForbiddenPopen(base):
            # MCP SDK uses Popen[bytes] at import time, preserve type.
            def __new__(cls, *args, **kwargs):
                return guard._ban("Popen")(*args, **kwargs)
        patch.setattr(subprocess, "Popen", _ForbiddenPopen)
        for name in (
            "kill", "killpg", "fork", "forkpty", "posix_spawn",
            "posix_spawnp", "system", "spawnl", "spawnle", "spawnlp",
            "spawnlpe", "spawnv", "spawnve", "spawnvp", "spawnvpe",
            "execl", "execle", "execlp", "execlpe", "execv", "execve",
            "execvp", "execvpe",
        ):
            if hasattr(os, name):
                patch.setattr(os, name, self._ban("os." + name))
        for name in ("pthread_kill", "raise_signal"):
            if hasattr(signal, name):
                patch.setattr(signal, name, self._ban("signal." + name))
        for name in ("create_subprocess_exec", "create_subprocess_shell"):
            if hasattr(asyncio, name):
                patch.setattr(asyncio, name, self._ban("asyncio." + name))


@pytest.fixture(autouse=True)
def _host_isolation(monkeypatch):
    guard = _HostGuard()
    guard.install(monkeypatch)
    try:
        yield
    finally:
        if guard.attempts:
            pytest.fail("B1B1_UNEXPECTED_HOST_PROCESS_OR_SIGNAL:" +
                        repr(guard.attempts), pytrace=False)


class _Scene:
    def __init__(self, tmp: Path, *, global_exec=True, workspace_exec=True):
        projects = tmp / "projects"
        projects.mkdir()
        self.a, self.b = projects / "a", projects / "b"
        self.a.mkdir()
        self.b.mkdir()
        (self.a / "src").mkdir()
        (self.a / "src" / "probe.py").write_text("print('NEVER RUN')\n")
        (self.b / "public.txt").write_text("file-access-survives\n")
        self.config = tmp / "config"
        self.config.mkdir(mode=0o700)
        self.runtime = tmp / "trusted-runtime"
        self.runtime.mkdir()
        self.state = self.config / "exec-state"
        self.settings = parse_workspace_config({
            "schema_version": 1,
            "server": {"exec": {"enabled": global_exec}},
            "workspaces": {
                "a": {"root": str(self.a), "exec": {
                    "enabled": workspace_exec,
                    "paths": ["src"] if workspace_exec else [],
                    "runners": ["src=direct"] if workspace_exec else [],
                }},
                "b": {"root": str(self.b)},
            },
        })
        self.services = []

    def service(self):
        svc = WorkspaceService(
            self.settings, config_dir=self.config,
            inventory=ActiveRuntimeInventory(paths=(self.runtime,)))
        self.services.append(svc)
        return svc

    def close(self):
        for svc in reversed(self.services):
            svc.close()


@pytest.fixture
def scene(tmp_path):
    x = _Scene(tmp_path)
    try:
        yield x
    finally:
        x.close()


def _require(predicate, marker, data):
    if not predicate:
        pytest.fail("B1B1_RED_" + marker + ": " + repr(data)[:450],
                    pytrace=False)



# D0 §6 permits ONLY this small, stable, public exec_policy surface.
# No PID, argv, environment, root/state path, internal test-grant object,
# or arbitrary user/diagnostic payload may be nested in an extra field.
_PUBLIC_POLICY_WARNING = (
    "Exec runs project code with the Gateway OS user's privileges; "
    "path scopes are not an OS sandbox."
)
_PUBLIC_POLICY_KEYS = frozenset({
    "enabled", "available", "adapter_exposed", "durability_state",
    "quarantined", "quarantine_reason_code", "completion_capability",
    "max_concurrent_per_workspace", "max_concurrent_total",
    "dry_run_default", "warning",
})
_PUBLIC_DURABILITY = {"disabled", "healthy", "quarantined", "unavailable"}
_PUBLIC_CAPABILITY = {"none", "test_original_group_only", "full_tree_qualified"}
_PUBLIC_REASON = {
    None, "cleanup_unknown", "corrupt_record", "owner_lock_unavailable",
    "state_io_unavailable",
}


def _public_policy_is_sanitized(policy):
    """Strict schema, types and enums: not a two-substring blacklist."""
    if type(policy) is not dict or set(policy) != _PUBLIC_POLICY_KEYS:
        return False
    if any(type(policy[k]) is not bool for k in (
            "enabled", "available", "adapter_exposed", "quarantined",
            "dry_run_default")):
        return False
    if any(type(policy[k]) is not int for k in (
            "max_concurrent_per_workspace", "max_concurrent_total")):
        return False
    if (policy["max_concurrent_per_workspace"] != 1
            or policy["max_concurrent_total"] != 4
            or policy["dry_run_default"] is not True
            or type(policy["warning"]) is not str
            or policy["warning"] != _PUBLIC_POLICY_WARNING):
        return False
    if (type(policy["durability_state"]) is not str
            or policy["durability_state"] not in _PUBLIC_DURABILITY):
        return False
    if (type(policy["completion_capability"]) is not str
            or policy["completion_capability"] not in _PUBLIC_CAPABILITY):
        return False
    reason = policy["quarantine_reason_code"]
    if reason is not None and type(reason) is not str:
        return False
    if reason not in _PUBLIC_REASON:
        return False
    state = policy["durability_state"]
    if state in ("healthy", "disabled") and reason is not None:
        return False
    if state == "healthy" and policy["quarantined"] is not False:
        return False
    if state in ("quarantined", "unavailable") and policy["available"] is not False:
        return False
    return True


def _run(svc, *, dry_run=False):
    try:
        value = svc.invoke_exec("a", "src", ["python", "probe.py"],
                                dry_run=dry_run)
        return "returned", value
    except GatewayError as exc:
        return exc.code, None


def _runner_spy(svc, monkeypatch):
    calls = []
    def fake(*args, **kwargs):
        calls.append((args, kwargs))
        return {"executed": True, "exit_code": 0, "timed_out": False,
                "stdout": "UNAUTHORIZED", "stderr": "", "dry_run": False}
    monkeypatch.setattr(svc.get("a").gateway, "run_command", fake)
    return calls


def _records(scene):
    """Snapshot ALL physical state directory entries without following links.

    Include non-regular entries, inode/link metadata and ordinary file bytes;
    absence of a newly created symlink/unknown entry must never be inferred
    from a regular-file-only listing. Read regular files through NOFOLLOW FDs.
    """
    if not scene.state.is_dir():
        return {}
    root_fd = os.open(scene.state, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        result = {}
        for name in os.listdir(root_fd):
            st = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
            identity = (st.st_mode, st.st_dev, st.st_ino,
                        st.st_nlink, st.st_size)
            if not stat.S_ISREG(st.st_mode):
                result[name] = ("nonregular", identity)
                continue
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=root_fd)
            try:
                opened = os.fstat(fd)
                if (opened.st_dev, opened.st_ino) != (st.st_dev, st.st_ino):
                    raise AssertionError("B1B1_STATE_SNAPSHOT_IDENTITY_CHANGED")
                chunks = []
                while True:
                    part = os.read(fd, 65536)
                    if not part:
                        break
                    chunks.append(part)
                result[name] = ("regular", identity, b"".join(chunks))
            finally:
                os.close(fd)
        return result
    finally:
        os.close(root_fd)


class _IntentWitness:
    """Watch both store APIs and intermediate physical state mutations.

    A broken Worker cannot hide 'write PREPARED then unlink' just by making
    before/after disk snapshots look identical. Install *after boot*, when
    ExecStateStore has legitimately initialized owner.lock.
    """
    def __init__(self, root: Path):
        self.root = os.path.abspath(os.fspath(root))
        self.events = []
        # Pin physical root identity, not a mutable pathname string.
        pinned = os.stat(self.root, follow_symlinks=False)
        if not stat.S_ISDIR(pinned.st_mode):
            raise AssertionError("B1B1_STATE_ROOT_NOT_DIRECTORY")
        self.root_identity = (pinned.st_dev, pinned.st_ino)

    def _same_root(self, st):
        return (st.st_dev, st.st_ino) == self.root_identity

    def _root_is_pinned(self):
        try:
            return self._same_root(os.stat(self.root, follow_symlinks=False))
        except (OSError, ValueError, TypeError):
            return False

    def _root_entry(self, path, dir_fd=None):
        """Detect a rename/replace of the root directory entry itself."""
        if not isinstance(path, (str, bytes, os.PathLike)):
            return False
        try:
            value = os.fsdecode(os.fspath(path))
            if os.path.isabs(value) or dir_fd is None:
                absolute = os.path.abspath(value)
                if absolute == self.root:
                    return True  # catches restoration after an intermediate move
                actual = os.stat(absolute, follow_symlinks=False)
            else:
                actual = os.stat(value, dir_fd=dir_fd,
                                 follow_symlinks=False)
            return self._same_root(actual)
        except (OSError, ValueError, TypeError):
            return False

    @staticmethod
    def _attempt(path):
        if not isinstance(path, (str, bytes, os.PathLike)):
            return False
        name = os.path.basename(os.fsdecode(os.fspath(path)))
        return (name.startswith("r-") and name.endswith(".json")
                or name.startswith("temp-") and name.endswith(".tmp"))

    def _matches(self, path, dir_fd=None):
        """Check actual parent dev/ino, also for nested dir_fd paths.

        The supplied dir_fd may be the config PARENT, not the state root:
        'exec-state/r-X.json' must compare stat('exec-state',dir_fd=fd),
        NOT fstat(fd). A directory symlink alias resolves to the same inode.
        Do not follow a symlink in the final record filename.
        """
        if not self._attempt(path):
            return False
        try:
            value = os.fsdecode(os.fspath(path))
            parent = os.path.dirname(value)
            if dir_fd is not None and not os.path.isabs(value):
                parent_stat = (os.fstat(dir_fd) if not parent
                               else os.stat(parent, dir_fd=dir_fd))
            else:
                parent_stat = os.stat(os.path.realpath(parent or "."))
            return self._same_root(parent_stat)
        except (OSError, ValueError, TypeError):
            # Ambiguous/unstatable attempted record is not a clean refusal.
            self.events.append("attempt_parent_identity_unavailable")
            return True

    def install(self, patch):
        real_prepare = ExecStateStore.prepare
        real_atomic = ExecStateStore._atomic_write
        real_open = os.open
        real_io_open = io.open
        real_builtin_open = builtins.open
        real_remove = os.remove
        real_link = os.link
        real_symlink = os.symlink
        real_replace = os.replace
        real_rename = os.rename
        real_unlink = os.unlink
        witness = self

        def prepare(store, *args, **kwargs):
            witness.events.append("prepare")
            return real_prepare(store, *args, **kwargs)
        def atomic(store, path, payload):
            if witness._matches(path, store._fd):
                witness.events.append("atomic_write")
            return real_atomic(store, path, payload)
        def open_write(path, flags, *args, **kwargs):
            if (flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC)
                    and witness._matches(path, kwargs.get("dir_fd"))):
                witness.events.append("open_write")
            return real_open(path, flags, *args, **kwargs)
        def file_open(real, event):
            def watched(path, mode="r", *args, **kwargs):
                # pathlib.Path.open/write_bytes use io.open, not os.open.
                # '+' covers read/write update modes as well as w/a/x.
                if (isinstance(mode, str)
                        and any(char in mode for char in ("w", "a", "x", "+"))
                        and witness._matches(path)):
                    witness.events.append(event)
                return real(path, mode, *args, **kwargs)
            return watched
        def replace(src, dst, *args, **kwargs):
            if (witness._root_entry(src, kwargs.get("src_dir_fd"))
                    or witness._root_entry(dst, kwargs.get("dst_dir_fd"))):
                witness.events.append("root_replace")
            # Moving a record OUT also mutates the pinned state directory.
            if witness._matches(src, kwargs.get("src_dir_fd")):
                witness.events.append("replace_src")
            if witness._matches(dst, kwargs.get("dst_dir_fd")):
                witness.events.append("replace")
            return real_replace(src, dst, *args, **kwargs)
        def rename(src, dst, *args, **kwargs):
            if (witness._root_entry(src, kwargs.get("src_dir_fd"))
                    or witness._root_entry(dst, kwargs.get("dst_dir_fd"))):
                witness.events.append("root_rename")
            if witness._matches(src, kwargs.get("src_dir_fd")):
                witness.events.append("rename_src")
            if witness._matches(dst, kwargs.get("dst_dir_fd")):
                witness.events.append("rename")
            return real_rename(src, dst, *args, **kwargs)
        def link(src, dst, *args, **kwargs):
            if witness._matches(src, kwargs.get("src_dir_fd")):
                witness.events.append("link_src")
            if witness._matches(dst, kwargs.get("dst_dir_fd")):
                witness.events.append("link_dst")
            return real_link(src, dst, *args, **kwargs)
        def symlink(target, link_name, *args, **kwargs):
            if witness._matches(link_name, kwargs.get("dir_fd")):
                witness.events.append("symlink")
            return real_symlink(target, link_name, *args, **kwargs)
        def unlink(path, *args, **kwargs):
            if witness._matches(path, kwargs.get("dir_fd")):
                witness.events.append("unlink")
            return real_unlink(path, *args, **kwargs)
        def remove(path, *args, **kwargs):
            # os.remove is a distinct attribute; patching unlink is not enough.
            if witness._matches(path, kwargs.get("dir_fd")):
                witness.events.append("remove")
            return real_remove(path, *args, **kwargs)

        patch.setattr(ExecStateStore, "prepare", prepare)
        patch.setattr(ExecStateStore, "_atomic_write", atomic)
        patch.setattr(os, "open", open_write)
        patch.setattr(io, "open", file_open(real_io_open, "io_open_write"))
        patch.setattr(builtins, "open",
                      file_open(real_builtin_open, "builtins_open_write"))
        patch.setattr(os, "replace", replace)
        patch.setattr(os, "rename", rename)
        patch.setattr(os, "link", link)
        patch.setattr(os, "symlink", symlink)
        patch.setattr(os, "unlink", unlink)
        patch.setattr(os, "remove", remove)


def _never_started(scene, witness, before, calls):
    return (not calls and not witness.events and witness._root_is_pinned()
            and _records(scene) == before)


def test_b1b1_normal_direct_apply_denies_before_any_intent(scene, monkeypatch):
    svc = scene.service()
    calls = _runner_spy(svc, monkeypatch)
    witness = _IntentWitness(scene.state)
    with monkeypatch.context() as p:
        witness.install(p)
        before = _records(scene)
        code, value = _run(svc)
        clean = _never_started(scene, witness, before, calls)
    _require(code == "exec_cleanup_proof_required" and value is None and clean,
             "DEFAULT_DIRECT",
             {"code": code, "runner_calls": len(calls),
              "intent_events": witness.events, "unchanged": _records(scene) == before})


def test_b1b1_normal_rest_apply_503_denied_before_any_intent(scene, monkeypatch):
    svc = scene.service()
    calls = _runner_spy(svc, monkeypatch)
    witness = _IntentWitness(scene.state)
    with monkeypatch.context() as p:
        witness.install(p)
        before = _records(scene)
        with TestClient(create_multi_app(svc, enable_mcp=False),
                        base_url="http://127.0.0.1:8765") as client:
            response = client.post("/run", json=APPLY)
        clean = _never_started(scene, witness, before, calls)
    _require(response.status_code == 503 and
             response.json() == {"error": "exec_cleanup_proof_required"} and
             clean, "DEFAULT_REST",
             {"status": response.status_code, "body": response.text[:135],
              "calls": len(calls), "intent_events": witness.events,
              "unchanged": _records(scene) == before})


def test_b1b1_normal_mcp_apply_structured_proof_error(scene, monkeypatch):
    pytest.importorskip("mcp")
    svc = scene.service()
    calls = _runner_spy(svc, monkeypatch)
    witness = _IntentWitness(scene.state)
    with monkeypatch.context() as p:
        witness.install(p)
        before = _records(scene)
        with TestClient(create_multi_app(svc),
                        base_url="http://127.0.0.1:8765") as client:
            initial = client.post("/mcp", headers=RPC_HEADERS, json={
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2025-11-25",
                           "capabilities": {},
                           "clientInfo": {"name": "b1b1-red", "version": "1"}}})
            assert initial.status_code == 200 and "result" in initial.json()
            client.post("/mcp", headers=RPC_HEADERS, json={
                "jsonrpc": "2.0", "method": "notifications/initialized"})
            response = client.post("/mcp", headers=RPC_HEADERS, json={
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "run_command", "arguments": APPLY}})
        clean = _never_started(scene, witness, before, calls)
    result = response.json().get("result", {}) if response.status_code == 200 else {}
    structured = result.get("structuredContent") or {}
    _require(response.status_code == 200 and
             result.get("isError") is True and
             structured.get("error") == "exec_cleanup_proof_required" and clean,
             "DEFAULT_MCP", {"http": response.status_code,
                             "result": repr(result)[:180], "calls": len(calls),
                             "intent_events": witness.events})


def test_b1b1_info_health_report_same_unavailable_proof_policy(scene):
    svc = scene.service()
    with TestClient(create_multi_app(svc, enable_mcp=False),
                    base_url="http://127.0.0.1:8765") as client:
        info = client.get("/info")
        health = client.get("/health")
    policy = info.json().get("exec_policy", {})
    health_policy = health.json().get("exec_policy")
    _require(info.status_code == 200 and health.status_code == 200 and
             policy == health_policy and
             _public_policy_is_sanitized(policy) and
             policy.get("enabled") is True and
             policy.get("adapter_exposed") is True and
             policy.get("available") is False and
             policy.get("quarantined") is False and
             policy.get("durability_state") == "healthy" and
             policy.get("quarantine_reason_code") is None and
             policy.get("completion_capability") == "none",
             "POLICY_PARITY",
             # Do not echo sensitive raw values into the CI log when a
             # broken product adds an untrusted status field.
             {"info_status": info.status_code, "health_status": health.status_code,
              "same": policy == health_policy, "sanitized": _public_policy_is_sanitized(policy),
              "available": policy.get("available"),
              "completion_capability": policy.get("completion_capability")})


def test_b1b1_missing_proof_precedes_worker_busy_slot(scene, monkeypatch):
    svc = scene.service()
    calls = _runner_spy(svc, monkeypatch)
    witness = _IntentWitness(scene.state)
    svc._exec_active.add("a")  # held slot, test-owned and released below
    try:
        with monkeypatch.context() as patch:
            witness.install(patch)
            before = _records(scene)
            code, value = _run(svc)
            clean = _never_started(scene, witness, before, calls)
    finally:
        svc._exec_active.discard("a")
    _require(code == "exec_cleanup_proof_required" and
             value is None and clean, "PROOF_BEFORE_BUSY",
             {"code": code, "calls": len(calls),
              "intent_events": witness.events,
              "unchanged": _records(scene) == before})


@pytest.mark.parametrize("flag", ["GATEWAY_EXEC_TEST_GRANT", "GATEWAY_R1_TEST_ONLY"])
def test_b1b1_env_cannot_mint_cleanup_proof(scene, monkeypatch, flag):
    monkeypatch.setenv(flag, "true")
    svc = scene.service()
    calls = _runner_spy(svc, monkeypatch)
    witness = _IntentWitness(scene.state)
    with monkeypatch.context() as p:
        witness.install(p)
        before = _records(scene)
        code, value = _run(svc)
        clean = _never_started(scene, witness, before, calls)
    _require(code == "exec_cleanup_proof_required" and
             value is None and clean, "ENV_BYPASS",
             {"flag": flag, "code": code, "calls": len(calls),
              "intent_events": witness.events})


def test_b1b1_guard_ordinary_preview_remains_allowed(scene, monkeypatch):
    svc = scene.service()
    witness = _IntentWitness(scene.state)
    with monkeypatch.context() as patch:
        witness.install(patch)
        before = _records(scene)
        code, result = _run(svc, dry_run=True)
        clean = _never_started(scene, witness, before, [])
    assert code == "returned"
    assert result["dry_run"] is True and result["executed"] is False
    assert result["workspace"] == "a"
    assert result["runner"] == "direct"
    assert clean, witness.events


def test_b1b1_guard_global_off_precedes_proof(tmp_path):
    local = _Scene(tmp_path, global_exec=False, workspace_exec=False)
    try:
        svc = local.service()
        code, val = _run(svc)
        assert code == "exec_disabled" and val is None
    finally:
        local.close()


def test_b1b1_guard_file_read_independent_of_missing_exec_proof(scene):
    svc = scene.service()
    data = svc.invoke("b", "read_file", "public.txt", 1, 10)
    assert data["workspace"] == "b"
    assert data["path"] == "public.txt"


@pytest.mark.parametrize("bad_field", [
    "test_grant", "listener_host", "full_descendant_tree_clean",
    "test_mode", "group_only_test_grant", "_trusted_bound_listener",
    "transport",
])
def test_b1b1_guard_client_fields_cannot_select_private_proof(
        scene, monkeypatch, bad_field):
    svc = scene.service()
    calls = _runner_spy(svc, monkeypatch)
    # Adapter registration is a legitimate status change. Baseline AFTER
    # create_multi_app, before sending untrusted client proof input.
    app = create_multi_app(svc, enable_mcp=False)
    policy_before = svc.info()["exec_policy"]
    witness = _IntentWitness(scene.state)
    with monkeypatch.context() as patch:
        witness.install(patch)
        before = _records(scene)
        with TestClient(app,
                        base_url="http://127.0.0.1:8765") as client:
            response = client.post("/run", json={**APPLY, bad_field: True})
        clean = _never_started(scene, witness, before, calls)
    assert response.status_code == 400
    assert response.json().get("error") == "invalid_argument"
    assert clean, (bad_field, witness.events, len(calls))
    assert svc.info()["exec_policy"] == policy_before



def test_b1b1_guard_status_policy_oracle_rejects_private_metadata(scene):
    """Positive public schema plus hostile false-GREEN variants of D0 §6."""
    ordinary = {
        "enabled": True,
        "available": False,
        "adapter_exposed": True,
        "durability_state": "healthy",
        "quarantined": False,
        "quarantine_reason_code": None,
        "completion_capability": "none",
        "max_concurrent_per_workspace": 1,
        "max_concurrent_total": 4,
        "dry_run_default": True,
        "warning": _PUBLIC_POLICY_WARNING,
    }
    assert _public_policy_is_sanitized(ordinary)
    mutations = [
        {"pid": os.getpid()},
        {"argv": ["python", "probe.py", "--token=SYNTHETIC_ONLY"]},
        {"environment": {"SYNTHETIC_API_TOKEN": "synthetic-never-real"}},
        {"workspace_root": str(scene.a)},
        {"state_path": str(scene.state)},
        {"owner_lock_path": str(scene.state / "owner.lock")},
        {"TestOnlyGroupRetirementGrant": True},
        {"metadata": {"test_mode": True, "host": "127.0.0.1"}},
        {"warning": _PUBLIC_POLICY_WARNING + " root=" + str(scene.a)},
        {"max_concurrent_total": True},  # bool is an int subclass
        {"completion_capability": ["none"]},
        {"durability_state": "UNTRUSTED"},
        {"quarantine_reason_code": "SYNTHETIC_SECRET"},
    ]
    for mutation in mutations:
        assert not _public_policy_is_sanitized({**ordinary, **mutation}), (
            "Unsafe extra policy data or invalid public field accepted: " +
            repr(tuple(mutation)))
    assert not _public_policy_is_sanitized(
        {k: v for k, v in ordinary.items() if k != "completion_capability"})


def test_b1b1_guard_busy_intent_witness_detects_transient_write_delete(
        scene, monkeypatch):
    """Physical PREPARED->unlink in a held slot is NOT a clean busy refusal."""
    svc = scene.service()
    store = svc._exec_state
    assert store is not None and store.durability_state == "healthy"
    svc._exec_active.add("a")
    try:
        witness = _IntentWitness(scene.state)
        with monkeypatch.context() as patch:
            witness.install(patch)
            before = _records(scene)
            st = scene.a.stat()
            attempt = store.prepare("a", (st.st_dev, st.st_ino))
            os.unlink("r-" + attempt + ".json", dir_fd=store._fd)
            os.fsync(store._fd)
            assert _records(scene) == before
            assert not _never_started(scene, witness, before, [])
        assert "prepare" in witness.events
        assert any(event in witness.events for event in
                   ("atomic_write", "open_write", "replace"))
        assert "unlink" in witness.events
    finally:
        svc._exec_active.discard("a")


@pytest.mark.parametrize("bad_field", [
    "test_mode", "test_grant", "group_only_test_grant",
    "_trusted_bound_listener", "listener_host",
])
def test_b1b1_guard_mcp_arguments_cannot_mint_private_proof(
        scene, monkeypatch, bad_field):
    """Actual SDK MCP tools/call, not just a copied REST validation result."""
    pytest.importorskip("mcp")
    svc = scene.service()
    calls = _runner_spy(svc, monkeypatch)
    # Adapter registration is a legitimate status change. Baseline AFTER
    # create_multi_app, before sending untrusted client proof input.
    app = create_multi_app(svc)
    policy_before = svc.info()["exec_policy"]
    witness = _IntentWitness(scene.state)
    with monkeypatch.context() as patch:
        witness.install(patch)
        before = _records(scene)
        with TestClient(app,
                        base_url="http://127.0.0.1:8765") as client:
            init = client.post("/mcp", headers=RPC_HEADERS, json={
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2025-11-25",
                           "capabilities": {},
                           "clientInfo": {"name": "b1b1-spoof", "version": "1"}}})
            assert init.status_code == 200 and "result" in init.json()
            client.post("/mcp", headers=RPC_HEADERS, json={
                "jsonrpc": "2.0", "method": "notifications/initialized"})
            response = client.post("/mcp", headers=RPC_HEADERS, json={
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "run_command",
                           "arguments": {**APPLY, bad_field: True}}})
        clean = _never_started(scene, witness, before, calls)
    result = response.json().get("result", {}) if response.status_code == 200 else {}
    assert response.status_code == 200
    assert result.get("isError") is True, (bad_field, result)
    assert "invalid_argument" in json.dumps(result), bad_field
    assert clean, (bad_field, witness.events, len(calls))
    assert svc.info()["exec_policy"] == policy_before


@pytest.mark.parametrize("header", [
    "x-gateway-test-mode", "x-internal-group-retirement-grant",
])
def test_b1b1_rest_header_cannot_mint_cleanup_proof(
        scene, monkeypatch, header):
    """Synthetic request metadata must not override ordinary default DENY."""
    svc = scene.service()
    calls = _runner_spy(svc, monkeypatch)
    # Adapter registration is a legitimate status change. Baseline AFTER
    # create_multi_app, before sending untrusted client proof input.
    app = create_multi_app(svc, enable_mcp=False)
    policy_before = svc.info()["exec_policy"]
    witness = _IntentWitness(scene.state)
    with monkeypatch.context() as patch:
        witness.install(patch)
        before = _records(scene)
        with TestClient(app,
                        base_url="http://127.0.0.1:8765") as client:
            response = client.post("/run", json=APPLY,
                                   headers={header: "true"})
        clean = _never_started(scene, witness, before, calls)
    _require(response.status_code == 503 and
             response.json() == {"error": "exec_cleanup_proof_required"} and
             clean and svc.info()["exec_policy"] == policy_before,
             "REST_HEADER_BYPASS",
             {"header": header, "status": response.status_code,
              "runner_calls": len(calls), "intent_events": witness.events})


@pytest.mark.parametrize("header", [
    "x-gateway-test-mode", "x-internal-group-retirement-grant",
])
def test_b1b1_mcp_header_cannot_mint_cleanup_proof(
        scene, monkeypatch, header):
    """MCP synthetic HTTP metadata is never a grant or cleanup-proof source."""
    pytest.importorskip("mcp")
    svc = scene.service()
    calls = _runner_spy(svc, monkeypatch)
    # Adapter registration is a legitimate status change. Baseline AFTER
    # create_multi_app, before sending untrusted client proof input.
    app = create_multi_app(svc)
    policy_before = svc.info()["exec_policy"]
    witness = _IntentWitness(scene.state)
    with monkeypatch.context() as patch:
        witness.install(patch)
        before = _records(scene)
        headers = {**RPC_HEADERS, header: "true"}
        with TestClient(app,
                        base_url="http://127.0.0.1:8765") as client:
            init = client.post("/mcp", headers=headers, json={
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2025-11-25",
                           "capabilities": {},
                           "clientInfo": {"name": "b1b1-header", "version": "1"}}})
            assert init.status_code == 200 and "result" in init.json()
            client.post("/mcp", headers=headers, json={
                "jsonrpc": "2.0", "method": "notifications/initialized"})
            response = client.post("/mcp", headers=headers, json={
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "run_command", "arguments": APPLY}})
        clean = _never_started(scene, witness, before, calls)
    result = response.json().get("result", {}) if response.status_code == 200 else {}
    _require(response.status_code == 200 and
             result.get("isError") is True and
             (result.get("structuredContent") or {}).get("error") ==
             "exec_cleanup_proof_required" and
             clean and svc.info()["exec_policy"] == policy_before,
             "MCP_HEADER_BYPASS",
             {"header": header, "status": response.status_code,
              "is_error": result.get("isError"),
              "runner_calls": len(calls), "intent_events": witness.events})


def test_b1b1_guard_transient_intent_witness_rejects_write_then_delete(
        scene, monkeypatch):
    """Infrastructure counterexample, not a product success.

    A *real* PREPARED record is written/fsynced and unlinked/fsynced.
    Final on-disk bytes are identical: a snapshot-only test would lie.
    """
    store = ExecStateStore(scene.state,
                           workspace_roots=(str(scene.a), str(scene.b)))
    try:
        assert store.durability_state == "healthy"
        witness = _IntentWitness(scene.state)
        with monkeypatch.context() as p:
            witness.install(p)
            before = _records(scene)
            st = scene.a.stat()
            attempt = store.prepare("a", (st.st_dev, st.st_ino))
            os.unlink("r-" + attempt + ".json", dir_fd=store._fd)
            os.fsync(store._fd)
            after = _records(scene)
        assert before == after
        assert "prepare" in witness.events
        assert any(x in witness.events for x in ("atomic_write", "open_write"))
        assert "unlink" in witness.events
        assert not _never_started(scene, witness, before, [])
    finally:
        store.close()


@pytest.mark.parametrize("write_api", [
    "path.open", "path.write_bytes", "builtins.open",
])
def test_b1b1_guard_python_file_io_detects_transient_prepared(
        scene, monkeypatch, write_api):
    """Physical PREPARED write, fsync, os.remove, dir-fsync must not look clean.

    Negative oracle for Python IO that bypasses os.open/os.unlink patches:
    the final state snapshot is unchanged, but BOTH write and remove events
    must be witnessed. No product Worker or host subprocess is run.
    """
    svc = scene.service()  # real owner.lock boot occurs before interception
    assert svc._exec_state is not None
    assert svc._exec_state.durability_state == "healthy"
    record = scene.state / ("r-" + "7" * 32 + ".json")
    assert not record.exists()
    witness = _IntentWitness(scene.state)
    with monkeypatch.context() as patch:
        witness.install(patch)
        before = _records(scene)
        payload = b'{"state":"PREPARED"}'
        if write_api == "path.write_bytes":
            assert record.write_bytes(payload) == len(payload)
            with record.open("rb") as stream:
                os.fsync(stream.fileno())
        else:
            opener = record.open if write_api == "path.open" else (
                lambda mode: open(record, mode))
            with opener("wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
        os.remove(record)
        parent_fd = os.open(scene.state, os.O_RDONLY)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
        after = _records(scene)
        incorrectly_clean = _never_started(scene, witness, before, [])
    assert after == before
    assert not record.exists()
    assert not incorrectly_clean
    expected_write_event = ("builtins_open_write"
                            if write_api == "builtins.open" else "io_open_write")
    assert expected_write_event in witness.events, (write_api, witness.events)
    assert "remove" in witness.events, (write_api, witness.events)


def test_b1b1_guard_physical_alias_intent_cannot_look_clean(
        scene, monkeypatch):
    """Write+remove by symlink alias into the SAME physical state directory."""
    svc = scene.service()
    store = svc._exec_state
    assert store is not None and store.durability_state == "healthy"
    alias = scene.config / "exec-state-alias"
    alias.symlink_to(scene.state, target_is_directory=True)
    assert (alias.stat().st_dev, alias.stat().st_ino) == (
        scene.state.stat().st_dev, scene.state.stat().st_ino)
    record = alias / ("r-" + "8" * 32 + ".json")
    witness = _IntentWitness(scene.state)
    with monkeypatch.context() as patch:
        witness.install(patch)
        before = _records(scene)
        with record.open("wb") as stream:
            stream.write(b'{"state":"PREPARED"}')
            stream.flush()
            os.fsync(stream.fileno())
        os.remove(record)
        os.fsync(store._fd)
        after = _records(scene)
        clean = _never_started(scene, witness, before, [])
    assert after == before and not record.exists()
    assert not clean
    assert "io_open_write" in witness.events, witness.events
    assert "remove" in witness.events, witness.events


def test_b1b1_guard_moved_root_pinned_fd_intent_cannot_look_clean(
        scene, monkeypatch):
    """Retained FD still points to pinned root after its pathname moves."""
    svc = scene.service()
    store = svc._exec_state
    assert store is not None and store.durability_state == "healthy"
    moved = scene.config / "moved-state-dir"
    name = "r-" + "9" * 32 + ".json"
    witness = _IntentWitness(scene.state)
    with monkeypatch.context() as patch:
        witness.install(patch)
        before = _records(scene)
        os.rename(scene.state, moved)
        try:
            assert not witness._root_is_pinned()
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                         0o600, dir_fd=store._fd)
            try:
                os.write(fd, b'{"state":"PREPARED"}')
                os.fsync(fd)
            finally:
                os.close(fd)
            os.unlink(name, dir_fd=store._fd)
            os.fsync(store._fd)
        finally:
            os.rename(moved, scene.state)
        after = _records(scene)
        clean = _never_started(scene, witness, before, [])
    assert after == before and not (scene.state / name).exists()
    assert not clean
    assert "root_rename" in witness.events, witness.events
    assert "open_write" in witness.events, witness.events
    assert "unlink" in witness.events, witness.events


def test_b1b1_guard_root_rename_roundtrip_alone_is_not_zero_intent(
        scene, monkeypatch):
    """Restoring the same snapshot cannot erase a physical root move."""
    svc = scene.service()
    assert svc._exec_state is not None
    moved = scene.config / "moved-state-no-record"
    witness = _IntentWitness(scene.state)
    with monkeypatch.context() as patch:
        witness.install(patch)
        before = _records(scene)
        os.rename(scene.state, moved)
        try:
            assert not witness._root_is_pinned()
        finally:
            os.rename(moved, scene.state)
        clean = _never_started(scene, witness, before, [])
        assert _records(scene) == before
    assert not clean
    assert witness.events.count("root_rename") >= 2, witness.events


@pytest.mark.parametrize("prefix", ["exec-state", "state-alias"])
def test_b1b1_guard_nested_config_fd_record_write_delete(
        scene, monkeypatch, prefix):
    """Relative multi-component paths via parent dir_fd target same root."""
    svc = scene.service()
    store = svc._exec_state
    assert store is not None and store.durability_state == "healthy"
    if prefix == "state-alias":
        (scene.config / prefix).symlink_to(scene.state,
                                           target_is_directory=True)
    relative = prefix + "/r-" + "a" * 32 + ".json"
    config_fd = os.open(scene.config, os.O_RDONLY | os.O_DIRECTORY)
    witness = _IntentWitness(scene.state)
    try:
        with monkeypatch.context() as patch:
            witness.install(patch)
            before = _records(scene)
            assert witness._same_root(os.stat(prefix, dir_fd=config_fd))
            fd = os.open(relative, os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                         0o600, dir_fd=config_fd)
            try:
                os.write(fd, b'{"state":"PREPARED"}')
                os.fsync(fd)
            finally:
                os.close(fd)
            os.unlink(relative, dir_fd=config_fd)
            os.fsync(store._fd)
            after = _records(scene)
            clean = _never_started(scene, witness, before, [])
        assert after == before and not (scene.state / relative.split("/")[-1]).exists()
        assert not clean
        assert "open_write" in witness.events, witness.events
        assert "unlink" in witness.events, witness.events
    finally:
        os.close(config_fd)


@pytest.mark.parametrize("method", ["rename", "replace"])
def test_b1b1_guard_hardlinked_prepared_moved_out(
        scene, monkeypatch, method):
    """Durable hardlink into state, then move record OUT: source must count."""
    svc = scene.service()
    store = svc._exec_state
    assert store is not None and store.durability_state == "healthy"
    external = scene.config / ("external-prepared-" + method + ".json")
    external.write_bytes(b'{"state":"PREPARED"}')
    record = scene.state / ("r-" + "b" * 32 + ".json")
    archived = scene.config / ("archived-" + method + ".json")
    witness = _IntentWitness(scene.state)
    with monkeypatch.context() as patch:
        witness.install(patch)
        before = _records(scene)
        os.link(external, record)
        assert record.stat().st_nlink == 2
        os.fsync(store._fd)
        getattr(os, method)(record, archived)
        os.fsync(store._fd)
        after = _records(scene)
        clean = _never_started(scene, witness, before, [])
    assert before == after and not record.exists() and archived.exists()
    assert not clean
    assert "link_dst" in witness.events, witness.events
    assert method + "_src" in witness.events, witness.events


@pytest.mark.parametrize("address", ["absolute", "pinned_fd"])
def test_b1b1_guard_illegal_symlink_record_visible_in_snapshot(
        scene, monkeypatch, address):
    """A symlink record is never invisible to the physical state snapshot."""
    svc = scene.service()
    store = svc._exec_state
    assert store is not None and store.durability_state == "healthy"
    external = scene.config / "external-symlink-PREPARED.json"
    external.write_bytes(b'{"state":"PREPARED"}')
    record = scene.state / ("r-" + "c" * 32 + ".json")
    witness = _IntentWitness(scene.state)
    try:
        with monkeypatch.context() as patch:
            witness.install(patch)
            before = _records(scene)
            if address == "absolute":
                os.symlink(external, record)
            else:
                os.symlink(external, record.name, dir_fd=store._fd)
            os.fsync(store._fd)
            after = _records(scene)
            clean = _never_started(scene, witness, before, [])
        assert record.is_symlink()
        assert record.name not in before
        assert after[record.name][0] == "nonregular"
        assert after != before and not clean
        assert "symlink" in witness.events, witness.events
    finally:
        if record.is_symlink():
            record.unlink()


def test_b1b1_guard_host_interceptor_is_type_preserving(monkeypatch):
    witness = _HostGuard()
    with monkeypatch.context() as p:
        witness.install(p)
        assert isinstance(subprocess.Popen, type)
        assert subprocess.Popen[bytes]
        with pytest.raises(AssertionError, match="B1B1_FORBIDDEN_HOST_ACTION"):
            subprocess.Popen(["python", "must-not-run.py"])
        with pytest.raises(AssertionError, match="B1B1_FORBIDDEN_HOST_ACTION"):
            os.killpg(os.getpgrp(), signal.SIGTERM)
    assert witness.attempts == ["Popen", "os.killpg"]
