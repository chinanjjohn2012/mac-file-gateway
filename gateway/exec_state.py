"""R2-T01 private durable Exec attempt store — deliberately NOT wired to Worker.

Persistent, owner-locked, fail-closed state *primitives* only. No process
creation, signals, group cleanup, test-only grant, or recovery/reset API.
Not yet an R2 end-to-end Exec implementation or full-descendant-tree proof.
"""
from __future__ import annotations

import fcntl
import json
import math
import os
from pathlib import Path
import re
import stat
import threading
import time
from typing import Any
from uuid import uuid4

from .core import GatewayError
from .private_fs import PrivateFileError, open_pinned_directory

_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_READ = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
_CREATE = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
_LOCK = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC
_ID = re.compile(r"[a-f0-9]{32}\Z")
_RECORD_NAME = re.compile(r"r-([a-f0-9]{32})\.json\Z")
_WORKSPACE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_FIELDS = frozenset({
    "schema_version", "attempt_id", "workspace", "workspace_dev",
    "workspace_ino", "phase", "created_at", "cleanup_scope",
    "full_descendant_tree_clean",
})
_PHASES = frozenset(("PREPARED", "RUNNING", "UNKNOWN", "RETIRED"))
_RECORD_MAX = 4096
_RECORD_COUNT_MAX = 4096
_PAYLOAD_MAX = 16 * 1024 * 1024
_LOCK_NAME = "owner.lock"


def _strict_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate Exec state field.")
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> None:
    raise ValueError("Non-finite Exec state value.")


def _strict_record(data: bytes, filename: str) -> dict[str, Any]:
    if not 0 < len(data) <= _RECORD_MAX:
        raise ValueError("Exec state record is empty or oversized.")
    match = _RECORD_NAME.fullmatch(filename)
    if match is None:
        raise ValueError("Invalid Exec state filename.")
    item = json.loads(data.decode("utf-8"), object_pairs_hook=_strict_pairs,
                      parse_constant=_reject_nonfinite)
    if type(item) is not dict or set(item) != _FIELDS:
        raise ValueError("Exec state record schema mismatch.")
    if type(item["schema_version"]) is not int or item["schema_version"] != 1:
        raise ValueError("Unexpected Exec state version.")
    if type(item["attempt_id"]) is not str or item["attempt_id"] != match[1]:
        raise ValueError("Exec record name/identity mismatch.")
    if type(item["workspace"]) is not str or not _WORKSPACE.fullmatch(item["workspace"]):
        raise ValueError("Invalid Workspace identity.")
    for field in ("workspace_dev", "workspace_ino"):
        if type(item[field]) is not int or item[field] < 0:
            raise ValueError("Invalid pinned Workspace identity.")
    if (type(item["created_at"]) not in (int, float) or
            not math.isfinite(item["created_at"]) or item["created_at"] < 0):
        raise ValueError("Invalid attempt timestamp.")
    if type(item["phase"]) is not str or item["phase"] not in _PHASES:
        raise ValueError("Invalid attempt phase.")
    if item["full_descendant_tree_clean"] != "not_proven":
        raise ValueError("Full tree cannot be certified by the Python store.")
    if item["cleanup_scope"] not in ("none", "original_group_only"):
        raise ValueError("Unknown cleanup evidence qualification.")
    if item["phase"] != "RETIRED" and item["cleanup_scope"] != "none":
        raise ValueError("Unresolved attempt cannot be marked group-clean.")
    if item["phase"] == "RETIRED" and item["cleanup_scope"] != "original_group_only":
        raise ValueError("Unqualified Exec retirement.")
    return item


def _encoded(record: dict[str, Any]) -> bytes:
    # Only the typed/whitelisted metadata is persisted; no argv/output/env.
    if set(record) != _FIELDS:
        raise ValueError("Unexpected fields in Exec attempt.")
    filename = "r-" + record["attempt_id"] + ".json"
    data = (json.dumps(record, sort_keys=True, separators=(",", ":"),
                       allow_nan=False, ensure_ascii=True) + "\n").encode("utf-8")
    _strict_record(data, filename)
    return data


class ExecStateStore:
    """Exclusive lifetime ownership of a pinned Gateway-private state root.

    The ordinary server must not use this store to bypass D0's default
    cleanup-proof DENY; T01 does not wire a WorkspaceService or grant factory.
    A store still holding unresolved in-memory PREPARED records is only a
    low-level durability primitive, not an admission/cleanup coordinator.
    """

    def __init__(self, state_dir: str | Path, *,
                 workspace_roots: tuple[str, ...] = ()) -> None:
        self._fd = -1
        self._lock_fd = -1
        self._gate = threading.RLock()
        self._pid = os.getpid()
        self._closed = False
        self._records: dict[str, dict[str, Any]] = {}
        self._payload_bytes = 0
        self._state = "unavailable"
        self._reason: str | None = "state_io_unavailable"
        try:
            raw = os.fspath(state_dir)
            if (type(raw) is not str or not raw.startswith("/") or
                    os.path.normpath(raw) != raw or raw.endswith("/") or
                    os.path.basename(raw) != "exec-state"):
                raise PrivateFileError("Invalid private Exec state location.")
            for root in workspace_roots:
                a, b = os.path.realpath(raw), os.path.realpath(root)
                if os.path.commonpath((a, b)) in (a, b):
                    raise PrivateFileError("Exec state intersects a Workspace.")
            parent = open_pinned_directory(os.path.dirname(raw), private_leaf=True)
            try:
                try:
                    os.mkdir("exec-state", 0o700, dir_fd=parent.fd)
                    os.fsync(parent.fd)
                except FileExistsError:
                    pass
                self._fd = os.open("exec-state", _DIR, dir_fd=parent.fd)
            finally:
                parent.close()
            st = os.fstat(self._fd)
            if (not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid()
                    or stat.S_IMODE(st.st_mode) != 0o700):
                raise PrivateFileError("Exec state root is not private.")
            self._lock_fd = os.open(_LOCK_NAME, _LOCK, 0o600, dir_fd=self._fd)
            lock = os.fstat(self._lock_fd)
            if (not stat.S_ISREG(lock.st_mode) or lock.st_nlink != 1 or
                    lock.st_uid != os.geteuid() or
                    stat.S_IMODE(lock.st_mode) != 0o600):
                raise PrivateFileError("Exec ownership lock is unsafe.")
            try:
                fcntl.flock(self._lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except (BlockingIOError, OSError) as exc:
                if isinstance(exc, BlockingIOError) or getattr(exc, "errno", None) in (11, 35):
                    self._reason = "owner_lock_unavailable"
                    return
                raise
            os.fsync(self._fd)  # persist the fixed owner-lock object
            self._state, self._reason = "healthy", None
            self._boot_scan()
        except (OSError, ValueError, TypeError) as exc:
            # Never silently create an in-memory fallback or open admission.
            if self._state != "quarantined":
                self._state, self._reason = "unavailable", "state_io_unavailable"
        finally:
            if self._state == "unavailable":
                self._release_fds()

    @property
    def durability_state(self) -> str:
        with self._gate:
            if self._closed or os.getpid() != self._pid:
                return "unavailable"
            return self._state

    @property
    def quarantine_reason_code(self) -> str | None:
        with self._gate:
            return self._reason

    def _release_fds(self) -> None:
        if self._lock_fd >= 0:
            os.close(self._lock_fd)  # flock ownership released at FD close
            self._lock_fd = -1
        if self._fd >= 0:
            os.close(self._fd)
            self._fd = -1

    def close(self) -> None:
        with self._gate:
            if not self._closed:
                self._closed = True
                self._release_fds()

    def require_healthy(self) -> None:
        with self._gate:
            if self._closed or os.getpid() != self._pid:
                raise GatewayError(
                    "exec_state_unavailable", "Exec state owner is unavailable.")
            if self._state == "quarantined":
                raise GatewayError(
                    "exec_quarantined", "Exec requires offline safety review.")
            if self._state != "healthy" or self._fd < 0 or self._lock_fd < 0:
                raise GatewayError(
                    "exec_state_unavailable", "Exec durable state is unavailable.")

    def _read_record(self, name: str) -> tuple[dict[str, Any], int]:
        fd = os.open(name, _READ, dir_fd=self._fd)
        try:
            st = os.fstat(fd)
            if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or
                    st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) != 0o600
                    or not 0 < st.st_size <= _RECORD_MAX):
                raise ValueError("Unsafe Exec record metadata.")
            data = os.read(fd, _RECORD_MAX + 1)
            after = os.fstat(fd)
            if (len(data) != st.st_size or len(data) > _RECORD_MAX
                    or (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns)
                    != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
                raise ValueError("Exec state record changed during reading.")
            return _strict_record(data, name), len(data)
        finally:
            os.close(fd)

    def _boot_scan(self) -> None:
        """Reject every unfinished/untrusted state, never replay/kill/clean."""
        try:
            names = os.listdir(self._fd)
            if _LOCK_NAME not in names or len(names) - 1 > _RECORD_COUNT_MAX:
                raise ValueError("Exec state owner or count is invalid.")
            for name in names:
                if name == _LOCK_NAME:
                    continue
                if _RECORD_NAME.fullmatch(name) is None:
                    raise ValueError("Foreign or interrupted Exec state record.")
                value, length = self._read_record(name)
                attempt = value["attempt_id"]
                if attempt in self._records:
                    raise ValueError("Duplicate Exec attempt.")
                self._records[attempt] = value
                self._payload_bytes += length
                if self._payload_bytes > _PAYLOAD_MAX:
                    raise ValueError("Exec state capacity exceeded.")
            for value in self._records.values():
                # Group-only RETIRED is scoped to its original ephemeral test
                # service; it is never proof for a newly started normal Gateway.
                if value["phase"] in _PHASES:
                    self._state, self._reason = "quarantined", "cleanup_unknown"
                    break
        except (OSError, ValueError, TypeError, UnicodeError):
            self._state, self._reason = "quarantined", "corrupt_record"

    def _unavailable(self) -> None:
        self._state, self._reason = "unavailable", "state_io_unavailable"

    def _atomic_write(self, name: str, data: bytes) -> None:
        """Unique temporary inode, full write, fsync file, replace, fsync dir.

        Leave any in-flight temporary file in place on errors: the following
        boot must recognize uncertain crash evidence and quarantine.
        """
        temp = "temp-" + uuid4().hex + ".tmp"
        fd = -1
        try:
            fd = os.open(temp, _CREATE, 0o600, dir_fd=self._fd)
            remaining = memoryview(data)
            while remaining:
                count = os.write(fd, remaining)
                if count <= 0:
                    raise OSError("Exec state write did not progress.")
                remaining = remaining[count:]
            os.fsync(fd)
            os.close(fd)
            fd = -1
            os.replace(temp, name, src_dir_fd=self._fd, dst_dir_fd=self._fd)
            os.fsync(self._fd)
        except (OSError, ValueError):
            self._unavailable()
            raise GatewayError(
                "exec_state_unavailable",
                "Exec state durability could not be confirmed.") from None
        finally:
            if fd >= 0:
                os.close(fd)

    def prepare(self, workspace: str, workspace_identity: tuple[int, int]) -> str:
        """Durably place a PREPARED intent; caller has not launched anything."""
        with self._gate:
            self.require_healthy()
            if (type(workspace) is not str or not _WORKSPACE.fullmatch(workspace)
                    or type(workspace_identity) is not tuple or
                    len(workspace_identity) != 2 or
                    any(type(i) is not int or i < 0 for i in workspace_identity)):
                raise GatewayError("invalid_argument", "Invalid Exec Workspace identity.")
            if (len(self._records) >= _RECORD_COUNT_MAX or
                    self._payload_bytes >= _PAYLOAD_MAX):
                self._unavailable()
                raise GatewayError("exec_state_unavailable",
                                   "Exec durable state capacity reached.")
            attempt = uuid4().hex
            while attempt in self._records:
                attempt = uuid4().hex
            record = {
                "schema_version": 1,
                "attempt_id": attempt,
                "workspace": workspace,
                "workspace_dev": workspace_identity[0],
                "workspace_ino": workspace_identity[1],
                "phase": "PREPARED",
                "created_at": time.time(),
                "cleanup_scope": "none",
                "full_descendant_tree_clean": "not_proven",
            }
            data = _encoded(record)
            if self._payload_bytes + len(data) > _PAYLOAD_MAX:
                self._unavailable()
                raise GatewayError("exec_state_unavailable",
                                   "Exec durable state capacity reached.")
            self._atomic_write("r-" + attempt + ".json", data)
            self._records[attempt] = record
            self._payload_bytes += len(data)
            return attempt

    def mark_unknown(self, attempt_id: str) -> None:
        """Persist uncertainty, then close all future Exec admission."""
        with self._gate:
            self.require_healthy()
            if type(attempt_id) is not str or attempt_id not in self._records:
                raise GatewayError("invalid_argument", "Unknown Exec attempt.")
            old = self._records[attempt_id]
            if old["phase"] not in ("PREPARED", "RUNNING"):
                raise GatewayError("invalid_argument", "Exec attempt is not unresolved.")
            entry = {**old, "phase": "UNKNOWN"}
            serialized = _encoded(entry)
            self._atomic_write("r-" + attempt_id + ".json", serialized)
            self._payload_bytes += len(serialized) - len(_encoded(old))
            self._records[attempt_id] = entry
            self._state, self._reason = "quarantined", "cleanup_unknown"
