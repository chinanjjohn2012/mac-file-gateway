"""Crash-durable admission for every Git child process, including first discovery.

Persist intent BEFORE Popen. Unconfirmed cleanup quarantines; no automatic
recovery or Web/MCP reset operation exists. The server chooses a stable private
directory outside all Workspaces. This class does not launch processes itself.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import stat
import threading
import time
from typing import Any, Callable, TypeVar
from uuid import uuid4

from .core import GatewayError
from .private_fs import PrivateFileError, open_pinned_directory

_T = TypeVar("_T")
_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_READ = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
_CREATE = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
_VALID_NAME = re.compile(r"(?:d-[a-f0-9]{32}|r-[0-9]+-[0-9]+|global)\.json\Z")
_ID = re.compile(r"[a-f0-9]{32}\Z")
_MAX_RECORD = 4096


class GitStateStore:
    """All mutable state is protected by a SHORT global admission mutex."""

    def __init__(self, state_dir: str | Path, *,
                 workspace_roots: tuple[str, ...] = ()) -> None:
        raw = os.fspath(state_dir)
        if not isinstance(raw, str) or not raw.startswith("/") or os.path.normpath(raw) != raw:
            raise PrivateFileError("Git state requires an absolute canonical directory.")
        for root in workspace_roots:
            parent, state = os.path.realpath(root), os.path.realpath(raw)
            if os.path.commonpath((parent, state)) in (parent, state):
                raise PrivateFileError("Git state cannot intersect an authorized Workspace.")
        config_parent = open_pinned_directory(os.path.dirname(raw), private_leaf=True)
        try:
            try:
                os.mkdir(os.path.basename(raw), 0o700, dir_fd=config_parent.fd)
                os.fsync(config_parent.fd)
            except FileExistsError:
                pass
            self._fd = os.open(os.path.basename(raw), _DIR, dir_fd=config_parent.fd)
        except OSError:
            raise PrivateFileError("Git state directory could not be pinned.") from None
        finally:
            config_parent.close()
        self._gate = threading.Lock()
        self._globally_bad = False
        self._bad_repos: set[tuple[int, int]] = set()
        self._discoveries: set[str] = set()
        self._running: dict[tuple[int, int], str] = {}
        self._closed = False
        self._boot_scan()

    @staticmethod
    def new_call_id() -> str:
        return uuid4().hex

    @staticmethod
    def _name_discover(call_id: str) -> str:
        if not _ID.fullmatch(call_id):
            raise ValueError("Invalid Git call identifier.")
        return "d-" + call_id + ".json"

    @staticmethod
    def _name_repo(key: tuple[int, int]) -> str:
        if (type(key) is not tuple or len(key) != 2 or
                any(type(i) is not int or i < 0 for i in key)):
            raise ValueError("Invalid Git repository identity.")
        return "r-" + str(key[0]) + "-" + str(key[1]) + ".json"

    def _read_record(self, name: str) -> dict[str, Any]:
        fd = os.open(name, _READ, dir_fd=self._fd)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_size > _MAX_RECORD:
                raise ValueError("Unsafe Git state record.")
            raw = os.read(fd, _MAX_RECORD + 1)
            if len(raw) > _MAX_RECORD:
                raise ValueError("Oversized Git state record.")
            item = json.loads(raw)
            if type(item) is not dict:
                raise ValueError("Invalid Git state record.")
            return item
        finally:
            os.close(fd)

    def _boot_scan(self) -> None:
        """Any previous discovery means GLOBAL quarantine; repo records bind key."""
        try:
            for name in os.listdir(self._fd):
                if not _VALID_NAME.fullmatch(name):
                    self._globally_bad = True
                    continue
                value = self._read_record(name)
                if name == "global.json":
                    self._globally_bad = True
                elif name.startswith("d-"):
                    if value.get("kind") != "DISCOVERING" or value.get("call_id") != name[2:-5]:
                        self._globally_bad = True
                    self._globally_bad = True
                else:
                    key = name[2:-5].split("-")
                    if (len(key) != 2 or value.get("kind") not in ("RUNNING", "QUARANTINED")
                            or value.get("key") != [int(key[0]), int(key[1])]):
                        self._globally_bad = True
                    else:
                        self._bad_repos.add((int(key[0]), int(key[1])))
        except (OSError, ValueError, TypeError, UnicodeError, KeyError):
            self._globally_bad = True

    def _atomic_write(self, name: str, record: dict[str, Any]) -> None:
        if not _VALID_NAME.fullmatch(name):
            raise ValueError("Invalid Git state filename.")
        payload = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode()
        if len(payload) > _MAX_RECORD:
            raise ValueError("Git state record too large.")
        temp = "temp-" + uuid4().hex + ".tmp"
        fd = os.open(temp, _CREATE, 0o600, dir_fd=self._fd)
        try:
            data = memoryview(payload)
            while data:
                n = os.write(fd, data)
                if not n:
                    raise OSError("Git state write failed.")
                data = data[n:]
            os.fsync(fd)
        finally:
            os.close(fd)
        os.rename(temp, name, src_dir_fd=self._fd, dst_dir_fd=self._fd)
        os.fsync(self._fd)

    def _delete(self, name: str) -> None:
        os.unlink(name, dir_fd=self._fd)
        os.fsync(self._fd)

    def _quarantine_global(self) -> None:
        # Called only with the admission gate held.
        self._globally_bad = True
        try:
            self._atomic_write("global.json",
                               {"kind": "GLOBAL_QUARANTINED", "created": time.time()})
        except (OSError, ValueError):
            # Surviving DISCOVERING/RUNNING record is also a durable failure marker.
            pass

    def _require_healthy(self) -> None:
        if self._closed:
            raise GatewayError("git_disabled", "Git state was closed.")
        if self._globally_bad:
            raise GatewayError("git_global_quarantined", "Git requires local offline recovery.")

    @property
    def globally_quarantined(self) -> bool:
        with self._gate:
            return self._globally_bad

    def is_repo_quarantined(self, key: tuple[int, int]) -> bool:
        with self._gate:
            return self._globally_bad or key in self._bad_repos

    def start_discovery(self, call_id: str, workspace: str,
                        spawn: Callable[[], _T]) -> _T:
        """Write+fsync DISCOVERING; spawn under SAME short global gate."""
        with self._gate:
            self._require_healthy()
            try:
                self._atomic_write(self._name_discover(call_id),
                                   {"kind": "DISCOVERING", "call_id": call_id,
                                    "workspace": workspace, "created": time.time()})
            except (OSError, ValueError):
                self._quarantine_global()
                raise GatewayError("git_state_unavailable",
                                   "Git discovery intent could not be persisted.") from None
            self._discoveries.add(call_id)
            try:
                return spawn()
            except BaseException:
                # Treat ambiguous Popen failures conservatively; marker stays.
                self._quarantine_global()
                raise

    def finish_discovery(self, call_id: str, *, clean: bool) -> None:
        with self._gate:
            if not clean:
                self._quarantine_global()
                raise GatewayError("git_cleanup_incomplete", "Git discovery cleanup is uncertain.")
            try:
                self._delete(self._name_discover(call_id))
            except OSError:
                self._quarantine_global()
                raise GatewayError("git_state_unavailable",
                                   "Git discovery intent could not be cleared.") from None
            self._discoveries.discard(call_id)

    def begin_repo(self, key: tuple[int, int], call_id: str) -> None:
        """Caller MUST already hold the same common-dir execution lock."""
        with self._gate:
            self._require_healthy()
            if key in self._bad_repos or key in self._running:
                raise GatewayError("git_repository_quarantined", "Git repository cannot run.")
            try:
                self._atomic_write(self._name_repo(key),
                                   {"kind": "RUNNING", "key": list(key),
                                    "call_id": call_id, "created": time.time()})
            except (OSError, ValueError):
                self._quarantine_global()
                raise GatewayError("git_state_unavailable",
                                   "Git repository intent could not be persisted.") from None
            self._running[key] = call_id

    def start_repo_process(self, key: tuple[int, int], call_id: str,
                           spawn: Callable[[], _T]) -> _T:
        with self._gate:
            self._require_healthy()
            if key in self._bad_repos or self._running.get(key) != call_id:
                raise GatewayError("git_repository_quarantined", "Git execution is not admitted.")
            try:
                return spawn()
            except BaseException:
                self._bad_repos.add(key)
                try:
                    self._atomic_write(self._name_repo(key),
                                       {"kind": "QUARANTINED", "key": list(key),
                                        "call_id": call_id, "created": time.time()})
                except (OSError, ValueError):
                    self._quarantine_global()
                raise

    def finish_repo(self, key: tuple[int, int], call_id: str, *,
                    clean: bool) -> None:
        """Clean or quarantine with the repository lock STILL held."""
        with self._gate:
            if self._running.get(key) != call_id:
                raise GatewayError("git_repository_quarantined", "Git execution ownership changed.")
            if not clean:
                self._bad_repos.add(key)
                try:
                    self._atomic_write(self._name_repo(key),
                                       {"kind": "QUARANTINED", "key": list(key),
                                        "call_id": call_id, "created": time.time()})
                except (OSError, ValueError):
                    self._quarantine_global()
                self._running.pop(key, None)
                raise GatewayError("git_cleanup_incomplete", "Git repository cleanup is uncertain.")
            if key in self._bad_repos or self._globally_bad:
                self._running.pop(key, None)
                raise GatewayError("git_repository_quarantined", "Git is quarantined.")
            try:
                self._delete(self._name_repo(key))
            except OSError:
                self._bad_repos.add(key)
                self._quarantine_global()
                raise GatewayError("git_state_unavailable",
                                   "Git repository intent could not be cleared.") from None
            self._running.pop(key, None)

    def close(self) -> None:
        with self._gate:
            if not self._closed:
                self._closed = True
                os.close(self._fd)
