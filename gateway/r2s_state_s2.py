"""R2-S S2: isolated, NONSPAWNING v2 private-FS candidate.

Not imported or invoked by WorkspaceService, REST, MCP or ExecStateStore v1.
No positive Native capability, live migration, process start or signal operation.
Only explicit caller-owned, disposable ``exec-state-s2-candidate`` directories.
An offline-fake consent is metadata for testing fencing, never an Exec grant.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import threading
from uuid import uuid4


class S2Blocked(RuntimeError):
    """Conservative denial, not a process or cleanup assertion."""


class S2Unavailable(S2Blocked):
    """The private FS cannot prove its required state transition."""


_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_READ = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC
_NEW = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
_LOCK = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC
_UUID = re.compile(r"[a-f0-9]{32}\Z")
_SCOPE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_STORE_NAME = "exec-state-s2-candidate"
_STATE_NAME = "state-v2.json"
_LIMIT_RECORD = 4096
_LIMIT_COUNT = 4096
_LIMIT_TOTAL = 16 * 1024 * 1024
_ROOT_FIELDS = frozenset({"schema_version", "consent_epoch", "consent_active",
                          "binding", "owner_generation", "attempts", "quarantined",
                          "orphan_positive"})
_ATTEMPT_FIELDS = frozenset({"consent_epoch", "owner_generation", "token",
                             "binding", "phase", "cleanup_scope", "delivered",
                             "late_positive"})
_BIND_FIELDS = frozenset({"dev", "ino", "scope", "backend"})


def _pin(path: str | Path) -> int:
    """Open all absolute path components without following any symlink."""
    raw = os.fspath(path)
    if (type(raw) is not str or not raw.startswith("/") or "\x00" in raw
            or "//" in raw or raw.endswith("/")):
        raise S2Blocked("noncanonical private path")
    parts = raw.split("/")[1:]
    if not parts or any(x in ("", ".", "..") for x in parts):
        raise S2Blocked("noncanonical private path")
    fd = os.open("/", _DIR)
    try:
        for part in parts:
            next_fd = os.open(part, _DIR, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd
    except BaseException:
        os.close(fd)
        raise


def _private_directory(fd: int) -> None:
    st = os.fstat(fd)
    if (not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid()
            or stat.S_IMODE(st.st_mode) != 0o700):
        raise S2Blocked("private directory identity/mode invalid")


def _strict_pairs(pairs: list[tuple[str, object]]) -> dict:
    value = {}
    for k, v in pairs:
        if k in value:
            raise ValueError("duplicate state key")
        value[k] = v
    return value


def _valid_binding(value: object) -> bool:
    return (type(value) is dict and set(value) == _BIND_FIELDS
            and all(type(value[k]) is int and value[k] > 0 for k in ("dev", "ino"))
            and type(value["scope"]) is str and bool(_SCOPE.fullmatch(value["scope"]))
            and type(value["backend"]) is str and value["backend"] == "offline-fake-v1")


def _strict_state(value: object, *, max_records: int, max_total: int) -> None:
    if type(value) is not dict or set(value) != _ROOT_FIELDS:
        raise ValueError("unsupported v2 state fields")
    if type(value["schema_version"]) is not int or value["schema_version"] != 2:
        raise ValueError("no implicit v1 migration")
    epoch = value["consent_epoch"]
    if type(epoch) is not int or not 0 <= epoch <= 2**63 - 1:
        raise ValueError("invalid consent epoch")
    if type(value["consent_active"]) is not bool or type(value["quarantined"]) is not bool:
        raise ValueError("invalid consent/fence flags")
    if type(value["orphan_positive"]) is not bool or (value["orphan_positive"] and not value["quarantined"]):
        raise ValueError("orphan observation must quarantine")
    if ((value["consent_active"] and (epoch == 0 or not _valid_binding(value["binding"])))
            or (value["binding"] is not None and not _valid_binding(value["binding"]))):
        raise ValueError("invalid or copied active consent")
    if type(value["owner_generation"]) is not str or not _UUID.fullmatch(value["owner_generation"]):
        raise ValueError("invalid owner generation")
    attempts = value["attempts"]
    if type(attempts) is not dict or len(attempts) > max_records:
        raise ValueError("attempt count exceeded")
    for name, record in attempts.items():
        if type(name) is not str or not _UUID.fullmatch(name):
            raise ValueError("invalid attempt id")
        if type(record) is not dict or set(record) != _ATTEMPT_FIELDS:
            raise ValueError("invalid attempt record")
        if (type(record["consent_epoch"]) is not int
                or not 0 < record["consent_epoch"] <= epoch
                or type(record["owner_generation"]) is not str
                or not _UUID.fullmatch(record["owner_generation"])
                or type(record["token"]) is not str or not _UUID.fullmatch(record["token"])
                or not _valid_binding(record["binding"])
                or type(record["delivered"]) is not bool
                or type(record["late_positive"]) is not bool):
            raise ValueError("invalid attempt identity")
        if type(record["phase"]) is not str or record["phase"] not in ("PREPARED", "UNKNOWN", "RETIRED_LIMITED"):
            raise ValueError("unqualified attempt phase")
        if (record["cleanup_scope"] != ("original_group_only" if record["phase"] == "RETIRED_LIMITED" else "none")
                or (record["late_positive"] and record["phase"] != "UNKNOWN")
                or (record["phase"] == "UNKNOWN" and not value["quarantined"])):
            raise ValueError("cleanup/uncertainty mismatch")
        if len(_json_bytes(record)) > _LIMIT_RECORD:
            raise ValueError("attempt record over quota")
    if len(_json_bytes(value)) > max_total:
        raise ValueError("total durable state over quota")


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True, allow_nan=False) + "\n").encode("utf-8")


@dataclass(frozen=True)
class OfflineTicket:
    attempt_id: str
    consent_epoch: int
    owner_generation: str
    token: str


class S2PrivateState:
    """Isolated v2 journal with real owner lock and file+directory fsync.

    A prepared offline ticket is never a spawn capability. The store does not
    provide allocate/start/dispatch, native cleanup, reset, or remote APIs.
    """

    def __init__(self, state_dir: str | Path, *, workspace_root: str | Path,
                 max_records: int = _LIMIT_COUNT, max_total_bytes: int = _LIMIT_TOTAL,
                 fault_at: str | None = None):
        if (type(max_records) is not int or not 1 <= max_records <= _LIMIT_COUNT
                or type(max_total_bytes) is not int or not 512 <= max_total_bytes <= _LIMIT_TOTAL):
            raise ValueError("invalid bounded test configuration")
        self._fd = self._lock_fd = self._workspace_fd = -1
        self._gate = threading.RLock()
        self._pid = os.getpid()
        self._closed = False
        self._status = "unavailable"
        self._value: dict | None = None
        self._max_records = max_records
        self._max_total = max_total_bytes
        self._fault_at = fault_at   # deterministic T1 fault injection; no OS kill
        self._state_identity = None
        try:
            raw = os.fspath(state_dir)
            work = os.fspath(workspace_root)
            if (type(raw) is not str or Path(raw).name != _STORE_NAME
                    or os.path.commonpath((raw, work)) in (raw, work)):
                raise S2Blocked("not a separate v2 candidate state root")
            self._workspace_path = work
            self._state_path = raw
            self._workspace_fd = _pin(work)
            parent = _pin(os.path.dirname(raw))
            try:
                _private_directory(parent)
                try:
                    os.mkdir(_STORE_NAME, 0o700, dir_fd=parent)
                    os.fsync(parent)
                except FileExistsError:
                    pass
                self._fd = os.open(_STORE_NAME, _DIR, dir_fd=parent)
            finally:
                os.close(parent)
            _private_directory(self._fd)
            self._lock_fd = os.open("owner.lock", _LOCK, 0o600, dir_fd=self._fd)
            self._check_file(self._lock_fd, size_limit=None)
            lock = os.fstat(self._lock_fd)
            self._lock_identity = (lock.st_dev, lock.st_ino)
            fcntl.flock(self._lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            os.fsync(self._fd)
            names = set(os.listdir(self._fd))
            if not names.issubset({"owner.lock", _STATE_NAME}) or "owner.lock" not in names:
                raise S2Blocked("foreign or interrupted v2 state; offline inspection required")
            if _STATE_NAME in names:
                self._value = self._read_state()
                self._state_identity = self._identity(os.stat(
                    _STATE_NAME, dir_fd=self._fd, follow_symlinks=False))
            else:
                self._value = {
                    "schema_version": 2, "consent_epoch": 0, "consent_active": False,
                    "binding": None, "owner_generation": uuid4().hex,
                    "attempts": {}, "quarantined": False, "orphan_positive": False,
                }
            # A valid PREPARED from an earlier owner is uncertain, not replayable.
            next_value = deepcopy(self._value)
            next_value["owner_generation"] = uuid4().hex
            # The former owner's PREPARED ticket has no surviving lease or
            # permission to advance. Persist UNKNOWN rather than carrying a
            # misleading live PREPARED phase into the new owner generation.
            for record in next_value["attempts"].values():
                if record["phase"] == "PREPARED":
                    record["phase"] = "UNKNOWN"
                    next_value["quarantined"] = True
            self._commit(next_value)
            self._value = next_value
            self._status = "quarantined" if next_value["quarantined"] else "healthy"
        except (OSError, ValueError, TypeError, OverflowError, RecursionError) as exc:
            self.close()
            raise S2Unavailable("private v2 state/lock unavailable") from exc
        except BaseException:
            self.close()
            raise

    def _check_file(self, fd: int, *, size_limit: int | None) -> os.stat_result:
        st = os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1
                or st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) != 0o600
                or (size_limit is not None and not 0 < st.st_size <= size_limit)):
            raise S2Blocked("unsafe v2 file identity/mode/size")
        return st

    def _read_state(self) -> dict:
        fd = os.open(_STATE_NAME, _READ, dir_fd=self._fd)
        try:
            before = self._check_file(fd, size_limit=self._max_total)
            buf = bytearray()
            while len(buf) <= self._max_total:
                chunk = os.read(fd, min(65536, self._max_total + 1 - len(buf)))
                if not chunk:
                    break
                buf.extend(chunk)
            after = os.fstat(fd)
            if (len(buf) != before.st_size or len(buf) > self._max_total
                    or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                        before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size,
                                               after.st_mtime_ns, after.st_ctime_ns)):
                raise S2Blocked("v2 state changed during read")
            obj = json.loads(buf.decode("utf-8"), object_pairs_hook=_strict_pairs,
                             parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite")))
            _strict_state(obj, max_records=self._max_records, max_total=self._max_total)
            return obj
        finally:
            os.close(fd)

    @staticmethod
    def _identity(st: os.stat_result) -> tuple[int, int, int, int, int]:
        return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)

    def _check_live_inodes(self) -> None:
        """Do not overwrite a foreign/replaced file or renamed state root."""
        fd = _pin(self._state_path)
        try:
            a, b = os.fstat(fd), os.fstat(self._fd)
            if (a.st_dev, a.st_ino) != (b.st_dev, b.st_ino):
                raise S2Blocked("v2 state root was replaced")
        finally:
            os.close(fd)
        names = set(os.listdir(self._fd))
        expected = {"owner.lock"} | ({_STATE_NAME} if self._state_identity else set())
        if names != expected:
            raise S2Blocked("unexpected private v2 object")
        lock = os.stat("owner.lock", dir_fd=self._fd, follow_symlinks=False)
        if (lock.st_dev, lock.st_ino) != self._lock_identity:
            raise S2Blocked("v2 owner lock was replaced")
        self._check_file(self._lock_fd, size_limit=None)
        if self._state_identity is not None:
            st = os.stat(_STATE_NAME, dir_fd=self._fd, follow_symlinks=False)
            if self._identity(st) != self._state_identity or self._read_state() != self._value:
                raise S2Blocked("v2 state changed outside the held owner lock")

    def _commit(self, value: dict) -> None:
        """Durable pending -> temp -> replace -> dir fsync -> unlink pending.

        A fault after mutation leaves pending forensic evidence. A fault before
        mutation leaves old valid state or a pending marker; no silent reset.
        """
        try:
            self._check_live_inodes()
        except (OSError, S2Blocked, ValueError) as exc:
            self._status = "unavailable"
            raise S2Unavailable("v2 prior source identity invalid") from exc
        pending = "pending-" + uuid4().hex
        temp = "temp-" + uuid4().hex
        try:
            fd = os.open(pending, _NEW, 0o600, dir_fd=self._fd)
            try:
                os.write(fd, b"v2-mutation-uncertain\n")
                os.fsync(fd)
            finally:
                os.close(fd)
            os.fsync(self._fd)
            # Quota/schema rejection is itself an uncertain attempt to mutate
            # durable state. Record a synced forensic fence *before* checking
            # payload limits so a previously healthy active-consent snapshot
            # cannot be reopened after a rejected/oversized PREPARED write.
            _strict_state(value, max_records=self._max_records, max_total=self._max_total)
            if self._fault_at == "after_pending":
                raise OSError("injected pending fault")
            fd = os.open(temp, _NEW, 0o600, dir_fd=self._fd)
            try:
                buf = memoryview(_json_bytes(value))
                while buf:
                    n = os.write(fd, buf)
                    if n <= 0:
                        raise OSError("write made no progress")
                    buf = buf[n:]
                os.fsync(fd)
            finally:
                os.close(fd)
            if self._fault_at == "before_replace":
                raise OSError("injected replace fault")
            os.replace(temp, _STATE_NAME, src_dir_fd=self._fd, dst_dir_fd=self._fd)
            if self._fault_at == "after_replace":
                raise OSError("injected dir sync fault")
            os.fsync(self._fd)
            if self._fault_at == "after_dirsync":
                raise OSError("injected finalization fault")
            os.unlink(pending, dir_fd=self._fd)
            os.fsync(self._fd)
            self._state_identity = self._identity(os.stat(
                _STATE_NAME, dir_fd=self._fd, follow_symlinks=False))
        except (OSError, ValueError, TypeError, OverflowError, RecursionError):
            self._status = "unavailable"
            raise S2Unavailable("v2 transition durability or capacity unconfirmed") from None

    def _require(self) -> None:
        if (self._closed or os.getpid() != self._pid or self._status != "healthy"):
            raise S2Blocked("v2 state not healthy; no offline admission")

    def _save(self, value: dict) -> None:
        self._commit(value)
        self._value = value
        self._status = "quarantined" if value["quarantined"] else "healthy"

    @property
    def status(self) -> str:
        if self._closed or os.getpid() != self._pid:
            return "unavailable"
        return self._status

    def snapshot(self) -> dict:
        with self._gate:
            if self._closed or os.getpid() != self._pid or self._value is None:
                raise S2Blocked("snapshot unavailable")
            return deepcopy(self._value)

    def approve_fake(self, *, exec_scope: str = "offline-scope", backend: str = "offline-fake-v1") -> None:
        """Persist offline TEST metadata only; cannot authorize actual Exec."""
        with self._gate:
            self._require()
            ws = os.fstat(self._workspace_fd)
            binding = {"dev": ws.st_dev, "ino": ws.st_ino,
                       "scope": exec_scope, "backend": backend}
            if not _valid_binding(binding) or not self._workspace_still_pinned():
                raise S2Blocked("unsupported/moved offline binding")
            v = self.snapshot()
            v["binding"] = binding
            v["consent_epoch"] += 1
            v["consent_active"] = True
            self._save(v)

    def _workspace_still_pinned(self) -> bool:
        try:
            fd = _pin(self._workspace_path)
            try:
                a, b = os.fstat(fd), os.fstat(self._workspace_fd)
                return (a.st_dev, a.st_ino) == (b.st_dev, b.st_ino)
            finally:
                os.close(fd)
        except (OSError, S2Blocked):
            return False

    def prepare_offline(self) -> OfflineTicket:
        """Durable PREPARED metadata; deliberately NO way to dispatch it."""
        with self._gate:
            self._require()
            v = self.snapshot()
            ws = os.fstat(self._workspace_fd)
            if (not v["consent_active"] or not _valid_binding(v["binding"])
                    or v["binding"]["dev"] != ws.st_dev
                    or v["binding"]["ino"] != ws.st_ino
                    or not self._workspace_still_pinned()):
                raise S2Blocked("offline consent/binding invalid")
            if len(v["attempts"]) >= self._max_records:
                self._status = "unavailable"
                raise S2Unavailable("v2 forensic quota full")
            aid, token = uuid4().hex, uuid4().hex
            v["attempts"][aid] = {
                "consent_epoch": v["consent_epoch"], "owner_generation": v["owner_generation"],
                "token": token, "binding": deepcopy(v["binding"]), "phase": "PREPARED",
                "cleanup_scope": "none", "delivered": False, "late_positive": False,
            }
            self._save(v)
            return OfflineTicket(aid, v["consent_epoch"], v["owner_generation"], token)

    def revoke_fake(self) -> None:
        with self._gate:
            self._require()
            v = self.snapshot()
            v["consent_epoch"] += 1
            v["consent_active"] = False
            for record in v["attempts"].values():
                if record["phase"] == "PREPARED":
                    record["phase"] = "UNKNOWN"
                    v["quarantined"] = True
            self._save(v)

    def late_positive_fake(self, ticket: OfflineTicket | None) -> None:
        """Trusted synthetic positive/orphan event; NO OS observer or signal."""
        with self._gate:
            self._require()
            v = self.snapshot()
            record = (v["attempts"].get(ticket.attempt_id)
                      if type(ticket) is OfflineTicket else None)
            if record is not None and (record["token"], record["owner_generation"],
                                       record["consent_epoch"]) == (ticket.token,
                                       ticket.owner_generation, ticket.consent_epoch):
                record["phase"] = "UNKNOWN"
                record["cleanup_scope"] = "none"
                record["late_positive"] = True
            else:
                # A positively reported but unattributable event is never clean.
                v["orphan_positive"] = True
            v["quarantined"] = True
            self._save(v)

    def close(self) -> None:
        with self._gate:
            if not self._closed:
                self._closed = True
                for key in ("_lock_fd", "_fd", "_workspace_fd"):
                    fd = getattr(self, key)
                    if fd >= 0:
                        os.close(fd)
                        setattr(self, key, -1)

    def __enter__(self) -> "S2PrivateState":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


class S2NonspawningCoordinator:
    """No backend reference. Calls never return an authorization capability."""

    def deny_apply(self, *args: object, **kwargs: object) -> None:
        raise S2Blocked("exec_cleanup_proof_required")
