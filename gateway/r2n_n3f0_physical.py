"""N3-F0 candidate: existing-only, FD-rooted private-state read-only reader.

NOT wired into Gateway / REST / MCP / Native.  No provisioning, writes,
rename, unlink, fsync, signals, subprocess or positive admission.  All OS
calls are inside RealFDPort and are NOT run by the T0 fake-port tests.
A real disposable T1 call requires a NEW resource-specific authorization.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import os
import re
import stat
from typing import Protocol

_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_FLAGS = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC
_STATE_NAMES = frozenset({"owner.lock", "control.v1", "attempts", "responses"})
_LINEAGE_NAMES = frozenset({"provision-witness.v1", "owner-authority.v1"})
_CONTROL_FIELDS = frozenset({
    "schema_id", "namespace_id", "lineage_generation", "owner_generation",
    "state_generation", "consent_epoch", "consent_record_id", "consent_active",
    "consent_expiry_or_null", "consent_binding_digest", "owner_lock_dev",
    "owner_lock_ino", "global_quarantined", "global_quarantine_reason",
    "max_attempts", "max_attempt_bytes", "max_total_attempt_payload",
    "unresolved_retired_tombstone_count",
})
_WITNESS_FIELDS = frozenset({"schema_id", "namespace_id", "lineage_generation",
                             "state_generation", "operator_provisioned"})
_MAX_ENTRIES = 4096
_MAX_ANCESTRY = 64
_MAX_OBJECT_BYTES = 4096
_IDENTIFIER = re.compile(r"[a-z][a-z0-9_-]{0,63}\Z")


class N3F0PhysicalDenied(RuntimeError):
    """Sanitized fail-closed reason; no filenames, record bytes, or host paths."""

    def __init__(self, reason_code: str):
        super().__init__(reason_code)
        self.reason_code = reason_code
        self.available = False
        self.completion_capability = "none"


@dataclass(frozen=True, slots=True)
class N3F0PhysicalSnapshot:
    durability_state: str = "unavailable"
    quarantine_reason_code: str = "offline_authority_unverified"
    available: bool = False
    completion_capability: str = "none"
    observation_level: str = "candidate_read_only_fd"  # neither authority nor T1 proof

    def __post_init__(self) -> None:
        if (self.durability_state != "unavailable" or
                self.available is not False or
                self.completion_capability != "none" or
                self.observation_level != "candidate_read_only_fd"):
            raise ValueError("no positive N3-F0 capability")


class FDPort(Protocol):
    """Only an internally trusted bootstrap may provide pinned borrowed FDs.

    The interface is deliberately not an HTTP/MCP/client/API capability.
    A fake port is permitted solely in T0; a RealFDPort call is T1.
    """
    def euid(self) -> int: ...
    def fstat(self, fd: int) -> os.stat_result: ...
    def open_directory(self, name: str, parent_fd: int) -> int: ...
    def open_file(self, name: str, parent_fd: int) -> int: ...
    def named_stat(self, name: str, parent_fd: int) -> os.stat_result: ...
    def names(self, fd: int, limit: int) -> tuple[str, ...]: ...
    def bytes_from(self, fd: int, limit: int) -> bytes: ...
    def ancestor_ids(self, fd: int, limit: int) -> tuple[tuple[int, int], ...]: ...
    def exclusive_lock(self, fd: int) -> None: ...
    def close(self, fd: int) -> None: ...


class RealFDPort:
    """Dormant real OS implementation; DO NOT CALL until exact approved T1.

    Does NOT provide the trusted control/Workspace bootstrap or provenance.
    Only takes relative literal names; never O_CREAT, truncates or writes.
    """

    def euid(self) -> int:
        return os.geteuid()

    def fstat(self, fd: int) -> os.stat_result:
        return os.fstat(fd)

    def open_directory(self, name: str, parent_fd: int) -> int:
        return os.open(name, _DIR_FLAGS, dir_fd=parent_fd)

    def open_file(self, name: str, parent_fd: int) -> int:
        return os.open(name, _FILE_FLAGS, dir_fd=parent_fd)

    def named_stat(self, name: str, parent_fd: int) -> os.stat_result:
        return os.stat(name, dir_fd=parent_fd, follow_symlinks=False)

    def names(self, fd: int, limit: int) -> tuple[str, ...]:
        names: list[str] = []
        with os.scandir(fd) as entries:
            for entry in entries:
                if len(names) >= limit:
                    raise N3F0PhysicalDenied("directory_entry_limit")
                names.append(entry.name)
        return tuple(names)

    def bytes_from(self, fd: int, limit: int) -> bytes:
        data = bytearray()
        while len(data) <= limit:
            chunk = os.read(fd, min(4096, limit + 1 - len(data)))
            if not chunk:
                return bytes(data)
            data.extend(chunk)
        raise N3F0PhysicalDenied("private_record_too_large")

    def ancestor_ids(self, fd: int, limit: int) -> tuple[tuple[int, int], ...]:
        """Bounded upward pinned-FD walk; no path strings, no symlink follow.

        Race/mount/firmlink behavior and actual macOS semantics still need T1.
        Every temporary opened FD has one matching close, including failures.
        """
        chain: list[tuple[int, int]] = []
        current = os.dup(fd)
        try:
            for _ in range(limit):
                before = os.fstat(current)
                item = (before.st_dev, before.st_ino)
                if item in chain:
                    raise N3F0PhysicalDenied("ancestor_cycle")
                chain.append(item)
                parent = os.open("..", _DIR_FLAGS, dir_fd=current)
                try:
                    after = os.fstat(current)
                    if (after.st_dev, after.st_ino) != item:
                        raise N3F0PhysicalDenied("ancestor_race")
                    pst = os.fstat(parent)
                    at_root = (pst.st_dev, pst.st_ino) == item
                except BaseException:
                    os.close(parent)
                    raise
                if at_root:
                    os.close(parent)
                    return tuple(reversed(chain))
                os.close(current)
                current = parent
            raise N3F0PhysicalDenied("ancestor_limit")
        finally:
            os.close(current)

    def exclusive_lock(self, fd: int) -> None:
        import fcntl  # imported ONLY by actual separately authorized T1 call
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def close(self, fd: int) -> None:
        os.close(fd)


def _id(st: os.stat_result) -> tuple[int, int]:
    dev, ino = st.st_dev, st.st_ino
    if (type(dev) is not int or type(ino) is not int or
            not 0 < dev < 2**63 or not 0 < ino < 2**63):
        raise N3F0PhysicalDenied("invalid_inode_identity")
    return (dev, ino)


def _private(st: os.stat_result, uid: int, *, directory: bool) -> None:
    want = 0o700 if directory else 0o600
    if (st.st_uid != uid or stat.S_IMODE(st.st_mode) != want or
            (not stat.S_ISDIR(st.st_mode) if directory else
             not stat.S_ISREG(st.st_mode) or st.st_nlink != 1)):
        raise N3F0PhysicalDenied("invalid_private_object")
    _id(st)


def _chain(port: FDPort, fd: int) -> tuple[tuple[int, int], ...]:
    result = port.ancestor_ids(fd, _MAX_ANCESTRY)
    if (type(result) is not tuple or not 2 <= len(result) <= _MAX_ANCESTRY or
            any(type(x) is not tuple or len(x) != 2 or
                any(type(n) is not int or not 0 < n < 2**63 for n in x)
                for x in result) or
            len(set(result)) != len(result) or result[-1] != _id(port.fstat(fd))):
        raise N3F0PhysicalDenied("unverified_ancestry")
    return result


def _separate(a: tuple, b: tuple, anchor: tuple[int, int]) -> None:
    if not a or not b or a[0] != b[0] or anchor not in a or anchor not in b:
        raise N3F0PhysicalDenied("lineage_not_independent")
    prefix = 0
    while prefix < min(len(a), len(b)) and a[prefix] == b[prefix]:
        prefix += 1
    if (prefix == len(a) or prefix == len(b) or
            a.index(anchor) >= prefix or b.index(anchor) >= prefix or
            set(a[prefix:]) & set(b[prefix:])):
        raise N3F0PhysicalDenied("lineage_not_independent")


def _json(raw: bytes, keys: frozenset[str]) -> dict:
    if type(raw) is not bytes or not 1 <= len(raw) <= _MAX_OBJECT_BYTES:
        raise N3F0PhysicalDenied("corrupt_record")

    def unique(pairs: list[tuple[str, object]]) -> dict:
        d: dict = {}
        for k, v in pairs:
            if k in d:
                raise ValueError("duplicate")
            d[k] = v
        return d

    def no_constant(_s: str) -> None:
        raise ValueError("nonfinite")

    try:
        d = json.loads(raw.decode("utf-8"), object_pairs_hook=unique,
                       parse_constant=no_constant)
    except (UnicodeError, RecursionError, ValueError, TypeError) as exc:
        raise N3F0PhysicalDenied("corrupt_record") from exc
    if type(d) is not dict or d.keys() != keys:
        raise N3F0PhysicalDenied("corrupt_record")
    return d


def _strict_control(raw: bytes) -> dict:
    c = _json(raw, _CONTROL_FIELDS)
    positives = ("lineage_generation", "owner_generation", "state_generation",
                 "owner_lock_dev", "owner_lock_ino")
    if any(type(c[k]) is not int or not 0 < c[k] < 2**63 for k in positives):
        raise N3F0PhysicalDenied("corrupt_record")
    if (c["schema_id"] != "native-n3-v1" or
            type(c["namespace_id"]) is not str or
            _IDENTIFIER.fullmatch(c["namespace_id"]) is None or
            type(c["consent_active"]) is not bool or
            type(c["global_quarantined"]) is not bool or
            type(c["consent_epoch"]) is not int or
            not 0 <= c["consent_epoch"] < 2**63 or
            (c["consent_active"] and not c["consent_epoch"]) or
            type(c["consent_record_id"]) is not str or
            _IDENTIFIER.fullmatch(c["consent_record_id"]) is None or
            type(c["consent_binding_digest"]) is not str or
            len(c["consent_binding_digest"]) != 64 or
            any(x not in "0123456789abcdef" for x in c["consent_binding_digest"]) or
            (c["consent_expiry_or_null"] is not None and
             (type(c["consent_expiry_or_null"]) is not int or
              not 0 < c["consent_expiry_or_null"] < 2**63)) or
            type(c["global_quarantine_reason"]) is not str or
            _IDENTIFIER.fullmatch(c["global_quarantine_reason"]) is None or
            type(c["max_attempts"]) is not int or
            not 1 <= c["max_attempts"] <= 4096 or
            type(c["max_attempt_bytes"]) is not int or
            not 256 <= c["max_attempt_bytes"] <= 4096 or
            type(c["max_total_attempt_payload"]) is not int or
            not 256 <= c["max_total_attempt_payload"] <= 16*1024*1024 or
            type(c["unresolved_retired_tombstone_count"]) is not int or
            not 0 <= c["unresolved_retired_tombstone_count"] <= c["max_attempts"]):
        raise N3F0PhysicalDenied("corrupt_record")
    if (c["global_quarantined"] == (c["global_quarantine_reason"] == "none") or
            c["consent_active"] or c["global_quarantined"] or
            c["unresolved_retired_tombstone_count"]):
        raise N3F0PhysicalDenied("prior_uncertainty")
    return c


def _strict_witness(raw: bytes) -> dict:
    w = _json(raw, _WITNESS_FIELDS)
    if (w["schema_id"] != "native-n3-lineage-v1" or
            type(w["namespace_id"]) is not str or
            type(w["lineage_generation"]) is not int or
            not 0 < w["lineage_generation"] < 2**63 or
            type(w["state_generation"]) is not int or
            not 0 < w["state_generation"] < 2**63 or
            w["operator_provisioned"] is not True):
        raise N3F0PhysicalDenied("invalid_lineage")
    return w


class N3F0PinnedReadOnlySession:
    """Owns existing roots + lifetime-exclusive lock FD until close().

    A successful report is METADATA ONLY.  `close` is mandatory, no API grant.
    The caller's control/parent/workspace FDs are borrowed, never closed here.
    Neither the source file nor this object registers with WorkspaceService.
    """
    def __init__(self, port: FDPort, owned: list[int], report: N3F0PhysicalSnapshot):
        self._port, self._owned, self.report = port, owned, report
        self.closed = False

    def close(self) -> None:
        if not self.closed:
            self.closed = True
            while self._owned:
                self._port.close(self._owned.pop())

    def __enter__(self) -> N3F0PinnedReadOnlySession:
        if self.closed:
            raise N3F0PhysicalDenied("closed_session")
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    @classmethod
    def open_existing(cls, *, port: FDPort, trusted_control_fd: int,
                      state_parent_fd: int, lineage_parent_fd: int,
                      workspace_root_fds: tuple[int, ...]) -> N3F0PinnedReadOnlySession:
        """No path input, no create; never used in current T0/production.

        Requires distinct pinned parent FDs under trusted private control root.
        The prior N3-D candidate has *sibling roots with the same parent*;
        that layout is conservatively rejected pending independent design
        resolution. This source DOES NOT silently turn T0 fake ancestry into
        real qualified provenance.
        """
        owned: list[int] = []
        try:
            if (type(workspace_root_fds) is not tuple or
                    not 1 <= len(workspace_root_fds) <= 16 or
                    any(type(fd) is not int or fd < 0 for fd in
                        (trusted_control_fd, state_parent_fd, lineage_parent_fd,
                         *workspace_root_fds))):
                raise N3F0PhysicalDenied("missing_trusted_scope")
            uid = port.euid()
            if type(uid) is not int or uid < 0:
                raise N3F0PhysicalDenied("invalid_owner")
            anchor = port.fstat(trusted_control_fd)
            state_parent = port.fstat(state_parent_fd)
            lineage_parent = port.fstat(lineage_parent_fd)
            for item in (anchor, state_parent, lineage_parent):
                _private(item, uid, directory=True)
            control_id = _id(anchor)
            control_chain = _chain(port, trusted_control_fd)
            parent_a = _chain(port, state_parent_fd)
            parent_b = _chain(port, lineage_parent_fd)
            _separate(parent_a, parent_b, control_id)
            if _id(state_parent) == _id(lineage_parent):
                raise N3F0PhysicalDenied("lineage_not_independent")
            for ws in workspace_root_fds:
                wchain = _chain(port, ws)
                for candidate in (control_chain, parent_a, parent_b):
                    if wchain[-1] in candidate or candidate[-1] in wchain:
                        raise N3F0PhysicalDenied("workspace_overlap")
            state_fd = port.open_directory("native-n3-state", state_parent_fd)
            owned.append(state_fd)
            lineage_fd = port.open_directory("native-n3-lineage", lineage_parent_fd)
            owned.append(lineage_fd)
            state_st = port.fstat(state_fd)
            lineage_st = port.fstat(lineage_fd)
            _private(state_st, uid, directory=True)
            _private(lineage_st, uid, directory=True)
            state_chain = _chain(port, state_fd)
            lineage_chain = _chain(port, lineage_fd)
            _separate(state_chain, lineage_chain, control_id)
            if (state_chain[-2] != _id(state_parent) or
                    lineage_chain[-2] != _id(lineage_parent)):
                raise N3F0PhysicalDenied("unverified_ancestry")
            for ws in workspace_root_fds:
                wchain = _chain(port, ws)
                for candidate in (state_chain, lineage_chain):
                    if wchain[-1] in candidate or candidate[-1] in wchain:
                        raise N3F0PhysicalDenied("workspace_overlap")
            names_a = port.names(state_fd, _MAX_ENTRIES+1)
            names_b = port.names(lineage_fd, _MAX_ENTRIES+1)
            if (len(names_a) > _MAX_ENTRIES or len(names_b) > _MAX_ENTRIES or
                    len(names_a) != len(set(names_a)) or
                    len(names_b) != len(set(names_b)) or
                    set(names_a) != _STATE_NAMES or
                    set(names_b) != _LINEAGE_NAMES):
                raise N3F0PhysicalDenied("unresolved_directory_entry")
            lock_fd = port.open_file("owner.lock", state_fd)
            owned.append(lock_fd)
            lock_st = port.fstat(lock_fd)
            _private(lock_st, uid, directory=False)
            identities = (control_id, _id(state_parent), _id(lineage_parent),
                          _id(state_st), _id(lineage_st), _id(lock_st))
            if len(set(identities)) != len(identities):
                raise N3F0PhysicalDenied("inode_alias")
            if _id(lock_st) in state_chain or _id(lock_st) in lineage_chain:
                raise N3F0PhysicalDenied("lock_alias")
            port.exclusive_lock(lock_fd)
            if _id(port.named_stat("owner.lock", state_fd)) != _id(lock_st):
                raise N3F0PhysicalDenied("owner_lock_replaced")
            if (stat.S_ISREG(port.named_stat("owner.lock", state_fd).st_mode)
                    is False):
                raise N3F0PhysicalDenied("owner_lock_replaced")
            ctrl = cls._read_regular(port, state_fd, "control.v1", uid)
            witness = cls._read_regular(port, lineage_fd,
                                        "provision-witness.v1", uid)
            # The operator authority file exists but is NOT treated as a
            # transferable trust token or as permission to first-provision.
            cls._read_regular(port, lineage_fd, "owner-authority.v1", uid)
            for dirname, fd in (("attempts", state_fd),
                                ("responses", state_fd)):
                child = port.open_directory(dirname, fd)
                try:
                    _private(port.fstat(child), uid, directory=True)
                    if port.names(child, _MAX_ENTRIES+1):
                        raise N3F0PhysicalDenied("unresolved_attempt")
                finally:
                    port.close(child)
            c = _strict_control(ctrl)
            w = _strict_witness(witness)
            if (c["namespace_id"] != w["namespace_id"] or
                    c["lineage_generation"] != w["lineage_generation"] or
                    c["state_generation"] != w["state_generation"] or
                    (c["owner_lock_dev"], c["owner_lock_ino"]) != _id(lock_st)):
                raise N3F0PhysicalDenied("lineage_mismatch")
            # Final immutable-object and parent identity checks prior to
            # yielding a metadata-only session. No new retry on disagreement.
            for fd, original in ((trusted_control_fd, anchor),
                                 (state_parent_fd, state_parent),
                                 (lineage_parent_fd, lineage_parent),
                                 (state_fd, state_st), (lineage_fd, lineage_st),
                                 (lock_fd, lock_st)):
                if _id(port.fstat(fd)) != _id(original):
                    raise N3F0PhysicalDenied("pinned_object_changed")
            if (_id(port.named_stat("owner.lock", state_fd)) != _id(lock_st) or
                    port.names(state_fd, _MAX_ENTRIES+1) != names_a or
                    port.names(lineage_fd, _MAX_ENTRIES+1) != names_b):
                raise N3F0PhysicalDenied("concurrent_mutation")
            # A well-formed self-described witness and an existing offline
            # authority file are NOT independently attested operator history.
            # Keep metadata UNAVAILABLE; qualification requires a separately
            # approved trusted authority source and actual physical T1.
            return cls(port, owned, N3F0PhysicalSnapshot())
        except (OSError, ValueError, TypeError, N3F0PhysicalDenied) as exc:
            while owned:
                try:
                    port.close(owned.pop())
                except OSError:
                    pass
            if isinstance(exc, N3F0PhysicalDenied):
                raise
            raise N3F0PhysicalDenied("private_fs_unavailable") from exc

    @staticmethod
    def _read_regular(port: FDPort, dir_fd: int, name: str, uid: int) -> bytes:
        fd = port.open_file(name, dir_fd)
        try:
            before = port.fstat(fd)
            _private(before, uid, directory=False)
            if before.st_size > _MAX_OBJECT_BYTES:
                raise N3F0PhysicalDenied("private_record_too_large")
            raw = port.bytes_from(fd, _MAX_OBJECT_BYTES)
            after = port.fstat(fd)
            if (_id(before) != _id(after) or
                    before.st_size != after.st_size or
                    _id(port.named_stat(name, dir_fd)) != _id(before)):
                raise N3F0PhysicalDenied("private_record_race")
            return raw
        finally:
            port.close(fd)
