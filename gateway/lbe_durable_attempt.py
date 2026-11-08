"""R006 durable *consumption* witness for a separately approved owner grant.

This module never signs grants, checks GitHub identity, authorizes T1, or calls
Popen. The service must independently verify a genuine owner approval and
bind its already-owner-locked private state directory BEFORE using consume().
A consumed or uncertain nonce is never released, even on cancellation or
process restart. Ordinary public F1/NativeLauncher denial is unchanged.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
import re
import stat
import threading

_SHA = re.compile(r"[0-9a-f]{64}\Z")
_SHA40 = re.compile(r"[0-9a-f]{40}\Z")
_WORKSPACE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_CREATED = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
_MAX_RECORD = 2048


class D4DurableAttemptDenied(ValueError):
    """The attempt cannot safely become a new executable admission."""


@dataclass(frozen=True, slots=True)
class D4AttemptIdentity:
    """Exact R006 binding, not evidence of independent owner approval."""

    nonce: str
    run_id: int
    run_attempt: int
    repo: str
    pr: int
    base_sha: str
    head_sha: str
    head_tree: str
    manifest_sha256: str
    r006_design_blob: str
    source_fingerprint: str
    runner_fingerprint: str
    workspace: str
    command_fingerprint: str

    def checked(self) -> "D4AttemptIdentity":
        # Type checks precede formatting/equality to avoid hostile subclasses.
        for name in ("nonce", "manifest_sha256", "source_fingerprint",
                     "runner_fingerprint", "command_fingerprint"):
            value = getattr(self, name)
            if type(value) is not str or _SHA.fullmatch(value) is None:
                raise D4DurableAttemptDenied("malformed attempt " + name)
        for name in ("base_sha", "head_sha", "head_tree", "r006_design_blob"):
            value = getattr(self, name)
            if type(value) is not str or _SHA40.fullmatch(value) is None:
                raise D4DurableAttemptDenied("malformed attempt " + name)
        if (self.r006_design_blob
                != "b8d8a1cb32fb7130dfa6d00b37831dfddfaad11c"):
            raise D4DurableAttemptDenied("wrong fixed R006 design identity")
        for name in ("run_id", "run_attempt", "pr"):
            value = getattr(self, name)
            if type(value) is not int or not 1 <= value <= 2**63 - 1:
                raise D4DurableAttemptDenied("malformed attempt " + name)
        if (type(self.repo) is not str
                or self.repo != "chinanjjohn2012/mac-file-gateway"
                or type(self.workspace) is not str
                or _WORKSPACE.fullmatch(self.workspace) is None):
            raise D4DurableAttemptDenied("unqualified repository/workspace")
        return self


class D4DurableAttemptJournal:
    """Append-only one-use attempt tombstones in an already secured directory.

    Directory FD must be supplied by an independently owner-locked private
    ExecStateStore, not chosen by a REST/MCP request or caller-controlled path.
    This is one prerequisite to authorization, NOT the authorization source.
    """

    def __init__(self, private_directory_fd: int):
        if type(private_directory_fd) is not int or private_directory_fd < 0:
            raise D4DurableAttemptDenied("invalid private journal FD")
        try:
            fd = os.dup(private_directory_fd)
            st = os.fstat(fd)
            if (not stat.S_ISDIR(st.st_mode)
                    or st.st_uid != os.getuid()
                    or stat.S_IMODE(st.st_mode) != 0o700):
                raise D4DurableAttemptDenied("untrusted private journal root")
        except OSError:
            raise D4DurableAttemptDenied("private journal unavailable") from None
        except BaseException:
            if "fd" in locals():
                os.close(fd)
            raise
        self._fd = fd
        self._identity = (st.st_dev, st.st_ino, st.st_uid, st.st_mode)
        self._pid = os.getpid()
        self._lock = threading.Lock()
        self._closed = False

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._closed = True
                os.close(self._fd)

    def __enter__(self) -> "D4DurableAttemptJournal":
        return self

    def __exit__(self, *_ignored: object) -> None:
        self.close()

    def _require_live(self) -> None:
        if self._closed or os.getpid() != self._pid:
            raise D4DurableAttemptDenied("journal is closed or forked")
        try:
            st = os.fstat(self._fd)
            if (st.st_dev, st.st_ino, st.st_uid, st.st_mode) != self._identity:
                raise D4DurableAttemptDenied("private journal identity drift")
        except OSError:
            raise D4DurableAttemptDenied("private journal unavailable") from None

    def consume(self, identity: D4AttemptIdentity) -> str:
        """Write a durable NONREUSABLE nonce before reservation/child IO.

        Returns a diagnostic digest, never a runnable capability. On ANY
        fault, including uncertain partial write/fsync, deny; never unlink or
        retry. O_EXCL is atomic across processes that share this pinned root.
        Crash safety assumes a persistent filesystem with working fsync and
        a trusted lock-owning bootstrap; volume loss/restore must deny.
        """
        if type(identity) is not D4AttemptIdentity:
            raise D4DurableAttemptDenied("attempt identity must be exact")
        checked = identity.checked()
        canonical = {
            name: getattr(checked, name) for name in D4AttemptIdentity.__dataclass_fields__
        }
        payload = (json.dumps(canonical, sort_keys=True,
                              separators=(",", ":"), ensure_ascii=True) + "\n").encode()
        if not 0 < len(payload) <= _MAX_RECORD:
            raise D4DurableAttemptDenied("oversized attempt")
        digest = hashlib.sha256(payload).hexdigest()
        filename = "d4-" + checked.nonce + ".json"
        with self._lock:
            self._require_live()
            created = None
            try:
                created = os.open(filename, _CREATED, 0o600, dir_fd=self._fd)
                st = os.fstat(created)
                if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1
                        or st.st_uid != os.getuid()
                        or stat.S_IMODE(st.st_mode) != 0o600):
                    raise D4DurableAttemptDenied("unsafe attempt tombstone")
                offset = 0
                while offset < len(payload):
                    amount = os.write(created, payload[offset:])
                    if amount <= 0:
                        raise D4DurableAttemptDenied("short journal write")
                    offset += amount
                os.fsync(created)
                os.fsync(self._fd)
            except (OSError, D4DurableAttemptDenied):
                raise D4DurableAttemptDenied(
                    "attempt already consumed or journal durability unavailable"
                ) from None
            finally:
                if created is not None:
                    os.close(created)
            return digest
