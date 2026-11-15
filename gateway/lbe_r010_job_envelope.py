"""R010 create-once Job envelope: real durable filesystem mechanics, no Exec.

This is the PREEXEC_HOLD state-construction candidate after an explicit A1+B1
Owner design choice. It does NOT authenticate a GitHub Job, verify a JWT,
grant authority, import WorkspaceService, or launch a child. Only a future
independently reviewed trusted PREEXEC may call the fixed-anchor entrypoint.
An existing, uncertain, crashed, or changed envelope is NEVER adopted.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
import re
import stat
import sys
import threading
import time

_REPO = "chinanjjohn2012/mac-file-gateway"
_DESIGN_ID = "MWE-LBE-R010-AUTHORITY-CHAIN-DESIGN-013-CANDIDATE"
_DESIGN_BLOB = "f57e39543a6fe3d64fe99b8669fc7da854b93a64"
_OWNER_CHOICE_COMMENT = 6740275850
_STATE_DOMAIN = "R010_EPHEMERAL_JOB_STATE_V1"
_SHA40 = re.compile(r"[0-9a-f]{40}\Z", re.ASCII)
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}\Z", re.ASCII)
_ASCII_POSITIVE = re.compile(r"[1-9][0-9]{0,11}\Z", re.ASCII)
_CREATED = (os.O_WRONLY | os.O_CREAT | os.O_EXCL
            | os.O_NOFOLLOW | os.O_CLOEXEC)
_DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


class R010JobEnvelopeDenied(ValueError):
    """Job envelope cannot safely be created, retained, or reused."""


def canonical_run_attempt(value: str) -> int:
    if type(value) is not str or _ASCII_POSITIVE.fullmatch(value) is None:
        raise R010JobEnvelopeDenied("invalid canonical GitHub run attempt")
    return int(value)


@dataclass(frozen=True, slots=True)
class R010JobKey:
    """Source format only: caller-supplied fields are NOT provider evidence."""

    repo: str
    pr: int
    workflow_id: int
    workflow_path: str
    workflow_ref: str
    run_id: int
    run_attempt: int
    check_run_id: int
    job_name: str
    head_sha: str
    design_id: str
    design_blob: str
    owner_choice_comment_id: int
    host_option: str
    review_sequence_option: str
    state_domain: str

    def checked(self) -> "R010JobKey":
        if (type(self.repo) is not str or self.repo != _REPO
                or type(self.pr) is not int or self.pr != 114
                or self.design_id != _DESIGN_ID
                or self.design_blob != _DESIGN_BLOB
                or type(self.owner_choice_comment_id) is not int
                or self.owner_choice_comment_id != _OWNER_CHOICE_COMMENT
                or self.host_option != "A1"
                or self.review_sequence_option != "B1"
                or self.state_domain != _STATE_DOMAIN):
            raise R010JobEnvelopeDenied("unqualified design or owner option")
        for value in (self.workflow_id, self.run_id, self.run_attempt,
                      self.check_run_id):
            if type(value) is not int or not 1 <= value <= 2**63 - 1:
                raise R010JobEnvelopeDenied("unqualified current Job identity")
        if type(self.head_sha) is not str or _SHA40.fullmatch(self.head_sha) is None:
            raise R010JobEnvelopeDenied("invalid implementation Head")
        if type(self.job_name) is not str or _NAME.fullmatch(self.job_name) is None:
            raise R010JobEnvelopeDenied("invalid GitHub Job name")
        for value in (self.workflow_path, self.workflow_ref):
            if (type(value) is not str or not 1 <= len(value) <= 240
                    or any(ord(c) < 33 or ord(c) > 126 for c in value)
                    or "\\" in value or ".." in value):
                raise R010JobEnvelopeDenied("unsafe workflow identity")
        if not self.workflow_path.startswith(".github/workflows/"):
            raise R010JobEnvelopeDenied("unreviewed workflow path")
        if not self.workflow_ref.startswith(
                _REPO + "/.github/workflows/"):
            raise R010JobEnvelopeDenied("unreviewed workflow reference")
        return self

    def key_sha256(self) -> str:
        self.checked()
        # Exact R009 canonical Job fields. Never accepts config/REST roots.
        values = ("r009-job-envelope-v1", self.repo, str(self.pr),
                  str(self.workflow_id), self.workflow_path, self.workflow_ref,
                  str(self.run_id), str(self.run_attempt),
                  str(self.check_run_id), self.job_name, self.head_sha)
        return hashlib.sha256(("\n".join(values) + "\n").encode("ascii")).hexdigest()


def _checked_private_dir(fd: int) -> tuple[int, int, int, int]:
    if type(fd) is not int or fd < 0:
        raise R010JobEnvelopeDenied("missing private descriptor")
    try:
        st = os.fstat(fd)
    except OSError:
        raise R010JobEnvelopeDenied("unavailable private directory") from None
    if (not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid()
            or stat.S_IMODE(st.st_mode) != 0o700):
        raise R010JobEnvelopeDenied("unsafe private directory identity")
    return st.st_dev, st.st_ino, st.st_uid, st.st_mode


def _write_once(dir_fd: int, name: str, payload: bytes) -> None:
    if (type(payload) is not bytes or not 1 <= len(payload) <= 8192
            or type(name) is not str or _NAME.fullmatch(name) is None):
        raise R010JobEnvelopeDenied("invalid durable record")
    fd = None
    try:
        fd = os.open(name, _CREATED, 0o600, dir_fd=dir_fd)
        st = os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid()
                or st.st_nlink != 1 or stat.S_IMODE(st.st_mode) != 0o600):
            raise R010JobEnvelopeDenied("unsafe exclusive journal record")
        at = 0
        while at != len(payload):
            count = os.write(fd, payload[at:])
            if count <= 0:
                raise R010JobEnvelopeDenied("incomplete durable record")
            at += count
        os.fsync(fd)
        os.fsync(dir_fd)
    except (OSError, R010JobEnvelopeDenied):
        raise R010JobEnvelopeDenied("exclusive durable write failed") from None
    finally:
        if fd is not None:
            os.close(fd)


def _new_private_directory(parent_fd: int, name: str) -> int:
    try:
        os.mkdir(name, 0o700, dir_fd=parent_fd)
        fd = os.open(name, _DIRECTORY, dir_fd=parent_fd)
    except OSError:
        raise R010JobEnvelopeDenied("create-once directory unavailable") from None
    try:
        _checked_private_dir(fd)
        os.fsync(parent_fd)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _fixed_macos_anchor_fd() -> int:
    """Check the R009 fixed platform anchor, not a user-provided path."""
    if sys.platform != "darwin":
        raise R010JobEnvelopeDenied("R010 positive anchor is Darwin-only")
    opened = []
    try:
        for path in ("/", "/private", "/private/tmp"):
            fd = os.open(path, _DIRECTORY)
            opened.append(fd)
            st = os.fstat(fd)
            if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0:
                raise R010JobEnvelopeDenied("untrusted platform ancestor")
            mode = stat.S_IMODE(st.st_mode)
            if path == "/private/tmp":
                if mode != 0o1777:
                    raise R010JobEnvelopeDenied("noncanonical platform anchor")
            elif mode & 0o022:
                raise R010JobEnvelopeDenied("writable platform ancestor")
        return os.dup(opened[-1])
    except OSError:
        raise R010JobEnvelopeDenied("fixed macOS anchor inaccessible") from None
    finally:
        for fd in opened:
            os.close(fd)


class R010CreatedJobEnvelope:
    """Only creates a fresh PREEXEC root; never returns an Exec capability.

    The lifetime-held root/journal descriptors are source candidates for later
    reviewed Job provenance and six-row operations. No existing-root reopen,
    read-only adoption, cleanup, grant, or Popen is provided here.
    """

    def __init__(self, marker: object, *, root_fd: int, journal_fd: int,
                 anchor_fd: int, anchor_identity: tuple[int, ...],
                 root_name: str, key: R010JobKey, secret_sha256: str,
                 instance_sha256: str, root_identity: tuple[int, ...],
                 journal_identity: tuple[int, ...]):
        if marker is not _CREATOR_MARKER:
            raise R010JobEnvelopeDenied("cannot fabricate a Job envelope")
        self._anchor_fd = anchor_fd
        self._anchor_identity = anchor_identity
        self._root_fd = root_fd
        self._journal_fd = journal_fd
        self._root_name = root_name
        self._key = key
        self._secret_sha256 = secret_sha256
        self._instance_sha256 = instance_sha256
        self._root_identity = root_identity
        self._journal_identity = journal_identity
        self._pid = os.getpid()
        self._closed = False
        self._lock = threading.Lock()

    def _require_live(self) -> None:
        if self._closed or os.getpid() != self._pid:
            raise R010JobEnvelopeDenied("envelope is closed or inherited")
        if (_checked_private_dir(self._root_fd) != self._root_identity
                or _checked_private_dir(self._journal_fd)
                != self._journal_identity):
            raise R010JobEnvelopeDenied("Job root or journal changed")
        try:
            anchor = os.fstat(self._anchor_fd)
            if ((anchor.st_dev, anchor.st_ino, anchor.st_uid, anchor.st_mode)
                    != self._anchor_identity):
                raise R010JobEnvelopeDenied("pinned Job anchor changed")
            root_entry = os.stat(
                self._root_name, dir_fd=self._anchor_fd,
                follow_symlinks=False)
            journal_entry = os.stat(
                "command-journal", dir_fd=self._root_fd,
                follow_symlinks=False)
            if ((root_entry.st_dev, root_entry.st_ino, root_entry.st_uid,
                 root_entry.st_mode) != self._root_identity
                    or (journal_entry.st_dev, journal_entry.st_ino,
                        journal_entry.st_uid, journal_entry.st_mode)
                    != self._journal_identity):
                raise R010JobEnvelopeDenied("Job path entry replaced")
        except OSError:
            raise R010JobEnvelopeDenied("Job path entry unavailable") from None

    def snapshot(self) -> dict[str, object]:
        """Public diagnostic hashes only; never expose local secrets."""
        with self._lock:
            self._require_live()
            return {
                "status": "JOB_PREEXEC_HOLD",
                "design_blob": _DESIGN_BLOB,
                "job_envelope_key": self._key.key_sha256(),
                "envelope_root_name": self._root_name,
                "job_local_secret_sha256": self._secret_sha256,
                "service_instance_nonce_sha256": self._instance_sha256,
                "state_domain": _STATE_DOMAIN,
                "native_launch_allowed": False,
                "provider_verified": False,
                "owner_product_t1_grant_verified": False,
            }

    def latch_failure(self, reason_code: str) -> None:
        """Durably latch PREEXEC failure; any fault leaves this Job consumed."""
        if (type(reason_code) is not str or
                _NAME.fullmatch(reason_code) is None):
            raise R010JobEnvelopeDenied("unqualified failure code")
        with self._lock:
            self._require_live()
            payload = (json.dumps(
                {"status": "JOB_FAILED_LATCHED", "reason": reason_code},
                sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
            _write_once(self._journal_fd, "latch-failure.json", payload)
            self._closed = True
            os.close(self._journal_fd)
            os.close(self._root_fd)
            os.close(self._anchor_fd)

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._closed = True
                os.close(self._journal_fd)
                os.close(self._root_fd)
                os.close(self._anchor_fd)

    def __enter__(self) -> "R010CreatedJobEnvelope":
        return self

    def __exit__(self, *_ignored: object) -> None:
        self.close()


_CREATOR_MARKER = object()
_FIXED_ANCHOR_MARKER = object()


def _create_once_in_pinned_anchor(anchor_fd: int, key: R010JobKey,
                                  *, _fixed_marker: object = None
                                  ) -> R010CreatedJobEnvelope:
    """Low-level create-only fd mechanics, used by safe disposable T0.

    The input FD alone is NOT evidence of a current signed GitHub Job or
    qualified host; this function is NOT wired into any positive path.
    The future trusted production PREEXEC must independently validate both.
    """
    if type(key) is not R010JobKey:
        raise R010JobEnvelopeDenied("missing exact Job key type")
    key.checked()
    if type(anchor_fd) is not int or anchor_fd < 0:
        raise R010JobEnvelopeDenied("unqualified anchor descriptor")
    try:
        anchor = os.fstat(anchor_fd)
        if not stat.S_ISDIR(anchor.st_mode):
            raise R010JobEnvelopeDenied("unqualified anchor")
        if _fixed_marker is _FIXED_ANCHOR_MARKER:
            if (anchor.st_uid != 0
                    or stat.S_IMODE(anchor.st_mode) != 0o1777):
                raise R010JobEnvelopeDenied("wrong fixed platform anchor")
        elif (anchor.st_uid != os.getuid()
              or stat.S_IMODE(anchor.st_mode) != 0o700):
            raise R010JobEnvelopeDenied("unqualified private T0 anchor")
    except OSError:
        raise R010JobEnvelopeDenied("unavailable anchor") from None
    name = "mfg-r009-job-" + key.key_sha256()
    root_fd = None
    journal_fd = None
    retained_anchor_fd = None
    successful = False
    # mkdir O_EXCL-like create-once is atomic even across processes. Never
    # unlink root on any failure, regardless of whether lease was written.
    try:
        retained_anchor_fd = os.dup(anchor_fd)
        root_fd = _new_private_directory(retained_anchor_fd, name)
        config_fd = _new_private_directory(root_fd, "service-config")
        os.close(config_fd)
        state_fd = _new_private_directory(root_fd, "exec-state")
        os.close(state_fd)
        journal_fd = _new_private_directory(root_fd, "command-journal")
        root_identity = _checked_private_dir(root_fd)
        journal_identity = _checked_private_dir(journal_fd)
        local_secret = os.urandom(32)
        instance_nonce = os.urandom(32)
        lease = {
            "version": "R010_CREATE_ONCE_JOB_LEASE_V1",
            "state_domain": _STATE_DOMAIN,
            "design_id": _DESIGN_ID,
            "design_blob": _DESIGN_BLOB,
            "owner_choice_comment_id": _OWNER_CHOICE_COMMENT,
            "job": {
                field: getattr(key, field)
                for field in R010JobKey.__dataclass_fields__
            },
            "root_dev": root_identity[0],
            "root_ino": root_identity[1],
            "journal_dev": journal_identity[0],
            "journal_ino": journal_identity[1],
            "created_unix": int(time.time()),
            "job_local_secret_hex": local_secret.hex(),
            "service_instance_nonce_hex": instance_nonce.hex(),
            "native_launch_allowed": False,
        }
        lease_bytes = (json.dumps(lease, sort_keys=True, separators=(",", ":"))
                       + "\n").encode("ascii")
        _write_once(root_fd, "job-lease.json", lease_bytes)
        _write_once(
            journal_fd, "row-state.json",
            (json.dumps({
                "state": "JOB_PREEXEC_HOLD", "expected_row": 1,
                "rows": ["ROW_NOT_RUN"] * 6, "native_launch_allowed": False,
            }, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii"))
        os.fsync(journal_fd)
        os.fsync(root_fd)
        envelope = R010CreatedJobEnvelope(
            _CREATOR_MARKER, root_fd=root_fd, journal_fd=journal_fd,
            anchor_fd=retained_anchor_fd,
            anchor_identity=(anchor.st_dev, anchor.st_ino,
                             anchor.st_uid, anchor.st_mode),
            root_name=name, key=key,
            secret_sha256=hashlib.sha256(local_secret).hexdigest(),
            instance_sha256=hashlib.sha256(instance_nonce).hexdigest(),
            root_identity=root_identity, journal_identity=journal_identity)
        successful = True
        return envelope
    except (OSError, R010JobEnvelopeDenied):
        raise R010JobEnvelopeDenied(
            "Job envelope already exists or durable creation failed") from None
    finally:
        if not successful:
            if journal_fd is not None:
                os.close(journal_fd)
            if root_fd is not None:
                os.close(root_fd)
            if retained_anchor_fd is not None:
                os.close(retained_anchor_fd)


def create_only_under_fixed_macos_anchor(key: R010JobKey
                                         ) -> R010CreatedJobEnvelope:
    """Fixed platform-root creation only; NOT a provider or T1 grant.

    Never use this directly from REST/MCP/config. Only a future reviewed
    provider-authenticated PREEXEC may invoke it in the one current Job.
    """
    anchor = _fixed_macos_anchor_fd()
    try:
        return _create_once_in_pinned_anchor(
            anchor, key, _fixed_marker=_FIXED_ANCHOR_MARKER)
    finally:
        os.close(anchor)
