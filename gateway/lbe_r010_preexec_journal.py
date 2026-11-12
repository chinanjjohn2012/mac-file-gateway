"""R010 A1 exact source PREEXEC record in the original one-use Job lease.

This is a SOURCE-only preparatory record, not a real signed GitHub Job or
Owner PRODUCT_T1 grant. It stores no raw JWT/bearer/socket path, only exact
digest identities, and is checked again before each Worker boundary.
The record is created exactly once with O_EXCL/0600/fsync by the existing
R010CreatedJobEnvelope. A crash or partial write makes the Job unusable.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
import stat

from .lbe_r010_a1_host import R010A1ClosedPreexecSource, R010A1HostSource
from .lbe_r010_job_envelope import (
    R010CreatedJobEnvelope, R010JobEnvelopeDenied, R010JobKey, _write_once,
)
from .lbe_r010_preexec_source import R010PreexecSourceObservation

_RECORD = "r010-preexec-original-source.json"
_HELPER = ("HOME", "LANG", "LC_ALL", "PATH", "TMPDIR")


class R010PreexecSealDenied(ValueError):
    """The source PREEXEC record cannot qualify any later Job transition."""


@dataclass(frozen=True, slots=True)
class R010PreexecSourceSeal:
    job_key_sha256: str
    original_jwt_sha256: str
    helper_env_sha256: str
    mount_sha256: str
    record_sha256: str
    record_identity: tuple[int, ...]
    status: str = "PREEXEC_SOURCE_RECORDED_NO_NATIVE_T1"
    provider_runtime_authenticated: bool = False
    owner_product_t1_grant_verified: bool = False
    native_launch_allowed: bool = False


def _inode_id(st: os.stat_result) -> tuple[int, ...]:
    return (
        st.st_dev, st.st_ino, st.st_uid, st.st_nlink,
        st.st_mode, st.st_size, st.st_mtime_ns, st.st_ctime_ns,
    )


def _hex64(value: object) -> bool:
    return (type(value) is str and len(value) == 64
            and all(c in "0123456789abcdef" for c in value))


def _record_bytes(
    key: R010JobKey,
    preexec: R010PreexecSourceObservation,
    host: R010A1HostSource,
    closed: R010A1ClosedPreexecSource,
) -> bytes:
    if (type(key) is not R010JobKey
            or type(preexec) is not R010PreexecSourceObservation
            or type(host) is not R010A1HostSource
            or type(closed) is not R010A1ClosedPreexecSource):
        raise R010PreexecSealDenied("wrong source PREEXEC object identity")
    try:
        key.checked()
    except (TypeError, ValueError):
        raise R010PreexecSealDenied("unqualified canonical Job key") from None
    if (preexec.status !=
            "PREEXEC_SOURCE_ONLY_NONOPERATIVE_NOT_PROVIDER_ATTESTED"
            or preexec.native_launch_allowed is not False
            or preexec.signed_provider_job_live is not False
            or preexec.owner_product_t1_grant_verified is not False
            or preexec.full_code_review_pass is not False
            or preexec.six_command_product_t1_pass is not False
            or preexec.design_blob != key.design_blob
            or preexec.owner_choice_comment_id != key.owner_choice_comment_id
            or preexec.job_envelope_key_sha256 != key.key_sha256()
            or preexec.full_darwin_mount_table_sha256
               != host.mount_table_sha256
            or preexec.full_darwin_mount_table_sha256
               != closed.mount_table_sha256
            or preexec.helper_keys != _HELPER
            or preexec.helper_env_sha256 != closed.helper_env_sha256
            or host.status != "R010_A1_HOST_SOURCE_ONLY_NO_PRODUCT_T1"
            or host.native_launch_allowed is not False
            or host.current_provider_job_authenticated is not False
            or host.owner_product_t1_grant_verified is not False
            or host.no_ambient_ssh_agent_proven is not False
            or host.no_shared_writable_mounts_proven is not False
            or host.full_boot_image_attested is not False
            or host.head_sha != key.head_sha
            or host.run_id != str(key.run_id)
            or host.run_attempt != str(key.run_attempt)
            or host.job_name != key.job_name
            or host.ssh_selector_observed is not True
            or closed.status !=
                "R010_A1_SOURCE_ONLY_SCRUBBED_NOT_LIVE_PREEXEC"
            or closed.native_launch_allowed is not False
            or closed.live_oidc_token_requested is not False
            or closed.ssh_agent_protocol_called is not False
            or closed.verified_current_provider_job is not False
            or closed.head_sha != key.head_sha
            or closed.run_id != str(key.run_id)
            or closed.helper_keys != _HELPER
            or closed.child_keys != _HELPER
            or not all(_hex64(v) for v in (
                preexec.oidc_original_jwt_sha256,
                preexec.helper_env_sha256,
                preexec.full_darwin_mount_table_sha256,
                host.host_source_sha256))):
        raise R010PreexecSealDenied("PREEXEC/Job/host source identity mismatch")
    record = {
        "version": "R010_ONE_USE_PREEXEC_SOURCE_V1",
        "job_key_sha256": key.key_sha256(),
        "design_blob": preexec.design_blob,
        "owner_design_choice_comment_id": preexec.owner_choice_comment_id,
        "original_jwt_sha256": preexec.oidc_original_jwt_sha256,
        "mount_table_sha256": preexec.full_darwin_mount_table_sha256,
        "host_selected_source_sha256": host.host_source_sha256,
        "original_host_source_observed": host.host_snapshot_from_original_os,
        "helper_env_sha256": preexec.helper_env_sha256,
        "source_model_only": True,
        "live_provider_job_verified": False,
        "live_owner_t1_grant_verified": False,
        "native_launch_allowed": False,
    }
    return (json.dumps(
        record, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True) + "\n").encode("ascii")


def seal_r010_preexec_source_in_job(
    *, envelope: R010CreatedJobEnvelope, job_key: R010JobKey,
    preexec: R010PreexecSourceObservation,
    host: R010A1HostSource, closed: R010A1ClosedPreexecSource,
) -> R010PreexecSourceSeal:
    """Persist one noncredential PREEXEC receipt before source row burn."""
    if type(envelope) is not R010CreatedJobEnvelope:
        raise R010PreexecSealDenied("not canonical Job envelope")
    raw = _record_bytes(job_key, preexec, host, closed)
    with envelope._lock:
        try:
            envelope._require_live()
            if (envelope._key != job_key
                    or getattr(envelope, "_r010_preexec_source_claimed", False)
                    or getattr(envelope, "_r010_source_service_claimed", False)):
                raise R010PreexecSealDenied(
                    "original PREEXEC source already sealed or Job changed")
            envelope._r010_preexec_source_claimed = True
            _write_once(envelope._journal_fd, _RECORD, raw)
            # Pin the actual durable inode, not only a caller-provided
            # digest. Even a same-byte replacement must fail later.
            source_fd = -1
            try:
                source_fd = os.open(
                    _RECORD, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
                    | os.O_NONBLOCK, dir_fd=envelope._journal_fd)
                st = os.fstat(source_fd)
                if (not stat.S_ISREG(st.st_mode)
                        or st.st_uid != os.getuid() or st.st_nlink != 1
                        or stat.S_IMODE(st.st_mode) != 0o600
                        or st.st_size != len(raw)
                        or os.read(source_fd, len(raw) + 1) != raw
                        or _inode_id(st) != _inode_id(os.fstat(source_fd))):
                    raise R010PreexecSealDenied(
                        "new PREEXEC original inode not stable")
                original_inode = _inode_id(st)
            finally:
                if source_fd >= 0:
                    os.close(source_fd)
        except R010JobEnvelopeDenied:
            # No retry after O_EXCL/fync/partial write ambiguity.
            raise R010PreexecSealDenied(
                "uncertain PREEXEC source write; permanent deny") from None
        except (OSError, ValueError, TypeError):
            raise R010PreexecSealDenied(
                "original PREEXEC source identity uncertain; deny") from None
    return R010PreexecSourceSeal(
        job_key_sha256=job_key.key_sha256(),
        original_jwt_sha256=preexec.oidc_original_jwt_sha256,
        helper_env_sha256=preexec.helper_env_sha256,
        mount_sha256=preexec.full_darwin_mount_table_sha256,
        record_sha256=hashlib.sha256(raw).hexdigest(),
        record_identity=original_inode,
    )


def recheck_r010_sealed_preexec_source_locked(
    *, envelope: R010CreatedJobEnvelope, job_key: R010JobKey,
    preexec: R010PreexecSourceObservation, seal: R010PreexecSourceSeal,
    host: R010A1HostSource, closed: R010A1ClosedPreexecSource,
) -> None:
    """Read original pinned 0600 bytes while caller holds Job envelope lock.

    No file/path/body provided by a REST/MCP caller can substitute for the
    private dir_fd or the expected exact record. This stays nonoperative.
    """
    if (type(envelope) is not R010CreatedJobEnvelope
            or type(seal) is not R010PreexecSourceSeal
            or seal.status != "PREEXEC_SOURCE_RECORDED_NO_NATIVE_T1"
            or seal.provider_runtime_authenticated is not False
            or seal.owner_product_t1_grant_verified is not False
            or seal.native_launch_allowed is not False
            or not getattr(envelope, "_r010_preexec_source_claimed", False)
            or envelope._key != job_key):
        raise R010PreexecSealDenied("missing exact original PREEXEC seal")
    raw = _record_bytes(job_key, preexec, host, closed)
    digest = hashlib.sha256(raw).hexdigest()
    if (seal.job_key_sha256 != job_key.key_sha256()
            or seal.original_jwt_sha256 != preexec.oidc_original_jwt_sha256
            or seal.helper_env_sha256 != preexec.helper_env_sha256
            or seal.mount_sha256 != preexec.full_darwin_mount_table_sha256
            or seal.record_sha256 != digest):
        raise R010PreexecSealDenied("PREEXEC seal source tuple changed")
    fd = -1
    try:
        envelope._require_live()
        fd = os.open(
            _RECORD, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
            | os.O_NONBLOCK, dir_fd=envelope._journal_fd)
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode)
                or before.st_uid != os.getuid()
                or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) != 0o600
                or not 1 <= before.st_size <= 8192):
            raise R010PreexecSealDenied("unsafe original PREEXEC record inode")
        observed = os.read(fd, before.st_size + 1)
        after = os.fstat(fd)
        identity = lambda st: (
            st.st_dev, st.st_ino, st.st_uid, st.st_nlink, st.st_mode,
            st.st_size, st.st_mtime_ns, st.st_ctime_ns)
        if (observed != raw or identity(before) != identity(after)
                or identity(before) != seal.record_identity
                or len(observed) != before.st_size):
            raise R010PreexecSealDenied("PREEXEC original record bytes drift")
    except (OSError, ValueError, TypeError):
        raise R010PreexecSealDenied("PREEXEC original source unavailable") from None
    finally:
        if fd >= 0:
            os.close(fd)
