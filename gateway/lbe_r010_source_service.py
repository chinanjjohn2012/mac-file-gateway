"""R010 A1 one-Job source authority -> one WorkspaceService/Owner/Worker/Journal.

This first-party product-source bridge joins the *persisted* exact
Provider/Owner source record with the already-implemented private six-row
WorkspaceService/DirectChildOwner/Worker result capture. Every source
receipt is NONOPERATIVE: none authenticates an actual provider, PREEXEC
process, code review, or execution grant. No method calls native Popen or
makes a client-visible capability. Ordinary F1/NativeLauncher remain DENY.

The bridge and its journal are consumed once. A lost ACK, corrupt receipt,
cross-service object or failing finite result never creates a second Job.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
import stat
import threading
from typing import Any

from .lbe_r010_a1_host import (
    R010A1ClosedPreexecSource, R010A1HostSource,
)
from .lbe_r010_authority_source import R010AuthoritySourceBinding
from .lbe_r010_job_envelope import (
    R010CreatedJobEnvelope, R010JobEnvelopeDenied, R010JobKey, _write_once,
)
from .lbe_r010_private_capture import R010PrivateWorkerCapture
from .lbe_r010_preexec_source import R010PreexecSourceObservation
from .lbe_r010_preexec_journal import (
    R010PreexecSourceSeal, R010PreexecSealDenied,
    recheck_r010_sealed_preexec_source_locked,
)
from .lbe_r010_serial_journal import R010SerialNonceJournal
from .workspaces import WorkspaceContext, WorkspaceService

_SOURCE_RECORD = "r010-authority-source-binding.json"
_BRIDGE_RECORD = "r010-service-owner-source-bridge.json"
_HELPER_KEYS = ("HOME", "LANG", "LC_ALL", "PATH", "TMPDIR")
_HEX = frozenset("0123456789abcdef")
_MARKER = object()


class R010ServiceSourceDenied(ValueError):
    """A same-Job owner/Worker source transition was not qualified."""


@dataclass(frozen=True, slots=True)
class R010ServiceSourceStatus:
    job_key_sha256: str
    authority_source_sha256: str
    service_bridge_sha256: str
    current_source_model_next_row: int | None
    source_model_rows_completed: int
    failed: bool
    status: str = "SOURCE_BRIDGED_TO_OWNER_WORKER_JOURNAL_NOT_T1"
    host_runtime_authenticated: bool = False
    provider_runtime_authenticated: bool = False
    owner_runtime_authenticated: bool = False
    native_launch_allowed: bool = False
    six_command_product_t1_pass: bool = False


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha256(value: object) -> bool:
    return (type(value) is str and len(value) == 64
            and all(c in _HEX for c in value))


def _check_real_post_scrub_product_environment(
    host: R010A1HostSource, closed: R010A1ClosedPreexecSource,
) -> None:
    """A1 physical-host SOURCE claim requires the ACTUAL five-key OS map.

    Synthetic/source-only fixtures are intentionally not authenticated
    provider evidence. An actual-host candidate must not silently borrow
    the T0 helper key NAMES while the process still holds SSH/OIDC
    credential selectors. This is a live in-process environment check,
    not a proof of no other same-UID access or a native execution grant.
    """
    if host.host_snapshot_from_original_os is not True:
        return
    if not _sha256(closed.helper_env_sha256):
        raise R010ServiceSourceDenied(
            "no original five-key PREEXEC helper digest")
    current = dict(os.environ)
    if (frozenset(current) != frozenset(_HELPER_KEYS)
            or any(type(key) is not str or type(val) is not str
                   for key, val in current.items())
            or current.get("PATH") != "/usr/bin:/bin"
            or current.get("LANG") != "C"
            or current.get("LC_ALL") != "C"
            or any(
                not current.get(key, "").startswith("/")
                or ".." in current.get(key, "").split("/")
                for key in ("HOME", "TMPDIR"))):
        raise R010ServiceSourceDenied(
            "unclosed real A1 product process environment")
    raw = json.dumps(
        current, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True).encode("ascii")
    if _digest(raw) != closed.helper_env_sha256:
        raise R010ServiceSourceDenied(
            "A1 PREEXEC helper environment changed after original scrub")


def _composed_preexec_sha256(
    *, preexec: R010PreexecSourceObservation,
    key: R010JobKey, source: R010AuthoritySourceBinding,
    host: R010A1HostSource, closed: R010A1ClosedPreexecSource,
) -> str:
    """Join ORIGINAL-JWT-verified PREEXEC source data to same Job/host/helper.

    A PREEXEC source observation proves only that cryptographic verification
    worked against supplied *untrusted* JWKS/issuer bytes. It is NOT provider
    TLS provenance, a current live Job/Owner attestation, or T1 authority.
    """
    if (type(preexec) is not R010PreexecSourceObservation
            or preexec.status !=
                "PREEXEC_SOURCE_ONLY_NONOPERATIVE_NOT_PROVIDER_ATTESTED"
            or preexec.native_launch_allowed is not False
            or preexec.signed_provider_job_live is not False
            or preexec.owner_product_t1_grant_verified is not False
            or preexec.full_code_review_pass is not False
            or preexec.six_command_product_t1_pass is not False
            or preexec.design_blob != key.design_blob
            or preexec.owner_choice_comment_id != key.owner_choice_comment_id
            or preexec.job_envelope_key_sha256 != key.key_sha256()
            or preexec.oidc_original_jwt_sha256 != source.oidc_jwt_sha256
            or preexec.full_darwin_mount_table_sha256
               != host.mount_table_sha256
            or preexec.full_darwin_mount_table_sha256
               != closed.mount_table_sha256
            or preexec.helper_keys != _HELPER_KEYS
            or preexec.helper_env_sha256 != closed.helper_env_sha256
            or not _sha256(preexec.helper_env_sha256)):
        raise R010ServiceSourceDenied(
            "PREEXEC signed source/Owner/Job/host binding mismatched")
    payload = {
        "version": "R010_PREEXEC_JOB_SOURCE_LINK_V1",
        "job_key_sha256": key.key_sha256(),
        "design_blob": preexec.design_blob,
        "owner_choice_comment_id": preexec.owner_choice_comment_id,
        "original_jwt_sha256": preexec.oidc_original_jwt_sha256,
        "host_mount_sha256": preexec.full_darwin_mount_table_sha256,
        "helper_env_sha256": preexec.helper_env_sha256,
        "source_only": True,
        "native_launch_allowed": False,
    }
    return _digest((json.dumps(
        payload, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True) + "\n").encode("ascii"))


def _read_durable_authority_source(
    envelope: R010CreatedJobEnvelope,
    source: R010AuthoritySourceBinding,
    key: R010JobKey,
) -> None:
    """Read the actual pinned O_EXCL source bytes, not a dataclass claim."""
    fd = -1
    try:
        fd = os.open(
            _SOURCE_RECORD,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=envelope._journal_fd)
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode)
                or before.st_uid != os.getuid() or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) != 0o600
                or not 1 <= before.st_size <= 8192):
            raise R010ServiceSourceDenied("unqualified authority source inode")
        raw = os.read(fd, before.st_size + 1)
        after = os.fstat(fd)
        identity = lambda s: (
            s.st_dev, s.st_ino, s.st_uid, s.st_nlink, s.st_mode,
            s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        if (len(raw) != before.st_size or identity(before) != identity(after)
                or _digest(raw) != source.source_digest_sha256):
            raise R010ServiceSourceDenied("authority source bytes changed")
        record = json.loads(raw)
        if (type(record) is not dict
                or record.get("version")
                   != "R010_CURRENT_AUTHORITY_SOURCE_BINDING_V1"
                or record.get("job_key_sha256") != key.key_sha256()
                or record.get("design_blob") != key.design_blob
                or record.get("choice_comment_id") != key.owner_choice_comment_id
                or record.get("implementation_head_sha") != key.head_sha
                or record.get("run_id") != key.run_id
                or record.get("run_attempt") != key.run_attempt
                or record.get("check_run_id") != key.check_run_id
                or record.get("oidc_jwt_sha256") != source.oidc_jwt_sha256
                or record.get("grant_body_sha256") != source.grant_body_sha256
                or record.get("b_review_node") != source.review_nodes[0]
                or record.get("c_review_node") != source.review_nodes[1]
                or record.get("source_model_only") is not True
                or record.get("native_launch_allowed") is not False
                or record.get("six_command_product_t1_pass") is not False):
            raise R010ServiceSourceDenied(
                "persistent Provider/Owner/Job source tuple mismatch")
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        raise R010ServiceSourceDenied(
            "pinned authority source missing or changed") from None
    finally:
        if fd >= 0:
            os.close(fd)


def _read_durable_bridge_source(
    envelope: R010CreatedJobEnvelope,
    session: "R010ServiceSourceSession",
) -> None:
    """Re-read the O_EXCL bridge inode before each actual Worker boundary.

    A digest of a caller-supplied dataclass alone is not durable authority;
    recheck exact pinned bytes, mode, inode and the job/source instance tuple.
    This never grants native PRODUCT_T1 even when all source fields match.
    """
    fd = -1
    try:
        fd = os.open(
            _BRIDGE_RECORD,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
            dir_fd=envelope._journal_fd)
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) != 0o600
                or not 1 <= before.st_size <= 8192):
            raise R010ServiceSourceDenied("unqualified service bridge inode")
        raw = os.read(fd, before.st_size + 1)
        after = os.fstat(fd)
        identity = lambda st: (
            st.st_dev, st.st_ino, st.st_uid, st.st_nlink, st.st_mode,
            st.st_size, st.st_mtime_ns, st.st_ctime_ns)
        if (len(raw) != before.st_size or identity(before) != identity(after)
                or _digest(raw) != session._bridge_digest):
            raise R010ServiceSourceDenied("service bridge source bytes changed")
        record = json.loads(raw)
        if (type(record) is not dict
                or record.get("version")
                    != "R010_SERVICE_OWNER_WORKER_SOURCE_BRIDGE_V1"
                or record.get("job_key_sha256")
                    != session._key.key_sha256()
                or record.get("service_instance_nonce_sha256")
                    != envelope._instance_sha256
                or record.get("workspace") != session._ctx.name
                or record.get("authority_source_sha256")
                    != session._source.source_digest_sha256
                or record.get("provider_oidc_jwt_sha256")
                    != session._source.oidc_jwt_sha256
                or record.get("provider_signed_check_run_id")
                    != session._key.check_run_id
                or record.get("host_selected_source_sha256")
                    != session._host.host_source_sha256
                or record.get("host_full_mount_sha256")
                    != session._host.mount_table_sha256
                or record.get("host_original_os_source_claim")
                    is not session._host.host_snapshot_from_original_os
                or record.get("preexec_source_scrubbed") is not True
                or record.get("preexec_source_model_joined")
                   is not (session._preexec is not None)
                or record.get("preexec_source_model_sha256")
                   != session._preexec_sha256
                or record.get("preexec_original_record_sha256")
                   != (session._preexec_seal.record_sha256
                       if session._preexec_seal is not None else None)
                or record.get("live_preexec_attested") is not False
                or record.get("native_launch_allowed") is not False
                or record.get("row_positive_success") is not False
                or record.get("six_command_product_t1_pass") is not False):
            raise R010ServiceSourceDenied(
                "durable source bridge tuple mismatched")
    except (OSError, ValueError, TypeError, IndexError):
        raise R010ServiceSourceDenied(
            "pinned service bridge missing or changed") from None
    finally:
        if fd >= 0:
            os.close(fd)


class R010ServiceSourceSession:
    """One live service+Owner+Journal source traversal, never a native grant."""

    __slots__ = (
        "_service", "_ctx", "_envelope", "_journal", "_source",
        "_host", "_closed", "_key", "_bridge_digest", "_next",
        "_capture", "_failed", "_lock", "_preexec", "_preexec_sha256",
        "_preexec_seal",
    )

    def __init__(self, marker: object, *,
                 service: WorkspaceService, ctx: WorkspaceContext,
                 envelope: R010CreatedJobEnvelope,
                 journal: R010SerialNonceJournal,
                 source: R010AuthoritySourceBinding,
                 host: R010A1HostSource,
                 closed: R010A1ClosedPreexecSource,
                 key: R010JobKey, bridge_digest: str,
                 preexec: R010PreexecSourceObservation | None,
                 preexec_sha256: str | None,
                 preexec_seal: R010PreexecSourceSeal | None):
        if marker is not _MARKER:
            raise R010ServiceSourceDenied("not a first-party source session")
        self._service = service
        self._ctx = ctx
        self._envelope = envelope
        self._journal = journal
        self._source = source
        self._host = host
        self._closed = closed
        self._preexec = preexec
        self._preexec_sha256 = preexec_sha256
        self._preexec_seal = preexec_seal
        self._key = key
        self._bridge_digest = bridge_digest
        self._next = 1
        self._capture = None
        self._failed = False
        self._lock = threading.Lock()

    def _recheck_durable_locked(self) -> None:
        """Called with the canonical envelope lock HELD, including at Worker.

        MUST NOT acquire the service lifecycle lock here: Service operations
        can already hold the lifecycle lock before entering the Job journal.
        """
        self._envelope._require_live()
        if (self._journal._envelope is not self._envelope
                or self._journal._failed
                or getattr(self._journal, "_r010_source_session", None)
                   is not self
                or self._service._lbe_owner is None
                or self._service._workspaces.get(self._ctx.name)
                   is not self._ctx):
            raise R010ServiceSourceDenied("not the unique live Job/service")
        _read_durable_authority_source(
            self._envelope, self._source, self._key)
        _read_durable_bridge_source(self._envelope, self)
        if self._preexec is not None:
            observed_sha = _composed_preexec_sha256(
                preexec=self._preexec, key=self._key,
                source=self._source, host=self._host, closed=self._closed)
            if observed_sha != self._preexec_sha256:
                raise R010ServiceSourceDenied(
                    "composed PREEXEC source changed before Worker")
            recheck_r010_sealed_preexec_source_locked(
                envelope=self._envelope, job_key=self._key,
                preexec=self._preexec, seal=self._preexec_seal,
                host=self._host, closed=self._closed)
        _check_real_post_scrub_product_environment(
            self._host, self._closed)

    def _check(self) -> None:
        """Validate pinned source+service identities before Worker transition."""
        with self._envelope._lock:
            self._recheck_durable_locked()
        with self._service._lifecycle:
            if (self._service._closed or self._service._closing
                    or self._service._workspaces.get(self._ctx.name)
                       is not self._ctx
                    or self._service._lbe_owner is None
                    or self._service._exec_state is None
                    or self._service._r006_pending is not None):
                raise R010ServiceSourceDenied("not the original live service")
            self._service._exec_state.require_healthy()
        if (self._closed.head_sha != self._key.head_sha
                or self._closed.mount_table_sha256
                   != self._host.mount_table_sha256
                or self._host.run_id != str(self._key.run_id)
                or self._host.run_attempt != str(self._key.run_attempt)
                or self._host.job_name != self._key.job_name
                or self._source.job_key_sha256 != self._key.key_sha256()):
            raise R010ServiceSourceDenied("source/job/host drift")

    def _deny(self) -> None:
        self._failed = True
        try:
            if not self._journal._failed:
                self._journal.latch_failure("source_preexec_denied")
        except Exception:
            self._journal._failed = True

    def begin_source_model_row(
        self, *, row: int, nonce: str,
    ) -> R010PrivateWorkerCapture:
        """Bind real first-party Worker capture; no positive child capability."""
        with self._lock:
            if (self._failed or self._capture is not None
                    or type(row) is not int or row != self._next
                    or not 1 <= row <= 6):
                raise R010ServiceSourceDenied("row is not the next source slot")
            try:
                self._check()
                if row == 1:
                    capture = self._service._prepare_and_bind_r010_first_row_source_only(
                        self._ctx.name, journal=self._journal, nonce=nonce)
                else:
                    six = self._journal._six_source_plan
                    capture = self._service._bind_r010_later_source_model_row(
                        self._ctx.name, source_plan=six,
                        journal=self._journal, row=row, nonce=nonce)
                if (type(capture) is not R010PrivateWorkerCapture
                        or capture._journal is not self._journal
                        or capture._row != row
                        or capture._owner is not self._service._lbe_owner
                        or capture._source_binding is None
                        or capture._source_binding[0] is not self._service):
                    raise R010ServiceSourceDenied("not the original private capture")
                self._capture = capture
                return capture
            except Exception:
                self._deny()
                raise R010ServiceSourceDenied(
                    "source row not admitted by same Job/Owner") from None

    def finish_source_model_row(
        self, *, row: int, capture: R010PrivateWorkerCapture,
        private_root_fd: int, private_before: object,
        go_output_parent_fd: int | None = None,
        go_output_before: object = None,
    ) -> dict[str, Any]:
        """Use actual service's Owner/Worker/finite-Journal classifier."""
        with self._lock:
            if (self._failed or type(row) is not int or row != self._next
                    or capture is not self._capture):
                raise R010ServiceSourceDenied("not the active Worker reservation")
            # A lost ACK MUST NOT allow retry or a different row.
            self._capture = None
            try:
                self._check()
                result = self._service._finalize_r010_source_model_row(
                    self._ctx.name, row=row, journal=self._journal,
                    capture=capture, private_root_fd=private_root_fd,
                    private_before=private_before,
                    go_output_parent_fd=go_output_parent_fd,
                    go_output_before=go_output_before)
                if result.get("status") != (
                        "OWNER_WORKER_FINITE_SOURCE_MODEL_ZERO_NOT_T1"):
                    self._failed = True
                else:
                    self._next += 1
                return result
            except Exception:
                self._deny()
                raise R010ServiceSourceDenied(
                    "original Owner/Worker/Journal result not qualified") from None

    def abort_unfinished_source_row(
        self, *, row: int, capture: R010PrivateWorkerCapture,
        reason: str,
    ) -> dict[str, object]:
        """Durably fail and VOID the rest after original Worker uncertainty.

        This is the only safe in-process fallback for a lost ACK, cancelled
        waiter, Worker/read failure or indeterminate result. It does NOT call
        kill/killpg, retry, restore a nonce, or grant any native child access.
        The failure is recorded in the exact original Job journal, not a
        per-request or per-client-owned sidecar.
        """
        allowed = frozenset({
            "waiter_disconnected", "worker_capture_missing",
            "owner_reader_ambiguous", "result_ack_lost",
            "source_postflight_uncertain",
        })
        with self._lock:
            if (self._failed or self._journal._failed
                    or type(row) is not int or row != self._next
                    or type(capture) is not R010PrivateWorkerCapture
                    or capture is not self._capture
                    or type(reason) is not str or reason not in allowed):
                raise R010ServiceSourceDenied(
                    "unqualified source abort; Job cannot be advanced")
            self._capture = None
            self._failed = True
            try:
                self._journal.latch_failure("owner_reader_ambiguous")
            except Exception:
                # An uncertain fsync is never permission to restart/reissue.
                self._journal._failed = True
                raise R010ServiceSourceDenied(
                    "durable source abort uncertain; permanent deny") from None
            return {
                "row": row,
                "status": "JOB_FAILED_LATCHED",
                "reason_class": reason,
                "rows_remaining": "ROW_VOID",
                "native_launch_allowed": False,
                "six_command_product_t1_pass": False,
            }

    def status(self) -> R010ServiceSourceStatus:
        """No secrets, no fake runtime authority or exposed reservations."""
        with self._lock:
            completed = self._next - 1
            return R010ServiceSourceStatus(
                job_key_sha256=self._key.key_sha256(),
                authority_source_sha256=self._source.source_digest_sha256,
                service_bridge_sha256=self._bridge_digest,
                current_source_model_next_row=(
                    self._next if not self._failed and not self._journal._failed
                    and self._next <= 6 else None),
                source_model_rows_completed=completed,
                failed=self._failed or self._journal._failed)


def bind_r010_authority_source_to_service_only(
    *, service: WorkspaceService, workspace: str,
    envelope: R010CreatedJobEnvelope, journal: R010SerialNonceJournal,
    job_key: R010JobKey, source: R010AuthoritySourceBinding,
    host: R010A1HostSource, closed: R010A1ClosedPreexecSource,
    preexec_source: R010PreexecSourceObservation | None = None,
    preexec_seal: R010PreexecSourceSeal | None = None,
) -> R010ServiceSourceSession:
    """Persist EXACT source->SAME service/Owner bind before any nonce burn.

    This is deliberately not in public REST/MCP and not the final trusted
    executable PREEXEC admission. The source dataclasses are T0 candidates,
    so a successful bind NEVER changes the actual positive Exec gate.
    """
    if (type(service) is not WorkspaceService
            or type(workspace) is not str or not workspace
            or type(envelope) is not R010CreatedJobEnvelope
            or type(journal) is not R010SerialNonceJournal
            or type(job_key) is not R010JobKey
            or type(source) is not R010AuthoritySourceBinding
            or type(host) is not R010A1HostSource
            or type(closed) is not R010A1ClosedPreexecSource):
        raise R010ServiceSourceDenied("invalid original source types")
    try:
        job_key.checked()
        ctx = service.require_exec(workspace)
        if (service.settings.schema_version != 2 or service._closed
                or service._closing or service._exec_state is None
                or service._lbe_owner is None or service._r006_pending is not None
                or journal._envelope is not envelope
                or envelope._key != job_key
                or source.status != "COMPOSED_CURRENT_SOURCE_ONLY_NO_T1"
                or source.provider_runtime_authenticated is not False
                or source.owner_runtime_authenticated is not False
                or source.native_launch_allowed is not False
                or source.six_command_product_t1_pass is not False
                or source.job_key_sha256 != job_key.key_sha256()
                or source.signed_check_run_id != job_key.check_run_id
                or len(source.review_nodes) != 2
                or source.review_nodes[0] == source.review_nodes[1]
                or not all(_sha256(x) for x in (
                    source.grant_body_sha256, source.oidc_jwt_sha256,
                    source.source_digest_sha256, host.mount_table_sha256,
                    host.host_source_sha256))
                or host.status != "R010_A1_HOST_SOURCE_ONLY_NO_PRODUCT_T1"
                or host.native_launch_allowed is not False
                or host.current_provider_job_authenticated is not False
                or host.owner_product_t1_grant_verified is not False
                or host.no_ambient_ssh_agent_proven is not False
                or host.no_shared_writable_mounts_proven is not False
                or host.full_boot_image_attested is not False
                or host.ssh_selector_observed is not True
                or host.head_sha != job_key.head_sha
                or host.run_id != str(job_key.run_id)
                or host.run_attempt != str(job_key.run_attempt)
                or host.job_name != job_key.job_name
                or closed.status != "R010_A1_SOURCE_ONLY_SCRUBBED_NOT_LIVE_PREEXEC"
                or closed.native_launch_allowed is not False
                or closed.verified_current_provider_job is not False
                or closed.live_oidc_token_requested is not False
                or closed.ssh_agent_protocol_called is not False
                or closed.head_sha != job_key.head_sha
                or closed.run_id != str(job_key.run_id)
                or closed.mount_table_sha256 != host.mount_table_sha256
                or closed.helper_keys != _HELPER_KEYS
                or closed.child_keys != _HELPER_KEYS):
            raise R010ServiceSourceDenied("wrong source/Owner/Job contract")
        service._exec_state.require_healthy()
        _check_real_post_scrub_product_environment(host, closed)
        preexec_sha = None
        if (preexec_source is None) is not (preexec_seal is None):
            raise R010ServiceSourceDenied(
                "composed PREEXEC requires one durable original seal")
        if preexec_source is not None:
            preexec_sha = _composed_preexec_sha256(
                preexec=preexec_source, key=job_key,
                source=source, host=host, closed=closed)
    except (R010ServiceSourceDenied, ValueError, TypeError, AttributeError):
        raise R010ServiceSourceDenied(
            "R010 service or PREEXEC source contract unavailable") from None

    with envelope._lock:
        try:
            envelope._require_live()
            if (getattr(envelope, "_r010_source_service_claimed", False)
                    or getattr(journal, "_r010_source_session", None) is not None
                    or journal._burned or journal._failed
                    or journal._six_source_bound):
                raise R010ServiceSourceDenied("service bridge already claimed")
            _read_durable_authority_source(envelope, source, job_key)
            if preexec_source is not None:
                try:
                    recheck_r010_sealed_preexec_source_locked(
                        envelope=envelope, job_key=job_key,
                        preexec=preexec_source, seal=preexec_seal,
                        host=host, closed=closed)
                except R010PreexecSealDenied:
                    raise R010ServiceSourceDenied(
                        "pinned PREEXEC source receipt unavailable") from None
            envelope._r010_source_service_claimed = True
            payload = (json.dumps({
                "version": "R010_SERVICE_OWNER_WORKER_SOURCE_BRIDGE_V1",
                "job_key_sha256": job_key.key_sha256(),
                "service_instance_nonce_sha256": envelope._instance_sha256,
                "workspace": workspace,
                "authority_source_sha256": source.source_digest_sha256,
                "provider_oidc_jwt_sha256": source.oidc_jwt_sha256,
                "provider_signed_check_run_id": source.signed_check_run_id,
                "host_selected_source_sha256": host.host_source_sha256,
                "host_full_mount_sha256": host.mount_table_sha256,
                "host_original_os_source_claim": host.host_snapshot_from_original_os,
                "preexec_source_scrubbed": True,
                "preexec_source_model_joined": preexec_source is not None,
                "preexec_source_model_sha256": preexec_sha,
                "preexec_original_record_sha256": (
                    preexec_seal.record_sha256
                    if preexec_seal is not None else None),
                "live_preexec_attested": False,
                "native_launch_allowed": False,
                "row_positive_success": False,
                "six_command_product_t1_pass": False,
            }, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
            try:
                _write_once(envelope._journal_fd, _BRIDGE_RECORD, payload)
            except R010JobEnvelopeDenied:
                journal._failed = True
                raise R010ServiceSourceDenied(
                    "uncertain service bridge fsync permanently denies Job") from None
            session = R010ServiceSourceSession(
                _MARKER, service=service, ctx=ctx, envelope=envelope,
                journal=journal, source=source, host=host, closed=closed,
                key=job_key, bridge_digest=_digest(payload),
                preexec=preexec_source, preexec_sha256=preexec_sha,
                preexec_seal=preexec_seal)
            journal._r010_source_session = session
            return session
        except R010JobEnvelopeDenied:
            raise R010ServiceSourceDenied("envelope unavailable") from None
