"""R010 source-only PREEXEC component composition; no provider/live Exec.

Rechecks actual pinned-owner-design native JSON data, verifies an ORIGINAL
JWT's RSA signature only against supplied untrusted discovery/JWKS bytes,
compares the one Job envelope, A1 full mount table, and scrubs PREEXEC selectors.
Missing TLS/provider provenance, live check-run, authenticated Owner T1 Grant,
native loaded source and B1 executable review make this permanently DENY-only.
Never makes HTTP/SSH/autofs requests or launches original children.
"""
from __future__ import annotations

from collections.abc import Mapping, MutableMapping
from dataclasses import dataclass
import hashlib
import json

from .lbe_r010_owner_choice import (
    R010OwnerChoiceDenied, validate_r010_owner_design_choice_offline,
)
from .lbe_r010_job_envelope import (
    R010CreatedJobEnvelope, R010JobEnvelopeDenied, R010JobKey,
)
from .lbe_r010_oidc_verify import (
    R010OIDCDenied, R010OIDCExpected,
    verify_r010_oidc_original_bytes_offline,
)
from .lbe_r010_preexec_env import (
    R010ExpectedRunnerEnv, R010PreexecEnvDenied,
    build_closed_product_child_env, scrub_preexec_mapping,
)
from .lbe_r010_a1_mount import (
    R010A1MountDenied, R010A1MountSnapshot, recheck_r010_a1_mounts,
)


class R010PreexecSourceDenied(ValueError):
    """The source-only PREEXEC candidate cannot be safely assembled."""


@dataclass(frozen=True, slots=True)
class R010PreexecSourceObservation:
    design_blob: str
    owner_choice_comment_id: int
    job_envelope_key_sha256: str
    oidc_original_jwt_sha256: str
    full_darwin_mount_table_sha256: str
    helper_keys: tuple[str, ...]
    helper_env_sha256: str = ""
    signed_input_sha256: str = ""
    signed_issuer_metadata_sha256: str = ""
    signed_jwks_sha256: str = ""
    signed_run_id: str = ""
    signed_run_attempt: str = ""
    signed_check_run_id: str = ""
    verified_at_unix: int = 0
    expires_unix: int = 0
    status: str = "PREEXEC_SOURCE_ONLY_NONOPERATIVE_NOT_PROVIDER_ATTESTED"
    native_launch_allowed: bool = False
    signed_provider_job_live: bool = False
    owner_product_t1_grant_verified: bool = False
    full_code_review_pass: bool = False
    six_command_product_t1_pass: bool = False


def compose_r010_preexec_source_only(
    *, comment: Mapping[str, object],
    standards_review: Mapping[str, object],
    spec_review: Mapping[str, object],
    job_key: R010JobKey,
    envelope: R010CreatedJobEnvelope,
    oidc_expected: R010OIDCExpected,
    original_jwt_bytes: bytes,
    issuer_metadata_bytes: bytes,
    issuer_jwks_bytes: bytes,
    verified_at_unix: int,
    env_expected: R010ExpectedRunnerEnv,
    bootstrap_env: MutableMapping[str, str],
    original_mount_snapshot: R010A1MountSnapshot,
    mount_rows_t0: tuple[tuple[str, str, str, int], ...],
) -> R010PreexecSourceObservation:
    """Combine existing real code predicates WITHOUT acquiring real authority.

    mount_rows_t0 is exclusively an injected synthetic test/source witness;
    this function deliberately does not read macOS host mounts or fetch OIDC.
    A future independently reviewed PREEXEC must use a distinct trusted,
    provider-verified entrypoint and perform its own original observations.
    """
    if not isinstance(bootstrap_env, MutableMapping):
        raise R010PreexecSourceDenied("no mutable PREEXEC environment")
    try:
        if (type(job_key) is not R010JobKey
                or type(envelope) is not R010CreatedJobEnvelope
                or type(oidc_expected) is not R010OIDCExpected
                or type(env_expected) is not R010ExpectedRunnerEnv):
            raise R010PreexecSourceDenied("unqualified PREEXEC component type")

        choice = validate_r010_owner_design_choice_offline(
            comment=comment, standards_review=standards_review,
            spec_review=spec_review)
        job_key.checked()
        env_expected.checked()
        oidc_expected.checked()
        if (choice.native_launch_allowed is not False
                or choice.product_t1_grant_verified is not False
                or job_key.owner_choice_comment_id != choice.comment_id
                or job_key.design_blob != choice.design_blob
                or job_key.host_option != "A1"
                or job_key.review_sequence_option != "B1"
                or env_expected.head_sha != job_key.head_sha
                or env_expected.run_id != str(job_key.run_id)
                or env_expected.run_attempt != str(job_key.run_attempt)
                or env_expected.job_name != job_key.job_name
                or oidc_expected.implementation_head_sha != job_key.head_sha
                or oidc_expected.run_id != str(job_key.run_id)
                or oidc_expected.run_attempt != str(job_key.run_attempt)
                or oidc_expected.check_run_id != str(job_key.check_run_id)
                or oidc_expected.workflow_ref != job_key.workflow_ref
                or oidc_expected.design_blob != job_key.design_blob):
            raise R010PreexecSourceDenied("cross-component Job/Choice drift")

        # Actual RSA verification of supplied original bytes. This is NOT
        # authenticated GitHub issuer metadata/JWKS transport or Job evidence.
        signature = verify_r010_oidc_original_bytes_offline(
            jwt_bytes=original_jwt_bytes,
            issuer_metadata_bytes=issuer_metadata_bytes,
            jwks_bytes=issuer_jwks_bytes,
            expected=oidc_expected, verified_at_unix=verified_at_unix)
        mount = recheck_r010_a1_mounts(
            original_mount_snapshot, observed_rows=mount_rows_t0)
        state = envelope.snapshot()
        if (state.get("status") != "JOB_PREEXEC_HOLD"
                or state.get("job_envelope_key") != job_key.key_sha256()
                or state.get("job_local_secret_sha256")
                != oidc_expected.job_local_secret_sha256
                or state.get("native_launch_allowed") is not False
                or state.get("provider_verified") is not False
                or state.get("owner_product_t1_grant_verified") is not False
                or mount.native_launch_allowed is not False
                or signature.native_launch_allowed is not False):
            raise R010PreexecSourceDenied("Job envelope not in exact HOLD state")

        # Destroy all preexec selectors BEFORE constructing any helper map.
        helper = scrub_preexec_mapping(bootstrap_env, env_expected)
        child = build_closed_product_child_env(helper)
        if (child != helper or
                frozenset(helper) !=
                frozenset({"PATH", "HOME", "TMPDIR", "LANG", "LC_ALL"})):
            raise R010PreexecSourceDenied("post-scrub child env drift")
        return R010PreexecSourceObservation(
            design_blob=choice.design_blob,
            owner_choice_comment_id=choice.comment_id,
            job_envelope_key_sha256=job_key.key_sha256(),
            oidc_original_jwt_sha256=signature.jwt_sha256,
            full_darwin_mount_table_sha256=mount.full_table_sha256,
            helper_keys=tuple(sorted(helper)),
            helper_env_sha256=hashlib.sha256(json.dumps(
                helper, sort_keys=True, separators=(",", ":"),
                ensure_ascii=True).encode("ascii")).hexdigest(),
            signed_input_sha256=signature.signing_input_sha256,
            signed_issuer_metadata_sha256=signature.issuer_metadata_sha256,
            signed_jwks_sha256=signature.jwks_sha256,
            signed_run_id=signature.checked_run_id,
            signed_run_attempt=signature.checked_run_attempt,
            signed_check_run_id=signature.checked_check_run_id,
            verified_at_unix=signature.verified_at_unix,
            expires_unix=signature.expires_unix,
        )
    except BaseException:
        # Any failing source-only PREEXEC observation must not leave a usable
        # selector map or healthy current envelope. Never log raw token/JWT.
        try:
            bootstrap_env.clear()
        except BaseException:
            pass
        if type(envelope) is R010CreatedJobEnvelope:
            try:
                envelope.latch_failure("source_preexec_denied")
            except BaseException:
                pass
        raise R010PreexecSourceDenied(
            "R010 PREEXEC source-only composition failed closed") from None
