"""R010 original JWT RSA signature/claims verification: source-only, NO Exec.

Only verifies ORIGINAL bytes against supplied OIDC discovery and JWKS bytes.
It does NOT authenticate those supplied bytes' TLS/provider provenance,
fetch live GitHub, check current Job, grant PRODUCT_T1 or launch anything.
Use only inside a separately reviewed future PREEXEC with those other gates.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import json
import re
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

_DESIGN = "f57e39543a6fe3d64fe99b8669fc7da854b93a64"
_ISSUER = "https://token.actions.githubusercontent.com"
_B64 = re.compile(r"[A-Za-z0-9_-]+", re.ASCII)
_SHA40 = re.compile(r"[0-9a-f]{40}", re.ASCII)
_SHA64 = re.compile(r"[0-9a-f]{64}", re.ASCII)
_CANON_ID = re.compile(r"[1-9][0-9]{0,17}", re.ASCII)
_KID = re.compile(r"[A-Za-z0-9_.:-]{1,120}", re.ASCII)


class R010OIDCDenied(ValueError):
    """No verified source-bounded OIDC result is available."""


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for name, item in pairs:
        if name in value:
            raise R010OIDCDenied("duplicate security-critical JSON name")
        value[name] = item
    return value


def _object(raw: bytes, limit: int) -> dict[str, object]:
    if type(raw) is not bytes or not 1 <= len(raw) <= limit:
        raise R010OIDCDenied("unavailable or unbounded JSON bytes")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique)
    except (UnicodeError, ValueError, TypeError):
        raise R010OIDCDenied("malformed or ambiguous original JSON") from None
    if type(value) is not dict:
        raise R010OIDCDenied("expected one JSON object")
    return value


def _segment(raw: str, limit: int) -> bytes:
    if type(raw) is not str or len(raw) > limit * 2 or not _B64.fullmatch(raw):
        raise R010OIDCDenied("noncanonical base64url input")
    try:
        data = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
    except (ValueError, base64.binascii.Error):
        raise R010OIDCDenied("malformed base64url input") from None
    if (not data or len(data) > limit or
            base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii") != raw):
        raise R010OIDCDenied("oversized or noncanonical base64url input")
    return data


def _jwks_url(raw: object) -> str:
    if type(raw) is not str or not 1 <= len(raw) <= 512 or "\\" in raw:
        raise R010OIDCDenied("unreviewed issuer JWKS URL")
    try:
        url = urlsplit(raw)
        if (url.scheme != "https" or
                url.hostname != "token.actions.githubusercontent.com" or
                url.port is not None or url.username is not None
                or url.password is not None or url.query or url.fragment
                or not url.path.startswith("/") or url.path.startswith("//")
                or ".." in url.path.split("/")
                or raw != _ISSUER + url.path):
            raise R010OIDCDenied("unreviewed issuer JWKS URL")
    except ValueError:
        raise R010OIDCDenied("invalid issuer JWKS URL") from None
    return raw


@dataclass(frozen=True, slots=True)
class R010OIDCExpected:
    """Typed caller expectations, not proof of issuer/Job provenance."""

    implementation_head_sha: str
    job_local_secret_sha256: str
    run_id: str
    run_attempt: str
    check_run_id: str
    workflow_ref: str
    workflow_sha: str
    signed_source_sha: str
    subject: str
    repository: str = "chinanjjohn2012/mac-file-gateway"
    design_blob: str = _DESIGN

    def checked(self) -> "R010OIDCExpected":
        if (self.repository != "chinanjjohn2012/mac-file-gateway"
                or self.design_blob != _DESIGN):
            raise R010OIDCDenied("wrong current contract identity")
        for value, pattern in (
            (self.implementation_head_sha, _SHA40),
            (self.job_local_secret_sha256, _SHA64),
            (self.workflow_sha, _SHA40),
            (self.signed_source_sha, _SHA40),
        ):
            if type(value) is not str or pattern.fullmatch(value) is None:
                raise R010OIDCDenied("unqualified signed source identity")
        for value in (self.run_id, self.run_attempt, self.check_run_id):
            if type(value) is not str or _CANON_ID.fullmatch(value) is None:
                raise R010OIDCDenied("invalid canonical run/Job ID")
        for value in (self.subject, self.workflow_ref):
            if (type(value) is not str or not 1 <= len(value) <= 384
                    or any(ord(ch) < 33 or ord(ch) > 126 for ch in value)
                    or "\\" in value):
                raise R010OIDCDenied("unreviewed signed subject/workflow")
        if (not self.workflow_ref.startswith(
                self.repository + "/.github/workflows/")
                or "@" not in self.workflow_ref):
            raise R010OIDCDenied("unexpected signed workflow identity")
        return self

    @property
    def audience(self) -> str:
        self.checked()
        return ("mfg-r010:" + self.design_blob + ":" +
                self.implementation_head_sha + ":" +
                self.job_local_secret_sha256)


@dataclass(frozen=True, slots=True)
class R010OIDCSignatureReceipt:
    """Offline raw-byte signature evidence, NEVER an execution authority."""

    jwt_sha256: str
    signing_input_sha256: str
    signed_payload_sha256: str
    issuer_metadata_sha256: str
    jwks_sha256: str
    issuer: str
    jwks_url: str
    key_id: str
    algorithm: str
    checked_run_id: str
    checked_run_attempt: str
    checked_check_run_id: str
    signed_subject: str
    verified_at_unix: int
    expires_unix: int
    status: str = "OFFLINE_SIGNATURE_VALID_EXTERNAL_TRUST_NOT_ATTESTED"
    native_launch_allowed: bool = False


def _rsa_key(jwks: dict[str, object], kid: str) -> rsa.RSAPublicKey:
    all_keys = jwks.get("keys")
    if type(all_keys) is not list or not 1 <= len(all_keys) <= 64:
        raise R010OIDCDenied("missing or unbounded JWKS")
    matches = [item for item in all_keys
               if type(item) is dict and item.get("kid") == kid]
    if len(matches) != 1:
        raise R010OIDCDenied("ambiguous or unknown issuer key")
    k = matches[0]
    if (k.get("kty") != "RSA" or k.get("use", "sig") != "sig"
            or k.get("alg", "RS256") != "RS256"
            or ("key_ops" in k and k["key_ops"] != ["verify"])
            or type(k.get("n")) is not str or type(k.get("e")) is not str):
        raise R010OIDCDenied("JWKS key not an RSA signing key")
    n = int.from_bytes(_segment(k["n"], 1024), "big")
    e = int.from_bytes(_segment(k["e"], 16), "big")
    if not 2048 <= n.bit_length() <= 4096 or e != 65537:
        raise R010OIDCDenied("unqualified RSA public parameters")
    try:
        return rsa.RSAPublicNumbers(e, n).public_key()
    except ValueError:
        raise R010OIDCDenied("invalid RSA issuer key") from None


def verify_r010_oidc_original_bytes_offline(
    *, jwt_bytes: bytes, issuer_metadata_bytes: bytes, jwks_bytes: bytes,
    expected: R010OIDCExpected, verified_at_unix: int,
) -> R010OIDCSignatureReceipt:
    """Verify original JWT signature + signed claims, no provider fetch or grant."""
    if type(expected) is not R010OIDCExpected:
        raise R010OIDCDenied("expected identity must be typed")
    expected.checked()
    if type(verified_at_unix) is not int or verified_at_unix <= 0:
        raise R010OIDCDenied("untrusted verification clock")
    if type(jwt_bytes) is not bytes or not 100 <= len(jwt_bytes) <= 16384:
        raise R010OIDCDenied("original JWT raw bytes missing or unbounded")
    try:
        raw = jwt_bytes.decode("ascii")
    except UnicodeError:
        raise R010OIDCDenied("non-ASCII JWT") from None
    parts = raw.split(".")
    if len(parts) != 3:
        raise R010OIDCDenied("JWT has no unique signature segment")
    header_bytes, claims_bytes, signature = (
        _segment(parts[0], 4096),
        _segment(parts[1], 8192),
        _segment(parts[2], 1024),
    )
    header = _object(header_bytes, 4096)
    claims = _object(claims_bytes, 8192)
    kid = header.get("kid")
    if (header.get("typ") != "JWT" or header.get("alg") != "RS256"
            or type(kid) is not str or _KID.fullmatch(kid) is None
            or any(name in header for name in
                   ("jwk", "jku", "x5u", "crit", "b64"))):
        raise R010OIDCDenied("unreviewed JWT algorithm/header")
    metadata = _object(issuer_metadata_bytes, 65536)
    if metadata.get("issuer") != _ISSUER:
        raise R010OIDCDenied("wrong trusted issuer")
    jwks_url = _jwks_url(metadata.get("jwks_uri"))
    public = _rsa_key(_object(jwks_bytes, 65536), kid)
    signing_input = (parts[0] + "." + parts[1]).encode("ascii")
    try:
        public.verify(signature, signing_input,
                      padding.PKCS1v15(), hashes.SHA256())
    except (InvalidSignature, ValueError):
        raise R010OIDCDenied("original RS256 signature invalid") from None
    signed = {
        "iss": _ISSUER, "aud": expected.audience,
        "repository": expected.repository, "run_id": expected.run_id,
        "run_attempt": expected.run_attempt, "check_run_id": expected.check_run_id,
        "workflow_ref": expected.workflow_ref,
        "workflow_sha": expected.workflow_sha,
        "sha": expected.signed_source_sha,
        "sub": expected.subject, "runner_environment": "github-hosted",
    }
    for name, value in signed.items():
        if type(claims.get(name)) is not str or claims[name] != value:
            raise R010OIDCDenied("mismatched signed Job claim: " + name)
    iat, nbf, exp = [claims.get(key) for key in ("iat", "nbf", "exp")]
    if (any(type(v) is not int or v <= 0 for v in (iat, nbf, exp))
            or not iat < exp or exp - iat > 600
            or iat > verified_at_unix + 30
            or verified_at_unix - iat > 120
            or nbf > verified_at_unix + 30
            or exp <= verified_at_unix):
        raise R010OIDCDenied("JWT temporal bounds invalid")
    return R010OIDCSignatureReceipt(
        jwt_sha256=hashlib.sha256(jwt_bytes).hexdigest(),
        signing_input_sha256=hashlib.sha256(signing_input).hexdigest(),
        signed_payload_sha256=hashlib.sha256(claims_bytes).hexdigest(),
        issuer_metadata_sha256=hashlib.sha256(issuer_metadata_bytes).hexdigest(),
        jwks_sha256=hashlib.sha256(jwks_bytes).hexdigest(),
        issuer=_ISSUER, jwks_url=jwks_url, key_id=kid, algorithm="RS256",
        checked_run_id=expected.run_id,
        checked_run_attempt=expected.run_attempt,
        checked_check_run_id=expected.check_run_id,
        signed_subject=expected.subject,
        verified_at_unix=verified_at_unix, expires_unix=exp,
    )


def require_r010_oidc_offline_fresh_at(
    receipt: R010OIDCSignatureReceipt, *, grant_now_unix: int,
) -> R010OIDCSignatureReceipt:
    """ONLY an offline time check; current Job/Owner approval still unverified."""
    if (type(receipt) is not R010OIDCSignatureReceipt
            or receipt.status != "OFFLINE_SIGNATURE_VALID_EXTERNAL_TRUST_NOT_ATTESTED"
            or receipt.native_launch_allowed is not False
            or type(grant_now_unix) is not int
            or grant_now_unix < receipt.verified_at_unix
            or grant_now_unix - receipt.verified_at_unix > 120
            or grant_now_unix >= receipt.expires_unix):
        raise R010OIDCDenied("stale or unqualified signed offline claim")
    return receipt
