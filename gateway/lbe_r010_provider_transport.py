"""R010 constrained original HTTPS source collectors; no execution authority.

Both readers implement production-shaped transport, but are not invoked by
any current Worker, workflow or public Exec path. Safe T0 supplies a fake
opener, never a live OIDC bearer. A successful read is not current Job/check
run attestation, an Owner PRODUCT_T1 Grant, or a child launch capability.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request

from .lbe_r010_oidc_verify import (
    R010OIDCDenied, R010OIDCExpected, R010OIDCSignatureReceipt,
    _jwks_url, _object, verify_r010_oidc_original_bytes_offline,
)
from .lbe_r010_preexec_env import (
    R010PreexecEnvDenied, _reviewed_oidc_base,
)
from .lbe_r010_grant_candidate import (
    R010GrantExpected, R010GrantSourceObservation,
    validate_r010_product_grant_source_offline,
)
from .lbe_r010_owner_choice import (
    R010OwnerDesignChoiceObservation,
    validate_r010_owner_design_choice_offline,
)

_REPO = "chinanjjohn2012/mac-file-gateway"
_API = "https://api.github.com/repos/" + _REPO
_DISCOVERY = (
    "https://token.actions.githubusercontent.com/"
    ".well-known/openid-configuration"
)
_REVIEWS = _API + "/pulls/114/reviews?per_page=100&page=1"
_DIGITS = re.compile(r"[1-9][0-9]{0,17}\Z", re.ASCII)
_MAX_GH = 1024 * 1024


class R010HttpsSourceDenied(ValueError):
    """Exact HTTPS source is unqualified; no credentials or child exposed."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        raise R010HttpsSourceDenied("HTTPS redirect forbidden")


def _no_duplicates(pairs):
    output = {}
    for k, v in pairs:
        if k in output:
            raise R010HttpsSourceDenied("duplicate JSON key")
        output[k] = v
    return output


def _reject_constant(_value):
    raise R010HttpsSourceDenied("nonfinite JSON value")


def _json(raw: bytes, *, size: int, kind: type):
    if type(raw) is not bytes or not 2 <= len(raw) <= size:
        raise R010HttpsSourceDenied("unbounded original JSON body")
    try:
        value = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_no_duplicates,
            parse_constant=_reject_constant)
    except R010HttpsSourceDenied:
        raise
    except (ValueError, TypeError, UnicodeError):
        raise R010HttpsSourceDenied("malformed original JSON") from None
    if type(value) is not kind:
        raise R010HttpsSourceDenied("wrong JSON container type")
    return value


def _owner_comment_url(value: int) -> str:
    if type(value) is not int or value <= 0 or value >= 10**18:
        raise R010HttpsSourceDenied("invalid Owner comment ID")
    return _API + "/issues/comments/" + str(value)


class _ConstrainedHttps:
    """No proxy, redirect, custom CA, caller headers or unreviewed hosts.

    This code is dormant until a separately authorized PREEXEC integration
    uses it. Replacing its opener in T0 does not prove real transport.
    """

    def __init__(self):
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=ssl.create_default_context()),
            _NoRedirect(),
        )

    def get(self, url: str, *, limit: int,
            oidc_bearer: str | None = None) -> bytes:
        if (type(url) is not str or type(limit) is not int
                or not 1 <= limit <= _MAX_GH
                or url.count("#") or "\\" in url
                or any(ord(ch) < 33 or ord(ch) > 126 for ch in url)):
            raise R010HttpsSourceDenied("unqualified HTTPS request")
        parsed = urllib.parse.urlsplit(url)
        if (parsed.scheme != "https" or parsed.username is not None
                or parsed.password is not None or parsed.port is not None
                or parsed.hostname is None
                or parsed.netloc != parsed.hostname):
            raise R010HttpsSourceDenied("HTTPS endpoint not canonical")
        is_api = (
            url == _REVIEWS or
            (url.startswith(_API + "/issues/comments/") and
             _DIGITS.fullmatch(url[len(_API) + len("/issues/comments/"):])
             is not None)
        )
        is_issuer = url == _DISCOVERY or (
            parsed.hostname == "token.actions.githubusercontent.com"
            and _valid_jwks_url(url))
        is_runner = False
        if oidc_bearer is not None:
            if (type(oidc_bearer) is not str
                    or not 16 <= len(oidc_bearer) <= 8192
                    or any(ord(ch) < 33 or ord(ch) > 126
                           for ch in oidc_bearer)):
                raise R010HttpsSourceDenied("unqualified OIDC bearer selector")
            # Only the exact original Runner profile with one appended
            # canonical audience is allowed to receive its bearer.
            if not url.startswith("https://") or "&audience=" not in url:
                raise R010HttpsSourceDenied("bearer request URL missing audience")
            base, audience = url.split("&audience=", 1)
            try:
                _reviewed_oidc_base(base)
                if (not audience or
                        urllib.parse.quote(
                            urllib.parse.unquote(audience), safe="") != audience):
                    raise R010HttpsSourceDenied("noncanonical OIDC audience")
            except R010PreexecEnvDenied:
                raise R010HttpsSourceDenied(
                    "bearer endpoint is not reviewed") from None
            is_runner = True
        if (not (is_api or is_issuer or is_runner)
                or (oidc_bearer is not None and not is_runner)):
            raise R010HttpsSourceDenied("unreviewed HTTPS destination")
        headers = {
            "Accept": "application/vnd.github+json" if is_api
                      else "application/json",
            "User-Agent": "mac-file-gateway-r010-source/1",
            "Accept-Encoding": "identity",
        }
        if is_api:
            headers["X-GitHub-Api-Version"] = "2022-11-28"
        if oidc_bearer is not None:
            headers["Authorization"] = "Bearer " + oidc_bearer
        request = urllib.request.Request(
            url, headers=headers, method="GET")
        try:
            with self._opener.open(request, timeout=8) as response:
                if (response.status != 200 or response.geturl() != url
                        or response.headers.get("Content-Encoding", "identity")
                           != "identity"
                        or response.headers.get("Location") is not None
                        or (is_api and "rel=\"next\"" in
                            response.headers.get("Link", ""))):
                    raise R010HttpsSourceDenied("HTTPS response unqualified")
                payload = response.read(limit + 1)
                if type(payload) is not bytes or not 1 <= len(payload) <= limit:
                    raise R010HttpsSourceDenied("HTTPS body size exceeded")
                return payload
        except R010HttpsSourceDenied:
            raise
        except (OSError, urllib.error.URLError, urllib.error.HTTPError,
                TimeoutError, ValueError):
            # Do not leak Authorization/JWT/original body via exception text.
            raise R010HttpsSourceDenied("HTTPS source unavailable") from None


def _valid_jwks_url(url: str) -> bool:
    try:
        _jwks_url(url)
        return True
    except R010OIDCDenied:
        return False


@dataclass(frozen=True, slots=True)
class R010ProviderOIDCSource:
    """Signature verified over original bytes, CURRENT Job still unproven."""

    signature: R010OIDCSignatureReceipt
    metadata_sha256: str
    jwks_sha256: str
    original_jwt_sha256: str
    status: str = "ORIGINAL_HTTPS_SOURCE_SIGNATURE_VALID_JOB_NOT_ATTESTED"
    current_job_independently_verified: bool = False
    owner_product_t1_grant_verified: bool = False
    native_launch_allowed: bool = False


def request_r010_provider_oidc_source(
    *, request_base_url: str, bearer: str,
    expected: R010OIDCExpected, now_unix: int,
) -> R010ProviderOIDCSource:
    """Explicit future PREEXEC entrypoint; NEVER automatically called.

    No unreviewed request URL, proxy, redirect or bearer propagation.
    Verification is RSA over original signed bytes and HTTPS issuer JWKS,
    but is NOT a real current GitHub Job/check-run API or Owner proof.
    """
    if type(expected) is not R010OIDCExpected:
        raise R010HttpsSourceDenied("missing typed OIDC expected identity")
    try:
        expected.checked()
        _reviewed_oidc_base(request_base_url)
    except (R010OIDCDenied, R010PreexecEnvDenied):
        raise R010HttpsSourceDenied("unreviewed OIDC request inputs") from None
    url = request_base_url + "&audience=" + urllib.parse.quote(
        expected.audience, safe="")
    transport = _ConstrainedHttps()
    try:
        jwt_response = _json(
            transport.get(url, limit=16384, oidc_bearer=bearer),
            size=16384, kind=dict)
        if set(jwt_response) != {"value"} or type(jwt_response["value"]) is not str:
            raise R010HttpsSourceDenied("original OIDC token payload missing")
        jwt = jwt_response["value"].encode("ascii")
        metadata = transport.get(_DISCOVERY, limit=65536)
        metadata_obj = _object(metadata, 65536)
        jwks_url = _jwks_url(metadata_obj.get("jwks_uri"))
        jwks = transport.get(jwks_url, limit=65536)
        signature = verify_r010_oidc_original_bytes_offline(
            jwt_bytes=jwt, issuer_metadata_bytes=metadata,
            jwks_bytes=jwks, expected=expected,
            verified_at_unix=now_unix)
    except (R010OIDCDenied, UnicodeError, ValueError,
            R010HttpsSourceDenied):
        raise R010HttpsSourceDenied(
            "OIDC original source or signature unqualified") from None
    return R010ProviderOIDCSource(
        signature=signature,
        metadata_sha256=hashlib.sha256(metadata).hexdigest(),
        jwks_sha256=hashlib.sha256(jwks).hexdigest(),
        original_jwt_sha256=hashlib.sha256(jwt).hexdigest(),
    )


@dataclass(frozen=True, slots=True)
class R010GithubOwnerRead:
    choice: R010OwnerDesignChoiceObservation
    raw_choice_sha256: str
    raw_reviews_sha256: str
    status: str = "GITHUB_API_SOURCE_MATCH_EXECUTION_NOT_AUTHORIZED"
    current_job_independently_verified: bool = False
    native_launch_allowed: bool = False


class R010GithubOwnerEvidenceReader:
    """Read exact native API objects, never infer B/C human identity or T1."""

    def __init__(self):
        self._transport = _ConstrainedHttps()

    def _get_comment(self, comment_id: int) -> tuple[dict, bytes]:
        raw = self._transport.get(
            _owner_comment_url(comment_id), limit=65536)
        return _json(raw, size=65536, kind=dict), raw

    def _get_reviews(self) -> tuple[list, bytes]:
        raw = self._transport.get(_REVIEWS, limit=_MAX_GH)
        reviews = _json(raw, size=_MAX_GH, kind=list)
        if (not 2 <= len(reviews) < 100
                or any(type(review) is not dict for review in reviews)):
            raise R010HttpsSourceDenied("complete GitHub review set missing")
        return reviews, raw

    @staticmethod
    def _role(reviews: list, expected_node: str) -> dict:
        matches = [x for x in reviews if x.get("node_id") == expected_node]
        if len(matches) != 1:
            raise R010HttpsSourceDenied("missing unique native Review node")
        return matches[0]

    def read_design_choice(self) -> R010GithubOwnerRead:
        comment, comment_raw = self._get_comment(6740275850)
        reviews, reviews_raw = self._get_reviews()
        b = self._role(reviews, "PRR_kwDOU5v3IM8AAAABWtAZjQ")
        c = self._role(reviews, "PRR_kwDOU5v3IM8AAAABWtBPMQ")
        try:
            value = validate_r010_owner_design_choice_offline(
                comment=comment, standards_review=b, spec_review=c)
        except ValueError:
            raise R010HttpsSourceDenied(
                "GitHub Owner/design source unqualified") from None
        return R010GithubOwnerRead(
            choice=value,
            raw_choice_sha256=hashlib.sha256(comment_raw).hexdigest(),
            raw_reviews_sha256=hashlib.sha256(reviews_raw).hexdigest(),
        )

    def read_product_grant_candidate(
        self, *, grant_comment_id: int,
        expected: R010GrantExpected,
        oidc_expected: R010OIDCExpected,
        oidc_receipt: R010OIDCSignatureReceipt,
        now_unix: int,
    ) -> R010GrantSourceObservation:
        """Actual GitHub API source fetch; no current signed Job or T1 grant."""
        choice_read = self.read_design_choice()
        grant, _raw = self._get_comment(grant_comment_id)
        reviews, _raw_reviews = self._get_reviews()
        # Only the actual Grant's declared B/C IDs select current reviews;
        # the offline validator independently binds each to exact target,
        # immutable implementation Head/Base/Tree, role, scope and verdict.
        from .lbe_r010_grant_candidate import _read_header
        fields = _read_header(grant.get("body"))
        b_id = fields.get("b_r010_t1_qualification_review_id", "")
        c_id = fields.get("c_r010_t1_qualification_review_id", "")
        if (not b_id.startswith("PRR_") or not c_id.startswith("PRR_")
                or b_id == c_id):
            raise R010HttpsSourceDenied("unqualified current role node IDs")
        b, c = self._role(reviews, b_id), self._role(reviews, c_id)
        try:
            return validate_r010_product_grant_source_offline(
                comment=grant, standards_review=b, spec_review=c,
                choice=choice_read.choice, expected=expected,
                oidc_expected=oidc_expected, oidc_receipt=oidc_receipt,
                now_unix=now_unix)
        except ValueError:
            raise R010HttpsSourceDenied(
                "Owner product grant source unqualified") from None
