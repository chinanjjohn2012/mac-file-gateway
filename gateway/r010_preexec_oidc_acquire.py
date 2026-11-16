"""R010 stdlib-only PREEXEC OIDC response acquisition source.

This file is designed to be loaded directly by the tracked PREEXEC entrypoint
before importing the gateway package.  It may use the runner-provided bearer
only for one exact reviewed HTTPS request.  It does NOT verify provider
signature, current Job, Owner grant or PRODUCT_T1 and is dormant until a
separately authorized live integration calls it.

SAFE T0 replaces urllib's opener; no real network request is made.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request


_HOST = re.compile(
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.actions\.githubusercontent\.com\Z",
    re.ASCII,
)
_AUDIENCE = re.compile(
    r"mfg-r010:[0-9a-f]{40}:[0-9a-f]{40}:[0-9a-f]{64}\Z",
    re.ASCII,
)
_JWT = re.compile(
    rb"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\Z",
    re.ASCII,
)
_MAX_RESPONSE = 16384


class R010PreexecOIDCAcquireDenied(ValueError):
    """Original runner OIDC response was not acquired under the exact source."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        raise R010PreexecOIDCAcquireDenied("redirect forbidden")


def _no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise R010PreexecOIDCAcquireDenied("duplicate token JSON key")
        result[key] = value
    return result


def _reject_constant(_value):
    raise R010PreexecOIDCAcquireDenied("nonfinite token JSON value")


def _checked_base_url(raw: str) -> str:
    if (type(raw) is not str or not 1 <= len(raw) <= 4096
            or "\\" in raw
            or any(ord(ch) < 33 or ord(ch) > 126 for ch in raw)):
        raise R010PreexecOIDCAcquireDenied("unqualified runner OIDC endpoint")
    try:
        parsed = urllib.parse.urlsplit(raw)
        host = parsed.hostname
        port = parsed.port
    except ValueError:
        raise R010PreexecOIDCAcquireDenied(
            "malformed runner OIDC endpoint") from None
    if (parsed.scheme != "https"
            or host is None or _HOST.fullmatch(host) is None
            or parsed.username is not None or parsed.password is not None
            or port is not None or parsed.fragment
            or parsed.path != "/_apis/oidc/token"
            or parsed.query != "api-version=2.0"
            or raw != (
                "https://" + host
                + "/_apis/oidc/token?api-version=2.0")):
        raise R010PreexecOIDCAcquireDenied(
            "unreviewed runner OIDC endpoint")
    return raw


def _checked_audience(raw: str) -> str:
    if type(raw) is not str or _AUDIENCE.fullmatch(raw) is None:
        raise R010PreexecOIDCAcquireDenied("unqualified OIDC audience")
    return raw


def _checked_bearer(raw: str) -> str:
    if (type(raw) is not str or not 16 <= len(raw) <= 8192
            or any(ord(ch) < 33 or ord(ch) > 126 for ch in raw)):
        raise R010PreexecOIDCAcquireDenied("unqualified OIDC bearer selector")
    return raw


def _token_from_response(raw: bytes) -> bytes:
    if type(raw) is not bytes or not 2 <= len(raw) <= _MAX_RESPONSE:
        raise R010PreexecOIDCAcquireDenied("unbounded token response")
    try:
        value = json.loads(
            raw.decode("ascii"),
            object_pairs_hook=_no_duplicates,
            parse_constant=_reject_constant,
        )
    except R010PreexecOIDCAcquireDenied:
        raise
    except (UnicodeError, ValueError, TypeError):
        raise R010PreexecOIDCAcquireDenied(
            "malformed token response") from None
    if type(value) is not dict or set(value) != {"value"}:
        raise R010PreexecOIDCAcquireDenied("unexpected token response shape")
    token = value["value"]
    if type(token) is not str:
        raise R010PreexecOIDCAcquireDenied("token response value not text")
    try:
        raw_token = token.encode("ascii")
    except UnicodeError:
        raise R010PreexecOIDCAcquireDenied(
            "token response not ASCII") from None
    if (not 5 <= len(raw_token) <= _MAX_RESPONSE
            or _JWT.fullmatch(raw_token) is None):
        raise R010PreexecOIDCAcquireDenied(
            "token response not canonical JWT bytes")
    return raw_token


@dataclass(frozen=True, slots=True)
class R010PreexecOIDCAcquisition:
    """Original token bytes only; never provider/current-Job authority."""

    original_jwt_bytes: bytes = field(repr=False)
    original_jwt_sha256: str
    request_url_sha256: str
    response_sha256: str
    status: str = "PREEXEC_ORIGINAL_OIDC_RESPONSE_SOURCE_ONLY_NOT_VERIFIED"
    provider_signature_verified: bool = False
    current_job_independently_verified: bool = False
    owner_product_t1_grant_verified: bool = False
    native_launch_allowed: bool = False


def acquire_r010_preexec_oidc_response(
    *, request_base_url: str, bearer: str, audience: str,
) -> R010PreexecOIDCAcquisition:
    """Acquire one exact original JWT response; no signature/T1 conclusion."""
    base = _checked_base_url(request_base_url)
    aud = _checked_audience(audience)
    secret = _checked_bearer(bearer)
    encoded_audience = urllib.parse.quote(aud, safe="")
    if urllib.parse.unquote(encoded_audience) != aud:
        raise R010PreexecOIDCAcquireDenied(
            "OIDC audience canonicalization failed")
    url = base + "&audience=" + encoded_audience
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        _NoRedirect(),
    )
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "mac-file-gateway-r010-preexec/1",
            "Accept-Encoding": "identity",
            "Authorization": "Bearer " + secret,
        },
        method="GET",
    )
    try:
        with opener.open(request, timeout=8) as response:
            if (response.status != 200 or response.geturl() != url
                    or response.headers.get(
                        "Content-Encoding", "identity") != "identity"
                    or response.headers.get("Location") is not None):
                raise R010PreexecOIDCAcquireDenied(
                    "OIDC response transport unqualified")
            body = response.read(_MAX_RESPONSE + 1)
            if (type(body) is not bytes
                    or not 1 <= len(body) <= _MAX_RESPONSE):
                raise R010PreexecOIDCAcquireDenied(
                    "OIDC response size exceeded")
    except R010PreexecOIDCAcquireDenied:
        raise
    except (OSError, urllib.error.URLError, urllib.error.HTTPError,
            TimeoutError, ValueError):
        raise R010PreexecOIDCAcquireDenied(
            "OIDC response unavailable") from None
    token = _token_from_response(body)
    return R010PreexecOIDCAcquisition(
        original_jwt_bytes=token,
        original_jwt_sha256=hashlib.sha256(token).hexdigest(),
        request_url_sha256=hashlib.sha256(
            url.encode("ascii")).hexdigest(),
        response_sha256=hashlib.sha256(body).hexdigest(),
    )
