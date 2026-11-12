"""R010 stdlib-only pre-scrub OIDC acquisition source, SAFE T0."""
from __future__ import annotations

import ast
import importlib.util
import json
from pathlib import Path
import sys
import urllib.request

import pytest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "gateway" / "r010_preexec_oidc_acquire.py"
BASE = (
    "https://pipelinesghubeus15.actions.githubusercontent.com/"
    "_apis/oidc/token?api-version=2.0"
)
AUDIENCE = "mfg-r010:" + "a" * 40 + ":" + "b" * 40 + ":" + "c" * 64
BEARER = "synthetic-preexec-bearer-1234567890"


class FakeResponse:
    def __init__(self, url, body, *, status=200, headers=None, final_url=None):
        self.status = status
        self.headers = headers or {}
        self._url = url if final_url is None else final_url
        self._body = body

    def geturl(self):
        return self._url

    def read(self, count):
        return self._body[:count]

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


class FakeOpener:
    def __init__(self):
        self.calls = []
        self.response = None

    def open(self, request, timeout):
        self.calls.append((request.full_url, dict(request.headers), timeout))
        assert self.response is not None
        return self.response


def _load(monkeypatch, opener):
    assert SOURCE.exists(), "RED: standalone pre-scrub OIDC source is missing"
    monkeypatch.setattr(urllib.request, "build_opener", lambda *_a: opener)
    name = "_mfg_r010_preexec_oidc_acquire_test"
    spec = importlib.util.spec_from_file_location(name, SOURCE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
        return module
    finally:
        sys.modules.pop(name, None)


def test_source_is_stdlib_only_and_has_no_gateway_import():
    assert SOURCE.exists(), "RED: standalone pre-scrub OIDC source is missing"
    tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
    allowed = {
        "__future__", "dataclasses", "hashlib", "json", "re", "ssl",
        "urllib",
    }
    seen = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            seen.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            seen.add((node.module or "").split(".", 1)[0])
    assert seen <= allowed
    assert "gateway" not in seen


def test_fake_https_acquires_original_token_response_without_gateway(monkeypatch):
    opener = FakeOpener()
    token = "a.b.c"
    expected_url = BASE + "&audience=" + urllib.parse.quote(AUDIENCE, safe="")
    opener.response = FakeResponse(
        expected_url, json.dumps({"value": token}).encode("ascii"))
    before = {n for n in sys.modules if n == "gateway" or n.startswith("gateway.")}
    mod = _load(monkeypatch, opener)
    receipt = mod.acquire_r010_preexec_oidc_response(
        request_base_url=BASE, bearer=BEARER, audience=AUDIENCE)
    after = {n for n in sys.modules if n == "gateway" or n.startswith("gateway.")}
    assert after == before
    assert receipt.original_jwt_bytes == token.encode("ascii")
    assert len(receipt.original_jwt_sha256) == 64
    assert receipt.native_launch_allowed is False
    assert receipt.provider_signature_verified is False
    assert receipt.current_job_independently_verified is False
    assert len(opener.calls) == 1
    url, headers, timeout = opener.calls[0]
    assert url == expected_url
    assert headers["Authorization"] == "Bearer " + BEARER
    assert timeout == 8
    assert BEARER not in repr(receipt)


@pytest.mark.parametrize("base,audience", [
    (BASE.replace("https://", "http://"), AUDIENCE),
    (BASE + "&extra=1", AUDIENCE),
    (BASE.replace("actions.githubusercontent", "evil.invalid"), AUDIENCE),
    (BASE, "mfg-r010:" + "a" * 40 + ":" + "b" * 40 + ":" + "C" * 64),
    (BASE, "mfg-r010:" + "a" * 40 + ":" + "b" * 40),
])
def test_bad_endpoint_or_audience_denied_before_bearer_send(
        monkeypatch, base, audience):
    opener = FakeOpener()
    mod = _load(monkeypatch, opener)
    with pytest.raises(mod.R010PreexecOIDCAcquireDenied):
        mod.acquire_r010_preexec_oidc_response(
            request_base_url=base, bearer=BEARER, audience=audience)
    assert opener.calls == []


@pytest.mark.parametrize("mode", [
    "status", "redirect", "location", "compressed", "oversize",
    "duplicate", "extra", "nonascii",
])
def test_unqualified_token_response_fails_closed(monkeypatch, mode):
    opener = FakeOpener()
    mod = _load(monkeypatch, opener)
    url = BASE + "&audience=" + urllib.parse.quote(AUDIENCE, safe="")
    body = json.dumps({"value": "a.b.c"}).encode("ascii")
    status = 200
    headers = {}
    final_url = None
    if mode == "status":
        status = 201
    elif mode == "redirect":
        final_url = "https://attacker.invalid/token"
    elif mode == "location":
        headers["Location"] = "https://attacker.invalid/token"
    elif mode == "compressed":
        headers["Content-Encoding"] = "gzip"
    elif mode == "oversize":
        body = b"x" * 16385
    elif mode == "duplicate":
        body = b'{"value":"a.b.c","value":"d.e.f"}'
    elif mode == "extra":
        body = b'{"value":"a.b.c","other":1}'
    elif mode == "nonascii":
        body = b'{"value":"\\u00e9"}'
    opener.response = FakeResponse(
        url, body, status=status, headers=headers, final_url=final_url)
    with pytest.raises(mod.R010PreexecOIDCAcquireDenied):
        mod.acquire_r010_preexec_oidc_response(
            request_base_url=BASE, bearer=BEARER, audience=AUDIENCE)


def test_bearer_never_appears_in_receipt_or_error(monkeypatch):
    opener = FakeOpener()
    mod = _load(monkeypatch, opener)
    url = BASE + "&audience=" + urllib.parse.quote(AUDIENCE, safe="")
    opener.response = FakeResponse(url, b'{"bad":1}')
    with pytest.raises(mod.R010PreexecOIDCAcquireDenied) as exc:
        mod.acquire_r010_preexec_oidc_response(
            request_base_url=BASE, bearer=BEARER, audience=AUDIENCE)
    assert BEARER not in str(exc.value)
