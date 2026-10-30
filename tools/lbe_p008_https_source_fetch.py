#!/usr/bin/env python3
"""P001/P008 exact source-only HTTPS fetch with pre-contact redirect validation.

Every requested URL, including every redirect hop, is checked BEFORE the
request. No executable installation, import, execution, subprocess or network
fetch outside the three previously approved fixed source artifacts.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlsplit
from urllib.request import Request, ProxyHandler, HTTPRedirectHandler, build_opener

GO_NAME = "go1.27.3.darwin-arm64.tar.gz"
GO_SHA = "dd3908cf20959d798c1e06ebe5b72213f0505ce01373b40ce3110975a6cd99c2"
GO_SIZE = 68196737
WHEEL_NAME = "pipenv-2026.10.4-py3-none-any.whl"
WHEEL_SHA = "308125623e4d08dfe32936f7259a9ed33c5480baa2c9a291a1ff8a9328eeeb1f"
META_NAME = "pipenv-2026.10.4-release.json"
META_URL = "https://pypi.org/pypi/pipenv/2026.10.4/json"
GO_URL = "https://go.dev/dl/" + GO_NAME
MAX_REDIRECTS = 3
CAPS = {"go": 70000000, "metadata": 1000000, "wheel": 6000000}
DELIVERED = {"go": GO_NAME, "metadata": META_NAME, "wheel": WHEEL_NAME}
TIMEOUT = {"go": 200, "metadata": 30, "wheel": 90}
CHUNK = 262144


class P008Error(ValueError):
    """A source fetch violates the exact-source and outbound-host contract."""


class NeverAutomaticallyRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def require_allowed_url(kind: str, url: str) -> str:
    if type(kind) is not str or kind not in CAPS or type(url) is not str:
        raise P008Error("unknown fixed source or untrusted URL type")
    if not 1 <= len(url) <= 1024 or any(ord(x) < 33 or ord(x) > 126 for x in url):
        raise P008Error("untrusted source URL characters")
    try:
        p = urlsplit(url)
        if (p.scheme != "https" or p.username is not None or
                p.password is not None or p.port not in (None, 443) or
                p.fragment or p.query or
                "\\" in p.path or "%" in p.path or
                any(part in ("", ".", "..") for part in p.path.split("/")[1:])):
            raise P008Error("not an exact canonical source HTTPS URL")
    except (ValueError, UnicodeError) as exc:
        raise P008Error("source URL is ambiguous") from exc
    host = p.hostname
    if kind == "go":
        approved = (
            (host == "go.dev" and p.path == "/dl/" + GO_NAME)
            or (host == "dl.google.com" and p.path == "/go/" + GO_NAME)
            or (host == "storage.googleapis.com" and
                p.path == "/golang/" + GO_NAME)
        )
    elif kind == "metadata":
        approved = host == "pypi.org" and p.path == "/pypi/pipenv/2026.10.4/json"
    else:
        approved = (host == "files.pythonhosted.org" and
                    p.path.startswith("/packages/") and
                    p.path.endswith("/" + WHEEL_NAME) and
                    len(p.path) <= 320 and
                    all(part and re.fullmatch(r"[a-zA-Z0-9_.-]+", part)
                        for part in p.path.split("/")[1:]))
    if not approved:
        raise P008Error("unapproved source/redirect destination")
    return host


def acquire(kind: str, start_url: str, destination: Path, opener=None) -> dict:
    """Source download only; opener is fakeable for offline redirect T0."""
    if kind not in CAPS:
        raise P008Error("unknown source kind")
    if (not destination.is_absolute() or destination.name != DELIVERED[kind]
            or not destination.parent.is_dir() or
            destination.parent.is_symlink() or
            destination.exists() or destination.is_symlink()):
        raise P008Error("source output path not an empty private regular slot")
    if opener is None:
        opener = build_opener(ProxyHandler({}), NeverAutomaticallyRedirect())
    url = start_url
    seen = set()
    hosts = []
    for i in range(MAX_REDIRECTS + 1):
        # Prevalidate BEFORE opener.open. A->evil->A cannot contact evil.
        host = require_allowed_url(kind, url)
        if url in seen:
            raise P008Error("source redirect cycle")
        seen.add(url)
        hosts.append(host)
        try:
            response = opener.open(
                Request(url, headers={"User-Agent": "mfg-p001-p008-source-only/1"}),
                timeout=TIMEOUT[kind],
            )
        except HTTPError as e:
            if e.code not in (301, 302, 303, 307, 308):
                e.close()
                raise P008Error("HTTP status outside approved redirect policy") from None
            location = e.headers.get("Location", "")
            e.close()
            if not location or i >= MAX_REDIRECTS:
                raise P008Error("missing/excessive redirect")
            next_url = urljoin(url, location)
            require_allowed_url(kind, next_url)  # BEFORE next request
            url = next_url
            continue
        except (URLError, OSError, TimeoutError) as exc:
            raise P008Error("source HTTPS fetch failed") from exc
        with response:
            if (response.geturl() != url or response.status != 200):
                raise P008Error("automatic redirect or non-200 source response")
            fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         getattr(os, "O_NOFOLLOW", 0), 0o600)
            digest = hashlib.sha256()
            n = 0
            with os.fdopen(fd, "wb") as output:
                while True:
                    data = response.read(min(CHUNK, CAPS[kind] + 1 - n))
                    if not data:
                        break
                    n += len(data)
                    if n > CAPS[kind]:
                        raise P008Error("source body too large")
                    output.write(data)
                    digest.update(data)
            sha = digest.hexdigest()
            if kind == "go" and (n != GO_SIZE or sha != GO_SHA):
                raise P008Error("Go source archive actual bytes do not match P001")
            if kind == "wheel" and (not n or sha != WHEEL_SHA):
                raise P008Error("Pipenv wheel actual SHA does not match P001")
            if kind == "metadata" and not n:
                raise P008Error("PyPI JSON source response is empty")
            return {"kind": kind, "source_host_chain": hosts,
                    "redirect_count": len(hosts) - 1,
                    "filename": destination.name,
                    "source_bytes": n, "sha256": sha,
                    "verified_go_or_wheel_hash": kind != "metadata",
                    "no_external_code_executed": True}
    raise P008Error("no approved source download completed")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--kind", choices=tuple(CAPS), required=True)
    parser.add_argument("--runner-temp", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        root = args.runner_temp
        if (not root.is_absolute() or not root.is_dir() or root.is_symlink()
                or root.resolve(strict=True) != root
                or os.environ.get("RUNNER_TEMP") != str(root)):
            raise P008Error("not an approved hosted runner-owned source root")
        if args.kind == "wheel":
            linkfile = root / "pipenv-2026.10.4-url.txt"
            stat_info = linkfile.lstat()
            if (not stat.S_ISREG(stat_info.st_mode) or
                    stat_info.st_nlink != 1 or
                    not 1 <= stat_info.st_size <= 1024):
                raise P008Error("Pipenv release metadata URL lock not a regular file")
            url = linkfile.read_text("utf-8").strip()
        else:
            url = GO_URL if args.kind == "go" else META_URL
        result = acquire(args.kind, url, root / DELIVERED[args.kind])
        evidence = root / ("lbe-p008-" + args.kind + "-fetch.json")
        fd = os.open(evidence, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            json.dump(result, out, sort_keys=True)
            out.write("\n")
    except (OSError, UnicodeError, ValueError) as exc:
        print("LBE_P008_SOURCE_FETCH=BLOCKED: " + str(exc), file=sys.stderr)
        return 2
    print("LBE_P008_SOURCE_FETCH=PASS kind=" + args.kind)
    print("LBE_P008_VERIFIED_HOST_CHAIN=" + ",".join(result["source_host_chain"]))
    print("LBE_P008_SHA256=" + result["sha256"])
    print("LBE_P008_NEW_EXTERNAL_CODE_EXECUTED=FALSE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
