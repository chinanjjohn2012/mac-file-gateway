"""Read-only curl smoke test for the Gemini Dev Tunnel adapter.

No OAuth credentials, cookies, local file content or mutation requests are sent.
The existing HTTP preflight verifies metadata, authentication and route isolation.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit

import httpx

from .config import load_config
from .devtunnel import verify_http

DEFAULT_CONFIG = "~/.config/mac-file-gateway/gemini-devtunnel/gemini.json"


class CurlClient:
    """Minimal HTTP client for verify_http, using the installed curl binary."""

    def __init__(self, executable: str):
        self.executable = executable

    def get(self, url: str, *, headers: dict[str, str]) -> httpx.Response:
        return self._request("GET", url, headers)

    def post(self, url: str, *, headers: dict[str, str], json: dict) -> httpx.Response:
        return self._request("POST", url, headers, json)

    def _request(self, method: str, url: str, headers: dict[str, str],
                 payload: dict | None = None) -> httpx.Response:
        path = urlsplit(url).path
        with tempfile.TemporaryDirectory(prefix="gemini-curl-") as temp:
            header_file = Path(temp) / "headers"
            body_file = Path(temp) / "body"
            # --disable must be the first option, to ignore ~/.curlrc.
            # Keep TLS certificate verification enabled; never follow redirects
            # or pick up proxy settings, authorization headers or cookies.
            argv = [
                self.executable, "--disable", "--silent", "--show-error",
                "--noproxy", "*", "--proto", "=http,https", "--globoff",
                "--path-as-is", "--max-redirs", "0",
                "--connect-timeout", "4", "--max-time", "10",
                "--max-filesize", "65536", "--request", method,
                "--dump-header", str(header_file), "--output", str(body_file),
                "--write-out", "%{http_code}",
            ]
            for name, value in headers.items():
                argv.extend(["--header", name + ": " + value])
            if payload is not None:
                argv.extend(["--header", "Content-Type: application/json",
                             "--data-binary", json.dumps(payload, separators=(",", ":"))])
            argv.extend(["--url", url])
            try:
                result = subprocess.run(argv, stdout=subprocess.PIPE,
                                        stderr=subprocess.DEVNULL, timeout=12)
            except subprocess.TimeoutExpired:
                raise ValueError(f"{method} {path}: curl timed out") from None
            if result.returncode != 0:
                raise ValueError(
                    f"{method} {path}: curl exit {result.returncode} "
                    "(check DNS, connection, timeout or TLS certificate)"
                )
            if not re.fullmatch(rb"[1-5][0-9]{2}", result.stdout):
                raise ValueError(f"{method} {path}: invalid curl HTTP status")
            status = int(result.stdout)
            print(f"  {method:4} {path} -> HTTP {status}", flush=True)
            # Use the final response header block, e.g. after an HTTP 100.
            blocks = [b for b in re.split(rb"\r?\n\r?\n", header_file.read_bytes())
                      if b.startswith(b"HTTP/")]
            if not blocks:
                raise ValueError("curl returned no HTTP response headers")
            lines = blocks[-1].splitlines()
            match = re.match(rb"HTTP/\S+\s+([0-9]{3})(?:\s|$)", lines[0])
            if not match or int(match.group(1)) != status:
                raise ValueError("curl response status/header mismatch")
            pairs = []
            for line in lines[1:]:
                name, sep, value = line.partition(b":")
                if not sep or not name:
                    raise ValueError("Invalid HTTP response header")
                pairs.append((name, value.strip()))
            if body_file.stat().st_size > 65536:
                raise ValueError("HTTP response exceeded smoke-test size limit")
            return httpx.Response(status, headers=pairs, content=body_file.read_bytes())


def main(args: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Check Gemini Dev Tunnel with curl (no credentials or file writes)")
    parser.add_argument("--config", default=DEFAULT_CONFIG,
                        help="Private Gemini Dev Tunnel config")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--local", action="store_true",
                       help="Check local Adapter only (default)")
    modes.add_argument("--public", action="store_true",
                       help="Check configured public HTTPS origin only")
    modes.add_argument("--both", action="store_true",
                       help="Check local Adapter and public HTTPS origin")
    ns = parser.parse_args(args)
    executable = shutil.which("curl")
    if not executable:
        print("ERROR: curl is required.", file=sys.stderr)
        return 2
    try:
        config = load_config(ns.config)
        if config.tunnel_type != "devtunnel":
            raise ValueError("Configuration must select tunnel_type=devtunnel")
    except (ValueError, OSError, TypeError):
        # Do not print config contents, parse exceptions or private credentials.
        print("ERROR: cannot load valid private Gemini Dev Tunnel configuration.",
              file=sys.stderr)
        return 2
    targets = []
    if ns.both or not ns.public:
        targets.append(("LOCAL", f"http://127.0.0.1:{config.listen_port}"))
    if ns.both or ns.public:
        targets.append(("PUBLIC", config.public_url))

    client = CurlClient(executable)
    failures = 0
    for label, origin in targets:
        print(f"[{label}] {origin}", flush=True)
        try:
            verify_http(client, origin, config)
        except json.JSONDecodeError:
            failures += 1
            print(f"[FAIL] {label}: expected JSON; possible Tunnel login/interstitial page.",
                  file=sys.stderr, flush=True)
        except (ValueError, OSError, httpx.HTTPError) as exc:
            failures += 1
            # verify_http emits fixed diagnostic messages and never response bodies.
            detail = str(exc) if isinstance(exc, ValueError) else type(exc).__name__
            print(f"[FAIL] {label}: {detail}", file=sys.stderr, flush=True)
        else:
            print(f"[PASS] {label}: OAuth discovery, MCP 401 challenge, route isolation",
                  flush=True)
    print(f"Summary: {len(targets) - failures}/{len(targets)} target(s) passed.",
          flush=True)
    print("No authenticated file access or real Gemini OAuth flow was tested.",
          flush=True)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
