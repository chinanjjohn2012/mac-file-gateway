"""Exercise the real curl executable on a disposable loopback Adapter."""
from __future__ import annotations

from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import shutil
import socket
import subprocess
from threading import Thread
import time

import pytest
import uvicorn

from gateway.gemini_adapter import curl_probe
from gateway.gemini_adapter.app import create_app
from gateway.gemini_adapter.config import initialize_config

CURL = shutil.which("curl")
pytestmark = pytest.mark.skipif(CURL is None, reason="curl executable required")


def config_for(tmp_path):
    return initialize_config(tmp_path / "private" / "gemini.json",
                             public_url="https://mfg-test-8766.usw2.devtunnels.ms",
                             tunnel_type="devtunnel")


def test_curl_probe_real_local_adapter(tmp_path, monkeypatch, capsys):
    config = config_for(tmp_path)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(16)
        config = replace(config, listen_port=listener.getsockname()[1])
        # No real Gateway, Google, Microsoft or production Workspace is needed.
        server = uvicorn.Server(uvicorn.Config(
            lambda: create_app(config), factory=True,
            host="127.0.0.1", port=config.listen_port,
            access_log=False, log_level="error", proxy_headers=False))
        thread = Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
        thread.start()
        try:
            deadline = time.monotonic() + 8
            while not server.started and thread.is_alive() and time.monotonic() < deadline:
                time.sleep(0.02)
            assert server.started
            monkeypatch.setattr(curl_probe, "load_config", lambda _: config)
            assert curl_probe.main(["--local"]) == 0
            output = capsys.readouterr().out
            assert "[PASS] LOCAL" in output
            assert "/mcp -> HTTP 401" in output
            assert "/health -> HTTP 404" in output
            assert "1/1 target(s) passed" in output
            assert config.client_secret not in output
        finally:
            server.should_exit = True
            thread.join(timeout=8)
            assert not thread.is_alive()


def test_curl_probe_does_not_follow_redirects(tmp_path):
    seen = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append(self.path)
            assert self.headers.get("Authorization") is None
            assert self.headers.get("Cookie") is None
            self.send_response(302)
            self.send_header("Location", "/must-not-follow")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *_):
            pass

    # A redirect to a local path makes accidental following observable without
    # touching any external host.
    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            client = curl_probe.CurlClient(CURL)
            url = f"http://127.0.0.1:{server.server_port}/redirect"
            assert client.get(url, headers={"Accept": "application/json"}).status_code == 302
            assert seen == ["/redirect"]
        finally:
            server.shutdown()
            thread.join(timeout=5)


def test_probe_modes_and_failure_exit(tmp_path, monkeypatch, capsys):
    config = config_for(tmp_path)
    seen = []
    monkeypatch.setattr(curl_probe, "load_config", lambda _: config)

    def verify(client, origin, cfg):
        assert cfg is config
        seen.append(origin)
        if origin == config.public_url:
            raise json.JSONDecodeError("Expecting JSON", "<html>", 0)

    monkeypatch.setattr(curl_probe, "verify_http", verify)
    assert curl_probe.main(["--both"]) == 1
    assert seen == ["http://127.0.0.1:8766", config.public_url]
    output = capsys.readouterr()
    assert "[PASS] LOCAL" in output.out
    assert "[FAIL] PUBLIC" in output.err
    assert "interstitial" in output.err
    assert "1/2 target(s) passed" in output.out
    assert config.client_secret not in output.out + output.err

    seen.clear()
    assert curl_probe.main(["--public"]) == 1
    assert seen == [config.public_url]
    seen.clear()
    assert curl_probe.main([]) == 0
    assert seen == ["http://127.0.0.1:8766"]


def test_probe_invalid_config_and_wrapper_help(tmp_path, capsys):
    assert curl_probe.main(["--config", str(tmp_path / "missing.json")]) == 2
    assert "ERROR:" in capsys.readouterr().err
    root = Path(__file__).resolve().parent.parent
    result = subprocess.run(["bash", str(root / "test-gemini-dev.sh"), "--help"],
                            cwd=root, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    for arg in ("--local", "--public", "--both", "--config"):
        assert arg in result.stdout
