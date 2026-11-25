"""Operator-managed Dev Tunnel launcher and unauthenticated probes.

Never changes tunnel ports or ACLs. The preflight assumes the operator
does not concurrently reconfigure the dedicated persistent tunnel.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys

import httpx

from .config import Config, load_config


def validate_tunnel_id(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,127}", value):
        raise ValueError("Use an explicit Dev Tunnel ID (prefer cluster-qualified ID)")
    return value


def validate_ports(raw: str, config: Config) -> None:
    payload = json.loads(raw)
    ports = payload.get("ports") if isinstance(payload, dict) else None
    if not isinstance(ports, list) or len(ports) != 1:
        raise ValueError("Dedicated Dev Tunnel must have exactly one configured port")
    entry = ports[0]
    if (not isinstance(entry, dict) or type(entry.get("portNumber")) is not int
            or entry["portNumber"] != config.listen_port or entry.get("protocol") != "http"):
        raise ValueError("Dev Tunnel must forward HTTP port 8766 only")
    # Some CLI versions omit forwarding URIs until hosting begins.
    uris = entry.get("portForwardingUris")
    if uris is not None:
        if not isinstance(uris, list) or any(not isinstance(u, str) for u in uris):
            raise ValueError("Unexpected Dev Tunnel forwarding URI format")
        if uris and not any(u.rstrip("/") == config.public_url for u in uris):
            raise ValueError("Dev Tunnel forwarding URI differs from configured public_url")


def check_ports(tunnel_id: str, config: Config) -> None:
    result = subprocess.run(
        ["devtunnel", "port", "list", validate_tunnel_id(tunnel_id), "--json", "--nologo"],
        check=True, capture_output=True, text=True, timeout=20,
    )
    validate_ports(result.stdout, config)


def verify_http(client: httpx.Client, origin: str, config: Config) -> None:
    """Never send a token or file contents. Do not follow provider redirects."""
    headers = {"Accept": "application/json"}
    resource_path = "/.well-known/oauth-protected-resource"
    for path in (resource_path, resource_path + "/mcp"):
        response = client.get(origin + path, headers=headers)
        if response.status_code != 200:
            raise ValueError("Protected-resource discovery did not return HTTP 200")
        resource = response.json()
        if (not isinstance(resource, dict) or resource.get("resource") != config.resource
                or resource.get("authorization_servers") != [config.issuer]):
            raise ValueError("Protected-resource metadata does not match configured origin")
    response = client.get(origin + "/.well-known/oauth-authorization-server", headers=headers)
    if response.status_code != 200:
        raise ValueError("OAuth discovery did not return HTTP 200")
    meta = response.json()
    if (not isinstance(meta, dict) or meta.get("issuer") != config.issuer
            or meta.get("authorization_endpoint") != config.issuer + "/oauth/authorize"
            or meta.get("token_endpoint") != config.issuer + "/oauth/token"):
        raise ValueError("OAuth metadata does not match configured origin")
    challenge = 'resource_metadata="' + config.issuer + resource_path + '"'
    replies = [
        client.get(origin + "/mcp", headers=headers),
        client.post(origin + "/mcp", headers=headers,
                    json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}),
    ]
    for reply in replies:
        if reply.status_code != 401 or challenge not in reply.headers.get("WWW-Authenticate", ""):
            raise ValueError("Unauthenticated MCP must return OAuth HTTP 401 challenge")
    for path in ("/health", "/read", "/write", "/git/run", "/mcp/", "/oauth/admin"):
        if client.get(origin + path, headers=headers).status_code != 404:
            raise ValueError("Dev Tunnel path isolation check failed: " + path)


def main(args: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Host a dedicated Gemini Dev Tunnel")
    parser.add_argument("tunnel_id", help="Existing persistent Dev Tunnel ID")
    parser.add_argument("--config", required=True, help="Private Gemini configuration")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--check-only", action="store_true", help="Check local adapter and tunnel ports; do not host")
    modes.add_argument("--probe-public", action="store_true", help="Check also the already-running public endpoint; do not host")
    ns = parser.parse_args(args)
    try:
        config = load_config(ns.config)
        if config.tunnel_type != "devtunnel":
            raise ValueError("Gemini config requires tunnel_type=devtunnel")
        tunnel_id = validate_tunnel_id(ns.tunnel_id)
        check_ports(tunnel_id, config)
        with httpx.Client(timeout=5.0, follow_redirects=False, trust_env=False) as client:
            verify_http(client, f"http://127.0.0.1:{config.listen_port}", config)
            if ns.probe_public:
                verify_http(client, config.public_url, config)
        print("Gemini Dev Tunnel preflight passed (no authenticated file access tested).", flush=True)
        if ns.check_only or ns.probe_public:
            return 0
        print("Check the hosted HTTPS URL against public_url. No access policy was changed.", flush=True)
        os.execvp("devtunnel", ["devtunnel", "host", tunnel_id])
    except (ValueError, OSError, subprocess.SubprocessError, httpx.HTTPError) as exc:
        # Do not echo provider stdout/stderr: it may contain account metadata.
        if isinstance(exc, ValueError):
            print(f"Gemini Dev Tunnel refused: {exc}", file=sys.stderr)
        else:
            print(f"Gemini Dev Tunnel refused: {type(exc).__name__}; check local adapter and CLI", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
