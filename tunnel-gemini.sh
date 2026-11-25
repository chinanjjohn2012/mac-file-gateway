#!/usr/bin/env bash
# Gemini-specific Named Tunnel. Does not change OpenAI's tunnel.sh or 8765.
set -euo pipefail
cd "$(dirname "$0")"
if ! command -v cloudflared >/dev/null 2>&1; then
  echo 'Install cloudflared first (brew install cloudflared).' >&2
  exit 2
fi
if [ "$#" -ne 1 ]; then
  echo 'Usage: bash tunnel-gemini.sh /private/path/to/cloudflared-config.yml' >&2
  echo 'Config ingress must expose only OAuth discovery, /oauth/* and /mcp on port 8766, with httpHostHeader 127.0.0.1:8766.' >&2
  exit 2
fi
if ! curl --noproxy '*' -fsS -m 3 http://127.0.0.1:8766/health >/dev/null; then
  echo 'Gemini Adapter health check failed; run python -m gateway.gemini_adapter serve --config ... first.' >&2
  exit 2
fi
# A local config file may expose arbitrary upstreams. Validate it manually
# against docs/GEMINI_INTEGRATION.md before starting the tunnel.
exec cloudflared tunnel --config "$1" run
