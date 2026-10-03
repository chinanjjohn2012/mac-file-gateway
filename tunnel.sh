#!/usr/bin/env bash
# Private OpenAI Secure MCP Tunnel. No public unauthenticated HTTP exposure.
set -euo pipefail
cd "$(dirname "$0")"
if ! command -v tunnel-client >/dev/null 2>&1; then
    echo 'Install the official client: brew install openai/tools/tunnel-client' >&2
    exit 2
fi
if [ -n "${GATEWAY_TOKEN:-}" ]; then
    echo 'This helper uses tunnel authorization, not a local bearer header.' >&2
    echo 'For this private-tunnel setup, restart both processes without GATEWAY_TOKEN.' >&2
    echo 'Never remove authentication from a public deployment.' >&2
    exit 2
fi
PORT="${GATEWAY_PORT:-8765}"
if ! [[ "$PORT" =~ ^[0-9]{4,5}$ ]] || [ "$PORT" -lt 1024 ] || [ "$PORT" -gt 65535 ]; then
    echo 'GATEWAY_PORT must be from 1024 to 65535.' >&2
    exit 2
fi
if [ ! -x .venv/bin/python ]; then
    echo 'Run bash setup.sh first.' >&2
    exit 2
fi
.venv/bin/python - "$PORT" <<'PY'
import json, sys, urllib.request
url = f"http://127.0.0.1:{sys.argv[1]}/health"
try:
    # Do not send the loopback health request through HTTP proxy settings.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(url, timeout=3) as response:
        data = json.load(response)
    if data.get("status") != "ok" or data.get("mcp_enabled") is not True:
        raise ValueError("MCP is not enabled")
except Exception:
    print("Gateway health check failed. Start bash run.sh PROJECT first, without --http-only.", file=sys.stderr)
    sys.exit(2)
print("Local gateway health: OK. This does not verify cloud connectivity.")
PY
if [ -z "${CONTROL_PLANE_TUNNEL_ID:-}" ]; then
    read -r -p 'Tunnel ID (tunnel_ followed by 32 lowercase hex characters): ' CONTROL_PLANE_TUNNEL_ID
fi
if ! [[ "$CONTROL_PLANE_TUNNEL_ID" =~ ^tunnel_[0-9a-f]{32}$ ]]; then
    echo 'Invalid tunnel ID.' >&2
    exit 2
fi
if [ -z "${CONTROL_PLANE_API_KEY:-}" ]; then
    read -r -s -p 'OpenAI Platform runtime API key (input hidden): ' CONTROL_PLANE_API_KEY
    printf '\n'
fi
if [ -z "$CONTROL_PLANE_API_KEY" ]; then
    echo 'An authorized runtime API key is required for the tunnel.' >&2
    exit 2
fi
export CONTROL_PLANE_TUNNEL_ID CONTROL_PLANE_API_KEY
export MCP_SERVER_URL="http://127.0.0.1:${PORT}/mcp"
echo 'Starting the private tunnel. Keep this terminal open; Ctrl-C stops it.'
exec tunnel-client run
