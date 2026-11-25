#!/usr/bin/env bash
# Unauthenticated curl smoke test; never changes Tunnel ACLs or files.
set -euo pipefail
cd "$(dirname "$0")"
if [ -x .venv/bin/python ]; then
  exec .venv/bin/python -m gateway.gemini_adapter.curl_probe "$@"
fi
if command -v python3 >/dev/null 2>&1; then
  exec python3 -m gateway.gemini_adapter.curl_probe "$@"
fi
echo 'Python 3 and project dependencies are required; run bash setup.sh first.' >&2
exit 2
