#!/usr/bin/env bash
# No anonymous access or port changes are performed by this launcher.
set -euo pipefail
cd "$(dirname "$0")"
if [ ! -x .venv/bin/python ]; then
  echo 'Run bash setup.sh first.' >&2
  exit 2
fi
if ! command -v devtunnel >/dev/null 2>&1; then
  echo 'Install Microsoft Dev Tunnels (brew install --cask devtunnel) and log in first.' >&2
  exit 2
fi
exec .venv/bin/python -m gateway.gemini_adapter.devtunnel "$@"
