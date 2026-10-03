#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
if [ ! -x .venv/bin/python ]; then
    echo 'Run bash setup.sh first.' >&2
    exit 2
fi
if [ "$#" -gt 1 ] || { [ "$#" -eq 1 ] && [ "$1" != '--require-mcp' ]; }; then
    echo 'Usage: bash verify.sh [--require-mcp]' >&2
    exit 2
fi
if [ "${1:-}" = '--require-mcp' ]; then
    .venv/bin/python -c 'from mcp.server.fastmcp import FastMCP; from gateway.mcp_adapter import build_mcp; print("Official MCP SDK import: OK")'
fi
.venv/bin/python -m compileall -q gateway
.venv/bin/python -m pytest -q

.venv/bin/python tests/smoke_live.py
