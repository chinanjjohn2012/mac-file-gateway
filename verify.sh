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

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        echo 'sha256sum or shasum is required to verify MANIFEST.sha256.' >&2
        return 2
    fi
}

verify_manifest() {
    if [ ! -f MANIFEST.sha256 ]; then
        echo 'MANIFEST.sha256 is missing.' >&2
        return 1
    fi

    local candidate
    candidate="$(mktemp)"
    trap 'rm -f "$candidate"' RETURN

    if command -v git >/dev/null 2>&1 && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        while IFS= read -r -d '' file; do
            [ "$file" = "MANIFEST.sha256" ] && continue
            printf '%s  ./%s\n' "$(sha256_file "$file")" "$file"
        done < <(git ls-files -z | sort -z) > "$candidate"
    else
        while IFS= read -r line; do
            [ -z "$line" ] && continue
            local path file
            path="${line#*  }"
            file="${path#./}"
            if [ ! -f "$file" ]; then
                echo "Manifest file missing: $path" >&2
                return 1
            fi
            printf '%s  %s\n' "$(sha256_file "$file")" "$path"
        done < MANIFEST.sha256 > "$candidate"
    fi

    if ! cmp -s MANIFEST.sha256 "$candidate"; then
        echo 'MANIFEST.sha256 does not match the current release files.' >&2
        diff -u MANIFEST.sha256 "$candidate" || true
        return 1
    fi
    echo 'Release manifest: OK'
}

if [ "${1:-}" = '--require-mcp' ]; then
    .venv/bin/python -c 'from mcp.server.fastmcp import FastMCP; from gateway.mcp_adapter import build_mcp; print("Official MCP SDK import: OK")'
fi
.venv/bin/python -m compileall -q gateway
.venv/bin/python -m pytest -q
.venv/bin/python tests/smoke_live.py
verify_manifest
